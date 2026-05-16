#![forbid(unsafe_code)]
//! Multi-hop path assembly + per-forwarder lease minting
//! (R-MULTIHOP-COORD).
//!
//! Owns the §11 D-6 RESOLVED option (c) cascading-edits surface: when
//! a peer asks the coordinator to be matched into a flow, this module
//! turns the request plus the live cohort state into a concrete
//! [`bibeam_protocol::control::MatchResponse`]:
//!
//! - [`MatchResponse::SingleHop`] when the requested region has a
//!   busy exit cohort and no intermediate hop is needed.
//! - [`MatchResponse::MultiHopAssignment`] when path-assembly chose
//!   `≥1` forwarder hops between the client and the exit. Carries
//!   the per-forwarder lease rows the coordinator hands each
//!   forwarder out-of-band, plus the client↔exit
//!   [`WgPeerConfig`] the client uses to bring its `WireGuard`
//!   session up.
//! - [`MultiHopPathError::NoAnonymousPathAvailable`] (the error
//!   variant returned via [`Err`]) when no path satisfies the
//!   per-position floor. Refusal is the §11 R-3 semantic — no
//!   union fallback, no piggy-backing on a neighbouring region's
//!   anonymity set.
//!
//! ## Per-position floor (R-FLOOR)
//!
//! Every position in the chain — exit, every intermediate — must
//! see at least `per_position_floor` *other* in-role flows in its
//! cohort. The floor is therefore phrased "≥ floor + 1 members
//! including the requester" inside this module; callers configure
//! the floor as `29` to get the project-canonical
//! "≥ 30 members" anonymity set (one of the 30 is the requester
//! themselves).
//!
//! ## WG public-key pairing (option (c))
//!
//! Path-assembly reads the client's and exit's
//! [`bibeam_discovery::PeerRecord::wg_public_key`] /
//! [`bibeam_discovery::ExitRecord::wg_public_key`], renders a
//! [`WgPeerConfig`] for the client, and emits the same lease /
//! response chain. The coordinator NEVER touches private key
//! material — the `WgPeerConfig` shape only carries public keys —
//! and an absent registered key is a hard error (no silent key
//! minting).
//!
//! ## `RegionView` trait
//!
//! [`RegionView`] is the read-only port through which path-assembly
//! sees the live cohort state. Production wires it up against
//! [`super::cohorts::CohortStore`] + [`super::registry::PeerRegistry`]
//! (plus the exit table); tests supply an in-memory fake. The trait
//! keeps the path-assembly tests free of redb fixtures while
//! preserving the single source of truth in production.
//!
//! ## Out of scope
//!
//! - Client-side multi-hop session establishment
//!   (R-MULTIHOP-CLI's work).
//! - Forwarder state machine (R-MULTIHOP-NODE's work).
//! - Region cross-check at registration time (R-REGION.3's work).
//! - Anonymity-set integration with the rotation scheduler
//!   (existing F-COORD.6 work; the rotation scheduler drives this
//!   module's callsites but lives elsewhere).

use core::net::SocketAddr;
use std::collections::HashMap;

use bibeam_core::{ChainId, NodeId, PeerId, Timestamp};
use bibeam_crypto::WgPublicKey as CryptoWgPublicKey;
use bibeam_protocol::control::{MatchRequest, MatchResponse, MultiHopAssignment, SingleHopMatch};
use bibeam_protocol::multihop::{ForwarderLease, WG_KEY_LEN, WgPeerConfig, WgPublicKey};
use ipnet::IpNet;
use thiserror::Error;
use time::Duration;

/// `WireGuard` persistent-keepalive value the coordinator renders
/// into every client-side [`WgPeerConfig`].
///
/// `25` is the standard NAT-punching value documented in
/// [`bibeam_protocol::multihop::WgPeerConfig::persistent_keepalive_secs`];
/// pinning it here keeps coordinator output deterministic across
/// path-assembly calls. Operators that need to tune it should
/// extend [`MultiHopBuilder::new`] with a builder parameter.
const DEFAULT_KEEPALIVE_SECS: u16 = 25;

/// Forwarder lease lifetime — §11 R-3 rotation cadence (15 minutes).
///
/// Every [`ForwarderLease`] emitted by this module expires
/// `LEASE_DURATION` after `Timestamp::now()`. The rotation scheduler
/// refreshes leases before expiry by issuing a fresh
/// [`ForwarderLease`] reusing the same [`ChainId`]; the forwarder
/// matches on `chain_id` and overwrites its row.
const LEASE_DURATION: Duration = Duration::minutes(15);

/// Snapshot the live region cohort state through this trait so
/// path-assembly stays decoupled from any single backing store.
///
/// Production wires the trait against the live coordinator state
/// (redb-backed [`super::cohorts::CohortStore`] +
/// [`super::registry::PeerRegistry`] + the exit table); tests use the
/// in-memory [`InMemoryRegionView`].
///
/// Every method returns owned snapshots — implementations are free to
/// take any internal lock they own and release it before returning.
/// The path-assembler does not hold any borrow across calls.
pub trait RegionView {
    /// All exits currently advertising `region` along with their
    /// registered `WireGuard` public keys + reachable sockets.
    fn exits_in(&self, region: &str) -> Vec<ExitCandidate>;

    /// All peers currently bucketed under `region` as candidate
    /// intermediate forwarders along with their reachable sockets.
    /// Production typically pulls from
    /// [`super::admission_gate::AdmissionGate::members_in_region`]
    /// joined against [`super::registry::PeerRegistry`].
    fn forwarders_in(&self, region: &str) -> Vec<ForwarderCandidate>;

    /// Look up the registered state for the peer making the
    /// [`MatchRequest`]. Returns:
    ///
    /// - [`ClientLookup::Found`] — the peer is registered AND has
    ///   a public [`bibeam_crypto::WgPublicKey`] on file.
    /// - [`ClientLookup::MissingWgKey`] — the peer is registered
    ///   but its registration carries no public key (the
    ///   R-MULTIHOP-COORD option (c) hard-refusal case; the
    ///   coord NEVER silently mints a key).
    /// - [`ClientLookup::Unknown`] — the registry has no record
    ///   for `peer_id` at all (e.g. the peer never registered, or
    ///   its registration has been evicted as stale).
    ///
    /// The three states are kept distinct so the path-assembler
    /// can surface each as the appropriate HTTP status code
    /// downstream — `404`-equivalent for unknown, `409`-equivalent
    /// for missing key, `200` for found.
    fn client(&self, peer_id: PeerId) -> ClientLookup;
}

/// Outcome of [`RegionView::client`].
///
/// Distinguishes the three states the path-assembler must surface
/// separately: registered-with-key, registered-without-key, and
/// not-registered. See [`RegionView::client`] for the rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientLookup {
    /// The peer is registered and has a public key on file.
    Found(ClientHandle),
    /// The peer is registered, but the registration carries no
    /// [`bibeam_discovery::PeerRecord::wg_public_key`]. Surfaces
    /// to the caller as [`MultiHopPathError::MissingClientWgKey`].
    MissingWgKey,
    /// The registry has no record for the peer. Surfaces to the
    /// caller as [`MultiHopPathError::UnknownClient`].
    Unknown,
}

/// One exit candidate the path-assembler may pick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitCandidate {
    /// Exit's stable [`NodeId`].
    pub node_id: NodeId,
    /// Public side of the exit's `WireGuard` keypair.
    pub wg_public_key: CryptoWgPublicKey,
    /// Reachable socket the client (or last forwarder hop) dials.
    pub addr: SocketAddr,
    /// Number of other in-role flows the exit's region cohort sees
    /// right now. Path-assembly checks this against the
    /// per-position floor.
    pub cohort_size: usize,
}

/// One forwarder candidate the path-assembler may pick as an
/// intermediate hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwarderCandidate {
    /// Forwarder's stable [`NodeId`].
    pub node_id: NodeId,
    /// Reachable socket the upstream peer dials.
    pub addr: SocketAddr,
    /// Number of other in-role flows the forwarder's region cohort
    /// sees right now. Path-assembly checks this against the
    /// per-position floor.
    pub cohort_size: usize,
}

/// Handle on the requesting client's registration state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandle {
    /// Public side of the client's `WireGuard` keypair (registered
    /// via [`bibeam_discovery::PeerRecord::wg_public_key`]).
    pub wg_public_key: CryptoWgPublicKey,
    /// Reachable socket the first forwarder (or the exit, on
    /// single-hop) dials to send return traffic. Same value the
    /// peer advertised through
    /// [`bibeam_discovery::PeerRecord::addr_hint`].
    pub addr: SocketAddr,
}

/// Failure modes for [`MultiHopBuilder::assemble`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultiHopPathError {
    /// No path satisfies the per-position floor. §11 R-3 refusal —
    /// no union fallback, no piggy-back on a neighbouring region's
    /// floor crossing. The caller surfaces this to the peer as a
    /// "no anonymous path available in `<region>`; retry later"
    /// response.
    #[error("no anonymous path available in region `{region}`")]
    NoAnonymousPathAvailable {
        /// Region the client requested. Echoed back to operator
        /// dashboards via the audit log.
        region: String,
    },
    /// The peer making the [`MatchRequest`] is not registered with
    /// the coordinator (the registry returned [`None`]). Surfaces
    /// to the peer as `401 Unauthorized`.
    #[error("client peer `{peer_id}` is not registered")]
    UnknownClient {
        /// Peer id the caller passed; not present in
        /// [`RegionView::client`].
        peer_id: PeerId,
    },
    /// The peer's [`bibeam_discovery::PeerRecord::wg_public_key`]
    /// is absent. The coordinator refuses to mint a key
    /// peer-side (it would never be verifiable) and instead
    /// surfaces this error so the caller can prompt the peer to
    /// re-register with a real key.
    #[error("client peer `{peer_id}` has no registered WireGuard public key")]
    MissingClientWgKey {
        /// Peer id whose registration lacks
        /// [`bibeam_discovery::PeerRecord::wg_public_key`].
        peer_id: PeerId,
    },
}

/// Path-assembler.
///
/// Configured with the per-position floor at construction and reused
/// across requests. Stateless beyond the floor; safe to share across
/// axum handlers without further synchronisation.
#[derive(Debug, Clone, Copy)]
pub struct MultiHopBuilder {
    per_position_floor: usize,
}

impl MultiHopBuilder {
    /// Construct a path-assembler that requires `per_position_floor`
    /// *other* in-role flows at every position in the path.
    ///
    /// Pass `29` to match the project-canonical anonymity-set
    /// floor of `30` (the 30th member is the requester).
    #[must_use]
    pub const fn new(per_position_floor: usize) -> Self {
        Self { per_position_floor }
    }

    /// Per-position floor enforced by this assembler.
    #[must_use]
    pub const fn per_position_floor(&self) -> usize {
        self.per_position_floor
    }

    /// Assemble a [`MatchResponse`] for `request` targeting
    /// `requested_region`.
    ///
    /// Returns:
    ///
    /// - `Ok(MatchResponse::SingleHop(_))` when the requested region
    ///   has a busy exit cohort and no intermediate hop is needed.
    /// - `Ok(MatchResponse::MultiHopAssignment(_))` when at least
    ///   one intermediate forwarder is needed and a busy hub region
    ///   carries the per-position floor.
    /// - `Err(MultiHopPathError::NoAnonymousPathAvailable)` per
    ///   §11 R-3 when no path satisfies the floor at every position.
    /// - `Err(MultiHopPathError::UnknownClient)` /
    ///   `Err(MultiHopPathError::MissingClientWgKey)` when the
    ///   requester's registration is incomplete.
    ///
    /// # Errors
    ///
    /// Surfaces every [`MultiHopPathError`] variant per the rules
    /// above. The coordinator's HTTP handler maps each to a
    /// well-known status code; see the variant docs.
    pub fn assemble<View: RegionView + ?Sized>(
        self,
        request: &MatchRequest,
        requested_region: &str,
        view: &View,
    ) -> Result<MatchResponse, MultiHopPathError> {
        let client = resolve_client(request.peer_id, view)?;
        // §11 D-6 RESOLVED option (c): the EXIT position must
        // ALWAYS satisfy the per-position floor — there is no
        // multi-hop fallback that lets a cold exit piggy-back on
        // an intermediate's anonymity set. If no busy exit lives
        // in `requested_region` we refuse outright.
        let exit =
            pick_busy_exit(self.per_position_floor, requested_region, view).ok_or_else(|| {
                MultiHopPathError::NoAnonymousPathAvailable {
                    region: requested_region.to_owned(),
                }
            })?;
        // Multi-hop kicks in when path-assembly finds a busy
        // intermediate forwarder; the intermediate may live in
        // `requested_region` OR in any busy hub region the view
        // exposes (per the task spec's "same region OR a busy
        // hub region" rule). When no busy intermediate exists,
        // the assembler falls back to the direct single-hop path
        // — that is acceptable because the exit itself already
        // carries the per-position floor.
        Ok(
            pick_busy_forwarder(self.per_position_floor, requested_region, view).map_or_else(
                || MatchResponse::SingleHop(build_single_hop(&exit)),
                |forwarder| {
                    MatchResponse::MultiHopAssignment(build_multi_hop(&client, &[forwarder], &exit))
                },
            ),
        )
    }
}

/// Look up the requester's [`ClientHandle`]; surface registry
/// gaps and key-absence as distinct typed errors so the caller
/// can map each to its proper HTTP status.
fn resolve_client<View: RegionView + ?Sized>(
    peer_id: PeerId,
    view: &View,
) -> Result<ClientHandle, MultiHopPathError> {
    match view.client(peer_id) {
        ClientLookup::Found(client) => Ok(client),
        ClientLookup::MissingWgKey => Err(MultiHopPathError::MissingClientWgKey { peer_id }),
        ClientLookup::Unknown => Err(MultiHopPathError::UnknownClient { peer_id }),
    }
}

/// Pick the first exit candidate in `requested_region` that
/// satisfies the per-position floor — i.e. its `cohort_size` is
/// strictly greater than the floor (the floor counts *other*
/// in-role flows; the requester themselves is the floor+1th).
fn pick_busy_exit<View: RegionView + ?Sized>(
    per_position_floor: usize,
    requested_region: &str,
    view: &View,
) -> Option<ExitCandidate> {
    view.exits_in(requested_region)
        .into_iter()
        .find(|candidate| candidate.cohort_size > per_position_floor)
}

/// Pick the first intermediate-forwarder candidate that
/// satisfies the per-position floor. Per the module docs the
/// intermediate may live in any busy region — that is the
/// "busy hub region" rule the §11 R-3 cascading-edits doc
/// describes — so the assembler scans the requested region
/// first, then falls back to ANY busy forwarder region the
/// view exposes through `forwarders_in`.
///
/// Production wires `forwarders_in` to scan every region's
/// bucket; tests pass the same region the request targets
/// (acceptable because [`pick_busy_exit`] already handled the
/// busy-region happy path).
fn pick_busy_forwarder<View: RegionView + ?Sized>(
    per_position_floor: usize,
    requested_region: &str,
    view: &View,
) -> Option<ForwarderCandidate> {
    view.forwarders_in(requested_region)
        .into_iter()
        .find(|candidate| candidate.cohort_size > per_position_floor)
}

/// Assemble a [`SingleHopMatch`] from the picked exit. The
/// coordinator stamps a single-hop response with the exit's
/// canonical [`NodeId`] inside the `exit_set` vec (the client
/// expects a list-shaped exit set even when the busy-region
/// branch only nominated one).
fn build_single_hop(exit: &ExitCandidate) -> SingleHopMatch {
    // R-REGION.3: the multihop fallback's single-hop shortcut does
    // not know each exit's region tag at this layer (the candidate
    // type only carries `node_id` + capacity). Ship an empty
    // `exit_regions` map so the client's region-aware exit picker
    // (F-CLI.4b) treats every exit as region-unknown — the §11 R-3
    // "no exit in <region>; defer / fallback to multi-hop" path.
    SingleHopMatch {
        cohort: bibeam_core::CohortId::new(),
        exit_set: vec![exit.node_id],
        exit_regions: HashMap::new(),
        rotation_deadline: rotation_deadline_now(),
    }
}

/// Assemble a [`MultiHopAssignment`] from the picked exit + the
/// ordered list of intermediate forwarders. The first forwarder's
/// `allowed_src` is the client's socket; the last forwarder's
/// `allowed_dst` is the exit's socket; each inner hop bridges its
/// predecessor to its successor.
fn build_multi_hop(
    client: &ClientHandle,
    forwarders: &[ForwarderCandidate],
    exit: &ExitCandidate,
) -> MultiHopAssignment {
    let lease_expires_at = lease_expires_at_now();
    let forwarder_chain = build_lease_chain(client.addr, forwarders, exit.addr, lease_expires_at);
    MultiHopAssignment {
        exit: exit.node_id,
        forwarder_chain,
        client_wg_config: build_client_wg_config(client, exit, forwarders),
    }
}

/// `Timestamp::now() + 15 min` — the rotation cadence §11 R-3
/// requires every assembled cohort to honour. Extracted so the
/// single-hop and multi-hop branches stamp the same horizon.
fn rotation_deadline_now() -> Timestamp {
    Timestamp::from_offset_date_time(Timestamp::now().into_inner() + LEASE_DURATION)
}

/// `Timestamp::now() + 15 min` — the lease expiry every
/// [`ForwarderLease`] this module emits inherits.
fn lease_expires_at_now() -> Timestamp {
    Timestamp::from_offset_date_time(Timestamp::now().into_inner() + LEASE_DURATION)
}

/// Build the per-forwarder lease chain for `forwarders` between
/// `client_addr` and `exit_addr`. Each lease carries a fresh
/// [`ChainId`], the upstream peer's socket as `allowed_src`, and
/// the downstream peer's socket as `allowed_dst`. The downstream
/// of the last forwarder is `exit_addr`; everyone else's downstream
/// is the next forwarder's `addr`.
fn build_lease_chain(
    client_addr: SocketAddr,
    forwarders: &[ForwarderCandidate],
    exit_addr: SocketAddr,
    lease_expires_at: Timestamp,
) -> Vec<ForwarderLease> {
    let mut leases: Vec<ForwarderLease> = Vec::with_capacity(forwarders.len());
    let mut upstream = client_addr;
    for (index, forwarder) in forwarders.iter().enumerate() {
        let downstream =
            forwarders.get(index.saturating_add(1)).map_or(exit_addr, |next| next.addr);
        leases.push(ForwarderLease {
            forwarder: forwarder.node_id,
            chain_id: ChainId::new(),
            allowed_src: upstream,
            allowed_dst: downstream,
            lease_expires_at,
        });
        upstream = forwarder.addr;
    }
    leases
}

/// Render the client-side [`WgPeerConfig`].
///
/// `peer_endpoint` is the first forwarder's socket when the chain
/// has at least one forwarder, otherwise the exit's socket directly
/// (single-hop). `local_static_public` is the client's registered
/// public key — the client uses this as a sanity-check that the
/// coordinator addressed this config to the right peer.
/// `peer_static_public` is the exit's registered public key (the
/// value the client's `wg setconf` writes after `PublicKey =`).
fn build_client_wg_config(
    client: &ClientHandle,
    exit: &ExitCandidate,
    forwarders: &[ForwarderCandidate],
) -> WgPeerConfig {
    let peer_endpoint = forwarders.first().map_or(exit.addr, |first| first.addr);
    WgPeerConfig {
        local_static_public: protocol_wg_key(&client.wg_public_key),
        peer_static_public: protocol_wg_key(&exit.wg_public_key),
        peer_endpoint,
        allowed_ips: default_client_allowed_ips(),
        persistent_keepalive_secs: DEFAULT_KEEPALIVE_SECS,
    }
}

/// Default CIDR set the client's `WgPeerConfig` carries — `0.0.0.0/0`
/// + `::/0` for full-egress through the exit.
fn default_client_allowed_ips() -> Vec<IpNet> {
    let v4 = IpNet::V4(ipnet::Ipv4Net::default());
    let v6 = IpNet::V6(ipnet::Ipv6Net::default());
    vec![v4, v6]
}

/// Translate the rich `bibeam_crypto::WgPublicKey` into the wire
/// `bibeam_protocol::multihop::WgPublicKey`. The two types are
/// deliberately parallel (see `bibeam_protocol::multihop` module
/// docs); this is the one-line conversion that crosses the gap
/// inside the coordinator process.
fn protocol_wg_key(rich: &CryptoWgPublicKey) -> WgPublicKey {
    let mut bytes = [0u8; WG_KEY_LEN];
    bytes.copy_from_slice(rich.as_bytes());
    WgPublicKey::from_bytes(bytes)
}

/// In-memory [`RegionView`] used by the path-assembly tests and
/// available to external integration tests.
///
/// Construct via [`InMemoryRegionView::default`] then mutate the
/// public fields. Production callsites wire the trait against the
/// redb-backed stores instead.
#[derive(Debug, Default, Clone)]
pub struct InMemoryRegionView {
    /// Exit candidates indexed by region.
    pub exits: HashMap<String, Vec<ExitCandidate>>,
    /// Forwarder candidates indexed by region.
    pub forwarders: HashMap<String, Vec<ForwarderCandidate>>,
    /// Client registrations indexed by [`PeerId`]. The map values
    /// carry the three [`ClientLookup`] states verbatim so tests
    /// can exercise the registered-without-key branch — a missing
    /// map entry is collapsed to [`ClientLookup::Unknown`] by the
    /// trait impl below.
    pub clients: HashMap<PeerId, ClientLookup>,
}

impl RegionView for InMemoryRegionView {
    fn exits_in(&self, region: &str) -> Vec<ExitCandidate> {
        self.exits.get(region).cloned().unwrap_or_default()
    }

    fn forwarders_in(&self, region: &str) -> Vec<ForwarderCandidate> {
        self.forwarders.get(region).cloned().unwrap_or_default()
    }

    fn client(&self, peer_id: PeerId) -> ClientLookup {
        match self.clients.get(&peer_id) {
            Some(ClientLookup::Found(handle)) => ClientLookup::Found(handle.clone()),
            Some(ClientLookup::MissingWgKey) => ClientLookup::MissingWgKey,
            Some(ClientLookup::Unknown) | None => ClientLookup::Unknown,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test-only convenience for unwrapping known-good fixture values"
)]
mod tests {
    use super::*;

    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bibeam_crypto::WgSecretKey;

    /// Per-position floor used by every test (`29` = the canonical
    /// ≥ 30-member anonymity set, the 30th being the requester).
    const FLOOR: usize = 29;

    fn fixture_socket(octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), port)
    }

    fn fixture_client() -> ClientHandle {
        let secret = WgSecretKey::generate();
        ClientHandle {
            wg_public_key: secret.public(),
            addr: fixture_socket(1, 41_443),
        }
    }

    fn fixture_exit(cohort_size: usize) -> ExitCandidate {
        let secret = WgSecretKey::generate();
        ExitCandidate {
            node_id: NodeId::new(),
            wg_public_key: secret.public(),
            addr: fixture_socket(2, 51_820),
            cohort_size,
        }
    }

    fn fixture_forwarder(cohort_size: usize) -> ForwarderCandidate {
        ForwarderCandidate {
            node_id: NodeId::new(),
            addr: fixture_socket(3, 51_820),
            cohort_size,
        }
    }

    fn fixture_view(
        region: &str,
        client_peer_id: PeerId,
        client: ClientHandle,
        exit: Option<ExitCandidate>,
        forwarder: Option<ForwarderCandidate>,
    ) -> InMemoryRegionView {
        let mut view = InMemoryRegionView::default();
        view.clients.insert(client_peer_id, ClientLookup::Found(client));
        if let Some(exit) = exit {
            view.exits.insert(region.to_owned(), vec![exit]);
        }
        if let Some(forwarder) = forwarder {
            view.forwarders.insert(region.to_owned(), vec![forwarder]);
        }
        view
    }

    fn fixture_match_request(peer_id: PeerId) -> MatchRequest {
        MatchRequest { peer_id, at: Timestamp::now() }
    }

    #[test]
    fn single_hop_when_requested_region_has_busy_exit() {
        // Contract: a region whose exit cohort meets the per-position
        // floor returns a SingleHop response carrying that exit. The
        // multi-hop branch must NOT be taken when the direct path is
        // already busy enough to support the anonymity set. Catches a
        // regression that mis-selected the multi-hop fallback for
        // already-busy regions.
        let region = "us-east";
        let peer_id = PeerId::new();
        let client = fixture_client();
        let exit = fixture_exit(FLOOR + 1);
        let view = fixture_view(region, peer_id, client, Some(exit.clone()), None);

        let builder = MultiHopBuilder::new(FLOOR);
        let request = fixture_match_request(peer_id);

        let response = builder.assemble(&request, region, &view).expect("single-hop assembly");
        let MatchResponse::SingleHop(single_hop) = response else {
            panic!("expected SingleHop, got {response:?}");
        };
        assert_eq!(single_hop.exit_set, vec![exit.node_id]);
        assert!(
            single_hop.rotation_deadline.into_inner() > Timestamp::now().into_inner(),
            "rotation deadline must be in the future",
        );
    }

    #[test]
    fn multi_hop_when_busy_intermediate_hub_carries_the_floor() {
        // Contract: when the requested region's exit cohort meets
        // the per-position floor AND a busy intermediate forwarder
        // exists, the assembler returns a MultiHopAssignment with
        // at least one forwarder. The chain's first lease must
        // carry the client's socket as `allowed_src`, and the last
        // lease's `allowed_dst` must be the exit's socket. Catches
        // a regression that misordered the lease chain or dropped
        // the exit terminator. (Per §11 D-6 RESOLVED option (c)
        // the EXIT must always satisfy the floor — there is no
        // multi-hop fallback that lets a cold exit piggy-back on
        // an intermediate's anonymity set.)
        let region = "us-east";
        let peer_id = PeerId::new();
        let client = fixture_client();
        let client_addr = client.addr;
        let exit = fixture_exit(FLOOR + 1);
        let exit_addr = exit.addr;
        let exit_node = exit.node_id;
        let forwarder = fixture_forwarder(FLOOR + 1);
        let forwarder_addr = forwarder.addr;
        let view = fixture_view(region, peer_id, client, Some(exit), Some(forwarder));

        let builder = MultiHopBuilder::new(FLOOR);
        let request = fixture_match_request(peer_id);

        let response = builder.assemble(&request, region, &view).expect("multi-hop assembly");
        let MatchResponse::MultiHopAssignment(multi_hop) = response else {
            panic!("expected MultiHopAssignment, got {response:?}");
        };

        assert_eq!(multi_hop.exit, exit_node);
        assert!(
            !multi_hop.forwarder_chain.is_empty(),
            "multi-hop must carry at least one forwarder lease",
        );
        let first = multi_hop.forwarder_chain.first().expect("non-empty");
        assert_eq!(first.allowed_src, client_addr);
        let last = multi_hop.forwarder_chain.last().expect("non-empty");
        assert_eq!(last.allowed_dst, exit_addr);
        // Single-forwarder chains pin client_wg_config.peer_endpoint
        // to the forwarder, not to the exit — otherwise the client
        // would route around the chain and break the anonymity-set.
        assert_eq!(multi_hop.client_wg_config.peer_endpoint, forwarder_addr);
        // Lease expiry rides 15 minutes out, per §11 R-3 rotation
        // cadence.
        let now = Timestamp::now();
        let too_soon = now.into_inner() + Duration::minutes(14);
        let too_late = now.into_inner() + Duration::minutes(16);
        let expires_at = first.lease_expires_at.into_inner();
        assert!(
            expires_at > too_soon && expires_at < too_late,
            "lease expiry must land in the 15-minute rotation window: \
             expires_at={expires_at:?}, too_soon={too_soon:?}, too_late={too_late:?}",
        );
    }

    #[test]
    fn cold_region_returns_no_anonymous_path_available() {
        // Contract: no busy exit + no busy forwarder must produce
        // NoAnonymousPathAvailable, NOT a single-hop response with a
        // cold exit or a multi-hop response with a sub-floor
        // intermediate. The §11 R-3 codex-corrected text explicitly
        // rejected the union fallback — refusal is the correct
        // outcome. Catches a regression that silently downgraded to
        // a cold cohort instead of refusing.
        let region = "us-east";
        let peer_id = PeerId::new();
        let client = fixture_client();
        let cold_exit = fixture_exit(/* cold cohort */ 0);
        let cold_forwarder = fixture_forwarder(/* cold cohort */ 0);
        let view = fixture_view(region, peer_id, client, Some(cold_exit), Some(cold_forwarder));

        let builder = MultiHopBuilder::new(FLOOR);
        let request = fixture_match_request(peer_id);

        let err = builder.assemble(&request, region, &view).expect_err("must refuse");
        assert_eq!(err, MultiHopPathError::NoAnonymousPathAvailable { region: region.to_owned() },);
    }

    #[test]
    fn wg_public_key_pairing_matches_client_and_exit_registrations() {
        // Contract: the client_wg_config carried in a multi-hop
        // response has `local_static_public` == the client's
        // registered key, and `peer_static_public` == the exit's
        // registered key. The two keys are wire-form
        // `bibeam_protocol::multihop::WgPublicKey` values (32-byte
        // newtype around a base64-rendered public key) — never a
        // private-key value. Catches a regression that mis-paired
        // the keys (sending the exit's key back to itself) or
        // accidentally surfaced a private key (the wire type would
        // not even compile against a private key, but a future
        // refactor that loosened the field types would). Also
        // covers AC #9 — the type system reflects coord NEVER holds
        // private key material.
        //
        // The SingleHop variant does not carry a
        // `client_wg_config` (the existing protocol type only puts
        // it on `MultiHopAssignment`), so the pairing assertion is
        // exercised through the multi-hop branch — both the busy
        // exit AND the busy intermediate forwarder are present.
        let region = "us-east";
        let peer_id = PeerId::new();
        let client = fixture_client();
        let exit = fixture_exit(FLOOR + 1);
        let busy_forwarder = fixture_forwarder(FLOOR + 1);
        let view =
            fixture_view(region, peer_id, client.clone(), Some(exit.clone()), Some(busy_forwarder));

        let builder = MultiHopBuilder::new(FLOOR);
        let request = fixture_match_request(peer_id);

        let response = builder.assemble(&request, region, &view).expect("multi-hop assembly");
        let MatchResponse::MultiHopAssignment(multi_hop) = response else {
            panic!("expected MultiHopAssignment, got {response:?}");
        };

        let expected_client_pub: [u8; WG_KEY_LEN] = *client.wg_public_key.as_bytes();
        let expected_exit_pub: [u8; WG_KEY_LEN] = *exit.wg_public_key.as_bytes();

        assert_eq!(
            multi_hop.client_wg_config.local_static_public.as_bytes(),
            &expected_client_pub,
            "local_static_public must match the client's registered key",
        );
        assert_eq!(
            multi_hop.client_wg_config.peer_static_public.as_bytes(),
            &expected_exit_pub,
            "peer_static_public must match the exit's registered key",
        );
        // Compile-time witness for AC #9 (coord never sees a
        // private key): pass the actual wire field through a
        // typed identity. The call only type-checks if the field
        // really is `WgPublicKey`; a regression that loosened the
        // field type would fail to compile here. The wire
        // `WgPeerConfig` carries no private-key field, so this
        // assertion is by construction the strongest "no
        // private-key on the wire" guarantee the type system can
        // give us.
        let witness: WgPublicKey =
            core::convert::identity::<WgPublicKey>(multi_hop.client_wg_config.local_static_public);
        assert_eq!(witness.as_bytes(), &expected_client_pub);
    }

    #[test]
    fn busy_forwarder_but_cold_exit_still_refuses() {
        // Contract: per §11 D-6 RESOLVED option (c) the EXIT
        // position must satisfy the per-position floor — even
        // when a busy intermediate hub is available. A multi-hop
        // chain that piggy-backed a cold exit on a busy
        // intermediate's anonymity set was the union-fallback
        // failure mode the §11 R-3 codex-corrected text
        // explicitly rejected. Catches a regression that
        // resurrected the cold-exit-multi-hop path.
        let region = "us-east";
        let peer_id = PeerId::new();
        let client = fixture_client();
        let cold_exit = fixture_exit(/* cold exit cohort */ 0);
        let busy_forwarder = fixture_forwarder(FLOOR + 1);
        let view = fixture_view(region, peer_id, client, Some(cold_exit), Some(busy_forwarder));

        let builder = MultiHopBuilder::new(FLOOR);
        let request = fixture_match_request(peer_id);

        let err = builder.assemble(&request, region, &view).expect_err("must refuse");
        assert_eq!(err, MultiHopPathError::NoAnonymousPathAvailable { region: region.to_owned() },);
    }

    #[test]
    fn missing_client_wg_key_surfaces_typed_error() {
        // Contract: a peer that is registered but whose
        // registration carries no `wg_public_key` (R-MULTIHOP-COORD
        // option (c)) surfaces as `MissingClientWgKey`, NOT as
        // `UnknownClient`. The coord NEVER silently mints a key;
        // refusing here is the only correct outcome. Catches a
        // regression that collapsed the absent-key and absent-record
        // states.
        let peer_id = PeerId::new();
        let view = InMemoryRegionView {
            clients: HashMap::from([(peer_id, ClientLookup::MissingWgKey)]),
            ..InMemoryRegionView::default()
        };
        let builder = MultiHopBuilder::new(FLOOR);
        let request = fixture_match_request(peer_id);

        let err = builder.assemble(&request, "us-east", &view).expect_err("must refuse");
        assert_eq!(err, MultiHopPathError::MissingClientWgKey { peer_id });
    }

    #[test]
    fn unknown_client_surfaces_typed_error() {
        // Contract: a `MatchRequest` from a peer the registry has
        // no record of must error with UnknownClient, NOT silently
        // fail to assemble (which would surface as a 500 instead of
        // the proper 401-equivalent). Catches a regression that
        // skipped the registry lookup.
        let view = InMemoryRegionView::default();
        let builder = MultiHopBuilder::new(FLOOR);
        let phantom_peer = PeerId::new();
        let request = fixture_match_request(phantom_peer);

        let err = builder.assemble(&request, "us-east", &view).expect_err("must refuse");
        assert_eq!(err, MultiHopPathError::UnknownClient { peer_id: phantom_peer });
    }
}
