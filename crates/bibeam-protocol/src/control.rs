#![forbid(unsafe_code)]
//! Control-plane messages exchanged with the coordinator.
//!
//! Peers register with the coordinator, ask it to match them into a
//! cohort, then keep the registration alive with heartbeats until they
//! either rotate to a new cohort or disconnect. Each of those steps is
//! represented by one struct in this module; [`ControlMessage`] is the
//! tagged sum that travels inside [`crate::frame::Frame::Control`].
//!
//! Per the project threat model the coordinator is semi-trusted: it is
//! authenticated and rate-limited, but it never sees plaintext tunnel
//! payloads. Every shape here is therefore part of the public, signed
//! control plane and intentionally carries no secret material — the
//! one apparent exception, [`RegisterAck::session_token`], holds a
//! PASETO v4 token that is itself self-contained and verifiable.
//!
//! All timestamps use [`Timestamp`], which round-trips through RFC 3339
//! on the wire (see `bibeam_core::time`).

use std::collections::HashMap;
use std::net::SocketAddr;

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::multihop::{ForwarderLease, MultiHopAssignmentError, WgPeerConfig};

/// Initial registration message a peer sends to the coordinator.
///
/// `addr_hint` is the address the peer advertises for inbound
/// connections; the coordinator may override or augment it with what
/// it sees at the socket level. `can_exit` advertises willingness to
/// serve as an exit node for other peers. `capacity_hint` is an
/// opaque, peer-supplied score the coordinator may use as one input
/// to match-making.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// Identifier of the registering peer.
    pub peer_id: PeerId,
    /// Address the peer advertises for inbound connections.
    pub addr_hint: SocketAddr,
    /// Whether this peer is willing to serve as an exit node.
    pub can_exit: bool,
    /// Peer-supplied capacity score; opaque to the coordinator.
    pub capacity_hint: u32,
    /// When the peer captured this registration.
    pub at: Timestamp,
}

/// Coordinator's acknowledgement of a successful [`Register`].
///
/// `session_token` is a PASETO v4 token issued by the coordinator (see
/// F-CRYPTO.4). Its claim set is the shape declared in
/// [`crate::claims::SessionClaims`]. `expires_at` is duplicated here so
/// peers do not have to parse the token to find out when to renew.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAck {
    /// PASETO v4 session token issued by the coordinator.
    pub session_token: Bytes,
    /// Wall-clock instant after which `session_token` will be rejected.
    pub expires_at: Timestamp,
}

/// Peer-initiated request to be matched into a cohort.
///
/// Sent after a successful [`Register`] and any time the peer wants a
/// fresh cohort (for example after a cohort rotation — see F-PROTO.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRequest {
    /// Identifier of the requesting peer.
    pub peer_id: PeerId,
    /// When the peer captured this request.
    pub at: Timestamp,
}

/// Single-hop match: cohort + canonical exit set + rotation deadline.
///
/// `cohort` identifies the cohort the peer should join. `exit_set` is
/// the canonical list of exit nodes for that cohort; the peer should
/// route through one of them. `rotation_deadline` tells the peer when
/// it must request a fresh cohort.
///
/// This is the pre-multihop shape — the peer routes directly to one
/// of the listed exits without an intermediate forwarder chain. Lives
/// inside the [`MatchResponse::SingleHop`] variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleHopMatch {
    /// Cohort the peer should join.
    pub cohort: CohortId,
    /// Exit nodes serving traffic for `cohort`.
    pub exit_set: Vec<NodeId>,
    /// Per-exit operator-tagged region tag, indexed by [`NodeId`] from
    /// [`Self::exit_set`]. Same free-form string shape as
    /// [`bibeam_core::Timestamp`]-companion `bibeam_discovery::ExitRecord::region`
    /// (R-REGION.1). The coordinator copies the tag verbatim from the
    /// discovery record at admission / drain time (R-REGION.3). Missing
    /// entries mean "region unknown for that exit"; the client's
    /// region-aware exit picker (F-CLI.4b) MUST treat a missing tag as
    /// a non-match, never as a wildcard.
    ///
    /// Defaults to an empty map for backward-compat: a coord that has
    /// not been upgraded ships an empty map, and the client's
    /// `pick_exit(.., Some(region), ..)` then refuses with `None` —
    /// matching the §11 R-3 "no exit in `<region>`; defer / fallback to
    /// multi-hop" semantics.
    #[serde(default)]
    pub exit_regions: HashMap<NodeId, String>,
    /// Wall-clock instant at which the peer must rotate.
    pub rotation_deadline: Timestamp,
}

/// Multi-hop match: client routes through a chain of forwarders to an
/// exit (R-MULTIHOP-PROTO).
///
/// Carries everything the client needs to bring its `WireGuard` session
/// up — the public side of the client↔exit session plus the
/// per-forwarder lease rows the forwarders need to authorise the
/// relayed packets.
///
/// # Structural invariants (unrepresentable invalid states)
///
/// - **Non-empty chain.** [`Self::forwarder_chain`] holds at least one
///   [`ForwarderLease`]; multi-hop with zero forwarders is by
///   definition the single-hop case, which lives in
///   [`MatchResponse::SingleHop`]. Validated on deserialize via a
///   `serde(try_from = ...)` shim that surfaces an empty chain as a
///   [`MultiHopAssignmentError::EmptyChain`] inside the standard
///   postcard / serde error path.
/// - **Forwarder ↔ lease binding by construction.** Each chain entry
///   IS a [`ForwarderLease`], so the [`ForwarderLease::forwarder`]
///   `NodeId` and its lease row are one element — no parallel `Vec`s,
///   no positional-alignment bug surface. The flow direction is the
///   `Vec`'s order: traffic enters `forwarder_chain[0]`, hops through
///   each successor, and exits the chain at `forwarder_chain[last]`'s
///   downstream socket (which terminates on [`Self::exit`]).
///
/// See [`crate::multihop`] for the on-the-wire packet-to-lease binding
/// mechanism (chosen: option (B), explicit relay framing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MultiHopAssignmentWire")]
pub struct MultiHopAssignment {
    /// Final exit serving the client's traffic.
    pub exit: NodeId,
    /// Ordered forwarder chain between the client and `exit`.
    ///
    /// The client sends its outbound `WireGuard` packets to
    /// `forwarder_chain[0]`'s upstream socket; each forwarder relays
    /// to the next; the last entry relays to `exit`. Non-empty by
    /// construction — see the type-level invariants section.
    pub forwarder_chain: Vec<ForwarderLease>,
    /// Client-facing `WireGuard` peer config for the client↔exit
    /// session.
    pub client_wg_config: WgPeerConfig,
}

/// Wire-shape twin of [`MultiHopAssignment`].
///
/// `serde` deserialises every [`MatchResponse::MultiHopAssignment`]
/// frame into this shape first, then runs [`Self::try_into`]; if the
/// resulting [`MultiHopAssignment`] would violate a structural
/// invariant (currently: empty `forwarder_chain`), the conversion
/// surfaces a [`MultiHopAssignmentError`] which serde reports as a
/// deserialize failure. The two types share the same on-the-wire
/// layout because the field set and order match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MultiHopAssignmentWire {
    pub exit: NodeId,
    pub forwarder_chain: Vec<ForwarderLease>,
    pub client_wg_config: WgPeerConfig,
}

impl TryFrom<MultiHopAssignmentWire> for MultiHopAssignment {
    type Error = MultiHopAssignmentError;

    fn try_from(wire: MultiHopAssignmentWire) -> Result<Self, Self::Error> {
        if wire.forwarder_chain.is_empty() {
            return Err(MultiHopAssignmentError::EmptyChain);
        }
        Ok(Self {
            exit: wire.exit,
            forwarder_chain: wire.forwarder_chain,
            client_wg_config: wire.client_wg_config,
        })
    }
}

/// Coordinator's response to a [`MatchRequest`].
///
/// Two shapes — the direct single-hop case ([`MatchResponse::SingleHop`])
/// and the multi-hop case ([`MatchResponse::MultiHopAssignment`]) — share
/// one variant family so the wire shape stays a single tagged sum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchResponse {
    /// Direct single-hop assignment: peer routes straight to one of
    /// the cohort's exit nodes.
    SingleHop(SingleHopMatch),
    /// Multi-hop assignment: peer routes through a chain of forwarders
    /// before reaching the exit.
    MultiHopAssignment(MultiHopAssignment),
}

/// Peer-to-coordinator keep-alive.
///
/// A peer sends one [`Heartbeat`] per session interval. Missing
/// heartbeats let the coordinator garbage-collect dead registrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Identifier of the peer sending the heartbeat.
    pub peer_id: PeerId,
    /// When the peer captured this heartbeat.
    pub at: Timestamp,
}

/// Voluntary disconnect notification.
///
/// Sent by a peer cleanly leaving the mesh so the coordinator can
/// remove its registration without waiting for the heartbeat timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disconnect {
    /// Identifier of the disconnecting peer.
    pub peer_id: PeerId,
    /// Human-readable disconnect reason for the coordinator's logs.
    pub reason: String,
    /// When the peer captured this disconnect.
    pub at: Timestamp,
}

/// Tagged sum of every control-plane message.
///
/// Wrapped by [`crate::frame::Frame::Control`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Initial peer registration.
    Register(Register),
    /// Acknowledgement of a successful registration.
    RegisterAck(RegisterAck),
    /// Request to be matched into a cohort.
    MatchRequest(MatchRequest),
    /// Response carrying the matched cohort and its exit set.
    MatchResponse(MatchResponse),
    /// Periodic keep-alive.
    Heartbeat(Heartbeat),
    /// Voluntary disconnect notification.
    Disconnect(Disconnect),
}
