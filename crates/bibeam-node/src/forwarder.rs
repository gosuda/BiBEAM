#![forbid(unsafe_code)]
//! Intermediate-node stateful UDP forwarder (R-MULTIHOP-NODE).
//!
//! Per §11 D-6 RESOLVED option (c) cascading-edits and the §11 R-4
//! architecture, an intermediate `bibeam-node` may run in **forwarder
//! mode**: a pure UDP byte-pump that relays
//! [`bibeam_protocol::RelayFrame`] datagrams between a coord-authorised
//! upstream and downstream peer, gated by a per-pair routing table
//! whose rows expire on a coord-issued lease.
//!
//! ## State machine
//!
//! [`Forwarder`] holds a [`parking_lot::RwLock`] over a
//! [`std::collections::HashMap`] keyed by [`bibeam_core::ChainId`]
//! (option (B) packet-to-lease binding from R-MULTIHOP-PROTO). One
//! entry per active chain × leases not yet expired, bounded by the
//! lease-expiry sweep that runs every [`LEASE_SWEEP_INTERVAL`].
//!
//! ## Trust boundary
//!
//! The forwarder NEVER decrypts a [`bibeam_protocol::RelayFrame`]'s
//! opaque payload; NEVER parses a `WireGuard` transport header; NEVER
//! holds any WG static key, PSK, or AEAD primitive. This module's
//! source file is grep-gated against any reference to that material
//! (see the verify command in the R-MULTIHOP-NODE task). The lookup
//! key is the coord-issued chain identifier carried in the first 16
//! bytes of every relay datagram — a value the forwarder treats as
//! opaque.
//!
//! ## Direction
//!
//! Direction is determined by the observed UDP source address of an
//! inbound datagram, matched against the chain's row:
//!
//! - Source matches `allowed_src` → upstream (forward to
//!   `allowed_dst`).
//! - Source matches `allowed_dst` → downstream (forward to
//!   `allowed_src` — return traffic from the next hop).
//! - Anything else → drop with the `src_mismatch` reason on the
//!   packets-dropped counter.
//!
//! ## Forward layout
//!
//! The relay frame is forwarded UNCHANGED: the forwarder peeks the
//! first 16 bytes to learn the chain id, looks the row up, then
//! `send_to`s the full received buffer onto the chosen endpoint. The
//! next forwarder (if any) repeats the same lookup against its own
//! routing table; the destination peer (an exit or a client) decodes
//! the frame in its receive loop.
//!
//! ## Metrics
//!
//! Exported via the existing [`bibeam_runtime`] Prometheus
//! exposition (`metrics_router`):
//!
//! - `bibeam_forwarder_packets_in_total{direction}`
//! - `bibeam_forwarder_packets_out_total{direction}`
//! - `bibeam_forwarder_packets_dropped_total{reason}`
//! - `bibeam_forwarder_active_chains` (gauge)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bibeam_core::{ChainId, Timestamp};
use bibeam_protocol::{ForwarderLease, RELAY_FRAME_PREFIX_LEN};
use parking_lot::RwLock;
use serde::Deserialize;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// `[forwarder]` config block for `bibeam-node`.
///
/// Operators enable the forwarder role by setting `enabled = true`
/// and supplying a `bind_addr`; both other fields default to the
/// values documented below.
///
/// # Example TOML
///
/// ```toml
/// [forwarder]
/// enabled = true
/// bind_addr = "0.0.0.0:51820"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ForwarderConfig {
    /// Whether the forwarder mode is mounted at all.
    ///
    /// When `false`, [`Forwarder::run`] is never started; the binary
    /// behaves as if this config block were absent. The flag exists so
    /// a deployment can ship the same TOML to every node and still
    /// keep a node out of the forwarder role.
    #[serde(default)]
    pub enabled: bool,
    /// UDP socket the forwarder binds for inbound relay frames.
    ///
    /// Should typically be a public-facing port (the coordinator hands
    /// this address to upstream peers as part of their
    /// [`ForwarderLease::allowed_dst`]) — but the type system does not
    /// enforce that, since the operator may also front the socket
    /// behind a load balancer or NAT.
    pub bind_addr: SocketAddr,
}

impl ForwarderConfig {
    /// Build a config with `enabled = true` and a caller-supplied
    /// `bind_addr`.
    ///
    /// Useful for tests and main-binary code that builds the config
    /// directly rather than going through `figment`.
    #[must_use]
    pub const fn new(bind_addr: SocketAddr) -> Self {
        Self { enabled: true, bind_addr }
    }
}

/// Default interval at which [`Forwarder::run`] sweeps expired
/// routing-table entries.
///
/// Picked so a 15-minute lease (the typical
/// [`ForwarderLease::lease_expires_at`] value the coordinator
/// issues) is observable as expired within 30 seconds of its
/// nominal end — short enough that a torn-down chain stops
/// relaying promptly, long enough that the sweep does not become
/// a hot lock on the routing table.
pub const LEASE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum UDP datagram the forwarder will accept off the wire.
///
/// Sized to the theoretical maximum UDP payload (`65_535` minus the
/// 8-byte UDP header) so the kernel cannot silently truncate any
/// datagram that arrives on the bind socket. The forwarder's
/// "forward UNCHANGED" contract depends on observing every byte the
/// upstream peer sent — a buffer sized to the typical `WireGuard`
/// MTU would silently corrupt jumbo-frame or IPv6-PMTUD-failed
/// flows. Pre-allocating the buffer once outside the recv loop
/// keeps the cost a single per-task vector, not per-packet. A UDP
/// payload cannot exceed this length on the wire (the 16-bit UDP
/// length field caps it), so no legitimate datagram can be silently
/// truncated by a buffer of this size.
const FORWARDER_RECV_BUFFER_LEN: usize = 65_527;

/// Prometheus metric name: total relay datagrams the forwarder
/// received off the bind socket.
///
/// Labelled by `direction = "upstream" | "downstream"`. Counted *after*
/// the chain-id lookup decided which side a packet came in on; a
/// datagram with no matching chain row is counted under
/// [`FORWARDER_PACKETS_DROPPED_TOTAL`] instead.
pub const FORWARDER_PACKETS_IN_TOTAL: &str = "bibeam_forwarder_packets_in_total";

/// Prometheus metric name: total relay datagrams the forwarder
/// successfully forwarded onto a downstream / upstream peer.
///
/// Labelled by `direction = "upstream" | "downstream"`. A non-zero
/// `packets_in - packets_out` (per direction) indicates either a
/// drop after lookup-success (network error on `send_to`) or a
/// lease that expired between match and forward.
pub const FORWARDER_PACKETS_OUT_TOTAL: &str = "bibeam_forwarder_packets_out_total";

/// Prometheus metric name: total relay datagrams the forwarder
/// dropped before forwarding.
///
/// Labelled by `reason`:
///
/// - `unknown_chain` — chain id has no row in the routing table.
/// - `src_mismatch` — source address matched neither the row's
///   `allowed_src` nor `allowed_dst`.
/// - `expired_lease` — the row's `lease_expires_at` is in the past
///   (and the sweep had not yet evicted it).
/// - `other` — any other reason (decode failure, frame too short,
///   socket-send failure after match).
pub const FORWARDER_PACKETS_DROPPED_TOTAL: &str = "bibeam_forwarder_packets_dropped_total";

/// Prometheus metric name: current number of chains in the
/// forwarder's routing table.
///
/// Set after every insert and after every sweep. Useful as a coarse
/// liveness signal: a coordinator that has issued no leases will see
/// this gauge stay at zero.
pub const FORWARDER_ACTIVE_CHAINS: &str = "bibeam_forwarder_active_chains";

/// Failure modes when constructing a [`Forwarder`].
#[derive(Debug, Error)]
pub enum ForwarderError {
    /// Binding the UDP socket failed — typically because the port
    /// is already in use, the address is not assigned to a local
    /// interface, or the operator lacks `CAP_NET_BIND_SERVICE` on
    /// a privileged port.
    #[error("forwarder: bind udp: {0}")]
    Bind(#[source] std::io::Error),
}

/// One entry in the per-chain routing table.
///
/// Inserted by [`Forwarder::insert_lease`] from a coord-issued
/// [`ForwarderLease`]; evicted either by the periodic
/// [`Forwarder::sweep_expired`] (lease expiry) or by an overwrite
/// from a renewal lease with the same `chain_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingEntry {
    /// Upstream peer for this chain — the client side for hop 1,
    /// the previous forwarder for inner hops.
    pub allowed_src: SocketAddr,
    /// Downstream peer for this chain — the next forwarder, or the
    /// exit for the last hop.
    pub allowed_dst: SocketAddr,
    /// Wall-clock instant after which the row MUST be removed.
    pub lease_expires_at: Timestamp,
}

impl From<&ForwarderLease> for RoutingEntry {
    fn from(lease: &ForwarderLease) -> Self {
        Self {
            allowed_src: lease.allowed_src,
            allowed_dst: lease.allowed_dst,
            lease_expires_at: lease.lease_expires_at,
        }
    }
}

/// Direction inferred for one inbound datagram.
///
/// Used as the `direction` label on the inbound / outbound counters
/// and to pick the forward target after a successful chain-id lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// Datagram came from the chain's `allowed_src` — forward to
    /// `allowed_dst`.
    Upstream,
    /// Datagram came from the chain's `allowed_dst` (return traffic
    /// from the next hop) — forward to `allowed_src`.
    Downstream,
}

impl Direction {
    /// String label used on the `direction` Prometheus label.
    const fn as_label(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Downstream => "downstream",
        }
    }
}

/// Reason a relay datagram was dropped before forwarding.
///
/// Maps 1:1 to the `reason` Prometheus label on
/// [`FORWARDER_PACKETS_DROPPED_TOTAL`]. Kept as a private enum so
/// the only public surface is the metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropReason {
    /// The frame's chain id has no row in the routing table.
    UnknownChain,
    /// The frame's source address matched neither
    /// [`RoutingEntry::allowed_src`] nor
    /// [`RoutingEntry::allowed_dst`].
    SrcMismatch,
    /// The matched row's [`RoutingEntry::lease_expires_at`] is in
    /// the past.
    ExpiredLease,
    /// Any other drop — frame decode failure, socket send failure
    /// after match, or buffer-too-short for the 16-byte chain-id
    /// prefix.
    Other,
}

impl DropReason {
    /// String label used on the `reason` Prometheus label.
    const fn as_label(self) -> &'static str {
        match self {
            Self::UnknownChain => "unknown_chain",
            Self::SrcMismatch => "src_mismatch",
            Self::ExpiredLease => "expired_lease",
            Self::Other => "other",
        }
    }
}

/// Outcome of evaluating one inbound datagram against the routing
/// table.
///
/// Returned by [`Forwarder::evaluate`]; the run-loop consumes it
/// into either a `send_to` call (forward) or a metric increment
/// (drop). Carrying the decision in a typed enum keeps the
/// run-loop body under the cognitive-complexity threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ForwardDecision {
    /// Forward the inbound buffer unchanged to `target`, labelled
    /// with `direction`.
    Forward {
        /// UDP target to forward the datagram to.
        target: SocketAddr,
        /// Direction inferred — used as the `direction` label.
        direction: Direction,
    },
    /// Drop the datagram with the given reason.
    Drop(DropReason),
}

/// Stateful UDP forwarder bound to a single UDP socket.
///
/// Construct with [`Forwarder::bind`], then either:
///
/// 1. Call [`Forwarder::insert_lease`] / [`Forwarder::sweep_expired`]
///    from the test or main wiring directly, or
/// 2. Spawn [`Forwarder::run`] on a tokio task and feed leases through
///    [`Forwarder::insert_lease`] from the coord-WS event handler.
///
/// The struct is cheap to clone — the routing table sits behind an
/// [`Arc`] / [`RwLock`] and the [`UdpSocket`] is reference-counted by
/// tokio. Cloning is the intended way to share a handle between the
/// run-loop task and the lease-ingestion task without funnelling
/// every insert through an mpsc.
#[derive(Clone)]
pub struct Forwarder {
    socket: Arc<UdpSocket>,
    routing: Arc<RwLock<HashMap<ChainId, RoutingEntry>>>,
}

impl core::fmt::Debug for Forwarder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let table_len = self.routing.read().len();
        formatter
            .debug_struct("Forwarder")
            .field("bind_addr", &self.socket.local_addr().ok())
            .field("active_chains", &table_len)
            .finish()
    }
}

impl Forwarder {
    /// Bind the forwarder's UDP socket and return a handle with an
    /// empty routing table.
    ///
    /// # Errors
    ///
    /// Returns [`ForwarderError::Bind`] when the UDP `bind` call
    /// fails (port in use, address not local, missing capability).
    pub async fn bind(bind_addr: SocketAddr) -> Result<Self, ForwarderError> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(ForwarderError::Bind)?;
        Ok(Self {
            socket: Arc::new(socket),
            routing: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Local address the forwarder is bound to.
    ///
    /// Convenience accessor over [`UdpSocket::local_addr`]; the
    /// coordinator hands this value to upstream peers as their
    /// [`ForwarderLease::allowed_dst`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] from
    /// [`UdpSocket::local_addr`] — only possible if the socket has
    /// been closed out from under the handle.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Insert (or replace) the routing-table row for `lease.chain_id`.
    ///
    /// Repeated calls with the same `chain_id` overwrite — that is
    /// the coordinator's lease-renewal semantics from
    /// [`ForwarderLease`]'s docstring. The active-chains gauge is
    /// updated after the write.
    pub fn insert_lease(&self, lease: &ForwarderLease) {
        let entry = RoutingEntry::from(lease);
        let table_len = {
            let mut table = self.routing.write();
            table.insert(lease.chain_id, entry);
            table.len()
        };
        publish_active_chains(table_len);
    }

    /// Remove every row whose `lease_expires_at` is strictly older
    /// than `now`. Returns the count of evicted entries.
    ///
    /// Called periodically by [`Forwarder::run`] on the
    /// [`LEASE_SWEEP_INTERVAL`] cadence; exposed publicly so tests
    /// can drive eviction without waiting on wall-clock time.
    pub fn sweep_expired(&self, now: Timestamp) -> usize {
        let (evicted, table_len) = sweep_under_lock(&self.routing, now);
        publish_active_chains(table_len);
        evicted
    }

    /// Number of routing-table rows currently held.
    ///
    /// Exposed for inspection in tests and the binary's health
    /// endpoint; the same value drives the active-chains gauge.
    pub fn active_chains(&self) -> usize {
        self.routing.read().len()
    }

    /// Run the forwarder until `cancel` fires.
    ///
    /// The loop receives one datagram at a time, evaluates it
    /// against the routing table, and either forwards it or
    /// increments a drop counter. A wall-clock ticker drives the
    /// expired-lease sweep at [`LEASE_SWEEP_INTERVAL`].
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] only when the UDP socket itself
    /// errors out in a non-recoverable way; transient errors on
    /// individual `recv_from` / `send_to` calls are logged and
    /// counted under [`FORWARDER_PACKETS_DROPPED_TOTAL`] with the
    /// `reason = "other"` label, so a noisy peer cannot tear the
    /// loop down.
    pub async fn run(&self, cancel: CancellationToken) -> std::io::Result<()> {
        let mut buf = vec![0u8; FORWARDER_RECV_BUFFER_LEN];
        let mut sweep = tokio::time::interval(LEASE_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The first tick fires immediately by default; skip it so we
        // do not sweep an empty table at startup. The lease-sweep
        // interval is dominated by the lease lifetime (15 min); one
        // missed startup sweep is negligible.
        sweep.tick().await;
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                instant = sweep.tick() => {
                    let _ = instant;
                    self.sweep_expired(Timestamp::now());
                },
                recv = self.socket.recv_from(&mut buf) => {
                    match recv {
                        Ok((len, src)) => self.handle_inbound(&buf[..len], src).await,
                        Err(error) => {
                            tracing::warn!(target: "bibeam_forwarder", %error, "recv_from error");
                            metrics::counter!(
                                FORWARDER_PACKETS_DROPPED_TOTAL,
                                "reason" => DropReason::Other.as_label(),
                            ).increment(1);
                        },
                    }
                },
            }
        }
    }

    /// Evaluate one inbound datagram and either forward it or count
    /// the drop.
    ///
    /// Extracted from [`Forwarder::run`] so the run-loop body stays
    /// under the cognitive-complexity threshold. The same call is
    /// driven directly by tests that want to exercise the
    /// decision-and-forward path without spawning the full task.
    async fn handle_inbound(&self, payload: &[u8], src: SocketAddr) {
        let decision = self.evaluate(payload, src, Timestamp::now());
        self.act_on_decision(payload, decision).await;
    }

    /// Decide what to do with `payload` received from `src` at `now`.
    ///
    /// Pure function on the routing-table snapshot, separated from
    /// the side-effecting send / metric paths so each branch can be
    /// unit-tested directly. The lock is held only for the table
    /// read; the decision struct is returned by value.
    fn evaluate(&self, payload: &[u8], src: SocketAddr, now: Timestamp) -> ForwardDecision {
        let Some(chain_id) = peek_chain_id(payload) else {
            return ForwardDecision::Drop(DropReason::Other);
        };
        let Some(entry) = self.routing.read().get(&chain_id).cloned() else {
            return ForwardDecision::Drop(DropReason::UnknownChain);
        };
        let direction = classify_direction(src, &entry);
        let Some(direction) = direction else {
            return ForwardDecision::Drop(DropReason::SrcMismatch);
        };
        if entry.lease_expires_at.as_offset_date_time() < now.as_offset_date_time() {
            return ForwardDecision::Drop(DropReason::ExpiredLease);
        }
        let target = match direction {
            Direction::Upstream => entry.allowed_dst,
            Direction::Downstream => entry.allowed_src,
        };
        ForwardDecision::Forward { target, direction }
    }

    /// Act on a [`ForwardDecision`] — forward the bytes or increment
    /// the matching drop counter.
    async fn act_on_decision(&self, payload: &[u8], decision: ForwardDecision) {
        match decision {
            ForwardDecision::Forward { target, direction } => {
                metrics::counter!(
                    FORWARDER_PACKETS_IN_TOTAL,
                    "direction" => direction.as_label(),
                )
                .increment(1);
                match self.socket.send_to(payload, target).await {
                    Ok(_sent) => {
                        metrics::counter!(
                            FORWARDER_PACKETS_OUT_TOTAL,
                            "direction" => direction.as_label(),
                        )
                        .increment(1);
                    },
                    Err(error) => {
                        tracing::warn!(
                            target: "bibeam_forwarder",
                            %error,
                            %target,
                            direction = direction.as_label(),
                            "send_to error",
                        );
                        metrics::counter!(
                            FORWARDER_PACKETS_DROPPED_TOTAL,
                            "reason" => DropReason::Other.as_label(),
                        )
                        .increment(1);
                    },
                }
            },
            ForwardDecision::Drop(reason) => {
                metrics::counter!(
                    FORWARDER_PACKETS_DROPPED_TOTAL,
                    "reason" => reason.as_label(),
                )
                .increment(1);
            },
        }
    }
}

/// Push the current routing-table size onto the
/// [`FORWARDER_ACTIVE_CHAINS`] gauge.
///
/// The cast `usize → f64` saturates at the float's `u32::MAX` upper
/// bound to dodge the `cast-precision-loss` lint without burying an
/// `#[allow]` on the hot path; the gauge does not need to resolve
/// four-billion-row counts to be useful, and the routing table is
/// bounded by the coordinator's lease budget well below that ceiling.
fn publish_active_chains(table_len: usize) {
    let clamped = u32::try_from(table_len).unwrap_or(u32::MAX);
    metrics::gauge!(FORWARDER_ACTIVE_CHAINS).set(f64::from(clamped));
}

/// Drop every routing-table row whose `lease_expires_at` is strictly
/// older than `now`. Returns `(evicted_count, remaining_count)`.
///
/// Extracted from [`Forwarder::sweep_expired`] so the lock guard is
/// dropped at the end of this function rather than carried across
/// the gauge publish — keeps the
/// `clippy::significant_drop_in_scrutinee` reading clean and lets
/// the publish step happen without the write lock held.
fn sweep_under_lock(
    routing: &RwLock<HashMap<ChainId, RoutingEntry>>,
    now: Timestamp,
) -> (usize, usize) {
    let (before, after) = {
        let mut table = routing.write();
        let before = table.len();
        table.retain(|_chain, entry| {
            entry.lease_expires_at.as_offset_date_time() >= now.as_offset_date_time()
        });
        (before, table.len())
    };
    (before.saturating_sub(after), after)
}

/// Peek the first 16 bytes of `payload` as a
/// [`bibeam_core::ChainId`].
///
/// Returns [`None`] when `payload` is shorter than
/// [`RELAY_FRAME_PREFIX_LEN`]. The peek deliberately does NOT decode
/// the full [`bibeam_protocol::RelayFrame`] — the forwarder never
/// touches the opaque payload tail, so the cheap prefix read is the
/// only work needed on the hot path.
fn peek_chain_id(payload: &[u8]) -> Option<ChainId> {
    let prefix = payload.get(..RELAY_FRAME_PREFIX_LEN)?;
    let mut bytes = [0u8; RELAY_FRAME_PREFIX_LEN];
    bytes.copy_from_slice(prefix);
    Some(ChainId(ulid::Ulid::from_bytes(bytes)))
}

/// Classify `src` against `entry`'s authorised endpoints.
///
/// Returns the [`Direction`] when `src` matches one of the row's
/// authorised peers, or [`None`] when it matches neither (the
/// `src_mismatch` drop path).
fn classify_direction(src: SocketAddr, entry: &RoutingEntry) -> Option<Direction> {
    if src == entry.allowed_src {
        Some(Direction::Upstream)
    } else if src == entry.allowed_dst {
        Some(Direction::Downstream)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test-only convenience for indexing into freshly-built test buffers."
)]
mod tests {
    use super::*;
    use bibeam_core::{ChainId, NodeId};
    use bibeam_protocol::{ForwarderLease, RelayFrame};
    use bytes::Bytes;
    use core::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    fn loopback_v4_zero() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn future_expiry() -> Timestamp {
        Timestamp::from_offset_date_time(
            Timestamp::now().into_inner() + time::Duration::minutes(15),
        )
    }

    fn past_expiry() -> Timestamp {
        Timestamp::from_offset_date_time(Timestamp::now().into_inner() - time::Duration::minutes(1))
    }

    fn fixture_lease(chain_id: ChainId, src: SocketAddr, dst: SocketAddr) -> ForwarderLease {
        ForwarderLease {
            forwarder: NodeId::new(),
            chain_id,
            allowed_src: src,
            allowed_dst: dst,
            lease_expires_at: future_expiry(),
        }
    }

    async fn bound_forwarder() -> Forwarder {
        Forwarder::bind(loopback_v4_zero()).await.expect("bind forwarder")
    }

    async fn bound_socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind(loopback_v4_zero()).await.expect("bind"))
    }

    /// Spawn the forwarder's run-loop on a dedicated task and return
    /// the join handle alongside the cancel token. Centralising this
    /// keeps each test's `tokio::spawn` body a single line and avoids
    /// the per-test deep-closure nesting that the
    /// `excessive_nesting` lint flags.
    fn spawn_run(
        forwarder: &Forwarder,
    ) -> (CancellationToken, tokio::task::JoinHandle<std::io::Result<()>>) {
        let cancel = CancellationToken::new();
        let forwarder_clone = forwarder.clone();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { forwarder_clone.run(cancel_clone).await });
        (cancel, handle)
    }

    /// Cancel the forwarder run-loop and assert it shuts down cleanly.
    /// Replaces the per-test `let _ = run_handle.await;` pattern,
    /// which clippy flags for both `let_underscore_must_use` and
    /// `let_underscore_drop` on the [`JoinHandle`]'s significant
    /// drop.
    async fn join_run(
        cancel: CancellationToken,
        handle: tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        cancel.cancel();
        let join_result = handle.await.expect("forwarder run loop task panicked");
        join_result.expect("forwarder run loop returned an error");
    }

    /// Spawn one receiver task that pulls a single relay frame off
    /// `dst_socket`, decodes it, and asserts the decoded `chain_id`
    /// matches the chain this receiver is bound to. Centralising the
    /// closure keeps the per-chain spawn site a one-liner and avoids
    /// the deep nesting clippy flags inside the concurrency test.
    fn spawn_concurrent_receiver(
        chain_id: ChainId,
        dst_socket: Arc<UdpSocket>,
    ) -> tokio::task::JoinHandle<RelayFrame> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (recv_len, _from) =
                tokio::time::timeout(Duration::from_secs(2), dst_socket.recv_from(&mut buf))
                    .await
                    .expect("dst recv timed out")
                    .expect("dst recv ok");
            let decoded = RelayFrame::decode(&buf[..recv_len]).expect("decode");
            assert_eq!(decoded.chain_id, chain_id, "cross-chain leak");
            decoded
        })
    }

    #[tokio::test]
    async fn insert_lease_then_evaluate_routes_upstream_to_dst() {
        // Contract: after insert_lease, a frame whose source matches
        // `allowed_src` evaluates to Forward(allowed_dst, Upstream).
        let forwarder = bound_forwarder().await;
        let src: SocketAddr = "127.0.0.1:11000".parse().expect("parse src");
        let dst: SocketAddr = "127.0.0.1:11001".parse().expect("parse dst");
        let chain_id = ChainId::new();
        forwarder.insert_lease(&fixture_lease(chain_id, src, dst));
        let frame = RelayFrame {
            chain_id,
            wg_payload: Bytes::from_static(b"opaque-payload"),
        };
        let payload = frame.encode();
        let decision = forwarder.evaluate(&payload, src, Timestamp::now());
        assert_eq!(
            decision,
            ForwardDecision::Forward {
                target: dst,
                direction: Direction::Upstream,
            },
        );
    }

    #[tokio::test]
    async fn return_traffic_routes_downstream_to_src() {
        // Contract: a frame whose source matches `allowed_dst`
        // (i.e. return traffic from the next hop) evaluates to
        // Forward(allowed_src, Downstream).
        let forwarder = bound_forwarder().await;
        let src: SocketAddr = "127.0.0.1:11010".parse().expect("parse src");
        let dst: SocketAddr = "127.0.0.1:11011".parse().expect("parse dst");
        let chain_id = ChainId::new();
        forwarder.insert_lease(&fixture_lease(chain_id, src, dst));
        let payload = RelayFrame {
            chain_id,
            wg_payload: Bytes::new(),
        }
        .encode();
        let decision = forwarder.evaluate(&payload, dst, Timestamp::now());
        assert_eq!(
            decision,
            ForwardDecision::Forward {
                target: src,
                direction: Direction::Downstream,
            },
        );
    }

    #[tokio::test]
    async fn unknown_chain_id_drops_with_unknown_chain_reason() {
        // Contract: a frame whose chain id has no row drops with
        // DropReason::UnknownChain.
        let forwarder = bound_forwarder().await;
        let payload = RelayFrame {
            chain_id: ChainId::new(),
            wg_payload: Bytes::new(),
        }
        .encode();
        let any_src: SocketAddr = "127.0.0.1:12000".parse().expect("parse src");
        let decision = forwarder.evaluate(&payload, any_src, Timestamp::now());
        assert_eq!(decision, ForwardDecision::Drop(DropReason::UnknownChain));
    }

    #[tokio::test]
    async fn src_mismatch_drops_with_src_mismatch_reason() {
        // Contract: a frame whose source address matches neither
        // `allowed_src` nor `allowed_dst` drops with
        // DropReason::SrcMismatch.
        let forwarder = bound_forwarder().await;
        let src: SocketAddr = "127.0.0.1:13000".parse().expect("parse src");
        let dst: SocketAddr = "127.0.0.1:13001".parse().expect("parse dst");
        let chain_id = ChainId::new();
        forwarder.insert_lease(&fixture_lease(chain_id, src, dst));
        let payload = RelayFrame {
            chain_id,
            wg_payload: Bytes::new(),
        }
        .encode();
        let bystander: SocketAddr = "127.0.0.1:13099".parse().expect("parse bystander");
        let decision = forwarder.evaluate(&payload, bystander, Timestamp::now());
        assert_eq!(decision, ForwardDecision::Drop(DropReason::SrcMismatch));
    }

    #[tokio::test]
    async fn expired_lease_drops_with_expired_lease_reason() {
        // Contract: a frame whose chain row has expired drops with
        // DropReason::ExpiredLease — even when src matches and the
        // chain id is in the table.
        let forwarder = bound_forwarder().await;
        let src: SocketAddr = "127.0.0.1:14000".parse().expect("parse src");
        let dst: SocketAddr = "127.0.0.1:14001".parse().expect("parse dst");
        let chain_id = ChainId::new();
        let mut lease = fixture_lease(chain_id, src, dst);
        lease.lease_expires_at = past_expiry();
        forwarder.insert_lease(&lease);
        let payload = RelayFrame {
            chain_id,
            wg_payload: Bytes::new(),
        }
        .encode();
        let decision = forwarder.evaluate(&payload, src, Timestamp::now());
        assert_eq!(decision, ForwardDecision::Drop(DropReason::ExpiredLease));
    }

    #[tokio::test]
    async fn truncated_buffer_below_prefix_drops_with_other_reason() {
        // Contract: a buffer shorter than the 16-byte chain-id prefix
        // drops with DropReason::Other — we cannot even derive a
        // chain id to look up, so this is the "frame malformed"
        // catch-all bucket.
        let forwarder = bound_forwarder().await;
        let any_src: SocketAddr = "127.0.0.1:15000".parse().expect("parse src");
        let payload = [0u8; RELAY_FRAME_PREFIX_LEN - 1];
        let decision = forwarder.evaluate(&payload, any_src, Timestamp::now());
        assert_eq!(decision, ForwardDecision::Drop(DropReason::Other));
    }

    #[tokio::test]
    async fn sweep_expired_evicts_only_expired_rows() {
        // Contract: sweep_expired removes rows whose
        // lease_expires_at is strictly older than `now`; fresh rows
        // survive. Catches a regression that swapped the comparison
        // (which would silently evict every active chain).
        let forwarder = bound_forwarder().await;
        let src: SocketAddr = "127.0.0.1:16000".parse().expect("parse");
        let dst: SocketAddr = "127.0.0.1:16001".parse().expect("parse");
        let fresh_chain = ChainId::new();
        let stale_chain = ChainId::new();
        forwarder.insert_lease(&fixture_lease(fresh_chain, src, dst));
        let mut stale = fixture_lease(stale_chain, src, dst);
        stale.lease_expires_at = past_expiry();
        forwarder.insert_lease(&stale);
        assert_eq!(forwarder.active_chains(), 2);
        let evicted = forwarder.sweep_expired(Timestamp::now());
        assert_eq!(evicted, 1);
        assert_eq!(forwarder.active_chains(), 1);
    }

    #[tokio::test]
    async fn insert_overwrites_same_chain_id() {
        // Contract: re-inserting a lease with the same chain id
        // overwrites the previous row. Catches a regression that
        // double-stored — which would let a stale `allowed_dst`
        // shadow a renewed one and break rotation.
        let forwarder = bound_forwarder().await;
        let src: SocketAddr = "127.0.0.1:17000".parse().expect("parse");
        let dst_initial: SocketAddr = "127.0.0.1:17001".parse().expect("parse");
        let dst_renewed: SocketAddr = "127.0.0.1:17002".parse().expect("parse");
        let chain_id = ChainId::new();
        forwarder.insert_lease(&fixture_lease(chain_id, src, dst_initial));
        forwarder.insert_lease(&fixture_lease(chain_id, src, dst_renewed));
        let payload = RelayFrame {
            chain_id,
            wg_payload: Bytes::new(),
        }
        .encode();
        let decision = forwarder.evaluate(&payload, src, Timestamp::now());
        assert_eq!(
            decision,
            ForwardDecision::Forward {
                target: dst_renewed,
                direction: Direction::Upstream,
            },
        );
    }

    #[tokio::test]
    async fn run_relays_inbound_frame_to_destination_unchanged() {
        // End-to-end happy path: install a lease, send a RelayFrame
        // through the forwarder's bound socket, observe the same
        // bytes on the destination socket. The payload is a
        // recognisable random-looking pattern that doubles as the
        // "forwarder never sees plaintext" assertion below.
        let forwarder = bound_forwarder().await;
        let dst_socket = bound_socket().await;
        let src_socket = bound_socket().await;
        let dst_addr = dst_socket.local_addr().expect("dst addr");
        let src_addr = src_socket.local_addr().expect("src addr");
        let fwd_addr = forwarder.local_addr().expect("fwd addr");
        let chain_id = ChainId::new();
        forwarder.insert_lease(&fixture_lease(chain_id, src_addr, dst_addr));

        let (cancel, run_handle) = spawn_run(&forwarder);

        // 16-byte sentinel prefix + opaque ciphertext-shaped body.
        // The body is not encrypted by us — the test only needs a
        // byte pattern that is observably random and not plaintext.
        let mut body = vec![0u8; 64];
        let mut counter: u8 = 0;
        for byte in &mut body {
            *byte = counter.wrapping_mul(31).wrapping_add(7);
            counter = counter.wrapping_add(1);
        }
        let frame = RelayFrame {
            chain_id,
            wg_payload: Bytes::from(body),
        };
        let encoded = frame.encode();

        src_socket.send_to(&encoded, fwd_addr).await.expect("send_to forwarder");

        let mut recv_buf = vec![0u8; 2048];
        let (recv_len, observed_from) =
            tokio::time::timeout(Duration::from_secs(2), dst_socket.recv_from(&mut recv_buf))
                .await
                .expect("recv timed out")
                .expect("recv ok");
        assert_eq!(observed_from, fwd_addr);
        assert_eq!(&recv_buf[..recv_len], encoded.as_ref(), "frame forwarded UNCHANGED");

        join_run(cancel, run_handle).await;
    }

    #[tokio::test]
    async fn run_drops_unknown_chain_does_not_reach_any_socket() {
        // Contract: a relay frame whose chain id is NOT in the
        // routing table never reaches any destination — the
        // forwarder must drop it before the send_to.
        let forwarder = bound_forwarder().await;
        let dst_socket = bound_socket().await;
        let src_socket = bound_socket().await;
        let fwd_addr = forwarder.local_addr().expect("fwd addr");

        let (cancel, run_handle) = spawn_run(&forwarder);

        let payload = RelayFrame {
            chain_id: ChainId::new(),
            wg_payload: Bytes::from_static(b"orphan"),
        }
        .encode();
        src_socket.send_to(&payload, fwd_addr).await.expect("send_to forwarder");

        let mut recv_buf = vec![0u8; 2048];
        let outcome =
            tokio::time::timeout(Duration::from_millis(300), dst_socket.recv_from(&mut recv_buf))
                .await;
        assert!(outcome.is_err(), "unknown chain id must NOT reach the destination socket");

        join_run(cancel, run_handle).await;
    }

    #[tokio::test]
    async fn run_drops_src_mismatch_does_not_reach_any_socket() {
        // Contract: a relay frame whose chain id IS leased but whose
        // source address matches neither end of the lease drops
        // before the send_to.
        let forwarder = bound_forwarder().await;
        let dst_socket = bound_socket().await;
        let bystander = bound_socket().await;
        let bystander_addr = bystander.local_addr().expect("bystander addr");
        // The lease binds a `src_addr` we deliberately do NOT use to
        // send: any socket address that is not the bystander suffices.
        let fake_src: SocketAddr = "127.0.0.1:18000".parse().expect("parse fake src");
        let dst_addr = dst_socket.local_addr().expect("dst addr");
        let fwd_addr = forwarder.local_addr().expect("fwd addr");
        let chain_id = ChainId::new();
        forwarder.insert_lease(&fixture_lease(chain_id, fake_src, dst_addr));

        let (cancel, run_handle) = spawn_run(&forwarder);

        let payload = RelayFrame {
            chain_id,
            wg_payload: Bytes::from_static(b"impostor"),
        }
        .encode();
        bystander.send_to(&payload, fwd_addr).await.expect("send_to forwarder");

        let mut recv_buf = vec![0u8; 2048];
        let outcome =
            tokio::time::timeout(Duration::from_millis(300), dst_socket.recv_from(&mut recv_buf))
                .await;
        assert!(
            outcome.is_err(),
            "src_mismatch must NOT reach the destination socket from {bystander_addr}",
        );

        join_run(cancel, run_handle).await;
    }

    #[tokio::test]
    async fn run_drops_expired_lease_does_not_reach_any_socket() {
        // Contract: a relay frame whose chain id matches but whose
        // lease has expired drops before the send_to.
        let forwarder = bound_forwarder().await;
        let dst_socket = bound_socket().await;
        let src_socket = bound_socket().await;
        let src_addr = src_socket.local_addr().expect("src addr");
        let dst_addr = dst_socket.local_addr().expect("dst addr");
        let fwd_addr = forwarder.local_addr().expect("fwd addr");
        let chain_id = ChainId::new();
        let mut lease = fixture_lease(chain_id, src_addr, dst_addr);
        lease.lease_expires_at = past_expiry();
        forwarder.insert_lease(&lease);

        let (cancel, run_handle) = spawn_run(&forwarder);

        let payload = RelayFrame {
            chain_id,
            wg_payload: Bytes::from_static(b"stale"),
        }
        .encode();
        src_socket.send_to(&payload, fwd_addr).await.expect("send_to forwarder");

        let mut recv_buf = vec![0u8; 2048];
        let outcome =
            tokio::time::timeout(Duration::from_millis(300), dst_socket.recv_from(&mut recv_buf))
                .await;
        assert!(outcome.is_err(), "expired lease must NOT reach the destination socket");

        join_run(cancel, run_handle).await;
    }

    #[tokio::test]
    async fn concurrent_chains_do_not_leak_across_chains() {
        // Contract: with N independent chains active in parallel, a
        // frame for chain `i` reaches destination `i` and only
        // destination `i`. Catches any aliasing bug in the routing
        // table or in the per-direction target selection.
        //
        // Synchronisation: every destination [`UdpSocket`] is
        // `bind`-ed before the forwarder is told it exists (the
        // bind happens inside `bound_socket().await` in the setup
        // loop). The kernel buffers any datagram delivered to a
        // bound socket in that socket's UDP receive queue
        // independently of when user-space calls `recv_from`, so
        // there is no "send before listen" race: every byte the
        // forwarder relays will be read by the receiver's
        // `recv_from` call whenever the task is polled. Each
        // payload embeds the chain id so a cross-chain leak fails
        // the per-task assertion regardless of completion order.
        const N: usize = 16;
        let forwarder = bound_forwarder().await;
        let fwd_addr = forwarder.local_addr().expect("fwd addr");

        let mut chains: Vec<(ChainId, Arc<UdpSocket>, Arc<UdpSocket>)> = Vec::with_capacity(N);
        for _ in 0..N {
            let src_socket = bound_socket().await;
            let dst_socket = bound_socket().await;
            let src_addr = src_socket.local_addr().expect("src addr");
            let dst_addr = dst_socket.local_addr().expect("dst addr");
            let chain_id = ChainId::new();
            forwarder.insert_lease(&fixture_lease(chain_id, src_addr, dst_addr));
            chains.push((chain_id, src_socket, dst_socket));
        }
        assert_eq!(forwarder.active_chains(), N);

        let (cancel, run_handle) = spawn_run(&forwarder);

        let mut receivers = Vec::with_capacity(N);
        for (chain_id, _src_socket, dst_socket) in &chains {
            receivers.push(spawn_concurrent_receiver(*chain_id, Arc::clone(dst_socket)));
        }

        // Sequentially fire one frame per chain — the forwarder
        // multiplexes them so the receivers may complete in any
        // order. Each payload embeds the chain id so a cross-chain
        // leak is detected by the assert in the receiver task.
        for (chain_id, src_socket, _dst_socket) in &chains {
            let payload = RelayFrame {
                chain_id: *chain_id,
                wg_payload: Bytes::from(chain_id.into_ulid().to_bytes().to_vec()),
            }
            .encode();
            src_socket.send_to(&payload, fwd_addr).await.expect("src send");
        }

        for receiver in receivers {
            let _decoded = receiver.await.expect("receiver task");
        }

        join_run(cancel, run_handle).await;
    }

    #[tokio::test]
    async fn forwarder_never_sees_plaintext_observation() {
        // Contract: every byte the forwarder emits on its outbound
        // socket is exactly the inbound frame the upstream peer
        // sent — i.e. the 16-byte chain_id prefix + the opaque
        // payload tail, byte-identical. We construct a payload that
        // *looks* like a WG transport-framed datagram (a 16-byte
        // tag-shaped sentinel followed by random-ish bytes) and
        // assert the destination observes those exact bytes.
        let forwarder = bound_forwarder().await;
        let dst_socket = bound_socket().await;
        let src_socket = bound_socket().await;
        let src_addr = src_socket.local_addr().expect("src addr");
        let dst_addr = dst_socket.local_addr().expect("dst addr");
        let fwd_addr = forwarder.local_addr().expect("fwd addr");
        let chain_id = ChainId::new();
        forwarder.insert_lease(&fixture_lease(chain_id, src_addr, dst_addr));

        let (cancel, run_handle) = spawn_run(&forwarder);

        // Sentinel "tag" — 16 bytes that look like an AEAD tag
        // (high-entropy, no recognisable plaintext) — followed by 96
        // bytes of equally-opaque ciphertext-shaped padding. The
        // forwarder MUST NOT alter or inspect any of this.
        let mut opaque = vec![0u8; 16 + 96];
        let mut counter: u8 = 0;
        for byte in &mut opaque {
            // Mix two coprime moduli so the byte sequence has no
            // recognisable structure shorter than 16 bytes — a
            // forwarder that tried to parse a WG transport header
            // would find no plaintext fields to lean on.
            *byte = counter.wrapping_mul(53) ^ counter.wrapping_add(17);
            counter = counter.wrapping_add(1);
        }
        let frame = RelayFrame {
            chain_id,
            wg_payload: Bytes::from(opaque.clone()),
        };
        let encoded = frame.encode();

        src_socket.send_to(&encoded, fwd_addr).await.expect("send_to forwarder");

        let mut recv_buf = vec![0u8; 2048];
        let (recv_len, _from) =
            tokio::time::timeout(Duration::from_secs(2), dst_socket.recv_from(&mut recv_buf))
                .await
                .expect("recv timed out")
                .expect("recv ok");
        // Forward-unchanged assertion: every byte the destination
        // observes is byte-identical to what the source sent. The
        // forwarder never touches the opaque tail, so this is the
        // strongest in-process witness that no decrypt path runs.
        assert_eq!(&recv_buf[..recv_len], encoded.as_ref());
        // The opaque body that follows the 16-byte chain id is
        // verbatim — the forwarder did not strip, re-frame, or
        // pad it.
        assert_eq!(&recv_buf[RELAY_FRAME_PREFIX_LEN..recv_len], opaque.as_slice());

        join_run(cancel, run_handle).await;
    }
}
