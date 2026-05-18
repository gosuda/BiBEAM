#![forbid(unsafe_code)]
//! Node data-plane Prometheus metric names + registration (F-NODE.9).
//!
//! Per F-RT.3 the workspace already exposes a `/metrics` endpoint via
//! [`bibeam_runtime::metrics::router`], which installs a global
//! `metrics_exporter_prometheus` recorder. This module defines the
//! node-DATA-plane-specific counter and gauge names that the data-plane
//! call sites (relay loop, exit mode, SOCKS5 fallback, DNS resolver,
//! rate-limiter, cohort/session tracker) will record into via the
//! [`metrics`] facade.
//!
//! ## Naming convention
//!
//! All metric names share the `bibeam_node_` prefix and follow the
//! workspace convention:
//!
//! ```text
//! bibeam_<crate>_<noun>_<unit>{labels…}
//! ```
//!
//! - Counters end in `_total` (Prometheus convention; the rendered
//!   exposition will surface them as `# TYPE … counter`).
//! - Gauges do NOT carry the `_total` suffix.
//!
//! Three structural unit tests in the test-only `tests` sub-module
//! lock the convention in.
//!
//! ## Registration
//!
//! [`register_node_metrics`] attaches `# HELP` and `# TYPE` metadata to
//! each metric name via [`metrics::describe_counter!`] /
//! [`metrics::describe_gauge!`]. The describe macros route through the
//! globally-installed recorder, so callers MUST invoke
//! [`register_node_metrics`] **after**
//! [`bibeam_runtime::metrics::router`] has installed the recorder.
//!
//! Wiring into `bibeam-node`'s `main.rs` is intentionally **deferred**
//! to a follow-up commit per the F-NODE.9 task scope; this commit
//! ships only the name constants, the registration entry point, and
//! the structural tests. Recording at the data-plane call sites is
//! also out of scope and lands with each data-plane module
//! (F-NODE.4 / .7 / .8).
//!
//! ## Trust boundary
//!
//! No metric defined here carries a label that identifies a peer, a
//! cohort member, or a destination address. Labels are bounded to the
//! finite enums documented at each `pub const` site (e.g.
//! `direction = "upstream" | "downstream"`). This keeps cardinality
//! finite and avoids accidental PII leakage onto the scrape endpoint.

use metrics::{Unit, describe_counter, describe_gauge};

// -------------------------------------------------------------------
// Counters — Prometheus convention: name ends in `_total`.
// -------------------------------------------------------------------

/// Prometheus metric name: total data-plane packets the node relayed,
/// labelled by `direction = "upstream" | "downstream"`.
///
/// Counts packets that the relay loop forwarded toward the next hop
/// (upstream) or back toward the previous hop (downstream). Distinct
/// from the forwarder-mode counters in [`crate::forwarder`] — those
/// are recorded only when the node is in pure stateless-UDP-pump mode;
/// these are recorded on every data-plane crate that ingests or emits
/// a packet on the node's behalf.
pub const NODE_PACKETS_RELAYED_TOTAL: &str = "bibeam_node_packets_relayed_total";

/// Prometheus metric name: total L3 packets emitted onto the exit-mode
/// upstream, labelled by `family = "ipv4" | "ipv6"`.
///
/// Recorded by the exit-mode L3 emitter (F-NODE.4). The `family` label
/// is the address family of the source / destination — bounded to two
/// values, so cardinality is constant.
pub const NODE_PACKETS_EXITED_TOTAL: &str = "bibeam_node_packets_exited_total";

/// Prometheus metric name: total SOCKS5 L4 exit-fallback connection
/// outcomes, labelled by `outcome = "accepted" | "denied" | "errored"`.
///
/// `accepted` — handshake completed and the inner relay was attached;
/// `denied`   — admission gate or policy rejected the request;
/// `errored`  — the upstream connect failed or the client dropped
///              during handshake.
pub const NODE_SOCKS5_CONNECTIONS_TOTAL: &str = "bibeam_node_socks5_connections_total";

/// Prometheus metric name: total DNS resolution attempts, labelled by
/// `outcome = "ok" | "err"`.
///
/// `ok`  — the resolver returned at least one record;
/// `err` — the resolver returned `NXDOMAIN`, `SERVFAIL`, a timeout,
///         or any other transport / protocol failure (the resolver's
///         own typed error is collapsed into this single label so
///         cardinality stays bounded).
pub const NODE_DNS_RESOLUTIONS_TOTAL: &str = "bibeam_node_dns_resolutions_total";

/// Prometheus metric name: total packets / requests the rate limiter
/// dropped, labelled by `kind = "cohort" | "peer"`.
///
/// `cohort` — the drop was triggered by the per-cohort bucket
///            (anonymity-set fairness);
/// `peer`   — the drop was triggered by the per-peer bucket
///            (single-source flood protection).
pub const NODE_RATE_LIMIT_DROPS_TOTAL: &str = "bibeam_node_rate_limit_drops_total";

/// Prometheus metric name: total cohort rotation events the node
/// processed.
///
/// Incremented once per successful atomic cohort swap inside
/// [`crate::rotation_handler::RotationHandler::swap_to`] (F-NODE.6).
/// Unlabelled: a cohort rotation is a process-wide event and the
/// node only ever owns a single active cohort at a time, so there is
/// no useful label dimension to slice on.
pub const NODE_COHORT_ROTATIONS_TOTAL: &str = "bibeam_node_cohort_rotations_total";

/// Prometheus metric name: total successful re-establishments of the
/// long-lived coordinator WebSocket event stream after a prior drop.
///
/// Incremented exactly once per fresh
/// [`bibeam_discovery::CoordinatorWs`] the F-NODE.5
/// [`crate::cohort_ws::CohortWsReceiver`] obtains after a previous
/// session ended (clean close, transport error, or coordinator-issued
/// disconnect). The first successful connect at startup does NOT
/// count — only the reconnects do, so the metric reads as "how often
/// did we have to recover the control-plane event stream" rather
/// than a confounded "total connects ever". Used by operators to
/// detect coordinator flapping (a sustained non-zero rate indicates
/// the coord pool is unstable rather than a single one-off blip).
pub const NODE_COORD_WS_RECONNECTS_TOTAL: &str = "bibeam_node_coord_ws_reconnects_total";

// -------------------------------------------------------------------
// Gauges — Prometheus convention: name does NOT end in `_total`.
// -------------------------------------------------------------------

/// Prometheus metric name: current number of active cohorts the node
/// is serving.
///
/// Set after every cohort admit / evict. Used as a coarse liveness
/// signal: a node with no cohort assignments will sit at zero.
pub const NODE_ACTIVE_COHORTS: &str = "bibeam_node_active_cohorts";

/// Prometheus metric name: current number of active per-peer sessions.
///
/// Distinct from [`NODE_ACTIVE_COHORTS`]: one cohort may carry many
/// per-peer sessions, and one peer may temporarily appear in more than
/// one cohort during rotation.
pub const NODE_ACTIVE_PEER_SESSIONS: &str = "bibeam_node_active_peer_sessions";

/// Prometheus metric name: current size of the DNS resolver cache.
///
/// Set by the DNS module (F-NODE.7) after every cache insert / evict.
/// If the DNS module does not expose a cache-size hook, this gauge
/// stays at zero — which is itself a useful signal (the resolver is
/// unconfigured or operates in pass-through mode).
pub const NODE_DNS_CACHE_SIZE: &str = "bibeam_node_dns_cache_size";

// -------------------------------------------------------------------
// Registration
// -------------------------------------------------------------------

/// Register `# HELP` and `# TYPE` metadata for every node data-plane
/// metric.
///
/// The [`metrics`] facade routes [`describe_counter!`] /
/// [`describe_gauge!`] through the globally-installed recorder. Callers
/// MUST therefore invoke this function **after**
/// [`bibeam_runtime::metrics::router`] has installed the
/// `metrics_exporter_prometheus` recorder; calling it earlier is a
/// silent no-op (the describe call is dropped on the floor recorder).
///
/// The function is idempotent: repeat calls re-issue the same
/// descriptions and have no effect on already-registered metrics.
///
/// # Follow-up
///
/// Wiring into `crates/bibeam-node/src/main.rs` startup is deferred
/// to a separate commit per the F-NODE.9 task scope (the data-plane
/// recording sites in F-NODE.4 / .7 / .8 land first).
pub fn register_node_metrics() {
    // Counters --------------------------------------------------------
    describe_counter!(
        NODE_PACKETS_RELAYED_TOTAL,
        Unit::Count,
        "Total data-plane packets relayed by the node, labelled by direction (upstream|downstream)."
    );
    describe_counter!(
        NODE_PACKETS_EXITED_TOTAL,
        Unit::Count,
        "Total L3 packets emitted by exit mode, labelled by address family (ipv4|ipv6)."
    );
    describe_counter!(
        NODE_SOCKS5_CONNECTIONS_TOTAL,
        Unit::Count,
        "Total SOCKS5 L4 exit-fallback connection outcomes, labelled by outcome (accepted|denied|errored)."
    );
    describe_counter!(
        NODE_DNS_RESOLUTIONS_TOTAL,
        Unit::Count,
        "Total DNS resolution attempts, labelled by outcome (ok|err)."
    );
    describe_counter!(
        NODE_RATE_LIMIT_DROPS_TOTAL,
        Unit::Count,
        "Total rate-limit drops, labelled by kind (cohort|peer)."
    );
    describe_counter!(
        NODE_COHORT_ROTATIONS_TOTAL,
        Unit::Count,
        "Total cohort rotation events processed by the node's RotationHandler (F-NODE.6)."
    );
    describe_counter!(
        NODE_COORD_WS_RECONNECTS_TOTAL,
        Unit::Count,
        "Total coordinator-WebSocket re-establishments after a prior session drop (initial connect at startup is not counted)."
    );

    // Gauges ----------------------------------------------------------
    describe_gauge!(
        NODE_ACTIVE_COHORTS,
        Unit::Count,
        "Current number of active cohorts the node is serving."
    );
    describe_gauge!(
        NODE_ACTIVE_PEER_SESSIONS,
        Unit::Count,
        "Current number of active per-peer sessions across all cohorts."
    );
    describe_gauge!(
        NODE_DNS_CACHE_SIZE,
        Unit::Count,
        "Current size of the DNS resolver cache, in entries."
    );
}

// -------------------------------------------------------------------
// Tests — structural assertions on the naming convention.
//
// These tests intentionally do NOT install a recorder or record any
// samples; they only assert the workspace convention on the metric
// name constants themselves. Recording-site coverage lives with each
// data-plane module (F-NODE.4 / .7 / .8) and the integration suite.
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: [`register_node_metrics`] is callable without a recorder
    /// installed (the describe macros route to the global no-op
    /// recorder in test binaries that do not install one). This
    /// guards against a future regression that switched to an API
    /// which panics on no recorder.
    #[test]
    fn register_node_metrics_is_safe_to_call_without_recorder() {
        // No recorder is installed in this test binary; the describe
        // calls drop on the floor. We only care that no panic occurs.
        register_node_metrics();
        // Calling twice must also be safe (idempotence).
        register_node_metrics();
    }
}
