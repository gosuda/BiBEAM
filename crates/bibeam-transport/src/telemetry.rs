#![forbid(unsafe_code)]
//! Connection-telemetry helpers for the `BiBeam` transport layer.
//!
//! F-TRANS.9 owns the `tracing` span / `metrics` counter naming for
//! every observable on the data plane: WG handshake start / complete,
//! ICE-lite hole-punch lifecycle, relay-fallback transitions,
//! decrypt-failure totals, and per-direction byte totals. Each name
//! is exported as a `const &str` so call-sites can not drift away
//! from the canonical string — a rename here is a compile-time
//! callsite breakage everywhere.
//!
//! ## Names
//!
//! Counter names use the Prometheus `_total` convention:
//!
//! - `wg_handshake_started_total`
//! - `wg_handshake_completed_total`
//! - `holepunch_started_total`
//! - `holepunch_succeeded_total`
//! - `holepunch_timed_out_fell_back_to_relay_total`
//! - `decrypt_failure_total`
//! - `bytes_in_total`
//! - `bytes_out_total`
//!
//! ## PII redaction
//!
//! Every helper that takes a [`PeerId`] also takes a
//! [`bibeam_core::RedactionKey`]. The helper calls
//! [`bibeam_core::redact_peer_id`] at the emit site and uses the
//! resulting redacted token as the `peer_id` field value. That makes
//! `bibeam_runtime::PiiRedactionLayer` a *detection* layer (which
//! audits any callsite that still emits a raw ID) rather than a
//! *redaction* layer — redaction happens here, where the typed
//! `PeerId` is in scope.
//!
//! ## Why no end-to-end wiring
//!
//! Per the F-TRANS.9 task scope, this commit ships **only** the
//! names + helpers. Hooking them into `WgTunnel`, `RelayPath`, and
//! `run_socks5_listener` is a follow-up — instrumenting earlier
//! modules in the same atomic commit would violate the atomic-
//! commit policy.

use bibeam_core::{PeerId, RedactionKey, redact_peer_id};

/// `tracing` target / counter prefix used by every helper. Keeps
/// metric scraping selectors short (`bibeam_transport_*`) and lets
/// operators grep one substring to find every span this module
/// emits.
pub const TELEMETRY_TARGET: &str = "bibeam_transport";

/// Counter incremented every time a WG handshake-init leaves a
/// `WgTunnel` (F-TRANS.1). Pre-increment, i.e. before the bytes hit
/// the wire — pairs with [`WG_HANDSHAKE_COMPLETED_TOTAL`].
pub const WG_HANDSHAKE_STARTED_TOTAL: &str = "wg_handshake_started_total";

/// Counter incremented every time a `WgTunnel` observes a completed
/// WG handshake (either side of the simultaneous-open dance).
///
/// Lags `wg_handshake_started_total` by one round-trip plus
/// `boringtun`'s session-establishment latency; the delta is a
/// useful liveness signal for hole-punch success.
pub const WG_HANDSHAKE_COMPLETED_TOTAL: &str = "wg_handshake_completed_total";

/// Counter for ICE-lite hole-punch attempts (F-TRANS.5).
/// Incremented once per [`crate::simultaneous_open`] invocation —
/// before the wall-clock sleep, so a slow `sync_at` does not skew
/// the rate.
pub const HOLEPUNCH_STARTED_TOTAL: &str = "holepunch_started_total";

/// Counter for ICE-lite hole-punches that completed a WG handshake
/// within the 5-second window.
pub const HOLEPUNCH_SUCCEEDED_TOTAL: &str = "holepunch_succeeded_total";

/// Counter for ICE-lite hole-punches that timed out and fell back to
/// the assigned relay node (F-TRANS.6).
///
/// The verbose name is on purpose — operators reading a
/// `metric_relabel_configs` should see the failure mode without a
/// lookup.
pub const HOLEPUNCH_TIMED_OUT_TOTAL: &str = "holepunch_timed_out_fell_back_to_relay_total";

/// Counter for AEAD-decrypt failures inside `boringtun`.
///
/// Each increment corresponds to one [`crate::WgTunnelError::WireGuard`]
/// surfaced from the receive path. A non-zero rate at a steady-state
/// session is a tampering or PSK-mismatch signal.
pub const DECRYPT_FAILURE_TOTAL: &str = "decrypt_failure_total";

/// Counter for plaintext bytes that left the tunnel toward the user
/// stack (boringtun decap output).
pub const BYTES_IN_TOTAL: &str = "bytes_in_total";

/// Counter for plaintext bytes that entered the tunnel from the
/// user stack (boringtun encap input).
pub const BYTES_OUT_TOTAL: &str = "bytes_out_total";

/// Record a WG handshake-started event for `peer_id`.
///
/// Emits a `tracing::info!` span breadcrumb plus a `metrics::counter!`
/// increment. `peer_id` is redacted through
/// [`bibeam_core::redact_peer_id`] before any field is recorded.
pub fn record_handshake_started(redaction: &RedactionKey, peer_id: PeerId) {
    let redacted = redact_peer_id(redaction, &peer_id);
    tracing::info!(
        target: TELEMETRY_TARGET,
        peer_id = %redacted,
        event = "wg_handshake_started",
        "wg handshake init dispatched",
    );
    metrics::counter!(WG_HANDSHAKE_STARTED_TOTAL).increment(1);
}

/// Record a WG handshake-completed event for `peer_id`.
pub fn record_handshake_completed(redaction: &RedactionKey, peer_id: PeerId) {
    let redacted = redact_peer_id(redaction, &peer_id);
    tracing::info!(
        target: TELEMETRY_TARGET,
        peer_id = %redacted,
        event = "wg_handshake_completed",
        "wg handshake completed",
    );
    metrics::counter!(WG_HANDSHAKE_COMPLETED_TOTAL).increment(1);
}

/// Record an ICE-lite hole-punch attempt for `peer_id`.
pub fn record_holepunch_started(redaction: &RedactionKey, peer_id: PeerId) {
    let redacted = redact_peer_id(redaction, &peer_id);
    tracing::info!(
        target: TELEMETRY_TARGET,
        peer_id = %redacted,
        event = "holepunch_started",
        "ice-lite simultaneous-open initiated",
    );
    metrics::counter!(HOLEPUNCH_STARTED_TOTAL).increment(1);
}

/// Record a successful ICE-lite hole-punch for `peer_id`.
pub fn record_holepunch_succeeded(redaction: &RedactionKey, peer_id: PeerId) {
    let redacted = redact_peer_id(redaction, &peer_id);
    tracing::info!(
        target: TELEMETRY_TARGET,
        peer_id = %redacted,
        event = "holepunch_succeeded",
        "ice-lite simultaneous-open established",
    );
    metrics::counter!(HOLEPUNCH_SUCCEEDED_TOTAL).increment(1);
}

/// Record an ICE-lite timeout for `peer_id` and the resulting
/// relay-fallback transition.
pub fn record_holepunch_timed_out(redaction: &RedactionKey, peer_id: PeerId) {
    let redacted = redact_peer_id(redaction, &peer_id);
    tracing::warn!(
        target: TELEMETRY_TARGET,
        peer_id = %redacted,
        event = "holepunch_timed_out_fell_back_to_relay",
        "ice-lite simultaneous-open timed out; falling back to relay",
    );
    metrics::counter!(HOLEPUNCH_TIMED_OUT_TOTAL).increment(1);
}

/// Record one AEAD-decrypt failure on the receive path.
///
/// Does NOT take a `peer_id`: by the time decrypt has failed, the
/// recipient does not know which authenticated peer the bytes came
/// from. The counter exists so an aggregate spike is visible
/// regardless.
pub fn record_decrypt_failure() {
    tracing::warn!(
        target: TELEMETRY_TARGET,
        event = "decrypt_failure",
        "boringtun decrypt failure",
    );
    metrics::counter!(DECRYPT_FAILURE_TOTAL).increment(1);
}

/// Record `byte_count` bytes leaving the tunnel toward the user stack.
///
/// Emits the counter increment only; no per-event tracing log (this
/// is a hot-path counter and a per-packet `tracing::info` would drown
/// the JSON log stream).
pub fn record_bytes_in(byte_count: u64) {
    metrics::counter!(BYTES_IN_TOTAL).increment(byte_count);
}

/// Record `byte_count` bytes entering the tunnel from the user
/// stack. Hot-path counter, no per-event tracing log.
pub fn record_bytes_out(byte_count: u64) {
    metrics::counter!(BYTES_OUT_TOTAL).increment(byte_count);
}

#[cfg(test)]
mod tests {
    use bibeam_core::{PeerId, RedactionKey};

    use super::*;

    fn fresh_redaction_key() -> RedactionKey {
        // RedactionKey is constructed from a 32-byte secret; tests
        // use a deterministic key so any future snapshot test sees
        // a stable token.
        RedactionKey::from_bytes([7_u8; 32])
    }

    #[test]
    fn counter_names_carry_the_prometheus_total_suffix() {
        for name in [
            WG_HANDSHAKE_STARTED_TOTAL,
            WG_HANDSHAKE_COMPLETED_TOTAL,
            HOLEPUNCH_STARTED_TOTAL,
            HOLEPUNCH_SUCCEEDED_TOTAL,
            HOLEPUNCH_TIMED_OUT_TOTAL,
            DECRYPT_FAILURE_TOTAL,
            BYTES_IN_TOTAL,
            BYTES_OUT_TOTAL,
        ] {
            assert!(
                name.ends_with("_total"),
                "counter name {name} must follow Prometheus _total convention",
            );
        }
    }

    #[test]
    fn telemetry_target_is_module_scoped() {
        assert_eq!(TELEMETRY_TARGET, "bibeam_transport");
    }

    #[test]
    fn record_helpers_are_callable_without_a_subscriber() {
        // None of the record_* helpers should panic when no
        // tracing subscriber is installed and no metrics recorder
        // is set — both `tracing::info!` and `metrics::counter!`
        // are no-ops in that configuration. Run them all to catch
        // an accidental .expect() in any code path.
        let key = fresh_redaction_key();
        let peer = PeerId::new();
        record_handshake_started(&key, peer);
        record_handshake_completed(&key, peer);
        record_holepunch_started(&key, peer);
        record_holepunch_succeeded(&key, peer);
        record_holepunch_timed_out(&key, peer);
        record_decrypt_failure();
        record_bytes_in(1_234);
        record_bytes_out(5_678);
    }
}
