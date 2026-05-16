#![forbid(unsafe_code)]
//! PII redaction utilities for `peer_id` and `ip` fields in
//! [`tracing`] events.
//!
//! ## What this module is — and is not
//!
//! [`tracing`] events are immutable: a [`tracing_subscriber::Layer`]
//! cannot reach into a downstream layer's formatter and rewrite a
//! field's value. The right shape for PII safety in this codebase is
//! therefore a **two-part** contract:
//!
//! 1. **Call-site discipline.** Every callsite that has a peer
//!    identifier or IP address MUST emit its redacted form, not the
//!    raw value. The [`redact`] convenience function takes a
//!    [`RedactionKey`] and a typed value and returns the redacted
//!    [`String`] the call-site should put in the field.
//!
//! 2. **Detection layer.** [`PiiRedactionLayer`] sits in the
//!    subscriber stack and scans every event for `peer_id` / `ip`
//!    fields whose string value parses as a real [`bibeam_core::PeerId`]
//!    or [`core::net::IpAddr`]. When it sees one — i.e. when a
//!    call-site forgot rule (1) and emitted a raw value — it
//!    surfaces a single `tracing::warn!` breadcrumb on the
//!    `bibeam.redaction` target so the operator can correlate the
//!    raw event back to the offending call-site at audit time.
//!
//! The layer does **not** suppress the raw event. Suppression in
//! tracing-subscriber requires a per-layer `Filter` in front of the
//! formatting layer, which would discard the whole event rather than
//! redact a field — that is a strictly worse tradeoff than emitting
//! the raw event plus a corrective audit breadcrumb. The detection
//! breadcrumb is what makes the contract testable in CI: a grep
//! over the JSON log stream for `bibeam.redaction` flags every
//! leak.
//!
//! ## Cognitive complexity
//!
//! The [`tracing_subscriber::field::Visit`] surface has six method
//! shapes (one per primitive type). The visitor here only cares
//! about `record_str` and `record_debug`, but the trait surface plus
//! the per-field-name branching still trips the default
//! `clippy::cognitive_complexity` threshold. The impl block carries
//! a scoped `#[allow]` with a rationale.

use core::net::IpAddr;
use core::str::FromStr as _;

use bibeam_core::{PeerId, RedactionKey, redact_ip, redact_peer_id};
use tracing::{Event, Subscriber, field::Visit};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

/// Field name a caller MUST use when emitting a peer identifier so
/// that [`PiiRedactionLayer`] can audit it.
const FIELD_PEER_ID: &str = "peer_id";

/// Field name a caller MUST use when emitting an IP address so that
/// [`PiiRedactionLayer`] can audit it.
const FIELD_IP: &str = "ip";

/// Tracing target the detection layer uses for its audit
/// breadcrumbs. A log aggregator can build a saved query against
/// this target to surface every PII leak in production.
pub const REDACTION_AUDIT_TARGET: &str = "bibeam.redaction";

/// Sentinel string the layer emits when it cannot recover a typed
/// value from a `Debug`-shape field. Reveals nothing about the raw
/// value; the breadcrumb's job here is to point an operator at the
/// offending callsite so the `?peer_id` / `?ip` syntax can be
/// replaced with `peer_id = %redact(...)`.
const SENTINEL_DEBUG_SHAPE: &str = "<debug-shape>";

/// Typed PII value that can be redacted through [`redact`].
#[derive(Debug, Clone, Copy)]
pub enum Pii<'a> {
    /// A peer identifier.
    Peer(&'a PeerId),
    /// An IP address.
    Ip(IpAddr),
}

/// Redact `value` under `key` and return the hex token a call-site
/// should put in its log field.
///
/// Typical usage:
///
/// ```ignore
/// use bibeam_core::RedactionKey;
/// use bibeam_runtime::redaction_layer::{Pii, redact};
///
/// fn on_admit(key: &RedactionKey, peer: &bibeam_core::PeerId) {
///     tracing::info!(peer_id = %redact(key, Pii::Peer(peer)), "admit");
/// }
/// ```
#[must_use]
pub fn redact(key: &RedactionKey, value: Pii<'_>) -> String {
    match value {
        Pii::Peer(peer) => redact_peer_id(key, peer),
        Pii::Ip(ip) => redact_ip(key, ip),
    }
}

/// Tracing layer that audits `peer_id` / `ip` fields for raw PII
/// leakage.
///
/// Add it to the subscriber stack alongside the formatting layer.
/// The layer does not transform the formatter's output (see the
/// module-level rationale); instead it emits a `warn!` on the
/// [`REDACTION_AUDIT_TARGET`] target whenever a call-site puts a
/// raw, parseable [`PeerId`] or [`IpAddr`] string into a `peer_id` or
/// `ip` field.
///
/// The audit breadcrumb itself carries the redacted token, so an
/// operator can correlate it back to the raw event by matching the
/// `peer_id` / `ip` value through the same [`RedactionKey`].
#[derive(Debug)]
pub struct PiiRedactionLayer {
    key: RedactionKey,
}

impl PiiRedactionLayer {
    /// Construct a [`PiiRedactionLayer`] that audits under `key`.
    ///
    /// The same key MUST be used as the call-site redaction key —
    /// otherwise the breadcrumb tokens will not correlate with the
    /// redacted values produced by [`redact`] at the call-site.
    #[must_use]
    pub const fn new(key: RedactionKey) -> Self {
        Self { key }
    }
}

/// Field-walking visitor used by [`PiiRedactionLayer::on_event`].
///
/// Captures the parseable redacted tokens it finds; the layer then
/// emits a breadcrumb per captured token after the walk completes.
struct AuditVisitor<'a> {
    key: &'a RedactionKey,
    leaked_peer_id: Option<String>,
    leaked_ip: Option<String>,
}

impl Visit for AuditVisitor<'_> {
    // The Visit trait surface forces method-per-primitive-type. Each
    // arm is trivial; the cognitive-complexity gate would only fire
    // if the trait surface itself shrank, which it cannot.
    #[allow(
        clippy::cognitive_complexity,
        reason = "Visit trait surface forces method-per-primitive-type \
                  pattern; field-name dispatch lives in each arm and \
                  cannot be hoisted without losing primitive coverage."
    )]
    fn record_debug(&mut self, field: &tracing::field::Field, _value: &dyn core::fmt::Debug) {
        // `?peer_id` and `?ip` callsite syntax (Debug formatting)
        // routes here. We deliberately do *not* try to parse the
        // `Debug` text back to a typed value: derived `Debug` on
        // `PeerId` renders as `PeerId(Ulid(...))`, which
        // `Ulid::from_string` cannot decode, so the parse would
        // silently miss leaks. Instead we mark the leak with a
        // sentinel token so the audit breadcrumb still fires and
        // points the operator at the offending callsite. The
        // sentinel reveals nothing about the raw value.
        match field.name() {
            FIELD_PEER_ID => {
                self.leaked_peer_id = Some(SENTINEL_DEBUG_SHAPE.to_owned());
            },
            FIELD_IP => {
                self.leaked_ip = Some(SENTINEL_DEBUG_SHAPE.to_owned());
            },
            _ => {},
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            FIELD_PEER_ID => {
                if let Ok(parsed) = PeerId::from_str(value) {
                    self.leaked_peer_id = Some(redact_peer_id(self.key, &parsed));
                }
            },
            FIELD_IP => {
                if let Ok(addr) = IpAddr::from_str(value) {
                    self.leaked_ip = Some(redact_ip(self.key, addr));
                }
            },
            _ => {},
        }
    }
}

impl<S> Layer<S> for PiiRedactionLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    #[allow(
        clippy::cognitive_complexity,
        reason = "Inflated by the `tracing::warn!` macro expansion (two \
                  call-sites, each fans out into a callsite struct + \
                  metadata + dispatch). The function's own logic is two \
                  guarded emissions; splitting it would just move the \
                  same expansion behind a thin wrapper."
    )]
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Skip events the layer itself emitted to avoid an infinite
        // breadcrumb cascade.
        if event.metadata().target() == REDACTION_AUDIT_TARGET {
            return;
        }

        let mut visitor = AuditVisitor {
            key: &self.key,
            leaked_peer_id: None,
            leaked_ip: None,
        };
        event.record(&mut visitor);

        if let Some(token) = visitor.leaked_peer_id.as_deref() {
            tracing::warn!(
                target: REDACTION_AUDIT_TARGET,
                redacted_peer_id = token,
                "raw peer_id leaked into a tracing event; correlate by token",
            );
        }
        if let Some(token) = visitor.leaked_ip.as_deref() {
            tracing::warn!(
                target: REDACTION_AUDIT_TARGET,
                redacted_ip = token,
                "raw ip leaked into a tracing event; correlate by token",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> RedactionKey {
        RedactionKey::from_bytes([0x42; 32])
    }

    #[test]
    fn redact_peer_returns_short_hex_token() {
        let key = test_key();
        let peer = PeerId::new();
        let token = redact(&key, Pii::Peer(&peer));
        // Contract: redaction output is a non-empty hex string.
        // Deleting this lets a regression that returns the raw
        // identifier slip past CI.
        assert!(!token.is_empty(), "token must be non-empty");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "token must be hex: {token}");
        assert!(token != peer.to_string(), "token must not equal the raw peer id");
    }

    #[test]
    fn redact_ip_returns_short_hex_token() {
        let key = test_key();
        let ip: IpAddr = "203.0.113.4".parse().expect("valid v4 literal");
        let token = redact(&key, Pii::Ip(ip));
        assert!(!token.is_empty());
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(token, ip.to_string());
    }

    #[test]
    fn redact_is_deterministic_for_same_key_and_input() {
        // The redaction contract is that operators can correlate
        // events for the same peer across log lines. That requires
        // determinism. A regression that randomised the digest would
        // silently break correlation; this test catches it.
        let key = test_key();
        let peer = PeerId::new();
        assert_eq!(redact(&key, Pii::Peer(&peer)), redact(&key, Pii::Peer(&peer)));
    }

    #[test]
    fn layer_does_not_panic_on_empty_event() {
        // Drive an empty event through the layer to lock in the
        // contract that emission with no PII fields is a no-op
        // (does not crash, does not infinite-loop on its own
        // breadcrumb).
        use tracing_subscriber::{Registry, layer::SubscriberExt as _};

        let subscriber = Registry::default().with(PiiRedactionLayer::new(test_key()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(message = "no PII here");
        });
    }
}
