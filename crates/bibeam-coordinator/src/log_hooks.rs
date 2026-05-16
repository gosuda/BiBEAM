#![forbid(unsafe_code)]
//! BLAKE3-keyed PII hash hooks for tracing + audit-log call sites
//! (F-COORD.10).
//!
//! Every call site inside the coordinator that wants to log a peer
//! id or IP address must route through this module's helpers so
//! the raw value never reaches the JSON log stream. Two surfaces:
//!
//! - [`peer_token`] / [`ip_token`] — thin wrappers around the
//!   public [`bibeam_core::redact_peer_id`] / [`bibeam_core::redact_ip`]
//!   API. Use these at every `tracing::info!(peer_id = …, …)` call
//!   site so the
//!   [`bibeam_runtime::PiiRedactionLayer`] audit breadcrumb never
//!   fires for the coordinator's own log lines.
//! - [`crate::audit_event!`] — declarative macro that:
//!     1. routes peer / IP values through the redaction helpers,
//!     2. emits a `tracing::info!` record carrying the redacted
//!        tokens (so the JSON log stream stays operator-readable
//!        but PII-clean), and
//!     3. forwards an [`crate::audit::AuditEntry`] into the
//!        supplied [`crate::audit::AuditLog`] for the operator
//!        audit trail.
//!
//! ## Why a macro
//!
//! `tracing::info!` is a macro at the call site — the field-name
//! shape (`peer_id = %token`) cannot be wrapped into a function
//! without losing the field-name binding. A declarative macro
//! gives us the wrapping at the call site, keeps the field shape
//! the [`bibeam_runtime::PiiRedactionLayer`] audit layer expects,
//! and lets the audit-log integration ride the same `let` bindings
//! the macro already establishes.

use core::net::IpAddr;

use bibeam_core::{PeerId, RedactionKey, redact_ip, redact_peer_id};

/// Compute the redaction token for `peer_id` under `key`.
///
/// Thin wrapper around [`bibeam_core::redact_peer_id`] so call
/// sites import a coordinator-local symbol and the
/// [`crate::audit_event!`] macro has a stable function name to invoke.
#[must_use]
pub fn peer_token(key: &RedactionKey, peer_id: &PeerId) -> String {
    redact_peer_id(key, peer_id)
}

/// Compute the redaction token for `source_ip` under `key`. Thin
/// wrapper around [`bibeam_core::redact_ip`].
#[must_use]
pub fn ip_token(key: &RedactionKey, source_ip: IpAddr) -> String {
    redact_ip(key, source_ip)
}

/// Emit a tracing event with redacted peer + IP fields AND append
/// the matching audit-log entry, all in one call site.
///
/// Shape (all arguments are required except where noted):
///
/// ```ignore
/// use bibeam_coordinator::audit_event;
/// use bibeam_coordinator::audit::AuditKind;
///
/// audit_event!(
///     audit_log: &audit_log,
///     redaction_key: &redaction_key,
///     kind: AuditKind::Admission,
///     peer_id: &peer,
///     ip: source_ip,
///     detail: serde_json::json!({ "cohort_id": cohort.to_string() }).to_string(),
///     message: "peer admitted",
/// );
/// ```
///
/// Behaviour:
///
/// - Computes the redacted tokens through [`peer_token`] /
///   [`ip_token`] **once** so a single `RedactionKey` derivation
///   is shared between the tracing emit and the audit-log entry.
/// - Emits `tracing::info!(target: "bibeam.coord.audit",
///   peer_id = %token, ip = %token, kind = …, $message)`.
///   The target string is well-known so a log aggregator can
///   filter the audit stream out of general tracing without
///   string-sniffing.
/// - Pushes an [`crate::audit::AuditEntry`] into `audit_log`. The
///   detail JSON is whatever the caller supplied.
///
/// Errors from `audit_log.append` are surfaced via
/// `tracing::error!` and otherwise swallowed — the audit log
/// must not take down the calling handler for a transient redb
/// hiccup.
#[macro_export]
macro_rules! audit_event {
    (
        audit_log: $audit_log:expr,
        redaction_key: $redaction_key:expr,
        kind: $kind:expr,
        peer_id: $peer_id:expr,
        ip: $ip:expr,
        detail: $detail:expr,
        message: $message:literal $(,)?
    ) => {{
        let __redaction_key: &$crate::log_hooks::__exports::RedactionKey = $redaction_key;
        let __peer_token =
            $crate::log_hooks::peer_token(__redaction_key, $peer_id);
        let __ip_token = $crate::log_hooks::ip_token(__redaction_key, $ip);
        let __kind: $crate::audit::AuditKind = $kind;
        let __detail: String = $detail;
        ::tracing::info!(
            target: $crate::log_hooks::AUDIT_LOG_TARGET,
            peer_id = %__peer_token,
            ip = %__ip_token,
            kind = ?__kind,
            $message,
        );
        let __entry = $crate::audit::AuditEntry {
            at: $crate::log_hooks::__exports::Timestamp::now(),
            kind: __kind,
            peer_token: Some(__peer_token),
            ip_token: Some(__ip_token),
            detail_json: __detail,
        };
        if let Err(__err) = $audit_log.append(&__entry) {
            ::tracing::error!(
                target: $crate::log_hooks::AUDIT_LOG_TARGET,
                error = %__err,
                "audit_event! failed to append audit-log entry",
            );
        }
    }};
}

/// Tracing target used by the [`crate::audit_event!`] macro's emit.
///
/// Reserved so a downstream log aggregator can filter the audit
/// stream into a separate sink without string-matching on message
/// content.
pub const AUDIT_LOG_TARGET: &str = "bibeam.coord.audit";

/// Re-exports the macro needs at expansion sites. Kept inside a
/// `#[doc(hidden)]` module so the public surface stays minimal.
#[doc(hidden)]
pub mod __exports {
    pub use bibeam_core::{RedactionKey, Timestamp};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditKind, AuditLog};
    use bibeam_core::{PeerId, Timestamp};
    use core::net::Ipv4Addr;
    use std::sync::Arc;

    fn audit_log_with_temp() -> (AuditLog, tempfile::NamedTempFile, Arc<RedactionKey>) {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let key = Arc::new(RedactionKey::from_bytes([0x42; 32]));
        let log = AuditLog::open(temp.path(), key.clone()).expect("open audit log");
        (log, temp, key)
    }

    #[test]
    fn peer_token_matches_core_redaction() {
        let key = RedactionKey::from_bytes([0x42; 32]);
        let peer = PeerId::new();
        let by_helper = peer_token(&key, &peer);
        let by_core = redact_peer_id(&key, &peer);
        assert_eq!(by_helper, by_core);
    }

    #[test]
    fn ip_token_matches_core_redaction() {
        let key = RedactionKey::from_bytes([0x42; 32]);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
        let by_helper = ip_token(&key, ip);
        let by_core = redact_ip(&key, ip);
        assert_eq!(by_helper, by_core);
    }

    /// Drive the macro once and return the resulting audit-log
    /// entry plus the `(before, after)` wall-clock window the
    /// call was inside. Extracted so the macro expansion does
    /// not blow up the test fn's cognitive complexity score.
    #[allow(
        clippy::cognitive_complexity,
        reason = "Inflated by the `audit_event!` macro expansion \
                  (which fans out into multiple `tracing::info!`/`error!` \
                  call sites plus the AuditEntry literal). The helper's \
                  own logic is three statements; splitting it would \
                  just move the same expansion behind a thin wrapper, \
                  the same precedent the runtime crate's \
                  redaction_layer uses for `tracing::warn!` expansion."
    )]
    fn drive_macro_once(
        log: &AuditLog,
        key: &Arc<RedactionKey>,
        peer: PeerId,
        ip: IpAddr,
    ) -> (crate::audit::AuditEntry, Timestamp, Timestamp) {
        let detail = String::from("{\"smoke\": true}");
        let before = Timestamp::now();
        crate::audit_event!(
            audit_log: log,
            redaction_key: &**key,
            kind: AuditKind::Admission,
            peer_id: &peer,
            ip: ip,
            detail: detail,
            message: "smoke admit",
        );
        let after = Timestamp::now();
        let mut rows = log.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 1);
        let entry = rows.pop().expect("entry");
        (entry, before, after)
    }

    /// Assert that the entry's redacted tokens match the
    /// expected helper outputs for `(peer, ip)` under `key`.
    fn assert_tokens_match(
        entry: &crate::audit::AuditEntry,
        key: &RedactionKey,
        peer: PeerId,
        ip: IpAddr,
    ) {
        let peer_redacted = entry.peer_token.as_deref().expect("peer token present");
        assert_eq!(peer_redacted, peer_token(key, &peer));
        let ip_redacted = entry.ip_token.as_deref().expect("ip token present");
        assert_eq!(ip_redacted, ip_token(key, ip));
    }

    /// Bounded-clock invariant: the recorded timestamp must sit
    /// inside `[before, after]`. A regression that stamped the
    /// entry with a cached or epoch value would fail the lower
    /// bound; a regression that produced a future timestamp
    /// would fail the upper bound.
    fn assert_timestamp_in_window(at: Timestamp, before: Timestamp, after: Timestamp) {
        assert!(
            at.as_offset_date_time() >= before.as_offset_date_time(),
            "entry timestamp must not predate the macro call",
        );
        assert!(
            at.as_offset_date_time() <= after.as_offset_date_time(),
            "entry timestamp must not postdate the macro call",
        );
    }

    #[test]
    fn audit_event_macro_appends_redacted_entry() {
        // Contract: the macro routes peer + IP through the
        // redaction helpers, appends an AuditEntry to the supplied
        // log, and stamps the entry with a fresh wall-clock
        // captured during the macro expansion (not a cached or
        // epoch value).
        let (log, _temp, key) = audit_log_with_temp();
        let peer = PeerId::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));

        let (entry, before, after) = drive_macro_once(&log, &key, peer, ip);

        assert_eq!(entry.kind, AuditKind::Admission);
        assert_tokens_match(&entry, &key, peer, ip);
        assert_eq!(entry.detail_json, "{\"smoke\": true}");
        assert_timestamp_in_window(entry.at, before, after);
    }
}
