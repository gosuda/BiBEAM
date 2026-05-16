#![forbid(unsafe_code)]
//! Append-only operator audit log (F-COORD.8).
//!
//! Records one [`AuditEntry`] per admission / rotation / token
//! issuance / invite redemption into a redb table keyed by a
//! monotonic 16-byte ULID. Every entry carries the operator's
//! redacted view of the originating peer + IP — never the raw
//! values.
//!
//! ## Append-only contract
//!
//! [`AuditLog`] exposes [`AuditLog::append`] but no delete /
//! truncate / modify call. Operators rotate the table out-of-band
//! (e.g. by archiving the redb file and starting a fresh one).
//! redb 4 itself does not enforce append-only at the
//! transaction layer; the policy is enforced by the API shape of
//! this module.
//!
//! ## Redaction
//!
//! [`AuditEntry::peer_token`] is the public
//! [`bibeam_core::redact_peer_id`] output (BLAKE3-keyed-hash under
//! the coordinator's [`bibeam_core::RedactionKey`], truncated to
//! 16 hex chars). [`AuditEntry::ip_token`] is the equivalent for
//! the IP. Re-using the same `RedactionKey` as
//! [`bibeam_runtime::PiiRedactionLayer`] means audit entries
//! correlate against the JSON log stream by token comparison —
//! the operator looks up `peer_token=abcdef1234567890` in either
//! surface and sees the same opaque identifier.
//!
//! ## Why ULID keys instead of `Timestamp`?
//!
//! Two audits captured in the same millisecond must each get a
//! unique row. ULIDs already encode millisecond timestamp + 80
//! bits of monotonic randomness, so:
//!
//! - rows sort chronologically without an explicit index,
//! - duplicate keys are impossible at the wall-clock resolution
//!   redb's read iteration uses,
//! - and the same key shape is already in use across the codebase
//!   ([`bibeam_core::PeerId`] / `NodeId` / `CohortId`).

use std::path::Path;
use std::sync::Arc;

use bibeam_core::{PeerId, RedactionKey, Timestamp, redact_ip, redact_peer_id};
use core::net::IpAddr;
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

/// redb table holding one postcard-encoded [`AuditEntry`] per
/// recorded event, keyed by a fresh 16-byte ULID.
const AUDIT_TABLE: TableDefinition<'_, &[u8; 16], &[u8]> = TableDefinition::new("operator_audit");

/// Event-kind classifier on an [`AuditEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditKind {
    /// A peer was admitted into a cohort.
    Admission,
    /// A cohort was rotated.
    Rotation,
    /// A PASETO session token was issued.
    TokenIssued,
    /// An invite was redeemed via [`crate::invite_admission`].
    InviteRedeemed,
}

/// One row in the operator audit log.
///
/// The shape is what the F-COORD.10 log-hooks layer fills in;
/// callers can construct one directly when they have all the
/// inputs, but the typical path is through the typed
/// `AuditLog::record_*` helpers (admission / rotation /
/// token-issued / invite-redeemed) so redaction usage stays
/// uniform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Wall-clock instant at which the event was captured.
    pub at: Timestamp,
    /// What kind of event this row records.
    pub kind: AuditKind,
    /// Redacted token for the originating peer, or `None` when the
    /// event is peer-agnostic (e.g. a coordinator-wide rotation).
    pub peer_token: Option<String>,
    /// Redacted token for the originating IP, or `None` when the
    /// event has no socket origin.
    pub ip_token: Option<String>,
    /// Small JSON blob for kind-specific context. Examples:
    /// `{"cohort_id":"…"}` for `TokenIssued`,
    /// `{"old_cohort":"…","new_cohort":"…"}` for `Rotation`.
    pub detail_json: String,
}

/// Failure modes for the audit log.
#[derive(Debug, Error)]
pub enum AuditError {
    /// redb reported a failure during open, transaction, or table
    /// operation.
    #[error("audit log redb error: {0}")]
    Redb(String),
    /// postcard failed to encode or decode the stored
    /// [`AuditEntry`].
    #[error("audit log postcard codec error: {0}")]
    Codec(#[from] postcard::Error),
}

impl AuditError {
    fn redb<DisplayErr: core::fmt::Display>(err: DisplayErr) -> Self {
        Self::Redb(err.to_string())
    }
}

/// Cheap-to-clone handle on the redb-backed audit log.
#[derive(Clone)]
pub struct AuditLog {
    db: Arc<Database>,
    redaction_key: Arc<RedactionKey>,
}

impl core::fmt::Debug for AuditLog {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open (or create) the redb-backed audit log.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Redb`] if redb cannot create the
    /// file or initialise the `operator_audit` table.
    pub fn open(path: &Path, redaction_key: Arc<RedactionKey>) -> Result<Self, AuditError> {
        let database = Database::create(path).map_err(AuditError::redb)?;
        let log = Self {
            db: Arc::new(database),
            redaction_key,
        };
        log.ensure_table_exists()?;
        Ok(log)
    }

    /// Append `entry` to the log. The key is a freshly-generated
    /// ULID so chronological ordering is implicit and double-key
    /// collisions are statistically impossible.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Codec`] when postcard rejects the
    /// shape, and [`AuditError::Redb`] on any redb transaction
    /// failure.
    pub fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let encoded = postcard::to_allocvec(entry)?;
        let key = Ulid::new().to_bytes();
        let txn = self.db.begin_write().map_err(AuditError::redb)?;
        {
            let mut table = txn.open_table(AUDIT_TABLE).map_err(AuditError::redb)?;
            table.insert(&key, encoded.as_slice()).map_err(AuditError::redb)?;
        }
        txn.commit().map_err(AuditError::redb)?;
        Ok(())
    }

    /// Record an admission event. Convenience wrapper that builds
    /// the entry through the redaction helpers so the peer + IP
    /// are never exposed in the stored row.
    ///
    /// # Errors
    ///
    /// Same as [`AuditLog::append`].
    pub fn record_admission(
        &self,
        peer_id: &PeerId,
        source_ip: IpAddr,
        cohort_id: bibeam_core::CohortId,
    ) -> Result<(), AuditError> {
        let detail = serde_json::json!({ "cohort_id": cohort_id.to_string() }).to_string();
        self.append(&AuditEntry {
            at: Timestamp::now(),
            kind: AuditKind::Admission,
            peer_token: Some(redact_peer_id(&self.redaction_key, peer_id)),
            ip_token: Some(redact_ip(&self.redaction_key, source_ip)),
            detail_json: detail,
        })
    }

    /// Record a rotation event (no peer / IP origin).
    ///
    /// # Errors
    ///
    /// Same as [`AuditLog::append`].
    pub fn record_rotation(
        &self,
        peers_evicted: usize,
        cohorts_evicted: usize,
    ) -> Result<(), AuditError> {
        let detail = serde_json::json!({
            "peers_evicted": peers_evicted,
            "cohorts_evicted": cohorts_evicted,
        })
        .to_string();
        self.append(&AuditEntry {
            at: Timestamp::now(),
            kind: AuditKind::Rotation,
            peer_token: None,
            ip_token: None,
            detail_json: detail,
        })
    }

    /// Record a PASETO token issuance event.
    ///
    /// # Errors
    ///
    /// Same as [`AuditLog::append`].
    pub fn record_token_issued(
        &self,
        peer_id: &PeerId,
        cohort_id: bibeam_core::CohortId,
        expires_at: Timestamp,
    ) -> Result<(), AuditError> {
        let detail = serde_json::json!({
            "cohort_id": cohort_id.to_string(),
            "expires_at": expires_at,
        })
        .to_string();
        self.append(&AuditEntry {
            at: Timestamp::now(),
            kind: AuditKind::TokenIssued,
            peer_token: Some(redact_peer_id(&self.redaction_key, peer_id)),
            ip_token: None,
            detail_json: detail,
        })
    }

    /// Record an invite redemption. `audit_tag` is the breadcrumb
    /// produced by [`crate::invite_admission::RedemptionBreadcrumb`].
    ///
    /// # Errors
    ///
    /// Same as [`AuditLog::append`].
    pub fn record_invite_redeemed(
        &self,
        audit_tag: &str,
        remaining: u32,
    ) -> Result<(), AuditError> {
        let detail = serde_json::json!({
            "audit_tag": audit_tag,
            "remaining": remaining,
        })
        .to_string();
        self.append(&AuditEntry {
            at: Timestamp::now(),
            kind: AuditKind::InviteRedeemed,
            peer_token: None,
            ip_token: None,
            detail_json: detail,
        })
    }

    /// Return every entry currently stored, in ULID order.
    /// Intended for tests + operator export tooling; production
    /// hot paths should NOT scan the full table.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Codec`] when a stored row fails
    /// postcard decode, and [`AuditError::Redb`] on any redb
    /// transaction failure.
    pub fn snapshot(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let txn = self.db.begin_read().map_err(AuditError::redb)?;
        let table = txn.open_table(AUDIT_TABLE).map_err(AuditError::redb)?;
        let mut rows: Vec<AuditEntry> = Vec::new();
        for entry in table.iter().map_err(AuditError::redb)? {
            let (_key_guard, value_guard) = entry.map_err(AuditError::redb)?;
            let row = postcard::from_bytes::<AuditEntry>(value_guard.value())?;
            rows.push(row);
        }
        Ok(rows)
    }

    fn ensure_table_exists(&self) -> Result<(), AuditError> {
        let txn = self.db.begin_write().map_err(AuditError::redb)?;
        {
            let _table = txn.open_table(AUDIT_TABLE).map_err(AuditError::redb)?;
        }
        txn.commit().map_err(AuditError::redb)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::{CohortId, PeerId};
    use core::net::Ipv4Addr;

    fn log_with_temp_file() -> (AuditLog, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let key = Arc::new(RedactionKey::from_bytes([0x42; 32]));
        let log = AuditLog::open(temp.path(), key).expect("open audit log");
        (log, temp)
    }

    #[test]
    fn record_admission_redacts_peer_and_ip() {
        // Contract: an admission entry MUST NOT carry the raw peer
        // id or IP. The stored token is the public-redaction-API
        // output, so it is opaque without the redaction key.
        let (log, _temp) = log_with_temp_file();
        let peer = PeerId::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
        let cohort = CohortId::new();
        log.record_admission(&peer, ip, cohort).expect("record");
        let rows = log.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 1);
        let entry = &rows[0];
        assert_eq!(entry.kind, AuditKind::Admission);
        let peer_token = entry.peer_token.as_deref().expect("peer token present");
        assert_ne!(peer_token, peer.to_string());
        let ip_token = entry.ip_token.as_deref().expect("ip token present");
        assert_ne!(ip_token, ip.to_string());
        assert!(entry.detail_json.contains(&cohort.to_string()));
    }

    #[test]
    fn rotation_entry_has_no_peer_or_ip_token() {
        // Contract: rotation is peer-agnostic — the entry must not
        // synthesise a fake redaction token. Catches a regression
        // that defaulted the field to `Some("".into())` (which
        // would correlate every rotation with every empty-peer
        // redaction in operator dashboards).
        let (log, _temp) = log_with_temp_file();
        log.record_rotation(2, 1).expect("record");
        let rows = log.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, AuditKind::Rotation);
        assert!(rows[0].peer_token.is_none());
        assert!(rows[0].ip_token.is_none());
    }

    #[test]
    fn append_is_strictly_additive() {
        // Contract: each append produces exactly one new row.
        // Catches a regression that overwrote on append (which
        // would silently break operator forensics).
        let (log, _temp) = log_with_temp_file();
        log.record_rotation(0, 0).expect("first");
        log.record_rotation(0, 0).expect("second");
        log.record_rotation(0, 0).expect("third");
        let rows = log.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn invite_redeemed_entry_round_trips_through_postcard() {
        // Contract: detail_json carries the audit_tag and remaining
        // count verbatim so an operator can grep it.
        let (log, _temp) = log_with_temp_file();
        log.record_invite_redeemed("invite=aaa ip=bbb", 7).expect("record");
        let rows = log.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 1);
        let entry = &rows[0];
        assert_eq!(entry.kind, AuditKind::InviteRedeemed);
        assert!(entry.detail_json.contains("invite=aaa"));
        assert!(entry.detail_json.contains("\"remaining\":7"));
    }
}
