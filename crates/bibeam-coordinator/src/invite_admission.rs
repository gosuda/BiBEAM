#![forbid(unsafe_code)]
//! Invite-code admission flow (F-COORD.7).
//!
//! A peer presenting a [`bibeam_discovery::SignedInvite`] is
//! admitted only after three checks pass in order:
//!
//! 1. **Signature verification** via
//!    [`bibeam_discovery::verify_invite`] against the coordinator's
//!    trusted [`bibeam_crypto::IdentityPublicKey`]. The verifier
//!    also enforces the invite's expiry; a forged or stale invite
//!    is rejected before any redemption work happens.
//! 2. **Redemption budget.** Each minted invite carries a cap on
//!    how many times it may be redeemed. The cap is tracked
//!    server-side in [`RedemptionLedger`] under the BLAKE3 hash of
//!    the invite code with a domain-separator prefix. Every
//!    successful admission decrements the counter; redemption with
//!    a zero counter is rejected.
//! 3. **Audit trail.** [`InviteAdmissioner::redeem`] returns a
//!    [`RedemptionBreadcrumb`] carrying a redacted hex token for
//!    `(invite_code, source_ip)` derived via the public
//!    [`bibeam_core::redact_peer_id`] / [`bibeam_core::redact_ip`]
//!    API. The audit log (F-COORD.8) records that breadcrumb
//!    instead of the raw values.
//!
//! ## Redemption-table key construction
//!
//! The table key is `BLAKE3(domain || invite_code_bytes)` — a
//! plain (un-keyed) digest. Hiding the invite code in the redb
//! file is not a security boundary: anyone with read access to
//! the file can also read the redemption counts and observe
//! invite usage. The domain prefix prevents the digest from
//! colliding with any other artifact hashed under BLAKE3 by the
//! coordinator.
//!
//! ## Audit-hash construction
//!
//! [`InviteAdmissioner::redeem`] computes the audit breadcrumb by
//! concatenating the redacted hex tokens for the invite-code-as-PeerId
//! and the source IP, both produced under the coordinator's
//! [`bibeam_core::RedactionKey`]. Reuse of the existing public API
//! keeps invite-admission code on the same redaction contract as
//! the tracing layer (F-COORD.10) and the audit log (F-COORD.8);
//! key rotation rolls all three surfaces at once.

use std::path::Path;
use std::sync::Arc;

use bibeam_core::{RedactionKey, redact_ip};
use bibeam_crypto::{INVITE_CODE_LEN, IdentityPublicKey, InviteCode};
use bibeam_discovery::{DiscoveryError, SignedInvite, verify_invite};
use core::net::IpAddr;
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use thiserror::Error;

/// redb table mapping the domain-prefixed BLAKE3 hash of an invite
/// code to the remaining redemption count. Keys are 32-byte
/// digests; values are little-endian `u32` counters.
const REDEMPTION_TABLE: TableDefinition<'_, &[u8; 32], u32> =
    TableDefinition::new("invite_redemptions");

/// Domain string folded into the invite-code BLAKE3 digest, so the
/// redemption-table key cannot collide with any other digest the
/// coordinator emits.
const INVITE_HASH_DOMAIN: &str = "bibeam.coord.invite_redemption.v1";

/// Failure modes for [`InviteAdmissioner::redeem`].
#[derive(Debug, Error)]
pub enum InviteAdmissionError {
    /// Forwarded from [`bibeam_discovery::verify_invite`] — bad
    /// signature, wrong issuer, or expired invite.
    #[error("invite signature verification failed: {0}")]
    Verify(#[from] DiscoveryError),
    /// The invite is well-signed but its redemption budget is
    /// exhausted (zero remaining redemptions in the ledger). The
    /// caller should surface this to the peer as `403`.
    #[error("invite has no redemptions remaining")]
    BudgetExhausted,
    /// redb reported a failure during open, transaction, or table
    /// operation.
    #[error("redemption ledger redb error: {0}")]
    Redb(String),
}

impl InviteAdmissionError {
    fn redb<DisplayErr: core::fmt::Display>(err: DisplayErr) -> Self {
        Self::Redb(err.to_string())
    }
}

/// Per-invite redemption ledger.
///
/// `register` stamps a fresh invite with its starting budget;
/// `debit` decrements the counter atomically inside a redb write
/// transaction so two simultaneous redemptions cannot both succeed
/// when only one slot remains.
#[derive(Clone)]
pub struct RedemptionLedger {
    db: Arc<Database>,
}

impl core::fmt::Debug for RedemptionLedger {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("RedemptionLedger").finish_non_exhaustive()
    }
}

impl RedemptionLedger {
    /// Open (or create) the redb-backed redemption ledger.
    ///
    /// # Errors
    ///
    /// Returns [`InviteAdmissionError::Redb`] if redb cannot
    /// create the file or initialise the `invite_redemptions`
    /// table.
    pub fn open(path: &Path) -> Result<Self, InviteAdmissionError> {
        let database = Database::create(path).map_err(InviteAdmissionError::redb)?;
        let ledger = Self { db: Arc::new(database) };
        ledger.ensure_table_exists()?;
        Ok(ledger)
    }

    /// Register a fresh invite with `starting_budget` redemptions.
    ///
    /// Overwrites any prior counter for the same invite — operator
    /// re-issue resets the budget.
    ///
    /// # Errors
    ///
    /// Returns [`InviteAdmissionError::Redb`] on any redb
    /// transaction failure.
    pub fn register(
        &self,
        code: &InviteCode,
        starting_budget: u32,
    ) -> Result<(), InviteAdmissionError> {
        let key = invite_hash_key(code);
        let txn = self.db.begin_write().map_err(InviteAdmissionError::redb)?;
        {
            let mut table = txn.open_table(REDEMPTION_TABLE).map_err(InviteAdmissionError::redb)?;
            table.insert(&key, starting_budget).map_err(InviteAdmissionError::redb)?;
        }
        txn.commit().map_err(InviteAdmissionError::redb)?;
        Ok(())
    }

    /// Atomically decrement the redemption counter for `code`. On
    /// success returns the **post-decrement** budget. Surfaces
    /// [`InviteAdmissionError::BudgetExhausted`] when the counter
    /// is missing or already at zero.
    ///
    /// # Errors
    ///
    /// Returns [`InviteAdmissionError::Redb`] on any redb
    /// transaction failure and
    /// [`InviteAdmissionError::BudgetExhausted`] when the counter
    /// is absent or zero.
    pub fn debit(&self, code: &InviteCode) -> Result<u32, InviteAdmissionError> {
        let key = invite_hash_key(code);
        let txn = self.db.begin_write().map_err(InviteAdmissionError::redb)?;
        let remaining = debit_under_write_txn(&txn, &key)?;
        txn.commit().map_err(InviteAdmissionError::redb)?;
        Ok(remaining)
    }

    /// Return the current redemption budget for `code`, or `None`
    /// when no record exists.
    ///
    /// # Errors
    ///
    /// Returns [`InviteAdmissionError::Redb`] on any redb
    /// transaction failure.
    pub fn get(&self, code: &InviteCode) -> Result<Option<u32>, InviteAdmissionError> {
        let key = invite_hash_key(code);
        let txn = self.db.begin_read().map_err(InviteAdmissionError::redb)?;
        let table = txn.open_table(REDEMPTION_TABLE).map_err(InviteAdmissionError::redb)?;
        let Some(guard) = table.get(&key).map_err(InviteAdmissionError::redb)? else {
            return Ok(None);
        };
        Ok(Some(guard.value()))
    }

    fn ensure_table_exists(&self) -> Result<(), InviteAdmissionError> {
        let txn = self.db.begin_write().map_err(InviteAdmissionError::redb)?;
        {
            let _table = txn.open_table(REDEMPTION_TABLE).map_err(InviteAdmissionError::redb)?;
        }
        txn.commit().map_err(InviteAdmissionError::redb)?;
        Ok(())
    }
}

/// Decrement the budget for `key` under an open write transaction.
/// Extracted so [`RedemptionLedger::debit`] stays under the
/// cognitive-complexity threshold.
fn debit_under_write_txn(
    txn: &redb::WriteTransaction,
    key: &[u8; 32],
) -> Result<u32, InviteAdmissionError> {
    let mut table = txn.open_table(REDEMPTION_TABLE).map_err(InviteAdmissionError::redb)?;
    let current_budget = {
        let Some(current_guard) = table.get(key).map_err(InviteAdmissionError::redb)? else {
            return Err(InviteAdmissionError::BudgetExhausted);
        };
        current_guard.value()
    };
    if current_budget == 0 {
        return Err(InviteAdmissionError::BudgetExhausted);
    }
    let next_budget = current_budget.saturating_sub(1);
    table.insert(key, next_budget).map_err(InviteAdmissionError::redb)?;
    Ok(next_budget)
}

/// Compute the redemption-table key for `code`. Plain BLAKE3 over
/// the domain string + raw invite-code bytes — see module rustdoc
/// for the rationale (the table contents are operator-owned; this
/// digest is collision-resistance, not confidentiality).
fn invite_hash_key(code: &InviteCode) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INVITE_HASH_DOMAIN.as_bytes());
    let code_bytes: &[u8; INVITE_CODE_LEN] = code.as_bytes();
    hasher.update(code_bytes);
    *hasher.finalize().as_bytes()
}

/// Verifier + ledger coordinator: turn a `(SignedInvite, source_ip)`
/// presentation into either an admission breadcrumb (caller mints
/// the PASETO via F-COORD.4 once redemption succeeds) or a typed
/// error.
#[derive(Clone)]
pub struct InviteAdmissioner {
    trusted_issuer: Arc<IdentityPublicKey>,
    ledger: RedemptionLedger,
    redaction_key: Arc<RedactionKey>,
}

impl core::fmt::Debug for InviteAdmissioner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("InviteAdmissioner").finish_non_exhaustive()
    }
}

impl InviteAdmissioner {
    /// Build an admissioner backed by `ledger` and trusting
    /// `trusted_issuer` as the coordinator-signing identity.
    /// `redaction_key` is the per-coordinator
    /// [`bibeam_core::RedactionKey`] used by the audit log and
    /// tracing layer; reusing the same key here means audit
    /// breadcrumbs correlate across surfaces.
    #[must_use]
    pub const fn new(
        trusted_issuer: Arc<IdentityPublicKey>,
        ledger: RedemptionLedger,
        redaction_key: Arc<RedactionKey>,
    ) -> Self {
        Self {
            trusted_issuer,
            ledger,
            redaction_key,
        }
    }

    /// Verify the invite, debit the ledger, and return the audit
    /// breadcrumb. The caller (F-COORD.8 audit log integration)
    /// records the breadcrumb; this layer is the authority on
    /// whether the redemption is legal.
    ///
    /// # Errors
    ///
    /// Returns [`InviteAdmissionError::Verify`] if the invite
    /// signature, expiry, or issuer-hint check fails;
    /// [`InviteAdmissionError::BudgetExhausted`] if the redemption
    /// budget for the invite is missing or already at zero; and
    /// [`InviteAdmissionError::Redb`] on any ledger transaction
    /// failure.
    pub fn redeem(
        &self,
        signed: &SignedInvite,
        source_ip: IpAddr,
    ) -> Result<RedemptionBreadcrumb, InviteAdmissionError> {
        verify_invite(signed, &self.trusted_issuer)?;
        let remaining = self.ledger.debit(&signed.code)?;
        let breadcrumb = self.compute_audit_breadcrumb(&signed.code, source_ip);
        Ok(RedemptionBreadcrumb {
            audit_tag: breadcrumb,
            remaining,
        })
    }

    /// Build the audit breadcrumb from `(code, source_ip)`. The
    /// invite-code half is an un-keyed BLAKE3 digest with a
    /// per-purpose domain prefix; the IP half goes through
    /// [`bibeam_core::redact_ip`] (which IS keyed by the
    /// coordinator's [`RedactionKey`]). The split matches the
    /// available primitives without forcing one surface through
    /// the other.
    ///
    /// The invite-code half is intentionally un-keyed: 16 bytes of
    /// CSPRNG entropy already make reverse-image attack infeasible,
    /// and an attacker with redb-file access can already see every
    /// active invite (the redemption-table keys are derived the
    /// same way). The IP half DOES need keying — IP addresses are
    /// low-entropy and an unkeyed digest would leak the underlying
    /// address to anyone with the audit log.
    fn compute_audit_breadcrumb(&self, code: &InviteCode, source_ip: IpAddr) -> String {
        let invite_token = invite_audit_token(code);
        let ip_token = redact_ip(&self.redaction_key, source_ip);
        format!("invite={invite_token} ip={ip_token}")
    }
}

/// Audit breadcrumb emitted by a successful redemption.
#[derive(Debug, Clone)]
pub struct RedemptionBreadcrumb {
    /// Pre-formatted audit tag: `invite=<redacted> ip=<redacted>`,
    /// where each redacted token is derived under the
    /// coordinator's [`RedactionKey`] via the public
    /// [`bibeam_core::redact_ip`] surface (plus the equivalent
    /// keyed-hash helper for invite codes).
    pub audit_tag: String,
    /// Post-decrement redemption budget. Useful to operators
    /// watching for invites approaching their cap.
    pub remaining: u32,
}

/// Domain-prefixed BLAKE3 digest of an invite code's raw bytes,
/// truncated to the same 16-hex-char shape
/// [`bibeam_core::redact_ip`] emits.
///
/// Un-keyed: see [`InviteAdmissioner::compute_audit_breadcrumb`]
/// for the rationale. 16 bytes of CSPRNG entropy in the code make
/// reverse-image attack infeasible even without keying.
fn invite_audit_token(code: &InviteCode) -> String {
    const AUDIT_TOKEN_DOMAIN: &str = "bibeam.coord.invite_audit_token.v1";
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUDIT_TOKEN_DOMAIN.as_bytes());
    let code_bytes: &[u8; INVITE_CODE_LEN] = code.as_bytes();
    hasher.update(code_bytes);
    let digest = hasher.finalize();
    let hex = digest.to_hex();
    hex[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::Timestamp;
    use bibeam_crypto::IdentitySecretKey;
    use bibeam_discovery::signing_payload;
    use core::net::Ipv4Addr;
    use time::Duration;

    fn fixture_invite(secret: &IdentitySecretKey) -> SignedInvite {
        let code = InviteCode::new([0x11; INVITE_CODE_LEN]);
        let issued_at = Timestamp::now();
        let expires_at =
            Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc() + Duration::hours(1));
        let payload = signing_payload(&code, &issued_at, Some(&expires_at));
        let signature = secret.sign(&payload).to_bytes().to_vec();
        SignedInvite {
            code,
            issuer: secret.public(),
            issued_at,
            expires_at: Some(expires_at),
            signature,
        }
    }

    fn fixture_ledger() -> (RedemptionLedger, tempfile::NamedTempFile, Arc<RedactionKey>) {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let key = Arc::new(RedactionKey::from_bytes([0x42; 32]));
        let ledger = RedemptionLedger::open(temp.path()).expect("open ledger");
        (ledger, temp, key)
    }

    #[test]
    fn debit_decrements_until_exhausted() {
        let (ledger, _temp, _key) = fixture_ledger();
        let code = InviteCode::new([0x07; INVITE_CODE_LEN]);
        ledger.register(&code, 2).expect("register");
        assert_eq!(ledger.debit(&code).expect("first"), 1);
        assert_eq!(ledger.debit(&code).expect("second"), 0);
        assert!(matches!(
            ledger.debit(&code).expect_err("third"),
            InviteAdmissionError::BudgetExhausted,
        ));
    }

    #[test]
    fn debit_rejects_unregistered_invite() {
        let (ledger, _temp, _key) = fixture_ledger();
        let code = InviteCode::new([0xAA; INVITE_CODE_LEN]);
        assert!(matches!(
            ledger.debit(&code).expect_err("must reject"),
            InviteAdmissionError::BudgetExhausted,
        ));
    }

    #[test]
    fn admissioner_redeem_round_trips() {
        let (ledger, _temp, key) = fixture_ledger();
        let secret = IdentitySecretKey::generate();
        let signed = fixture_invite(&secret);
        let trusted = Arc::new(secret.public());
        ledger.register(&signed.code, 1).expect("register");
        let admissioner = InviteAdmissioner::new(trusted, ledger, key);
        let breadcrumb = admissioner
            .redeem(&signed, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)))
            .expect("redeem");
        assert_eq!(breadcrumb.remaining, 0);
        assert!(breadcrumb.audit_tag.contains("invite="));
        assert!(breadcrumb.audit_tag.contains("ip="));
    }

    #[test]
    fn admissioner_rejects_forged_signature() {
        let (ledger, _temp, key) = fixture_ledger();
        let real = IdentitySecretKey::generate();
        let other = IdentitySecretKey::generate();
        let signed = fixture_invite(&other);
        let trusted = Arc::new(real.public());
        ledger.register(&signed.code, 1).expect("register");
        let admissioner = InviteAdmissioner::new(trusted, ledger, key);
        let err = admissioner
            .redeem(&signed, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4)))
            .expect_err("must reject forged signature");
        assert!(matches!(err, InviteAdmissionError::Verify(_)));
    }

    #[test]
    fn audit_tag_ip_token_changes_on_different_keys() {
        // Contract: the same source IP under two different
        // redaction keys produces different IP tokens inside the
        // audit tag. The invite-code half is un-keyed by design
        // (see module rustdoc), so it stays the same — that is
        // also load-bearing for cross-process correlation under
        // operator-rotated keys.
        let secret = IdentitySecretKey::generate();
        let signed = fixture_invite(&secret);
        let trusted = Arc::new(secret.public());

        let temp_a = tempfile::NamedTempFile::new().expect("tempfile a");
        let temp_b = tempfile::NamedTempFile::new().expect("tempfile b");
        let ledger_a = RedemptionLedger::open(temp_a.path()).expect("open a");
        let ledger_b = RedemptionLedger::open(temp_b.path()).expect("open b");
        ledger_a.register(&signed.code, 1).expect("register a");
        ledger_b.register(&signed.code, 1).expect("register b");

        let key_a = Arc::new(RedactionKey::from_bytes([0x11; 32]));
        let key_b = Arc::new(RedactionKey::from_bytes([0x22; 32]));
        let admissioner_a = InviteAdmissioner::new(trusted.clone(), ledger_a, key_a);
        let admissioner_b = InviteAdmissioner::new(trusted, ledger_b, key_b);

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
        let tag_a = admissioner_a.redeem(&signed, ip).expect("redeem a").audit_tag;
        let tag_b = admissioner_b.redeem(&signed, ip).expect("redeem b").audit_tag;
        assert_ne!(tag_a, tag_b, "IP token must change with the redaction key");
    }
}
