#![forbid(unsafe_code)]
//! Invite-code → [`SessionPsk`] derivation (F-CRYPTO.6).
//!
//! ## Flow
//!
//! [`MasterInviteKey`] is held by the coordinator and never leaves
//! the coordinator process. The coordinator mints 16-byte
//! [`InviteCode`] values and sends each to a prospective peer
//! through an out-of-band channel (printed card, signed e-mail, QR
//! code) — that out-of-band channel does not carry the master key.
//!
//! At registration time:
//!
//! 1. The peer presents its invite code to the coordinator over the
//!    control-plane channel.
//! 2. The coordinator runs [`derive_session_psk`] on its master key
//!    and the presented code to obtain the per-invite [`SessionPsk`].
//! 3. The coordinator delivers that [`SessionPsk`] back to the peer
//!    inside the registration response, sealed by the control-plane
//!    AEAD (F-CRYPTO.2) so the value is confidentiality- and
//!    integrity-protected on the wire.
//! 4. Both sides cache the [`SessionPsk`] for the life of the invite
//!    and feed it to [`crate::derive_wg_psk`] each rotation window.
//!
//! The peer therefore never holds [`MasterInviteKey`] and cannot
//! derive [`SessionPsk`] for a different code. The function in this
//! module is the coordinator-side primitive only — clients consume
//! the [`SessionPsk`] they receive, they do not call `derive_session_psk`
//! themselves.
//!
//! ## Algorithm
//!
//! BLAKE3-keyed-hash. The master key is the BLAKE3 key, the invite
//! code is the input. The output is a uniformly-distributed 32-byte
//! value suitable for use as an HKDF PRK in F-CRYPTO.5. BLAKE3 was
//! picked over HMAC-SHA256 because (a) it is already a workspace
//! dep, (b) `Hasher::new_keyed` makes the keyed-hash construction
//! obvious at the call site, and (c) its constant-time `Hash`
//! equality is helpful for future invite-validation use cases that
//! re-derive and compare.

use blake3::Hasher;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::wg_keys::{SessionPsk, WG_KEY_LEN};

/// Length of the per-coordinator master invite key in bytes (32).
pub const MASTER_INVITE_KEY_LEN: usize = 32;

/// Length of an individual invite code in bytes (16 — 128 bits of
/// invite-code entropy).
pub const INVITE_CODE_LEN: usize = 16;

/// Long-term coordinator key used to derive every per-invite
/// [`SessionPsk`].
///
/// One value per coordinator deployment. The key never leaves the
/// coordinator process; what gets shared with redeeming peers is the
/// derived [`SessionPsk`], not this master key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterInviteKey([u8; MASTER_INVITE_KEY_LEN]);

impl MasterInviteKey {
    /// Wrap 32 raw bytes as the coordinator's master invite key.
    #[must_use]
    pub const fn new(bytes: [u8; MASTER_INVITE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MASTER_INVITE_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for MasterInviteKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("MasterInviteKey").finish_non_exhaustive()
    }
}

impl PartialEq for MasterInviteKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for MasterInviteKey {}

/// 16-byte invite code. One per redeemable invite.
///
/// The byte form is the canonical representation; encode for
/// out-of-band distribution (base32, friendly-words, QR code, etc.)
/// at the call site that owns the user-facing format. This newtype
/// keeps the bytes themselves type-safe through the codebase.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InviteCode([u8; INVITE_CODE_LEN]);

impl InviteCode {
    /// Wrap 16 raw bytes as an invite code.
    #[must_use]
    pub const fn new(bytes: [u8; INVITE_CODE_LEN]) -> Self {
        Self(bytes)
    }

    /// Decode an invite code from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`InviteCodeError::WrongLength`] if the slice is not
    /// exactly [`INVITE_CODE_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InviteCodeError> {
        let array: [u8; INVITE_CODE_LEN] = bytes
            .try_into()
            .map_err(|_| InviteCodeError::WrongLength { got: bytes.len() })?;
        Ok(Self(array))
    }

    /// Borrow the underlying 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; INVITE_CODE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for InviteCode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("InviteCode").finish_non_exhaustive()
    }
}

impl PartialEq for InviteCode {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for InviteCode {}

/// Derive the per-invite long-term [`SessionPsk`] from the
/// coordinator's master key and a redeemable invite code.
///
/// Pure function — same `(master, code)` always returns the same
/// `SessionPsk`. This is a coordinator-side primitive: the
/// coordinator runs it during invite redemption, then ships the
/// resulting [`SessionPsk`] to the peer inside the registration
/// response sealed by the control-plane AEAD (F-CRYPTO.2). Clients
/// do not hold [`MasterInviteKey`] and do not call this function;
/// they consume the [`SessionPsk`] the coordinator delivers.
#[must_use]
pub fn derive_session_psk(master: &MasterInviteKey, code: &InviteCode) -> SessionPsk {
    let mut hasher = Hasher::new_keyed(master.as_bytes());
    hasher.update(code.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; WG_KEY_LEN];
    bytes.copy_from_slice(hash.as_bytes());
    SessionPsk::new(bytes)
}

/// Errors raised while decoding an invite code.
#[derive(Debug, Error)]
pub enum InviteCodeError {
    /// Slice was not exactly [`INVITE_CODE_LEN`] bytes.
    #[error(
        "invite code has wrong length: got {got}, expected {expected}",
        expected = INVITE_CODE_LEN
    )]
    WrongLength {
        /// Actual byte count of the candidate slice.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_master() -> MasterInviteKey {
        MasterInviteKey::new([0x11; MASTER_INVITE_KEY_LEN])
    }

    fn fixture_code(byte: u8) -> InviteCode {
        InviteCode::new([byte; INVITE_CODE_LEN])
    }

    #[test]
    fn derive_session_psk_is_deterministic() {
        let master = fixture_master();
        let code = fixture_code(0xab);
        let first = derive_session_psk(&master, &code);
        let second = derive_session_psk(&master, &code);
        assert_eq!(first.as_bytes(), second.as_bytes(), "same inputs collide");
    }

    #[test]
    fn derive_session_psk_varies_by_code() {
        let master = fixture_master();
        let first = derive_session_psk(&master, &fixture_code(0x01));
        let second = derive_session_psk(&master, &fixture_code(0x02));
        assert_ne!(first.as_bytes(), second.as_bytes(), "different codes diverge");
    }

    #[test]
    fn derive_session_psk_varies_by_master() {
        let master_a = MasterInviteKey::new([0x01; MASTER_INVITE_KEY_LEN]);
        let master_b = MasterInviteKey::new([0x02; MASTER_INVITE_KEY_LEN]);
        let code = fixture_code(0xab);
        let from_a = derive_session_psk(&master_a, &code);
        let from_b = derive_session_psk(&master_b, &code);
        assert_ne!(from_a.as_bytes(), from_b.as_bytes(), "different masters diverge");
    }

    #[test]
    fn invite_code_from_slice_round_trip() {
        let bytes = [0x42; INVITE_CODE_LEN];
        let code = InviteCode::from_slice(&bytes).expect("decode");
        assert_eq!(code.as_bytes(), &bytes);
    }

    #[test]
    fn invite_code_from_slice_rejects_wrong_length() {
        let short = [0u8; 10];
        let err = InviteCode::from_slice(&short).expect_err("must reject");
        assert!(matches!(err, InviteCodeError::WrongLength { got: 10 }));
    }

    #[test]
    fn master_invite_key_partial_eq_is_byte_equal() {
        let bytes = [7u8; MASTER_INVITE_KEY_LEN];
        let lhs = MasterInviteKey::new(bytes);
        let rhs = MasterInviteKey::new(bytes);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn debug_redacts_secret_material() {
        let key = fixture_master();
        let dbg = format!("{key:?}");
        assert!(!dbg.chars().any(|byte| byte.is_ascii_digit()), "{dbg}");
        let code = fixture_code(0xab);
        let dbg = format!("{code:?}");
        assert!(!dbg.contains("ab"), "{dbg}");
    }
}
