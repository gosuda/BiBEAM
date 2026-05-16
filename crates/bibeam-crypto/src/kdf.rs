#![forbid(unsafe_code)]
//! HKDF-SHA256 key derivation (F-CRYPTO.5).
//!
//! Two entry points:
//!
//! - [`derive_wg_psk`] — the sole owner of the per-rotation
//!   `WireGuard` PSK. Takes a long-term [`SessionPsk`] (the per-invite
//!   key F-CRYPTO.6 hands back) and a rotation counter, returns the
//!   short-lived [`WgPsk`] that `bibeam-transport` feeds to
//!   `boringtun`.
//! - [`derive_subkey`] — a general 32-byte subkey helper for any
//!   other control-plane derivation that wants a context-bound
//!   sub-key from an existing PRK. Use a distinct `info` for each
//!   derivation purpose so two callers never collide.
//!
//! ## Algorithm choice
//!
//! HKDF-SHA256, RFC 5869. The HMAC-SHA256-based KDF is the
//! best-understood option and is what `hkdf` (the workspace
//! `hkdf = "0.13"`) exposes natively. Both entry points are pure
//! HKDF-Expand-from-PRK: callers hand in keys that are already
//! cryptographically strong 32-byte values, so re-extracting them
//! would only obscure the schedule. Domain separation across call
//! sites rides on the `info` block — `derive_wg_psk` pins
//! `b"bibeam/wg-psk/v1"` as the static label and binds the rotation
//! counter through `info`; other call sites pick their own `info`.

use crate::wg_keys::{SessionPsk, WG_KEY_LEN, WgPsk};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

/// Static label embedded in every WG-PSK `info` block, ensuring no
/// other call site can collide with `derive_wg_psk` outputs even if
/// it reuses the underlying `SessionPsk` PRK.
const WG_PSK_LABEL: &[u8] = b"bibeam/wg-psk/v1";

/// Errors returned by HKDF helpers.
#[derive(Debug, Error)]
pub enum KdfError {
    /// HKDF-Expand failed.
    ///
    /// For HKDF-SHA256, expand only fails when the requested output
    /// length exceeds 255 × hash-output-length = 8160 bytes. All
    /// callers in this module request exactly 32 bytes, so this
    /// variant is unreachable in practice — we surface it as a
    /// proper error variant anyway because the workspace clippy
    /// policy forbids `expect()` / `unreachable!()` in library code.
    #[error("HKDF-Expand failed")]
    ExpandFailed,
    /// HKDF-from-PRK rejected the input: the PRK was shorter than
    /// the hash's output size (SHA-256 → 32 bytes).
    #[error("HKDF PRK too short: must be at least 32 bytes for SHA-256")]
    PrkTooShort,
}

/// Derive the per-rotation `WireGuard` PSK from the long-term
/// [`SessionPsk`] and a monotonically-increasing rotation counter.
///
/// The [`SessionPsk`] is already a 32-byte cryptographically strong
/// key (BLAKE3-keyed-hash output, see F-CRYPTO.6), so we drive HKDF
/// from PRK directly — there is no benefit to running Extract again
/// over an already-uniform input. `info` is
/// `WG_PSK_LABEL || rotation_counter.to_le_bytes()`. Two invocations
/// with the same `SessionPsk` and different counters diverge; two
/// with the same counter collide.
///
/// # Errors
///
/// Returns [`KdfError::ExpandFailed`] if HKDF-Expand fails. This is
/// unreachable for the fixed 32-byte output we request, but the
/// `expect`-free policy in this workspace forces the explicit error
/// path. `PrkTooShort` is also unreachable here because
/// [`SessionPsk`] always wraps exactly 32 bytes; we still surface
/// the error rather than `expect()`.
pub fn derive_wg_psk(session_psk: &SessionPsk, rotation_counter: u64) -> Result<WgPsk, KdfError> {
    let mut info = [0u8; WG_PSK_LABEL.len() + size_of::<u64>()];
    info[..WG_PSK_LABEL.len()].copy_from_slice(WG_PSK_LABEL);
    info[WG_PSK_LABEL.len()..].copy_from_slice(&rotation_counter.to_le_bytes());
    let hk = Hkdf::<Sha256>::from_prk(session_psk.as_bytes()).map_err(|_| KdfError::PrkTooShort)?;
    let mut out = [0u8; WG_KEY_LEN];
    hk.expand(&info, &mut out).map_err(|_| KdfError::ExpandFailed)?;
    Ok(WgPsk::new(out))
}

/// Derive a 32-byte subkey from a PRK using a caller-chosen `info`.
///
/// The input is assumed to be a cryptographically strong PRK — at
/// minimum 32 bytes, uniformly distributed. This helper runs
/// HKDF-Expand only (no re-extract). If the caller has *initial key
/// material* (IKM) instead — biased, low-entropy, or shorter than
/// 32 bytes — they should run their own extract first (the `hkdf`
/// crate's `Hkdf::new(salt, ikm)` form) before calling this helper,
/// or use a different KDF entirely.
///
/// Use a unique `info` per derivation purpose. Two call sites that
/// share `info` over the same PRK will collide.
///
/// Callers should wrap the returned `[u8; 32]` in
/// [`zeroize::Zeroizing`] or move it into a [`zeroize::Zeroize`]-derived
/// newtype (the established pattern in this crate, e.g.
/// [`SessionPsk`], [`WgPsk`]) so the secret bytes are scrubbed on
/// drop.
///
/// # Errors
///
/// - [`KdfError::PrkTooShort`] if `prk.len() < 32`.
/// - [`KdfError::ExpandFailed`] if HKDF-Expand fails. Unreachable for
///   32-byte outputs but surfaced because the workspace forbids
///   `expect()`.
pub fn derive_subkey(prk: &[u8], info: &[u8]) -> Result<[u8; 32], KdfError> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| KdfError::PrkTooShort)?;
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).map_err(|_| KdfError::ExpandFailed)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_session_psk(byte: u8) -> SessionPsk {
        SessionPsk::new([byte; WG_KEY_LEN])
    }

    #[test]
    fn derive_wg_psk_is_deterministic() {
        let psk = fixture_session_psk(0x42);
        let first = derive_wg_psk(&psk, 7).expect("first");
        let second = derive_wg_psk(&psk, 7).expect("second");
        assert_eq!(first.as_bytes(), second.as_bytes(), "same inputs collide deterministically");
    }

    #[test]
    fn derive_wg_psk_varies_by_rotation_counter() {
        let psk = fixture_session_psk(0x42);
        let zeroth = derive_wg_psk(&psk, 0).expect("0");
        let first = derive_wg_psk(&psk, 1).expect("1");
        assert_ne!(zeroth.as_bytes(), first.as_bytes(), "different counters diverge");
    }

    #[test]
    fn derive_wg_psk_varies_by_session_psk() {
        let psk_a = fixture_session_psk(0x01);
        let psk_b = fixture_session_psk(0x02);
        let from_a = derive_wg_psk(&psk_a, 0).expect("a");
        let from_b = derive_wg_psk(&psk_b, 0).expect("b");
        assert_ne!(from_a.as_bytes(), from_b.as_bytes(), "different PRKs diverge");
    }

    #[test]
    fn derive_subkey_is_deterministic() {
        let prk = [9u8; 32];
        let info = b"unit-test-purpose";
        let first = derive_subkey(&prk, info).expect("first");
        let second = derive_subkey(&prk, info).expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn derive_subkey_varies_by_info() {
        let prk = [9u8; 32];
        let purpose_a = derive_subkey(&prk, b"purpose-a").expect("a");
        let purpose_b = derive_subkey(&prk, b"purpose-b").expect("b");
        assert_ne!(purpose_a, purpose_b, "info separates derivations");
    }

    #[test]
    fn derive_subkey_rejects_short_prk() {
        let too_short = [9u8; 16];
        let err = derive_subkey(&too_short, b"info").expect_err("must reject short PRK");
        assert!(matches!(err, KdfError::PrkTooShort));
    }
}
