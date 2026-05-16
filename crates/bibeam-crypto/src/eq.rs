//! Constant-time equality helpers for secrets, tokens, MACs, and key fingerprints.
//!
//! Downstream crates compare PASETO tokens, BLAKE3-keyed-hash MAC tags, and
//! various 32-byte secret-key fingerprints. Plain `==` on `[u8; N]` short-circuits
//! on the first differing byte; for secret material that lets a timing-side-channel
//! observer infer prefixes of the secret. These helpers wrap [`subtle::ConstantTimeEq`]
//! so callers do not have to re-import the `subtle` crate at every comparison site.
//!
//! The per-type `PartialEq` impls inside this crate (e.g. on [`crate::SessionPsk`],
//! [`crate::WgPublicKey`], [`crate::WgPsk`], [`crate::MasterInviteKey`]) already
//! delegate to `ConstantTimeEq` directly. These free functions exist for callers
//! that hold raw byte buffers (e.g. a PASETO token string compared against a
//! coordinator-side fixture, or a BLAKE3 MAC tag compared against a transmitted
//! tag where neither side is wrapped in a domain newtype).

#![forbid(unsafe_code)]

use subtle::ConstantTimeEq;

/// Constant-time equality on two fixed-size 32-byte buffers.
///
/// Returns `true` if every byte is equal, `false` otherwise. Time taken is
/// independent of where the first differing byte (if any) sits.
#[must_use]
pub fn ct_eq_32(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
    lhs.ct_eq(rhs).into()
}

/// Constant-time equality on two byte slices.
///
/// Length mismatch short-circuits to `false` — leaking the length is acceptable
/// for the use cases here (PASETO tokens are fixed-format and MAC tag lengths are
/// public). For equal-length slices, the per-byte compare is constant-time.
#[must_use]
pub fn ct_eq_bytes(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    lhs.ct_eq(rhs).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_32_true_on_equal() {
        let lhs = [0xa5u8; 32];
        let rhs = [0xa5u8; 32];
        assert!(ct_eq_32(&lhs, &rhs));
    }

    #[test]
    fn ct_eq_32_false_on_one_byte_difference() {
        let lhs = [0xa5u8; 32];
        let mut rhs = [0xa5u8; 32];
        rhs[17] = 0xa6;
        assert!(!ct_eq_32(&lhs, &rhs));
    }

    #[test]
    fn ct_eq_bytes_false_on_length_mismatch() {
        assert!(!ct_eq_bytes(&[1, 2, 3], &[1, 2, 3, 4]));
        assert!(!ct_eq_bytes(&[1, 2, 3, 4], &[1, 2, 3]));
    }

    #[test]
    fn ct_eq_bytes_true_on_equal() {
        let lhs = b"paseto-token-fixture";
        let rhs = b"paseto-token-fixture";
        assert!(ct_eq_bytes(lhs, rhs));
    }

    #[test]
    fn ct_eq_bytes_false_on_last_byte_diff() {
        let lhs = b"paseto-token-fixture";
        let rhs = b"paseto-token-fixturE";
        assert!(!ct_eq_bytes(lhs, rhs));
    }

    #[test]
    fn ct_eq_bytes_true_on_empty() {
        assert!(ct_eq_bytes(b"", b""));
    }
}
