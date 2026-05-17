#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Integration-level regression locks for the invite-signature
//! length guard at
//! [`bibeam_discovery::invite_validator::decode_signature_bytes`].
//!
//! The inline `#[cfg(test)]` module in `invite_validator.rs` already
//! covers most of the surface this plan flagged (lower-bound 32-byte
//! signature rejection, expiry-after-signature ordering). What is NOT
//! covered there is the **upper-bound** of the 64-byte length guard:
//! `bytes.try_into::<&[u8; 64]>()` rejects ANY non-64 length, but a
//! future refactor to `if bytes.len() < 64` would silently accept a
//! padded 128-byte signature. This integration test locks the upper
//! bound at the public API boundary.

use bibeam_core::Timestamp;
use bibeam_crypto::{INVITE_CODE_LEN, IdentitySecretKey, InviteCode};
use bibeam_discovery::{DiscoveryError, SignedInvite, verify_invite};

/// `decode_signature_bytes` enforces "exactly 64 bytes" via a
/// `try_into::<&[u8; 64]>()` over the slice. The existing inline
/// `verify_invite_rejects_short_signature_before_expiry_check` test
/// covers the below-64 case (32 bytes); this test covers the
/// above-64 case (128 bytes). The error variant is
/// [`DiscoveryError::Url`] tagged "decode", matching the lower-bound
/// test's contract.
#[test]
fn rejects_signature_too_long() {
    let secret = IdentitySecretKey::generate();
    let issuer = secret.public();
    let signed = SignedInvite {
        code: InviteCode::new([0xAB; INVITE_CODE_LEN]),
        issuer: issuer.clone(),
        issued_at: Timestamp::now(),
        expires_at: None,
        // 128 bytes — double the expected length. A `len < 64` guard
        // would accept this; the `try_into` guard rejects it.
        signature: vec![0_u8; 128],
    };
    let err = verify_invite(&signed, &issuer).expect_err("oversized signature must reject");
    match err {
        DiscoveryError::Url(message) => {
            assert!(message.contains("decode"), "expected decode tag, got: {message}");
            assert!(
                message.contains("128") || message.contains("64"),
                "error should mention the length mismatch (got=128 or expected=64): {message}",
            );
        },
        other => panic!("expected DiscoveryError::Url, got {other:?}"),
    }
}
