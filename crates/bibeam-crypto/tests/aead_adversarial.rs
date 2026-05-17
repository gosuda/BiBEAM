#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Adversarial tests for [`bibeam_crypto::ControlAead`].
//!
//! The inline `#[cfg(test)]` module in `aead.rs` already covers
//! tampered ciphertext (`modified_ciphertext_fails_open`), wrong
//! associated data (`wrong_aad_fails_open`), and wrong nonce
//! (`wrong_nonce_fails_open`). This file fills the two integration-
//! level gaps from §B2 of the plan:
//!
//! 1. **Wrong key** — the inline tests all reuse one `KEY`, so a
//!    regression that ignored the key would not be caught. Open a
//!    seal made with `key_a` using `key_b` and assert
//!    [`AeadError::Open`].
//! 2. **Truncated ciphertext below tag size** — Poly1305 appends a
//!    16-byte authentication tag; a ciphertext shorter than 16 bytes
//!    cannot carry a valid tag. The AEAD must reject without
//!    panicking on slice arithmetic.

use bibeam_crypto::{AEAD_KEY_LEN, AEAD_NONCE_LEN, AeadError, ControlAead};

const NONCE: [u8; AEAD_NONCE_LEN] =
    [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

const fn key(byte: u8) -> [u8; AEAD_KEY_LEN] {
    [byte; AEAD_KEY_LEN]
}

/// A ciphertext sealed under one key must not open under a different
/// key. Surfaces as [`AeadError::Open`] (the only failure variant
/// `open` produces — `Seal` is reserved for the dual direction).
#[test]
fn decrypt_rejects_wrong_key() {
    let aead_a = ControlAead::new(&key(0xAA));
    let aead_b = ControlAead::new(&key(0xBB));
    let ct = aead_a.seal(&NONCE, b"aad", b"plaintext").expect("seal under key A");
    let err = aead_b
        .open(&NONCE, b"aad", &ct)
        .expect_err("ciphertext from key A must not open under key B");
    assert!(matches!(err, AeadError::Open), "expected AeadError::Open, got {err:?}");
}

/// Poly1305 appends a 16-byte tag to the ciphertext. For any input
/// shorter than the tag length the AEAD cannot extract a tag from
/// the bytes, so it must reject — and reject with the typed
/// [`AeadError::Open`], not by panicking on `ct.len() - 16`. Covers
/// every length from 0 to 15 bytes.
#[test]
fn decrypt_rejects_truncated_ciphertext_below_tag_size() {
    let aead = ControlAead::new(&key(0xCC));
    for len in 0_usize..16 {
        let truncated = vec![0_u8; len];
        let err = aead
            .open(&NONCE, b"aad", &truncated)
            .expect_err(&format!("len={len} (below tag size) must reject without panic"));
        assert!(
            matches!(err, AeadError::Open),
            "len={len}: expected AeadError::Open, got {err:?}",
        );
    }
}
