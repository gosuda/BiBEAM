#![forbid(unsafe_code)]
//! Control-plane AEAD wrapper around `ChaCha20-Poly1305` (F-CRYPTO.2).
//!
//! `ControlAead` exists to seal small control-plane structures —
//! PASETO claim extensions, redb audit-log entries, and any other
//! coordinator-side record that wants symmetric AEAD with explicit
//! AAD binding. The data-plane AEAD is owned by `boringtun` inside
//! `bibeam-transport` per D-4 and is **not** exposed here.
//!
//! The interface is deliberately small: a 256-bit key, a 96-bit
//! nonce, optional AAD, and a single round-trip pair. Callers are
//! responsible for nonce uniqueness — this module does not generate
//! nonces, store nonces, or detect reuse. Pair this wrapper with an
//! external nonce-management scheme (per-record counter persisted
//! alongside the ciphertext, random 96-bit nonce with a
//! ciphertext-size budget, etc.) appropriate to your call site.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;

/// `ChaCha20-Poly1305` key length in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// `ChaCha20-Poly1305` nonce length in bytes (96 bits).
pub const NONCE_LEN: usize = 12;

/// Errors returned by [`ControlAead::seal`] / [`ControlAead::open`].
#[derive(Debug, Error)]
pub enum AeadError {
    /// Sealing failed — should never happen with `ChaCha20-Poly1305` for
    /// reasonable input sizes, but the underlying API returns a
    /// `Result` so we surface it rather than panic.
    #[error("AEAD seal failed")]
    Seal,
    /// Opening failed — authentication tag did not verify (modified
    /// ciphertext, wrong key, wrong nonce, or wrong AAD).
    #[error("AEAD open failed: authentication tag did not verify")]
    Open,
}

/// Control-plane AEAD wrapper over `ChaCha20-Poly1305`.
///
/// One value per long-lived key. `seal` and `open` borrow `&self`, so
/// the wrapper is `Sync` and may be shared across threads — a single
/// `ControlAead` can fan out to many seal sites if the surrounding
/// nonce-management scheme guarantees uniqueness.
pub struct ControlAead {
    inner: ChaCha20Poly1305,
}

impl core::fmt::Debug for ControlAead {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("ControlAead").finish_non_exhaustive()
    }
}

impl ControlAead {
    /// Build a `ControlAead` from a 256-bit key.
    ///
    /// The caller retains ownership of the key bytes; the wrapper
    /// only borrows for the duration of this call to seed the cipher
    /// state, so the original buffer can be zeroised afterwards.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let key_ref = Key::from_slice(key);
        Self {
            inner: ChaCha20Poly1305::new(key_ref),
        }
    }

    /// Encrypt `plaintext`, binding `aad` into the authentication tag.
    ///
    /// Returns ciphertext with the 16-byte Poly1305 tag appended.
    ///
    /// # Errors
    ///
    /// Returns [`AeadError::Seal`] on the (vanishingly unlikely) case
    /// where the underlying AEAD implementation reports failure.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let nonce_ref = Nonce::from_slice(nonce);
        let payload = Payload { msg: plaintext, aad };
        self.inner.encrypt(nonce_ref, payload).map_err(|_| AeadError::Seal)
    }

    /// Decrypt `ciphertext` (with appended tag), verifying that `aad`
    /// matches what was bound at seal time.
    ///
    /// # Errors
    ///
    /// Returns [`AeadError::Open`] if the tag did not verify — wrong
    /// key, wrong nonce, modified ciphertext, or mismatched AAD.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let nonce_ref = Nonce::from_slice(nonce);
        let payload = Payload { msg: ciphertext, aad };
        self.inner.decrypt(nonce_ref, payload).map_err(|_| AeadError::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const NONCE: [u8; NONCE_LEN] =
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    #[test]
    fn seal_open_round_trip() {
        let aead = ControlAead::new(&KEY);
        let aad = b"context";
        let msg = b"hello control plane";
        let ct = aead.seal(&NONCE, aad, msg).expect("seal");
        let pt = aead.open(&NONCE, aad, &ct).expect("open");
        assert_eq!(pt, msg);
    }

    #[test]
    fn modified_ciphertext_fails_open() {
        let aead = ControlAead::new(&KEY);
        let mut ct = aead.seal(&NONCE, b"a", b"m").expect("seal");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let err = aead.open(&NONCE, b"a", &ct).expect_err("must reject tamper");
        assert!(matches!(err, AeadError::Open));
    }

    #[test]
    fn wrong_aad_fails_open() {
        let aead = ControlAead::new(&KEY);
        let ct = aead.seal(&NONCE, b"original-aad", b"m").expect("seal");
        let err = aead.open(&NONCE, b"other-aad", &ct).expect_err("must reject");
        assert!(matches!(err, AeadError::Open));
    }

    #[test]
    fn wrong_nonce_fails_open() {
        let aead = ControlAead::new(&KEY);
        let ct = aead.seal(&NONCE, b"a", b"m").expect("seal");
        let mut bad_nonce = NONCE;
        bad_nonce[0] ^= 0x01;
        let err = aead.open(&bad_nonce, b"a", &ct).expect_err("must reject");
        assert!(matches!(err, AeadError::Open));
    }
}
