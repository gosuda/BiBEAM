#![forbid(unsafe_code)]
//! X25519 keypair primitives and 32-byte keying-material newtypes for
//! `WireGuard` peers (F-CRYPTO.1) and the [`SessionPsk`] / [`WgPsk`]
//! envelopes consumed by F-CRYPTO.5 and F-CRYPTO.6.
//!
//! Scope (per D-4): pure key and keying-material helpers only. This
//! module:
//!
//! - Generates and serialises X25519 peer keypairs ([`WgSecretKey`],
//!   [`WgPublicKey`]). The public key serialises in standard
//!   `WireGuard`-wire base64 form — the same form `wg-quick` and the
//!   `wg` tool print and parse.
//! - Owns the newtype envelopes for the two flavours of 32-byte WG
//!   keying material: [`SessionPsk`] (per-invite, long-term, owned by
//!   F-CRYPTO.6) and [`WgPsk`] (per-rotation, short-term, owned by
//!   F-CRYPTO.5).
//!
//! Out of scope: deriving any PSK (that is F-CRYPTO.5 / F-CRYPTO.6),
//! building a `WgPeerConfig`, rendering `wg-quick` text, or wrapping a
//! `boringtun` tunnel — those live in `bibeam-transport` per D-4's
//! architecture line.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an X25519 public or secret key in bytes (32 octets).
pub const WG_KEY_LEN: usize = 32;

/// X25519 secret key for a `WireGuard` peer.
///
/// The wrapped [`StaticSecret`] is zeroised on drop by the
/// `x25519-dalek` crate's default `zeroize` feature; the
/// [`ZeroizeOnDrop`] derive on this newtype is the explicit
/// type-level marker that F-CRYPTO.7's audit consumes. The redacted
/// [`core::fmt::Debug`] impl below means the bytes cannot leak
/// through `tracing` or `format!("{:?}", …)` either.
#[derive(Clone, ZeroizeOnDrop)]
pub struct WgSecretKey(StaticSecret);

impl core::fmt::Debug for WgSecretKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("WgSecretKey").finish_non_exhaustive()
    }
}

impl WgSecretKey {
    /// Generate a fresh X25519 secret key using the OS-seeded thread
    /// RNG.
    ///
    /// 32 raw bytes are drawn from [`rand::random`] (a cryptographic
    /// thread-local RNG seeded from the OS on first use) and passed
    /// to [`StaticSecret::from`]. We deliberately avoid feeding the
    /// `x25519-dalek` constructor a `RngCore` impl directly: the
    /// `rand`/`rand_core` ecosystem currently spans two major
    /// versions and threading a single trait object through both is
    /// far more brittle than producing 32 bytes once.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes: [u8; WG_KEY_LEN] = rand::random();
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        Self(secret)
    }

    /// Derive this secret key's public peer key.
    #[must_use]
    pub fn public(&self) -> WgPublicKey {
        WgPublicKey(PublicKey::from(&self.0))
    }

    /// Return the raw 32-byte secret. Callers must zeroise the copy
    /// they hold.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; WG_KEY_LEN] {
        self.0.to_bytes()
    }
}

/// X25519 public key for a `WireGuard` peer.
///
/// `WireGuard`'s wire form for public keys is standard base64 of the
/// raw 32 octets. [`Self::to_wg_base64`] and
/// [`Self::from_wg_base64`] round-trip that form.
#[derive(Clone, Debug)]
pub struct WgPublicKey(PublicKey);

impl WgPublicKey {
    /// Wrap an existing `x25519_dalek::PublicKey`.
    #[must_use]
    pub const fn new(inner: PublicKey) -> Self {
        Self(inner)
    }

    /// Encode the 32 public-key bytes as standard base64 — the form
    /// `wg-quick`, `wg`, and stock `WireGuard` clients accept.
    #[must_use]
    pub fn to_wg_base64(&self) -> String {
        BASE64.encode(self.0.as_bytes())
    }

    /// Decode a standard-base64 32-byte public key as printed by
    /// `wg-quick` / `wg`.
    ///
    /// # Errors
    ///
    /// Returns [`WgKeyError::Base64`] if the input is not valid
    /// base64, and [`WgKeyError::WrongLength`] if the decoded byte
    /// count is anything other than 32.
    pub fn from_wg_base64(input: &str) -> Result<Self, WgKeyError> {
        let raw = BASE64.decode(input.trim().as_bytes()).map_err(WgKeyError::Base64)?;
        let bytes: [u8; WG_KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| WgKeyError::WrongLength { got: raw.len() })?;
        Ok(Self(PublicKey::from(bytes)))
    }

    /// Borrow the raw 32 public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        self.0.as_bytes()
    }
}

impl PartialEq for WgPublicKey {
    fn eq(&self, other: &Self) -> bool {
        // Public keys aren't secret, but `subtle` is cheap and the
        // policy of constant-time equality on key-shaped values is
        // simpler to reason about uniformly.
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for WgPublicKey {}

/// 32-byte per-invite long-term `WireGuard` pre-shared key.
///
/// Output of `derive_session_psk` (F-CRYPTO.6 — added in a later
/// commit in this series). Persists across rotations: callers feed
/// it to `derive_wg_psk` (F-CRYPTO.5) each rotation window to obtain
/// the per-rotation [`WgPsk`].
///
/// Held by reference everywhere downstream; this newtype exists so a
/// caller cannot accidentally mix a per-invite key with a per-rotation
/// [`WgPsk`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionPsk([u8; WG_KEY_LEN]);

impl SessionPsk {
    /// Wrap 32 raw bytes as a `SessionPSK`.
    #[must_use]
    pub const fn new(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for SessionPsk {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("SessionPsk").finish_non_exhaustive()
    }
}

impl PartialEq for SessionPsk {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SessionPsk {}

/// 32-byte per-rotation `WireGuard` pre-shared key.
///
/// Output of `derive_wg_psk` (F-CRYPTO.5 — added in a later commit
/// in this series). Lifetime is one rotation window — `bibeam-transport`
/// feeds this value into `boringtun::Tunn` as the WG PSK for the
/// matching peer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WgPsk([u8; WG_KEY_LEN]);

impl WgPsk {
    /// Wrap 32 raw bytes as a `WgPsk`.
    #[must_use]
    pub const fn new(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for WgPsk {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("WgPsk").finish_non_exhaustive()
    }
}

impl PartialEq for WgPsk {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for WgPsk {}

/// Errors decoding a `WireGuard`-wire public key.
#[derive(Debug, Error)]
pub enum WgKeyError {
    /// The candidate string was not valid base64.
    #[error("invalid base64 in WireGuard public key: {0}")]
    Base64(base64::DecodeError),
    /// The decoded byte count was not exactly [`WG_KEY_LEN`].
    #[error("WireGuard public key has wrong length: got {got}, expected {WG_KEY_LEN}")]
    WrongLength {
        /// Number of bytes the candidate actually decoded to.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_round_trip_via_base64() {
        let sk = WgSecretKey::generate();
        let pk = sk.public();
        let encoded = pk.to_wg_base64();
        let decoded = WgPublicKey::from_wg_base64(&encoded).expect("decode");
        assert_eq!(pk.as_bytes(), decoded.as_bytes(), "round-trip preserves bytes");
    }

    #[test]
    fn distinct_secrets_have_distinct_publics() {
        let first = WgSecretKey::generate().public();
        let second = WgSecretKey::generate().public();
        assert_ne!(first.as_bytes(), second.as_bytes(), "two fresh keys collide");
    }

    #[test]
    fn rejects_short_base64() {
        let err = WgPublicKey::from_wg_base64("AAAA").expect_err("too short must error");
        assert!(matches!(err, WgKeyError::WrongLength { got: 3 }));
    }

    #[test]
    fn rejects_garbage_base64() {
        let err = WgPublicKey::from_wg_base64("!!!not-base64!!!").expect_err("must error");
        assert!(matches!(err, WgKeyError::Base64(_)));
    }

    #[test]
    fn debug_redacts_secret_material() {
        let sk = WgSecretKey::generate();
        let dbg_sk = format!("{sk:?}");
        assert!(
            !dbg_sk.chars().any(|byte| byte.is_ascii_digit()),
            "{dbg_sk} should not leak bytes",
        );
        let psk = SessionPsk::new([1; WG_KEY_LEN]);
        let dbg_psk = format!("{psk:?}");
        assert!(!dbg_psk.contains("1, 1"));
    }
}
