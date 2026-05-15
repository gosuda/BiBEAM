#![forbid(unsafe_code)]
//! Identity primitives: the 32-byte BLAKE3 fingerprint over an X25519 public
//! key.
//!
//! A [`Fingerprint`] is the stable, comparable form of a peer's long-term
//! identity. It's what gets exchanged out-of-band (QR code, paper, sticky
//! note) and what every other layer of the stack uses for "is this the same
//! peer I trust?" decisions.
//!
//! [`PartialEq`] is implemented in constant time so a comparison against an
//! attacker-supplied value can't be measured to recover the legitimate
//! fingerprint a byte at a time.

use core::fmt;
use core::hash::{Hash, Hasher};

use subtle::ConstantTimeEq;

/// Number of leading hex characters shown by [`Fingerprint`]'s [`Debug`]
/// impl. Same convention as [`crate::redaction`]'s redacted tokens — 64
/// bits of output, readable in log lines.
const DEBUG_HEX_PREFIX: usize = 16;

/// 32-byte BLAKE3 digest of a peer's long-term X25519 public key.
///
/// Constructed via [`Fingerprint::from_x25519_pubkey`]; compare with
/// [`PartialEq`] (constant time); render with [`Debug`] (a short hex
/// prefix). The full 32 bytes are reachable through
/// [`Fingerprint::as_bytes`] for callers that need to emit the value on the
/// wire.
#[derive(Clone, Copy)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute the fingerprint of an X25519 public key.
    ///
    /// X25519 public keys are exactly 32 bytes, which is BLAKE3's full
    /// output size — so the fingerprint is BLAKE3 applied directly to the
    /// raw key bytes, no additional encoding.
    #[must_use]
    pub fn from_x25519_pubkey(pubkey: &[u8; 32]) -> Self {
        Self(*blake3::hash(pubkey).as_bytes())
    }

    /// Construct a fingerprint from raw 32 bytes.
    ///
    /// Primarily for deserialising a fingerprint that came over the wire;
    /// new fingerprints from a public key should use
    /// [`Fingerprint::from_x25519_pubkey`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the full 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Fingerprint {}

impl Hash for Fingerprint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = blake3::Hash::from_bytes(self.0).to_hex();
        write!(formatter, "Fingerprint({})", &hex[..DEBUG_HEX_PREFIX])
    }
}
