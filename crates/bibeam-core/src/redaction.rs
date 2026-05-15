#![forbid(unsafe_code)]
//! Keyed-BLAKE3 redaction helpers for PII surfaces (peer IDs, IP addresses).
//!
//! Log output and metrics labels must never carry raw peer identifiers or IP
//! addresses. This module derives a short, opaque hex token from each value
//! using a per-node [`RedactionKey`] so:
//!
//! - the same input under the same key always produces the same token
//!   (operators can still correlate events for one peer across log lines), and
//! - the token reveals nothing about the input without the key.
//!
//! The key is 32 bytes — exactly BLAKE3's keyed-hash key size — and is
//! held in a [`ZeroizeOnDrop`] wrapper so it gets wiped from memory on
//! drop.

use core::net::IpAddr;

use zeroize::ZeroizeOnDrop;

use crate::ids::PeerId;

/// Number of leading hex characters returned by every redaction helper.
///
/// 16 hex characters = 64 bits of the BLAKE3 output, which is enough to keep
/// collisions vanishingly unlikely while remaining readable in log lines.
const REDACTED_HEX_LEN: usize = 16;

/// 32-byte key for BLAKE3 keyed-hash PII redaction.
///
/// Each node should hold one [`RedactionKey`] for the lifetime of its
/// process. The key MUST stay private — anyone with the key can replay the
/// hash and de-anonymise any token this module emits.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RedactionKey([u8; 32]);

impl core::fmt::Debug for RedactionKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material — even on a panic path.
        formatter.debug_struct("RedactionKey").finish_non_exhaustive()
    }
}

impl RedactionKey {
    /// Construct a [`RedactionKey`] from a 32-byte buffer.
    ///
    /// The buffer should come from a CSPRNG; callers SHOULD NOT derive it
    /// from any low-entropy source.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    ///
    /// Intended for one place only — passing the key into BLAKE3. Callers
    /// outside this module should not need this.
    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hash `input` under `key` and return its first [`REDACTED_HEX_LEN`]
/// lowercase hex characters.
fn redact_bytes(key: &RedactionKey, input: &[u8]) -> String {
    let digest = blake3::keyed_hash(key.as_bytes(), input);
    let hex = digest.to_hex();
    hex[..REDACTED_HEX_LEN].to_owned()
}

/// Produce a redacted token for the given [`PeerId`].
///
/// Equivalent to `BLAKE3-keyed(peer_id.as_bytes())` truncated to 16 hex
/// characters.
#[must_use]
pub fn redact_peer_id(key: &RedactionKey, peer_id: &PeerId) -> String {
    let bytes = peer_id.into_ulid().to_bytes();
    redact_bytes(key, &bytes)
}

/// Produce a redacted token for the given IP address.
///
/// Hashes the textual form (e.g. `203.0.113.4` or
/// `2001:db8::1`) so v4 and v6 share the same code path.
#[must_use]
pub fn redact_ip(key: &RedactionKey, ip: IpAddr) -> String {
    redact_bytes(key, ip.to_string().as_bytes())
}
