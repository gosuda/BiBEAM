#![forbid(unsafe_code)]
//! pkarr-on-Mainline-DHT fallback (F-DISC.4).
//!
//! Used when every coordinator in a [`crate::failover::CoordinatorPool`]
//! returned a retriable error: the peer falls back to resolving the
//! target peer's record from the Mainline DHT through `pkarr`. The
//! DHT path is **degraded** by design — no admission gate enforces who
//! published the record, and no anonymity-set guarantee applies. The
//! cohort-and-exit subsystem treats records resolved through this
//! module as best-effort hints only.
//!
//! ## Binding: Ed25519 identity key, not `PeerId`
//!
//! The original F-DISC.4 spec hands [`DhtFallback::resolve_peer`] a
//! [`bibeam_core::PeerId`] (a 16-byte ULID). pkarr resolves records
//! keyed by an Ed25519 public key — the **publisher must hold the
//! matching secret to sign the packet**. ULIDs are not curve points
//! and have no associated secret, so no entity could publish the
//! record under a `PeerId`-derived key (a hash of the ULID would be
//! statistically a valid curve point only ~half the time, and even
//! when valid, nobody would hold the discrete log).
//!
//! We adapt by taking a [`bibeam_crypto::IdentityPublicKey`]: the
//! Ed25519 identity key the coordinator and the peer already share
//! through the control plane. The peer (or the coordinator, signing
//! on its behalf) holds the matching [`bibeam_crypto::IdentitySecretKey`]
//! and can publish a [`SignedPacket`] under it. The `PeerId` →
//! `IdentityPublicKey` mapping is held by the coordinator as part of
//! the per-peer registry; F-DISC.4 covers only the resolve path.
//!
//! ## Wire form of the resolved record
//!
//! The peer record is published as one DNS TXT record. Each
//! character string inside the TXT is a chunk of the **base64-encoded
//! postcard** bytes of [`crate::records::PeerRecord`]; concatenating
//! the strings in order reconstructs the full base64 payload.
//!
//! We read each character string through `TXT::iter_raw` (re-exported
//! by pkarr from `simple-dns`), which yields a
//! `(key_bytes, Option<value_bytes>)` pair per string by splitting at
//! the first `=`. We **rejoin** those halves back with `=` so base64
//! padding (`=`, `==`) and key/value-shaped chunks survive intact;
//! the alternative `attributes()` view loses padding and is not
//! suitable for binary-shaped payloads.
//!
//! Postcard keeps the on-wire size small; base64 keeps the value
//! inside the printable-ASCII subset every TXT consumer tolerates.
//! Multi-string TXT records are supported so records larger than the
//! 255-byte character-string limit can still travel through the
//! pkarr/DHT path.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use pkarr::dns::rdata::RData;
use pkarr::{Client, ClientBuilder, PublicKey, SignedPacket};

use bibeam_crypto::IdentityPublicKey;

use crate::error::DiscoveryError;
use crate::records::PeerRecord;

/// pkarr-on-Mainline-DHT fallback resolver.
///
/// One instance per process is sufficient; the inner [`Client`] is
/// `Clone` and cheap to share. Constructed in DHT-only mode (no
/// relays) by default.
#[derive(Clone)]
pub struct DhtFallback {
    /// pkarr client configured for Mainline-DHT-only operation.
    pkarr_client: Client,
}

impl core::fmt::Debug for DhtFallback {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("DhtFallback").finish_non_exhaustive()
    }
}

impl DhtFallback {
    /// Build a DHT-only fallback resolver.
    ///
    /// Relays are explicitly disabled via
    /// [`ClientBuilder::no_relays`] so the configured network surface
    /// is exactly Mainline DHT. Bootstrap nodes are pkarr's defaults.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Url`] tagged "pkarr build" if the
    /// underlying [`ClientBuilder::build`] fails (typically a missing
    /// runtime or no network).
    pub fn new() -> Result<Self, DiscoveryError> {
        let mut builder = ClientBuilder::default();
        builder.no_relays();
        let pkarr_client = builder
            .build()
            .map_err(|err| DiscoveryError::Url(format!("pkarr build: {err}")))?;
        Ok(Self { pkarr_client })
    }

    /// Resolve a peer's [`PeerRecord`] from the Mainline DHT.
    ///
    /// `identity` is the Ed25519 identity key the peer (or the
    /// coordinator on its behalf) used to sign the published
    /// [`SignedPacket`]. See the module rustdoc for why this binding
    /// is used instead of [`bibeam_core::PeerId`].
    ///
    /// 1. Convert `identity` into a pkarr [`PublicKey`] via the raw
    ///    32 Ed25519 bytes.
    /// 2. Ask pkarr to resolve the latest [`SignedPacket`] for that
    ///    key.
    /// 3. Scan the packet's resource records for a TXT entry,
    ///    base64-decode the joined attributes, and postcard-decode
    ///    the result as [`PeerRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Url`] when the binding fails (the 32
    /// identity bytes are not a valid Ed25519 curve point), when no
    /// packet is available (pkarr returned `None`), when the packet
    /// lacks a usable TXT record, when base64 decoding fails, or
    /// when the payload does not postcard-decode as [`PeerRecord`].
    /// The same error variant is used for all cases because callers
    /// observing a DHT-fallback failure treat them uniformly — there
    /// is no retriable subset.
    pub async fn resolve_peer(
        &self,
        identity: &IdentityPublicKey,
    ) -> Result<PeerRecord, DiscoveryError> {
        let key = identity_to_pkarr_public_key(identity)?;
        let packet = self
            .pkarr_client
            .resolve(&key)
            .await
            .ok_or_else(|| DiscoveryError::Url("pkarr resolve: no signed packet".into()))?;
        extract_peer_record(&packet)
    }
}

/// Convert a [`bibeam_crypto::IdentityPublicKey`] into a pkarr
/// [`PublicKey`].
///
/// The `IdentityPublicKey` already wraps a valid Ed25519 verifying
/// key, so the conversion is total in practice — the `Err` arm
/// exists only because pkarr's [`PublicKey::try_from`] returns
/// `Result`.
fn identity_to_pkarr_public_key(identity: &IdentityPublicKey) -> Result<PublicKey, DiscoveryError> {
    let bytes: &[u8; 32] = identity.as_bytes();
    PublicKey::try_from(bytes).map_err(|err| DiscoveryError::Url(format!("pkarr binding: {err}")))
}

/// Scan a resolved [`SignedPacket`] for a base64-postcard
/// [`PeerRecord`].
///
/// Each TXT record is treated as a candidate: its character strings
/// are concatenated raw (no key/value parsing), base64-decoded, and
/// passed to postcard. The first TXT that decodes cleanly wins; a
/// malformed TXT does not poison the scan, so unrelated TXT records
/// can coexist with the peer record in the same packet.
fn extract_peer_record(packet: &SignedPacket) -> Result<PeerRecord, DiscoveryError> {
    let mut last_error: Option<DiscoveryError> = None;
    for record in packet.all_resource_records() {
        if let RData::TXT(txt) = &record.rdata {
            match try_decode_txt(txt) {
                Ok(Some(peer_record)) => return Ok(peer_record),
                Ok(None) => {},
                Err(err) => last_error = Some(err),
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| DiscoveryError::Url("pkarr resolve: no usable TXT record".into())))
}

/// Try to decode a single TXT record's character strings as a
/// base64-encoded postcard [`PeerRecord`].
///
/// Returns:
///
/// - `Ok(Some(record))` on a successful decode.
/// - `Ok(None)` when the record carries no payload bytes (e.g. an
///   empty TXT — common in service discovery, never an error).
/// - `Err(DiscoveryError::Url)` when base64 or postcard rejected the
///   payload; the caller continues scanning but remembers the last
///   failure for diagnostics.
fn try_decode_txt(txt: &pkarr::dns::rdata::TXT<'_>) -> Result<Option<PeerRecord>, DiscoveryError> {
    let joined = reassemble_txt_bytes(txt);
    if joined.is_empty() {
        return Ok(None);
    }
    let decoded = BASE64
        .decode(&joined)
        .map_err(|err| DiscoveryError::Url(format!("pkarr TXT base64: {err}")))?;
    postcard::from_bytes::<PeerRecord>(&decoded)
        .map(Some)
        .map_err(|err| DiscoveryError::Url(format!("pkarr TXT postcard: {err}")))
}

/// Concatenate every character string in `txt` back into one byte
/// vector.
///
/// `iter_raw` yields `(key, Option<value>)` where the split point is
/// the first `=` in the original string. We rejoin halves with `=`
/// so base64 padding survives — `"abc=="` parses as
/// `("abc", Some("="))` and we recover `b"abc=="` byte-exactly. A
/// string with no `=` parses as `(string, None)` and contributes its
/// `key` half verbatim.
fn reassemble_txt_bytes(txt: &pkarr::dns::rdata::TXT<'_>) -> Vec<u8> {
    let mut joined: Vec<u8> = Vec::new();
    for (key, value) in txt.iter_raw() {
        joined.extend_from_slice(key);
        if let Some(value_bytes) = value {
            joined.push(b'=');
            joined.extend_from_slice(value_bytes);
        }
    }
    joined
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bibeam_core::{PeerId, Timestamp};
    use bibeam_crypto::IdentitySecretKey;
    use pkarr::dns::rdata::TXT;

    use super::*;

    fn sample_peer_record() -> PeerRecord {
        PeerRecord {
            peer_id: PeerId::new(),
            addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)), 41_443),
            can_exit: false,
            capacity_hint: 17,
            last_seen: Timestamp::now(),
            region: String::new(),
            region_last_verified_at: Timestamp::now(),
            wg_public_key: None,
        }
    }

    fn encode_record(record: &PeerRecord) -> String {
        let bytes = postcard::to_allocvec(record).expect("postcard encode");
        BASE64.encode(&bytes)
    }

    /// Build a TXT record whose character strings concatenate to
    /// `payload`. `chunk_size` controls how the payload is split
    /// across character strings; must lie in `1..=255` (the
    /// `CharacterString` hard limit). `Box::leak` keeps the chunk
    /// bytes alive for `'static`, which is what
    /// `CharacterString::new` requires in this test.
    fn txt_from_payload(payload: &str, chunk_size: usize) -> TXT<'static> {
        assert!((1..=255).contains(&chunk_size), "invalid chunk size");
        let mut txt = TXT::new();
        let bytes = payload.as_bytes();
        let mut cursor: usize = 0;
        while cursor < bytes.len() {
            let chunk_end = (cursor + chunk_size).min(bytes.len());
            let slice = &bytes[cursor..chunk_end];
            let owned: Vec<u8> = slice.to_vec();
            let leaked: &'static [u8] = Box::leak(owned.into_boxed_slice());
            txt.add_char_string(
                pkarr::dns::CharacterString::new(leaked).expect("CharacterString new"),
            );
            cursor = chunk_end;
        }
        txt
    }

    #[test]
    fn identity_to_pkarr_public_key_is_total_for_real_identity_keys() {
        // Every IdentitySecretKey::generate output is a valid Ed25519
        // verifying key by construction; pkarr's `try_from` must
        // therefore accept it. Run a handful to guard against a
        // future binding change.
        for _ in 0_u32..8 {
            let secret = IdentitySecretKey::generate();
            let identity = secret.public();
            let key = identity_to_pkarr_public_key(&identity).expect("real Ed25519 key accepted");
            // Round-trip the raw bytes: pkarr's PublicKey must agree
            // with the source identity on every byte.
            assert_eq!(key.as_bytes(), identity.as_bytes().as_slice());
        }
    }

    #[test]
    fn identity_to_pkarr_public_key_is_deterministic() {
        let secret = IdentitySecretKey::generate();
        let identity = secret.public();
        let first = identity_to_pkarr_public_key(&identity).expect("first");
        let second = identity_to_pkarr_public_key(&identity).expect("second");
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    /// Count how many character strings a TXT record holds by
    /// iterating its raw view; `iter_raw` yields one item per
    /// `CharacterString`.
    fn txt_string_count(txt: &TXT<'_>) -> usize {
        txt.iter_raw().count()
    }

    #[test]
    fn try_decode_txt_round_trips_single_string_payload() {
        let original = sample_peer_record();
        let payload = encode_record(&original);
        // A single character string holds the whole payload.
        let txt = txt_from_payload(&payload, 255);
        assert_eq!(txt_string_count(&txt), 1, "single-chunk fixture must produce one string");
        let decoded = try_decode_txt(&txt)
            .expect("decode result")
            .expect("non-empty payload yields record");
        assert_eq!(decoded, original);
    }

    #[test]
    fn try_decode_txt_handles_multi_string_chunked_payload() {
        // Splitting the same base64 payload into 16-byte chunks
        // forces the decoder onto its multi-string concatenation
        // path. We assert at least two chunks so a future change
        // that accidentally falls back to a single string fails
        // loudly.
        let original = sample_peer_record();
        let payload = encode_record(&original);
        assert!(payload.len() > 16, "fixture payload must be longer than one chunk");
        let txt = txt_from_payload(&payload, 16);
        assert!(txt_string_count(&txt) >= 2, "multi-chunk fixture must produce multiple strings");
        let decoded = try_decode_txt(&txt)
            .expect("decode result")
            .expect("non-empty payload yields record");
        assert_eq!(decoded, original);
    }

    #[test]
    fn try_decode_txt_returns_none_on_empty_record() {
        let txt = TXT::new();
        let decoded = try_decode_txt(&txt).expect("empty txt is not an error");
        assert!(decoded.is_none());
    }

    #[test]
    fn try_decode_txt_reports_error_on_garbage_payload() {
        let txt = txt_from_payload("not-valid-base64-!!!", 255);
        let err = try_decode_txt(&txt).expect_err("garbage must error");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("base64")));
    }
}
