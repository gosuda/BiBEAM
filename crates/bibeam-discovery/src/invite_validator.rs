#![forbid(unsafe_code)]
//! Invite-code Ed25519 signature validator (F-DISC.6).
//!
//! A coordinator issuing an invite signs a deterministic payload
//! that binds three fields together — the [`InviteCode`] bytes, the
//! issue time, and the optional expiry — with its long-term
//! [`bibeam_crypto::IdentitySecretKey`]. Peers redeeming an invite
//! present the resulting [`SignedInvite`] to the coordinator; the
//! coordinator's matching [`bibeam_crypto::IdentityPublicKey`] is
//! distributed out-of-band (printed, scanned from a QR code, served
//! from a static URL) so a peer can verify the invite locally before
//! starting any network round-trip.
//!
//! ## Signing payload
//!
//! The byte layout is the **domain-separated postcard**
//! serialisation
//!
//! ```text
//! (
//!     domain: &str = "bibeam.invite.v1",
//!     code: [u8; bibeam_crypto::INVITE_CODE_LEN] = 16 bytes,
//!     issued_at: bibeam_core::Timestamp,
//!     expires_at_or_epoch: bibeam_core::Timestamp,
//! )
//! ```
//!
//! The leading `"bibeam.invite.v1"` domain string is a fixed-version
//! domain-separator: the same coordinator key signs other artifacts
//! (PASETO session tokens, future signed records), and the domain
//! prefix guarantees a signature minted for one purpose cannot be
//! replayed as another. A future invite format must bump the suffix
//! (`.v2`) to remain distinguishable.
//!
//! `expires_at` is folded into a non-`Option`-shaped [`Timestamp`]
//! before encoding: when the invite never expires, we substitute
//! [`OffsetDateTime::UNIX_EPOCH`] (1970-01-01T00:00:00Z), which the
//! verifier recognises by reading the `expires_at` field of the
//! [`SignedInvite`] (not by re-parsing the signed payload). The
//! reason for the substitution is **canonicalisation**: postcard
//! encodes `Option<T>` with a leading variant byte, so an
//! `expires_at_or_zero: Timestamp` field keeps the wire form
//! lock-stepped across "expires" and "never expires" invites and
//! removes a round-trip ambiguity (`Some(UNIX_EPOCH)` vs `None`).
//!
//! [`Timestamp`] serialises as RFC 3339 (see
//! [`bibeam_core::time::Timestamp`]); postcard treats that as a
//! length-prefixed UTF-8 string. The whole payload is deterministic
//! in byte form for fixed inputs, which is what the signature
//! relies on.
//!
//! ## Issuer binding
//!
//! [`SignedInvite::issuer`] is **not** part of the signed payload —
//! including it would let an attacker swap the field freely. The
//! field is therefore a hint only; [`verify_invite`] rejects when
//! `signed.issuer` does not match the trusted `coord_pubkey` passed
//! into the call, before doing any signature work. Callers that
//! have a single trusted coordinator can ignore the field entirely;
//! callers with a roster look the trusted pubkey up by `issuer` and
//! then call `verify_invite` with the chosen pubkey.
//!
//! ## Verification order
//!
//! [`verify_invite`] performs, in order:
//!
//! 1. Match `signed.issuer` against `coord_pubkey`.
//! 2. Decode the signature bytes.
//! 3. Verify the Ed25519 signature.
//! 4. **Only then** check the expiry.
//!
//! Step 3 runs before step 4 so a bad-signature invite cannot
//! side-channel-leak through an expiry-check timing difference, and
//! rejecting a tampered invite at a later step is a downgrade
//! attack surface we deliberately close.

use bibeam_core::Timestamp;
use bibeam_crypto::{INVITE_CODE_LEN, IdentityPublicKey, InviteCode};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::DiscoveryError;

/// Sentinel substituted for `expires_at` in the signed payload when
/// the invite carries no expiry. Picked as the Unix epoch because:
///
/// - it is far enough in the past that any live invite has a real
///   `expires_at >= now` and cannot collide with it,
/// - [`OffsetDateTime::UNIX_EPOCH`] is `const`,
/// - and it round-trips cleanly through RFC 3339 / postcard.
const NEVER_EXPIRES_PAYLOAD_MARKER: Timestamp =
    Timestamp::from_offset_date_time(OffsetDateTime::UNIX_EPOCH);

/// Fixed domain-separator string mixed into the signed payload as
/// its leading element. A future incompatible change to the invite
/// shape must bump the suffix (`.v2`, `.v3`, …) so a verifier built
/// against the new format can refuse a v1-signed invite by virtue
/// of the prefix mismatch alone.
const INVITE_SIGNING_DOMAIN: &str = "bibeam.invite.v1";

/// An invite carrying an Ed25519 signature over its
/// [`signing_payload`].
///
/// `InviteCode` and `IdentityPublicKey` do not carry serde derives
/// of their own; field-level adapters route each through its
/// raw-byte form — see the `invite_code_serde` and `issuer_serde`
/// private modules in this file for the byte layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInvite {
    /// 16-byte invite code the coordinator minted.
    #[serde(with = "invite_code_serde")]
    pub code: InviteCode,
    /// Long-term identity public key of the issuing coordinator.
    /// **Hint only** — not part of the signed payload. See
    /// [`verify_invite`] for the issuer-mismatch check that ensures
    /// the hint cannot be replayed against a different trusted key.
    #[serde(with = "issuer_serde")]
    pub issuer: IdentityPublicKey,
    /// When the coordinator issued this invite.
    pub issued_at: Timestamp,
    /// Wall-clock instant after which the invite must be rejected,
    /// or `None` if it never expires.
    pub expires_at: Option<Timestamp>,
    /// Raw Ed25519 signature bytes (64 octets) over the
    /// [`signing_payload`] computed from `(code, issued_at,
    /// expires_at)`. Stored as `Vec<u8>` so the wire shape is
    /// independent of `ed25519-dalek`'s [`Signature`] re-encoding
    /// choices.
    pub signature: Vec<u8>,
}

/// Serde adapter for [`bibeam_crypto::InviteCode`].
///
/// Encodes / decodes the raw 16 bytes as a fixed-length byte array.
/// Serde + postcard treat `[u8; N]` as a packed N-byte sequence, so
/// the on-wire size matches the source bytes exactly.
mod invite_code_serde {
    use bibeam_crypto::{INVITE_CODE_LEN, InviteCode};
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub(super) fn serialize<TargetSerializer>(
        code: &InviteCode,
        serializer: TargetSerializer,
    ) -> Result<TargetSerializer::Ok, TargetSerializer::Error>
    where
        TargetSerializer: Serializer,
    {
        let bytes: &[u8; INVITE_CODE_LEN] = code.as_bytes();
        bytes.serialize(serializer)
    }

    pub(super) fn deserialize<'de, SourceDeserializer>(
        deserializer: SourceDeserializer,
    ) -> Result<InviteCode, SourceDeserializer::Error>
    where
        SourceDeserializer: Deserializer<'de>,
    {
        let bytes = <[u8; INVITE_CODE_LEN]>::deserialize(deserializer)?;
        Ok(InviteCode::new(bytes))
    }
}

/// Serde adapter for [`bibeam_crypto::IdentityPublicKey`].
///
/// Encodes the raw 32 Ed25519 public-key bytes as a fixed-length
/// byte array. On decode we reconstruct the key via SPKI: build a
/// [`VerifyingKey`] from raw bytes, encode it to SPKI PEM, then
/// hand the PEM to [`IdentityPublicKey::from_pem`] (the only public
/// constructor on the wrapper today). PEM is a one-off intermediary
/// hop — the wire form is the compact 32-byte array, not PEM —
/// so the on-wire size stays compact for postcard.
mod issuer_serde {
    use bibeam_crypto::IdentityPublicKey;
    use ed25519_dalek::VerifyingKey;
    use ed25519_dalek::pkcs8::EncodePublicKey as _;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer, de::Error as _};

    pub(super) fn serialize<TargetSerializer>(
        key: &IdentityPublicKey,
        serializer: TargetSerializer,
    ) -> Result<TargetSerializer::Ok, TargetSerializer::Error>
    where
        TargetSerializer: Serializer,
    {
        let bytes: &[u8; 32] = key.as_bytes();
        bytes.serialize(serializer)
    }

    pub(super) fn deserialize<'de, SourceDeserializer>(
        deserializer: SourceDeserializer,
    ) -> Result<IdentityPublicKey, SourceDeserializer::Error>
    where
        SourceDeserializer: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        let verifying =
            VerifyingKey::from_bytes(&bytes).map_err(SourceDeserializer::Error::custom)?;
        let pem = verifying
            .to_public_key_pem(LineEnding::LF)
            .map_err(SourceDeserializer::Error::custom)?;
        IdentityPublicKey::from_pem(&pem).map_err(SourceDeserializer::Error::custom)
    }
}

/// Build the canonical byte payload an Ed25519 signature over a
/// [`SignedInvite`] is computed over.
///
/// See the module rustdoc for the byte layout. Postcard-encodes a
/// 4-tuple of `(INVITE_SIGNING_DOMAIN, code_bytes, issued_at,
/// expires_at_or_epoch)` — the domain prefix is what keeps a
/// signature minted for an invite from being replayed against a
/// future invite format or against a different artifact the same
/// coordinator key signs.
#[must_use]
pub fn signing_payload(
    code: &InviteCode,
    issued_at: &Timestamp,
    expires_at: Option<&Timestamp>,
) -> Vec<u8> {
    let expires_at_or_epoch = expires_at.copied().unwrap_or(NEVER_EXPIRES_PAYLOAD_MARKER);
    let tuple: (&str, &[u8; INVITE_CODE_LEN], &Timestamp, &Timestamp) =
        (INVITE_SIGNING_DOMAIN, code.as_bytes(), issued_at, &expires_at_or_epoch);
    postcard::to_allocvec(&tuple).unwrap_or_else(|err| {
        // Fail-soft: surface a deterministic empty payload if postcard
        // breaks. An empty payload will fail Ed25519 verify against any
        // real signature; the caller observes a BadSignature rather
        // than a panic, and tracing carries the underlying error.
        tracing::error!(
            error = %err,
            "postcard encode of signing payload failed; emitting empty payload",
        );
        Vec::new()
    })
}

/// Verify a [`SignedInvite`] against the supplied coordinator
/// identity key.
///
/// Performs, in this exact order:
///
/// 1. Match `signed.issuer` against `coord_pubkey`; on mismatch
///    return [`DiscoveryError::Url`] tagged "invite issuer". The
///    `issuer` field is **not** part of the signed payload — it is
///    a routing hint only — so an attacker can flip it freely.
///    Rejecting at this step keeps a hint-mismatched invite from
///    consuming any signature work.
/// 2. Decode `signed.signature` as an Ed25519 [`Signature`]; on
///    decode failure return [`DiscoveryError::Url`] tagged
///    "invite signature decode". The decode is fixed-shape (a
///    `try_into` over 64 bytes), so failure does not leak more than
///    "the byte count was wrong".
/// 3. Build the canonical payload via [`signing_payload`] and call
///    [`IdentityPublicKey::verify`]; on mismatch return
///    [`DiscoveryError::Url`] tagged "invite signature".
/// 4. Only after a valid signature, compare `expires_at` against
///    [`Timestamp::now`]; on expiry return [`DiscoveryError::Url`]
///    tagged "invite expired".
///
/// `coord_pubkey` is the trusted coordinator identity key — the
/// same key the caller would use to verify any other
/// coordinator-signed artifact.
///
/// # Errors
///
/// Returns [`DiscoveryError::Url`] for every failure mode (issuer
/// mismatch, bad signature bytes, signature mismatch, expired
/// invite). Variants are not split because the discovery plane
/// treats all four as "this invite cannot be used"; the error
/// string carries the distinguishing tag for human-readable
/// diagnostics.
pub fn verify_invite(
    signed: &SignedInvite,
    coord_pubkey: &IdentityPublicKey,
) -> Result<(), DiscoveryError> {
    if signed.issuer.as_bytes() != coord_pubkey.as_bytes() {
        return Err(DiscoveryError::Url(
            "invite issuer: claimed issuer does not match trusted coordinator key".into(),
        ));
    }
    let signature = decode_signature_bytes(&signed.signature)?;
    let payload = signing_payload(&signed.code, &signed.issued_at, signed.expires_at.as_ref());
    coord_pubkey
        .verify(&payload, &signature)
        .map_err(|err| DiscoveryError::Url(format!("invite signature: {err}")))?;
    // Only check expiry once the signature is known good — an
    // attacker holding a stale-but-genuine signature must not learn
    // about expiry through a side channel.
    if let Some(expires_at) = signed.expires_at {
        let now = Timestamp::now();
        if now.as_offset_date_time() >= expires_at.as_offset_date_time() {
            return Err(DiscoveryError::Url(format!(
                "invite expired: expired_at={expires_at:?} now={now:?}",
            )));
        }
    }
    Ok(())
}

/// Decode a 64-byte Ed25519 signature from a slice without panicking.
fn decode_signature_bytes(bytes: &[u8]) -> Result<Signature, DiscoveryError> {
    let array: &[u8; 64] = bytes.try_into().map_err(|_| {
        DiscoveryError::Url(format!(
            "invite signature decode: expected 64 bytes, got {len}",
            len = bytes.len(),
        ))
    })?;
    Ok(Signature::from_bytes(array))
}

#[cfg(test)]
mod tests {
    use bibeam_crypto::{INVITE_CODE_LEN, IdentitySecretKey, InviteCode};
    use time::Duration;

    use super::*;

    fn fixture_code() -> InviteCode {
        InviteCode::new([0xAB; INVITE_CODE_LEN])
    }

    fn sign(
        secret: &IdentitySecretKey,
        code: &InviteCode,
        issued_at: Timestamp,
        expires_at: Option<&Timestamp>,
    ) -> Vec<u8> {
        let payload = signing_payload(code, &issued_at, expires_at);
        secret.sign(&payload).to_bytes().to_vec()
    }

    #[test]
    fn signing_payload_is_deterministic_for_same_inputs() {
        let code = fixture_code();
        let issued_at = Timestamp::now();
        let expires_at =
            Timestamp::from_offset_date_time(issued_at.into_inner() + Duration::hours(1));
        let lhs = signing_payload(&code, &issued_at, Some(&expires_at));
        let rhs = signing_payload(&code, &issued_at, Some(&expires_at));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn signing_payload_differs_when_expires_at_is_none() {
        let code = fixture_code();
        let issued_at = Timestamp::now();
        let expires_at =
            Timestamp::from_offset_date_time(issued_at.into_inner() + Duration::hours(1));
        let with_expiry = signing_payload(&code, &issued_at, Some(&expires_at));
        let without_expiry = signing_payload(&code, &issued_at, None);
        // Different `expires_at` payloads must produce different
        // signed bytes — a coordinator must not be able to swap one
        // expiry for another after signing.
        assert_ne!(with_expiry, without_expiry);
    }

    #[test]
    fn verify_invite_accepts_valid_signature() {
        let secret = IdentitySecretKey::generate();
        let issuer = secret.public();
        let code = fixture_code();
        let issued_at = Timestamp::now();
        let expires_at =
            Timestamp::from_offset_date_time(issued_at.into_inner() + Duration::hours(1));
        let signature = sign(&secret, &code, issued_at, Some(&expires_at));
        let signed = SignedInvite {
            code,
            issuer: issuer.clone(),
            issued_at,
            expires_at: Some(expires_at),
            signature,
        };
        verify_invite(&signed, &issuer).expect("valid invite must verify");
    }

    #[test]
    fn verify_invite_accepts_no_expiry() {
        let secret = IdentitySecretKey::generate();
        let issuer = secret.public();
        let code = fixture_code();
        let issued_at = Timestamp::now();
        let signature = sign(&secret, &code, issued_at, None);
        let signed = SignedInvite {
            code,
            issuer: issuer.clone(),
            issued_at,
            expires_at: None,
            signature,
        };
        verify_invite(&signed, &issuer).expect("no-expiry invite must verify");
    }

    #[test]
    fn verify_invite_rejects_wrong_trusted_pubkey() {
        // Hint-issuer matches signature key; but the trusted key
        // the caller passes in is a different identity. Must
        // reject at the issuer-mismatch step.
        let real_secret = IdentitySecretKey::generate();
        let other_secret = IdentitySecretKey::generate();
        let real_issuer = real_secret.public();
        let other_issuer = other_secret.public();
        let code = fixture_code();
        let issued_at = Timestamp::now();
        let signature = sign(&real_secret, &code, issued_at, None);
        let signed = SignedInvite {
            code,
            issuer: real_issuer,
            issued_at,
            expires_at: None,
            signature,
        };
        let err = verify_invite(&signed, &other_issuer).expect_err("must reject");
        assert!(
            matches!(&err, DiscoveryError::Url(message) if message.contains("issuer")),
            "expected issuer-mismatch tag, got {err:?}",
        );
    }

    #[test]
    fn verify_invite_rejects_forged_issuer_hint() {
        // An attacker holding a signature from `real_secret` swaps
        // the `issuer` field to claim a different identity. The
        // caller passes the *attacker-claimed* issuer as the trusted
        // pubkey. Signature verify would fail anyway, but we want
        // the issuer-mismatch path to fire first.
        let real_secret = IdentitySecretKey::generate();
        let other_secret = IdentitySecretKey::generate();
        let other_issuer = other_secret.public();
        let code = fixture_code();
        let issued_at = Timestamp::now();
        // Sign with the real secret.
        let signature = sign(&real_secret, &code, issued_at, None);
        // Swap the `issuer` hint to claim the other identity.
        let forged = SignedInvite {
            code,
            issuer: other_issuer,
            issued_at,
            expires_at: None,
            signature,
        };
        // Trusted pubkey is the *real* (signing) issuer — so the
        // hint mismatch path triggers.
        let err = verify_invite(&forged, &real_secret.public()).expect_err("must reject");
        assert!(
            matches!(&err, DiscoveryError::Url(message) if message.contains("issuer")),
            "expected issuer-mismatch tag, got {err:?}",
        );
    }

    #[test]
    fn verify_invite_rejects_tampered_code() {
        let secret = IdentitySecretKey::generate();
        let issuer = secret.public();
        let issued_at = Timestamp::now();
        let signature = sign(&secret, &fixture_code(), issued_at, None);
        let tampered = SignedInvite {
            // Same issuer, same issued_at, same signature — but a
            // different code. Must fail signature check.
            code: InviteCode::new([0xCD; INVITE_CODE_LEN]),
            issuer: issuer.clone(),
            issued_at,
            expires_at: None,
            signature,
        };
        let err = verify_invite(&tampered, &issuer).expect_err("must reject");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("signature")));
    }

    #[test]
    fn verify_invite_rejects_short_signature_before_expiry_check() {
        let secret = IdentitySecretKey::generate();
        let issuer = secret.public();
        let already_expired =
            Timestamp::from_offset_date_time(OffsetDateTime::now_utc() - Duration::hours(1));
        let signed = SignedInvite {
            code: fixture_code(),
            issuer: issuer.clone(),
            issued_at: Timestamp::now(),
            expires_at: Some(already_expired),
            // 32 bytes — wrong length; decode must reject this
            // *before* the expiry check runs, even though `expires_at`
            // is already in the past. If the expiry check ran first
            // the test would still pass (an expired-and-bad-signature
            // invite is rejected either way), but the error string
            // would mention "expired" instead of "decode". We assert
            // the decode tag is present to guard the ordering.
            signature: vec![0u8; 32],
        };
        let err = verify_invite(&signed, &issuer).expect_err("must reject short sig");
        assert!(
            matches!(&err, DiscoveryError::Url(message) if message.contains("decode")),
            "expected decode failure first, got {err:?}",
        );
    }

    #[test]
    fn verify_invite_rejects_expired_invite_after_signature_check() {
        let secret = IdentitySecretKey::generate();
        let issuer = secret.public();
        let code = fixture_code();
        let issued_at =
            Timestamp::from_offset_date_time(OffsetDateTime::now_utc() - Duration::hours(2));
        let expires_at =
            Timestamp::from_offset_date_time(OffsetDateTime::now_utc() - Duration::hours(1));
        let signature = sign(&secret, &code, issued_at, Some(&expires_at));
        let signed = SignedInvite {
            code,
            issuer: issuer.clone(),
            issued_at,
            expires_at: Some(expires_at),
            signature,
        };
        let err = verify_invite(&signed, &issuer).expect_err("expired invite must reject");
        assert!(
            matches!(&err, DiscoveryError::Url(message) if message.contains("expired")),
            "expected expiry failure (signature is good), got {err:?}",
        );
    }
}
