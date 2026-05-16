#![forbid(unsafe_code)]
//! PASETO v4 issuer + verifier (F-CRYPTO.4).
//!
//! The coordinator mints session tokens via [`PasetoIssuer::issue`]
//! and clients (or any verifier that holds the matching public key)
//! validate them via [`PasetoVerifier::verify`]. Each token's payload
//! carries the typed [`SessionClaims`] from
//! [`bibeam_protocol::claims`] — the canonical authorisation record
//! the coordinator hands to a peer at registration time.
//!
//! ## Wire format
//!
//! PASETO v4 public tokens use Ed25519 signatures over a JSON
//! payload. We bridge our typed `SessionClaims` through `pasetors`'
//! own `Claims` map by serialising it under a single
//! `"bibeam_session"` custom claim. `iat` / `nbf` / `exp` are set to
//! the coordinator's wall-clock at issue time and to
//! `SessionClaims.exp`, so the default validation rules already
//! enforce expiry without the caller having to bring custom validator
//! logic.

use bibeam_protocol::claims::SessionClaims;
use core::convert::TryFrom;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{Public, public};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The custom-claim key under which the typed [`SessionClaims`] is
/// encoded inside the PASETO payload.
const SESSION_CLAIM_KEY: &str = "bibeam_session";

/// Errors returned by [`PasetoIssuer::issue`] / [`PasetoVerifier::verify`].
#[derive(Debug, Error)]
pub enum TokenError {
    /// `pasetors` reported an error while building the claim set,
    /// signing, or verifying.
    #[error("PASETO operation failed: {0}")]
    Paseto(String),
    /// `serde_json` failed to serialise or deserialise the typed
    /// [`SessionClaims`] inside the PASETO payload.
    #[error("session claim serde error: {0}")]
    Serde(String),
    /// The verified token did not carry the expected
    /// `bibeam_session` claim.
    #[error("verified PASETO token is missing the bibeam_session claim")]
    MissingSessionClaim,
    /// The token's `SessionClaims.exp` could not be formatted as a
    /// valid RFC 3339 PASETO `exp` value.
    #[error("session expiry could not be formatted as RFC 3339: {0}")]
    BadExpiry(String),
}

impl TokenError {
    fn paseto<E: core::fmt::Display>(err: E) -> Self {
        Self::Paseto(err.to_string())
    }

    fn serde<E: core::fmt::Display>(err: E) -> Self {
        Self::Serde(err.to_string())
    }
}

/// PASETO v4 issuer.
///
/// Holds the coordinator's signing key. One instance per coordinator;
/// safe to share across threads (the underlying `pasetors` API uses
/// `&self`).
pub struct PasetoIssuer {
    secret: AsymmetricSecretKey<V4>,
}

impl core::fmt::Debug for PasetoIssuer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("PasetoIssuer").finish_non_exhaustive()
    }
}

impl PasetoIssuer {
    /// Wrap an existing PASETO v4 secret key.
    #[must_use]
    pub const fn new(secret: AsymmetricSecretKey<V4>) -> Self {
        Self { secret }
    }

    /// Issue a fresh PASETO v4 public token carrying the given
    /// [`SessionClaims`].
    ///
    /// `iat` is set to the wall-clock at the call site. `nbf` is set
    /// to the same instant. `exp` is set from `claims.exp`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Serde`] if the typed claims cannot be
    /// JSON-serialised, [`TokenError::BadExpiry`] if
    /// `claims.exp.into_inner()` cannot be RFC 3339-formatted, and
    /// [`TokenError::Paseto`] on `pasetors` failure.
    pub fn issue(&self, claims: &SessionClaims) -> Result<String, TokenError> {
        let mut paseto_claims = Claims::new().map_err(TokenError::paseto)?;
        let now = OffsetDateTime::now_utc().format(&Rfc3339).map_err(TokenError::paseto)?;
        paseto_claims.issued_at(&now).map_err(TokenError::paseto)?;
        paseto_claims.not_before(&now).map_err(TokenError::paseto)?;
        let exp = claims
            .exp
            .into_inner()
            .format(&Rfc3339)
            .map_err(|err| TokenError::BadExpiry(err.to_string()))?;
        paseto_claims.expiration(&exp).map_err(TokenError::paseto)?;
        let payload = serde_json::to_value(claims).map_err(TokenError::serde)?;
        paseto_claims
            .add_additional(SESSION_CLAIM_KEY, payload)
            .map_err(TokenError::paseto)?;
        public::sign(&self.secret, &paseto_claims, None, None).map_err(TokenError::paseto)
    }
}

/// PASETO v4 verifier.
///
/// Holds the coordinator's public key. One instance per verifier; safe
/// to share across threads.
pub struct PasetoVerifier {
    public: AsymmetricPublicKey<V4>,
}

impl core::fmt::Debug for PasetoVerifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("PasetoVerifier").finish_non_exhaustive()
    }
}

impl PasetoVerifier {
    /// Wrap an existing PASETO v4 public key.
    #[must_use]
    pub const fn new(public: AsymmetricPublicKey<V4>) -> Self {
        Self { public }
    }

    /// Verify `token` and return the embedded [`SessionClaims`].
    ///
    /// Applies the default `ClaimsValidationRules`, which enforce
    /// `iat`, `nbf`, and `exp` presence and validity.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Paseto`] for signature or claim
    /// validation failures, [`TokenError::MissingSessionClaim`] if
    /// the `bibeam_session` custom claim is absent, and
    /// [`TokenError::Serde`] if the embedded payload does not
    /// deserialise into [`SessionClaims`].
    pub fn verify(&self, token: &str) -> Result<SessionClaims, TokenError> {
        let rules = ClaimsValidationRules::new();
        let untrusted =
            UntrustedToken::<Public, V4>::try_from(token).map_err(TokenError::paseto)?;
        let trusted = public::verify(&self.public, &untrusted, &rules, None, None)
            .map_err(TokenError::paseto)?;
        let claims = trusted.payload_claims().ok_or(TokenError::MissingSessionClaim)?;
        let value = claims.get_claim(SESSION_CLAIM_KEY).ok_or(TokenError::MissingSessionClaim)?;
        serde_json::from_value::<SessionClaims>(value.clone()).map_err(TokenError::serde)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
    use pasetors::keys::{AsymmetricKeyPair, Generate};

    fn fixture_claims() -> SessionClaims {
        let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
        SessionClaims {
            sub: PeerId::new(),
            cohort: CohortId::new(),
            exp: Timestamp::from_offset_date_time(exp),
            exit_set: vec![NodeId::new(), NodeId::new()],
        }
    }

    #[test]
    fn issue_verify_round_trip() {
        let kp = AsymmetricKeyPair::<V4>::generate().expect("kp");
        let issuer = PasetoIssuer::new(kp.secret);
        let verifier = PasetoVerifier::new(kp.public);
        let claims = fixture_claims();
        let token = issuer.issue(&claims).expect("issue");
        let recovered = verifier.verify(&token).expect("verify");
        assert_eq!(recovered, claims);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp_a = AsymmetricKeyPair::<V4>::generate().expect("kp a");
        let kp_b = AsymmetricKeyPair::<V4>::generate().expect("kp b");
        let issuer = PasetoIssuer::new(kp_a.secret);
        let verifier_wrong = PasetoVerifier::new(kp_b.public);
        let claims = fixture_claims();
        let token = issuer.issue(&claims).expect("issue");
        let err = verifier_wrong.verify(&token).expect_err("must reject other key");
        assert!(matches!(err, TokenError::Paseto(_)));
    }

    #[test]
    fn verify_rejects_tampered_token() {
        let kp = AsymmetricKeyPair::<V4>::generate().expect("kp");
        let issuer = PasetoIssuer::new(kp.secret);
        let verifier = PasetoVerifier::new(kp.public);
        let claims = fixture_claims();
        let token = issuer.issue(&claims).expect("issue");
        // Flip a byte deep in the payload to provoke a signature mismatch.
        let mut bytes = token.into_bytes();
        if let Some(byte) = bytes.last_mut() {
            *byte = byte.wrapping_add(1);
        }
        let tampered = String::from_utf8(bytes).expect("utf-8 preserved");
        let err = verifier.verify(&tampered).expect_err("must reject tamper");
        assert!(matches!(err, TokenError::Paseto(_)));
    }
}
