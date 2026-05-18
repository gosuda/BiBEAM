#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Adversarial tests for the PASETO v4 verifier
//! ([`bibeam_crypto::PasetoVerifier`]).
//!
//! The inline `#[cfg(test)]` module in `token.rs` already covers
//! wrong-key rejection (`verify_rejects_wrong_key`) and tampered-
//! payload rejection (`verify_rejects_tampered_token`). This file
//! fills the two integration-level gaps from
//! /home/alpha/.claude/plans/recursive-sauteeing-codd.md §B1:
//!
//! 1. Missing `bibeam_session` custom claim — the typed
//!    [`TokenError::MissingSessionClaim`] path. Requires
//!    hand-constructing a v4.public token via `pasetors` directly
//!    (the `PasetoIssuer::issue` API always emits the custom claim),
//!    kept inline per the plan's "shared helpers earn their place
//!    only when a second test reuses them" rule.
//! 2. Past-expiry token — `pasetors`'s default
//!    `ClaimsValidationRules` enforces `exp` against wall-clock at
//!    verify time, so a token minted with `SessionClaims.exp` in the
//!    past must surface as [`TokenError::Paseto`].

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp, claims::SessionClaims};
use bibeam_crypto::{PasetoIssuer, PasetoVerifier, TokenError};
use pasetors::claims::Claims;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::public;
use pasetors::version4::V4;
use time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Build a [`SessionClaims`] with `exp` at the supplied offset from
/// `now`. The `exit_set` / `path` shape follows the same one-element
/// pattern used by the issuer-side unit tests so the round-trip
/// invariant `path.last() ∈ exit_set` holds.
fn make_claims(exp_offset: Duration) -> SessionClaims {
    let exp = OffsetDateTime::now_utc() + exp_offset;
    let exit = NodeId::new();
    SessionClaims {
        sub: PeerId::new(),
        cohort: CohortId::new(),
        exp: Timestamp::from_offset_date_time(exp),
        exit_set: vec![exit],
        path: vec![exit],
    }
}

/// Hand-construct a v4.public token whose `Claims` set carries the
/// PASETO-required `iat` / `nbf` / `exp` fields but NOT the custom
/// `bibeam_session` claim. The verifier must surface
/// [`TokenError::MissingSessionClaim`] rather than collapsing the
/// case into `Paseto(_)` — the typed variant is the contract
/// downstream consumers match on.
///
/// `pasetors` construction is performed inline (no shared helper)
/// per the plan: this is the only test that needs raw-claim
/// construction.
#[test]
fn verify_rejects_token_missing_bibeam_session_claim() {
    let kp = AsymmetricKeyPair::<V4>::generate().expect("kp");
    let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("iat rfc3339");
    let exp = (OffsetDateTime::now_utc() + Duration::hours(1))
        .format(&Rfc3339)
        .expect("exp rfc3339");
    let mut claims = Claims::new().expect("claims::new");
    claims.issued_at(&now).expect("iat");
    claims.not_before(&now).expect("nbf");
    claims.expiration(&exp).expect("exp");
    // Deliberately do NOT call `add_additional("bibeam_session", ...)`.
    let token = public::sign(&kp.secret, &claims, None, None).expect("sign");

    let verifier = PasetoVerifier::new(kp.public);
    let err = verifier
        .verify(&token)
        .expect_err("token without bibeam_session claim must reject");
    assert!(
        matches!(err, TokenError::MissingSessionClaim),
        "expected TokenError::MissingSessionClaim, got {err:?}",
    );
}

/// `PasetoVerifier::verify` applies `ClaimsValidationRules::new()`,
/// which `pasetors` documents as enforcing presence + validity of
/// `iat` / `nbf` / `exp` (including a past-`exp` rejection against
/// wall-clock). A token minted via the real [`PasetoIssuer::issue`]
/// path with `SessionClaims.exp` set one hour ago must therefore
/// surface as [`TokenError::Paseto`] at the verify-time validation
/// step — no clock mocking required.
#[test]
fn verify_rejects_past_expiry_token() {
    let kp = AsymmetricKeyPair::<V4>::generate().expect("kp");
    let issuer = PasetoIssuer::new(kp.secret);
    let verifier = PasetoVerifier::new(kp.public);

    let claims = make_claims(Duration::hours(-1));
    let token = issuer.issue(&claims).expect("issue past-expiry token");

    let err = verifier.verify(&token).expect_err("past-expiry token must reject");
    assert!(matches!(err, TokenError::Paseto(_)), "expected TokenError::Paseto, got {err:?}");
}
