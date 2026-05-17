#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Adversarial tests for
//! [`bibeam_node::registration::UnverifiedRegistrationToken::verify`]
//! — the subject-claim binding that closes the confusion-deputy hole
//! between a coord-asserted PASETO bytes-blob and trusted node state.
//!
//! Two contracts under test, both from §B1 of
//! /home/alpha/.claude/plans/recursive-sauteeing-codd.md:
//!
//! 1. A token whose recovered `claims.sub` does NOT match the
//!    `expected_peer` the caller passes must surface as the typed
//!    [`TokenVerifyError::SubjectMismatch`] variant, with `token_sub`
//!    and `expected` populated to mirror the inputs. The variant is
//!    matched on with exact fields so a future flattening (e.g.
//!    collapsing into `Paseto(_)`) breaks the test loudly.
//! 2. A corrupt PASETO bytes-blob must propagate through
//!    `#[from] TokenError` as [`TokenVerifyError::Paseto`], NOT be
//!    swallowed or re-mapped to `SubjectMismatch` (a wrong-bytes
//!    token never makes it to the subject check).

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use bibeam_crypto::{PasetoIssuer, PasetoVerifier};
use bibeam_node::registration::{TokenVerifyError, UnverifiedRegistrationToken};
use bibeam_protocol::claims::SessionClaims;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use time::Duration;
use time::OffsetDateTime;

/// Single-exit claim fixture; matches the issuer-side invariant
/// `path.last() ∈ exit_set` documented in
/// `bibeam_protocol::claims::SessionClaims`.
fn make_claims_for(sub: PeerId) -> SessionClaims {
    let exp = OffsetDateTime::now_utc() + Duration::hours(1);
    let exit = NodeId::new();
    SessionClaims {
        sub,
        cohort: CohortId::new(),
        exp: Timestamp::from_offset_date_time(exp),
        exit_set: vec![exit],
        path: vec![exit],
    }
}

/// Token minted with `sub = peer_a` must be rejected by
/// `verify(verifier, peer_b)` with the typed
/// [`TokenVerifyError::SubjectMismatch`] variant. Both `token_sub`
/// and `expected` fields are asserted: a future refactor that
/// dropped the populated payload would silently lose observability,
/// so the test pins both halves.
#[test]
fn unverified_token_verify_rejects_subject_mismatch_with_typed_variant() {
    let kp = AsymmetricKeyPair::<V4>::generate().expect("kp");
    let issuer = PasetoIssuer::new(kp.secret);
    let verifier = PasetoVerifier::new(kp.public);

    let peer_a = PeerId::new();
    let peer_b = PeerId::new();
    assert_ne!(peer_a, peer_b, "fixture sanity: distinct peers");

    let claims_a = make_claims_for(peer_a);
    let token = issuer.issue(&claims_a).expect("issue");

    let unverified = UnverifiedRegistrationToken {
        paseto_token: token,
        expires_at: claims_a.exp,
    };
    let err = unverified.verify(&verifier, peer_b).expect_err("subject mismatch must reject");
    match err {
        TokenVerifyError::SubjectMismatch { token_sub, expected } => {
            assert_eq!(token_sub, peer_a, "token_sub must mirror minted claims.sub");
            assert_eq!(expected, peer_b, "expected must mirror the caller's peer");
        },
        TokenVerifyError::Paseto(err) => {
            panic!(
                "expected TokenVerifyError::SubjectMismatch, got TokenVerifyError::Paseto({err:?})"
            )
        },
    }
}

/// A garbage PASETO blob (still ASCII-shaped to keep the
/// [`UnverifiedRegistrationToken`] field type honest) must surface
/// as [`TokenVerifyError::Paseto`] via the `#[from] TokenError`
/// conversion. The subject check never runs, so the test pins that
/// the variant does NOT collapse into [`TokenVerifyError::SubjectMismatch`].
#[test]
fn unverified_token_verify_propagates_paseto_failure() {
    let kp = AsymmetricKeyPair::<V4>::generate().expect("kp");
    let verifier = PasetoVerifier::new(kp.public);

    let unverified = UnverifiedRegistrationToken {
        // Shape (`v4.public.` prefix) is correct so the parser
        // attempts to decode; payload is gibberish so verification
        // fails inside pasetors and surfaces via `#[from] TokenError`.
        paseto_token: "v4.public.not_a_real_token_just_bytes".to_string(),
        expires_at: Timestamp::from_offset_date_time(
            OffsetDateTime::now_utc() + Duration::hours(1),
        ),
    };
    let err = unverified
        .verify(&verifier, PeerId::new())
        .expect_err("corrupt token must reject");
    assert!(
        matches!(err, TokenVerifyError::Paseto(_)),
        "expected TokenVerifyError::Paseto, got {err:?}",
    );
}
