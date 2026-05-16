#![forbid(unsafe_code)]
//! PASETO v4 session-token issuance at admission (F-COORD.4).
//!
//! The coordinator issues exactly one [`bibeam_protocol::SessionClaims`]
//! token per peer per cohort assignment. [`Admissioner`] owns the
//! PASETO signing key and turns a `(PeerId, CohortId, CohortRecord)`
//! triple into a signed v4 token via
//! [`bibeam_crypto::PasetoIssuer`].
//!
//! ## Claim set
//!
//! The shape of [`bibeam_protocol::SessionClaims`] is fixed by
//! F-PROTO.4. Each issuance binds:
//!
//! - `sub`: the registering peer's id.
//! - `cohort`: the cohort the peer was admitted to.
//! - `exp`: the cohort's `rotation_deadline` — the moment the peer
//!   must re-register and pick up a fresh token.
//! - `exit_set`: the cohort's canonical exit list, copied verbatim
//!   from [`super::cohorts::CohortRecord::exits`].
//!
//! Peers re-register on rotation to pick up the next token, so
//! tying the token's expiry to the cohort's rotation deadline is
//! the right policy at MVP — there is no scenario where a token
//! should outlive its cohort's exit set.
//!
//! ## Scope
//!
//! [`Admissioner`] is signing-only. Persisting an admission to the
//! redb peer registry / cohort store is the matchmaking layer's
//! job (F-COORD.5); admissioner does not hold those handles
//! because the signing call does not read or write them.

use std::sync::Arc;

use bibeam_core::PeerId;
use bibeam_crypto::{PasetoIssuer, TokenError};
use bibeam_protocol::SessionClaims;
use thiserror::Error;

use super::cohorts::CohortRecord;

/// Failure modes for [`Admissioner::issue`].
#[derive(Debug, Error)]
pub enum AdmissionError {
    /// [`bibeam_crypto::PasetoIssuer::issue`] reported a failure —
    /// either the claim set could not be encoded or the signing
    /// operation rejected.
    #[error("PASETO issue failed: {0}")]
    Token(#[from] TokenError),
}

/// PASETO v4 admission token minter.
///
/// Cheap to clone — the underlying [`PasetoIssuer`] sits behind an
/// [`Arc`] so the secret key is allocated exactly once per process.
#[derive(Clone)]
pub struct Admissioner {
    issuer: Arc<PasetoIssuer>,
}

impl core::fmt::Debug for Admissioner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("Admissioner").finish_non_exhaustive()
    }
}

impl Admissioner {
    /// Construct an admissioner from the shared PASETO issuer.
    #[must_use]
    pub const fn new(issuer: Arc<PasetoIssuer>) -> Self {
        Self { issuer }
    }

    /// Mint a PASETO v4 session token for `peer_id` admitted into
    /// `cohort_id` with the assignment described by `cohort`.
    ///
    /// The returned [`String`] is the PASETO v4 token wire form;
    /// hand it back to the peer as
    /// [`bibeam_protocol::control::RegisterAck::session_token`].
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Token`] when the underlying PASETO
    /// issuer rejects the claim set or fails to sign — typically
    /// because the system clock is too far skewed for the upstream
    /// crate to format `exp` as RFC 3339.
    pub fn issue(
        &self,
        peer_id: PeerId,
        cohort_id: bibeam_core::CohortId,
        cohort: &CohortRecord,
    ) -> Result<String, AdmissionError> {
        let claims = SessionClaims {
            sub: peer_id,
            cohort: cohort_id,
            exp: cohort.rotation_deadline,
            exit_set: cohort.exits.clone(),
        };
        let token = self.issuer.issue(&claims)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
    use bibeam_crypto::PasetoVerifier;
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;
    use time::Duration;

    fn fixture_admissioner() -> (Admissioner, PasetoVerifier) {
        let key_pair = AsymmetricKeyPair::<V4>::generate().expect("kp");
        let verifier = PasetoVerifier::new(key_pair.public);
        let issuer = Arc::new(PasetoIssuer::new(key_pair.secret));
        (Admissioner::new(issuer), verifier)
    }

    fn fixture_cohort_record() -> CohortRecord {
        let deadline = Timestamp::from_offset_date_time(
            time::OffsetDateTime::now_utc() + Duration::minutes(15),
        );
        CohortRecord {
            members: vec![PeerId::new()],
            exits: vec![NodeId::new(), NodeId::new()],
            rotation_deadline: deadline,
            region: String::new(),
        }
    }

    #[test]
    fn issued_token_round_trips_via_verifier() {
        // Contract: a token minted by the admissioner verifies
        // under the matching public key and yields the same
        // SessionClaims the issuer was given. Catches a regression
        // that scrambled exit_set / cohort ordering inside the
        // claim payload — every downstream auth decision would
        // break silently.
        let (admissioner, verifier) = fixture_admissioner();
        let peer = PeerId::new();
        let cohort_id = CohortId::new();
        let record = fixture_cohort_record();
        let token = admissioner.issue(peer, cohort_id, &record).expect("issue");
        let claims = verifier.verify(&token).expect("verify");
        assert_eq!(claims.sub, peer);
        assert_eq!(claims.cohort, cohort_id);
        assert_eq!(claims.exit_set, record.exits);
        assert_eq!(claims.exp, record.rotation_deadline);
    }
}
