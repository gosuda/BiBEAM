#![forbid(unsafe_code)]
//! PASETO v4 session-token claim set.
//!
//! The coordinator issues a PASETO v4 token to every successfully
//! registered peer (see F-CRYPTO.4); that token carries a
//! [`SessionClaims`] payload. The struct lives in the protocol crate
//! — not in `bibeam-crypto` — so the discovery layer can reference one
//! canonical shape without depending on the cryptographic machinery
//! that issues and verifies it.
//!
//! The fields mirror the registration agreement the peer holds with
//! the coordinator: which peer (`sub`), in which cohort (`cohort`),
//! until when (`exp`), routed through which exit nodes (`exit_set`).

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use serde::{Deserialize, Serialize};

/// Claim set sealed inside a PASETO v4 session token.
///
/// Field names follow PASETO/JWT convention: `sub` for the subject
/// peer, `exp` for the expiry instant. Together with `cohort` and
/// `exit_set` they fix every authorisation decision the data plane
/// makes on behalf of `sub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Subject peer the token was issued to.
    pub sub: PeerId,
    /// Cohort this session belongs to.
    pub cohort: CohortId,
    /// Wall-clock instant after which the token must be rejected.
    pub exp: Timestamp,
    /// Exit nodes the subject is authorised to route through.
    pub exit_set: Vec<NodeId>,
}
