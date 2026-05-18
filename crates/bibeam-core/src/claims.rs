#![forbid(unsafe_code)]
//! PASETO v4 session-token claim set.
//!
//! The coordinator issues a PASETO v4 token to every successfully
//! registered peer (see F-CRYPTO.4); that token carries a
//! [`SessionClaims`] payload. The struct lives in the core crate so
//! the crypto issuer/verifier and protocol control-plane types can
//! both reference one canonical authorisation shape without depending
//! on each other.
//!
//! The fields mirror the registration agreement the peer holds with
//! the coordinator: which peer (`sub`), in which cohort (`cohort`),
//! until when (`exp`), routed through which exit nodes (`exit_set`),
//! over which forwarder chain (`path`).
//!
//! `exit_set` and `path` carry distinct information and are NOT
//! redundant:
//!
//! - `exit_set` is the cohort's full exit roster — every exit node
//!   the subject could have been assigned. Its membership is fixed
//!   by the cohort and does not change across the cohort's lifetime.
//! - `path` is the concrete forwarder chain the subject was assigned
//!   *this session*, with the chosen exit as its last entry.
//!
//! The issuer-side invariant is: `path.last()` MUST be an element of
//! `exit_set`. Enforcement of this invariant on the data-plane
//! verifier is deferred to R-MULTIHOP-NODE; tokens emitted in this
//! commit are produced by issuers that already respect it (see
//! `bibeam_node::coordinator::admission`), and the round-trip tests
//! exercise the resulting shape end-to-end.

use serde::{Deserialize, Serialize};

use crate::{CohortId, NodeId, PeerId, Timestamp};

/// Claim set sealed inside a PASETO v4 session token.
///
/// Field names follow PASETO/JWT convention: `sub` for the subject
/// peer, `exp` for the expiry instant. Together with `cohort`,
/// `exit_set`, and `path` they fix every authorisation decision the
/// data plane makes on behalf of `sub`.
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
    /// Ordered forwarder chain the subject is authorised to use.
    ///
    /// The last entry is the exit; preceding entries (if any) are the
    /// forwarders, in the order traffic flows. A one-element path
    /// (`path == [exit]`) is the direct single-hop case — the
    /// pre-multihop shape collapses naturally into this form.
    pub path: Vec<NodeId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId(ulid::Ulid::from_bytes([byte; 16]))
    }

    fn fixture_claims() -> SessionClaims {
        SessionClaims {
            sub: PeerId(ulid::Ulid::from_bytes([1; 16])),
            cohort: CohortId(ulid::Ulid::from_bytes([2; 16])),
            exp: Timestamp::from_offset_date_time(
                time::OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp"),
            ),
            exit_set: vec![node(3), node(4)],
            path: vec![node(5), node(4)],
        }
    }

    #[test]
    fn serde_round_trips_claim_shape() {
        let claims = fixture_claims();
        let encoded = serde_json::to_value(&claims).expect("claims serialize");
        let decoded: SessionClaims = serde_json::from_value(encoded).expect("claims deserialize");

        assert_eq!(decoded, claims);
    }

    #[test]
    fn exit_set_and_path_remain_distinct_fields() {
        let encoded = serde_json::to_value(fixture_claims()).expect("claims serialize");

        assert_ne!(encoded["exit_set"], encoded["path"]);
        assert_eq!(encoded["path"][1], encoded["exit_set"][1]);
    }
}
