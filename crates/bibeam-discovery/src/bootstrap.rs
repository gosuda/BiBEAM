#![forbid(unsafe_code)]
//! Session bootstrap protocol (F-DISC.7).
//!
//! [`SessionBootstrap`] glues together the four primitives shipped
//! earlier in this crate into the single end-to-end flow a fresh
//! peer runs against a coordinator pool:
//!
//! 1. Verify the [`SignedInvite`] the peer was given out-of-band
//!    against the trusted coordinator [`IdentityPublicKey`]
//!    ([`verify_invite`]). If the invite is forged or expired the
//!    bootstrap stops here.
//! 2. Pick a coordinator from the [`CoordinatorPool`] (round-robin
//!    failover) and send `/api/v1/register` carrying the peer's
//!    declared identity, address hint, exit capability, and
//!    capacity hint. The coordinator answers with a
//!    [`bibeam_protocol::control::RegisterAck`] whose
//!    `session_token` is a PASETO v4 token.
//! 3. Parse the token as a UTF-8 string and verify it locally with
//!    the supplied [`PasetoVerifier`] to recover the
//!    [`SessionClaims`]. Verification fails fast if the coordinator
//!    returns a token signed by a different key than the one the
//!    peer trusts.
//! 4. Send `/api/v1/match` bearing the verified session token. The
//!    coordinator answers with a
//!    [`bibeam_protocol::control::MatchResponse`]; the bootstrap
//!    extracts the single-hop branch
//!    ([`bibeam_protocol::control::MatchResponse::SingleHop`])
//!    naming the peer's cohort, exit set, and rotation deadline.
//!    Multi-hop responses surface as a typed error until
//!    R-MULTIHOP-CLI wires the client side.
//! 5. Assemble a partial [`CohortLive`] snapshot from the verified
//!    claims and the match response. Full cohort membership lands
//!    later via [`crate::CoordinatorEvent::CohortAssigned`] on the
//!    WebSocket stream (F-DISC.2); the bootstrap returns a
//!    members-empty snapshot for the caller to enrich.
//!
//! ## Coordinator affinity
//!
//! Registration mints a per-coordinator session-token state record;
//! every coordinator in the pool would issue a different token, and
//! the `/match` endpoint expects to see the token *its* registration
//! handler issued. The bootstrap therefore performs the
//! register-then-match sequence against a **single** coordinator:
//! the pool's `try_each` picks the coordinator that successfully
//! answered `/register`, and the matching `/match` call goes to the
//! same client. Failover across coordinators is allowed during the
//! `/register` attempt (one coordinator might be down) but not
//! between `/register` and `/match` (the token would be unknown to
//! a fresh coordinator). When the chosen coordinator drops between
//! the two calls the bootstrap surfaces a [`DiscoveryError`] and
//! the caller must restart from step 1.
//!
//! ## Subject-claim binding
//!
//! After PASETO verification recovers the [`SessionClaims`], the
//! bootstrap checks `claims.sub == my_peer_id` before issuing the
//! `/match` request. A coordinator that mints a token bound to a
//! *different* peer must not let the bootstrap proceed: matching
//! under a mismatched subject would attach this peer's traffic to
//! another peer's cohort state, a confusion-deputy hole we close
//! at this layer.
//!
//! ## Deviations from the F-DISC.7 spec
//!
//! - `BootstrappedSession.session_token` is a `String`, not a
//!   [`bytes::Bytes`]. [`bibeam_protocol::control::RegisterAck`]'s
//!   `session_token` field is [`bytes::Bytes`]; we convert to UTF-8
//!   once at the bootstrap boundary because PASETO v4 tokens are
//!   ASCII (`v4.public.<base64>...`) and downstream consumers
//!   ([`crate::http::CoordinatorClient::match_`] / `heartbeat` /
//!   `disconnect`) take `token: &str`.
//! - HTTP body wire form is JSON, not postcard. The existing
//!   [`crate::CoordinatorClient`] is the JSON-over-HTTPS client
//!   F-DISC.1 introduced; reusing it keeps a single decoder.
//! - HTTP path prefix is `/api/v1/...`, not `/v1/...`. The bootstrap
//!   defers to the [`crate::http::CoordinatorClient`] for path
//!   construction.

use std::net::SocketAddr;
use std::sync::Arc;

use bibeam_core::{PeerId, Timestamp};
use bibeam_crypto::{IdentityPublicKey, PasetoVerifier};
use bibeam_protocol::claims::SessionClaims;
use bibeam_protocol::cohort::CohortLive;
use bibeam_protocol::control::{MatchRequest, Register};

use crate::error::DiscoveryError;
use crate::failover::CoordinatorPool;
use crate::invite_validator::{SignedInvite, verify_invite};

/// Bootstrap orchestrator owning a coordinator pool and the trusted
/// coordinator public key.
///
/// `coord_pubkey` is the long-term Ed25519 identity key the peer
/// trusts for invite-signature verification. It is **distinct**
/// from the PASETO v4 verifying key the caller passes to
/// [`SessionBootstrap::bootstrap`]: identity-signing and
/// session-token-signing keys live in different cryptographic
/// schemes (Ed25519-PEM vs PASETO v4) and the coordinator MAY
/// rotate the PASETO key independently of its identity key.
#[derive(Clone, Debug)]
pub struct SessionBootstrap {
    /// Round-robin pool of coordinator HTTP clients.
    pool: Arc<CoordinatorPool>,
    /// Trusted long-term identity key for invite-signature checks.
    coord_pubkey: IdentityPublicKey,
}

/// Inputs the peer brings to a bootstrap call. Bundled into a
/// struct so [`SessionBootstrap::bootstrap`] stays under clippy's
/// `too_many_arguments` cap (5).
#[derive(Debug, Clone, Copy)]
pub struct PeerProfile {
    /// Peer's chosen identifier; the coordinator binds it to the
    /// issued session token's `sub` claim.
    pub peer_id: PeerId,
    /// Address the peer advertises for inbound connections. The
    /// coordinator MAY override or augment it.
    pub addr_hint: SocketAddr,
    /// Whether the peer is willing to serve as an exit node.
    pub can_exit: bool,
    /// Peer-supplied capacity score; opaque to the coordinator.
    pub capacity_hint: u32,
}

/// Successful bootstrap result: the verified session token, its
/// embedded claims, and the partial cohort view assembled from the
/// match response.
#[derive(Debug, Clone)]
pub struct BootstrappedSession {
    /// PASETO v4 token returned by the coordinator and verified
    /// locally. Stored as `String` for use with
    /// [`crate::CoordinatorClient::heartbeat`] etc.
    pub session_token: String,
    /// Claims sealed inside `session_token`, recovered by
    /// [`PasetoVerifier::verify`].
    pub claims: SessionClaims,
    /// Partial cohort snapshot. `members` is empty until the
    /// WebSocket [`crate::CoordinatorEvent::CohortAssigned`] frame
    /// fills it in.
    pub cohort_live: CohortLive,
}

impl SessionBootstrap {
    /// Wire the bootstrap orchestrator to a pool and a trusted
    /// coordinator identity key.
    #[must_use]
    pub const fn new(pool: Arc<CoordinatorPool>, coord_pubkey: IdentityPublicKey) -> Self {
        Self { pool, coord_pubkey }
    }

    /// Run the five-step bootstrap flow.
    ///
    /// `signed_invite` is the out-of-band invite the peer was
    /// given. `my_peer_id` is the peer's chosen identifier, which
    /// the coordinator binds to the issued session token.
    /// `my_addr_hint` is the address the peer advertises for
    /// inbound connections; the coordinator may override it.
    /// `can_exit` and `capacity_hint` are the same fields
    /// [`Register`] carries. `verifier` is the PASETO v4 verifier
    /// the peer trusts to authenticate the session token.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when invite verification fails,
    /// when every coordinator in the pool is unreachable
    /// (transport retriable errors), when the coordinator returns
    /// a non-success status (4xx / 5xx — see
    /// [`crate::CoordinatorClient`] for the mapping), when the
    /// session token is not valid UTF-8, when PASETO verification
    /// fails, or when JSON decoding fails. None of these are
    /// retriable at the bootstrap layer.
    pub async fn bootstrap(
        &self,
        signed_invite: &SignedInvite,
        profile: PeerProfile,
        verifier: &PasetoVerifier,
    ) -> Result<BootstrappedSession, DiscoveryError> {
        verify_invite(signed_invite, &self.coord_pubkey)?;

        let register = Register {
            peer_id: profile.peer_id,
            addr_hint: profile.addr_hint,
            can_exit: profile.can_exit,
            capacity_hint: profile.capacity_hint,
            at: Timestamp::now(),
        };
        // Run register through the pool; the closure captures both
        // the chosen client and the ack so we can keep coordinator
        // affinity for the follow-up `/match` call.
        let register_request = &register;
        let (chosen_client, ack) = self
            .pool
            .try_each(move |client| async move {
                let ack = client.register(register_request).await?;
                Ok::<_, DiscoveryError>((client, ack))
            })
            .await?;

        let session_token = parse_session_token(&ack.session_token)?;
        let claims = verifier
            .verify(&session_token)
            .map_err(|err| DiscoveryError::Url(format!("session token verify: {err}")))?;
        // Subject-claim binding: refuse to proceed when the
        // coordinator has issued the token to a different peer.
        // Matching under a mismatched subject would attach this
        // peer's traffic to another peer's cohort state.
        if claims.sub != profile.peer_id {
            return Err(DiscoveryError::Url(format!(
                "session token subject mismatch: token.sub={token_sub:?} \
                 requested_peer={requested:?}",
                token_sub = claims.sub,
                requested = profile.peer_id,
            )));
        }

        // Match under the same coordinator that minted the token.
        // No failover here: a fresh coordinator does not know
        // about this token.
        let match_request = MatchRequest {
            peer_id: profile.peer_id,
            at: Timestamp::now(),
        };
        let match_response = chosen_client.match_(&match_request, &session_token).await?;

        // R-MULTIHOP-PROTO only landed the wire shapes; the multi-hop
        // bootstrap flow (R-MULTIHOP-CLI) is a later commit. Until
        // then, only the single-hop variant has a meaningful
        // bootstrap outcome; a multi-hop assignment surfaces as a
        // typed error so the caller can route around it.
        let single_hop = match match_response {
            bibeam_protocol::MatchResponse::SingleHop(single_hop) => single_hop,
            bibeam_protocol::MatchResponse::MultiHopAssignment(_) => {
                return Err(DiscoveryError::Url(
                    "coordinator returned a multi-hop assignment; \
                     client-side multi-hop bootstrap is not yet wired \
                     (R-MULTIHOP-CLI)"
                        .into(),
                ));
            },
        };
        let cohort_live = CohortLive {
            cohort: single_hop.cohort,
            members: Vec::new(),
            exits: single_hop.exit_set,
            // R-REGION.3: coord-side `SingleHopMatch` now carries the
            // per-exit region map; copy it verbatim so the client's
            // region-aware exit pick (F-CLI.4b) has real data to
            // filter on. An empty map (no GeoIP DB configured)
            // collapses every `pick_exit(.., ExitFilter::Region(r), ..)`
            // to the §11 R-3 refusal path.
            exit_regions: single_hop.exit_regions,
            at: Timestamp::now(),
        };
        Ok(BootstrappedSession {
            session_token,
            claims,
            cohort_live,
        })
    }
}

/// Parse the PASETO session-token [`Bytes`] returned in
/// [`RegisterAck::session_token`] as a UTF-8 string.
fn parse_session_token(bytes: &bytes::Bytes) -> Result<String, DiscoveryError> {
    let view = std::str::from_utf8(bytes)
        .map_err(|err| DiscoveryError::Url(format!("session token not utf-8: {err}")))?;
    Ok(view.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_session_token_accepts_ascii() {
        let raw = bytes::Bytes::from_static(b"v4.public.example");
        let token = parse_session_token(&raw).expect("ascii parses");
        assert_eq!(token, "v4.public.example");
    }

    #[test]
    fn parse_session_token_rejects_non_utf8() {
        let raw = bytes::Bytes::from_static(&[0xFF, 0xFE, 0xFD]);
        let err = parse_session_token(&raw).expect_err("invalid utf-8 must reject");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("utf-8")));
    }
}
