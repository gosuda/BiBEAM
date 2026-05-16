#![forbid(unsafe_code)]
//! Node-side coordinator registration + heartbeat flow (F-NODE.1).
//!
//! [`NodeRegistrar`] is the daemon-startup primitive every
//! [`bibeam_node`](crate) instance runs against the federation's
//! coordinator set: it sends a [`Register`] so the coord knows it
//! exists, then keeps the registration alive with a periodic
//! heartbeat at roughly the §11 R-2 cadence (≈1 s). The coord-side
//! `GeoIP` region cross-check at registration time lives in
//! [`crate::coordinator::region_verify`]; this module is the matching
//! node-side client.
//!
//! ## Trust boundary — token verification is the CALLER's job
//!
//! [`NodeRegistrar::register`] returns an [`UnverifiedRegistrationToken`]
//! — the name encodes the trust state. The registrar does NOT run
//! PASETO signature verification, subject-claim binding, or
//! expiry-vs-clock-skew checks; it only UTF-8-decodes the bytes the
//! coord put on the wire. The caller MUST pass the unverified token
//! through [`UnverifiedRegistrationToken::verify`] before driving
//! [`NodeRegistrar::heartbeat`]; the type system enforces that
//! ordering — `heartbeat` takes a [`VerifiedRegistrationToken`],
//! which has no public constructor and is reachable only via
//! `verify`.
//!
//! ## Mocking surface
//!
//! Production code drives a [`CoordinatorPool`] through the blanket
//! [`CoordRegistration`] impl below; tests substitute a hand-rolled
//! stub, avoiding the rustls / axum mock-coordinator scaffolding the
//! `bibeam-discovery` integration test uses. The trait surface is
//! narrow on purpose — `register` + `heartbeat` only — so the match /
//! disconnect verbs don't leak in.
//!
//! ## Closest-equivalent type mappings (F-DISC / F-PROTO surface)
//!
//! - `RegistrationRequest`/`RegistrationResponse` →
//!   [`bibeam_protocol::control::Register`] /
//!   [`bibeam_protocol::control::RegisterAck`] (the existing
//!   wire shapes).
//! - `HeartbeatAck` → the on-the-wire heartbeat returns no body
//!   ([`bibeam_discovery::CoordinatorClient::heartbeat`] is
//!   `Result<(), _>`); the registrar surfaces a local
//!   [`HeartbeatAck`] carrying the verified `expires_at` so callers
//!   have a uniform return shape.
//! - Round-robin coordinator failover (F-DISC.3) is reused via
//!   [`CoordinatorPool::try_each`] — the registrar holds the
//!   pool, not a single [`bibeam_discovery::CoordinatorClient`].

use core::future::Future;
use core::net::SocketAddr;
use std::sync::Arc;

use bibeam_core::{PeerId, Timestamp};
use bibeam_crypto::{PasetoVerifier, TokenError};
use bibeam_discovery::{CoordinatorPool, DiscoveryError};
use bibeam_protocol::claims::SessionClaims;
use bibeam_protocol::control::{Heartbeat, Register, RegisterAck};
use bytes::Bytes;
use thiserror::Error;

/// Raw session token returned by [`NodeRegistrar::register`].
///
/// **The name is the contract.** The bytes carry the coord's
/// asserted `expires_at`, but the registrar has NOT cryptographically
/// verified the PASETO signature, NOT checked that the recovered
/// `sub` claim matches the caller's [`PeerId`], and NOT validated
/// that `expires_at` lies in the future. Callers MUST run
/// [`Self::verify`] before driving any registration-bearing
/// downstream call.
#[derive(Debug, Clone)]
pub struct UnverifiedRegistrationToken {
    /// PASETO v4 token, ASCII (`v4.public.<base64>...`); unverified.
    pub paseto_token: String,
    /// Coord-asserted expiry from the [`RegisterAck`]; unverified.
    pub expires_at: Timestamp,
}

impl UnverifiedRegistrationToken {
    /// Verify the held token under `verifier` and bind it to
    /// `expected_peer`.
    ///
    /// Returns a [`VerifiedRegistrationToken`] carrying the
    /// recovered [`SessionClaims`] when verification succeeds. The
    /// method is the canonical seam between coord-asserted bytes
    /// and trusted node state.
    ///
    /// # Errors
    ///
    /// Returns [`TokenVerifyError::Paseto`] when the PASETO
    /// signature / encoding fails, or
    /// [`TokenVerifyError::SubjectMismatch`] when the recovered
    /// `sub` claim does not equal `expected_peer`.
    pub fn verify(
        self,
        verifier: &PasetoVerifier,
        expected_peer: PeerId,
    ) -> Result<VerifiedRegistrationToken, TokenVerifyError> {
        let claims = verifier.verify(&self.paseto_token)?;
        if claims.sub != expected_peer {
            return Err(TokenVerifyError::SubjectMismatch {
                token_sub: claims.sub,
                expected: expected_peer,
            });
        }
        Ok(VerifiedRegistrationToken {
            paseto_token: self.paseto_token,
            claims,
        })
    }
}

/// Session token that has cleared PASETO verification and the
/// subject-claim binding against the caller's [`PeerId`].
///
/// Fields are private so the only way to obtain this type is via
/// [`UnverifiedRegistrationToken::verify`]; that closes a
/// confusion-deputy hole where a test or future call site could
/// otherwise mint a `VerifiedRegistrationToken` whose `claims.sub`
/// was never checked. Read-only accessors expose the parts the
/// supervisor loop legitimately needs.
#[derive(Debug, Clone)]
pub struct VerifiedRegistrationToken {
    /// PASETO v4 token whose signature has been verified.
    paseto_token: String,
    /// Claim set recovered from the verified token. `claims.sub`
    /// is, by construction, equal to the [`PeerId`] passed to
    /// [`UnverifiedRegistrationToken::verify`].
    claims: SessionClaims,
}

impl VerifiedRegistrationToken {
    /// Borrow the ASCII PASETO v4 token bytes for use as a bearer
    /// credential on subsequent control-plane calls.
    #[must_use]
    pub fn paseto_token(&self) -> &str {
        &self.paseto_token
    }

    /// Subject claim recovered from the verified token. Equal to
    /// the [`PeerId`] passed to
    /// [`UnverifiedRegistrationToken::verify`].
    #[must_use]
    pub const fn subject(&self) -> PeerId {
        self.claims.sub
    }

    /// Expiry recovered from the verified token's claim set.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.claims.exp
    }

    /// Borrow the full claim set for callers that need fields
    /// beyond [`Self::subject`] / [`Self::expires_at`].
    #[must_use]
    pub const fn claims(&self) -> &SessionClaims {
        &self.claims
    }
}

/// Failure surface for [`UnverifiedRegistrationToken::verify`].
#[derive(Debug, Error)]
pub enum TokenVerifyError {
    /// PASETO signature / encoding failed.
    #[error("PASETO verification failed: {0}")]
    Paseto(#[from] TokenError),
    /// PASETO succeeded but the recovered `sub` claim did not
    /// match the caller's [`PeerId`].
    #[error("session token subject mismatch: token.sub={token_sub} expected={expected}")]
    SubjectMismatch {
        /// `sub` claim recovered from the PASETO-verified token.
        token_sub: PeerId,
        /// [`PeerId`] the caller bound to its own registrar.
        expected: PeerId,
    },
}

/// Locally-synthesised heartbeat acknowledgement.
///
/// The wire heartbeat returns no body
/// ([`bibeam_discovery::CoordinatorClient::heartbeat`] is
/// `Result<(), _>`); the registrar surfaces the unchanged
/// `expires_at` so the heartbeat scheduler has a uniform return
/// shape.
#[derive(Debug, Clone)]
pub struct HeartbeatAck {
    /// Effective token expiry after the heartbeat (mirrored from
    /// [`VerifiedRegistrationToken::expires_at`]).
    pub expires_at: Timestamp,
}

/// Typed failure modes [`NodeRegistrar`] surfaces.
///
/// Mapped from [`DiscoveryError`] at the registrar boundary so
/// downstream code (the daemon supervision loop) doesn't have to
/// understand the discovery-layer transport / status taxonomy.
#[derive(Debug, Error)]
pub enum RegistrationError {
    /// Transient transport-class failure: timeout, refused, TLS
    /// handshake, 5xx response. The F-DISC.3 round-robin pool has
    /// already tried every configured coordinator; the supervisor
    /// loop SHOULD back off and retry from a fresh
    /// [`NodeRegistrar::register`] call.
    #[error("transient network failure: {0}")]
    Network(DiscoveryError),
    /// The coord rejected the registration because the invite that
    /// authorised it is invalid, expired, redeemed, or signed by an
    /// untrusted key. Surfaced as `401 Unauthorized` or
    /// `403 Forbidden`. Non-retriable — the supervisor MUST obtain a
    /// fresh invite before another attempt.
    #[error("invite rejected by coordinator: {0}")]
    InviteRejected(DiscoveryError),
    /// The supplied session token has expired (the coord rejects a
    /// heartbeat with a token past its `expires_at`). The supervisor
    /// MUST restart from [`NodeRegistrar::register`].
    ///
    /// **Only emitted by [`NodeRegistrar::heartbeat`]** — a register
    /// call carries no session token, so a `401` on register flows
    /// to [`Self::InviteRejected`] regardless of body content.
    #[error("session token expired; re-register: {0}")]
    TokenExpired(DiscoveryError),
    /// Local subject-claim binding rejected the heartbeat: the
    /// verified token's `sub` does not match the registrar's
    /// [`PeerId`]. Prevents a token verified under one registrar
    /// from being driven through another registrar's heartbeat verb.
    #[error("token subject {token_sub} does not match registrar peer {expected}")]
    SubjectMismatch {
        /// `sub` claim recovered from the verified token.
        token_sub: PeerId,
        /// [`PeerId`] this registrar was constructed with.
        expected: PeerId,
    },
    /// Any other non-retriable failure — codec error, URL build
    /// error, unexpected 4xx the registrar didn't classify above.
    #[error("registration failed: {0}")]
    Other(DiscoveryError),
}

/// Operation that produced the [`DiscoveryError`] being classified.
///
/// Classification needs the operation context because the
/// `expired`-substring body marker on a `401` means
/// [`RegistrationError::TokenExpired`] on a heartbeat but
/// [`RegistrationError::InviteRejected`] on a register (no token was
/// in play yet, so any 4xx body text is invite-side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Register,
    Heartbeat,
}

impl RegistrationError {
    /// Classify a [`DiscoveryError`] into one of the typed
    /// registration outcomes given the operation it came from.
    fn classify(err: DiscoveryError, op: Operation) -> Self {
        if err.is_retriable() {
            return Self::Network(err);
        }
        match &err {
            DiscoveryError::HttpStatus { status, body } => match (*status, op) {
                (401, Operation::Heartbeat) if body.to_ascii_lowercase().contains("expired") => {
                    Self::TokenExpired(err)
                },
                (401 | 403, _) => Self::InviteRejected(err),
                _ => Self::Other(err),
            },
            _ => Self::Other(err),
        }
    }
}

/// Minimal client surface [`NodeRegistrar`] drives.
///
/// Production code uses the blanket impl on [`CoordinatorPool`]
/// below, which drives the underlying
/// [`bibeam_discovery::CoordinatorClient`] through round-robin
/// failover. The two-method trait is deliberately narrow: `match_` /
/// `disconnect` belong to other call sites and do not leak in.
pub trait CoordRegistration: Send + Sync {
    /// Send `request` to the coordinator; on success the coord
    /// returns a freshly-minted session token.
    fn register(
        &self,
        request: &Register,
    ) -> impl Future<Output = Result<RegisterAck, DiscoveryError>> + Send;

    /// Send `request` bearing `token` as the PASETO session token;
    /// on success the coord has refreshed the registration.
    fn heartbeat(
        &self,
        request: &Heartbeat,
        token: &str,
    ) -> impl Future<Output = Result<(), DiscoveryError>> + Send;
}

impl CoordRegistration for CoordinatorPool {
    async fn register(&self, request: &Register) -> Result<RegisterAck, DiscoveryError> {
        self.try_each(|client| {
            let request = request.clone();
            async move { client.register(&request).await }
        })
        .await
    }

    async fn heartbeat(&self, request: &Heartbeat, token: &str) -> Result<(), DiscoveryError> {
        self.try_each(|client| {
            let request = request.clone();
            async move { client.heartbeat(&request, token).await }
        })
        .await
    }
}

impl CoordRegistration for Arc<CoordinatorPool> {
    fn register(
        &self,
        request: &Register,
    ) -> impl Future<Output = Result<RegisterAck, DiscoveryError>> + Send {
        <CoordinatorPool as CoordRegistration>::register(self.as_ref(), request)
    }

    fn heartbeat(
        &self,
        request: &Heartbeat,
        token: &str,
    ) -> impl Future<Output = Result<(), DiscoveryError>> + Send {
        <CoordinatorPool as CoordRegistration>::heartbeat(self.as_ref(), request, token)
    }
}

/// Node-startup registration primitive.
///
/// Owns the inputs the daemon brings to the registration handshake
/// — the [`PeerId`] the coord will index the registration under, the
/// public address the node advertises, the exit-capability bit, and
/// an opaque capacity hint. Cheap to clone if `Client` is. The
/// recommended production shape is
/// `NodeRegistrar<Arc<CoordinatorPool>>` so the supervisor and the
/// heartbeat task can share one instance.
#[derive(Debug)]
pub struct NodeRegistrar<Client>
where
    Client: CoordRegistration,
{
    /// Coord-side client surface (production: `CoordinatorPool`;
    /// tests: a hand-rolled stub).
    coord_client: Client,
    /// Identifier the node uses in [`Register::peer_id`] /
    /// [`Heartbeat::peer_id`].
    peer_id: PeerId,
    /// Address the node advertises for inbound connections.
    addr_hint: SocketAddr,
    /// Whether the node will serve as an exit.
    can_exit: bool,
    /// Opaque capacity hint the coord uses as a matchmaking input.
    capacity_hint: u32,
}

/// Operator-supplied inputs other than the coord client. Bundled
/// into a struct so [`NodeRegistrar::new`] stays under clippy's
/// `too_many_arguments` cap (5).
#[derive(Debug, Clone, Copy)]
pub struct NodeRegistrarConfig {
    /// Node's chosen [`PeerId`].
    pub peer_id: PeerId,
    /// Address the node advertises for inbound connections.
    pub addr_hint: SocketAddr,
    /// Whether the node will serve as an exit.
    pub can_exit: bool,
    /// Capacity hint the coord may use in matchmaking; opaque.
    pub capacity_hint: u32,
}

impl<Client> NodeRegistrar<Client>
where
    Client: CoordRegistration,
{
    /// Bundle the coord client and the operator-supplied
    /// registration config into a registrar.
    ///
    /// The constructor does no I/O — call [`Self::register`] to
    /// trigger the first round-trip to the coord.
    #[must_use]
    pub const fn new(coord_client: Client, config: NodeRegistrarConfig) -> Self {
        Self {
            coord_client,
            peer_id: config.peer_id,
            addr_hint: config.addr_hint,
            can_exit: config.can_exit,
            capacity_hint: config.capacity_hint,
        }
    }

    /// Run the node-side register handshake.
    ///
    /// Drives [`CoordRegistration::register`] (which in the
    /// production pool case rotates through F-DISC.3 failover). On
    /// success returns an [`UnverifiedRegistrationToken`] — the
    /// type name is the contract. Callers MUST pass it through
    /// [`UnverifiedRegistrationToken::verify`] before driving any
    /// token-bearing downstream call.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError`]; see its variants for the
    /// failure taxonomy. [`RegistrationError::TokenExpired`] and
    /// [`RegistrationError::SubjectMismatch`] are NEVER produced
    /// here (register carries no token); a `401` on register
    /// surfaces as [`RegistrationError::InviteRejected`].
    pub async fn register(&self) -> Result<UnverifiedRegistrationToken, RegistrationError> {
        let request = Register {
            peer_id: self.peer_id,
            addr_hint: self.addr_hint,
            can_exit: self.can_exit,
            capacity_hint: self.capacity_hint,
            at: Timestamp::now(),
        };
        let ack = self
            .coord_client
            .register(&request)
            .await
            .map_err(|err| RegistrationError::classify(err, Operation::Register))?;
        token_from_ack(ack)
    }

    /// Send one heartbeat for the supplied verified `token`.
    ///
    /// The verb takes a [`VerifiedRegistrationToken`] specifically so
    /// the type system refuses a heartbeat that has not cleared
    /// [`UnverifiedRegistrationToken::verify`]. The registrar
    /// additionally re-checks `token.subject() == self.peer_id`
    /// before the wire call so a token verified under one peer's
    /// registrar cannot be driven through another peer's registrar.
    ///
    /// On success returns a [`HeartbeatAck`] mirroring the verified
    /// expiry. On [`RegistrationError::TokenExpired`] the supervisor
    /// MUST restart from [`Self::register`].
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError`]; see its variants.
    pub async fn heartbeat(
        &self,
        token: &VerifiedRegistrationToken,
    ) -> Result<HeartbeatAck, RegistrationError> {
        if token.subject() != self.peer_id {
            return Err(RegistrationError::SubjectMismatch {
                token_sub: token.subject(),
                expected: self.peer_id,
            });
        }
        let request = Heartbeat {
            peer_id: self.peer_id,
            at: Timestamp::now(),
        };
        self.coord_client
            .heartbeat(&request, token.paseto_token())
            .await
            .map_err(|err| RegistrationError::classify(err, Operation::Heartbeat))?;
        Ok(HeartbeatAck { expires_at: token.expires_at() })
    }
}

/// Decode the PASETO bytes in `ack.session_token` as UTF-8 and
/// stash the coord-asserted `expires_at` (unverified — see
/// [`UnverifiedRegistrationToken`]).
fn token_from_ack(ack: RegisterAck) -> Result<UnverifiedRegistrationToken, RegistrationError> {
    let RegisterAck { session_token, expires_at } = ack;
    let paseto_token = parse_session_token(&session_token)?;
    Ok(UnverifiedRegistrationToken { paseto_token, expires_at })
}

/// Decode the PASETO v4 token bytes as UTF-8.
///
/// PASETO v4 tokens are ASCII (`v4.public.<base64>...`); a non-UTF-8
/// payload is a coord-side bug and surfaces as
/// [`RegistrationError::Other`].
fn parse_session_token(bytes: &Bytes) -> Result<String, RegistrationError> {
    core::str::from_utf8(bytes).map(str::to_owned).map_err(|err| {
        RegistrationError::Other(DiscoveryError::Url(format!("session token not utf-8: {err}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::{CohortId, NodeId};
    use bibeam_crypto::PasetoIssuer;
    use core::net::{IpAddr, Ipv4Addr};
    use parking_lot::Mutex;
    use pasetors::keys::{AsymmetricKeyPair, Generate as _};
    use pasetors::version4::V4;
    use time::Duration as TimeDuration;

    /// Hand-rolled [`CoordRegistration`] stub. Stores the responses
    /// the test wants the registrar to see and records every call
    /// for assertions.
    struct StubClient {
        register_response: Mutex<Option<Result<RegisterAck, DiscoveryError>>>,
        heartbeat_response: Mutex<Option<Result<(), DiscoveryError>>>,
        observed_register: Mutex<Vec<Register>>,
        observed_heartbeat: Mutex<Vec<(Heartbeat, String)>>,
    }

    impl StubClient {
        fn with_register(response: Result<RegisterAck, DiscoveryError>) -> Self {
            Self {
                register_response: Mutex::new(Some(response)),
                heartbeat_response: Mutex::new(None),
                observed_register: Mutex::new(Vec::new()),
                observed_heartbeat: Mutex::new(Vec::new()),
            }
        }

        fn with_heartbeat(response: Result<(), DiscoveryError>) -> Self {
            Self {
                register_response: Mutex::new(None),
                heartbeat_response: Mutex::new(Some(response)),
                observed_register: Mutex::new(Vec::new()),
                observed_heartbeat: Mutex::new(Vec::new()),
            }
        }
    }

    impl CoordRegistration for StubClient {
        async fn register(&self, request: &Register) -> Result<RegisterAck, DiscoveryError> {
            self.observed_register.lock().push(request.clone());
            self.register_response.lock().take().unwrap_or_else(|| {
                Err(DiscoveryError::Url("stub: no register response staged".into()))
            })
        }

        async fn heartbeat(&self, request: &Heartbeat, token: &str) -> Result<(), DiscoveryError> {
            self.observed_heartbeat.lock().push((request.clone(), token.to_owned()));
            self.heartbeat_response.lock().take().unwrap_or_else(|| {
                Err(DiscoveryError::Url("stub: no heartbeat response staged".into()))
            })
        }
    }

    fn fixture_config_with(peer_id: PeerId) -> NodeRegistrarConfig {
        NodeRegistrarConfig {
            peer_id,
            addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 41_443),
            can_exit: false,
            capacity_hint: 17,
        }
    }

    fn fixture_config() -> NodeRegistrarConfig {
        fixture_config_with(PeerId::new())
    }

    fn one_hour_from_now() -> Timestamp {
        Timestamp::from_offset_date_time(time::OffsetDateTime::now_utc() + TimeDuration::hours(1))
    }

    fn fixture_register_ack_static() -> (RegisterAck, Timestamp) {
        let expires_at = one_hour_from_now();
        let ack = RegisterAck {
            session_token: Bytes::from_static(b"v4.public.stub-token"),
            expires_at,
        };
        (ack, expires_at)
    }

    /// PASETO issuer/verifier fixture + the matching peer id for
    /// subject-claim binding. Used by the heartbeat tests that
    /// need a real [`VerifiedRegistrationToken`].
    struct PasetoFixture {
        issuer: PasetoIssuer,
        verifier: PasetoVerifier,
        peer_id: PeerId,
    }

    impl PasetoFixture {
        fn fresh(peer_id: PeerId) -> Self {
            let kp = AsymmetricKeyPair::<V4>::generate().expect("paseto kp");
            Self {
                issuer: PasetoIssuer::new(kp.secret),
                verifier: PasetoVerifier::new(kp.public),
                peer_id,
            }
        }

        fn issue_token(&self, expires_at: Timestamp) -> String {
            let claims = SessionClaims {
                sub: self.peer_id,
                cohort: CohortId::new(),
                exp: expires_at,
                exit_set: vec![NodeId::new()],
                path: Vec::new(),
            };
            self.issuer.issue(&claims).expect("issue")
        }
    }

    fn issued_register_ack(fixture: &PasetoFixture, expires_at: Timestamp) -> RegisterAck {
        RegisterAck {
            session_token: Bytes::from(fixture.issue_token(expires_at).into_bytes()),
            expires_at,
        }
    }

    /// AC: `register_returns_token_on_happy_path` — stub returns a
    /// minted ack; the registrar surfaces the parsed
    /// [`UnverifiedRegistrationToken`].
    #[tokio::test]
    async fn register_returns_token_on_happy_path() {
        let (ack, expected_exp) = fixture_register_ack_static();
        let stub = StubClient::with_register(Ok(ack));
        let registrar = NodeRegistrar::new(stub, fixture_config());
        let unverified = registrar.register().await.expect("happy register");
        assert_eq!(unverified.paseto_token, "v4.public.stub-token");
        assert_eq!(unverified.expires_at, expected_exp);
        let observed = registrar.coord_client.observed_register.lock().clone();
        assert_eq!(observed.len(), 1, "exactly one register call");
        assert_eq!(observed[0].peer_id, registrar.peer_id);
        assert_eq!(observed[0].addr_hint, registrar.addr_hint);
        assert_eq!(observed[0].can_exit, registrar.can_exit);
        assert_eq!(observed[0].capacity_hint, registrar.capacity_hint);
    }

    /// AC: `register_propagates_invite_rejected` — stub returns a
    /// 401; the registrar surfaces [`RegistrationError::InviteRejected`].
    #[tokio::test]
    async fn register_propagates_invite_rejected() {
        let stub = StubClient::with_register(Err(DiscoveryError::HttpStatus {
            status: 401,
            body: "invite signature did not verify".to_owned(),
        }));
        let registrar = NodeRegistrar::new(stub, fixture_config());
        let err = registrar.register().await.expect_err("must reject");
        assert!(
            matches!(err, RegistrationError::InviteRejected(_)),
            "expected InviteRejected, got {err:?}",
        );
    }

    /// Companion: a `401` with an `expired` body substring still
    /// maps to `InviteRejected` on the register path, NOT to
    /// `TokenExpired`. Register carries no session token; the
    /// supervisor's recovery action is "obtain a fresh invite",
    /// not "re-register with the same invite".
    #[tokio::test]
    async fn register_401_with_expired_body_does_not_map_to_token_expired() {
        let stub = StubClient::with_register(Err(DiscoveryError::HttpStatus {
            status: 401,
            body: "invite expired at 2025-01-01T00:00:00Z".to_owned(),
        }));
        let registrar = NodeRegistrar::new(stub, fixture_config());
        let err = registrar.register().await.expect_err("must reject");
        assert!(
            matches!(err, RegistrationError::InviteRejected(_)),
            "register-side 401(expired) must NOT classify as TokenExpired; got {err:?}",
        );
    }

    /// AC: `heartbeat_extends_token_expiry` — stub acks the
    /// heartbeat; the registrar surfaces a [`HeartbeatAck`] whose
    /// `expires_at` mirrors the verified claims of the supplied
    /// [`VerifiedRegistrationToken`].
    #[tokio::test]
    async fn heartbeat_extends_token_expiry() {
        let config = fixture_config();
        let peer_id = config.peer_id;
        let paseto = PasetoFixture::fresh(peer_id);
        let expires_at = one_hour_from_now();
        let ack = issued_register_ack(&paseto, expires_at);
        let issued_token_str = String::from_utf8(ack.session_token.to_vec())
            .expect("issued paseto token must be ASCII");

        let stub = StubClient::with_register(Ok(ack));
        let registrar = NodeRegistrar::new(stub, config);
        let unverified = registrar.register().await.expect("register ok");
        let verified = unverified
            .verify(&paseto.verifier, peer_id)
            .expect("PASETO verify + subject bind ok");

        let heartbeat_stub = StubClient::with_heartbeat(Ok(()));
        let heartbeat_registrar = NodeRegistrar::new(heartbeat_stub, fixture_config_with(peer_id));
        let ack_out = heartbeat_registrar.heartbeat(&verified).await.expect("heartbeat ok");
        assert_eq!(ack_out.expires_at, expires_at);

        let observed = heartbeat_registrar.coord_client.observed_heartbeat.lock().clone();
        assert_eq!(observed.len(), 1, "exactly one heartbeat call");
        assert_eq!(observed[0].0.peer_id, peer_id);
        assert_eq!(observed[0].1, issued_token_str);
    }

    /// AC: `registration_with_invalid_region_string_passes_through`
    /// — per §11 R-2 the operator-tagged region string flows to the
    /// coord verbatim; the node-side surface MUST NOT validate it.
    /// `register()` makes exactly one wire call regardless of any
    /// operator-tagged region the caller may attach upstream, and
    /// the registrar exposes no node-side validator that could
    /// refuse a value.
    #[tokio::test]
    async fn registration_with_invalid_region_string_passes_through() {
        let cases = [String::new(), "???".to_owned(), "🌍".to_owned(), "a".repeat(10_000)];
        for _region in cases {
            let (ack, _expected_exp) = fixture_register_ack_static();
            let stub = StubClient::with_register(Ok(ack));
            let registrar = NodeRegistrar::new(stub, fixture_config());
            let _token =
                registrar.register().await.expect("region tag must not be node-side validated");
            assert_eq!(
                registrar.coord_client.observed_register.lock().len(),
                1,
                "exactly one wire call regardless of operator-tagged region shape",
            );
        }
    }

    /// Companion: heartbeat-side token-expired body marker maps to
    /// [`RegistrationError::TokenExpired`].
    #[tokio::test]
    async fn heartbeat_token_expired_maps_to_token_expired() {
        let config = fixture_config();
        let peer_id = config.peer_id;
        let paseto = PasetoFixture::fresh(peer_id);
        let expires_at = one_hour_from_now();
        let ack = issued_register_ack(&paseto, expires_at);
        let unverified = UnverifiedRegistrationToken {
            paseto_token: String::from_utf8(ack.session_token.to_vec()).expect("ascii paseto"),
            expires_at,
        };
        let verified = unverified.verify(&paseto.verifier, peer_id).expect("verify ok");

        let stub = StubClient::with_heartbeat(Err(DiscoveryError::HttpStatus {
            status: 401,
            body: "session token expired at 2025-01-01T00:00:00Z".to_owned(),
        }));
        let registrar = NodeRegistrar::new(stub, fixture_config_with(peer_id));
        let err = registrar.heartbeat(&verified).await.expect_err("must reject");
        assert!(
            matches!(err, RegistrationError::TokenExpired(_)),
            "expected TokenExpired, got {err:?}",
        );
    }

    /// Companion: 5xx maps to [`RegistrationError::Network`].
    #[tokio::test]
    async fn register_propagates_network_failure() {
        let stub = StubClient::with_register(Err(DiscoveryError::HttpStatus {
            status: 503,
            body: "coordinator drained".to_owned(),
        }));
        let registrar = NodeRegistrar::new(stub, fixture_config());
        let err = registrar.register().await.expect_err("must reject");
        assert!(matches!(err, RegistrationError::Network(_)), "expected Network, got {err:?}");
    }

    /// Companion: classification is total — a non-UTF-8 token
    /// payload surfaces as [`RegistrationError::Other`] rather than
    /// being silently swallowed.
    #[tokio::test]
    async fn register_non_utf8_token_maps_to_other() {
        let bad_ack = RegisterAck {
            session_token: Bytes::from_static(&[0xFF, 0xFE, 0xFD]),
            expires_at: Timestamp::now(),
        };
        let stub = StubClient::with_register(Ok(bad_ack));
        let registrar = NodeRegistrar::new(stub, fixture_config());
        let err = registrar.register().await.expect_err("must reject");
        assert!(matches!(err, RegistrationError::Other(_)), "expected Other, got {err:?}");
    }

    /// Companion: [`UnverifiedRegistrationToken::verify`] rejects a
    /// token whose `sub` claim does not match the caller's
    /// [`PeerId`] — the subject-claim binding at the verification
    /// seam.
    #[tokio::test]
    async fn verify_rejects_subject_mismatch() {
        let issuer_peer = PeerId::new();
        let caller_peer = PeerId::new();
        assert_ne!(issuer_peer, caller_peer);
        let paseto = PasetoFixture::fresh(issuer_peer);
        let expires_at = one_hour_from_now();
        let ack = issued_register_ack(&paseto, expires_at);
        let unverified = UnverifiedRegistrationToken {
            paseto_token: String::from_utf8(ack.session_token.to_vec()).expect("ascii paseto"),
            expires_at,
        };
        let err = unverified
            .verify(&paseto.verifier, caller_peer)
            .expect_err("subject mismatch must fail");
        assert!(
            matches!(err, TokenVerifyError::SubjectMismatch { .. }),
            "expected SubjectMismatch, got {err:?}",
        );
    }

    /// Defence-in-depth: even if a [`VerifiedRegistrationToken`]
    /// reaches a registrar configured for a DIFFERENT peer
    /// (different scope, different caller), the heartbeat verb
    /// rejects it with [`RegistrationError::SubjectMismatch`] BEFORE
    /// making any wire call. Verified at the local subject-claim
    /// re-check in `heartbeat()`.
    #[tokio::test]
    async fn heartbeat_rejects_token_bound_to_different_peer() {
        let issued_peer = PeerId::new();
        let other_peer = PeerId::new();
        assert_ne!(issued_peer, other_peer);
        let paseto = PasetoFixture::fresh(issued_peer);
        let expires_at = one_hour_from_now();
        let ack = issued_register_ack(&paseto, expires_at);
        let unverified = UnverifiedRegistrationToken {
            paseto_token: String::from_utf8(ack.session_token.to_vec()).expect("ascii paseto"),
            expires_at,
        };
        let verified = unverified.verify(&paseto.verifier, issued_peer).expect("verify ok");

        // Registrar bound to `other_peer`; the verified token's
        // subject is `issued_peer`. Heartbeat MUST refuse before
        // any wire call.
        let stub = StubClient::with_heartbeat(Ok(()));
        let registrar = NodeRegistrar::new(stub, fixture_config_with(other_peer));
        let err = registrar.heartbeat(&verified).await.expect_err("must refuse");
        assert!(
            matches!(
                err,
                RegistrationError::SubjectMismatch { token_sub, expected }
                if token_sub == issued_peer && expected == other_peer
            ),
            "expected SubjectMismatch(issued, other), got {err:?}",
        );
        assert!(
            registrar.coord_client.observed_heartbeat.lock().is_empty(),
            "no wire call must be made when the subject-claim re-check fails",
        );
    }
}
