//! Integration test for [`bibeam_discovery::SessionBootstrap`]
//! (F-DISC.7).
//!
//! Stands up a real TLS-terminated axum mock coordinator on a
//! loopback port, points a [`CoordinatorClient`] at it through a
//! `rustls` config that trusts the mock's self-signed cert, and
//! exercises the full register-and-match bootstrap flow including a
//! PASETO v4 token signed by a fixture keypair.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test fixtures use unwrap/expect in setup paths"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "test functions never document panic behaviour"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Router, http::HeaderMap};
use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use bibeam_crypto::{IdentitySecretKey, PasetoIssuer, PasetoVerifier};
use bibeam_discovery::invite_validator::{SignedInvite, signing_payload};
use bibeam_discovery::{CoordinatorClient, CoordinatorPool, PeerProfile, SessionBootstrap};
use bibeam_protocol::claims::SessionClaims;
use bibeam_protocol::control::{
    MatchRequest, MatchResponse, Register, RegisterAck, SingleHopMatch,
};
use bytes::Bytes;
use pasetors::keys::{AsymmetricKeyPair, Generate as _};
use pasetors::version4::V4;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::oneshot;
use url::Url;

fn ensure_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _previously_installed = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Test fixture combining the issuer + verifier sides of a fresh
/// PASETO v4 keypair, plus the matching coordinator long-term
/// identity key.
struct Fixture {
    issuer: PasetoIssuer,
    verifier: PasetoVerifier,
    identity_secret: IdentitySecretKey,
}

impl Fixture {
    fn fresh() -> Self {
        let kp = AsymmetricKeyPair::<V4>::generate().expect("paseto kp");
        Self {
            issuer: PasetoIssuer::new(kp.secret),
            verifier: PasetoVerifier::new(kp.public),
            identity_secret: IdentitySecretKey::generate(),
        }
    }
}

/// Mock coordinator state shared between handlers.
#[derive(Clone)]
struct MockState {
    /// PASETO issuer for `/register` ack tokens.
    issuer: Arc<PasetoIssuer>,
    /// The exact peer identifier the test expects on register and match.
    expected_peer: PeerId,
    /// Cohort identifier the match handler returns.
    cohort: CohortId,
    /// Exit set the match handler returns.
    exit_set: Vec<NodeId>,
    /// Per-exit region tags the match handler stamps on
    /// [`SingleHopMatch::exit_regions`]. Empty for the F-CLI.4
    /// happy-path test that does not exercise the F-CLI.4b filter;
    /// populated for the F-CLI.4b end-to-end test below.
    exit_regions: std::collections::HashMap<NodeId, String>,
}

async fn register_handler(
    State(state): State<MockState>,
    Json(request): Json<Register>,
) -> Result<Json<RegisterAck>, (StatusCode, String)> {
    if request.peer_id != state.expected_peer {
        return Err((StatusCode::BAD_REQUEST, "unexpected peer_id".into()));
    }
    let now = time::OffsetDateTime::now_utc();
    let exp = Timestamp::from_offset_date_time(now + time::Duration::hours(1));
    let claims = SessionClaims {
        sub: request.peer_id,
        cohort: state.cohort,
        exp,
        exit_set: state.exit_set.clone(),
        // Single-hop test fixture: the path collapses to the chosen
        // exit. R-MULTIHOP-PROTO landed the wire shape; the
        // bootstrap test still drives the pre-multihop happy path.
        path: state.exit_set.iter().take(1).copied().collect(),
    };
    let token = state
        .issuer
        .issue(&claims)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("issue: {err}")))?;
    Ok(Json(RegisterAck {
        session_token: Bytes::from(token.into_bytes()),
        expires_at: exp,
    }))
}

async fn match_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(request): Json<MatchRequest>,
) -> Result<Json<MatchResponse>, (StatusCode, String)> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing authorization".to_string()))?;
    let value = auth
        .to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "non-ascii authorization".into()))?;
    if !value.starts_with("Bearer v4.public.") {
        return Err((StatusCode::UNAUTHORIZED, "wrong bearer format".into()));
    }
    if request.peer_id != state.expected_peer {
        return Err((StatusCode::BAD_REQUEST, "peer mismatch".into()));
    }
    let deadline = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    Ok(Json(MatchResponse::SingleHop(SingleHopMatch {
        cohort: state.cohort,
        exit_set: state.exit_set,
        exit_regions: state.exit_regions,
        rotation_deadline: Timestamp::from_offset_date_time(deadline),
    })))
}

/// Generate a self-signed cert for `localhost`. Returns the
/// `ServerConfig` for `axum-server` and the matching
/// `ClientConfig` trust store for the test's reqwest client.
fn self_signed_tls() -> (ServerConfig, ClientConfig) {
    let mut params = CertificateParams::new(vec!["localhost".into()]).expect("cert params");
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().expect("rcgen kp");
    let cert = params.self_signed(&key_pair).expect("self-sign");
    let cert_der = cert.der().clone();
    let key_pem = key_pair.serialize_pem();
    // `rustls-pki-types` 1.9+ exposes the `PemObject` trait directly,
    // so we decode the PKCS#8 PEM the rcgen keypair serialised without
    // pulling in `rustls-pemfile` (which is unmaintained per
    // RUSTSEC-2025-0134).
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("pkcs8 decode");
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der.to_vec())], key_der)
        .expect("server config");
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der.to_vec())).expect("trust cert");
    let client_config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    (server_config, client_config)
}

/// Spawn the mock coordinator on a fresh TLS-bound loopback port.
/// Returns the listening `SocketAddr`, a oneshot the caller can
/// drop or send through to signal shutdown, and the trust-store
/// `ClientConfig` the caller plugs into a `CoordinatorClient`.
async fn spawn_mock_coordinator(
    state: MockState,
) -> (SocketAddr, oneshot::Sender<()>, Arc<ClientConfig>) {
    ensure_crypto_provider();
    let (server_config, client_config) = self_signed_tls();
    let app = Router::new()
        .route("/api/v1/register", post(register_handler))
        .route("/api/v1/match", post(match_handler))
        .with_state(state);

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind addr");
    let listener = std::net::TcpListener::bind(bind).expect("tcp bind");
    let local_addr = listener.local_addr().expect("local addr");
    listener.set_nonblocking(true).expect("nonblocking");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server = axum_server::from_tcp_rustls(
        listener,
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config)),
    );

    tokio::spawn(async move {
        let serve = server.serve(app.into_make_service());
        tokio::pin!(serve);
        tokio::select! {
            _ = &mut serve => {},
            _ = shutdown_rx => {},
        }
    });

    // Tiny readiness wait so the listener accepts before the
    // client's first connect attempt.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (local_addr, shutdown_tx, Arc::new(client_config))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_happy_path_register_and_match() {
    ensure_crypto_provider();
    let fixture = Fixture::fresh();
    let expected_peer = PeerId::new();
    let cohort = CohortId::new();
    let exit_set = vec![NodeId::new(), NodeId::new()];

    let state = MockState {
        issuer: Arc::new(fixture.issuer),
        expected_peer,
        cohort,
        exit_set: exit_set.clone(),
        exit_regions: std::collections::HashMap::new(),
    };
    let (addr, shutdown_tx, tls) = spawn_mock_coordinator(state).await;
    let base =
        Url::parse(&format!("https://localhost:{port}/", port = addr.port())).expect("base url");

    let client = CoordinatorClient::new(base, Arc::clone(&tls)).expect("client");
    let pool = Arc::new(CoordinatorPool::new(vec![client]).expect("pool"));

    let coord_pubkey = fixture.identity_secret.public();
    let bootstrap = SessionBootstrap::new(Arc::clone(&pool), coord_pubkey.clone());

    let signed_invite = build_signed_invite(&fixture.identity_secret);
    let my_addr_hint: SocketAddr = "127.0.0.1:41443".parse().expect("addr hint");

    let profile = PeerProfile {
        peer_id: expected_peer,
        addr_hint: my_addr_hint,
        can_exit: true,
        capacity_hint: 42,
    };
    let session = bootstrap
        .bootstrap(&signed_invite, profile, &fixture.verifier)
        .await
        .expect("bootstrap must succeed");

    assert_eq!(session.claims.sub, expected_peer);
    assert_eq!(session.claims.cohort, cohort);
    assert_eq!(session.claims.exit_set, exit_set);
    assert_eq!(session.cohort_live.cohort, cohort);
    assert_eq!(session.cohort_live.exits, exit_set);
    assert!(session.cohort_live.members.is_empty(), "bootstrap returns partial live");
    assert!(
        session.cohort_live.exit_regions.is_empty(),
        "unfiltered happy-path test should not populate exit_regions",
    );
    assert!(
        session.session_token.starts_with("v4.public."),
        "session token must be PASETO v4 public",
    );

    // Shut down the mock cleanly so the test process does not leak
    // the listener task.
    let _ignored = shutdown_tx.send(());
}

/// R-REGION.3 + F-CLI.4b end-to-end: the coord-emitted
/// `SingleHopMatch.exit_regions` map propagates through
/// `bootstrap()` into `CohortLive.exit_regions`, where the client's
/// region-aware exit picker can filter by it. Before the
/// `SingleHopMatch` field was added this map was empty regardless
/// of operator config — `pick_exit(.., ExitFilter::Region(r), ..)` then refused
/// every call (the §11 R-3 deferral path). This test pins the
/// happy production-path data flow: coord emits → bootstrap copies
/// → client filter sees real region tags.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_propagates_exit_regions_into_cohort_live() {
    ensure_crypto_provider();
    let fixture = Fixture::fresh();
    let expected_peer = PeerId::new();
    let cohort = CohortId::new();
    let exit_set = vec![NodeId::new(), NodeId::new(), NodeId::new()];
    let mut exit_regions = std::collections::HashMap::new();
    exit_regions.insert(exit_set[0], "us-east".to_owned());
    exit_regions.insert(exit_set[1], "eu-de".to_owned());
    exit_regions.insert(exit_set[2], "us-east".to_owned());

    let state = MockState {
        issuer: Arc::new(fixture.issuer),
        expected_peer,
        cohort,
        exit_set: exit_set.clone(),
        exit_regions: exit_regions.clone(),
    };
    let (addr, shutdown_tx, tls) = spawn_mock_coordinator(state).await;
    let base =
        Url::parse(&format!("https://localhost:{port}/", port = addr.port())).expect("base url");

    let client = CoordinatorClient::new(base, Arc::clone(&tls)).expect("client");
    let pool = Arc::new(CoordinatorPool::new(vec![client]).expect("pool"));

    let coord_pubkey = fixture.identity_secret.public();
    let bootstrap = SessionBootstrap::new(Arc::clone(&pool), coord_pubkey.clone());

    let signed_invite = build_signed_invite(&fixture.identity_secret);
    let my_addr_hint: SocketAddr = "127.0.0.1:41443".parse().expect("addr hint");

    let profile = PeerProfile {
        peer_id: expected_peer,
        addr_hint: my_addr_hint,
        can_exit: true,
        capacity_hint: 42,
    };
    let session = bootstrap
        .bootstrap(&signed_invite, profile, &fixture.verifier)
        .await
        .expect("bootstrap must succeed");

    assert_eq!(session.cohort_live.exits, exit_set);
    assert_eq!(
        session.cohort_live.exit_regions, exit_regions,
        "coord-emitted exit_regions must flow into CohortLive verbatim — \
         this is the contract gap F-CLI.4b left open and R-REGION.3 closes",
    );

    let _ignored = shutdown_tx.send(());
}

/// Construct a valid `SignedInvite` signed by the fixture identity
/// key. Lives outside `bootstrap_happy_path_register_and_match` to
/// keep the test body shallow.
fn build_signed_invite(secret: &IdentitySecretKey) -> SignedInvite {
    use bibeam_crypto::{INVITE_CODE_LEN, InviteCode};
    let code = InviteCode::new([0xAB; INVITE_CODE_LEN]);
    let issued_at = Timestamp::now();
    let expires_at =
        Timestamp::from_offset_date_time(issued_at.into_inner() + time::Duration::hours(2));
    let payload = signing_payload(&code, &issued_at, Some(&expires_at));
    let signature = secret.sign(&payload).to_bytes().to_vec();
    SignedInvite {
        code,
        issuer: secret.public(),
        issued_at,
        expires_at: Some(expires_at),
        signature,
    }
}
