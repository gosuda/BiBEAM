#![forbid(unsafe_code)]
//! axum HTTP + WebSocket server scaffolding for the coordinator
//! daemon (F-COORD.1).
//!
//! [`build_router`] returns the full [`axum::Router`] the coordinator
//! mounts on its listening socket. Routes:
//!
//! - `POST /api/v1/register` — body: [`bibeam_protocol::control::Register`],
//!   response: [`bibeam_protocol::control::RegisterAck`].
//! - `POST /api/v1/match` — bearer token in `Authorization`; body:
//!   [`bibeam_protocol::control::MatchRequest`], response:
//!   [`bibeam_protocol::control::MatchResponse`].
//! - `POST /api/v1/heartbeat` — bearer token; body:
//!   [`bibeam_protocol::control::Heartbeat`], response: empty body.
//! - `POST /api/v1/disconnect` — bearer token; body:
//!   [`bibeam_protocol::control::Disconnect`], response: empty body.
//! - `GET /ws` — WebSocket upgrade with bearer token; emits
//!   [`bibeam_discovery::CoordinatorEvent`] envelopes.
//! - `GET /healthz` + `GET /readyz` — composed from
//!   [`bibeam_runtime::health_router`].
//! - `GET /metrics` — composed from
//!   [`bibeam_runtime::metrics_router`].
//!
//! ## Authorization
//!
//! [`BearerToken`] is an axum extractor that pulls the
//! `Authorization: Bearer <token>` header off the request and
//! short-circuits with `401 Unauthorized` when it is missing or
//! malformed. The token's content is opaque to this module — the
//! verifier in [`bibeam_crypto::PasetoVerifier`] is the layer that
//! decides whether the token is good. Until the F-COORD.4 admission
//! service lands, the request handlers accept any well-formed bearer
//! and return `503 Service Unavailable` to indicate the matchmaker
//! is not yet plumbed.
//!
//! ## Handler stubs
//!
//! The handlers in this module are **scaffolding only**: F-COORD.1
//! is the route surface; the service layer that backs the handlers
//! arrives in F-COORD.2 (registry), F-COORD.4 (admissioner) and
//! F-COORD.5 (gate). The current implementations validate the
//! request shape (so callers do not need to wait for the service
//! layer to learn the API is JSON-typed) and reply with an explicit
//! `503` carrying a short diagnostic message. Replacing each body
//! with a call into the typed service layer is the work of the
//! later sub-items.

use axum::{
    Json, Router,
    extract::ws::{WebSocket, WebSocketUpgrade},
    http::{StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bibeam_protocol::control::{Disconnect, Heartbeat, MatchRequest, Register};

/// Bearer prefix expected on `Authorization` headers — RFC 6750 §2.1.
const BEARER_PREFIX: &str = "Bearer ";

/// Short diagnostic body returned by every handler whose service
/// dependency has not yet been plumbed in.
const PENDING_SERVICE_BODY: &str = "coordinator service layer not yet wired in";

/// Bearer-token axum extractor.
///
/// Rejects with `401 Unauthorized` when the `Authorization` header
/// is missing, not UTF-8, or not prefixed with the canonical
/// `Bearer ` token. The captured value is the raw token string
/// (with the prefix stripped); validation against the PASETO
/// verifier happens in the F-COORD.4 admission layer.
#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

impl<RouterState> axum::extract::FromRequestParts<RouterState> for BearerToken
where
    RouterState: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &RouterState,
    ) -> Result<Self, Self::Rejection> {
        let Some(header_value) = parts.headers.get(AUTHORIZATION) else {
            return Err(unauthorized("missing authorization header"));
        };
        let Ok(header_str) = header_value.to_str() else {
            return Err(unauthorized("authorization header is not valid UTF-8"));
        };
        let Some(token) = header_str.strip_prefix(BEARER_PREFIX) else {
            return Err(unauthorized("authorization header is not a Bearer credential"));
        };
        if token.is_empty() {
            return Err(unauthorized("bearer token is empty"));
        }
        Ok(Self(token.to_owned()))
    }
}

/// Build the full coordinator [`axum::Router`] from the
/// control-plane routes, the health router, and a pre-built metrics
/// router.
///
/// Recorder installation is decoupled from router composition so the
/// daemon's `main` calls [`install_metrics`] exactly once (the
/// Prometheus exporter installs a process-global recorder; a second
/// install fails) while integration tests and other callers that
/// only care about the control plane can call [`build_router`]
/// repeatedly with a router they build out of band — or with
/// [`Router::new`] when they do not need the metrics surface.
///
/// `ready_latch` is forwarded to [`bibeam_runtime::health_router`]
/// so a separate plumbing step can flip the latch once the daemon
/// has finished its bring-up sequence.
pub fn build_router(ready_latch: bibeam_runtime::ReadyLatch, metrics: Router) -> Router {
    let health = bibeam_runtime::health_router(ready_latch);
    let control = Router::new()
        .route("/api/v1/register", post(handle_register))
        .route("/api/v1/match", post(handle_match))
        .route("/api/v1/heartbeat", post(handle_heartbeat))
        .route("/api/v1/disconnect", post(handle_disconnect))
        .route("/ws", get(handle_ws));
    Router::new().merge(control).merge(health).merge(metrics)
}

/// Install the process-global Prometheus recorder and return the
/// matching `GET /metrics` router.
///
/// Call once in `main`, never twice in the same process. Tests that
/// exercise [`build_router`] without the metrics surface should pass
/// [`Router::new`] instead.
///
/// # Errors
///
/// Returns [`ServerBuildError::Metrics`] if the recorder install
/// fails — typically because a recorder has already been installed
/// earlier in the process.
pub fn install_metrics() -> Result<Router, ServerBuildError> {
    bibeam_runtime::metrics_router().map_err(|err| ServerBuildError::Metrics(err.to_string()))
}

/// Failure modes for [`install_metrics`].
#[derive(Debug, thiserror::Error)]
pub enum ServerBuildError {
    /// Global Prometheus recorder install rejected the build —
    /// typically because the process already installed one.
    #[error("metrics router build failed: {0}")]
    Metrics(String),
}

#[allow(
    clippy::unused_async,
    reason = "axum's `post(...)` route signature requires `async`; the \
              stubbed body does no I/O until the F-COORD.2/4/5 service \
              layer lands."
)]
async fn handle_register(Json(_request): Json<Register>) -> Response {
    pending_service()
}

#[allow(
    clippy::unused_async,
    reason = "axum's `post(...)` route signature requires `async`; the \
              stubbed body does no I/O until the F-COORD.4 admissioner \
              and F-COORD.5 gate land."
)]
async fn handle_match(_bearer: BearerToken, Json(_request): Json<MatchRequest>) -> Response {
    pending_service()
}

#[allow(
    clippy::unused_async,
    reason = "axum's `post(...)` route signature requires `async`; the \
              stubbed body does no I/O until F-COORD.2's registry lands."
)]
async fn handle_heartbeat(_bearer: BearerToken, Json(_request): Json<Heartbeat>) -> Response {
    pending_service()
}

#[allow(
    clippy::unused_async,
    reason = "axum's `post(...)` route signature requires `async`; the \
              stubbed body does no I/O until F-COORD.2's registry lands."
)]
async fn handle_disconnect(_bearer: BearerToken, Json(_request): Json<Disconnect>) -> Response {
    pending_service()
}

async fn handle_ws(_bearer: BearerToken, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(close_immediately)
}

/// WebSocket on-upgrade handler stub.
///
/// Until the coordinator-pushed event stream lands behind the gate
/// (F-COORD.5) we accept the upgrade and immediately send a
/// `CloseFrame` so the peer learns to retry rather than hang waiting
/// for frames. Reusing
/// [`bibeam_discovery::ws::CoordinatorEvent::Disconnect`] would be
/// the right shape once the cohort-assigned path is wired in.
async fn close_immediately(mut socket: WebSocket) {
    use axum::extract::ws::{CloseFrame, Message};
    let frame = CloseFrame {
        code: axum::extract::ws::close_code::AWAY,
        reason: PENDING_SERVICE_BODY.into(),
    };
    let _previously_sent = socket.send(Message::Close(Some(frame))).await;
}

/// Build the canonical `401 Unauthorized` response used by the
/// bearer-token extractor.
fn unauthorized(message: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, message).into_response()
}

/// Build a `503 Service Unavailable` response with the
/// pending-service body.
fn pending_service() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, PENDING_SERVICE_BODY).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    fn json_body<Value: serde::Serialize>(value: &Value) -> Body {
        let encoded = serde_json::to_vec(value).expect("encode");
        Body::from(encoded)
    }

    fn fixture_register() -> Register {
        use core::net::{IpAddr, Ipv4Addr, SocketAddr};
        Register {
            peer_id: bibeam_core::PeerId::new(),
            addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 41_443),
            can_exit: false,
            capacity_hint: 0,
            at: bibeam_core::Timestamp::now(),
        }
    }

    fn fixture_match() -> MatchRequest {
        MatchRequest {
            peer_id: bibeam_core::PeerId::new(),
            at: bibeam_core::Timestamp::now(),
        }
    }

    #[tokio::test]
    async fn register_returns_pending_service_until_wired() {
        // Contract: F-COORD.1 lands the route surface only; the
        // service layer arrives in F-COORD.2/4/5. The placeholder
        // must respond with 503 + the pending-service diagnostic
        // body, *not* with a panic or a 5xx without a body. A
        // regression that returned 500 (or worse, dropped the body)
        // would mask the missing-service condition during the
        // staged rollout.
        let latch = bibeam_runtime::ReadyLatch::new();
        let router = build_router(latch, Router::new());
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/register")
            .header("content-type", "application/json")
            .body(json_body(&fixture_register()))
            .expect("build request");
        let response = router.oneshot(request).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn match_requires_bearer_token() {
        // Contract: every authenticated route returns 401 when the
        // Authorization header is absent. Catches a regression that
        // dropped the bearer extractor from the handler signature
        // (which would let unauthenticated peers reach the service
        // layer once it lands).
        let latch = bibeam_runtime::ReadyLatch::new();
        let router = build_router(latch, Router::new());
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/match")
            .header("content-type", "application/json")
            .body(json_body(&fixture_match()))
            .expect("build request");
        let response = router.oneshot(request).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn match_accepts_bearer_token() {
        // Contract: a well-formed bearer satisfies the extractor;
        // the handler then surfaces the pending-service 503. The
        // value of the bearer is opaque at this layer (verification
        // is F-COORD.4's job) so any non-empty token passes.
        let latch = bibeam_runtime::ReadyLatch::new();
        let router = build_router(latch, Router::new());
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/match")
            .header("content-type", "application/json")
            .header("authorization", "Bearer placeholder")
            .body(json_body(&fixture_match()))
            .expect("build request");
        let response = router.oneshot(request).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn healthz_is_always_ok() {
        // Contract: liveness must be independent of readiness. A
        // regression that wired both endpoints to the same latch
        // would break Kubernetes / systemd / Nomad orchestration
        // (the daemon would never report alive on a slow startup).
        let latch = bibeam_runtime::ReadyLatch::new();
        let router = build_router(latch, Router::new());
        let request = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())
            .expect("build request");
        let response = router.oneshot(request).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_starts_not_ready() {
        // Contract: a fresh latch reports not-ready (503). The
        // daemon flips it after redb + bind succeed (F-COORD.11).
        // A regression that defaulted the latch to ready would let
        // an orchestrator route traffic onto a half-initialised
        // process.
        let latch = bibeam_runtime::ReadyLatch::new();
        let router = build_router(latch, Router::new());
        let request = Request::builder()
            .method("GET")
            .uri("/readyz")
            .body(Body::empty())
            .expect("build request");
        let response = router.oneshot(request).await.expect("dispatch");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
