#![forbid(unsafe_code)]
//! Coordinator WebSocket client (F-DISC.2).
//!
//! Where [`crate::http`] handles the four request/response control-plane
//! verbs, [`CoordinatorWs`] receives the coordinator-pushed event stream
//! a peer needs after registration:
//!
//! - [`CoordinatorEvent::CohortAssigned`] — initial cohort membership and
//!   exit set (a fresh [`bibeam_protocol::cohort::CohortLive`]).
//! - [`CoordinatorEvent::CohortRotated`] — cohort is retiring; rotate
//!   in-flight tunnels to the replacement
//!   ([`bibeam_protocol::cohort::CohortRotate`]).
//! - [`CoordinatorEvent::Disconnect`] — coordinator is asking us to
//!   leave for the wrapped reason.
//!
//! ## Wire format
//!
//! The endpoint lives at `wss://<coordinator>/api/v1/events`. Each frame
//! is a single tungstenite text [`tokio_tungstenite::tungstenite::Message::Text`]
//! holding a tagged JSON envelope (see the module's private
//! `WirePayload` type — exposed only through [`encode_event`] for
//! integration-test fixtures). Binary frames, ping/pong, and close
//! frames are handled at the transport layer; ping/pong is passed
//! through automatically by tungstenite, close surfaces as `Ok(None)`
//! from [`CoordinatorWs::next_event`].
//!
//! Auth is the PASETO session token from [`bibeam_protocol::control::RegisterAck`],
//! presented as the WS upgrade `Authorization: Bearer <token>` header.

use std::sync::Arc;

use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderValue, Request};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};
use url::Url;

use crate::error::DiscoveryError;

/// Path suffix appended to the coordinator base URL for the
/// coordinator-pushed event stream.
pub const PATH_EVENTS: &str = "api/v1/events";

/// Event a peer learns about by listening on the coordinator's
/// WebSocket stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorEvent {
    /// The coordinator has assigned the peer to a (possibly fresh)
    /// cohort and is broadcasting its canonical snapshot.
    CohortAssigned(bibeam_protocol::cohort::CohortLive),
    /// The coordinator is rotating the peer's cohort; in-flight
    /// tunnels should migrate to the replacement before the old
    /// cohort is torn down.
    CohortRotated(bibeam_protocol::cohort::CohortRotate),
    /// The coordinator is asking the peer to leave. The wrapped
    /// reason is captured for human-readable diagnostics.
    Disconnect(String),
}

/// Wire shape of one event frame on the coordinator's WebSocket
/// stream.
///
/// This is the canonical JSON envelope; [`CoordinatorEvent`] is the
/// typed view callers consume. Decoupling the two means we can
/// extend either side independently (e.g. add a new variant the
/// client tolerates as unknown without breaking decode).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WirePayload {
    CohortAssigned {
        cohort: bibeam_protocol::cohort::CohortLive,
    },
    CohortRotated {
        rotation: bibeam_protocol::cohort::CohortRotate,
    },
    Disconnect {
        reason: String,
    },
}

impl From<WirePayload> for CoordinatorEvent {
    fn from(wire: WirePayload) -> Self {
        match wire {
            WirePayload::CohortAssigned { cohort } => Self::CohortAssigned(cohort),
            WirePayload::CohortRotated { rotation } => Self::CohortRotated(rotation),
            WirePayload::Disconnect { reason } => Self::Disconnect(reason),
        }
    }
}

impl From<&CoordinatorEvent> for WirePayload {
    fn from(event: &CoordinatorEvent) -> Self {
        match event {
            CoordinatorEvent::CohortAssigned(cohort) => {
                Self::CohortAssigned { cohort: cohort.clone() }
            },
            CoordinatorEvent::CohortRotated(rotation) => {
                Self::CohortRotated { rotation: rotation.clone() }
            },
            CoordinatorEvent::Disconnect(reason) => Self::Disconnect { reason: reason.clone() },
        }
    }
}

/// Open WebSocket connection to one coordinator's event stream.
///
/// Owns the tungstenite stream; not `Clone`. Drop the value to drop
/// the connection (or call [`CoordinatorWs::close`] for a graceful
/// close frame).
pub struct CoordinatorWs {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl core::fmt::Debug for CoordinatorWs {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("CoordinatorWs").finish_non_exhaustive()
    }
}

impl CoordinatorWs {
    /// Open a WebSocket to the coordinator's event endpoint.
    ///
    /// `base_url` is the same HTTPS coordinator URL the HTTP client
    /// uses; this constructor derives the matching `wss://` endpoint
    /// at `<base>/api/v1/events`. `token` is the PASETO session token
    /// the coordinator issued at registration; it is presented in the
    /// WS upgrade as `Authorization: Bearer <token>`.
    ///
    /// `tls` is the rustls config the upgrade handshake uses. The
    /// caller is expected to share the same config it built for the
    /// HTTP client; we wrap it in a [`Connector::Rustls`] for the
    /// tungstenite upgrade path.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Url`] if `base_url` is non-HTTPS,
    /// lacks a trailing slash, cannot serve as a base, or produces a
    /// path the tungstenite request builder rejects. Returns
    /// [`DiscoveryError::Ws`] for any tungstenite failure during the
    /// upgrade (TCP, TLS, malformed response, status != 101).
    pub async fn connect(
        base_url: &Url,
        token: &str,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, DiscoveryError> {
        let endpoint = derive_ws_endpoint(base_url)?;
        let request = build_upgrade_request(&endpoint, token)?;
        let connector = Connector::Rustls(tls);
        let (stream, _response) =
            connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(DiscoveryError::from)?;
        Ok(Self { stream })
    }

    /// Pull the next coordinator event off the stream.
    ///
    /// Returns:
    ///
    /// - `Ok(Some(event))` for a successfully-decoded event frame,
    /// - `Ok(None)` when the coordinator closed the stream cleanly,
    /// - `Err(DiscoveryError::Ws | ::Json)` for transport / decode
    ///   errors.
    ///
    /// Binary, ping, and pong frames are ignored; tungstenite handles
    /// ping/pong automatically.
    pub async fn next_event(&mut self) -> Result<Option<CoordinatorEvent>, DiscoveryError> {
        while let Some(frame) = self.stream.next().await {
            let message = frame.map_err(DiscoveryError::from)?;
            match message {
                Message::Text(text) => {
                    let wire: WirePayload =
                        serde_json::from_str(&text).map_err(DiscoveryError::from)?;
                    return Ok(Some(CoordinatorEvent::from(wire)));
                },
                Message::Close(_) => return Ok(None),
                Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {},
            }
        }
        Ok(None)
    }

    /// Send a graceful close frame and tear the stream down.
    pub async fn close(mut self) -> Result<(), DiscoveryError> {
        self.stream.close(None).await.map_err(DiscoveryError::from)?;
        Ok(())
    }
}

/// Encode a [`CoordinatorEvent`] as the JSON envelope the wire format
/// uses.
///
/// Exposed so a mock server (the F-DISC.7 integration test) can build
/// the same byte sequence the production coordinator emits, without
/// re-implementing the envelope shape.
///
/// # Errors
///
/// Returns [`DiscoveryError::Json`] if the underlying
/// [`bibeam_protocol::cohort`] types fail to serialise — vanishingly
/// unlikely given the shapes are pure data, but surfaced for
/// completeness.
pub fn encode_event(event: &CoordinatorEvent) -> Result<String, DiscoveryError> {
    let wire = WirePayload::from(event);
    serde_json::to_string(&wire).map_err(DiscoveryError::from)
}

/// Translate the HTTPS coordinator base URL into the matching `wss://`
/// event-stream URL.
fn derive_ws_endpoint(base_url: &Url) -> Result<Url, DiscoveryError> {
    if base_url.scheme() != "https" {
        return Err(DiscoveryError::Url(format!(
            "WebSocket base URL must be HTTPS: got scheme {scheme:?}",
            scheme = base_url.scheme(),
        )));
    }
    if !base_url.path().ends_with('/') {
        return Err(DiscoveryError::Url(format!(
            "WebSocket base URL must end with '/': got path {path:?}",
            path = base_url.path(),
        )));
    }
    let mut endpoint = base_url
        .join(PATH_EVENTS)
        .map_err(|err| DiscoveryError::Url(format!("join {PATH_EVENTS}: {err}")))?;
    endpoint
        .set_scheme("wss")
        .map_err(|()| DiscoveryError::Url("unable to set wss scheme on event endpoint".into()))?;
    Ok(endpoint)
}

/// Build the tungstenite upgrade request: the WS-required headers
/// tungstenite generates plus `Authorization: Bearer <token>`.
///
/// `into_client_request` already produces a fully-formed handshake
/// request from the endpoint URL string — including the upgrade
/// headers, a fresh `Sec-WebSocket-Key`, and a correct `Host` header
/// that carries any non-default port. We deliberately only *augment*
/// that request with the bearer token; overwriting `Host` or `Uri` is
/// what breaks coordinator deployments behind non-standard ports
/// (`wss://host:8443/...`) and virtual-host routing.
fn build_upgrade_request(endpoint: &Url, token: &str) -> Result<Request<()>, DiscoveryError> {
    let bearer = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|err| DiscoveryError::Url(format!("authorization header rejected: {err}")))?;
    let mut request = endpoint.as_str().into_client_request().map_err(DiscoveryError::from)?;
    request.headers_mut().insert("Authorization", bearer);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
    use bibeam_protocol::cohort::{CohortLive, CohortRotate};

    use super::*;

    fn sample_cohort_live() -> CohortLive {
        CohortLive {
            cohort: CohortId::new(),
            members: vec![PeerId::new()],
            exits: vec![NodeId::new()],
            exit_regions: std::collections::HashMap::new(),
            at: Timestamp::now(),
        }
    }

    fn sample_cohort_rotate() -> CohortRotate {
        CohortRotate {
            old: CohortId::new(),
            new: CohortId::new(),
            at: Timestamp::now(),
        }
    }

    #[test]
    fn derive_ws_endpoint_rejects_http() {
        let bad = Url::parse("http://coord.example.com/").expect("parse");
        let err = derive_ws_endpoint(&bad).expect_err("must reject");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("HTTPS")));
    }

    #[test]
    fn derive_ws_endpoint_rejects_missing_trailing_slash() {
        let bad = Url::parse("https://coord.example.com/v1").expect("parse");
        let err = derive_ws_endpoint(&bad).expect_err("must reject");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("'/'")));
    }

    #[test]
    fn derive_ws_endpoint_promotes_scheme_and_appends_events_path() {
        let base = Url::parse("https://coord.example.com/").expect("parse");
        let endpoint = derive_ws_endpoint(&base).expect("derive");
        assert_eq!(endpoint.scheme(), "wss");
        assert_eq!(endpoint.path(), "/api/v1/events");
    }

    #[test]
    fn derive_ws_endpoint_preserves_path_prefix() {
        let base = Url::parse("https://coord.example.com/v1/").expect("parse");
        let endpoint = derive_ws_endpoint(&base).expect("derive");
        assert_eq!(endpoint.path(), "/v1/api/v1/events");
    }

    #[test]
    fn wire_payload_round_trips_cohort_assigned() {
        let event = CoordinatorEvent::CohortAssigned(sample_cohort_live());
        let encoded = encode_event(&event).expect("encode");
        assert!(encoded.contains("cohort_assigned"), "{encoded}");
        let decoded: WirePayload = serde_json::from_str(&encoded).expect("decode");
        let recovered: CoordinatorEvent = decoded.into();
        assert_eq!(recovered, event);
    }

    #[test]
    fn wire_payload_round_trips_cohort_rotated() {
        let event = CoordinatorEvent::CohortRotated(sample_cohort_rotate());
        let encoded = encode_event(&event).expect("encode");
        assert!(encoded.contains("cohort_rotated"), "{encoded}");
        let decoded: WirePayload = serde_json::from_str(&encoded).expect("decode");
        let recovered: CoordinatorEvent = decoded.into();
        assert_eq!(recovered, event);
    }

    #[test]
    fn wire_payload_round_trips_disconnect() {
        let event = CoordinatorEvent::Disconnect("rotation".to_string());
        let encoded = encode_event(&event).expect("encode");
        assert!(encoded.contains("disconnect"), "{encoded}");
        let decoded: WirePayload = serde_json::from_str(&encoded).expect("decode");
        let recovered: CoordinatorEvent = decoded.into();
        assert_eq!(recovered, event);
    }

    #[test]
    fn build_upgrade_request_attaches_bearer_token() {
        let endpoint = Url::parse("wss://coord.example.com/api/v1/events").expect("parse");
        let request = build_upgrade_request(&endpoint, "abc.def.ghi").expect("build");
        let auth = request
            .headers()
            .get("Authorization")
            .expect("authorization header")
            .to_str()
            .expect("ascii");
        assert_eq!(auth, "Bearer abc.def.ghi");
    }

    #[test]
    fn build_upgrade_request_preserves_non_default_port_host_header() {
        // Regression guard for the bug where overwriting `Host` with
        // `host_str()` dropped the port and broke coordinators behind
        // non-standard ports (`wss://host:8443/...`) and virtual-host
        // routers that key off `host:port`.
        let endpoint = Url::parse("wss://coord.example.com:8443/api/v1/events").expect("parse");
        let request = build_upgrade_request(&endpoint, "tok").expect("build");
        let host = request.headers().get("Host").expect("host header").to_str().expect("ascii");
        assert_eq!(host, "coord.example.com:8443");
    }
}
