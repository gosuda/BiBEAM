#![forbid(unsafe_code)]
//! Coordinator HTTP client (F-DISC.1).
//!
//! [`CoordinatorClient`] is the JSON-over-HTTPS facade peers use to
//! drive the four request/response control-plane verbs the coordinator
//! exposes:
//!
//! - `POST /api/v1/register` — see [`CoordinatorClient::register`]
//! - `POST /api/v1/match` — see [`CoordinatorClient::match_`]
//! - `POST /api/v1/heartbeat` — see [`CoordinatorClient::heartbeat`]
//! - `POST /api/v1/disconnect` — see [`CoordinatorClient::disconnect`]
//!
//! Authenticated routes carry the PASETO session token as
//! `Authorization: Bearer <token>`. The token is opaque to this layer;
//! verification is the caller's job (typically through
//! [`bibeam_crypto::PasetoVerifier`]).
//!
//! ## TLS injection
//!
//! `reqwest`'s `use_preconfigured_tls` accepts a value-typed
//! [`rustls::ClientConfig`]; we accept an `Arc<rustls::ClientConfig>`
//! at the constructor so callers can share a single config across
//! multiple coordinators (typical in the round-robin pool landing in
//! F-DISC.3) and clone the inner value once, at builder time, into the
//! reqwest `Client`.

use std::sync::Arc;

use reqwest::{Client, StatusCode};
use url::Url;

use crate::error::DiscoveryError;

/// Path suffix appended to the coordinator base URL for the
/// register verb.
const PATH_REGISTER: &str = "api/v1/register";
/// Path suffix appended to the coordinator base URL for the
/// match verb.
const PATH_MATCH: &str = "api/v1/match";
/// Path suffix appended to the coordinator base URL for the
/// heartbeat verb.
const PATH_HEARTBEAT: &str = "api/v1/heartbeat";
/// Path suffix appended to the coordinator base URL for the
/// disconnect verb.
const PATH_DISCONNECT: &str = "api/v1/disconnect";

/// Authenticated, TLS-pinned JSON client for a single coordinator
/// endpoint.
///
/// Cheap to clone — internally backed by an `Arc`-shared `reqwest::Client`.
/// Intended to be wrapped in an `Arc` by callers that build the
/// round-robin pool landing in F-DISC.3.
#[derive(Clone, Debug)]
pub struct CoordinatorClient {
    /// Reqwest client pre-armed with the caller-supplied rustls config.
    http: Client,
    /// Base URL of the coordinator; per-call paths are joined off this.
    base_url: Url,
}

impl CoordinatorClient {
    /// Build a coordinator client targeting `base_url` and using
    /// `tls` as the rustls `ClientConfig`.
    ///
    /// The inner config is cloned once into the reqwest builder via
    /// [`reqwest::ClientBuilder::use_preconfigured_tls`]. The `Arc`
    /// at the call boundary lets the same config be shared across
    /// every coordinator in a pool without redundant per-config
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Url`] if `base_url` is non-HTTPS,
    /// cannot serve as a base for joining path suffixes (i.e.
    /// `base_url.cannot_be_a_base()`), or lacks a trailing slash on
    /// its path. [`DiscoveryError::HttpTransport`] is returned if
    /// reqwest cannot build the underlying client.
    ///
    /// The trailing-slash requirement avoids the silent
    /// last-path-segment drop that [`Url::join`] performs against a
    /// segmentless base. Coordinator deployments behind a path prefix
    /// (`https://coord.example.com/v1/`) work correctly; bare hosts
    /// (`https://coord.example.com`) are normalised by the parser to
    /// have a single-slash path.
    pub fn new(base_url: Url, tls: Arc<rustls::ClientConfig>) -> Result<Self, DiscoveryError> {
        if base_url.scheme() != "https" {
            return Err(DiscoveryError::Url(format!(
                "coordinator base URL must be HTTPS: got scheme {scheme:?}",
                scheme = base_url.scheme(),
            )));
        }
        if base_url.cannot_be_a_base() {
            return Err(DiscoveryError::Url(format!(
                "coordinator base URL cannot serve as a base: {base_url}",
            )));
        }
        if !base_url.path().ends_with('/') {
            return Err(DiscoveryError::Url(format!(
                "coordinator base URL must end with '/': got path {path:?}",
                path = base_url.path(),
            )));
        }
        // `reqwest::ClientBuilder::use_preconfigured_tls` downcasts the
        // argument to the concrete TLS backend type (`rustls::ClientConfig`
        // here) via `Any`; an `Arc<ClientConfig>` is therefore *not*
        // accepted directly. `Arc::unwrap_or_clone` consumes the caller's
        // arc — avoiding a clone when refcount=1 (the typical
        // single-coordinator case) and falling back to one clone when the
        // caller is sharing it across a pool (F-DISC.3).
        let tls_config = Arc::unwrap_or_clone(tls);
        let http = Client::builder()
            .use_preconfigured_tls(tls_config)
            .build()
            .map_err(DiscoveryError::from)?;
        Ok(Self { http, base_url })
    }

    /// Return the configured base URL.
    #[must_use]
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Send a registration request.
    ///
    /// On success returns the coordinator's [`RegisterAck`] carrying
    /// the freshly-minted PASETO session token. Authentication is
    /// out-of-band: the registration body itself names the peer.
    ///
    /// [`RegisterAck`]: bibeam_protocol::control::RegisterAck
    pub async fn register(
        &self,
        request: &bibeam_protocol::control::Register,
    ) -> Result<bibeam_protocol::control::RegisterAck, DiscoveryError> {
        let url = self.endpoint(PATH_REGISTER)?;
        let builder = self.http.post(url).json(request);
        send_json(builder).await
    }

    /// Send a match request bearing `token` as the PASETO session
    /// token.
    ///
    /// On success returns the coordinator's [`MatchResponse`] —
    /// cohort, exit set, rotation deadline.
    ///
    /// Trailing-underscore naming sidesteps the reserved word
    /// `match`.
    ///
    /// [`MatchResponse`]: bibeam_protocol::control::MatchResponse
    pub async fn match_(
        &self,
        request: &bibeam_protocol::control::MatchRequest,
        token: &str,
    ) -> Result<bibeam_protocol::control::MatchResponse, DiscoveryError> {
        let url = self.endpoint(PATH_MATCH)?;
        let builder = self.http.post(url).bearer_auth(token).json(request);
        send_json(builder).await
    }

    /// Send a heartbeat bearing `token` as the PASETO session token.
    pub async fn heartbeat(
        &self,
        request: &bibeam_protocol::control::Heartbeat,
        token: &str,
    ) -> Result<(), DiscoveryError> {
        let url = self.endpoint(PATH_HEARTBEAT)?;
        let builder = self.http.post(url).bearer_auth(token).json(request);
        send_no_content(builder).await
    }

    /// Send a disconnect bearing `token` as the PASETO session token.
    pub async fn disconnect(
        &self,
        request: &bibeam_protocol::control::Disconnect,
        token: &str,
    ) -> Result<(), DiscoveryError> {
        let url = self.endpoint(PATH_DISCONNECT)?;
        let builder = self.http.post(url).bearer_auth(token).json(request);
        send_no_content(builder).await
    }

    /// Join the base URL with one of the per-verb path suffixes.
    fn endpoint(&self, suffix: &str) -> Result<Url, DiscoveryError> {
        self.base_url
            .join(suffix)
            .map_err(|err| DiscoveryError::Url(format!("join {suffix}: {err}")))
    }
}

/// Send `builder`, raise on non-success status, decode the JSON body
/// as `T`.
async fn send_json<T>(builder: reqwest::RequestBuilder) -> Result<T, DiscoveryError>
where
    T: serde::de::DeserializeOwned,
{
    let response = builder.send().await.map_err(DiscoveryError::from)?;
    let response = check_status(response).await?;
    let bytes = response.bytes().await.map_err(DiscoveryError::from)?;
    serde_json::from_slice::<T>(&bytes).map_err(DiscoveryError::from)
}

/// Send `builder`, raise on non-success status, discard the body.
async fn send_no_content(builder: reqwest::RequestBuilder) -> Result<(), DiscoveryError> {
    let response = builder.send().await.map_err(DiscoveryError::from)?;
    let _checked = check_status(response).await?;
    Ok(())
}

/// Promote a non-2xx HTTP response to [`DiscoveryError::HttpStatus`],
/// capturing a truncated body for diagnostics.
async fn check_status(response: reqwest::Response) -> Result<reqwest::Response, DiscoveryError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = status_body(response).await;
    Err(DiscoveryError::HttpStatus { status: status.as_u16(), body })
}

/// Body length cap on the diagnostic message captured for a failed
/// response. Long bodies are truncated to avoid logging arbitrary
/// server output verbatim.
const STATUS_BODY_CAP: usize = 1024;

/// Drain `response` into a short, lossy UTF-8 string suitable for
/// diagnostics. Never errors; on read failure returns a placeholder
/// so the caller still surfaces the status code.
async fn status_body(response: reqwest::Response) -> String {
    match response.bytes().await {
        Ok(bytes) => {
            let take = bytes.len().min(STATUS_BODY_CAP);
            String::from_utf8_lossy(&bytes[..take]).into_owned()
        },
        Err(err) => format!("<body unreadable: {err}>"),
    }
}

/// Helper: report whether a status maps to a retriable
/// [`DiscoveryError::HttpStatus`]. Exposed for callers that pre-check
/// before constructing an error.
#[must_use]
pub fn status_is_retriable(status: StatusCode) -> bool {
    status.is_server_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Once};

    /// Idempotently install the `ring` crypto provider for rustls.
    ///
    /// `rustls` 0.23 requires a process-level [`rustls::crypto::CryptoProvider`]
    /// to be installed before any TLS handshake (or `ClientConfig::builder`
    /// call without an explicit provider). Tests don't actually handshake,
    /// but `Client::builder().use_preconfigured_tls(_)` still trips this
    /// check on construction. Using `Once` keeps multiple test threads
    /// from racing the install.
    fn ensure_crypto_provider() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            // `install_default` returns `Err(provider)` if a provider was
            // already installed; that is exactly the "already-installed"
            // success case and we discard it.
            let _previously_installed = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn empty_tls_config() -> Arc<rustls::ClientConfig> {
        ensure_crypto_provider();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Arc::new(config)
    }

    #[test]
    fn rejects_cannot_be_a_base_url() {
        let bad = Url::parse("mailto:nope@example.com").expect("parse");
        let err = CoordinatorClient::new(bad, empty_tls_config()).expect_err("must reject");
        assert!(matches!(err, DiscoveryError::Url(_)));
    }

    #[test]
    fn rejects_non_https_base_url() {
        let bad = Url::parse("http://coord.example.com/").expect("parse");
        let err = CoordinatorClient::new(bad, empty_tls_config()).expect_err("must reject");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("HTTPS")));
    }

    #[test]
    fn rejects_base_url_without_trailing_slash() {
        // Bare hostnames are normalised by `Url::parse` to `/`, so this
        // exercises the explicit-path case `/v1` (no trailing slash).
        let bad = Url::parse("https://coord.example.com/v1").expect("parse");
        let err = CoordinatorClient::new(bad, empty_tls_config()).expect_err("must reject");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("'/'")));
    }

    #[test]
    fn accepts_https_base_url() {
        let good = Url::parse("https://coord.example.com/").expect("parse");
        let client = CoordinatorClient::new(good.clone(), empty_tls_config()).expect("build");
        assert_eq!(client.base_url(), &good);
    }

    #[test]
    fn endpoint_joins_path_suffix() {
        let base = Url::parse("https://coord.example.com/").expect("parse");
        let client = CoordinatorClient::new(base, empty_tls_config()).expect("build");
        let joined = client.endpoint(PATH_REGISTER).expect("join");
        assert_eq!(joined.path(), "/api/v1/register");
    }

    #[test]
    fn endpoint_preserves_path_prefix_with_trailing_slash() {
        let base = Url::parse("https://coord.example.com/v1/").expect("parse");
        let client = CoordinatorClient::new(base, empty_tls_config()).expect("build");
        let joined = client.endpoint(PATH_REGISTER).expect("join");
        assert_eq!(joined.path(), "/v1/api/v1/register");
    }

    #[test]
    fn status_is_retriable_classifies_5xx() {
        assert!(status_is_retriable(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!status_is_retriable(StatusCode::UNAUTHORIZED));
    }
}
