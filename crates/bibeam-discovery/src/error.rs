#![forbid(unsafe_code)]
//! Discovery-layer error type.
//!
//! [`DiscoveryError`] is the single error surface every public call in
//! this crate funnels through. Variants are grouped by failure class
//! rather than by call site so downstream callers (the node, the CLI,
//! the coordinator-as-client side) can classify retryability without
//! string-sniffing.
//!
//! ## Retry semantics
//!
//! [`DiscoveryError::is_retriable`] separates the transport-level
//! failures that round-robin failover (lands in F-DISC.3) is allowed
//! to retry from the server-side rejections that would give the same
//! answer at every coordinator. The split is the contract
//! `CoordinatorPool::try_each` will rely on.

use thiserror::Error;

/// All-purpose error type returned by every public call in
/// `bibeam-discovery`.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// `reqwest` failed to send or receive an HTTP request.
    ///
    /// The wrapped error covers the full transport-failure surface:
    /// DNS, connection refused, TLS handshake, idle timeout, body
    /// decode, etc. Distinguishing those further is the responsibility
    /// of the caller via [`DiscoveryError::is_retriable`].
    #[error("HTTP transport error: {0}")]
    HttpTransport(#[from] reqwest::Error),
    /// The HTTP response was structurally well-formed but carried a
    /// non-success status code.
    ///
    /// 4xx classes (authentication / invalid invite / mismatched
    /// session) are not retriable; 5xx classes are.
    #[error("HTTP {status}: {body}")]
    HttpStatus {
        /// HTTP status code returned by the coordinator.
        status: u16,
        /// Truncated body of the rejecting response, captured for
        /// human-readable diagnostics.
        body: String,
    },
    /// `serde_json` failed to encode a request body or decode a
    /// response body.
    ///
    /// HTTP-mode bodies are JSON; this variant is raised by the HTTP
    /// client only.
    #[error("JSON codec error: {0}")]
    Json(#[from] serde_json::Error),
    /// `url::Url::join` failed to combine the coordinator base URL
    /// with the per-call path suffix, or the constructor was handed a
    /// URL that cannot serve as a base.
    #[error("URL error: {0}")]
    Url(String),
}

impl DiscoveryError {
    /// Return `true` if the failure looks retriable to a higher layer.
    ///
    /// The contract is round-robin failover in F-DISC.3: retry only
    /// when another coordinator might return a different result.
    /// Transport-level failures (timeouts, refused connections, DNS,
    /// TLS) and 5xx responses are retriable; 4xx and codec failures
    /// are not.
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::HttpTransport(err) => is_transport_retriable(err),
            Self::HttpStatus { status, .. } => *status >= 500,
            Self::Json(_) | Self::Url(_) => false,
        }
    }
}

/// Classify a [`reqwest::Error`] as retriable.
///
/// Connection / timeout / request-send errors are retriable. A response
/// that successfully arrived but failed to decode is not — another
/// coordinator would round-trip the same broken bytes.
fn is_transport_retriable(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_5xx_is_retriable() {
        let err = DiscoveryError::HttpStatus {
            status: 503,
            body: "service unavailable".to_string(),
        };
        assert!(err.is_retriable());
    }

    #[test]
    fn http_status_4xx_is_not_retriable() {
        let err = DiscoveryError::HttpStatus {
            status: 401,
            body: "unauthorized".to_string(),
        };
        assert!(!err.is_retriable());
    }

    #[test]
    fn json_is_not_retriable() {
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("not json").expect_err("must error");
        let err = DiscoveryError::Json(serde_err);
        assert!(!err.is_retriable());
    }

    #[test]
    fn url_is_not_retriable() {
        let err = DiscoveryError::Url("bad base".to_string());
        assert!(!err.is_retriable());
    }
}
