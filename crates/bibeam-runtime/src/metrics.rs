#![forbid(unsafe_code)]
//! Prometheus `/metrics` endpoint mounted on an [`axum::Router`].
//!
//! [`router`] installs a global recorder via
//! [`metrics_exporter_prometheus::PrometheusBuilder::install_recorder`]
//! and returns a router that serves the rendered exposition format at
//! `GET /metrics`. The returned router is `Router<()>` — it carries
//! its state (the [`PrometheusHandle`]) closed-over in the handler
//! and is ready to be merged into any larger service.
//!
//! ## Installation is global
//!
//! The recorder install affects the process: a second call to
//! [`router`] (or to any other caller that installs a metrics
//! recorder) will fail. Callers SHOULD construct exactly one router
//! during `main` and clone it into whatever serve fabric they use.
//!
//! ## Render contract
//!
//! `GET /metrics` returns `200 OK` with the text body produced by
//! [`PrometheusHandle::render`]. The body is `text/plain;
//! version=0.0.4` per the Prometheus exposition spec; we use
//! `text/plain; charset=utf-8` which is what the upstream exporter
//! examples use and what every Prometheus scraper tolerates.

use std::sync::Arc;

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use thiserror::Error;

/// Failure modes when constructing the metrics router.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// The Prometheus recorder could not be installed — typically
    /// because another recorder is already global to this process.
    #[error("failed to install Prometheus recorder: {0}")]
    Install(#[from] BuildError),
}

/// Build an [`axum::Router`] that serves Prometheus exposition on
/// `GET /metrics`.
///
/// # Errors
///
/// Returns [`MetricsError::Install`] when
/// [`PrometheusBuilder::install_recorder`] rejects — typically
/// because a `metrics` global recorder is already installed.
pub fn router() -> Result<Router, MetricsError> {
    let handle = PrometheusBuilder::new().install_recorder()?;
    let state = Arc::new(handle);
    let router = Router::new().route("/metrics", get(render_metrics)).with_state(state);
    Ok(router)
}

/// Axum handler that renders the current Prometheus snapshot.
#[allow(
    clippy::unused_async,
    reason = "axum's `get(...)` route handler signature requires `async`; \
              `PrometheusHandle::render` is synchronous and never yields."
)]
async fn render_metrics(State(handle): State<Arc<PrometheusHandle>>) -> impl IntoResponse {
    let body = handle.render();
    (StatusCode::OK, [("content-type", "text/plain; charset=utf-8")], body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_install_failure_surfaces_as_install_variant() {
        // Lock in the contract that double-install of the recorder
        // surfaces as `MetricsError::Install`, not as a panic. Without
        // this assertion a regression that switched `install_recorder`
        // to `install` (which panics on conflict) would only show up
        // at deploy time. We tolerate either ordering of the two
        // calls succeeding — exactly one of them must.
        let first = router();
        let second = router();
        // At least one call must fail (the second install conflicts
        // with the first), and the failure must be the typed variant.
        let failure = match (first.is_ok(), second.is_ok()) {
            (true, false) => second,
            (false, _) => first,
            (true, true) => {
                panic!("both installs succeeded — recorder install is supposed to be global");
            },
        };
        assert!(matches!(failure, Err(MetricsError::Install(_))));
    }
}
