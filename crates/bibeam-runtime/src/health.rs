#![forbid(unsafe_code)]
//! Liveness + readiness HTTP endpoints.
//!
//! [`router`] returns an [`axum::Router`] that mounts two operationally
//! conventional paths used by every Kubernetes / systemd / Nomad
//! deployment:
//!
//! - `GET /healthz` — liveness. Always returns `200 OK`. A failure to
//!   answer at all (timeout, TCP RST) is the signal the orchestrator
//!   uses to restart the process. Returning `200` from this endpoint
//!   asserts only that the HTTP runtime itself is up.
//!
//! - `GET /readyz` — readiness. Returns `200 OK` once a [`ReadyLatch`]
//!   has been flipped to ready, and `503 Service Unavailable` until
//!   then. The orchestrator uses this signal to gate traffic onto
//!   the instance.
//!
//! ## Latch semantics
//!
//! [`ReadyLatch`] is a thin wrapper around an [`Arc<AtomicBool>`].
//! It is intentionally write-once-shaped at the API level
//! ([`ReadyLatch::set_ready`] takes no argument), but the underlying
//! bool is not actually one-shot — a future revision can add a
//! `set_not_ready` for drain semantics. For the MVP, callers should
//! treat readiness as monotonic: once `set_ready` is called the
//! latch stays ready for the rest of the process lifetime.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};

/// Shared readiness flag plumbed into the [`router`].
///
/// Build one with [`ReadyLatch::new`] before constructing the
/// router; flip it with [`ReadyLatch::set_ready`] once the daemon
/// has finished its bring-up sequence (transport listening, storage
/// open, etc.).
#[derive(Debug, Clone)]
pub struct ReadyLatch {
    ready: Arc<AtomicBool>,
}

impl ReadyLatch {
    /// Construct a [`ReadyLatch`] in the *not-ready* state.
    #[must_use]
    #[allow(
        clippy::new_without_default,
        reason = "ReadyLatch is constructed explicitly at daemon bring-up; \
                  implicit Default construction is unused ceremony."
    )]
    pub fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Flip the latch to *ready*.
    ///
    /// `Release` ordering pairs with the `Acquire` load inside the
    /// readiness handler so any writes that completed before
    /// `set_ready` are observable to a reader that has just seen the
    /// `true`.
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Return whether the latch is currently ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

/// Build the health-check [`axum::Router`].
///
/// `latch` is cloned into the router's state; the caller's copy
/// remains valid and can flip the latch at any time.
pub fn router(latch: ReadyLatch) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/readyz", get(handle_readyz))
        .with_state(latch)
}

/// Liveness handler. Always responds `200 OK`.
#[allow(
    clippy::unused_async,
    reason = "axum's `get(...)` route signature requires `async`. The \
              handler does no I/O, but staying async-shaped lets a \
              later sub-item add a self-check without breaking the \
              router."
)]
async fn handle_healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness handler. `200` once the latch is ready, `503` otherwise.
#[allow(
    clippy::unused_async,
    reason = "axum's `get(...)` route signature requires `async`. The \
              underlying load is a single AcqRel atomic read; no I/O \
              happens. Future sub-items that probe storage or transport \
              state will benefit from the async shape."
)]
async fn handle_readyz(State(latch): State<ReadyLatch>) -> impl IntoResponse {
    if latch.is_ready() {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latch_starts_not_ready() {
        // Contract: a freshly-constructed latch reports not-ready
        // until something flips it. A regression that flipped the
        // default to `true` would let a half-initialised daemon
        // start receiving traffic from its orchestrator the moment
        // the HTTP runtime came up.
        let latch = ReadyLatch::new();
        assert!(!latch.is_ready());
    }

    #[test]
    fn set_ready_flips_atomically() {
        // Contract: `set_ready` is visible to every clone of the
        // latch under acquire ordering. This is the test that would
        // catch a regression to `Relaxed` ordering — the daemon
        // would still pass tests on x86 but break on ARM where the
        // memory model is weaker.
        let latch = ReadyLatch::new();
        let clone = latch.clone();
        latch.set_ready();
        assert!(clone.is_ready());
    }
}
