#![forbid(unsafe_code)]
//! `/healthz` + `/readyz` wiring (F-COORD.11).
//!
//! F-COORD.1 already mounted the underlying
//! [`bibeam_runtime::health_router`] inside
//! [`super::server::build_router`]. This module owns the
//! coordinator-specific *bring-up sequence* that decides when the
//! latch flips to ready:
//!
//! 1. The peer registry (F-COORD.2) opens cleanly.
//! 2. The cohort store (F-COORD.3) opens cleanly.
//! 3. The axum listener has bound its socket.
//!
//! [`flip_ready_when_bound`] is the single helper a daemon's main
//! calls to flip the [`bibeam_runtime::ReadyLatch`] once all three
//! preconditions have been satisfied. The function returns
//! [`ReadyError`] when any precondition is missing — the caller
//! decides whether to fail-soft (log + continue serving 503s) or
//! to exit, since the right policy depends on the operator
//! runbook.
//!
//! ## Why a separate module
//!
//! The bring-up sequence is the kind of code that grows as new
//! resources land (e.g. the F-COORD.7 redemption ledger, the
//! F-COORD.8 audit log, the F-COORD.12 leader lease). Keeping the
//! "what counts as ready" decision in one place means a future
//! sub-item only needs to extend [`BringUp`] rather than chasing
//! latch flips across the codebase.

use std::sync::Arc;

use bibeam_runtime::ReadyLatch;
use thiserror::Error;

use super::cohorts::CohortStore;
use super::registry::PeerRegistry;

/// Pre-condition bundle for [`flip_ready_when_bound`].
///
/// Each field is the live handle to a resource the coordinator
/// daemon must have brought up before readiness is asserted.
/// Extra resources (audit log, redemption ledger, leader lease)
/// land here as later sub-items wire them in.
#[derive(Clone)]
pub struct BringUp {
    /// Live peer registry (F-COORD.2).
    pub registry: Arc<PeerRegistry>,
    /// Live cohort store (F-COORD.3).
    pub cohorts: Arc<CohortStore>,
    /// True iff the axum listener has bound its socket. The
    /// daemon's main flips this to `true` *after* the
    /// `axum_server::Server::serve` (or `bind_with_listener`)
    /// call has returned successfully.
    pub listener_bound: bool,
}

impl core::fmt::Debug for BringUp {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BringUp")
            .field("listener_bound", &self.listener_bound)
            .finish_non_exhaustive()
    }
}

/// Failure modes for [`flip_ready_when_bound`].
#[derive(Debug, Error)]
pub enum ReadyError {
    /// The axum listener has not yet bound its socket.
    #[error("readyz: axum listener has not bound a socket")]
    ListenerNotBound,
}

/// Flip `latch` to ready if every resource in `bring_up` is
/// available; otherwise return [`ReadyError`] without touching the
/// latch.
///
/// The function does not retry — the caller drives the bring-up
/// sequence and calls this once the resources are live. Listeners
/// that bind asynchronously should call this from the spawn site
/// that learned about the `Local socket address` event.
///
/// # Errors
///
/// Returns [`ReadyError::ListenerNotBound`] when
/// `bring_up.listener_bound` is `false`. The registry + cohort
/// store cannot be "half-open" — their constructors return `Err`
/// at open time, so a missing handle is a build-time error rather
/// than a runtime ready-error.
pub fn flip_ready_when_bound(latch: &ReadyLatch, bring_up: &BringUp) -> Result<(), ReadyError> {
    if !bring_up.listener_bound {
        return Err(ReadyError::ListenerNotBound);
    }
    // The registry + cohort store cannot be present-but-broken:
    // `PeerRegistry::open` and `CohortStore::open` return `Err`
    // if the underlying redb file fails to initialise, and they
    // run inside a write transaction that touches the table. By
    // the time the caller hands us live `Arc` handles inside
    // `bring_up`, both resources are known good. The latch flip
    // therefore only depends on the listener-bound bit.
    latch.set_ready();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn fixture_bring_up(listener_bound: bool) -> BringUp {
        let registry_temp = tempfile::NamedTempFile::new().expect("registry tempfile");
        let cohorts_temp = tempfile::NamedTempFile::new().expect("cohort tempfile");
        let registry = Arc::new(PeerRegistry::open(registry_temp.path()).expect("open registry"));
        let cohorts = Arc::new(CohortStore::open(cohorts_temp.path()).expect("open cohorts"));
        // Tempfiles drop here; redb opens its mmap inside `open`
        // and keeps the file handle alive through the Database
        // value's Drop, which lives as long as the Arc<Database>.
        // Closing the tempfile guard does not unlink the file
        // because we passed `path()` (not the named handle), so
        // the redb file persists until `registry` / `cohorts`
        // drop.
        BringUp {
            registry,
            cohorts,
            listener_bound,
        }
    }

    #[test]
    fn flip_ready_succeeds_when_listener_is_bound() {
        // Contract: every pre-condition met → the latch flips
        // ready and the function returns Ok.
        let latch = ReadyLatch::new();
        let bring_up = fixture_bring_up(true);
        flip_ready_when_bound(&latch, &bring_up).expect("flip");
        assert!(latch.is_ready());
    }

    #[test]
    fn flip_ready_returns_error_when_listener_unbound() {
        // Contract: pre-condition violated → the latch stays
        // not-ready and the function returns ListenerNotBound.
        // Catches a regression that flipped the latch even when
        // the listener had not yet bound (which would let the
        // orchestrator route traffic onto a daemon that cannot
        // accept connections).
        let latch = ReadyLatch::new();
        let bring_up = fixture_bring_up(false);
        let err =
            flip_ready_when_bound(&latch, &bring_up).expect_err("must reject unbound listener");
        assert!(matches!(err, ReadyError::ListenerNotBound));
        assert!(!latch.is_ready());
    }
}
