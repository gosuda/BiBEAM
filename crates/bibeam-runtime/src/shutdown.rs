#![forbid(unsafe_code)]
//! Graceful-shutdown coordination via [`CancellationToken`].
//!
//! [`Shutdown`] owns a single [`CancellationToken`] that every
//! spawned task in the process holds a clone of, plus a bounded
//! deadline for the drain phase.
//!
//! The intended usage shape:
//!
//! ```ignore
//! let shutdown = Shutdown::new(std::time::Duration::from_secs(15));
//! let token = shutdown.token();
//!
//! // every spawned task receives a clone of `token` and selects
//! // against it to know when to stop.
//! tokio::spawn(async move {
//!     tokio::select! {
//!         _ = token.cancelled() => { /* drain and exit */ }
//!         _ = work() => {}
//!     }
//! });
//!
//! // main task waits for the OS signal, then triggers shutdown
//! // and waits up to the deadline before forcing exit.
//! bibeam_runtime::shutdown_signal().await;
//! shutdown.trigger_and_wait().await;
//! ```
//!
//! ## Deadline semantics
//!
//! [`Shutdown::trigger_and_wait`] flips the token and then sleeps
//! the deadline before returning. It does **not** poll for task
//! completion — the canonical Tokio pattern for waiting on every
//! spawned task is a [`tokio_util::task::TaskTracker`], which lives
//! outside the scope of this primitive. The deadline here is a
//! ceiling: callers that want a faster exit on the happy path
//! should compose the deadline with a tracker on their side.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Graceful shutdown coordinator.
///
/// Cheap to construct (one [`CancellationToken`] allocation, one
/// [`Duration`] copy). Hand out clones of the inner token via
/// [`Shutdown::token`] to every task that needs to learn about
/// stop; consume the [`Shutdown`] itself on the main task via
/// [`Shutdown::trigger_and_wait`] once the OS signal arrives.
///
/// Intentionally not `Clone`: the lifecycle contract is one
/// [`Shutdown`] per process, owned by the daemon's main task. Every
/// other task observes shutdown via a [`CancellationToken`] clone
/// handed out by [`Shutdown::token`]. A `Clone` impl would let two
/// owners race on [`Shutdown::trigger_and_wait`] (or worse, double-
/// drain the deadline) which is a real footgun.
#[derive(Debug)]
pub struct Shutdown {
    token: CancellationToken,
    deadline: Duration,
}

impl Shutdown {
    /// Construct a new [`Shutdown`] with the given drain `deadline`.
    ///
    /// The deadline is the upper bound on how long
    /// [`Shutdown::trigger_and_wait`] sleeps after flipping the
    /// token. Callers should pick a value that gives every
    /// outstanding task room to drain its in-flight work — the
    /// operator runbook for this codebase recommends 15 seconds for
    /// the server binaries.
    #[must_use]
    pub fn new(deadline: Duration) -> Self {
        Self {
            token: CancellationToken::new(),
            deadline,
        }
    }

    /// Clone of the inner [`CancellationToken`] for hand-out to
    /// spawned tasks.
    #[must_use]
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Flip the token and sleep the drain deadline.
    ///
    /// Consumes `self` so the [`Shutdown`] cannot be triggered
    /// twice: a daemon's main task calls this once at the end of
    /// its lifecycle. After this future resolves, callers should
    /// return from `main` so the process exits.
    pub async fn trigger_and_wait(self) {
        self.token.cancel();
        tokio::time::sleep(self.deadline).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn trigger_cancels_token_before_deadline_elapses() {
        // Contract: the token is cancelled at the *start* of
        // `trigger_and_wait`, not after the deadline. A task that
        // selects on `token.cancelled()` must therefore resolve
        // while `trigger_and_wait` is still sleeping. This is the
        // test that catches the inverse regression — sleep first,
        // cancel later — which would silently waste the entire
        // drain budget.
        //
        // `start_paused` gives us deterministic virtual time so
        // the test does not depend on wall-clock CI behaviour.
        let shutdown = Shutdown::new(Duration::from_secs(10));
        let token = shutdown.token();

        let observer = tokio::spawn(async move {
            token.cancelled().await;
        });

        let trigger = tokio::spawn(async move {
            shutdown.trigger_and_wait().await;
        });

        // Yield once to let both tasks reach their await points.
        tokio::task::yield_now().await;

        // Observer must be done — the cancel happens before the
        // sleep, so it resolves on the first poll.
        observer.await.expect("observer task panicked");

        // Trigger must still be pending — the 10-second sleep has
        // not elapsed yet (virtual time is frozen until we advance
        // it). This is the load-bearing assertion that proves the
        // sleep actually runs.
        assert!(!trigger.is_finished(), "trigger task ran past its deadline");

        // Advance virtual time past the deadline and confirm the
        // trigger task finishes.
        tokio::time::advance(Duration::from_secs(11)).await;
        trigger.await.expect("trigger task panicked");
    }

    #[test]
    fn token_clones_share_cancellation_state() {
        // Contract: every clone of the inner token observes the
        // same cancellation. A regression that built a fresh
        // CancellationToken per `token()` call would break the
        // entire graceful-shutdown contract — every task would
        // wait forever on its own private token.
        let shutdown = Shutdown::new(Duration::from_millis(1));
        let first = shutdown.token();
        let second = shutdown.token();
        first.cancel();
        assert!(second.is_cancelled());
    }
}
