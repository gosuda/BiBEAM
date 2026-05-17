#![forbid(unsafe_code)]
//! Async helper that resolves on the first OS shutdown signal.
//!
//! [`shutdown_signal`] is the canonical way for a `BiBeam` daemon's
//! main task to wait for an external stop. The future resolves
//! when:
//!
//! - **Unix:** either `SIGINT` (operator pressed Ctrl-C in a
//!   foreground session) or `SIGTERM` (init system or container
//!   runtime asked for a graceful stop) is delivered. The plan
//!   intentionally excludes `SIGHUP` for the MVP — config reload is
//!   not in scope and a stray `SIGHUP` from a parent shell exit
//!   should not bring a server down.
//!
//! - **Non-Unix (Windows, WASI, etc.):** Tokio's
//!   [`tokio::signal::ctrl_c`] handler. We fall back to it on every
//!   platform that does not implement `signal::unix`, so the
//!   function compiles and behaves sanely on the developer's
//!   machine even if the platform's signal model differs.
//!
//! ## Cancel safety
//!
//! The returned future is cancel-safe: dropping it before resolution
//! deregisters the underlying signal handler. Callers can race it
//! against another future via [`tokio::select!`] without leaking
//! handler state.

/// Wait for the first OS-delivered shutdown signal.
///
/// See the module docs for the per-platform signal set. The future
/// resolves with `()` when any monitored signal is received; it does
/// not surface errors because there is no useful caller recovery —
/// signal handler installation failures are panics inside Tokio's
/// implementation and pre-Tokio failures (e.g. missing
/// `tokio::signal` feature) are compile-time errors.
#[allow(
    clippy::cognitive_complexity,
    reason = "Expansion of `tokio::select!` on two `signal()?.recv()` \
              futures plus the `match` to resurface install errors as \
              warnings inflates the cognitive score; the body's own \
              logic is two branches that resolve identically."
)]
#[cfg(unix)]
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let install_int = signal(SignalKind::interrupt());
    let install_term = signal(SignalKind::terminate());

    match (install_int, install_term) {
        (Ok(mut sigint), Ok(mut sigterm)) => {
            tokio::select! {
                _ = sigint.recv() => {},
                _ = sigterm.recv() => {},
            }
        },
        (Err(err), _) | (_, Err(err)) => {
            // Signal handler installation failed (e.g. seccomp
            // sandbox forbids `sigaction`). Fall back to ctrl-c so
            // the process can still terminate gracefully on a
            // foreground shell.
            tracing::warn!(
                error = %err,
                "failed to install SIGINT/SIGTERM handler; falling back to ctrl_c",
            );
            // `ctrl_c().await` returns `Result<(), io::Error>`; if
            // it too fails the daemon will just keep running and
            // operators will have to send SIGKILL. We deliberately
            // do not panic here — a missing signal facility is not
            // grounds to crash a running server.
            if let Err(ctrlc_err) = tokio::signal::ctrl_c().await {
                tracing::warn!(error = %ctrlc_err, "ctrl_c handler failed");
            }
        },
    }
}

/// Non-Unix shutdown-signal stub: waits for `ctrl_c`.
///
/// See the module docs.
#[cfg(not(unix))]
pub async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::warn!(error = %err, "ctrl_c handler failed; sleeping forever");
        // If even ctrl_c is unavailable, park the task. The runtime
        // will outlive the future until the orchestrator kills the
        // process; this is the same semantics as a process that
        // ignores the signal entirely.
        core::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_signal_is_pending_until_signalled() {
        // Contract: the future does not resolve spontaneously. A
        // regression that wired in an always-ready future (e.g. a
        // stale `pending` replaced with `ready(())`) would let every
        // daemon exit immediately on startup. We give the runtime a
        // small window to drive the future and assert it has not
        // resolved.
        let signal = shutdown_signal();
        let timeout = tokio::time::timeout(core::time::Duration::from_millis(50), signal).await;
        assert!(timeout.is_err(), "shutdown_signal resolved before a signal arrived");
    }
}
