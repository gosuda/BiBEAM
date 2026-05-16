#![forbid(unsafe_code)]
//! JSON structured logging bootstrap.
//!
//! [`init_json_logging`] installs a global [`tracing_subscriber::Registry`]
//! with a single [`mod@tracing_subscriber::fmt`] layer configured for
//! JSON output to standard output. Log filtering is driven entirely by
//! the `RUST_LOG` environment variable through [`EnvFilter`]; when the
//! variable is unset or invalid the bootstrap falls back to `info` so a
//! freshly-deployed binary still produces operationally useful output.
//!
//! ## Idempotence
//!
//! The function should be called exactly once per process — usually from
//! `main` before any other [`tracing`] machinery is touched. A second
//! call returns [`LogInitError::AlreadySet`] because
//! [`tracing::subscriber::set_global_default`] is one-shot.
//!
//! ## Output shape
//!
//! Each log line is a single JSON object on its own line, which is the
//! shape consumed by every log aggregator in scope for this project
//! (Loki, Vector, fluent-bit). The wire format intentionally avoids
//! pretty-printing so a downstream pipeline can split on `\n` without
//! tracking brace depth.

use thiserror::Error;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _};

/// Default tracing filter used when `RUST_LOG` is absent or unparsable.
///
/// `info` is the right floor for a daemon: `debug` would be too chatty
/// for steady-state operation, while `warn` would hide the lifecycle
/// breadcrumbs (startup, shutdown, peer admit) operators rely on.
const DEFAULT_FILTER: &str = "info";

/// Failure modes for [`init_json_logging`].
#[derive(Debug, Error)]
pub enum LogInitError {
    /// A global subscriber was already installed in this process.
    ///
    /// Surfaced when the function is called more than once or after some
    /// other code path has already set a `tracing` global default.
    #[error("a global tracing subscriber is already installed")]
    AlreadySet,
}

/// Install a JSON-formatted [`tracing`] subscriber as the global default.
///
/// The subscriber writes to standard output and obeys the `RUST_LOG`
/// environment variable; the fallback filter is `"info"`.
///
/// # Errors
///
/// Returns [`LogInitError::AlreadySet`] when a global subscriber is
/// already installed in the process. The function is intentionally
/// one-shot — callers should invoke it once during early `main`
/// initialisation and never again.
pub fn init_json_logging() -> Result<(), LogInitError> {
    // `try_from_default_env` returns `Err` for both missing-var and
    // parse-failure cases; we recover with the same fallback in either
    // case so a typo in `RUST_LOG` does not silently disable logging.
    // `unwrap_or_else` is OK here under the restriction lints —
    // `clippy::unwrap_used` only fires on `Option::unwrap` /
    // `Result::unwrap`, never on `unwrap_or_else` which has no panic
    // path.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));

    let json_layer = fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(std::io::stdout);

    tracing_subscriber::registry()
        .with(filter)
        .with(json_layer)
        .try_init()
        .map_err(|_| LogInitError::AlreadySet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_init_returns_already_set() {
        // First call may succeed or fail depending on test-runner order
        // (nextest's per-test sandbox usually gives us a fresh process,
        // but cargo test reuses one). Either way the *second* call must
        // surface `AlreadySet` so callers can detect double-init bugs.
        let _first = init_json_logging();
        let second = init_json_logging();
        assert!(matches!(second, Err(LogInitError::AlreadySet)));
    }
}
