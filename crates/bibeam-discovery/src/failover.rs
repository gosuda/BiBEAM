#![forbid(unsafe_code)]
//! Round-robin coordinator failover (F-DISC.3).
//!
//! [`CoordinatorPool`] holds one or more [`crate::http::CoordinatorClient`]
//! instances and tries an operation against each in round-robin order
//! until one succeeds. The retry policy is the contract
//! [`crate::error::DiscoveryError::is_retriable`] codifies:
//!
//! - **Retry** transport errors (DNS, refused, timeout, TLS handshake)
//!   and 5xx responses — another coordinator may give a different
//!   answer.
//! - **Do not retry** 4xx responses (authentication / invalid invite),
//!   codec errors, URL errors. The next coordinator would reject the
//!   same request the same way.
//!
//! Round-robin order is per-pool and advances exactly once per
//! [`CoordinatorPool::try_each`] call: a successful operation against
//! coordinator N leaves the next call starting at coordinator N+1, so
//! load distributes across the cluster instead of hammering whichever
//! coordinator was first in the configured list.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::DiscoveryError;
use crate::http::CoordinatorClient;

/// A non-empty pool of coordinator clients participating in
/// round-robin failover.
///
/// Cheap to clone — internally backed by `Arc`-shared state. The
/// rotation cursor is shared across clones, so multiple consumers
/// hitting the same pool concurrently still rotate through
/// coordinators rather than each starting from index 0.
#[derive(Clone)]
pub struct CoordinatorPool {
    /// Coordinators in configured order. Wrapped in `Arc` so the
    /// closure passed to [`Self::try_each`] can clone one entry into
    /// its own captured state cheaply.
    coordinators: Arc<[Arc<CoordinatorClient>]>,
    /// Monotonic rotation cursor; modulo `coordinators.len()` gives
    /// the index to start the next `try_each` call at.
    cursor: Arc<AtomicUsize>,
}

impl core::fmt::Debug for CoordinatorPool {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Custom Debug because the inner `Arc<[Arc<CoordinatorClient>]>`
        // hands every client to the underlying `<Arc as Debug>` impl,
        // which dumps the full reqwest config tree — too noisy for logs
        // and not actionable. The cursor's current value is
        // implementation detail.
        formatter
            .debug_struct("CoordinatorPool")
            .field("coordinator_count", &self.coordinators.len())
            .field("cursor", &self.cursor.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl CoordinatorPool {
    /// Build a pool from one or more coordinator clients.
    ///
    /// The configured order is preserved; the rotation cursor starts
    /// at index 0 (the first coordinator). Subsequent
    /// [`Self::try_each`] calls advance the cursor by one regardless
    /// of which coordinator answered.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Url`] with an "empty pool" message
    /// if `clients` is empty — a pool must hold at least one
    /// coordinator for the failover semantics to make sense.
    pub fn new(clients: Vec<CoordinatorClient>) -> Result<Self, DiscoveryError> {
        if clients.is_empty() {
            return Err(DiscoveryError::Url(
                "coordinator pool must hold at least one client".into(),
            ));
        }
        let coordinators: Arc<[Arc<CoordinatorClient>]> =
            clients.into_iter().map(Arc::new).collect();
        Ok(Self {
            coordinators,
            cursor: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Number of coordinators in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.coordinators.len()
    }

    /// Whether the pool is empty. Always `false` because
    /// [`Self::new`] rejects empty inputs; surfaced for parity with
    /// other "slice-shaped" types and for `clippy::len_without_is_empty`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Try `operation` against each coordinator in round-robin order
    /// until one succeeds.
    ///
    /// Behaviour:
    ///
    /// - Iterates the pool starting at the current rotation cursor
    ///   and wraps around at the end. Each [`Self::try_each`] call
    ///   advances the cursor by one before the iteration starts, so
    ///   successive calls naturally distribute load.
    /// - On `Ok(_)`, returns immediately.
    /// - On retriable `Err(_)` (see
    ///   [`DiscoveryError::is_retriable`]), continues to the next
    ///   coordinator and remembers the last error seen.
    /// - On non-retriable `Err(_)`, returns it immediately — the
    ///   next coordinator would reject the same request the same way.
    /// - If every coordinator returned a retriable error, returns
    ///   the most recent one (the "all coordinators down" case).
    ///
    /// The closure is `FnMut` so callers can stash state across
    /// per-coordinator invocations (e.g. log the addresses tried).
    pub async fn try_each<Operation, Future, Output>(
        &self,
        mut operation: Operation,
    ) -> Result<Output, DiscoveryError>
    where
        Operation: FnMut(Arc<CoordinatorClient>) -> Future,
        Future: std::future::Future<Output = Result<Output, DiscoveryError>>,
    {
        let pool_len = self.coordinators.len();
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % pool_len;
        let mut last_error: Option<DiscoveryError> = None;
        for offset in 0..pool_len {
            let index = (start + offset) % pool_len;
            let client = Arc::clone(&self.coordinators[index]);
            match operation(client).await {
                Ok(value) => return Ok(value),
                Err(err) if err.is_retriable() => {
                    tracing::warn!(
                        index,
                        error = %err,
                        "coordinator transport error, trying next",
                    );
                    last_error = Some(err);
                },
                Err(err) => return Err(err),
            }
        }
        // Invariant: `pool_len >= 1` (enforced by `new`), so the loop
        // body executed at least once; either we returned from it or
        // we stashed an error each iteration. The fallback branch is
        // unreachable in practice but kept as a typed `Err` rather than
        // a clippy-flagged `unreachable!()`.
        Err(last_error.unwrap_or_else(|| {
            DiscoveryError::Url("coordinator pool exhausted with no error captured".into())
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use url::Url;

    use super::*;

    fn ensure_crypto_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
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

    fn make_client(host: &str) -> CoordinatorClient {
        let base = Url::parse(&format!("https://{host}/")).expect("parse base");
        CoordinatorClient::new(base, empty_tls_config()).expect("build client")
    }

    #[test]
    fn new_rejects_empty_pool() {
        let err = CoordinatorPool::new(Vec::new()).expect_err("must reject");
        assert!(matches!(err, DiscoveryError::Url(message) if message.contains("empty")
            || message.contains("at least one")));
    }

    #[test]
    fn new_accepts_non_empty_pool() {
        let pool = CoordinatorPool::new(vec![make_client("a.example.com")]).expect("build pool");
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
    }

    /// Helper: bump `calls` by one and return a constant `Ok` value
    /// wrapped in a ready future. Pulled out of the test body so the
    /// closure passed to `try_each` stays one level shallower — the
    /// test body is then under clippy's `excessive_nesting` threshold
    /// (= 4). The helpers are pure synchronous operations; wrapping
    /// in `core::future::ready` avoids `clippy::unused_async`.
    fn count_then_ok(calls: &Arc<AtomicUsize>) -> core::future::Ready<Result<u32, DiscoveryError>> {
        calls.fetch_add(1, Ordering::SeqCst);
        core::future::ready(Ok(42))
    }

    /// Two retriable errors then success — kept free so the test body
    /// shows only the operation name, not the per-attempt branching.
    fn retriable_then_ok(
        calls: &Arc<AtomicUsize>,
    ) -> core::future::Ready<Result<u32, DiscoveryError>> {
        let attempt = calls.fetch_add(1, Ordering::SeqCst);
        let outcome = if attempt < 2 {
            Err(DiscoveryError::HttpStatus {
                status: 503,
                body: "down".to_string(),
            })
        } else {
            Ok(7)
        };
        core::future::ready(outcome)
    }

    /// Always errors with a fixed-status non-retriable rejection.
    fn always_401(calls: &Arc<AtomicUsize>) -> core::future::Ready<Result<u32, DiscoveryError>> {
        calls.fetch_add(1, Ordering::SeqCst);
        core::future::ready(Err(DiscoveryError::HttpStatus {
            status: 401,
            body: "no".to_string(),
        }))
    }

    /// Each invocation returns 500 + attempt-index as a retriable
    /// error. Kept free so the test body stays shallow. Arithmetic is
    /// the original `500 + try_from(attempt).unwrap_or(0)` form so
    /// regression behaviour matches the prior commit.
    fn escalating_5xx(
        calls: &Arc<AtomicUsize>,
    ) -> core::future::Ready<Result<u32, DiscoveryError>> {
        let attempt = calls.fetch_add(1, Ordering::SeqCst);
        let status = 500 + u16::try_from(attempt).unwrap_or(0);
        core::future::ready(Err(DiscoveryError::HttpStatus {
            status,
            body: "all down".to_string(),
        }))
    }

    fn record_base_url(
        client: &Arc<CoordinatorClient>,
        observed: &Arc<parking_lot::Mutex<Vec<String>>>,
    ) -> core::future::Ready<Result<(), DiscoveryError>> {
        observed.lock().push(client.base_url().to_string());
        core::future::ready(Ok(()))
    }

    #[tokio::test]
    async fn try_each_returns_first_success() {
        let pool =
            CoordinatorPool::new(vec![make_client("a.example.com"), make_client("b.example.com")])
                .expect("build");
        let calls = Arc::new(AtomicUsize::new(0));
        let result: Result<u32, DiscoveryError> =
            pool.try_each(|_client| count_then_ok(&calls)).await;
        assert_eq!(result.expect("ok"), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "succeeds on first try");
    }

    #[tokio::test]
    async fn try_each_retries_after_retriable_error() {
        let pool = CoordinatorPool::new(vec![
            make_client("a.example.com"),
            make_client("b.example.com"),
            make_client("c.example.com"),
        ])
        .expect("build");
        let calls = Arc::new(AtomicUsize::new(0));
        let result: Result<u32, DiscoveryError> =
            pool.try_each(|_client| retriable_then_ok(&calls)).await;
        assert_eq!(result.expect("eventually ok"), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 3, "two retries before success");
    }

    #[tokio::test]
    async fn try_each_short_circuits_on_non_retriable_error() {
        let pool = CoordinatorPool::new(vec![
            make_client("a.example.com"),
            make_client("b.example.com"),
            make_client("c.example.com"),
        ])
        .expect("build");
        let calls = Arc::new(AtomicUsize::new(0));
        let result: Result<u32, DiscoveryError> = pool.try_each(|_client| always_401(&calls)).await;
        let err = result.expect_err("must error");
        assert!(matches!(err, DiscoveryError::HttpStatus { status: 401, .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "4xx must short-circuit");
    }

    #[tokio::test]
    async fn try_each_returns_last_retriable_error_when_all_fail() {
        let pool =
            CoordinatorPool::new(vec![make_client("a.example.com"), make_client("b.example.com")])
                .expect("build");
        let calls = Arc::new(AtomicUsize::new(0));
        let result: Result<u32, DiscoveryError> =
            pool.try_each(|_client| escalating_5xx(&calls)).await;
        let err = result.expect_err("must error");
        // Last attempt was the second one (offset 1, status 501).
        assert!(
            matches!(err, DiscoveryError::HttpStatus { status, .. } if status == 501),
            "expected last retriable error, got {err:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "tried every coordinator");
    }

    #[tokio::test]
    async fn try_each_advances_rotation_cursor() {
        let pool = CoordinatorPool::new(vec![
            make_client("a.example.com"),
            make_client("b.example.com"),
            make_client("c.example.com"),
        ])
        .expect("build");
        // Record the base URL of the first client tried on each call.
        let observed: Arc<parking_lot::Mutex<Vec<String>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        for _ in 0_u32..3 {
            let _ignored: Result<(), DiscoveryError> =
                pool.try_each(|client| record_base_url(&client, &observed)).await;
        }
        let observed_final = observed.lock().clone();
        // Three calls, each succeeding on its first attempt, must
        // start at three distinct coordinators in round-robin order.
        let unique: std::collections::HashSet<_> = observed_final.iter().collect();
        assert_eq!(
            unique.len(),
            3,
            "rotation cursor must visit every coordinator: {observed_final:?}",
        );
    }
}
