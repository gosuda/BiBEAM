#![forbid(unsafe_code)]
//! Quinn server accept loop (F-NODE.2).
//!
//! [`NodeQuicServer`] wraps a [`quinn::Endpoint`] in a cancel-aware
//! accept loop. Per-connection business logic — cohort-traffic relay
//! (option (a) custom QUIC), `WireGuard`-over-QUIC datagram forward
//! (option (c) multi-hop), or any future inbound protocol — plugs in
//! via the [`AcceptHandler`] trait. The accept loop itself is
//! protocol-agnostic: it owns the lifecycle of the endpoint, the
//! per-connection task fan-out, and the cooperative shutdown handshake
//! against a [`CancellationToken`], and nothing else.
//!
//! ## Where this fits
//!
//! D-4 picked `WireGuard` wire-compat as the primary data plane
//! (option (a)), with custom `Noise_IK` over QUIC kept as an opt-in
//! alternate (option (c)). This module is the inbound surface for either
//! posture: in (c), a client (or an upstream forwarder) opens a QUIC
//! connection to this node and the [`AcceptHandler`] consumes the
//! resulting bi-directional streams plus datagrams. In (a) the same
//! loop hosts the control-channel side QUIC connection used for
//! coord-signalled session rotation events when those are mounted on
//! the node (not the per-flow WG data plane, which lives in
//! [`bibeam_transport::wg_tunnel`]).
//!
//! ## Cooperative shutdown
//!
//! [`NodeQuicServer::run`] races [`quinn::Endpoint::accept`] against
//! the supplied [`CancellationToken`] in a [`tokio::select!`]. When
//! the token fires, the loop returns `Ok(())` without waiting for
//! in-flight per-connection tasks to finish — those are detached on
//! [`tokio::spawn`] and inherit their own
//! [`CancellationToken::child_token`] so an external shutdown
//! coordinator can race them separately. The loop also exits cleanly
//! when [`quinn::Endpoint::accept`] returns [`None`], which is
//! `quinn`'s signal that the underlying endpoint has been closed
//! out-of-band.
//!
//! ## Per-connection task isolation
//!
//! One inbound `quinn::Incoming` becomes one spawned task. A
//! [`AcceptHandler::handle`] failure on that task is logged at
//! `tracing::warn!` and dropped — the accept loop continues. This is
//! load-bearing for the `accept_handler_errors_do_not_kill_loop`
//! invariant the test module locks in: a misbehaving / hostile client
//! must not be able to tear the loop down by triggering a handler
//! error.
//!
//! ## Trust boundary
//!
//! This module does NOT terminate user-application TLS, decrypt
//! `WireGuard` payloads, parse cohort-relay frames, or hold any AEAD
//! material. Cert provisioning + ECH plumbing live in
//! [`bibeam_transport::tls`] (F-TRANS.2); the
//! [`bibeam_transport::wg_tunnel`] module owns WG AEAD; cohort relay
//! semantics live in [`crate::forwarder`] / a future relay handler.
//! The accept loop's only job is "spawn a handler per inbound
//! connection".

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Default cap on in-flight per-connection tasks. The accept loop
/// acquires one [`Semaphore`] permit per spawned task and blocks on
/// acquire when saturated, applying backpressure before spawning.
pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Failure modes for [`NodeQuicServer::run`].
///
/// The accept loop itself is structured so a per-accept or
/// per-handshake failure does NOT bubble out as an error — those are
/// logged and the loop continues, mirroring
/// [`bibeam_transport::run_socks5_listener`]'s posture. The variants
/// here therefore enumerate "the loop could not continue at all":
/// today only [`QuicServerError::EndpointClosed`], which the loop
/// surfaces as the typed reason rather than `Ok(())` so the caller
/// can distinguish "operator cancelled" from "endpoint torn down by
/// something else".
#[derive(Debug, Error)]
pub enum QuicServerError {
    /// The underlying [`quinn::Endpoint`] returned [`None`] from
    /// [`quinn::Endpoint::accept`], meaning the endpoint has been
    /// closed out-of-band (e.g., the operator-supplied driver was
    /// dropped while the loop was still arming a select).
    ///
    /// The accept loop treats this as a clean exit, not a fatal — the
    /// caller can rebuild a fresh endpoint and call [`NodeQuicServer::run`]
    /// again. Carrying it as a typed reason rather than collapsing into
    /// `Ok(())` keeps the post-mortem clear in mixed
    /// shutdown-vs-failure logs.
    #[error("quic server: underlying endpoint was closed out-of-band")]
    EndpointClosed,
}

/// Failure modes for [`AcceptHandler::handle`].
///
/// Carries an opaque human-readable reason rather than enumerating
/// every possible per-handler failure: each [`AcceptHandler`]
/// implementation owns its own typed error vocabulary internally and
/// flattens it onto this trait's `Result` at the call boundary. The
/// accept loop never inspects the variant — it logs the error and
/// drops the per-connection task — so a `String` here is the right
/// level of structure.
#[derive(Debug, Error)]
pub enum HandlerError {
    /// The handler rejected the inbound connection or aborted
    /// mid-stream. The string is the handler's own reason; the accept
    /// loop logs it under the `bibeam_quic_server` tracing target and
    /// continues.
    #[error("accept handler failed: {0}")]
    Handler(String),
}

impl HandlerError {
    /// Wrap any [`Display`]-able error into [`HandlerError::Handler`].
    ///
    /// Convenience for the common pattern at the
    /// [`AcceptHandler::handle`] boundary: an implementation flattens
    /// its own typed error onto this trait's `Result` without forcing
    /// every call site to write `HandlerError::Handler(format!("…"))`.
    ///
    /// [`Display`]: core::fmt::Display
    pub fn from_display<E: core::fmt::Display>(err: E) -> Self {
        Self::Handler(err.to_string())
    }
}

/// Per-connection business-logic plugin point.
///
/// One implementation owns the bi-directional stream and datagram
/// surface of a single inbound [`quinn::Connection`]. The accept loop
/// spawns one task per accepted connection and invokes
/// [`AcceptHandler::handle`] on the supplied [`Arc<dyn AcceptHandler>`].
///
/// ## Implementations
///
/// - [`NoopAcceptHandler`] — discards every connection. Used by the
///   test module and by any wiring path that needs a "loop runs but
///   does nothing" surface (e.g., a startup smoke test before the
///   real handler is plugged in).
/// - The cohort-traffic relay handler (future commit, F-NODE.3) will
///   read sealed datagrams from `conn.read_datagram()` and forward
///   them across the cohort's other half-connection.
/// - The WG-datagram-forward handler (future commit, option (c)) will
///   pump QUIC datagrams onto a per-peer
///   [`bibeam_transport::wg_tunnel::WgTunnel`].
///
/// ## Object safety
///
/// The trait uses [`macro@async_trait`] so it stays
/// `dyn`-compatible — Rust's native async-fn-in-trait does not yet
/// support dynamic dispatch on stable. This mirrors the
/// `TunPacketSink` choice in [`crate::exit_mode`].
///
/// ## Cancellation
///
/// The accept loop does NOT cancel an in-flight handler when its own
/// [`CancellationToken`] fires — handlers receive their own token from
/// the loop (via [`CancellationToken::child_token`]) and observe it
/// themselves. This matches the
/// [`bibeam_transport::run_socks5_listener`] shape and keeps the
/// "loop owns the loop, handler owns the handler" trust boundary
/// clean.
#[async_trait]
pub trait AcceptHandler: Send + Sync {
    /// Handle one inbound connection.
    ///
    /// The accept loop has already driven the QUIC handshake to
    /// completion before calling this — implementations receive a
    /// fully established [`quinn::Connection`] and can call any of
    /// `open_bi`, `accept_bi`, `read_datagram`, `send_datagram`
    /// directly. The supplied `cancel` token fires when the loop's
    /// own token fires; handlers should race their pumps against it
    /// so a shutdown finishes promptly.
    ///
    /// # Errors
    ///
    /// Returns [`HandlerError::Handler`] when the handler decides the
    /// connection cannot continue. The accept loop logs the error and
    /// drops the per-connection task; subsequent inbound connections
    /// continue to be accepted.
    async fn handle(
        &self,
        conn: quinn::Connection,
        cancel: CancellationToken,
    ) -> Result<(), HandlerError>;
}

/// Default handler that discards every accepted connection.
///
/// Used by the test module to exercise the accept loop's lifecycle
/// without coupling to a real protocol handler, and by wiring paths
/// that want the loop's lifecycle running before the production
/// handler is plugged in. The connection is immediately dropped, which
/// triggers `quinn`'s default "application closed" path on the wire —
/// a real client sees a clean connection close, not a hang.
#[derive(Debug, Default)]
pub struct NoopAcceptHandler;

#[async_trait]
impl AcceptHandler for NoopAcceptHandler {
    async fn handle(
        &self,
        _conn: quinn::Connection,
        _cancel: CancellationToken,
    ) -> Result<(), HandlerError> {
        // Drop the connection immediately on return — quinn closes
        // the wire cleanly with the default "application closed"
        // code. No work, no error.
        Ok(())
    }
}

/// Cancel-aware accept loop wrapping a [`quinn::Endpoint`].
///
/// Construct with [`NodeQuicServer::new`] (caller owns endpoint
/// construction via [`quinn::Endpoint::server`] — typically with the
/// [`bibeam_transport::tls`]-supplied [`quinn::ServerConfig`] once
/// F-TRANS.2 ships the helper; until then, callers build the config
/// directly), then drive the loop with [`NodeQuicServer::run`] on a
/// dedicated tokio task.
///
/// The struct is intentionally minimal: it owns no per-flow state, no
/// metrics surface, and no auth gate — those are all the handler's
/// concern. [`NodeQuicServer::run`] consumes `self`, which statically
/// rules out two concurrent accept loops on the same endpoint
/// splitting inbound-connection ownership.
pub struct NodeQuicServer {
    endpoint: quinn::Endpoint,
    accept_handler: Arc<dyn AcceptHandler>,
    /// Semaphore capping concurrent per-connection tasks. The loop
    /// acquires one permit before [`tokio::spawn`] and the spawned
    /// task holds it for its lifetime; saturation produces backpressure
    /// at the acquire point rather than unbounded task spawn.
    connection_budget: Arc<Semaphore>,
}

impl core::fmt::Debug for NodeQuicServer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The handler is a `dyn` and has no `Debug` bound; render the
        // bound address + the budget cap only (those are what an
        // operator inspecting the server's startup state cares about).
        // `finish_non_exhaustive` silences `manual_debug` on the
        // intentionally elided handler field.
        formatter
            .debug_struct("NodeQuicServer")
            .field("local_addr", &self.endpoint.local_addr().ok())
            .field("available_permits", &self.connection_budget.available_permits())
            .finish_non_exhaustive()
    }
}

impl NodeQuicServer {
    /// Wire a pre-built [`quinn::Endpoint`] to an [`AcceptHandler`]
    /// with the [`DEFAULT_MAX_CONCURRENT_CONNECTIONS`] cap.
    ///
    /// The endpoint is assumed to be in **server mode** — i.e.,
    /// constructed via [`quinn::Endpoint::server`] with a populated
    /// [`quinn::ServerConfig`]. Passing a pure client endpoint (one
    /// built with [`quinn::Endpoint::client`]) compiles but
    /// [`NodeQuicServer::run`] will exit immediately on the first
    /// poll of [`quinn::Endpoint::accept`] because no server config
    /// is installed; that is treated as
    /// [`QuicServerError::EndpointClosed`].
    ///
    /// The handler is shared via [`Arc`] so the spawned per-connection
    /// tasks can each hold a cheap clone.
    #[must_use]
    pub fn new(endpoint: quinn::Endpoint, accept_handler: Arc<dyn AcceptHandler>) -> Self {
        Self::with_max_concurrent_connections(
            endpoint,
            accept_handler,
            DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        )
    }

    /// [`NodeQuicServer::new`] variant with an explicit concurrent-task
    /// cap. The semaphore is created with `max_concurrent_connections`
    /// permits; `0` is silently promoted to `1` because a zero-permit
    /// semaphore would deadlock the accept loop on its first inbound
    /// connection.
    #[must_use]
    pub fn with_max_concurrent_connections(
        endpoint: quinn::Endpoint,
        accept_handler: Arc<dyn AcceptHandler>,
        max_concurrent_connections: usize,
    ) -> Self {
        let permits = max_concurrent_connections.max(1);
        Self {
            endpoint,
            accept_handler,
            connection_budget: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Bound local address of the underlying [`quinn::Endpoint`].
    ///
    /// Convenience pass-through. Useful in tests that bind to
    /// `127.0.0.1:0` and need to learn the OS-assigned port to wire up
    /// an in-process client.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] from
    /// [`quinn::Endpoint::local_addr`] — only possible if the
    /// endpoint's UDP socket has been closed out from under it.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Run the accept loop until `cancel` fires or the endpoint
    /// closes. Consuming `self` statically rules out two concurrent
    /// accept loops on the same endpoint.
    ///
    /// Each loop iteration races [`quinn::Endpoint::accept`] against
    /// the supplied [`CancellationToken`]. On the happy path, an
    /// accepted [`quinn::Incoming`] is spawned onto a per-connection
    /// task that:
    ///
    /// 1. Drives the QUIC handshake to a [`quinn::Connection`]
    ///    (logging + dropping the task on handshake failure).
    /// 2. Calls the [`AcceptHandler::handle`] hook on the supplied
    ///    handler (logging + dropping the task on handler error).
    ///
    /// Per-connection tasks receive a child token of `cancel` so a
    /// global shutdown reaches their handlers without forcing every
    /// call site to share the parent token. Each spawned task holds
    /// one permit from the [`Semaphore`] passed in at construction;
    /// the loop awaits a permit before spawning, applying
    /// backpressure on a hostile or runaway peer rather than
    /// unbounded [`tokio::spawn`].
    ///
    /// # Errors
    ///
    /// Returns [`QuicServerError::EndpointClosed`] if the underlying
    /// [`quinn::Endpoint`] reports it has been closed out-of-band
    /// (a [`None`] from [`quinn::Endpoint::accept`]). A successful
    /// cancel returns `Ok(())`; per-accept handshake or handler
    /// failures are logged and absorbed.
    #[allow(
        clippy::cognitive_complexity,
        reason = "the cognitive-complexity score comes from the tokio::select! expansion, \
                  which clippy counts every generated branch as a separate decision point. \
                  The hand-written control flow is a flat accept-or-cancel loop, mirroring \
                  bibeam_transport::run_socks5_listener."
    )]
    pub async fn run(self, cancel: CancellationToken) -> Result<(), QuicServerError> {
        let local_addr = self.endpoint.local_addr().ok();
        tracing::info!(
            target: "bibeam_quic_server",
            ?local_addr,
            "quic accept loop started",
        );
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    tracing::info!(
                        target: "bibeam_quic_server",
                        ?local_addr,
                        "quic accept loop cancelled; draining",
                    );
                    return Ok(());
                }
                maybe_incoming = self.endpoint.accept() => {
                    let Some(incoming) = maybe_incoming else {
                        tracing::warn!(
                            target: "bibeam_quic_server",
                            ?local_addr,
                            "quic endpoint closed out-of-band; accept loop exiting",
                        );
                        return Err(QuicServerError::EndpointClosed);
                    };
                    // Acquire a permit BEFORE spawning so a runaway
                    // peer cannot exhaust tokio task slots / memory.
                    // Race the acquire against `cancel` so a shutdown
                    // never wedges on a saturated semaphore.
                    let permit = tokio::select! {
                        biased;
                        () = cancel.cancelled() => {
                            tracing::info!(
                                target: "bibeam_quic_server",
                                ?local_addr,
                                "quic accept loop cancelled while awaiting permit; draining",
                            );
                            // Drop the just-accepted `incoming` — quinn
                            // closes the wire cleanly on drop.
                            drop(incoming);
                            return Ok(());
                        }
                        acquired = Arc::clone(&self.connection_budget).acquire_owned() => {
                            match acquired {
                                Ok(permit) => permit,
                                Err(_closed) => {
                                    tracing::warn!(
                                        target: "bibeam_quic_server",
                                        ?local_addr,
                                        "connection-budget semaphore closed; accept loop exiting",
                                    );
                                    return Err(QuicServerError::EndpointClosed);
                                }
                            }
                        }
                    };
                    spawn_handler(
                        incoming,
                        Arc::clone(&self.accept_handler),
                        &cancel,
                        permit,
                    );
                }
            }
        }
    }
}

/// Spawn one per-connection task for `incoming`.
///
/// Extracted from [`NodeQuicServer::run`] so the run-loop body stays
/// under the cognitive-complexity ceiling and so the spawn shape can
/// be reused by future variants (e.g., a metrics-instrumented loop).
/// Per-connection tasks receive a child token of the loop's
/// `parent_cancel` so listener-level cancel propagates without
/// forcing the per-connection task to share the parent. The `permit`
/// is moved into the spawned task and held for its lifetime; it
/// returns to the loop's connection-budget semaphore on drop.
fn spawn_handler(
    incoming: quinn::Incoming,
    handler: Arc<dyn AcceptHandler>,
    parent_cancel: &CancellationToken,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let conn_cancel = parent_cancel.child_token();
    tokio::spawn(drive_handshake_then_handler(incoming, handler, conn_cancel, permit));
}

/// Per-connection task body: drive the QUIC handshake, then hand the
/// finished [`quinn::Connection`] to the handler.
///
/// Each side of the dispatch (handshake error vs handler error) is
/// logged at `warn` and absorbed — neither must tear the parent
/// accept loop down. The function does not return a `Result` because
/// the parent task does not consume one; the spawned task either runs
/// to completion or is observed only through tracing. The owned
/// `permit` parameter is held for the entire task lifetime so the
/// connection-budget semaphore tracks concurrent in-flight tasks
/// exactly.
#[allow(
    clippy::cognitive_complexity,
    reason = "the score comes from the two tracing emit-sites plus the match arms. \
              The hand-written body is: drive handshake → log on error → hand off, \
              with no nested control flow."
)]
async fn drive_handshake_then_handler(
    incoming: quinn::Incoming,
    handler: Arc<dyn AcceptHandler>,
    cancel: CancellationToken,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let remote_addr = incoming.remote_address();
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::warn!(
                target: "bibeam_quic_server",
                %remote_addr,
                error = %err,
                "quic handshake failed; dropping connection",
            );
            return;
        },
    };
    if let Err(err) = handler.handle(conn, cancel).await {
        tracing::warn!(
            target: "bibeam_quic_server",
            %remote_addr,
            error = %err,
            "accept handler returned error; per-connection task exiting",
        );
    }
    // Permit is dropped here, returning the slot to the loop's
    // connection-budget semaphore. Naming it `_permit` would let the
    // optimiser drop it earlier; the named binding keeps the lifetime
    // pinned to function scope.
    drop(permit);
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use parking_lot::Mutex;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use tokio::time::timeout;

    use super::*;

    /// Common deadline for "the accept loop should reach X within
    /// this wall-clock budget" assertions. Generous enough to absorb
    /// CI scheduling jitter, tight enough that a hung loop fails the
    /// test rather than the whole nextest run.
    const DEADLINE: Duration = Duration::from_secs(5);

    /// Loopback bind for tests — port 0 → OS-assigned.
    fn loopback_v4_zero() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    /// Mint a self-signed cert + key pair scoped to `localhost` and
    /// return the chain + private key in the rustls-pki-types shape
    /// [`quinn::ServerConfig::with_single_cert`] consumes.
    ///
    /// The cert is generated per-call with `rcgen`'s defaults
    /// (ECDSA-P256 under the `ring` feature this workspace pins);
    /// the SAN list is `["localhost"]` so the in-process client below
    /// can connect with that same name and pass server-name
    /// verification.
    fn mint_self_signed() -> (Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("rcgen must mint a self-signed cert");
        let cert_der = certified.cert.der().clone();
        let key_der = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        (vec![cert_der], key_der)
    }

    /// Ensure the rustls ring crypto provider is installed exactly
    /// once for the test binary's lifetime. `install_default` errors
    /// after the first call; tests across this module must be safe to
    /// run in parallel under nextest, so we ignore that error.
    fn ensure_crypto_provider() {
        // `install_default` is `#[must_use]` and its return type
        // owns a destructor; both `clippy::let_underscore_must_use`
        // and `let_underscore_drop` complain about `let _ = …` here.
        // Explicit match + drop sidesteps both lints while preserving
        // the "intentionally ignore the post-first-call error"
        // semantic.
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => {},
            Err(_already_installed) => {},
        }
    }

    /// Build a [`quinn::Endpoint`] in server mode bound to a fresh
    /// loopback port, paired with the cert chain a matching client
    /// can trust.
    fn build_server_endpoint() -> (quinn::Endpoint, CertificateDer<'static>) {
        ensure_crypto_provider();
        let (chain, key) = mint_self_signed();
        let server_cert = chain[0].clone();
        let server_config = quinn::ServerConfig::with_single_cert(chain, key.into())
            .expect("quinn must accept the self-signed cert + key");
        let endpoint = quinn::Endpoint::server(server_config, loopback_v4_zero())
            .expect("quinn must bind the loopback server endpoint");
        (endpoint, server_cert)
    }

    /// Build an in-process [`quinn::Endpoint`] in client mode that
    /// trusts only `server_cert` as a root anchor.
    ///
    /// The client endpoint is bound to a fresh loopback port (the
    /// OS picks one); the returned endpoint is configured to use the
    /// server's self-signed cert as its sole trust anchor.
    fn build_client_endpoint(server_cert: CertificateDer<'static>) -> quinn::Endpoint {
        ensure_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_cert).expect("rustls must accept the self-signed anchor");
        let client_config =
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config");
        let mut endpoint = quinn::Endpoint::client(loopback_v4_zero())
            .expect("quinn must bind the loopback client endpoint");
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    /// Recording handler: increments a counter on every accepted
    /// connection so tests can assert "the handler was invoked N
    /// times".
    #[derive(Debug, Default)]
    struct CountingHandler {
        accepted: AtomicUsize,
    }

    impl CountingHandler {
        fn count(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AcceptHandler for CountingHandler {
        async fn handle(
            &self,
            _conn: quinn::Connection,
            _cancel: CancellationToken,
        ) -> Result<(), HandlerError> {
            self.accepted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Toggling handler: returns `Err` on the calls listed in
    /// `fail_at_calls`, `Ok` otherwise. Used by the
    /// "errors do not kill the loop" test to assert subsequent
    /// connections continue to be accepted.
    #[derive(Debug)]
    struct TogglingHandler {
        calls: AtomicUsize,
        fail_at_calls: Mutex<Vec<usize>>,
    }

    impl TogglingHandler {
        fn new(fail_at_calls: Vec<usize>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail_at_calls: Mutex::new(fail_at_calls),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AcceptHandler for TogglingHandler {
        async fn handle(
            &self,
            _conn: quinn::Connection,
            _cancel: CancellationToken,
        ) -> Result<(), HandlerError> {
            let nth = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_at_calls.lock().contains(&nth) {
                return Err(HandlerError::from_display(format!(
                    "synthetic failure on call #{nth}"
                )));
            }
            Ok(())
        }
    }

    /// Open one in-process QUIC connection from `client` to
    /// `server_addr` and wait for it to be established. The returned
    /// `Connection` is held only long enough for the assertion to
    /// observe the server-side handler tick — dropping it triggers
    /// `quinn`'s default close.
    async fn drive_one_client_connection(
        client: &quinn::Endpoint,
        server_addr: SocketAddr,
    ) -> quinn::Connection {
        let connecting = client.connect(server_addr, "localhost").expect("connect must dispatch");
        connecting.await.expect("client handshake must succeed")
    }

    /// Block until `pred` returns `true` or `DEADLINE` expires; panic
    /// otherwise. Used in lieu of `tokio::time::sleep`-then-assert
    /// because the handler invocation is asynchronous wrt the client
    /// connect's return.
    async fn wait_for(label: &str, pred: impl Fn() -> bool) {
        let start = std::time::Instant::now();
        while !pred() {
            assert!(
                start.elapsed() <= DEADLINE,
                "`{label}` did not become true within {DEADLINE:?}",
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn accept_loop_handles_one_connection() {
        // Contract: a successful in-process client connect drives the
        // server's `AcceptHandler::handle` exactly once. Catches a
        // regression that wired up the loop but never dispatched onto
        // the handler.
        let (endpoint, server_cert) = build_server_endpoint();
        let server_addr = endpoint.local_addr().expect("server local_addr");
        let handler = Arc::new(CountingHandler::default());
        let handler_dyn: Arc<dyn AcceptHandler> = handler.clone();
        let server = NodeQuicServer::new(endpoint, handler_dyn);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let server_task = tokio::spawn(async move { server.run(cancel_clone).await });

        let client = build_client_endpoint(server_cert);
        let conn = drive_one_client_connection(&client, server_addr).await;

        let handler_obs = Arc::clone(&handler);
        wait_for("CountingHandler invoked once", move || handler_obs.count() >= 1).await;
        assert_eq!(handler.count(), 1, "handler must have been invoked exactly once");

        // Tear down — drop the client connection, cancel the server,
        // wait for the join handle.
        drop(conn);
        client.close(0u32.into(), b"test end");
        cancel.cancel();
        let outcome = timeout(DEADLINE, server_task).await.expect("server task must exit");
        assert!(outcome.expect("join").is_ok(), "clean cancel returns Ok");
    }

    #[tokio::test]
    async fn accept_loop_exits_on_cancel() {
        // Contract: the run loop returns `Ok(())` within `DEADLINE`
        // when the cancel token fires. Catches a regression that
        // dropped the cancel arm from `tokio::select!` (which would
        // wedge the loop on a perpetual `accept`).
        let (endpoint, _server_cert) = build_server_endpoint();
        let server = NodeQuicServer::new(endpoint, Arc::new(NoopAcceptHandler));
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let server_task = tokio::spawn(async move { server.run(cancel_clone).await });
        // Give the loop a moment to arm `accept`, then cancel.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        let outcome = timeout(DEADLINE, server_task)
            .await
            .expect("server task must exit before deadline");
        let outcome = outcome.expect("join handle must not panic");
        assert!(outcome.is_ok(), "clean shutdown returns Ok, got {outcome:?}");
    }

    #[tokio::test]
    async fn accept_handler_errors_do_not_kill_loop() {
        // Contract: a handler that returns `Err` on call #0 must not
        // tear the accept loop down — a second client connection
        // must still be accepted and dispatched onto the handler.
        // Catches a regression that propagated handler errors upward
        // (which would let one bad client kill the loop for everyone).
        let (endpoint, server_cert) = build_server_endpoint();
        let server_addr = endpoint.local_addr().expect("server local_addr");
        let handler = Arc::new(TogglingHandler::new(vec![0])); // fail only on call #0
        let handler_dyn: Arc<dyn AcceptHandler> = handler.clone();
        let server = NodeQuicServer::new(endpoint, handler_dyn);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let server_task = tokio::spawn(async move { server.run(cancel_clone).await });

        let client = build_client_endpoint(server_cert);

        // First connection — handler should return Err and the loop
        // must absorb it.
        let conn0 = drive_one_client_connection(&client, server_addr).await;
        let h1 = Arc::clone(&handler);
        wait_for("first handler invocation observed", move || h1.call_count() >= 1).await;
        drop(conn0);

        // Second connection — handler returns Ok, but the load-bearing
        // assertion is that we successfully dispatched onto it AT ALL.
        let conn1 = drive_one_client_connection(&client, server_addr).await;
        let h2 = Arc::clone(&handler);
        wait_for("second handler invocation observed", move || h2.call_count() >= 2).await;
        assert_eq!(
            handler.call_count(),
            2,
            "loop must have dispatched both connections despite the first handler's error",
        );

        drop(conn1);
        client.close(0u32.into(), b"test end");
        cancel.cancel();
        let outcome = timeout(DEADLINE, server_task).await.expect("server task must exit");
        assert!(outcome.expect("join").is_ok(), "clean cancel returns Ok");
    }

    #[test]
    fn handler_error_wraps_display() {
        // Contract: `HandlerError::from_display` formats any
        // Display-able error through the `Handler(String)` variant
        // without losing the underlying message. Catches a regression
        // that swallowed the source error's text or replaced it with
        // a hard-coded literal.
        #[derive(Debug, thiserror::Error)]
        #[error("synthetic source: {0}")]
        struct Synthetic(&'static str);

        let wrapped = HandlerError::from_display(Synthetic("test message"));
        let rendered = format!("{wrapped}");
        assert!(
            rendered.contains("synthetic source: test message"),
            "wrapped error must preserve the source message; got {rendered:?}",
        );
    }
}
