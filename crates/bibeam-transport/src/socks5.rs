#![forbid(unsafe_code)]
//! SOCKS5 listener for clients that cannot install a TUN device.
//!
//! Per F-TRANS.7's scope: `bibeam-cli` hosts a local SOCKS5 server so
//! a user on a restricted network — typical reasons: corporate
//! laptop, Android without root, Windows without admin — can route
//! application traffic through `BiBEAM` without standing up a kernel
//! TUN. The actual SOCKS5-to-`WgTunnel` bridging lives in `bibeam-cli`
//! (F-CLI.8); this module ships exactly the server-start API.
//!
//! ## What this layer does
//!
//! 1. Bind a [`tokio::net::TcpListener`] on the caller-supplied
//!    [`SocketAddr`].
//! 2. Accept incoming TCP connections in a loop, racing the accept
//!    against the caller's [`CancellationToken`].
//! 3. For each accepted socket, drive `fast_socks5`'s
//!    `Socks5ServerProtocol` state machine through `accept_no_auth →
//!    read_command → run_tcp_proxy`. The default `run_tcp_proxy`
//!    opens a direct outbound TCP connection — `bibeam-cli` will
//!    replace that direct dial with a `WgTunnel`-routed dial once
//!    F-CLI.8 lands; until then the listener works as a transparent
//!    SOCKS5 proxy, which is the documented MVP behaviour.
//!
//! ## What this layer does NOT do
//!
//! - It does not require authentication. Listen on `127.0.0.1` only;
//!   exposing this to a hostile network would let anybody inside
//!   that network use the local machine as a SOCKS5 relay.
//! - It does not implement UDP ASSOCIATE. The user-facing surface is
//!   CONNECT-only at MVP. UDP ASSOCIATE lands when `bibeam-cli`
//!   needs it.

use std::net::SocketAddr;
use std::time::Duration;

use fast_socks5::server::Socks5ServerProtocol;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Per-CONNECT request timeout fed to `run_tcp_proxy`. 30 seconds is
/// `fast-socks5`'s own default for its example servers and matches
/// the upper-bound TCP-connect latency we are willing to wait for on
/// a normal home broadband link.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors emitted by [`run_socks5_listener`].
#[derive(Debug, Error)]
pub enum Socks5Error {
    /// Bind / accept failure on the underlying `TcpListener`.
    #[error("socks5: tcp listener error: {0}")]
    Listen(#[from] std::io::Error),
}

/// Run a SOCKS5 listener on `bind_addr` until `cancel` is triggered.
///
/// Returns `Ok(())` after a clean shutdown (cancel observed before or
/// during an accept call). Returns [`Socks5Error::Listen`] only if
/// the initial bind fails — per-connection errors inside the accept
/// loop are logged via `tracing` and do not abort the listener,
/// because one misbehaving client should not take down service for
/// everyone else.
///
/// `bind_addr` is what the caller chose — `127.0.0.1:1080` is the
/// conventional local SOCKS5 binding. The function does not enforce
/// loopback-only; that policy lives one level up so an operator
/// running on a trusted private network can opt in to a non-loopback
/// bind if they understand the implications.
///
/// ## Shutdown semantics
///
/// When `cancel` fires, the listener stops accepting new connections
/// and returns immediately. Each spawned per-connection task gets a
/// `cancel.child_token()` and races the SOCKS5 state machine and the
/// `run_tcp_proxy` work against that cancellation: an in-flight
/// proxy that has been idle for the request-timeout window or that
/// sees the cancel signal exits promptly.
///
/// Tasks are spawned via `tokio::spawn` rather than tracked in a
/// `JoinSet`. The parent task does not block on outstanding tunnels
/// at cancel time. That matches what `bibeam-cli` needs at shutdown:
/// drop the listener, let in-flight tunnels exit on their own as
/// they observe the same cancel they were forked from.
///
/// # Errors
///
/// [`Socks5Error::Listen`] if the bind fails.
#[allow(
    clippy::cognitive_complexity,
    reason = "the cognitive-complexity score comes from the tokio::select! expansion, \
              which clippy counts every generated branch as a separate decision point. \
              The hand-written control flow here is a flat accept-or-cancel loop."
)]
pub async fn run_socks5_listener(
    bind_addr: SocketAddr,
    cancel: CancellationToken,
) -> Result<(), Socks5Error> {
    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "socks5 listener bound");
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::info!(%bind_addr, "socks5 listener cancelled; draining accept loop");
                return Ok(());
            }
            accept_outcome = listener.accept() => {
                handle_accept(accept_outcome, &cancel);
            }
        }
    }
}

/// Dispatch one accept-loop outcome: spawn the SOCKS5 state machine
/// on a fresh tokio task for the happy path, log + drop the listener
/// error on the failure path (a per-accept failure must not abort
/// the loop — see [`run_socks5_listener`]'s rustdoc).
///
/// Each per-connection task gets `parent_cancel.child_token()` so
/// listener-level cancel propagates without forcing the per-connection
/// task to share the parent token.
#[allow(
    clippy::cognitive_complexity,
    reason = "tokio::spawn + tracing macros expand to enough decision points to push \
              the synthetic score past 15. The hand-written body is a 2-arm match."
)]
fn handle_accept(
    accept_outcome: Result<(tokio::net::TcpStream, SocketAddr), std::io::Error>,
    parent_cancel: &CancellationToken,
) {
    match accept_outcome {
        Ok((socket, client_addr)) => {
            tracing::debug!(%client_addr, "socks5: connection accepted");
            let conn_cancel = parent_cancel.child_token();
            tokio::spawn(handle_connection(socket, client_addr, conn_cancel));
        },
        Err(err) => {
            tracing::warn!(error = %err, "socks5: accept failed; loop continues");
        },
    }
}

/// Drive one SOCKS5 client through `accept_no_auth → read_command →
/// run_tcp_proxy`. Logs and drops on any per-state failure — one
/// hostile or buggy client must not abort the listener.
///
/// The proxy work is raced against `cancel`, so a global shutdown
/// terminates the per-connection task even if `run_tcp_proxy` is
/// still pumping bytes.
#[allow(
    clippy::cognitive_complexity,
    reason = "the score comes from the tokio::select! macro expansion plus the \
              two tracing emit-sites. The hand-written body is straightforward: race \
              the SOCKS5 state machine against cancel, log the outcome."
)]
async fn handle_connection(
    socket: tokio::net::TcpStream,
    client_addr: SocketAddr,
    cancel: CancellationToken,
) {
    let span = tracing::debug_span!("socks5_conn", client = %client_addr);
    let _entered = span.enter();
    let outcome = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            tracing::debug!("socks5: connection cancelled before / during proxy");
            return;
        }
        result = drive_connection(socket) => result,
    };
    if let Err(err) = outcome {
        tracing::debug!(error = %err, "socks5: connection failed");
    }
}

/// Inner: split out so [`handle_connection`] stays under the
/// cognitive-complexity / too-many-lines ceilings.
///
/// Unsupported SOCKS5 commands (BIND, UDP ASSOCIATE) send a typed
/// `CommandNotSupported` reply on the wire via `proto.reply_error`
/// before returning, so the client surfaces a real SOCKS5 error
/// rather than seeing the TCP socket close without warning.
async fn drive_connection(socket: tokio::net::TcpStream) -> Result<(), fast_socks5::SocksError> {
    let proto = Socks5ServerProtocol::accept_no_auth(socket).await?;
    let (proto, command, target_addr) = proto.read_command().await?;
    if !matches!(command, fast_socks5::Socks5Command::TCPConnect) {
        // SOCKS5 BIND and UDP ASSOCIATE are deliberately out of scope
        // for the MVP listener. Send the standard
        // `CommandNotSupported` reply so the client surfaces a
        // sensible error to its user, then return.
        proto.reply_error(&fast_socks5::ReplyError::CommandNotSupported).await?;
        return Ok(());
    }
    let _socket = fast_socks5::server::run_tcp_proxy(proto, &target_addr, REQUEST_TIMEOUT, false)
        .await
        .map_err(fast_socks5::SocksError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::*;

    fn loopback_v4_zero() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    async fn listener_returns_when_cancel_token_fires() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        // Pick port 0 so the OS assigns one — we don't care about
        // the value, only that the bind succeeds and that cancel
        // tears the listener down.
        let listener_handle =
            tokio::spawn(
                async move { run_socks5_listener(loopback_v4_zero(), cancel_clone).await },
            );
        // Give the listener a moment to bind, then cancel.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        let outcome = timeout(Duration::from_millis(500), listener_handle)
            .await
            .expect("listener task must exit before timeout");
        let outcome = outcome.expect("join handle must not panic");
        assert!(outcome.is_ok(), "clean shutdown must return Ok: {outcome:?}");
    }

    #[tokio::test]
    async fn listener_surfaces_bind_failure_as_typed_error() {
        // Bind a TCP listener first to claim a port, then ask
        // run_socks5_listener to bind the SAME address — the second
        // bind must fail with Socks5Error::Listen.
        let blocker = TcpListener::bind(loopback_v4_zero()).await.expect("blocker binds");
        let occupied = blocker.local_addr().expect("blocker addr");
        let cancel = CancellationToken::new();
        let outcome = run_socks5_listener(occupied, cancel).await;
        assert!(matches!(outcome, Err(Socks5Error::Listen(_))));
    }
}
