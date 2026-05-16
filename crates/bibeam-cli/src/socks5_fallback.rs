#![forbid(unsafe_code)]
//! SOCKS5 fallback when TUN setup fails (F-CLI.8).
//!
//! When [`crate::tun_setup::setup_tun`] surfaces
//! [`crate::tun_setup::TunSetupError::NoPrivilege`] (Linux
//! `CAP_NET_ADMIN` absent, macOS not running as root, Windows
//! not elevated), this module's [`run_fallback`] takes over: it
//! starts a SOCKS5 listener on a loopback address (default
//! `127.0.0.1:1080`) via the already-shipped
//! [`bibeam_transport::run_socks5_listener`] and runs until the
//! supplied cancellation token fires.
//!
//! ## Why loopback
//!
//! The SOCKS5 listener does NOT enforce loopback at the
//! transport layer (the policy lives one level up — see the
//! `bibeam_transport::socks5` module's rustdoc). This module
//! parses the operator-supplied bind string and warns prominently
//! when the result is a non-loopback address — exposing this to
//! a hostile network would let anybody on the LAN use the local
//! machine as an open SOCKS5 relay. The bind itself still
//! happens (an operator on a trusted private network may
//! legitimately want it); the warning ensures the operator sees
//! the consequence.

use std::net::SocketAddr;

use anyhow::{Context as _, Result};
use bibeam_transport::run_socks5_listener;
use tokio_util::sync::CancellationToken;

/// Default bind address used when the operator's config carries
/// no `socks5_bind` key. Matches the F-CLI.8 spec
/// (`127.0.0.1:1080`) — the conventional local SOCKS5 binding
/// that every browser and curl-style tool knows out of the box.
const DEFAULT_BIND: &str = "127.0.0.1:1080";

/// Resolve the SOCKS5 bind address from a config override.
///
/// Returns the parsed [`SocketAddr`]; surfaces a typed error
/// when the operator-supplied string does not parse.
///
/// # Errors
///
/// Returns an [`anyhow::Error`] when `override_str` is set and
/// the value fails to parse as a [`SocketAddr`].
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: rustc's `unreachable_pub` rejects bare `pub` on items \
              consumed only by sibling private modules; clippy disagrees. We side with \
              rustc, the load-bearing lint."
)]
pub(crate) fn resolve_bind(override_str: Option<&str>) -> Result<SocketAddr> {
    let raw = override_str.unwrap_or(DEFAULT_BIND);
    raw.parse::<SocketAddr>().with_context(|| {
        format!("socks5 fallback: invalid bind address {raw:?} — expected a host:port pair")
    })
}

/// Run the SOCKS5 fallback listener until `cancel` fires.
///
/// The bind log line is emitted at `info` level so operators see
/// it without bumping the global filter; a non-loopback bind
/// gets an additional `warn`-level line that flags the broader
/// exposure.
///
/// # Errors
///
/// Forwards any error from
/// [`bibeam_transport::run_socks5_listener`] verbatim.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see resolve_bind for the rustc-vs-clippy rationale."
)]
pub(crate) async fn run_fallback(bind: SocketAddr, cancel: CancellationToken) -> Result<()> {
    warn_if_non_loopback(bind);
    tracing::info!(
        %bind,
        "socks5 fallback: TUN setup denied (F-CLI.2) — starting SOCKS5 listener (F-CLI.8)",
    );
    run_socks5_listener(bind, cancel)
        .await
        .context("socks5 fallback: listener exited with an error")
}

/// Emit a `warn`-level line when the resolved bind is reachable
/// from outside the local host. The SOCKS5 listener has no
/// authentication; a non-loopback bind on an open network would
/// let anyone reach it.
fn warn_if_non_loopback(bind: SocketAddr) {
    if bind.ip().is_loopback() {
        return;
    }
    tracing::warn!(
        %bind,
        "socks5 fallback: bind address is NOT loopback — the listener has no \
         authentication and anybody on this network can use it as an open SOCKS5 \
         relay. Set socks5_bind to a 127.0.0.1 / ::1 form unless you know what you \
         are doing.",
    );
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn resolve_bind_defaults_to_loopback_1080() {
        // Contract: a fresh install with no socks5_bind override
        // resolves to the documented 127.0.0.1:1080 default.
        let bind = resolve_bind(None).expect("default must parse");
        assert_eq!(bind.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(bind.port(), 1080);
    }

    #[test]
    fn resolve_bind_honours_operator_override() {
        let bind = resolve_bind(Some("127.0.0.1:7777")).expect("override must parse");
        assert_eq!(bind.port(), 7777);
    }

    #[test]
    fn resolve_bind_accepts_ipv6_loopback() {
        // Contract: `[::1]:1080` is a valid loopback alternative.
        // A regression that hard-coded ipv4-only would break
        // every macOS / Linux operator preferring v6.
        let bind = resolve_bind(Some("[::1]:1080")).expect("ipv6 must parse");
        assert!(bind.ip().is_loopback());
    }

    #[test]
    fn resolve_bind_rejects_malformed_input() {
        let err = resolve_bind(Some("not a socket addr")).expect_err("must reject");
        let chain: Vec<String> = err.chain().map(ToString::to_string).collect();
        let joined = chain.join(" / ");
        assert!(
            joined.contains("invalid bind address") || joined.contains("host:port"),
            "error chain must mention the parse failure: {joined}",
        );
    }
}
