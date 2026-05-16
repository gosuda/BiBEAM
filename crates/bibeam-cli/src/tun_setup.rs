#![forbid(unsafe_code)]
//! Cross-platform TUN setup with privilege-escalation guard (F-CLI.2).
//!
//! [`setup_tun`] is the single entry point the `up` subcommand
//! (F-CLI.1) calls to materialise a [`bibeam_tun::TunDevice`]. It
//! pre-checks the running process's privilege before touching the
//! kernel-side TUN driver so the binary can return a typed
//! [`TunSetupError::NoPrivilege`] — the signal F-CLI.8 reads to
//! switch into SOCKS5 fallback mode.
//!
//! The check is per-platform:
//!
//! - **Linux** — `CAP_NET_ADMIN` in the process's effective
//!   capability set, via the `caps` crate. Running as `euid==0`
//!   implicitly satisfies this because the Linux kernel grants
//!   every capability to root in the effective set; we do not
//!   special-case root because the same `caps::has_cap` call
//!   returns `true` for both root and a non-root process that
//!   was granted `cap_net_admin+ep`. The operator runbook's
//!   `setcap cap_net_admin+ep` recipe is the documented
//!   non-root path.
//!
//! - **macOS** — `utun` device creation through `tun_rs` requires
//!   `euid==0`. We *attempt* the open and surface
//!   [`TunSetupError::NoPrivilege`] when the underlying I/O fails
//!   with a permission-class error (`EPERM`, `EACCES`). Other
//!   I/O failures stay as [`TunSetupError::OpenFailed`] so an
//!   operator running into a wintun-driver-missing-equivalent
//!   does not get a misleading "no privilege" message.
//!
//! - **Windows** — the `wintun` driver only accepts an
//!   administrator token. Same `Open*` surface as macOS: try
//!   the open, partition `ERROR_ACCESS_DENIED` into
//!   [`TunSetupError::NoPrivilege`].
//!
//! ## Why the Linux check is pre-flight
//!
//! `tun_rs` on Linux opens `/dev/net/tun` synchronously inside
//! `DeviceBuilder::build_async`. A pre-flight `caps::has_cap`
//! call costs one `prctl` syscall and gives F-CLI.8 a clean
//! decision point *before* `boringtun`'s side state initialises.
//! On non-Linux platforms there is no equivalent kernel-side
//! probe API, so the post-hoc error classification is the right
//! shape.
//!
//! ## Interface name and MTU
//!
//! `setup_tun` accepts an [`TunSetupConfig`] for the interface
//! name and MTU rather than hard-coding them. The defaults
//! ([`TunSetupConfig::default`]) are `bibeam0` and
//! [`DEFAULT_MTU`]; F-CLI.6 will thread the config file's
//! values through here.

use std::io;

use bibeam_tun::{DEFAULT_MTU, TunDevice, TunError};
use thiserror::Error;

/// Default TUN interface name. Picks a fixed `bibeam0` so
/// operator-side `ip` / `netstat` invocations have a stable
/// hook. F-CLI.6's config file will let operators override.
const DEFAULT_TUN_NAME: &str = "bibeam0";

/// Inputs to [`setup_tun`].
///
/// The struct is `pub(crate)` because the `up` handler in the
/// sibling `cli` module materialises one and threads it through
/// `setup_tun`. The fields stay `pub(crate)` so the caller can
/// build a config inline.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: rustc's `unreachable_pub` rejects bare `pub` on items \
              consumed only by sibling private modules. The clippy nursery lint \
              disagrees with rustc on the same items; we side with rustc, the \
              load-bearing lint for the workspace's `-D warnings` gate."
)]
#[derive(Debug, Clone)]
pub(crate) struct TunSetupConfig {
    /// Interface name hint passed to [`TunDevice::new`].
    pub(crate) name: String,
    /// Negotiated MTU passed to [`TunDevice::new`].
    pub(crate) mtu: u16,
}

impl Default for TunSetupConfig {
    fn default() -> Self {
        Self {
            name: DEFAULT_TUN_NAME.to_owned(),
            mtu: DEFAULT_MTU,
        }
    }
}

/// Errors emitted by [`setup_tun`].
///
/// `pub(crate)` so the sibling `cli` module's `up` handler can
/// pattern-match the `NoPrivilege` variant for F-CLI.8's
/// SOCKS5-fallback handoff.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see `TunSetupConfig` for the rustc-vs-clippy rationale."
)]
#[derive(Debug, Error)]
pub(crate) enum TunSetupError {
    /// The running process lacks the privilege the platform's TUN
    /// driver requires. F-CLI.8 reads this variant as the signal
    /// to switch into the SOCKS5-listener fallback. The `help`
    /// string points operators at the platform-specific recipe
    /// for granting the missing privilege; consumers should
    /// surface it verbatim.
    #[error("tun setup failed: process lacks the required privilege ({platform}): {help}")]
    NoPrivilege {
        /// Platform tag ("linux" / "macos" / "windows") so log
        /// readers can correlate against the host quickly.
        platform: &'static str,
        /// Operator-facing help string. Plain text, ASCII, no
        /// terminal escapes — operators copy this verbatim.
        help: &'static str,
    },
    /// The TUN device opened, but with an unexpected I/O failure
    /// that is *not* a privilege denial. Preserves the underlying
    /// [`TunError`] for diagnostics.
    #[error("tun setup failed: {0}")]
    OpenFailed(#[source] TunError),
    /// `caps::has_cap` itself failed (e.g. an obscure container
    /// runtime forbids `capget(2)`). Distinct from
    /// [`Self::NoPrivilege`] because the cause is "we cannot
    /// even check", not "we checked and lack the cap".
    #[cfg(target_os = "linux")]
    #[error("tun setup failed: cannot read capability set: {0}")]
    CapCheckFailed(String),
}

/// Operator-facing help string emitted alongside Linux
/// [`TunSetupError::NoPrivilege`]. Documented in
/// `docs/operator-runbook.md`.
#[cfg(target_os = "linux")]
const LINUX_NO_PRIV_HELP: &str = "grant cap_net_admin to the binary with \
     `sudo setcap cap_net_admin+ep $(which bibeam)`, \
     or run as root";

/// Operator-facing help string emitted on macOS.
#[cfg(target_os = "macos")]
const MACOS_NO_PRIV_HELP: &str = "the macOS utun driver requires root; \
     re-launch with `sudo bibeam up ...` \
     or run a privileged install";

/// Operator-facing help string emitted on Windows.
#[cfg(target_os = "windows")]
const WINDOWS_NO_PRIV_HELP: &str = "the wintun driver requires an administrator token; \
     re-launch the binary from an elevated PowerShell or \
     install bibeam as a Windows service running as LocalSystem";

/// Build a [`TunDevice`] for the daemon, returning a typed
/// failure when the process is not allowed to.
///
/// # Errors
///
/// - [`TunSetupError::NoPrivilege`] — F-CLI.8 reads this as the
///   trigger to start the SOCKS5 listener fallback. The variant
///   carries an operator-facing help string.
/// - [`TunSetupError::OpenFailed`] — every other TUN-open
///   failure (driver missing, name conflict, etc.). The caller
///   should bail out rather than fall back.
/// - [`TunSetupError::CapCheckFailed`] (Linux only) — the
///   capability check itself failed, which is rare enough that
///   we surface it as a distinct variant rather than treat it
///   as "no privilege".
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see `TunSetupConfig` for the rustc-vs-clippy rationale."
)]
pub(crate) async fn setup_tun(config: &TunSetupConfig) -> Result<TunDevice, TunSetupError> {
    #[cfg(target_os = "linux")]
    {
        check_linux_privilege()?;
        return open_with_privilege_classification(config, "linux", LINUX_NO_PRIV_HELP).await;
    }
    #[cfg(target_os = "macos")]
    {
        return open_with_privilege_classification(config, "macos", MACOS_NO_PRIV_HELP).await;
    }
    #[cfg(target_os = "windows")]
    {
        return open_with_privilege_classification(config, "windows", WINDOWS_NO_PRIV_HELP).await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // Unsupported platform: surface a NoPrivilege variant so
        // F-CLI.8's SOCKS5 fallback still has a graceful path,
        // rather than panicking on an unimplemented branch.
        let _ = config;
        Err(TunSetupError::NoPrivilege {
            platform: "unsupported",
            help: "TUN setup is implemented for linux, macos, and windows targets only",
        })
    }
}

/// Linux-only: confirm `CAP_NET_ADMIN` is in the running thread's
/// effective set.
#[cfg(target_os = "linux")]
fn check_linux_privilege() -> Result<(), TunSetupError> {
    use caps::{CapSet, Capability};
    let has = caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN)
        .map_err(|err| TunSetupError::CapCheckFailed(err.to_string()))?;
    if has {
        Ok(())
    } else {
        Err(TunSetupError::NoPrivilege {
            platform: "linux",
            help: LINUX_NO_PRIV_HELP,
        })
    }
}

/// Open the TUN device and partition any permission-class I/O
/// error into [`TunSetupError::NoPrivilege`]. Used as the
/// macOS / Windows main path and as the post-cap-check Linux
/// path.
async fn open_with_privilege_classification(
    config: &TunSetupConfig,
    platform: &'static str,
    help: &'static str,
) -> Result<TunDevice, TunSetupError> {
    match TunDevice::new(&config.name, config.mtu).await {
        Ok(device) => Ok(device),
        Err(err) if is_privilege_denied(&err) => Err(TunSetupError::NoPrivilege { platform, help }),
        Err(err) => Err(TunSetupError::OpenFailed(err)),
    }
}

/// Classify a [`TunError`] as a privilege denial.
///
/// Returns `true` when the underlying [`io::Error`] kind matches
/// the platform's privilege-denied signature. Other I/O failures
/// (e.g. interface-name conflict, driver missing) return `false`
/// so [`open_with_privilege_classification`] preserves the
/// distinction.
fn is_privilege_denied(err: &TunError) -> bool {
    let TunError::Open(io_err) = err else {
        return false;
    };
    matches!(io_err.kind(), io::ErrorKind::PermissionDenied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_documented_defaults() {
        // Contract: the documented default name and MTU are
        // `bibeam0` and `bibeam_tun::DEFAULT_MTU`. A regression
        // that flipped either would silently change what
        // operator-side `ip link` reports.
        let config = TunSetupConfig::default();
        assert_eq!(config.name, DEFAULT_TUN_NAME);
        assert_eq!(config.mtu, DEFAULT_MTU);
    }

    #[test]
    fn is_privilege_denied_classifies_permission_denied() {
        // Contract: a `TunError::Open` whose inner io::Error has
        // kind `PermissionDenied` is read as a privilege failure.
        // A regression that read a different kind here would let
        // F-CLI.8's fallback path stay dark when the kernel said
        // "no" for the canonical reason.
        let io_err = io::Error::from(io::ErrorKind::PermissionDenied);
        let err = TunError::Open(io_err);
        assert!(is_privilege_denied(&err));
    }

    #[test]
    fn is_privilege_denied_rejects_non_open_variants() {
        // Contract: TunError::Read / Write / Packet are not
        // "the device could not be opened because privilege was
        // denied" signals; they are post-open failures. F-CLI.8
        // must not interpret them as "fall back to SOCKS5".
        let err = TunError::Packet("malformed".into());
        assert!(!is_privilege_denied(&err));
    }

    #[test]
    fn is_privilege_denied_rejects_unrelated_io_kinds() {
        // Contract: a non-permission-denied I/O kind (e.g.
        // NotFound for a missing wintun driver, or AddrInUse for
        // a name conflict) is *not* a privilege issue.
        let io_err = io::Error::from(io::ErrorKind::NotFound);
        let err = TunError::Open(io_err);
        assert!(!is_privilege_denied(&err));
    }
}
