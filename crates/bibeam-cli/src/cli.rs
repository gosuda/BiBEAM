#![forbid(unsafe_code)]
#![allow(
    clippy::redundant_pub_crate,
    reason = "this module is binary-private (`mod cli;` in main.rs has no `pub`); rustc's \
              `unreachable_pub` warns on bare `pub` here, so every public-shaped item \
              below uses `pub(crate)`. The clippy nursery lint disagrees with rustc on \
              the same items — we side with rustc, the load-bearing one for the \
              workspace's `-D warnings` gate."
)]
//! Clap subcommand surface for the `bibeam` CLI (F-CLI.1).
//!
//! The [`Cli`] / [`Cmd`] pair below is the entry-point shape every
//! end-user invocation goes through. Subcommands are dispatched by
//! [`dispatch`], which routes to a private per-command handler in
//! this module. Per-subcommand work that grows beyond a handful of
//! lines lives in a sibling module (`src/tun_setup.rs`, etc.) and
//! is wired in by later F-CLI sub-items; the handlers below stub
//! the data-plane verbs until those modules land.
//!
//! ## Why a single dispatch fn
//!
//! The crate exposes one binary (`bibeam`). The clap derive macros
//! prefer to live near the binary's `main`, but keeping the
//! subcommand `enum` in a library module makes the dispatch table
//! testable without spawning the binary. `main.rs` is the
//! single user of [`dispatch`] and stays trivial.
//!
//! ## Version surface
//!
//! Both `--version` (handled by clap from `env!("CARGO_PKG_VERSION")`)
//! and the explicit `version` subcommand print the same string. The
//! subcommand emits to stdout because the convention for `--version`
//! output is stdout, not a tracing log line — operators script
//! against it.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Parsed top-level CLI invocation.
#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"), version, about)]
pub(crate) struct Cli {
    /// Optional override for the configuration file path. When
    /// unset the daemon resolves the platform-standard location
    /// via `crate::config::config_dir` (which lands with F-CLI.6).
    #[arg(long, global = true)]
    pub(crate) config: Option<PathBuf>,
    /// Selected subcommand.
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

/// End-user verbs the `bibeam` binary exposes.
#[derive(Debug, Subcommand)]
pub(crate) enum Cmd {
    /// Write a default config file at the platform's standard
    /// location.
    Init,
    /// Start the `BiBEAM` daemon. Defaults to TUN-mode; falls
    /// back to the SOCKS5 listener when TUN setup fails (F-CLI.8).
    Up {
        /// Coordinator invite code. When absent the daemon prompts
        /// on stdin (F-CLI.3).
        #[arg(long)]
        invite: Option<String>,
        /// Run in the foreground instead of daemonising. Without
        /// this flag the binary detaches into a long-lived daemon
        /// once the bootstrap completes; with this flag it stays
        /// attached to the controlling terminal — the shape a
        /// supervisor like `systemd --user` expects.
        ///
        /// The default value is `false` (i.e. daemonise);
        /// [`dispatch`] inverts this flag exactly once at the
        /// dispatch boundary into the canonical "should I
        /// daemonise?" question downstream callers ask, so the
        /// binary never carries two booleans for one mode choice.
        #[arg(long, default_value_t = false)]
        foreground: bool,
    },
    /// Stop a running daemon by sending the process its
    /// platform-appropriate termination signal (SIGTERM on Unix;
    /// CTRL-BREAK on Windows).
    Down,
    /// Print the local daemon's `/healthz` and `/readyz` state.
    Status,
    /// Print the resolved config (post-figment merge).
    Config,
    /// Print the version.
    Version,
}

/// Dispatch a parsed [`Cli`] to its per-subcommand handler.
///
/// Returns [`Ok`] on a successful invocation. Handlers that need
/// to surface a non-zero exit status return an
/// [`anyhow::Error`]; the caller (`main.rs`) converts that into a
/// process-level failure.
///
/// # Errors
///
/// Propagates every handler's error verbatim.
pub(crate) async fn dispatch(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init => handle_init(cli.config.as_deref()).await,
        Cmd::Up { invite, foreground } => {
            handle_up(cli.config.as_deref(), invite, !foreground).await
        },
        Cmd::Down => handle_down(cli.config.as_deref()).await,
        Cmd::Status => handle_status(cli.config.as_deref()).await,
        Cmd::Config => handle_config(cli.config.as_deref()).await,
        Cmd::Version => handle_version(),
    }
}

/// `init` — placeholder; F-CLI.6 wires the real config-write.
#[allow(
    clippy::unused_async,
    reason = "async-shaped to keep the dispatch table uniform; F-CLI.6 will introduce \
              filesystem I/O here and benefit from staying inside the tokio runtime."
)]
async fn handle_init(config_override: Option<&std::path::Path>) -> Result<()> {
    tracing::info!(
        config_override = ?config_override,
        "init: scaffold subcommand — config-write lands in F-CLI.6",
    );
    Ok(())
}

/// `up` — partial; F-CLI.2 wires the privilege-guarded TUN
/// setup. Bootstrap (F-CLI.3+) and the SOCKS5 fallback
/// (F-CLI.8) arrive in later sub-items; for now the handler
/// delegates to [`probe_tun_or_fallback`] so the cognitive
/// score of the cli-side dispatch stays compact as later
/// sub-items extend it.
async fn handle_up(
    config_override: Option<&std::path::Path>,
    invite: Option<String>,
    daemonise: bool,
) -> Result<()> {
    tracing::info!(
        config_override = ?config_override,
        has_invite = invite.is_some(),
        daemonise,
        "up: invoking TUN setup probe (F-CLI.2)",
    );
    probe_tun_or_fallback().await
}

/// Probe the TUN setup once and route the three outcomes:
/// successful open, typed `NoPrivilege` (F-CLI.8's fallback
/// signal), or any other TUN failure (surfaced as an error).
///
/// Returns `Ok(())` for both "TUN opened" and "no privilege —
/// SOCKS5 fallback would take over". The SOCKS5 path lands in
/// F-CLI.8; this commit gives the dispatch path something real
/// to do beyond logging.
async fn probe_tun_or_fallback() -> Result<()> {
    let tun_config = crate::tun_setup::TunSetupConfig::default();
    let outcome = crate::tun_setup::setup_tun(&tun_config).await;
    classify_tun_outcome(&tun_config, outcome)
}

/// Route a [`crate::tun_setup::setup_tun`] outcome into the
/// dispatch contract. Kept as a free fn so the cognitive
/// complexity of [`probe_tun_or_fallback`] stays flat for
/// later F-CLI sub-items.
fn classify_tun_outcome(
    tun_config: &crate::tun_setup::TunSetupConfig,
    outcome: Result<bibeam_tun::TunDevice, crate::tun_setup::TunSetupError>,
) -> Result<()> {
    match outcome {
        Ok(_device) => {
            log_tun_opened(tun_config);
            Ok(())
        },
        Err(crate::tun_setup::TunSetupError::NoPrivilege { platform, help }) => {
            log_no_privilege(platform, help);
            Ok(())
        },
        Err(other) => Err(anyhow::Error::new(other).context("up: TUN setup failed")),
    }
}

/// Log the "TUN opened" branch. Free fn so
/// [`classify_tun_outcome`]'s match arms each shrink to one
/// expression — keeps the cognitive-complexity score under the
/// 15-cap as F-CLI.3+ add more arms.
fn log_tun_opened(tun_config: &crate::tun_setup::TunSetupConfig) {
    tracing::info!(
        interface = %tun_config.name,
        mtu = tun_config.mtu,
        "up: TUN device opened — bootstrap path lands in F-CLI.3+",
    );
}

/// Log the "no privilege" branch the same way as
/// [`log_tun_opened`]. F-CLI.8 will replace the body with the
/// SOCKS5-fallback handoff.
fn log_no_privilege(platform: &'static str, help: &'static str) {
    tracing::warn!(platform, help, "up: TUN setup denied — SOCKS5 fallback lands in F-CLI.8",);
}

/// `down` — placeholder; the kill-via-PID-file path lands together
/// with the daemonisation flag in a later sub-item.
#[allow(
    clippy::unused_async,
    reason = "async-shaped to keep the dispatch table uniform; later sub-items read a \
              PID file and signal the running daemon from this body."
)]
async fn handle_down(config_override: Option<&std::path::Path>) -> Result<()> {
    tracing::info!(
        config_override = ?config_override,
        "down: scaffold subcommand — PID-file signalling lands with daemonisation",
    );
    Ok(())
}

/// `status` — placeholder; once the daemon listens on a local
/// management port the handler probes `/healthz` and `/readyz`.
#[allow(
    clippy::unused_async,
    reason = "async-shaped to keep the dispatch table uniform; the real handler does \
              HTTP I/O against the local daemon."
)]
async fn handle_status(config_override: Option<&std::path::Path>) -> Result<()> {
    tracing::info!(
        config_override = ?config_override,
        "status: scaffold subcommand — health probe lands with the local mgmt port",
    );
    Ok(())
}

/// `config` — placeholder; F-CLI.6 wires the figment loader and
/// prints the merged value.
#[allow(
    clippy::unused_async,
    reason = "async-shaped to keep the dispatch table uniform; F-CLI.6 may add file I/O \
              here and benefit from staying inside the tokio runtime."
)]
async fn handle_config(config_override: Option<&std::path::Path>) -> Result<()> {
    tracing::info!(
        config_override = ?config_override,
        "config: scaffold subcommand — resolved-config print lands in F-CLI.6",
    );
    Ok(())
}

/// `version` — emits the package version to stdout. Stdout is
/// the conventional sink for `--version` output, which operator
/// scripts capture with backticks.
#[allow(
    clippy::print_stdout,
    reason = "user-facing CLI output, not log: `bibeam version` is the documented \
              operator scripting hook, and operators capture this on stdout."
)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the dispatch table treats every handler uniformly as `-> Result<()>`; \
              the wrap keeps `match cli.cmd { ... }` exhaustive without per-arm \
              `Ok(())` adapters. Future handlers that surface a real error remain \
              shape-compatible."
)]
fn handle_version() -> Result<()> {
    println!(
        "{name} {version}",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_help_is_non_empty() {
        // Contract: `bibeam --help` must produce a non-empty
        // string. A regression that dropped the `about` attribute
        // or replaced the binary name with an empty string would
        // silently surface as a help dump with no body.
        let mut command = Cli::command();
        let rendered = command.render_help().to_string();
        assert!(!rendered.is_empty(), "rendered help must not be empty");
        assert!(rendered.contains("bibeam"), "rendered help must mention the binary name");
    }

    #[test]
    fn parses_init_subcommand() {
        let cli = Cli::try_parse_from(["bibeam", "init"]).expect("init must parse");
        assert!(matches!(cli.cmd, Cmd::Init));
    }

    #[test]
    fn parses_up_with_invite() {
        let cli = Cli::try_parse_from(["bibeam", "up", "--invite", "AAAA"]).expect("up must parse");
        match cli.cmd {
            Cmd::Up { invite, foreground } => {
                assert_eq!(invite.as_deref(), Some("AAAA"));
                assert!(!foreground, "foreground defaults to false (i.e. daemonise)");
            },
            other => panic!("expected Cmd::Up, got {other:?}"),
        }
    }

    #[test]
    fn parses_up_with_foreground_flag() {
        // Contract: `--foreground` is the only way to opt out of
        // the daemonise default. A regression that swapped the
        // sign or dropped the flag would silently leave the
        // daemon attached to the terminal in every invocation.
        let cli =
            Cli::try_parse_from(["bibeam", "up", "--foreground"]).expect("--foreground must parse");
        match cli.cmd {
            Cmd::Up { foreground, .. } => assert!(foreground),
            other => panic!("expected Cmd::Up, got {other:?}"),
        }
    }

    #[test]
    fn parses_global_config_flag() {
        let cli = Cli::try_parse_from(["bibeam", "--config", "/tmp/x.toml", "config"])
            .expect("config must parse");
        assert_eq!(cli.config.as_deref(), Some(std::path::Path::new("/tmp/x.toml")));
        assert!(matches!(cli.cmd, Cmd::Config));
    }

    #[test]
    fn parses_version_subcommand() {
        let cli = Cli::try_parse_from(["bibeam", "version"]).expect("version must parse");
        assert!(matches!(cli.cmd, Cmd::Version));
    }

    #[tokio::test]
    async fn dispatch_version_returns_ok() {
        // Contract: the `version` subcommand exits 0. The handler
        // prints to stdout; we capture the parse-then-dispatch
        // path here to guard against future regressions that
        // swap the handler for an `Err(...)`.
        let cli = Cli::try_parse_from(["bibeam", "version"]).expect("version must parse");
        dispatch(cli).await.expect("version handler must return Ok");
    }

    #[tokio::test]
    async fn dispatch_init_is_idempotent_today() {
        // Contract: the scaffold handler returns Ok and does not
        // mutate any external state. F-CLI.6 will tighten this
        // contract once the real handler lands.
        let cli = Cli::try_parse_from(["bibeam", "init"]).expect("init must parse");
        dispatch(cli).await.expect("init scaffold must return Ok");
    }
}
