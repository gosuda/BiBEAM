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

/// `init` — write a default config at the platform-standard
/// path (or the override). Delegates to
/// [`crate::config::run_init`] so the cli dispatch table stays
/// compact.
async fn handle_init(config_override: Option<&std::path::Path>) -> Result<()> {
    crate::config::run_init(config_override).await
}

/// `up` — partial; F-CLI.2 wires the privilege-guarded TUN
/// setup. F-CLI.3 adds the invite parse step before the probe
/// (so operators get a typed parse error before any TUN work).
/// Full bootstrap, rotation, and SOCKS5 fallback land in
/// F-CLI.5 through F-CLI.8.
async fn handle_up(
    config_override: Option<&std::path::Path>,
    invite: Option<String>,
    daemonise: bool,
) -> Result<()> {
    tracing::info!(
        config_override = ?config_override,
        has_invite = invite.is_some(),
        daemonise,
        "up: invoking invite parse + TUN setup probe (F-CLI.3, F-CLI.2)",
    );
    let armoured = obtain_invite_string(invite)?;
    log_parsed_invite(&armoured)?;
    probe_tun_or_fallback().await
}

/// Resolve the invite string: prefer `--invite`, fall back to a
/// stdin prompt. Kept as a free fn so [`handle_up`] stays compact.
fn obtain_invite_string(supplied: Option<String>) -> Result<String> {
    if let Some(arg) = supplied {
        return Ok(arg);
    }
    crate::register::read_invite_from_stdin()
        .map_err(|err| anyhow::Error::new(err).context("up: read invite from stdin"))
}

/// Parse the armoured invite, log its issuer fingerprint, and
/// surface a typed error on malformed input. The verified
/// `SignedInvite` is *not* yet handed to a
/// `bibeam_discovery::SessionBootstrap` — that wire-up lands in
/// F-CLI.5 / F-CLI.6 once `CoordinatorPool` + `PasetoVerifier`
/// come from config.
fn log_parsed_invite(armoured: &str) -> Result<()> {
    let invite = crate::register::parse_invite(armoured)
        .map_err(|err| anyhow::Error::new(err).context("up: invite parse"))?;
    let fingerprint = issuer_fingerprint_hex(invite.issuer.as_bytes());
    tracing::info!(
        issuer_fp_blake3_prefix = %fingerprint,
        expires_at = ?invite.expires_at,
        "up: invite parsed — bootstrap wire-up lands in F-CLI.5 / F-CLI.6",
    );
    Ok(())
}

/// Render a short BLAKE3 fingerprint of the issuer's raw bytes
/// for log lines. Returns the first 16 hex characters (64 bits) —
/// matches the operator-runbook convention for redacted IDs.
fn issuer_fingerprint_hex(issuer_bytes: &[u8; 32]) -> String {
    let digest = blake3::hash(issuer_bytes);
    let prefix = &digest.as_bytes()[..8];
    hex_encode(prefix)
}

/// Lowercase hex lookup table. One byte expands to two nybbles,
/// each indexed into `HEX_LUT`. Avoids `fmt::Write` (whose
/// `Result` discards trip the workspace's strict lint gate) and
/// keeps the encoder pure and panic-free.
const HEX_LUT: &[u8; 16] = b"0123456789abcdef";

/// Encode `bytes` as lowercase hex without pulling in the `hex`
/// crate. Each input byte produces exactly two ASCII output
/// bytes, so the indexing is bounds-checked once via the LUT
/// constant.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = usize::from(*byte >> 4);
        let low = usize::from(*byte & 0x0f);
        out.push(HEX_LUT[high]);
        out.push(HEX_LUT[low]);
    }
    // SAFETY of `from_utf8_unchecked` would be sound here
    // (every HEX_LUT byte is ASCII), but #![forbid(unsafe_code)]
    // bars it; the safe constructor is a no-op validation pass.
    String::from_utf8(out).unwrap_or_default()
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

/// `status` — print the ECH policy line today (F-CLI.7). The
/// local management port's `/healthz` and `/readyz` probe lands
/// once the daemon is fully wired up; this commit gives the
/// subcommand a real, operator-visible thing to do.
#[allow(
    clippy::unused_async,
    reason = "async-shaped to keep the dispatch table uniform; later sub-items add a \
              local HTTP probe against /healthz and /readyz from this body."
)]
async fn handle_status(config_override: Option<&std::path::Path>) -> Result<()> {
    let cfg = crate::config::load_config(config_override)
        .map_err(|err| anyhow::Error::new(err).context("status: load config"))?;
    let policy = resolved_ech_policy(cfg.ech_policy.as_deref())?;
    crate::ech::print_ech_status(policy);
    Ok(())
}

/// Parse a string-typed ECH policy from the figment-loaded
/// config into the typed [`crate::ech::EchPolicy`]. `None`
/// (operator did not set the key) falls back to the typed
/// `Default` impl, which D-1 fixes at `Deferred`.
fn resolved_ech_policy(raw: Option<&str>) -> Result<crate::ech::EchPolicy> {
    use std::str::FromStr as _;
    raw.map_or_else(
        || Ok(crate::ech::EchPolicy::default()),
        |value| {
            crate::ech::EchPolicy::from_str(value)
                .map_err(|err| anyhow::Error::new(err).context("status: parse ech-policy"))
        },
    )
}

/// `config` — print the resolved config (post-figment merge).
/// Delegates to [`crate::config::run_config`].
async fn handle_config(config_override: Option<&std::path::Path>) -> Result<()> {
    crate::config::run_config(config_override).await
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
    async fn dispatch_init_writes_into_supplied_config_path() {
        // Contract: F-CLI.6's init handler writes the default
        // TOML to the path the operator supplies via --config.
        // A regression that ignored the override would mutate
        // the real ~/.config/bibeam/config.toml during tests —
        // that's the failure mode this test guards against.
        let salt: u64 = rand::random();
        let target = std::env::temp_dir().join(format!("bibeam-cli-init-{salt:016x}.toml"));
        // Ensure the path does not pre-exist (a stale leftover
        // would trip the non-overwrite guard in F-CLI.6).
        drop(std::fs::remove_file(&target));
        let target_str = target.to_string_lossy().into_owned();
        let cli = Cli::try_parse_from(["bibeam", "--config", &target_str, "init"])
            .expect("init must parse");
        dispatch(cli).await.expect("init handler must return Ok");
        let body = std::fs::read_to_string(&target).expect("init must have written the target");
        assert!(body.contains("bibeam-cli"));
        // Cleanup.
        drop(std::fs::remove_file(&target));
    }
}
