#![forbid(unsafe_code)]
//! Configuration persistence at the platform-standard path
//! (F-CLI.6).
//!
//! [`config_dir`] resolves the per-user config directory via
//! [`directories::ProjectDirs`]. The path layout per platform is:
//!
//! - **Linux** — `~/.config/bibeam/` (honours `$XDG_CONFIG_HOME`)
//! - **macOS** — `~/Library/Application Support/bibeam/`
//! - **Windows** — `%APPDATA%\bibeam\`
//!
//! [`load_config`] is a thin wrapper over
//! [`bibeam_runtime::load_config`]: it resolves the config file
//! path (caller override → platform-standard
//! `<config_dir>/config.toml`) and delegates the figment
//! TOML+env merge to the runtime crate.
//!
//! [`write_default_config`] is what the `init` subcommand calls
//! to seed a fresh `config.toml` under the platform path. It
//! refuses to overwrite an existing file — operators who want to
//! reset their config delete the file by hand first, which is the
//! same shape every other daemon uses (`sshd_config` etc).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Filename of the user-facing config file under [`config_dir`].
const CONFIG_FILENAME: &str = "config.toml";

/// Default body of the TOML config file written by
/// [`write_default_config`]. Each line is commented out by
/// default so [`Config::default`] applies until the operator
/// uncomments a key.
const DEFAULT_CONFIG_TOML: &str = "\
# bibeam-cli — default user configuration.
#
# This file is written by `bibeam init` and merged with
# `BIBEAM_*` environment variables by figment at startup. Every
# key below is commented out so the typed Config struct's
# Default impl applies until an operator opts into an override.
#
# See the operator runbook for the meaning of each field.

# Local SOCKS5 bind address used when TUN setup fails (F-CLI.8).
# socks5_bind = \"127.0.0.1:1080\"

# ECH (Encrypted Client Hello) policy for coordinator-bound TLS.
# Accepted values: \"best-effort\", \"deferred\" (default).
# See F-CLI.7 / D-1; the mechanism itself lives in F-TRANS.2.
# ech_policy = \"deferred\"

# TUN interface name hint passed to setup_tun (F-CLI.2).
# tun_interface_name = \"bibeam0\"

# TUN interface MTU (F-CLI.2).
# tun_mtu = 1500
";

/// Errors emitted by the config helpers.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: rustc's `unreachable_pub` rejects bare `pub` on items \
              consumed only by sibling private modules; clippy disagrees. We side with \
              rustc, the load-bearing lint."
)]
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    /// No home directory is available — `directories::ProjectDirs::from`
    /// returned [`None`]. Surfaces on a misconfigured container or a
    /// process running with no `HOME` / `%APPDATA%`.
    #[error("config: no home directory available (HOME / APPDATA unset?)")]
    NoHome,
    /// `init` was asked to write a default config, but a config
    /// file already exists. F-CLI.6's contract is "init never
    /// overwrites" — the operator must delete by hand first.
    #[error("config: refusing to overwrite existing config at {path}")]
    AlreadyExists {
        /// Path that already exists.
        path: PathBuf,
    },
    /// Filesystem I/O failed.
    #[error("config: I/O error: {0}")]
    Io(#[source] std::io::Error),
    /// `figment` failed to load, merge, or deserialise.
    #[error("config: load failed: {0}")]
    Load(#[from] bibeam_runtime::ConfigError),
}

/// Typed config struct loaded from
/// `<config_dir>/config.toml` and the `BIBEAM_*` env overlay.
///
/// Every field is `Option<T>` so a partially-populated TOML or
/// env overlay does not fall over on the missing keys; the
/// `Default` impl is empty (all `None`) which means "use the
/// in-code defaults the consumer carries".
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see ConfigError for the rustc-vs-clippy rationale."
)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Config {
    /// Local SOCKS5 bind address used by the F-CLI.8 fallback.
    /// `None` -> `127.0.0.1:1080`.
    pub(crate) socks5_bind: Option<String>,
    /// ECH policy (F-CLI.7). `None` -> `crate::ech::EchPolicy::Deferred` (the F-CLI.7 default).
    pub(crate) ech_policy: Option<String>,
    /// TUN interface name hint (F-CLI.2). `None` -> `bibeam0`.
    pub(crate) tun_interface_name: Option<String>,
    /// TUN interface MTU (F-CLI.2). `None` -> `1500`.
    pub(crate) tun_mtu: Option<u16>,
}

/// Resolve the platform-standard config directory for `bibeam`.
///
/// Returns the path that holds `config.toml` (and, since
/// F-CLI.3, the session-state files).
///
/// # Errors
///
/// Returns [`ConfigError::NoHome`] when
/// `directories::ProjectDirs::from` returns [`None`] — a host
/// with no home directory available.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see ConfigError for the rustc-vs-clippy rationale."
)]
pub(crate) fn config_dir() -> Result<PathBuf, ConfigError> {
    let dirs = directories::ProjectDirs::from("", "BiBeam", "bibeam").ok_or(ConfigError::NoHome)?;
    Ok(dirs.config_dir().to_owned())
}

/// Resolve the platform-standard config file path.
///
/// Equivalent to [`config_dir`] joined with `config.toml`.
///
/// # Errors
///
/// Returns [`ConfigError::NoHome`] when no home directory is
/// available.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see ConfigError for the rustc-vs-clippy rationale."
)]
pub(crate) fn config_file_path() -> Result<PathBuf, ConfigError> {
    Ok(config_dir()?.join(CONFIG_FILENAME))
}

/// Load the typed config from a TOML file plus the `BIBEAM_*`
/// env overlay.
///
/// When `path_override` is `Some`, the supplied path is used
/// verbatim. When [`None`], the platform-standard path
/// ([`config_file_path`]) is consulted. A missing file is *not*
/// an error — figment silently produces an empty figment and
/// the env overlay alone populates the struct.
///
/// # Errors
///
/// Returns [`ConfigError::NoHome`] when no `path_override` is
/// supplied and no home directory is available;
/// [`ConfigError::Load`] for figment merge / parse / decode
/// failures.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see ConfigError for the rustc-vs-clippy rationale."
)]
pub(crate) fn load_config(path_override: Option<&Path>) -> Result<Config, ConfigError> {
    let resolved = match path_override {
        Some(path) => path.to_owned(),
        None => config_file_path()?,
    };
    bibeam_runtime::load_config::<Config>(Some(&resolved)).map_err(ConfigError::Load)
}

/// Write a fresh `config.toml` at the platform-standard path.
///
/// `path_override` lets the caller redirect the write (e.g. for
/// tests). Returns the path that was written.
///
/// # Errors
///
/// - [`ConfigError::NoHome`] when no home directory is
///   available.
/// - [`ConfigError::AlreadyExists`] when the target file
///   already exists (F-CLI.6 contract: `init` is non-destructive).
/// - [`ConfigError::Io`] on filesystem failures.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see ConfigError for the rustc-vs-clippy rationale."
)]
pub(crate) fn write_default_config(path_override: Option<&Path>) -> Result<PathBuf, ConfigError> {
    let resolved = match path_override {
        Some(path) => path.to_owned(),
        None => config_file_path()?,
    };
    if resolved.exists() {
        return Err(ConfigError::AlreadyExists { path: resolved });
    }
    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent).map_err(ConfigError::Io)?;
    }
    std::fs::write(&resolved, DEFAULT_CONFIG_TOML).map_err(ConfigError::Io)?;
    Ok(resolved)
}

/// Run the `init` subcommand: write the default config, log the
/// path. Bundled here (rather than inlined in cli.rs) so the
/// dispatch handler stays under the cognitive-complexity cap as
/// future sub-items extend it.
///
/// # Errors
///
/// Propagates any [`ConfigError`] verbatim, wrapped in an
/// "init" context.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see ConfigError for the rustc-vs-clippy rationale."
)]
#[allow(
    clippy::unused_async,
    reason = "async-shaped to keep the cli.rs dispatch table uniform; later sub-items \
              that add filesystem permission-tweaks or daemonisation handshakes here \
              benefit from staying inside the tokio runtime."
)]
pub(crate) async fn run_init(path_override: Option<&Path>) -> Result<()> {
    let written = write_default_config(path_override).context("init: write default config")?;
    tracing::info!(
        path = %written.display(),
        "init: default config written",
    );
    Ok(())
}

/// Run the `config` subcommand: load the resolved config, log
/// its TOML rendering. Bundled here so cli.rs's dispatch handler
/// stays compact.
///
/// # Errors
///
/// Propagates any [`ConfigError`] verbatim, wrapped in a
/// "config" context. Also surfaces TOML serialisation errors
/// (vanishingly rare for a struct of `Option<...>` fields).
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see ConfigError for the rustc-vs-clippy rationale."
)]
#[allow(
    clippy::unused_async,
    reason = "async-shaped to keep the cli.rs dispatch table uniform; the figment loader \
              is sync today but later sub-items may add async I/O (e.g. fetching \
              dynamic config from a remote agent) here."
)]
pub(crate) async fn run_config(path_override: Option<&Path>) -> Result<()> {
    let config = load_config(path_override).context("config: load resolved config")?;
    let rendered =
        toml::to_string_pretty(&config).context("config: render resolved config as TOML")?;
    log_resolved_config(&rendered);
    Ok(())
}

/// Emit the resolved config to stdout. The `config` subcommand
/// is an operator-script hook ("dump my current config"), so it
/// writes to stdout rather than a tracing log line. The same
/// `#[allow(clippy::print_stdout)]` carve-out the `version`
/// handler uses applies here.
#[allow(
    clippy::print_stdout,
    reason = "user-facing CLI output: `bibeam config` is the documented operator hook \
              for piping the resolved config into other tools."
)]
fn log_resolved_config(rendered: &str) {
    println!("{rendered}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-test scratch dir under `std::env::temp_dir`. Mirrors
    /// the helper in `register.rs` — keeps the dep graph free
    /// of `tempfile` for one tiny utility.
    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let salt: u64 = rand::random();
            let path = std::env::temp_dir().join(format!("bibeam-cli-cfg-{tag}-{salt:016x}"));
            std::fs::create_dir_all(&path).expect("create scratch dir");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.path));
        }
    }

    #[test]
    fn config_dir_resolves_under_known_project_path() {
        // Contract: config_dir's path includes the `bibeam`
        // project identifier under whatever home it lands at.
        // A regression that renamed the project string would
        // silently relocate every operator's config file.
        let Ok(resolved_path) = config_dir() else {
            return; // headless CI may lack HOME; skip.
        };
        let path_str = resolved_path.to_string_lossy().to_lowercase();
        assert!(
            path_str.contains("bibeam"),
            "config_dir must mention `bibeam` somewhere in its path, got {resolved_path:?}",
        );
    }

    #[test]
    fn write_default_config_creates_file() {
        let tmp = ScratchDir::new("write");
        let target = tmp.join("config.toml");
        let written = write_default_config(Some(&target)).expect("write");
        assert_eq!(written, target);
        let body = std::fs::read_to_string(&target).expect("read back");
        assert!(body.contains("bibeam-cli"), "default config must mention bibeam-cli");
    }

    #[test]
    fn write_default_config_refuses_overwrite() {
        // Contract: init is non-destructive. A regression that
        // silently overwrote a tweaked config would erase every
        // operator's tuning the next time they re-ran `init`.
        let tmp = ScratchDir::new("overwrite");
        let target = tmp.join("config.toml");
        std::fs::write(&target, "pre-existing\n").expect("seed");
        let err = write_default_config(Some(&target)).expect_err("must refuse");
        assert!(matches!(err, ConfigError::AlreadyExists { .. }));
        let body = std::fs::read_to_string(&target).expect("read back");
        assert_eq!(body, "pre-existing\n", "existing file must be untouched");
    }

    #[test]
    fn load_config_reads_a_toml_file() {
        // Contract: load_config picks up the keys an operator
        // sets in their TOML file. The Config struct's
        // Option-typed shape means missing keys stay None.
        let tmp = ScratchDir::new("load");
        let target = tmp.join("config.toml");
        std::fs::write(&target, "socks5_bind = \"127.0.0.1:9999\"\ntun_mtu = 1380\n")
            .expect("seed");
        let cfg = load_config(Some(&target)).expect("load");
        assert_eq!(cfg.socks5_bind.as_deref(), Some("127.0.0.1:9999"));
        assert_eq!(cfg.tun_mtu, Some(1380));
        assert!(cfg.ech_policy.is_none());
        assert!(cfg.tun_interface_name.is_none());
    }

    #[test]
    fn load_config_returns_default_when_file_absent() {
        // Contract: figment treats a missing file as an empty
        // figment, so the typed Config falls back to its
        // Default. This is what runtime startup relies on:
        // a fresh install has no `config.toml` and must come
        // up with sane defaults.
        let tmp = ScratchDir::new("absent");
        let target = tmp.join("config.toml");
        // Do NOT write the file.
        let cfg = load_config(Some(&target)).expect("load");
        assert!(cfg.socks5_bind.is_none());
        assert!(cfg.ech_policy.is_none());
        assert!(cfg.tun_interface_name.is_none());
        assert!(cfg.tun_mtu.is_none());
    }
}
