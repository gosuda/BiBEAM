#![forbid(unsafe_code)]
//! Configuration loader on top of [`figment`].
//!
//! [`load`] merges two sources in order:
//!
//! 1. An optional TOML file (path supplied by the caller — typically
//!    via the binary's `--config` CLI flag, or the `BIBEAM_CONFIG`
//!    environment variable that the binary's CLI layer interprets).
//! 2. Environment variables with the `BIBEAM_` prefix, which override
//!    anything from the file.
//!
//! The result is deserialised into the caller's typed config struct
//! `C: DeserializeOwned`. The contract is intentionally narrow: the
//! caller defines the struct, the call returns either a populated
//! `C` or a typed error. Callers should not reach into [`figment`]
//! directly elsewhere in the codebase — the env-prefix and merge
//! order live here so they cannot drift.

use std::path::{Path, PathBuf};

use figment::{
    Figment,
    providers::{Env, Format as _, Toml},
};
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

/// Environment-variable prefix shared by every `BiBEAM` binary's
/// configuration overlay. A variable named `BIBEAM_FOO__BAR`
/// populates the `foo.bar` field of the loaded struct (the double
/// underscore is the nested-key separator; single underscores are
/// preserved inside a key name).
const ENV_PREFIX: &str = "BIBEAM_";

/// Substring inside an environment-variable name (after the
/// [`ENV_PREFIX`] is stripped) that figment treats as a nested-key
/// separator. We pick `__` so a single `_` inside a key name does
/// not get split — `BIBEAM_LOG_LEVEL` should stay flat, while
/// `BIBEAM_TRANSPORT__BIND_ADDR` should resolve to
/// `transport.bind_addr`.
const ENV_NESTED_SEP: &str = "__";

/// Failure modes for [`load`].
///
/// The `figment::Error` payload is boxed so the [`Result<C,
/// ConfigError>`] returned by [`load`] stays compact; the upstream
/// error is ~200 bytes on the stack and the `clippy::result_large_err`
/// gate fires otherwise. Boxing is a one-time allocation on the error
/// path, which is acceptable for a one-shot startup load.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Figment failed to merge, parse, or deserialise. Wraps the
    /// upstream [`figment::Error`] losslessly so the caller can
    /// inspect the chain.
    #[error("config load failed: {0}")]
    Figment(#[from] Box<figment::Error>),
}

/// Load a typed configuration struct from an optional TOML file plus
/// a `BIBEAM_`-prefixed environment overlay.
///
/// When `toml_path` is `Some(path)` and the file exists, its
/// contents are parsed first; the environment overlay then merges
/// on top. When `toml_path` is `None`, only the environment overlay
/// is consulted — useful for daemons deployed as a single binary
/// with no on-disk config.
///
/// The TOML file is loaded with [`Toml::file`]; figment's contract
/// is that a *missing* file silently produces an empty figment,
/// while a *malformed* one surfaces as
/// [`ConfigError::Figment`]. Callers that want strict "must exist"
/// semantics should `std::fs::metadata` the path themselves before
/// calling.
///
/// # Errors
///
/// Returns [`ConfigError::Figment`] when the merge, parse, or
/// deserialise step fails — for example because a TOML key is
/// malformed, an env-var-typed coercion fails, or the resulting
/// shape does not match the caller's struct.
pub fn load<C: DeserializeOwned>(toml_path: Option<&Path>) -> Result<C, ConfigError> {
    let mut figment = Figment::new();
    if let Some(path) = toml_path {
        figment = figment.merge(Toml::file(path));
    }
    figment = figment.merge(Env::prefixed(ENV_PREFIX).split(ENV_NESTED_SEP));
    figment.extract::<C>().map_err(|err| ConfigError::Figment(Box::new(err)))
}

/// `[geoip]` config block for coord-enabled `bibeam-node` instances
/// (R-REGION.2 / D-5).
///
/// The operator supplies the `MaxMind` `GeoLite2-Country` DB file at
/// deploy time; the coordinator's `geoip_verify` module loads it
/// and cross-checks each peer's declared `region` against the
/// country code derived from its observed IP. Per D-5 the MVP
/// response is warn-only: a mismatch emits an audit-log entry,
/// admission proceeds either way.
///
/// Coord-config roots should wrap this in `Option<GeoipConfig>` so
/// deployments without a `GeoIP` DB still load cleanly — `None`
/// means "`GeoIP` cross-check disabled".
///
/// # Example TOML
///
/// ```toml
/// [geoip]
/// mmdb_path = "/var/lib/bibeam/GeoLite2-Country.mmdb"
/// refresh_interval_secs = 86400
/// mismatch_allowlist_cidrs = ["10.0.0.0/8", "203.0.113.0/24"]
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct GeoipConfig {
    /// Path to the `GeoLite2-Country` `.mmdb` file. Operator-supplied
    /// — `MaxMind`'s data license forbids redistribution, so the
    /// repo never ships one. The operator-runbook documents how to
    /// obtain a fresh DB.
    pub mmdb_path: PathBuf,
    /// Refresh interval in seconds for re-loading the DB file from
    /// disk. `0` means "never auto-refresh" — the operator
    /// restarts the coord process after updating the DB.
    #[serde(default)]
    pub refresh_interval_secs: u64,
    /// CIDRs to skip the `GeoIP` cross-check for. Operators add
    /// expected-mismatch ranges here (e.g. a CDN-fronted load
    /// balancer whose edge IP geolocates differently from the
    /// node's actual hosting region). Defaults to an empty list.
    ///
    /// The strings are operator-facing — they are parsed by the
    /// caller (R-REGION.3) and not validated by this struct so a
    /// malformed entry surfaces as an admission-time warning rather
    /// than a startup-time hard fail.
    #[serde(default)]
    pub mismatch_allowlist_cidrs: Vec<String>,
}

#[cfg(test)]
#[allow(
    clippy::result_large_err,
    reason = "figment::Jail::expect_with takes `FnOnce(...) -> \
              Result<(), figment::Error>`; the closure return type \
              is fixed by upstream and we cannot box it on the way out."
)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Settings {
        listen: String,
        peers: u32,
    }

    #[test]
    fn env_overlay_overrides_missing_file() {
        // Contract: when no TOML path is supplied, the env overlay
        // alone must populate the struct. The figment env provider
        // is case-insensitive and uses `_` as a key separator after
        // the prefix is stripped; this test would catch a regression
        // that changed the prefix or the separator (both would
        // silently break every deployment).
        figment::Jail::expect_with(|jail| {
            jail.set_env("BIBEAM_LISTEN", "0.0.0.0:8080");
            jail.set_env("BIBEAM_PEERS", "7");
            let settings: Settings = load(None).unwrap();
            assert_eq!(
                settings,
                Settings {
                    listen: "0.0.0.0:8080".to_owned(),
                    peers: 7
                },
            );
            Ok(())
        });
    }

    #[test]
    fn env_overlay_overrides_file_value() {
        // Contract: env-var overlay wins over TOML file. A regression
        // that swapped merge order would let operators set a value in
        // the file and have it silently ignored by the env-var that
        // CI / config-management would normally override with — or
        // worse, the other way around: an attacker who could set an
        // env-var would not be able to win over a hard-coded TOML
        // value. Both regressions are caught here.
        figment::Jail::expect_with(|jail| {
            jail.create_file("bibeam.toml", "listen = \"127.0.0.1:1\"\npeers = 1\n")?;
            jail.set_env("BIBEAM_LISTEN", "0.0.0.0:9090");
            let settings: Settings = load(Some(Path::new("bibeam.toml"))).unwrap();
            assert_eq!(settings.listen, "0.0.0.0:9090");
            // The TOML-only value still arrives through:
            assert_eq!(settings.peers, 1);
            Ok(())
        });
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Nested {
        transport: Transport,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Transport {
        bind_addr: String,
    }

    #[test]
    fn double_underscore_separator_populates_nested_field() {
        // Contract: `BIBEAM_TRANSPORT__BIND_ADDR` populates
        // `transport.bind_addr`, while a single underscore inside
        // `bind_addr` stays as part of the key. This is the test
        // that catches a regression dropping the `.split("__")` call
        // — every operator that uses nested config keys would
        // suddenly see their env-vars ignored, and the symptom
        // would be silent: the daemon would start with the
        // TOML-file default for the nested field.
        figment::Jail::expect_with(|jail| {
            jail.set_env("BIBEAM_TRANSPORT__BIND_ADDR", "0.0.0.0:443");
            let settings: Nested = load(None).unwrap();
            assert_eq!(settings.transport.bind_addr, "0.0.0.0:443");
            Ok(())
        });
    }
}
