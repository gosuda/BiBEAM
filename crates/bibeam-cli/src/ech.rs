#![forbid(unsafe_code)]
//! ECH (Encrypted Client Hello) policy as a CLI-visible config
//! flag (F-CLI.7).
//!
//! Per D-1, the actual ECH mechanism (DNS HTTPS record lookup,
//! `rustls` ECH-extension wiring) lives in `bibeam-transport`
//! and is **deferred** until upstream rustls's ECH support
//! stabilises. This module exposes the *policy* an operator can
//! pick — `best-effort` reserves the user's intent (turn ECH on
//! once F-TRANS.2 lights up) versus `deferred` (the MVP pick,
//! standard TLS 1.3 with SNI in cleartext to the coordinator).
//!
//! The CLI does NOT load DNS HTTPS records here. That belongs
//! to F-TRANS.2 inside `bibeam-transport`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ECH policy the operator selected.
///
/// Per D-1 the MVP ships `Deferred` and never reaches for a DNS
/// HTTPS lookup. `BestEffort` is the forward-looking variant the
/// operator opts into when F-TRANS.2 lands — at that point the
/// transport layer reads this enum and decides whether to attempt
/// the ECH handshake.
///
/// Wire form is kebab-case (`"best-effort"`, `"deferred"`) to
/// match the operator-runbook convention; TOML keys and string
/// literals alike are stable across config-file edits and env
/// overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EchPolicy {
    /// Attempt ECH when the underlying transport supports it. A
    /// future stabilisation of rustls's ECH extension will let
    /// F-TRANS.2 honour this; the CLI surface is forward-looking
    /// only today.
    BestEffort,
    /// MVP pick: do not attempt ECH. The coordinator-bound TLS
    /// handshake uses standard TLS 1.3 with SNI in cleartext.
    #[default]
    Deferred,
}

impl EchPolicy {
    /// Stable kebab-case wire form for this policy.
    pub(crate) const fn as_kebab_case(self) -> &'static str {
        match self {
            Self::BestEffort => "best-effort",
            Self::Deferred => "deferred",
        }
    }
}

impl fmt::Display for EchPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_kebab_case())
    }
}

/// Error returned by [`EchPolicy::from_str`] when the input is
/// not one of the documented kebab-case names.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("ech-policy: unknown value {value:?} — accepted: \"best-effort\", \"deferred\"")]
pub(crate) struct EchPolicyParseError {
    /// The value that failed to parse.
    pub(crate) value: String,
}

impl FromStr for EchPolicy {
    type Err = EchPolicyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "best-effort" => Ok(Self::BestEffort),
            "deferred" => Ok(Self::Deferred),
            other => Err(EchPolicyParseError { value: other.to_owned() }),
        }
    }
}

/// Emit the ECH policy as a single line of operator-readable
/// status. Bracketed in `#[allow(clippy::print_stdout)]` because
/// it lands on stdout for the `status` subcommand (the operator
/// scripting hook) rather than the JSON tracing layer.
#[allow(
    clippy::print_stdout,
    reason = "user-facing CLI output, not log: `bibeam status` is the documented \
              operator scripting hook for piping the daemon's resolved policy state \
              into other tools."
)]
pub(crate) fn print_ech_status(policy: EchPolicy) {
    println!("ech-policy: {policy} (mechanism deferred to bibeam-transport per D-1)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_deferred() {
        // Contract: D-1 picks Deferred as the MVP shape.
        // A regression that swapped the default to BestEffort
        // would silently change every fresh install's TLS
        // behaviour the moment F-TRANS.2 ships.
        assert_eq!(EchPolicy::default(), EchPolicy::Deferred);
    }

    #[test]
    fn kebab_case_round_trips_through_from_str() {
        let cases = [EchPolicy::BestEffort, EchPolicy::Deferred];
        for policy in cases {
            let encoded = policy.as_kebab_case();
            let parsed = EchPolicy::from_str(encoded).expect("kebab-case must round-trip");
            assert_eq!(parsed, policy, "{encoded} did not round-trip");
        }
    }

    #[test]
    fn from_str_rejects_unknown_value() {
        let err = EchPolicy::from_str("skipped").expect_err("must reject unknown");
        assert_eq!(err.value, "skipped");
    }

    #[test]
    fn serde_uses_kebab_case_wire_form() {
        // Contract: the serde rename_all attribute means TOML
        // / JSON encode the variants in kebab-case. A regression
        // that dropped the rename_all attribute would emit
        // PascalCase, which operator-side TOML edits would not
        // round-trip.
        let serialised = serde_json::to_string(&EchPolicy::BestEffort).expect("encode");
        assert_eq!(serialised, "\"best-effort\"");
        let parsed: EchPolicy = serde_json::from_str("\"deferred\"").expect("decode");
        assert_eq!(parsed, EchPolicy::Deferred);
    }
}
