#![forbid(unsafe_code)]
//! `GeoIP` region cross-check wiring (R-REGION.3 / D-5 warn-only MVP).
//!
//! Where [`super::geoip_verify::GeoipReader`] owns the DB handle and
//! the lookup primitive, this module owns the integration:
//!
//! - [`cross_check_on_register`] runs at coord registration time. It
//!   compares the registrant's declared region against the
//!   country code returned by the `GeoIP` lookup for the observed
//!   source IP and, on mismatch, appends an
//!   [`super::audit::AuditKind::RegionMismatch`] row through the
//!   supplied [`super::audit::AuditLog`]. Per D-5 admission proceeds
//!   regardless; the row is the operator's record of the divergence,
//!   not a refusal.
//! - [`cross_check_on_heartbeat`] runs on every heartbeat tick (the
//!   coord's existing heartbeat loop). On a successful `Match` the
//!   returned `Option<Timestamp>` is `Some(Timestamp::now())` so the
//!   caller can bump `region_last_verified_at` on the in-memory peer
//!   record. On the high-frequency heartbeat path DB-lookup failures
//!   log at [`tracing::Level::DEBUG`] (vs the registration path's
//!   `tracing::warn`) so a stuck DB does not spam the operator log
//!   stream once per second.
//!
//! ## Operator-allowlisted CIDRs
//!
//! Deployments behind a reverse-proxy / CDN edge see an observed IP
//! that geolocates differently from the node's actual hosting region.
//! The operator-runbook documents adding the affected ranges to
//! [`bibeam_runtime::GeoipConfig::mismatch_allowlist_cidrs`];
//! [`AllowlistCidrs::parse`] turns the operator-supplied strings into
//! a [`Vec<IpNet>`] once at config-load time and surfaces every
//! malformed entry through a `tracing::warn` at that one site. The
//! hot paths then take `&AllowlistCidrs` and run a constant-time
//! contains check — no per-registration / per-heartbeat parsing,
//! no repeated warnings.
//!
//! ## D-5 warn-only at MVP
//!
//! The post-MVP strict-mode escalation lives outside this module —
//! see the §11 R-2 plan. Today every outcome falls through to
//! "admit"; only the audit-log side-effect differs.

use core::net::IpAddr;
use std::sync::Arc;

use bibeam_core::{Error as CoreError, PeerId, Timestamp};
use ipnet::IpNet;

use super::audit::AuditLog;
use super::geoip_verify::GeoipReader;

/// Outcome of one cross-check call.
///
/// All four variants surface the same admission decision (admit) at
/// MVP per D-5. The variants encode WHY the cross-check returned —
/// `Match` and `Skipped` are silent; `Mismatch` and `LookupFailed`
/// emit a side-effect (audit row + tracing event) before returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The `GeoIP` DB's country code matched the declared region's
    /// ISO-3166-alpha2 prefix (case-insensitive). No side-effect.
    Match,
    /// The cross-check was skipped because either:
    /// - no `GeoIP` lookup is configured (no `mmdb_path` in the
    ///   operator config — the caller passed `None`), or
    /// - the observed IP matched an operator-allowlisted CIDR, or
    /// - the declared region was empty (registrant did not declare
    ///   one; the empty-string sentinel mirrors
    ///   [`bibeam_discovery::PeerRecord::region`]), or
    /// - the DB has no record for the observed IP (RFC1918 / loopback
    ///   / uncovered anycast — the lookup returned `Ok(None)`).
    Skipped,
    /// The `GeoIP` DB's country code did NOT match the declared
    /// region. The audit-log row has already been appended; per D-5
    /// admission proceeds anyway. Payload captures the same country
    /// codes the audit row stamped.
    Mismatch {
        /// Region the registrant declared.
        declared: String,
        /// Country code (lowercased) the `GeoIP` DB returned for
        /// the observed source IP.
        observed: String,
    },
    /// The `GeoIP` DB lookup itself failed (DB read / decode error).
    /// Logged at the appropriate level (warn for registration, debug
    /// for heartbeat) and admission still proceeds — the operator's
    /// signal is the tracing event, not a failed admission.
    LookupFailed,
}

/// Trait the cross-check calls into for the country-code lookup.
///
/// In production the implementor is a thin wrapper around
/// [`GeoipReader::country_code`]; in tests it is a closure that
/// returns a stubbed `Result<Option<String>, CoreError>` so the
/// cross-check's match / mismatch / lookup-failure branches are
/// exercised without a real `MaxMind` DB.
pub trait CountryLookup {
    /// Resolve `ip` to its lowercased ISO-3166-alpha2 country code.
    /// `Ok(None)` is "no record for `ip`"; `Err(_)` is a DB-level
    /// failure (open / decode / corrupt).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Geoip`] when the lookup itself fails.
    fn country_code(&self, ip: IpAddr) -> Result<Option<String>, CoreError>;
}

impl CountryLookup for GeoipReader {
    fn country_code(&self, ip: IpAddr) -> Result<Option<String>, CoreError> {
        Self::country_code(self, ip)
    }
}

/// Pre-parsed mismatch-allowlist.
///
/// Built once at config-load time via [`AllowlistCidrs::parse`] so
/// the hot paths run a constant-time `IpNet::contains` walk without
/// re-parsing or re-warning on every registration / heartbeat.
#[derive(Debug, Clone, Default)]
pub struct AllowlistCidrs {
    nets: Arc<[IpNet]>,
}

impl AllowlistCidrs {
    /// Parse the operator-supplied CIDR strings into [`IpNet`] once.
    /// Malformed entries surface a single `tracing::warn` and are
    /// dropped — per R-REGION.2 a bad entry must NOT turn a
    /// per-registration warning into a startup hard-fail.
    #[must_use]
    pub fn parse(raw: &[String]) -> Self {
        let mut nets: Vec<IpNet> = Vec::with_capacity(raw.len());
        for entry in raw {
            match entry.parse::<IpNet>() {
                Ok(net) => nets.push(net),
                Err(err) => {
                    tracing::warn!(
                        cidr = %entry,
                        error = %err,
                        "ignoring malformed mismatch_allowlist_cidrs entry; \
                         check operator-runbook",
                    );
                },
            }
        }
        Self {
            nets: Arc::from(nets.into_boxed_slice()),
        }
    }

    /// Return `true` when `observed_ip` is contained in any of the
    /// parsed allowlist CIDRs.
    #[must_use]
    pub fn contains(&self, observed_ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(&observed_ip))
    }

    /// Number of valid CIDR entries in the allowlist; intended for
    /// tests + metrics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nets.len()
    }

    /// Whether the allowlist holds zero valid CIDR entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }
}

/// Cross-check at registration time (R-REGION.3).
///
/// Returns the outcome and, when `Outcome::Mismatch`, appends one
/// audit-log row through `audit_log`. The returned variant is
/// informational — admission proceeds in every branch per D-5.
///
/// `lookup` is `Option<&dyn CountryLookup>` because the operator may
/// run the coord without a configured `mmdb_path`; that branch
/// returns `Outcome::Skipped` immediately, no DB touch and no audit
/// row.
pub fn cross_check_on_register(
    lookup: Option<&dyn CountryLookup>,
    declared_region: &str,
    observed_ip: IpAddr,
    allowlist: &AllowlistCidrs,
    peer_id: &PeerId,
    audit_log: &AuditLog,
) -> Outcome {
    let request = CrossCheckRequest {
        lookup,
        declared_region,
        observed_ip,
        allowlist,
        peer_id,
        audit_log,
    };
    dispatch(&request, LookupSite::Register).0
}

/// Cross-check on the heartbeat tick (R-REGION.3).
///
/// Same shape as [`cross_check_on_register`] but tuned for the
/// high-frequency heartbeat path:
///
/// - on `Outcome::Match` the returned `Option<Timestamp>` is
///   `Some(Timestamp::now())` so the caller can bump
///   `region_last_verified_at` on the in-memory peer record,
/// - DB-lookup failures log at [`tracing::Level::DEBUG`] (not warn)
///   so a stuck DB does not spam the operator log stream once per
///   second.
///
/// Mismatch handling is identical to registration — one audit row
/// per heartbeat tick that observes a divergence. The audit cadence
/// matches the §11 R-3 R-FLOOR precedent (one row per gate poll).
#[must_use]
pub fn cross_check_on_heartbeat(
    lookup: Option<&dyn CountryLookup>,
    declared_region: &str,
    observed_ip: IpAddr,
    allowlist: &AllowlistCidrs,
    peer_id: &PeerId,
    audit_log: &AuditLog,
) -> (Outcome, Option<Timestamp>) {
    let request = CrossCheckRequest {
        lookup,
        declared_region,
        observed_ip,
        allowlist,
        peer_id,
        audit_log,
    };
    dispatch(&request, LookupSite::Heartbeat)
}

/// Private bundle of the six borrows the two entry points share. The
/// public API takes the six borrows directly so each call site reads
/// at its argument list — this struct only exists so the internal
/// dispatch helper does not re-thread six arguments through every
/// branch (and to keep [`cognitive_complexity`] at the dispatcher
/// site under threshold).
struct CrossCheckRequest<'a> {
    lookup: Option<&'a dyn CountryLookup>,
    declared_region: &'a str,
    observed_ip: IpAddr,
    allowlist: &'a AllowlistCidrs,
    peer_id: &'a PeerId,
    audit_log: &'a AuditLog,
}

/// Call-site discriminator for [`dispatch`]'s tracing-level + match
/// behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupSite {
    Register,
    Heartbeat,
}

/// Result of the dispatcher's "pull a country code, or short-circuit"
/// stage. `Country` is the happy path (lookup returned `Ok(Some)`);
/// `ShortCircuit` is any of the four reasons the cross-check stops
/// before comparing strings.
enum CountryOrSkip {
    Country(String),
    ShortCircuit(Outcome),
}

/// Walk the four short-circuit branches (no lookup, empty region,
/// allowlisted IP, no DB record) and return either the observed
/// country code or the [`Outcome`] the caller should surface. Split
/// out so [`dispatch`] stays under the cognitive-complexity
/// threshold.
fn pull_observed_country(request: &CrossCheckRequest<'_>, site: LookupSite) -> CountryOrSkip {
    let Some(reader) = request.lookup else {
        return CountryOrSkip::ShortCircuit(Outcome::Skipped);
    };
    if request.declared_region.is_empty() {
        return CountryOrSkip::ShortCircuit(Outcome::Skipped);
    }
    if request.allowlist.contains(request.observed_ip) {
        return CountryOrSkip::ShortCircuit(Outcome::Skipped);
    }
    match reader.country_code(request.observed_ip) {
        Ok(Some(country)) => CountryOrSkip::Country(country),
        Ok(None) => CountryOrSkip::ShortCircuit(Outcome::Skipped),
        Err(err) => {
            log_lookup_failure(&err, site);
            CountryOrSkip::ShortCircuit(Outcome::LookupFailed)
        },
    }
}

#[allow(
    clippy::cognitive_complexity,
    reason = "Inflated by two `tracing::warn!`/`debug!` macro expansions \
              inside the match arms; the function's own logic is one \
              match. Same precedent as the runtime crate's \
              redaction_layer log helper."
)]
fn log_lookup_failure(err: &CoreError, site: LookupSite) {
    match site {
        LookupSite::Register => {
            tracing::warn!(
                error = %err,
                "geoip lookup failed at registration; admission proceeds (D-5 warn-only)",
            );
        },
        LookupSite::Heartbeat => {
            tracing::debug!(
                error = %err,
                "geoip lookup failed on heartbeat; admission proceeds (D-5 warn-only)",
            );
        },
    }
}

/// Body of both cross-check entry points. Splitting the warn-vs-debug
/// tracing dispatch and the `verified_at` return into one function
/// keeps the two sites in lockstep (a regression on one would
/// otherwise need to be re-fixed on the other).
fn dispatch(request: &CrossCheckRequest<'_>, site: LookupSite) -> (Outcome, Option<Timestamp>) {
    let observed_country = match pull_observed_country(request, site) {
        CountryOrSkip::Country(country) => country,
        CountryOrSkip::ShortCircuit(outcome) => return (outcome, None),
    };
    if region_matches_country(request.declared_region, &observed_country) {
        let verified_at = match site {
            LookupSite::Register => None,
            LookupSite::Heartbeat => Some(Timestamp::now()),
        };
        return (Outcome::Match, verified_at);
    }
    if let Err(err) = request.audit_log.record_region_mismatch(
        request.peer_id,
        request.observed_ip,
        request.declared_region,
        &observed_country,
    ) {
        tracing::error!(
            error = %err,
            site = ?site,
            "audit: RegionMismatch append failed",
        );
    }
    let outcome = Outcome::Mismatch {
        declared: request.declared_region.to_owned(),
        observed: observed_country,
    };
    (outcome, None)
}

/// Return `true` when `declared_region` starts with the
/// ISO-3166-alpha2 prefix matching `country_code` (case-insensitive).
///
/// `GeoIP` returns ISO-3166-alpha2 uppercase; the
/// [`super::geoip_verify::GeoipReader::country_code`] hot path
/// already lowercases the return. The recommended `region`
/// convention is
/// `<iso3166-alpha2>-<sub-region>[-<city>]` lowercase
/// (operator-runbook). A leading exact prefix avoids the false
/// positive where a region tagged `"usa-east"` would accidentally
/// match the country code `"us"` — the function only returns true
/// when the next character is either the end of the region string or
/// the `-` separator the operator-runbook documents.
fn region_matches_country(declared_region: &str, country_code: &str) -> bool {
    let region = declared_region.to_ascii_lowercase();
    let country = country_code.to_ascii_lowercase();
    if !region.starts_with(&country) {
        return false;
    }
    let rest = &region[country.len()..];
    rest.is_empty() || rest.starts_with('-')
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use bibeam_core::{PeerId, RedactionKey};
    use core::net::Ipv4Addr;

    use super::*;
    use crate::coordinator::audit::{AuditKind, AuditLog};

    fn audit_log_with_temp() -> (AuditLog, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let key = Arc::new(RedactionKey::from_bytes([0x42; 32]));
        let log = AuditLog::open(temp.path(), key).expect("open audit log");
        (log, temp)
    }

    /// Test-only [`CountryLookup`] that returns the value the test
    /// pre-loaded — covers the Ok(Some) / Ok(None) / Err(_) branches
    /// without depending on a `MaxMind` DB. Wrapped in a `Cell` so
    /// the lookup can be re-armed mid-test for the heartbeat-cadence
    /// assertion.
    struct StubLookup {
        value: Cell<Option<Result<Option<String>, CoreError>>>,
    }

    impl StubLookup {
        fn new(result: Result<Option<String>, CoreError>) -> Self {
            Self { value: Cell::new(Some(result)) }
        }
    }

    impl CountryLookup for StubLookup {
        fn country_code(&self, _ip: IpAddr) -> Result<Option<String>, CoreError> {
            // Each call consumes one armed value; re-arm with the
            // last successful return so subsequent calls in the
            // same test stay deterministic.
            let armed = self.value.take().unwrap_or(Ok(None));
            let cloned = match &armed {
                Ok(value) => Ok(value.clone()),
                Err(err) => Err(CoreError::Geoip(err.to_string())),
            };
            self.value.set(Some(armed));
            cloned
        }
    }

    fn fixture_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4))
    }

    #[test]
    fn register_skipped_when_lookup_is_none() {
        // Contract: with no `Option<&dyn CountryLookup>` the cross-
        // check is a no-op — no audit row, no admission impact.
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let allowlist = AllowlistCidrs::default();
        let outcome =
            cross_check_on_register(None, "us-east", fixture_ip(), &allowlist, &peer, &log);
        assert_eq!(outcome, Outcome::Skipped);
        assert!(log.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn register_skipped_when_declared_region_empty() {
        // Contract: empty declared region matches the
        // PeerRecord/RelayRecord/ExitRecord "registrant did not
        // declare one" sentinel; no cross-check possible.
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Ok(Some("kr".to_owned())));
        let allowlist = AllowlistCidrs::default();
        let outcome =
            cross_check_on_register(Some(&stub), "", fixture_ip(), &allowlist, &peer, &log);
        assert_eq!(outcome, Outcome::Skipped);
        assert!(log.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn register_skipped_when_observed_ip_allowlisted() {
        // Contract: an observed IP that falls inside any allowlist
        // CIDR skips the cross-check — the operator configured this
        // range as expected-mismatch (CDN edge, etc.).
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Ok(Some("kr".to_owned())));
        let allowlist = AllowlistCidrs::parse(&["203.0.113.0/24".to_owned()]);
        let outcome =
            cross_check_on_register(Some(&stub), "us-east", fixture_ip(), &allowlist, &peer, &log);
        assert_eq!(outcome, Outcome::Skipped);
        assert!(log.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn register_skipped_when_db_has_no_record() {
        // Contract: `Ok(None)` from the lookup (RFC1918, anycast)
        // surfaces as Skipped — not Mismatch. Catches a regression
        // that treated absence-of-record as a mismatch (which would
        // spam audit rows for every loopback heartbeat).
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Ok(None));
        let allowlist = AllowlistCidrs::default();
        let outcome =
            cross_check_on_register(Some(&stub), "us-east", fixture_ip(), &allowlist, &peer, &log);
        assert_eq!(outcome, Outcome::Skipped);
        assert!(log.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn register_match_emits_no_audit_row() {
        // Contract: a successful match short-circuits before the
        // audit-emission site. A regression that called
        // `record_region_mismatch` on the happy path would spam
        // the audit log on every healthy registration.
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Ok(Some("us".to_owned())));
        let allowlist = AllowlistCidrs::default();
        let outcome =
            cross_check_on_register(Some(&stub), "us-east", fixture_ip(), &allowlist, &peer, &log);
        assert_eq!(outcome, Outcome::Match);
        assert!(log.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn register_mismatch_emits_audit_row_and_admits() {
        // Contract: declared `us-east` vs observed `kr` emits one
        // [`AuditKind::RegionMismatch`] row with the matching
        // declared / observed pair, AND returns Outcome::Mismatch.
        // Per D-5 admission proceeds upstream regardless — this
        // test pins the audit-emission side-effect + variant shape.
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Ok(Some("kr".to_owned())));
        let allowlist = AllowlistCidrs::default();
        let outcome =
            cross_check_on_register(Some(&stub), "us-east", fixture_ip(), &allowlist, &peer, &log);
        match outcome {
            Outcome::Mismatch { declared, observed } => {
                assert_eq!(declared, "us-east");
                assert_eq!(observed, "kr");
            },
            other => panic!("expected Outcome::Mismatch, got {other:?}"),
        }
        let rows = log.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 1);
        let entry = &rows[0];
        match &entry.kind {
            AuditKind::RegionMismatch { declared, observed } => {
                assert_eq!(declared, "us-east");
                assert_eq!(observed, "kr");
            },
            other => panic!("expected RegionMismatch row, got {other:?}"),
        }
        assert!(entry.peer_token.is_some());
        assert!(entry.ip_token.is_some());
        // The variant carries the payload — detail_json stays empty
        // (mirrors the NoAnonymousPathAvailable precedent).
        assert!(entry.detail_json.is_empty());
    }

    #[test]
    fn register_lookup_failure_returns_lookup_failed() {
        // Contract: a DB read failure surfaces as Outcome::LookupFailed
        // with no audit row — the operator's signal is the tracing
        // event captured at the call site (warn for registration).
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Err(CoreError::Geoip("db corrupt".to_owned())));
        let allowlist = AllowlistCidrs::default();
        let outcome =
            cross_check_on_register(Some(&stub), "us-east", fixture_ip(), &allowlist, &peer, &log);
        assert_eq!(outcome, Outcome::LookupFailed);
        assert!(log.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn heartbeat_match_returns_verified_at_timestamp() {
        // Contract: the heartbeat path returns
        // `Some(Timestamp::now())` on Match so the caller can bump
        // `region_last_verified_at` on the in-memory peer record.
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Ok(Some("us".to_owned())));
        let allowlist = AllowlistCidrs::default();
        let before = Timestamp::now();
        let (outcome, verified_at) =
            cross_check_on_heartbeat(Some(&stub), "us-east", fixture_ip(), &allowlist, &peer, &log);
        let after = Timestamp::now();
        assert_eq!(outcome, Outcome::Match);
        let stamp = verified_at.expect("match path must surface verified_at");
        assert!(stamp.as_offset_date_time() >= before.as_offset_date_time());
        assert!(stamp.as_offset_date_time() <= after.as_offset_date_time());
        assert!(log.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn heartbeat_mismatch_emits_audit_row_and_does_not_bump_verified_at() {
        // Contract: D-5 warn-only on the heartbeat path mirrors
        // registration — declared=us-east, observed=kr-seoul lookup
        // (returns `kr`) emits one audit row, returns Mismatch, and
        // the caller's verified_at field is NOT bumped (the stamp
        // belongs to the last successful match).
        let (log, _temp) = audit_log_with_temp();
        let peer = PeerId::new();
        let stub = StubLookup::new(Ok(Some("kr".to_owned())));
        let allowlist = AllowlistCidrs::default();
        let (outcome, verified_at) =
            cross_check_on_heartbeat(Some(&stub), "us-east", fixture_ip(), &allowlist, &peer, &log);
        match outcome {
            Outcome::Mismatch { declared, observed } => {
                assert_eq!(declared, "us-east");
                assert_eq!(observed, "kr");
            },
            other => panic!("expected Outcome::Mismatch, got {other:?}"),
        }
        assert!(verified_at.is_none(), "mismatch path must NOT bump verified_at");
        let rows = log.snapshot().expect("snapshot");
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].kind, AuditKind::RegionMismatch { .. }));
    }

    #[test]
    fn allowlist_parse_drops_malformed_entries_without_failing() {
        // Contract: a malformed CIDR string surfaces a tracing::warn
        // at parse time and is silently dropped — per R-REGION.2 it
        // must NOT turn a per-registration warning into a startup
        // hard-fail. The valid entry survives.
        let raw = vec!["not-a-cidr".to_owned(), "10.0.0.0/8".to_owned(), "garbage".to_owned()];
        let allowlist = AllowlistCidrs::parse(&raw);
        assert_eq!(allowlist.len(), 1);
        assert!(allowlist.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!allowlist.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn region_matches_country_accepts_exact_and_subregion() {
        // Contract: starts-with check honours the
        // `<iso3166-alpha2>-<sub-region>` convention. `"us"` country
        // matches `"us"`, `"us-east"`, `"us-west-pdx"`; does NOT
        // match `"usa-east"`.
        assert!(region_matches_country("us", "us"));
        assert!(region_matches_country("us-east", "us"));
        assert!(region_matches_country("us-west-pdx", "us"));
        assert!(!region_matches_country("usa-east", "us"));
        assert!(!region_matches_country("kr-seoul", "us"));
    }

    #[test]
    fn region_matches_country_is_case_insensitive() {
        // Contract: the `GeoIP` reader lowercases its return and the
        // operator-runbook recommends lowercase regions, but we
        // tolerate operator-typo'd uppercase tags so a single bad
        // entry does not surface as a mismatch.
        assert!(region_matches_country("US-EAST", "us"));
        assert!(region_matches_country("Us-East", "US"));
    }
}
