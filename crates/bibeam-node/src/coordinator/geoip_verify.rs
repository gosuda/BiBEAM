#![forbid(unsafe_code)]
//! `GeoLite2-Country` cross-check (R-REGION.2 / D-5 warn-only MVP).
//!
//! [`GeoipReader`] wraps the operator-supplied `MaxMind`
//! `GeoLite2-Country` `.mmdb` file and exposes [`country_code`] for
//! the coordinator's registration / heartbeat cross-check. The caller
//! (R-REGION.3, separate task) compares the returned country code
//! against the peer's declared `region` and emits an
//! `AuditKind::RegionMismatch { declared, observed }` entry on
//! mismatch. Per D-5 the response is warn-only at MVP: a mismatch is
//! observed by the audit log, admission proceeds either way.
//!
//! ## Why ISO-3166-alpha2 lowercase
//!
//! The operator-tagged `region` field (R-REGION.1) is free-form, but
//! the recommended convention is
//! `<iso3166-alpha2>-<sub-region>[-<city>]`, **lowercase**,
//! hyphen-separated (operator-runbook). The `GeoIP` DB returns the
//! ISO-3166-alpha2 country code in **upper**-case (`"US"`, `"DE"`,
//! `"KR"`). This module lower-cases the returned code so caller-side
//! comparisons can use `region.starts_with(country_code)` directly
//! without re-normalising on the hot path.
//!
//! ## Reload semantics
//!
//! The DB is hot-swappable: [`GeoipReader::reload`] opens a fresh
//! reader from the same (or a different) path and atomically replaces
//! the inner handle via [`parking_lot::RwLock`]. In-flight
//! [`country_code`] calls hold a read guard and finish against the
//! old DB; subsequent calls see the new one. This is the path the
//! operator uses to roll a refreshed `MaxMind` release without
//! restarting the coord process.
//!
//! ## Private-CIDR / anycast behaviour
//!
//! The DB has no entry for RFC1918 / link-local / loopback IPs, nor
//! for some anycast prefixes. [`country_code`] surfaces that as
//! `Ok(None)` (lookup-not-found), distinct from `Err(Geoip(...))`
//! (DB open / parse failure). The caller treats `None` as "no cross
//! check possible" — not as a mismatch.
//!
//! [`country_code`]: GeoipReader::country_code

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use bibeam_core::Error as CoreError;
use maxminddb::{Reader, geoip2};
use parking_lot::RwLock;

/// `GeoLite2-Country` reader handle with hot-reload support.
///
/// Constructed once at coord boot via [`GeoipReader::open`] and
/// shared across the registration / heartbeat hot paths. The inner
/// reader is wrapped in an [`Arc<RwLock<_>>`] so [`country_code`]
/// readers do not block each other and [`reload`] swaps the DB
/// atomically.
///
/// [`country_code`]: GeoipReader::country_code
/// [`reload`]: GeoipReader::reload
#[derive(Debug, Clone)]
pub struct GeoipReader {
    inner: Arc<RwLock<Reader<Vec<u8>>>>,
}

impl GeoipReader {
    /// Open the GeoLite2-Country `.mmdb` file at `path`.
    ///
    /// The DB is loaded fully into memory (via
    /// [`Reader::open_readfile`]) so subsequent lookups never touch
    /// disk. The file is opened once at coord boot; operators who
    /// want to roll a refreshed release call [`reload`] without
    /// restarting the process.
    ///
    /// [`reload`]: GeoipReader::reload
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Geoip`] when the file cannot be opened
    /// or the on-disk format is invalid. Per D-5, the caller treats
    /// this as a coord-startup error rather than a per-peer
    /// failure: if the DB is missing at boot, the operator either
    /// supplies one and restarts, or runs the coord without
    /// `GeoIP` cross-check (in which case this constructor is never
    /// called).
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let reader = open_reader(path)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(reader)),
        })
    }

    /// Country code for `ip`, ISO-3166-alpha2 **lowercase**.
    ///
    /// Returns `Ok(None)` when the DB has no record for `ip` — the
    /// common case for RFC1918 / link-local / loopback addresses
    /// and for anycast prefixes the DB does not cover. The caller
    /// treats `None` as "no cross-check possible" rather than as a
    /// region mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Geoip`] when the DB lookup itself
    /// fails (corrupt record, invalid decode, etc.). Per D-5 the
    /// caller folds this into an audit-log entry and admits the
    /// registration anyway.
    pub fn country_code(&self, ip: IpAddr) -> Result<Option<String>, CoreError> {
        // Two error paths fold into CoreError::Geoip via the same
        // String form: `lookup` fails when the IP version disagrees
        // with the DB metadata (e.g. an IPv6 address against an
        // IPv4-only DB); `decode` fails when the on-disk record is
        // structurally corrupt. Both are surfaced to the caller —
        // R-REGION.3 turns them into audit-log entries per D-5 and
        // admits the registration anyway.
        //
        // `geoip2::Country::country` is a struct (not Option) with
        // `#[serde(default)]` — always present after a successful
        // decode; only its inner `iso_code` field is optional. So
        // the `Ok(None)` paths here are (a) the DB has no record
        // for the IP and (b) the record exists but has no
        // country.iso_code (rare, but possible for some anycast
        // entries).
        //
        // The read guard is held for the whole borrow-chain
        // `guard → LookupResult → geoip2::Country` because the
        // decoded record borrows from the DB buffer. We copy out
        // the ISO code as an owned `String`, then explicitly
        // `drop(guard)` to release the read lock as early as the
        // borrow graph allows. The explicit drop is what
        // `clippy::significant_drop_tightening` is asking for —
        // an inner-scope drop alone is still considered "at end of
        // contained scope" by that lint.
        let guard = self.inner.read();
        let result = guard
            .lookup(ip)
            .map_err(|err| CoreError::Geoip(format!("lookup failed for {ip}: {err}")))?;
        let decoded = result
            .decode::<geoip2::Country<'_>>()
            .map_err(|err| CoreError::Geoip(format!("decode failed for {ip}: {err}")))?;
        let code = decoded.and_then(|record| record.country.iso_code.map(str::to_ascii_lowercase));
        drop(guard);
        Ok(code)
    }

    /// Reload the DB from `path`, atomically swapping the inner
    /// reader.
    ///
    /// In-flight [`country_code`] calls hold a read guard and finish
    /// against the old DB; subsequent calls see the new one. The
    /// swap is constant-time (a pointer replacement under the
    /// write guard) — operators can call this on a timer driven by
    /// [`bibeam_runtime::GeoipConfig::refresh_interval_secs`]
    /// without disrupting the registration / heartbeat hot path.
    ///
    /// [`country_code`]: GeoipReader::country_code
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Geoip`] when the new file cannot be
    /// opened. The existing reader is left in place on error so
    /// the coord keeps serving the previous DB rather than
    /// degrading to "no `GeoIP` cross-check at all".
    pub fn reload(&self, path: &Path) -> Result<(), CoreError> {
        let fresh = open_reader(path)?;
        *self.inner.write() = fresh;
        Ok(())
    }
}

/// Inner helper: open a [`Reader<Vec<u8>>`] from `path`, mapping
/// every upstream `maxminddb` error class onto [`CoreError::Geoip`].
///
/// Kept private so the `maxminddb` dependency does not leak into the
/// coord-module surface — every public method on [`GeoipReader`]
/// returns [`CoreError`] only.
fn open_reader(path: &Path) -> Result<Reader<Vec<u8>>, CoreError> {
    Reader::open_readfile(path)
        .map_err(|err| CoreError::Geoip(format!("open {} failed: {err}", path.display())))
}

#[cfg(test)]
mod tests {
    //! Unit tests for [`GeoipReader`].
    //!
    //! ## Why most lookup tests are `#[ignore]`d
    //!
    //! The `MaxMind` `GeoLite2-Country` DB cannot ship in this repo —
    //! `MaxMind`'s data license forbids redistribution (see the
    //! R-REGION.2 task notes / operator-runbook). The lookup tests
    //! below are marked `#[ignore]` with a `BIBEAM_TEST_MMDB_PATH`
    //! environment-variable hook so operators with a locally-fetched
    //! DB can run them via `cargo nextest run --run-ignored only`.
    //!
    //! The DB-independent test (`open_returns_geoip_error_for_missing_file`)
    //! always runs and pins the error-mapping contract: a missing
    //! file surfaces as [`CoreError::Geoip`], not as
    //! [`CoreError::Io`].
    use std::{env, net::Ipv4Addr, path::PathBuf};

    use bibeam_core::Error;

    use super::*;

    /// Pull the operator-supplied `.mmdb` path from
    /// `BIBEAM_TEST_MMDB_PATH`. Returns `None` (and the test
    /// short-circuits to "pass") when the env-var is unset — the
    /// CI runner does not have a DB and `#[ignore]` already gates
    /// these tests, but the env-var check keeps a stray
    /// `--run-ignored only` invocation on a CI host from failing
    /// rather than silently skipping.
    fn fixture_mmdb() -> Option<PathBuf> {
        env::var_os("BIBEAM_TEST_MMDB_PATH").map(PathBuf::from)
    }

    #[test]
    fn open_returns_geoip_error_for_missing_file() {
        // Contract: a path that does not exist surfaces as
        // CoreError::Geoip, not CoreError::Io. This pins the error
        // mapping in open_reader — a regression that switched to
        // `?` (which would route std::io::Error into CoreError::Io
        // via the existing #[from] impl) is caught here.
        let path = Path::new("/tmp/bibeam-geoip-test-this-path-does-not-exist.mmdb");
        let err = GeoipReader::open(path).expect_err("missing file must fail");
        assert!(
            matches!(err, Error::Geoip(_)),
            "missing file must surface as CoreError::Geoip, got {err:?}",
        );
    }

    #[test]
    #[ignore = "requires operator-supplied GeoLite2-Country.mmdb (MaxMind license forbids redistribution); set BIBEAM_TEST_MMDB_PATH and run with --run-ignored only"]
    fn country_code_returns_none_for_private_cidr() {
        // Contract: RFC1918 addresses have no DB entry; the API
        // surfaces that as Ok(None) (lookup-not-found), distinct
        // from Err(Geoip(...)) (DB open / parse failure). Pins the
        // private-CIDR carve-out documented on country_code().
        let Some(path) = fixture_mmdb() else {
            return;
        };
        let reader = GeoipReader::open(&path).expect("operator-supplied DB must open");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = reader.country_code(ip).expect("lookup must not fail");
        assert!(result.is_none(), "RFC1918 10.0.0.1 must lookup to Ok(None), got {result:?}");
    }

    #[test]
    #[ignore = "requires operator-supplied GeoLite2-Country.mmdb (MaxMind license forbids redistribution); set BIBEAM_TEST_MMDB_PATH and run with --run-ignored only"]
    fn reload_replaces_inner_reader() {
        // Contract: reload() with the same valid path returns Ok
        // and leaves the reader in a state where subsequent
        // country_code() calls still work. Pins the atomic-swap
        // path — a regression that left the RwLock poisoned or
        // emptied the inner Vec<u8> would be caught here on the
        // post-reload lookup.
        let Some(path) = fixture_mmdb() else {
            return;
        };
        let reader = GeoipReader::open(&path).expect("operator-supplied DB must open");
        reader.reload(&path).expect("reload of valid path must succeed");
        // Post-reload lookup: a well-known public IP should resolve
        // to some country code (the specific value depends on the
        // operator's DB, so we assert "lookup succeeds" rather than
        // a specific country).
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result = reader.country_code(ip).expect("post-reload lookup must succeed");
        assert!(result.is_some(), "post-reload lookup of 8.8.8.8 must return Some(..), got None");
    }
}
