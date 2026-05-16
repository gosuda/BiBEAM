#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test fixtures use unwrap/expect in setup paths"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "test functions never document panic behaviour"
)]
//! Integration tests for §11 verification gate #5 — the D-5 warn-only
//! `GeoIP` cross-check primitive (R-REGION.2 / R-REGION.3).
//!
//! ## Scope — cross-check primitive only
//!
//! The production registration handler in
//! `crates/bibeam-node/src/coordinator/server.rs::handle_register`
//! is still stubbed at this point in the project's history (it
//! returns [`bibeam_runtime::pending_service`]; the
//! F-COORD.2/4/5 service layer that will wire the cross-check
//! into the live admission path has not landed). These tests
//! therefore cover ONLY the cross-check primitive — they pin its
//! signature, its return-value contract, and its audit-emission
//! side-effect.
//!
//! The D-5 "warn-only at MVP" guarantee resolves at TWO layers:
//!
//! 1. **API shape (this file's load-bearing assertion).**
//!    [`cross_check_on_register`] returns
//!    [`Outcome`] — a value-shaped sum, NOT
//!    `Result<(), RefusedError>`. A caller has nothing to
//!    propagate as a refusal; refusal is unrepresentable at the
//!    type system level. A future regression that switched the
//!    return type to `Result<Outcome, RefusedError>` would break
//!    these tests on the signature alone.
//!
//! 2. **Handler integration (deferred — separate later task).**
//!    Once the F-COORD.2/4/5 wiring lands the cross-check inside
//!    `handle_register`, a parallel integration test will assert
//!    that a real `POST /api/v1/register` whose declared region
//!    mismatches the geolocation still admits the peer (HTTP
//!    200) and produces the same audit row. That test is out of
//!    scope here per the task description's "F-NODE.1-9 wiring"
//!    deferral.
//!
//! Each test:
//!
//! - Stands up a fresh redb-backed [`AuditLog`] via
//!   [`helpers::audit_log_with_temp`].
//! - Builds a [`helpers::StubCountryLookup`] that returns the
//!   per-test canned country code.
//! - Calls [`cross_check_on_register`] with the per-test
//!   declared region and observed IP.
//! - Asserts the [`Outcome`] returned AND the audit-log
//!   side-effects: zero rows for `Skipped` / `Match` /
//!   `LookupFailed`, exactly one [`AuditKind::RegionMismatch`]
//!   for `Mismatch`.

mod helpers;

use core::net::{IpAddr, Ipv4Addr};

use bibeam_core::PeerId;
use bibeam_node::coordinator::audit::AuditKind;
use bibeam_node::coordinator::region_verify::{AllowlistCidrs, Outcome, cross_check_on_register};

use crate::helpers::{StubCountryLookup, audit_log_with_temp};

/// Type-aliased shape of [`cross_check_on_register`]'s signature.
///
/// Extracted into a `type` definition so the compile-time witness
/// constant below sidesteps the `clippy::type_complexity` lint.
#[allow(
    dead_code,
    reason = "The alias is read only by the compile-time witness constant \
              below; cargo's per-test dead-code lint cannot see that the \
              alias is the constant's type."
)]
type CrossCheckSignature = fn(
    Option<&dyn bibeam_node::coordinator::region_verify::CountryLookup>,
    &str,
    IpAddr,
    &AllowlistCidrs,
    &PeerId,
    &bibeam_node::coordinator::audit::AuditLog,
) -> Outcome;

/// Compile-time witness: `cross_check_on_register`'s return type
/// is [`Outcome`] — NOT a [`Result`]. A regression that switched
/// the return type to expose a refusal branch would fail to
/// compile this constant. The D-5 "no refusal" contract is
/// encoded in the type system, not in a callsite's behaviour.
const _CROSS_CHECK_RETURN_IS_OUTCOME_NOT_RESULT: CrossCheckSignature = cross_check_on_register;

/// Public-IP-shaped fixture address. Lands outside RFC1918 so the
/// `geoip_unavailable_admission_proceeds` test exercises the
/// "DB-doesn't-know-this-IP" branch by stubbing `Ok(None)` rather
/// than relying on a private-CIDR carve-out the stub does not
/// implement.
const fn fixture_public_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4))
}

#[test]
fn mismatch_audit_emitted_admission_proceeds() {
    // Contract: declared = "us-east", observed country = "kr" →
    // the cross-check emits exactly one [`AuditKind::RegionMismatch`]
    // row carrying `{ declared: "us-east", observed: "kr" }` AND
    // returns [`Outcome::Mismatch`] (NOT a refusal). Per D-5
    // upstream admission proceeds anyway — the row is the
    // operator's record, not a denial.
    let (audit, _temp) = audit_log_with_temp();
    let peer = PeerId::new();
    let stub = StubCountryLookup::some("kr");
    let allowlist = AllowlistCidrs::default();
    let outcome = cross_check_on_register(
        Some(&stub),
        "us-east",
        fixture_public_ip(),
        &allowlist,
        &peer,
        &audit,
    );

    match outcome {
        Outcome::Mismatch { declared, observed } => {
            assert_eq!(declared, "us-east");
            assert_eq!(observed, "kr");
        },
        other => panic!("expected Outcome::Mismatch, got {other:?}"),
    }

    let rows = audit.snapshot().expect("snapshot audit log");
    let mismatches: Vec<&AuditKind> = rows
        .iter()
        .map(|entry| &entry.kind)
        .filter(|kind| matches!(kind, AuditKind::RegionMismatch { .. }))
        .collect();
    assert_eq!(mismatches.len(), 1, "exactly one mismatch row expected, got {mismatches:?}");
    match mismatches[0] {
        AuditKind::RegionMismatch { declared, observed } => {
            assert_eq!(declared, "us-east");
            assert_eq!(observed, "kr");
        },
        other => panic!("expected RegionMismatch kind, got {other:?}"),
    }

    // D-5 warn-only at the cross-check primitive: the row exists
    // and the [`Outcome::Mismatch`] variant is returned by value
    // — the function signature has no `Err` branch (witnessed at
    // compile time by `_CROSS_CHECK_RETURN_IS_OUTCOME_NOT_RESULT`
    // at the file head). The downstream handler integration is a
    // separate later task per the file-level module docs.
}

#[test]
fn match_no_audit_emitted() {
    // Contract: declared = "us-east", observed country = "us" →
    // [`Outcome::Match`] AND zero audit rows. A regression that
    // emitted a row on the happy path would spam the audit log on
    // every healthy registration.
    let (audit, _temp) = audit_log_with_temp();
    let peer = PeerId::new();
    let stub = StubCountryLookup::some("us");
    let allowlist = AllowlistCidrs::default();
    let outcome = cross_check_on_register(
        Some(&stub),
        "us-east",
        fixture_public_ip(),
        &allowlist,
        &peer,
        &audit,
    );

    assert_eq!(outcome, Outcome::Match);
    let rows = audit.snapshot().expect("snapshot audit log");
    let mismatches = rows
        .iter()
        .filter(|entry| matches!(entry.kind, AuditKind::RegionMismatch { .. }))
        .count();
    assert_eq!(mismatches, 0, "match path must emit zero RegionMismatch rows");
}

#[test]
fn geoip_unavailable_admission_proceeds() {
    // Contract: per the D-5 contract documented on
    // [`Outcome::Skipped`], a stub that returns `Ok(None)`
    // ("DB doesn't know this IP", e.g. an RFC1918 / private CIDR
    // / uncovered anycast) surfaces as [`Outcome::Skipped`] and
    // emits no audit row. Missing data is NOT a mismatch.
    let (audit, _temp) = audit_log_with_temp();
    let peer = PeerId::new();
    let stub = StubCountryLookup::none();
    let allowlist = AllowlistCidrs::default();
    let outcome = cross_check_on_register(
        Some(&stub),
        "us-east",
        fixture_public_ip(),
        &allowlist,
        &peer,
        &audit,
    );

    assert_eq!(outcome, Outcome::Skipped);
    let rows = audit.snapshot().expect("snapshot");
    assert!(
        rows.iter().all(|entry| !matches!(entry.kind, AuditKind::RegionMismatch { .. })),
        "Ok(None) lookup must NOT emit a RegionMismatch row",
    );
}

#[test]
fn mismatch_allowlist_cidr_skipped() {
    // Contract: declared region MISMATCHES the stub's observed
    // country code, BUT the observed IP falls inside an
    // operator-allowlisted CIDR. The cross-check must short-
    // circuit BEFORE the audit-emission site and return
    // [`Outcome::Skipped`] with zero rows. This is the
    // operator-config'd exception per R-REGION.2/.3 (CDN edge /
    // reverse-proxy ranges that geolocate differently from the
    // node's actual hosting region).
    let (audit, _temp) = audit_log_with_temp();
    let peer = PeerId::new();
    let stub = StubCountryLookup::some("kr"); // would mismatch us-east
    // Allowlist contains the fixture IP — 203.0.113.0/24 covers
    // 203.0.113.4 the test sends.
    let allowlist = AllowlistCidrs::parse(&["203.0.113.0/24".to_owned()]);
    let outcome = cross_check_on_register(
        Some(&stub),
        "us-east",
        fixture_public_ip(),
        &allowlist,
        &peer,
        &audit,
    );

    assert_eq!(outcome, Outcome::Skipped);
    let rows = audit.snapshot().expect("snapshot audit log");
    let mismatches = rows
        .iter()
        .filter(|entry| matches!(entry.kind, AuditKind::RegionMismatch { .. }))
        .count();
    assert_eq!(
        mismatches, 0,
        "allowlist short-circuit MUST emit zero rows even when stub + region would mismatch",
    );
}
