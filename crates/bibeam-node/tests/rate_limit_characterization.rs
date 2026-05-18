#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Characterization test for
//! [`bibeam_node::rate_limit::NodeRateLimiter`] residency.
//!
//! The plan's §Findings #4 names "rate-limit `DashMap` eviction policy"
//! as a design decision required before any cap-prescribing test
//! can be written. This file does NOT prescribe a cap; it documents
//! the **current** behavior — `NodeRateLimiter::check_peer` inserts
//! a fresh per-peer limiter on every distinct `PeerId`, and no
//! eviction trims the map — and locks that behavior in. When an
//! eviction policy lands in `rate_limit.rs:45-57`, this test will
//! fail at the boundary; the implementer updates the assertion with
//! the new bound.
//!
//! The map size is observed via the `Debug` impl, which `rate_limit.rs`
//! exposes as `per_peer_keys: <N>` (see `NodeRateLimiter`'s manual
//! `fmt::Debug` impl). Parsing `Debug` output is brittle — but it is
//! the only public surface the type offers for residency inspection
//! today. If the inspection contract changes (e.g. an explicit
//! `len_peer()` accessor lands), this test should switch to the
//! accessor.

use bibeam_core::PeerId;
use bibeam_node::coordinator::rate_limit::{
    RateLimitConfigError as CoordinatorRateLimitConfigError, RouteLimiter,
};
use bibeam_node::rate_limit::{
    NodeRateLimiter, RateLimitConfigError as SharedRateLimitConfigError,
};

/// The coordinator module keeps its historical public import path,
/// but the type is now the shared data-plane config-error enum.
#[test]
fn coordinator_rate_limit_config_error_reexport_is_shared_type() {
    let err: SharedRateLimitConfigError =
        RouteLimiter::new("register", 0, None).expect_err("zero budget is rejected");
    let _: CoordinatorRateLimitConfigError = err;
}

/// Admitting N distinct peers populates the per-peer map with
/// exactly N entries. No eviction trims the map; the residency
/// grows linearly with peer cardinality. Pins that behavior so the
/// future addition of an eviction policy (plan §Findings #4) is
/// surfaced loudly.
#[test]
fn peer_dashmap_size_equals_distinct_peer_count() {
    const PEERS: usize = 100;
    let limiter = NodeRateLimiter::with_default_config().expect("default config builds");

    for _ in 0..PEERS {
        // `check_peer` returns Ok at the first call for a fresh
        // peer because the GCRA bucket starts full. The Ok/Err
        // outcome is irrelevant to this test — the side effect
        // (per-peer entry inserted) is what we observe.
        drop(limiter.check_peer(PeerId::new()));
    }

    // Manual `fmt::Debug` impl in rate_limit.rs prints
    // `per_peer_keys: <N>` and `per_cohort_keys: <N>`. Parse the
    // first match.
    let debug = format!("{limiter:?}");
    let key_count = parse_per_peer_keys(&debug)
        .unwrap_or_else(|| panic!("per_peer_keys field missing from Debug output:\n{debug}"));

    assert_eq!(
        key_count, PEERS,
        "per_peer DashMap residency equals distinct peer cardinality; \
         no eviction policy in place today",
    );
}

/// Extract the integer value of `per_peer_keys: N` from the
/// `NodeRateLimiter` `Debug` output. Returns `None` if the field is
/// absent or cannot be parsed.
fn parse_per_peer_keys(debug: &str) -> Option<usize> {
    let after_label = debug.split("per_peer_keys: ").nth(1)?;
    let number_str: String = after_label.chars().take_while(char::is_ascii_digit).collect();
    number_str.parse::<usize>().ok()
}
