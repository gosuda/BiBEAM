#![forbid(unsafe_code)]
#![allow(
    dead_code,
    reason = "Helpers shared across integration test binaries; cargo flags \
              per-binary unused items even when one of the consumer binaries \
              exercises every helper."
)]
#![allow(
    unreachable_pub,
    reason = "Integration-test helper module: `mod helpers;` makes every \
              symbol crate-internal to the consuming test binary, so `pub` \
              is the natural visibility for the helpers' API; the lint's \
              `pub(crate)` suggestion does not change semantics here."
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "Integration-test fixtures unwrap/expect/panic in setup paths."
)]
//! Cross-test fixture helpers for the bibeam-node integration suite.
//!
//! Three integration test binaries (`region_routing_e2e`,
//! `multihop_e2e`, `geoip_verify_e2e`) share fixture-building code for
//! the per-region cohort state used by §11 R-3 R-FLOOR + R-MULTIHOP +
//! R-REGION verification. The helpers in this module wire a fresh
//! [`AdmissionGate`], a fresh redb-backed [`AuditLog`], and an
//! [`InMemoryRegionView`] in lockstep so each test focuses on its own
//! contract assertion instead of re-deriving the fixture-build steps.
//!
//! Per Rust integration-test idiom each consumer file declares
//! `mod helpers;` which loads `tests/helpers/mod.rs`. Items below are
//! tagged `#[allow(dead_code)]` because cargo runs the per-binary
//! dead-code lint independently — a helper used by binaries `A` and
//! `B` is still "unused" inside binary `C`.

use core::net::IpAddr;
use std::sync::Arc;

use bibeam_core::{CohortId, Error as CoreError, NodeId, PeerId, RedactionKey, Timestamp};
use bibeam_crypto::WgSecretKey;
use bibeam_node::coordinator::admission_gate::{AdmissionGate, ExitRegionLookup};
use bibeam_node::coordinator::audit::AuditLog;
use bibeam_node::coordinator::cohorts::CohortRecord;
use bibeam_node::coordinator::multihop::{
    ClientHandle, ClientLookup, ExitCandidate, ForwarderCandidate, InMemoryRegionView,
};
use bibeam_node::coordinator::region_verify::CountryLookup;
use core::net::{Ipv4Addr, SocketAddr};
use time::Duration;

/// Canonical per-position anonymity floor used across every fixture
/// — `29` *other* in-role flows = `30`-member set when the requester
/// is counted. Mirrors `multihop::tests::FLOOR` and the
/// `admission_gate` two-region precedent.
pub const FLOOR: u32 = 30;

/// `MultiHopBuilder` configures its floor in "other in-role flows"
/// terms (the requester is the 30th); that is `FLOOR - 1`.
pub const PER_POSITION_FLOOR: usize = (FLOOR as usize).saturating_sub(1);

/// Open a fresh in-memory audit log + its backing tempfile. The
/// tempfile is returned alongside the log because the redb file is
/// reaped when the tempfile drops; tests bind both values.
#[must_use]
pub fn audit_log_with_temp() -> (AuditLog, tempfile::NamedTempFile) {
    let temp = tempfile::NamedTempFile::new().expect("tempfile");
    let key = Arc::new(RedactionKey::from_bytes([0x42; 32]));
    let log = AuditLog::open(temp.path(), key).expect("open audit log");
    (log, temp)
}

/// Build a fresh empty [`CohortRecord`] with a single fixture exit
/// and a far-future rotation deadline. Matches the in-module
/// `cohort_with` helper in `admission_gate::tests`.
#[must_use]
pub fn cohort_with(members: Vec<PeerId>) -> CohortRecord {
    CohortRecord {
        members,
        exits: vec![NodeId::new()],
        rotation_deadline: Timestamp::from_offset_date_time(
            Timestamp::now().into_inner() + Duration::minutes(15),
        ),
        region: String::new(),
    }
}

/// The "no exit knows its region" lookup the in-module gate tests use.
pub fn no_region_lookup() -> ExitRegionLookup<'static> {
    &|_| None
}

/// Loopback v4 socket on a caller-supplied octet/port. Each fixture
/// picks distinct octet+port pairs so the multi-hop e2e tests can
/// share helpers without socket-address collisions.
#[must_use]
pub const fn fixture_socket(octet: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet)), port)
}

/// One exit candidate with a `cohort_size` field that reflects the
/// number of *other* in-role flows the exit's cohort sees right now.
/// Pass `PER_POSITION_FLOOR + 1` for a "busy" exit, `0` for cold.
#[must_use]
pub fn fixture_exit(cohort_size: usize) -> ExitCandidate {
    ExitCandidate {
        node_id: NodeId::new(),
        wg_public_key: WgSecretKey::generate().public(),
        addr: fixture_socket(2, 51_820),
        cohort_size,
    }
}

/// Client handle for the multi-hop path-assembler. Mirrors
/// `multihop::tests::fixture_client`.
#[must_use]
pub fn fixture_client_handle() -> ClientHandle {
    ClientHandle {
        wg_public_key: WgSecretKey::generate().public(),
        addr: fixture_socket(1, 41_443),
    }
}

/// `(peer_id, handle, view)` triple wired so the `peer_id` resolves
/// through `view.client()` to `ClientLookup::Found(handle.clone())`.
/// Caller may further populate `view.exits` / `view.forwarders` per
/// region before passing it to `MultiHopBuilder::assemble`.
#[must_use]
pub fn fresh_view_with_client() -> (PeerId, ClientHandle, InMemoryRegionView) {
    let peer_id = PeerId::new();
    let client = fixture_client_handle();
    let mut view = InMemoryRegionView::default();
    view.clients.insert(peer_id, ClientLookup::Found(client.clone()));
    (peer_id, client, view)
}

/// Add one exit to `view` for `region` with the supplied cohort size.
/// Returns the [`ExitCandidate::node_id`] so the test can compare it
/// against the emitted [`bibeam_protocol::SingleHopMatch::exit_set`].
pub fn insert_busy_exit(view: &mut InMemoryRegionView, region: &str, cohort_size: usize) -> NodeId {
    let exit = fixture_exit(cohort_size);
    let node_id = exit.node_id;
    view.exits.entry(region.to_owned()).or_default().push(exit);
    node_id
}

/// Add one intermediate-forwarder candidate to `view` for `region`.
pub fn insert_busy_forwarder(view: &mut InMemoryRegionView, region: &str, cohort_size: usize) {
    let forwarder = ForwarderCandidate {
        node_id: NodeId::new(),
        addr: fixture_socket(3, 51_820),
        cohort_size,
    };
    view.forwarders.entry(region.to_owned()).or_default().push(forwarder);
}

/// Bucket `count` fresh peers into `gate` for `region` against
/// `cohort`, returning the [`tokio::sync::oneshot::Receiver`]s the
/// callers can probe for `Empty` (still parked) /
/// `Closed` (cancelled) state. Panics if any admit returns the
/// already-admitted variant (i.e. caller passed `count >= FLOOR`).
pub fn bucket_peers_below_floor(
    gate: &AdmissionGate,
    region: &str,
    cohort_id: CohortId,
    cohort: &mut CohortRecord,
    count: u32,
) -> Vec<tokio::sync::oneshot::Receiver<bibeam_protocol::control::MatchResponse>> {
    use bibeam_node::coordinator::admission_gate::AdmissionOutcome;
    assert!(count < FLOOR, "bucket_peers_below_floor requires count < FLOOR");
    let mut receivers = Vec::with_capacity(count as usize);
    for _index in 0..count {
        let outcome =
            gate.admit_or_bucket(PeerId::new(), cohort_id, region, cohort, no_region_lookup());
        match outcome {
            AdmissionOutcome::Bucketed(receiver) => receivers.push(receiver),
            AdmissionOutcome::Admitted(_) => {
                panic!("{region} must bucket below floor at count={count}")
            },
            AdmissionOutcome::RegionMismatch { .. } => {
                panic!("{region} must not mismatch on {region} admits")
            },
        }
    }
    receivers
}

/// Stub implementation of
/// [`bibeam_node::coordinator::region_verify::CountryLookup`] that
/// always returns the same canned result. The integration suite never
/// re-arms mid-test, so the [`std::cell::Cell`] ceremony in the
/// in-module `StubLookup` is not needed.
pub struct StubCountryLookup {
    pub canned: Result<Option<String>, CoreError>,
}

impl StubCountryLookup {
    /// Build a stub that always returns `Ok(Some(code))` — the
    /// happy / mismatch path.
    #[must_use]
    pub fn some(code: &str) -> Self {
        Self {
            canned: Ok(Some(code.to_owned())),
        }
    }

    /// Build a stub that always returns `Ok(None)` — the
    /// DB-doesn't-know-this-IP path.
    #[must_use]
    pub const fn none() -> Self {
        Self { canned: Ok(None) }
    }
}

impl CountryLookup for StubCountryLookup {
    fn country_code(&self, _ip: IpAddr) -> Result<Option<String>, CoreError> {
        match &self.canned {
            Ok(value) => Ok(value.clone()),
            Err(err) => Err(CoreError::Geoip(err.to_string())),
        }
    }
}
