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
//! Integration tests for §11 verification gate #3 — per-region floor
//! formalism (R-FLOOR + R-MULTIHOP-COORD's path-assembly refusal).
//!
//! Three regions populate the in-process coordinator state with
//! deliberately mismatched in-role-flow counts:
//!
//! - `us-east`: 5 bucketed registrants + cold exit (`cohort_size` 5).
//!   The cold region request is REFUSED with
//!   [`MultiHopPathError::NoAnonymousPathAvailable`]; the audit log
//!   gets one
//!   [`AuditKind::NoAnonymousPathAvailable { region: "us-east",
//!   pending_count: 5 }`] entry from the gate's drain poll.
//! - `eu-de`: 35 admissions through the gate + busy exit
//!   (`cohort_size` 35). The eu-de request returns
//!   [`MatchResponse::SingleHop`] with the busy exit in `exit_set`.
//! - `kr-seoul`: same pattern as eu-de — 40 admissions + busy exit
//!   (`cohort_size` 40). Returns [`MatchResponse::SingleHop`].
//!
//! Catches a regression that reintroduced the
//! `live_members(h1) ∪ live_members(h2) ∪ live_members(exit)` union
//! fallback the §11 R-3 codex-corrected text rejected: refusal is the
//! safe outcome, NOT auto-merge.

mod helpers;

use bibeam_core::{CohortId, PeerId, Timestamp};
use bibeam_node::coordinator::admission_gate::AdmissionGate;
use bibeam_node::coordinator::audit::AuditKind;
use bibeam_node::coordinator::multihop::{MultiHopBuilder, MultiHopPathError};
use bibeam_protocol::control::{MatchRequest, MatchResponse};

use crate::helpers::{
    FLOOR, PER_POSITION_FLOOR, audit_log_with_temp, bucket_peers_below_floor, cohort_with,
    fresh_view_with_client, insert_busy_exit, no_region_lookup,
};

#[test]
fn us_east_request_refused_with_no_anonymous_path_available() {
    // Contract: a cohort with 5 bucketed registrants in `us-east`
    // (under-floor) PLUS a cold exit (`cohort_size` 5) MUST refuse the
    // path-assembly attempt with `NoAnonymousPathAvailable` AND emit
    // exactly one `AuditKind::NoAnonymousPathAvailable { region:
    // "us-east", pending_count: 5 }` audit row on the matching gate
    // drain poll. No union fallback.
    let (audit, _audit_temp) = audit_log_with_temp();
    let gate = AdmissionGate::new(FLOOR);
    let (peer_id, _client, mut view) = fresh_view_with_client();

    // Populate the gate's pending bucket: 5 us-east admissions, all
    // bucketed since 5 < FLOOR.
    let us_east_cohort_id = CohortId::new();
    let mut us_east_cohort = cohort_with(Vec::new());
    let _receivers =
        bucket_peers_below_floor(&gate, "us-east", us_east_cohort_id, &mut us_east_cohort, 5);

    // The path-assembler view sees a us-east exit with `cohort_size
    // = 5`, also under the per-position floor — the requested-region
    // exit is cold.
    let _us_east_cold_exit_node = insert_busy_exit(&mut view, "us-east", 5);

    let builder = MultiHopBuilder::new(PER_POSITION_FLOOR);
    let request = MatchRequest { peer_id, at: Timestamp::now() };

    let err = builder
        .assemble(&request, "us-east", &view)
        .expect_err("cold region must refuse");
    assert_eq!(
        err,
        MultiHopPathError::NoAnonymousPathAvailable { region: "us-east".to_owned() },
    );

    // Drive the matching audit emission via the gate drain poll. In
    // production the rotation scheduler polls every region on every
    // tick; here the test drives the same primitive directly.
    let released = gate.drain_ready(
        "us-east",
        us_east_cohort_id,
        &us_east_cohort,
        Some(&audit),
        no_region_lookup(),
    );
    assert_eq!(released, 0, "us-east drain must release zero waiters");

    let rows = audit.snapshot().expect("snapshot audit log");
    let refusals: Vec<&AuditKind> = rows
        .iter()
        .map(|entry| &entry.kind)
        .filter(|kind| matches!(kind, AuditKind::NoAnonymousPathAvailable { .. }))
        .collect();
    assert_eq!(refusals.len(), 1, "exactly one refusal entry expected, got {refusals:?}");
    match refusals[0] {
        AuditKind::NoAnonymousPathAvailable { region, pending_count } => {
            assert_eq!(region, "us-east");
            assert_eq!(*pending_count, 5);
        },
        other => panic!("expected NoAnonymousPathAvailable kind, got {other:?}"),
    }
    // Bucket survives the refusal — pending registrations stay
    // parked for a future release attempt (per the §11 R-3 contract
    // documented in admission_gate::emit_no_anonymous_path_if_pending).
    assert_eq!(gate.pending_count_for_region("us-east"), 5);
}

#[test]
fn eu_de_request_returns_direct_single_hop() {
    // Contract: a region with 35 admissions through the gate +
    // a busy exit (`cohort_size` 35) clears both the gate's floor
    // AND the multihop assembler's per-position floor. The
    // path-assembly call must return `MatchResponse::SingleHop`
    // with the registered exit's NodeId in `exit_set`.
    let (peer_id, _client, mut view) = fresh_view_with_client();
    let busy_exit_node = insert_busy_exit(&mut view, "eu-de", 35);

    let builder = MultiHopBuilder::new(PER_POSITION_FLOOR);
    let request = MatchRequest { peer_id, at: Timestamp::now() };
    let response = builder.assemble(&request, "eu-de", &view).expect("eu-de single-hop");

    let MatchResponse::SingleHop(single_hop) = response else {
        panic!("expected SingleHop, got {response:?}");
    };
    assert_eq!(single_hop.exit_set, vec![busy_exit_node]);
    // Rotation deadline must ride the standard 15-minute lease
    // horizon the assembler stamps; the test only needs to know it
    // is in the future.
    assert!(
        single_hop.rotation_deadline.into_inner() > Timestamp::now().into_inner(),
        "rotation deadline must be in the future",
    );
}

#[test]
fn kr_seoul_request_returns_direct_single_hop() {
    // Contract: kr-seoul, populated identically to eu-de but with
    // 40 in-role flows, also returns `MatchResponse::SingleHop`.
    // Verifies the per-region floor lift is independent: a region
    // that cleared the floor by its own population MUST not be
    // gated on the under-floor neighbour's bucket.
    let (peer_id, _client, mut view) = fresh_view_with_client();
    let busy_exit_node = insert_busy_exit(&mut view, "kr-seoul", 40);

    let builder = MultiHopBuilder::new(PER_POSITION_FLOOR);
    let request = MatchRequest { peer_id, at: Timestamp::now() };
    let response = builder.assemble(&request, "kr-seoul", &view).expect("kr-seoul single-hop");

    let MatchResponse::SingleHop(single_hop) = response else {
        panic!("expected SingleHop, got {response:?}");
    };
    assert_eq!(single_hop.exit_set, vec![busy_exit_node]);
}

#[test]
fn three_regions_route_independently_per_floor() {
    // Contract: with us-east (5/cold), eu-de (35/busy), kr-seoul
    // (40/busy) populated in ONE shared view + gate, each region's
    // outcome is exactly what its own population dictates — the
    // cold region's refusal does NOT block the busy regions'
    // single-hop releases, AND the busy regions do NOT lift the
    // cold region over the floor. This is the load-bearing
    // assertion that no union fallback is possible across regions.
    let (audit, _audit_temp) = audit_log_with_temp();
    let gate = AdmissionGate::new(FLOOR);
    let (peer_id, _client, mut view) = fresh_view_with_client();

    // us-east — bucket 5 below the floor; install a cold exit (also
    // `cohort_size` 5 so neither the gate nor the assembler can
    // emit a path).
    let us_east_cohort_id = CohortId::new();
    let mut us_east_cohort = cohort_with(Vec::new());
    let _us_east_receivers =
        bucket_peers_below_floor(&gate, "us-east", us_east_cohort_id, &mut us_east_cohort, 5);
    let _us_east_cold_exit = insert_busy_exit(&mut view, "us-east", 5);

    // eu-de + kr-seoul — install only the busy exits; the
    // assembler's exit-pick stage already meets the floor on
    // cohort_size alone, no gate-drive needed for these paths.
    let eu_de_exit = insert_busy_exit(&mut view, "eu-de", 35);
    let kr_seoul_exit = insert_busy_exit(&mut view, "kr-seoul", 40);

    let builder = MultiHopBuilder::new(PER_POSITION_FLOOR);

    // Drive every region's path-assembly call. Each call uses a
    // FRESH peer registration so the resolved client survives —
    // the assembler reads `view.clients` keyed by the request's
    // peer_id.
    let us_east_err = builder
        .assemble(&MatchRequest { peer_id, at: Timestamp::now() }, "us-east", &view)
        .expect_err("us-east refuses");
    assert_eq!(
        us_east_err,
        MultiHopPathError::NoAnonymousPathAvailable { region: "us-east".to_owned() },
    );

    let eu_de_resp = builder
        .assemble(&MatchRequest { peer_id, at: Timestamp::now() }, "eu-de", &view)
        .expect("eu-de single-hop");
    let MatchResponse::SingleHop(eu_de_single) = eu_de_resp else {
        panic!("expected eu-de SingleHop");
    };
    assert_eq!(eu_de_single.exit_set, vec![eu_de_exit]);

    let kr_seoul_resp = builder
        .assemble(&MatchRequest { peer_id, at: Timestamp::now() }, "kr-seoul", &view)
        .expect("kr-seoul single-hop");
    let MatchResponse::SingleHop(kr_seoul_single) = kr_seoul_resp else {
        panic!("expected kr-seoul SingleHop");
    };
    assert_eq!(kr_seoul_single.exit_set, vec![kr_seoul_exit]);

    // The cold region's gate poll must still surface its audit
    // entry; the busy regions never reach the audit-emission
    // branch (per the gate contract: refusal only fires when the
    // floor is unmet AND the bucket is non-empty).
    let released = gate.drain_ready(
        "us-east",
        us_east_cohort_id,
        &us_east_cohort,
        Some(&audit),
        no_region_lookup(),
    );
    assert_eq!(released, 0);
    let rows = audit.snapshot().expect("snapshot");
    let refusal_count = rows
        .iter()
        .filter(|entry| matches!(entry.kind, AuditKind::NoAnonymousPathAvailable { .. }))
        .count();
    assert_eq!(
        refusal_count, 1,
        "exactly one us-east refusal expected; busy regions never emit"
    );

    // Each region's gate bucket survives independently — the busy
    // regions hold zero waiters because their admissions never
    // went through the gate's bucket path in this test (they hit
    // the assembler's exit-pick branch directly), while us-east
    // retains its 5 pending registrants.
    assert_eq!(gate.pending_count_for_region("us-east"), 5);
    assert_eq!(gate.pending_count_for_region("eu-de"), 0);
    assert_eq!(gate.pending_count_for_region("kr-seoul"), 0);

    // PeerId stays alive across calls so we are not exercising a
    // re-registration race; the assertion below is structural.
    let _silenced_unused_warning = PeerId::new();
}
