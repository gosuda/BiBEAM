#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Characterization tests for
//! [`bibeam_node::coordinator::admission_gate::AdmissionGate`].
//!
//! These tests document the gate's **current** behavior at the
//! boundaries the plan flagged as design-decisions-required (§
//! Findings of /home/alpha/.claude/plans/recursive-sauteeing-codd.md).
//! Each test locks in observable behavior; none of them prescribes a
//! cap, eviction policy, or new constant. When a bound is eventually
//! added, the affected test will fail at the boundary and the
//! implementer updates the assertion with the new bound.
//!
//! The inline `#[cfg(test)]` tests in `admission_gate.rs` already
//! cover member-list dedup
//! (`admit_is_idempotent_for_already_member_peer`) and
//! pending-bucket dedup on retry
//! (`admit_replaces_prior_waiter_on_retry_for_same_peer_and_cohort`).
//! What is NOT locked there is (a) the absence of a region-string
//! length cap and (b) the linear growth of a region's bucket with
//! distinct waiting peers — the two characterization concerns in §C1.

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use bibeam_node::coordinator::admission_gate::{AdmissionGate, AdmissionOutcome, ExitRegionLookup};
use bibeam_node::coordinator::cohorts::CohortRecord;
use time::{Duration, OffsetDateTime};

fn empty_cohort() -> CohortRecord {
    CohortRecord {
        members: Vec::new(),
        exits: vec![NodeId::new()],
        rotation_deadline: Timestamp::from_offset_date_time(
            OffsetDateTime::now_utc() + Duration::minutes(15),
        ),
        region: String::new(),
    }
}

fn no_region_lookup() -> ExitRegionLookup<'static> {
    &|_| None
}

/// The gate clone-stores the caller's region string verbatim into
/// both the cohort record's `region` field and the pending bucket's
/// `HashMap` key. No length cap exists today; a multi-kilobyte region
/// string survives both clones without error. This test pins that
/// observable behavior. When a cap lands in
/// `admission_gate.rs:237-244` (see plan §Findings #1) the
/// assertion will need to change — the test failing is the signal.
#[test]
fn admits_pending_entry_with_multi_kilobyte_region_string() {
    let gate = AdmissionGate::new(2);
    let cohort_id = CohortId::new();
    let mut cohort = empty_cohort();
    let huge_region: String = "x".repeat(4096);

    let outcome = gate.admit_or_bucket(
        PeerId::new(),
        cohort_id,
        &huge_region,
        &mut cohort,
        no_region_lookup(),
    );

    // Under-floor → Bucketed. The cohort record carries the full
    // region string and the pending bucket exists under the same
    // key.
    assert!(
        matches!(outcome, AdmissionOutcome::Bucketed(_)),
        "below-floor admission must bucket; got {outcome:?}",
    );
    assert_eq!(
        cohort.region.len(),
        huge_region.len(),
        "region clone is verbatim, no truncation",
    );
    assert_eq!(
        gate.pending_count_for_region(&huge_region),
        1,
        "pending bucket is keyed on the full region string",
    );
}

/// The pending bucket holds one entry per distinct
/// `(peer_id, cohort_id)`. With N distinct peers admitted into the
/// same cohort under the same region (all below the floor), the
/// bucket grows to exactly N entries — no cap, no eviction. This
/// pins the linear growth profile flagged in plan §Findings #3.
/// `admit_is_idempotent_for_already_member_peer` (inline) already
/// covers the SAME-peer-twice case; this test covers DISTINCT
/// peers, which the inline coverage does not.
#[test]
fn pending_wait_list_grows_with_distinct_peers_in_one_region() {
    const PEERS: usize = 50;
    let gate = AdmissionGate::new(1_000); // Floor far above the test load.
    let cohort_id = CohortId::new();
    let mut cohort = empty_cohort();
    let region = "us-east";

    // Hold the receivers so the senders inside the gate stay live
    // for the full duration of the test. The collection is never
    // read, but its lifetime is the point — dropping each rx
    // immediately would let the gate's oneshot::Sender observe a
    // closed receiver; keeping them alive matches what a real
    // axum handler would do while awaiting its match response.
    let mut receivers = Vec::with_capacity(PEERS);
    for _ in 0..PEERS {
        let outcome =
            gate.admit_or_bucket(PeerId::new(), cohort_id, region, &mut cohort, no_region_lookup());
        match outcome {
            AdmissionOutcome::Bucketed(rx) => receivers.push(rx),
            other => panic!("expected Bucketed at peer count below floor, got {other:?}"),
        }
    }

    assert_eq!(
        receivers.len(),
        PEERS,
        "exactly one receiver per admitted peer (sanity); every admission below the floor must Bucket",
    );
    assert_eq!(
        gate.pending_count_for_region(region),
        PEERS,
        "bucket grows linearly with distinct admitted peers; no cap or eviction today",
    );
    assert_eq!(
        cohort.members.len(),
        PEERS,
        "every distinct peer is added to cohort.members exactly once",
    );
}
