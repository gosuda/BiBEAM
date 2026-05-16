#![forbid(unsafe_code)]
//! End-to-end smoke test for the coordinator admission pipeline.
//!
//! Wires together the F-COORD.2 peer registry, the F-COORD.3
//! cohort store, the F-COORD.4 PASETO admissioner, the F-COORD.5
//! anonymity-set gate, and the F-COORD.4 token verifier. The
//! happy path:
//!
//! 1. Register two peers explicitly + a 30-member fixture
//!    population (property-test-style; every peer is a fresh
//!    `PeerId`).
//! 2. Drive every peer through `AdmissionGate::admit_or_bucket`.
//! 3. Once the cohort clears the floor, mint a PASETO token for
//!    one of the explicit peers via `Admissioner::issue`.
//! 4. Verify the token via `PasetoVerifier::verify` and assert
//!    the recovered claims match the cohort's canonical state.

use std::sync::Arc;

use bibeam_coordinator::admission::Admissioner;
use bibeam_coordinator::admission_gate::{AdmissionGate, AdmissionOutcome};
use bibeam_coordinator::cohorts::{CohortRecord, CohortStore};
use bibeam_coordinator::registry::PeerRegistry;
use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use bibeam_crypto::{PasetoIssuer, PasetoVerifier};
use bibeam_discovery::PeerRecord;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use time::Duration;

/// The F-COORD.5 MVP floor — kept in lockstep with the gate's
/// default in `admission_gate.rs`.
const ANONYMITY_FLOOR: u32 = 30;

/// Assertion helper for [`AdmissionOutcome::Admitted`] inside the
/// e2e loop. Pulled out so the loop body stays under the
/// excessive-nesting threshold.
fn assert_admitted_outcome(
    response_cohort: CohortId,
    expected_cohort: CohortId,
    one_indexed_position: usize,
    is_explicit_first: bool,
    explicit_first_admitted: &mut bool,
) {
    assert_eq!(response_cohort, expected_cohort);
    assert!(one_indexed_position >= ANONYMITY_FLOOR as usize);
    if is_explicit_first {
        *explicit_first_admitted = true;
    }
}

const fn fixture_peer_record(peer_id: PeerId, last_seen: Timestamp) -> PeerRecord {
    PeerRecord {
        peer_id,
        addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 41_443),
        can_exit: false,
        capacity_hint: 0,
        last_seen,
    }
}

fn fixture_cohort_record(rotation_deadline: Timestamp) -> CohortRecord {
    CohortRecord {
        members: Vec::new(),
        exits: vec![NodeId::new(), NodeId::new()],
        rotation_deadline,
    }
}

#[tokio::test]
async fn admission_pipeline_round_trips_token_at_floor() {
    let registry_temp = tempfile::NamedTempFile::new().expect("registry tempfile");
    let cohorts_temp = tempfile::NamedTempFile::new().expect("cohorts tempfile");
    let registry = Arc::new(PeerRegistry::open(registry_temp.path()).expect("open registry"));
    let cohorts = Arc::new(CohortStore::open(cohorts_temp.path()).expect("open cohort store"));

    let key_pair = AsymmetricKeyPair::<V4>::generate().expect("generate keypair");
    let verifier = PasetoVerifier::new(key_pair.public);
    let issuer = Arc::new(PasetoIssuer::new(key_pair.secret));
    let admissioner = Admissioner::new(issuer);

    let gate = AdmissionGate::new(ANONYMITY_FLOOR);

    let cohort_id = CohortId::new();
    let now = Timestamp::now();
    let rotation_deadline =
        Timestamp::from_offset_date_time(now.into_inner() + Duration::minutes(15));
    let mut cohort_record = fixture_cohort_record(rotation_deadline);

    // Register two explicit peers — the first is the one we
    // mint the final token for at the end of the run.
    let explicit_first = PeerId::new();
    let explicit_second = PeerId::new();
    let mut all_peers: Vec<PeerId> = Vec::with_capacity(usize::from(u8::MAX));
    all_peers.push(explicit_first);
    all_peers.push(explicit_second);
    for _index in 0..28 {
        all_peers.push(PeerId::new());
    }
    assert_eq!(all_peers.len(), ANONYMITY_FLOOR as usize);

    // Persist every peer into the registry — the matchmaker would
    // do this inside the axum handler; we do it directly here.
    for peer_id in &all_peers {
        registry.upsert(&fixture_peer_record(*peer_id, now)).expect("upsert peer");
    }

    // Drive every peer through the gate. The 30th admission
    // should flip the cohort over the floor and admit.
    let mut bucketed_receivers: Vec<tokio::sync::oneshot::Receiver<_>> =
        Vec::with_capacity(all_peers.len());
    let mut explicit_first_admitted = false;
    for (index, peer_id) in all_peers.iter().enumerate() {
        let outcome = gate.admit_or_bucket(*peer_id, cohort_id, &mut cohort_record);
        let one_indexed = index + 1;
        match outcome {
            AdmissionOutcome::Admitted(response) => assert_admitted_outcome(
                response.cohort,
                cohort_id,
                one_indexed,
                *peer_id == explicit_first,
                &mut explicit_first_admitted,
            ),
            AdmissionOutcome::Bucketed(receiver) => {
                bucketed_receivers.push(receiver);
                assert!(one_indexed < ANONYMITY_FLOOR as usize);
            },
        }
    }

    // The matchmaker persists the cohort after the floor-crossing
    // admission; the test does the same.
    cohorts.upsert(&cohort_id, &cohort_record).expect("upsert cohort");

    // Drain the bucketed waiters — every one of them should
    // receive a MatchResponse now that the cohort meets the
    // floor.
    let released = gate.drain_ready(cohort_id, &cohort_record);
    assert_eq!(released, bucketed_receivers.len());
    for mut receiver in bucketed_receivers {
        let response = receiver.try_recv().expect("waiter resolved");
        assert_eq!(response.cohort, cohort_id);
        assert_eq!(response.exit_set, cohort_record.exits);
    }
    // The explicit first peer was bucketed at index 0; its
    // receiver above already saw the response. Set the flag
    // accordingly: either the floor-crossing peer was the first
    // or `released` had the first peer included.
    assert!(
        explicit_first_admitted || cohort_record.members.contains(&explicit_first),
        "explicit_first must be in the cohort by the end of the run",
    );
    assert!(cohort_record.members.contains(&explicit_second));
    assert_eq!(cohort_record.members.len(), ANONYMITY_FLOOR as usize);

    // Mint a PASETO token for explicit_first via the admissioner
    // and verify it through PasetoVerifier::verify.
    let token = admissioner
        .issue(explicit_first, cohort_id, &cohort_record)
        .expect("issue token");
    let claims = verifier.verify(&token).expect("verify token");
    assert_eq!(claims.sub, explicit_first);
    assert_eq!(claims.cohort, cohort_id);
    assert_eq!(claims.exit_set, cohort_record.exits);
    assert_eq!(claims.exp, cohort_record.rotation_deadline);
}
