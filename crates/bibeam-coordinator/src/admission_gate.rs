#![forbid(unsafe_code)]
//! Anonymity-set ≥ 30 admission invariant (F-COORD.5).
//!
//! Per plan §2 decision #8 a cohort must hold at least 30 live
//! members before any [`bibeam_protocol::control::MatchResponse`]
//! is sent. A peer arriving at the admission gate either:
//!
//! - finds the cohort already at or above the floor and is admitted
//!   immediately, or
//! - finds the cohort below the floor, is added to the cohort
//!   record, and is **bucketed** on an in-memory wait list. The
//!   matchmaker drives [`AdmissionGate::drain_ready`] after every
//!   successful admission, which releases the bucketed peers if
//!   the cohort has finally cleared the floor.
//!
//! Each bucketed peer holds a [`tokio::sync::oneshot::Sender`] that
//! the gate uses to deliver the final
//! [`bibeam_protocol::control::MatchResponse`] once the cohort
//! clears the floor; the axum handler `await`s the matching receiver
//! with a bounded timeout. The send is fire-and-forget: if the
//! handler timed out and dropped its receiver, the matched response
//! is simply discarded — that is the correct outcome (the peer will
//! retry through a fresh `MatchRequest`).
//!
//! Each waiter row is keyed by both the peer id and the cohort id,
//! so a peer that re-registers into a different cohort cannot have
//! a stale waiter released against the new cohort's match
//! response.
//!
//! ## Concurrency
//!
//! The gate's only shared state is the wait list, guarded by a
//! [`parking_lot::Mutex`]. We deliberately avoid an async mutex
//! because admit / drain are CPU-bound (no I/O happens inside the
//! lock — the redb writes happen *outside* the gate, in the caller).
//! The lock is held for the duration of the linear walk over the
//! list (admission and drain alike) and never across an `await`.

use bibeam_core::{CohortId, PeerId, Timestamp};
use bibeam_protocol::control::MatchResponse;
use parking_lot::Mutex;

use crate::cohorts::CohortRecord;

/// Outcome of a single [`AdmissionGate::admit_or_bucket`] call.
#[derive(Debug)]
pub enum AdmissionOutcome {
    /// The cohort cleared the floor when this peer was added;
    /// caller should respond immediately with the supplied
    /// [`MatchResponse`]. The response carries the real cohort id
    /// supplied at call time, not a placeholder.
    Admitted(MatchResponse),
    /// The cohort did not clear the floor; the peer has been
    /// bucketed on the wait list and the caller should `await` the
    /// returned [`tokio::sync::oneshot::Receiver`] (with a bounded
    /// timeout) to learn its final response.
    Bucketed(tokio::sync::oneshot::Receiver<MatchResponse>),
}

/// One peer parked on the wait list until its cohort clears the
/// anonymity-set floor.
#[derive(Debug)]
struct PendingAdmission {
    peer_id: PeerId,
    cohort_id: CohortId,
    #[allow(
        dead_code,
        reason = "Reserved for the F-COORD.6 rotation scheduler / \
                  F-COORD.9 rate-limit / F-COORD.10 audit hooks that \
                  read enqueue time to decide whether a waiter has \
                  exceeded its bucket SLO. The field round-trips through \
                  drain_ready unmodified."
    )]
    enqueued_at: Timestamp,
    response_tx: tokio::sync::oneshot::Sender<MatchResponse>,
}

/// In-memory anonymity-set admission gate.
///
/// One instance per coordinator process. Wrap in [`std::sync::Arc`]
/// if the gate needs to be shared across axum handlers and the
/// rotation scheduler.
#[derive(Debug)]
pub struct AdmissionGate {
    floor: u32,
    pending: Mutex<Vec<PendingAdmission>>,
}

impl AdmissionGate {
    /// Construct a gate enforcing the given anonymity-set `floor`.
    #[must_use]
    pub const fn new(floor: u32) -> Self {
        Self {
            floor,
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Floor enforced by this gate.
    #[must_use]
    pub const fn floor(&self) -> u32 {
        self.floor
    }

    /// Add `peer_id` to `cohort` (identified by `cohort_id`) and
    /// decide whether it should be admitted immediately or
    /// bucketed.
    ///
    /// Idempotent on `cohort.members`: a peer already in the
    /// member list is not duplicated. The caller is responsible
    /// for persisting the updated `cohort` back to the redb
    /// cohort store outside the gate.
    pub fn admit_or_bucket(
        &self,
        peer_id: PeerId,
        cohort_id: CohortId,
        cohort: &mut CohortRecord,
    ) -> AdmissionOutcome {
        if !cohort.members.contains(&peer_id) {
            cohort.members.push(peer_id);
        }
        let live_count = u32::try_from(cohort.members.len()).unwrap_or(u32::MAX);
        if live_count >= self.floor {
            return AdmissionOutcome::Admitted(build_response(cohort_id, cohort));
        }
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let pending_entry = PendingAdmission {
            peer_id,
            cohort_id,
            enqueued_at: Timestamp::now(),
            response_tx,
        };
        self.pending.lock().push(pending_entry);
        AdmissionOutcome::Bucketed(response_rx)
    }

    /// Release every bucketed peer whose `(peer_id, cohort_id)`
    /// pair matches `cohort_id` and is in `cohort.members`, but
    /// only when the cohort meets the floor. Returns the count of
    /// waiters that were released.
    ///
    /// The matchmaker calls this after every successful admission
    /// plus persistence so a peer that flipped a cohort over the
    /// floor releases every other peer it brought along for the
    /// same cohort. Waiters bucketed under a different `cohort_id`
    /// are untouched.
    pub fn drain_ready(&self, cohort_id: CohortId, cohort: &CohortRecord) -> usize {
        let live_count = u32::try_from(cohort.members.len()).unwrap_or(u32::MAX);
        if live_count < self.floor {
            return 0;
        }
        let response = build_response(cohort_id, cohort);
        let drained = self.partition_waiters_for(cohort_id, cohort);
        let released = drained.len();
        for waiter in drained {
            // Fire-and-forget: a closed receiver means the axum
            // handler timed out before we could deliver, which is
            // a benign drop.
            let _previously_sent = waiter.response_tx.send(response.clone());
        }
        released
    }

    /// Partition the wait list under the gate lock. Waiters whose
    /// `(peer_id, cohort_id)` matches the given cohort are
    /// returned; everyone else is left on the list.
    fn partition_waiters_for(
        &self,
        cohort_id: CohortId,
        cohort: &CohortRecord,
    ) -> Vec<PendingAdmission> {
        let mut waiters = self.pending.lock();
        let mut ready: Vec<PendingAdmission> = Vec::with_capacity(waiters.len());
        let mut still_waiting: Vec<PendingAdmission> = Vec::new();
        for entry in waiters.drain(..) {
            let matches_cohort = entry.cohort_id == cohort_id;
            let matches_member = cohort.members.contains(&entry.peer_id);
            if matches_cohort && matches_member {
                ready.push(entry);
            } else {
                still_waiting.push(entry);
            }
        }
        *waiters = still_waiting;
        ready
    }

    /// Number of peers currently bucketed. Intended for metrics +
    /// tests; not load-bearing for the wire protocol.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// Unique `cohort_id`s currently represented on the wait list.
    ///
    /// The rotation scheduler (F-COORD.6) reads this set so it can
    /// call [`AdmissionGate::drain_ready`] against every cohort
    /// that has at least one bucketed waiter, without scanning the
    /// full redb cohort store. The returned [`Vec`] is a snapshot —
    /// fresh waiters bucketed after the call are not reflected
    /// (that is fine; the next tick picks them up).
    #[must_use]
    pub fn pending_cohort_ids(&self) -> Vec<CohortId> {
        let mut ids: Vec<CohortId> = {
            let waiters = self.pending.lock();
            waiters.iter().map(|entry| entry.cohort_id).collect()
        };
        ids.sort_unstable_by_key(|cohort| *cohort.as_ulid());
        ids.dedup();
        ids
    }

    /// Cancel every waiter whose `cohort_id` is not present in
    /// `live_cohort_ids`. Drops the matching
    /// [`tokio::sync::oneshot::Sender`]s, which surfaces to the
    /// awaiting axum handler as `oneshot::error::RecvError` — the
    /// handler maps that to `503 Service Unavailable` so the peer
    /// learns to retry rather than hang forever.
    ///
    /// Returns the count of waiters that were cancelled. Called by
    /// the rotation scheduler after a cohort eviction so a peer
    /// bucketed under a cohort that has since been evicted does
    /// not leak its sender into the next epoch.
    pub fn cancel_orphans<CohortIdSlice>(&self, live_cohort_ids: CohortIdSlice) -> usize
    where
        CohortIdSlice: AsRef<[CohortId]>,
    {
        let live = live_cohort_ids.as_ref();
        let mut waiters = self.pending.lock();
        let mut surviving: Vec<PendingAdmission> = Vec::with_capacity(waiters.len());
        let mut cancelled: usize = 0;
        for entry in waiters.drain(..) {
            if live.contains(&entry.cohort_id) {
                surviving.push(entry);
            } else {
                // Dropping `entry` drops `response_tx`, which the
                // awaiting handler observes as RecvError.
                cancelled = cancelled.saturating_add(1);
                drop(entry);
            }
        }
        *waiters = surviving;
        cancelled
    }
}

/// Build a wire [`MatchResponse`] from the cohort id + record.
fn build_response(cohort_id: CohortId, cohort: &CohortRecord) -> MatchResponse {
    MatchResponse {
        cohort: cohort_id,
        exit_set: cohort.exits.clone(),
        rotation_deadline: cohort.rotation_deadline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
    use time::Duration;

    fn cohort_with(members: Vec<PeerId>) -> CohortRecord {
        CohortRecord {
            members,
            exits: vec![NodeId::new()],
            rotation_deadline: Timestamp::from_offset_date_time(
                time::OffsetDateTime::now_utc() + Duration::minutes(15),
            ),
        }
    }

    #[test]
    fn admit_returns_immediately_when_floor_already_met() {
        // Contract: a peer arriving at a cohort that already meets
        // the floor is admitted on the spot — no waiter row, no
        // oneshot. Catches a regression that bucketed everyone
        // regardless of floor.
        let gate = AdmissionGate::new(2);
        let pre_existing = vec![PeerId::new(), PeerId::new()];
        let mut cohort = cohort_with(pre_existing);
        let cohort_id = CohortId::new();
        let peer = PeerId::new();
        let outcome = gate.admit_or_bucket(peer, cohort_id, &mut cohort);
        match outcome {
            AdmissionOutcome::Admitted(response) => {
                assert_eq!(response.cohort, cohort_id);
                assert_eq!(response.exit_set, cohort.exits);
            },
            AdmissionOutcome::Bucketed(_) => panic!("must admit immediately"),
        }
        assert_eq!(gate.pending_count(), 0);
        assert!(cohort.members.contains(&peer));
    }

    #[test]
    fn admit_buckets_below_floor_then_drains_when_floor_met() {
        // Contract: peers arriving below the floor are bucketed;
        // a later admission that pushes the cohort over the floor
        // releases every bucketed peer via drain_ready. Catches a
        // regression that lost a waiter inside drain (which would
        // strand peers in the bucket forever).
        let gate = AdmissionGate::new(3);
        let cohort_id = CohortId::new();
        let mut cohort = cohort_with(Vec::new());

        let first = PeerId::new();
        let outcome_first = gate.admit_or_bucket(first, cohort_id, &mut cohort);
        let mut receiver_first = match outcome_first {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            AdmissionOutcome::Admitted(_) => panic!("first peer must bucket"),
        };

        let second = PeerId::new();
        let outcome_second = gate.admit_or_bucket(second, cohort_id, &mut cohort);
        let mut receiver_second = match outcome_second {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            AdmissionOutcome::Admitted(_) => panic!("second peer must bucket"),
        };

        // Third peer pushes the cohort to 3 — at the floor.
        let third = PeerId::new();
        let outcome_third = gate.admit_or_bucket(third, cohort_id, &mut cohort);
        assert!(matches!(outcome_third, AdmissionOutcome::Admitted(_)));
        let released = gate.drain_ready(cohort_id, &cohort);
        assert_eq!(released, 2);
        assert_eq!(gate.pending_count(), 0);

        // Both receivers must now resolve to a MatchResponse with
        // the real cohort id.
        let response_first = receiver_first.try_recv().expect("first receiver should resolve");
        let response_second = receiver_second.try_recv().expect("second receiver should resolve");
        assert_eq!(response_first.cohort, cohort_id);
        assert_eq!(response_first.exit_set, cohort.exits);
        assert_eq!(response_second.cohort, cohort_id);
        assert_eq!(response_second.exit_set, cohort.exits);
    }

    #[test]
    fn drain_is_no_op_when_floor_still_unmet() {
        // Contract: drain_ready with a sub-floor cohort releases
        // nobody and leaves every waiter on the list.
        let gate = AdmissionGate::new(5);
        let cohort_id = CohortId::new();
        let mut cohort = cohort_with(Vec::new());
        let _outcome = gate.admit_or_bucket(PeerId::new(), cohort_id, &mut cohort);
        let _outcome_second = gate.admit_or_bucket(PeerId::new(), cohort_id, &mut cohort);
        let released = gate.drain_ready(cohort_id, &cohort);
        assert_eq!(released, 0);
        assert_eq!(gate.pending_count(), 2);
    }

    #[test]
    fn admit_is_idempotent_for_already_member_peer() {
        // Contract: a peer already in the member list is not
        // duplicated by a second admit_or_bucket call. Catches a
        // regression that double-counted re-registration (which
        // would let a single peer fake the anonymity floor).
        let gate = AdmissionGate::new(3);
        let cohort_id = CohortId::new();
        let peer = PeerId::new();
        let mut cohort = cohort_with(vec![peer]);
        let _outcome = gate.admit_or_bucket(peer, cohort_id, &mut cohort);
        assert_eq!(cohort.members.len(), 1);
    }

    #[test]
    fn drain_does_not_release_waiter_bucketed_under_different_cohort() {
        // Contract: drain_ready strictly matches the cohort id a
        // waiter was bucketed under. A peer whose `peer_id` also
        // appears in some other cohort's member list must not be
        // released against the other cohort's MatchResponse.
        // Catches a regression that keyed waiters by peer_id alone.
        let gate = AdmissionGate::new(2);
        let cohort_old = CohortId::new();
        let cohort_new = CohortId::new();
        let mut old_record = cohort_with(Vec::new());

        let shared_peer = PeerId::new();
        // Bucket `shared_peer` under the old cohort; the old
        // cohort stays sub-floor so the waiter is genuinely parked.
        let outcome = gate.admit_or_bucket(shared_peer, cohort_old, &mut old_record);
        let mut receiver = match outcome {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            AdmissionOutcome::Admitted(_) => panic!("must bucket"),
        };

        // Construct a *separate* new cohort that already meets the
        // floor and happens to list `shared_peer` among its
        // members. The matchmaker should never call drain_ready on
        // a cohort the peer was not bucketed under, but a
        // regression that ignored entry.cohort_id would release
        // the old-cohort waiter against the new cohort's response
        // here. The drain call models that buggy path; the test
        // asserts the gate refuses to release the waiter anyway.
        let new_record = cohort_with(vec![shared_peer, PeerId::new()]);
        let released = gate.drain_ready(cohort_new, &new_record);
        assert_eq!(released, 0, "old-cohort waiter must not be released");
        assert_eq!(gate.pending_count(), 1, "old-cohort waiter must remain");
        assert!(receiver.try_recv().is_err());
    }
}
