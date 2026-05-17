#![forbid(unsafe_code)]
//! Per-region anonymity-set ≥ 30 admission invariant (F-COORD.5 + §11 R-3 R-FLOOR).
//!
//! Per plan §2 decision #8 a cohort must hold at least 30 live
//! members before any [`bibeam_protocol::control::MatchResponse`]
//! is sent. Per the §11 R-3 R-FLOOR cascading-edits, the
//! "≥ 30 members" check is enforced **per region**: the gate
//! partitions pending registrations by the registrant's declared
//! [`bibeam_discovery::PeerRecord::region`] string, and each
//! region's bucket releases independently when it reaches the
//! anonymity floor. Cohorts inherit the region tag at admission
//! time.
//!
//! A peer arriving at the admission gate either:
//!
//! - finds its region's cohort already at or above the floor and is
//!   admitted immediately, or
//! - finds its region's cohort below the floor, is added to the
//!   cohort record, and is bucketed on an in-memory wait list keyed
//!   by region. The rotation scheduler (F-COORD.6) drives
//!   [`AdmissionGate::drain_ready`] for every `(region, cohort_id)`
//!   pair on every tick; each call releases that region's bucketed
//!   peers if the region's cohort has finally cleared the floor.
//!
//! Each bucketed peer holds a [`tokio::sync::oneshot::Sender`] that
//! the gate uses to deliver the final
//! [`bibeam_protocol::control::MatchResponse`] once the cohort
//! clears the floor; the axum handler `await`s the matching
//! receiver with a bounded timeout. The send is fire-and-forget: if
//! the handler timed out and dropped its receiver, the matched
//! response is simply discarded — that is the correct outcome (the
//! peer will retry through a fresh `MatchRequest`).
//!
//! Each waiter row is keyed by both the peer id and the cohort id,
//! so a peer that re-registers into a different cohort cannot have
//! a stale waiter released against the new cohort's match response.
//!
//! ## §11 R-3 refusal — no union fallback
//!
//! When a region's bucket holds at least one pending registration
//! but fewer than the floor's worth of in-role flows, the gate
//! REFUSES to assemble a cohort. The §11 R-3 codex-corrected text
//! rules out the previously-drafted
//! `live_members(h1) ∪ live_members(h2) ∪ live_members(exit)` union
//! fallback — refusal is the correct outcome, not an auto-merge of
//! the smaller regions. Refusal surfaces through an
//! [`super::audit::AuditKind::NoAnonymousPathAvailable`] entry on
//! every gate poll where the region remains under-floor; the
//! pending registrations stay bucketed for a future release attempt
//! (rotation may bring fresh registrations from the same region).
//!
//! ## Multi-hop scope
//!
//! At MVP the gate tracks only the exit-role bucket per region; the
//! per-intermediate-hop floor check happens at path-assembly time
//! (R-MULTIHOP-COORD's concern). At this layer the constraint is
//! "exit position satisfied".
//!
//! ## Concurrency
//!
//! The gate's only shared state is the wait list, guarded by a
//! [`parking_lot::Mutex`]. We deliberately avoid an async mutex
//! because admit / drain are CPU-bound (no I/O happens inside the
//! lock — the redb writes happen *outside* the gate, in the caller
//! — and the audit-log append in
//! [`AdmissionGate::drain_ready`] is captured outside the lock).
//! The lock is held for the duration of the linear walk over the
//! list (admission and drain alike) and never across an `await`.

use std::collections::HashMap;
use std::sync::Arc;

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use bibeam_protocol::control::{MatchResponse, SingleHopMatch};
use parking_lot::Mutex;

use super::audit::AuditLog;
use super::cohorts::CohortRecord;

/// Callable resolving a cohort exit's [`NodeId`] to a region string.
///
/// Sourced at the coord from
/// [`bibeam_discovery::ExitRecord::region`] (or
/// [`bibeam_discovery::PeerRecord::region`] for relay-promoted exits)
/// per R-REGION.3. `None` means "region unknown for that exit"; the
/// caller's region-aware exit picker (F-CLI.4b) treats that as a
/// non-match, not a wildcard.
///
/// Passed to [`AdmissionGate::admit_or_bucket`] +
/// [`AdmissionGate::drain_ready`] so each emitted [`MatchResponse`]
/// carries the per-exit region map straight through to the client's
/// `CohortLive` view — closing the silent contract gap F-CLI.4b
/// left in place at commit 155a0f1.
pub type ExitRegionLookup<'a> = &'a (dyn Fn(NodeId) -> Option<String> + Send + Sync);

/// [`Arc`]-shared variant of [`ExitRegionLookup`].
///
/// For owners that keep the lookup state across `tokio` task
/// boundaries (e.g. [`super::rotation::RotationScheduler`]).
/// Deref-coerces to [`ExitRegionLookup`] at the gate-call site via
/// `&*lookup`.
pub type SharedExitRegionLookup = Arc<dyn Fn(NodeId) -> Option<String> + Send + Sync>;

/// Outcome of a single [`AdmissionGate::admit_or_bucket`] call.
///
/// The [`Self::Admitted`] variant boxes its [`MatchResponse`] payload
/// because the multi-hop variant
/// ([`MatchResponse::MultiHopAssignment`]) is materially larger than
/// the single-hop one — without the indirection, every `Bucketed`
/// value on the wait list would carry the same memory footprint as a
/// fully populated multi-hop response, which `clippy::large_enum_variant`
/// flags at the workspace's `-D warnings` setting.
#[derive(Debug)]
pub enum AdmissionOutcome {
    /// The cohort cleared the floor when this peer was added;
    /// caller should respond immediately with the supplied
    /// [`MatchResponse`]. The response carries the real cohort id
    /// supplied at call time, not a placeholder.
    Admitted(Box<MatchResponse>),
    /// The cohort did not clear the floor; the peer has been
    /// bucketed on the wait list and the caller should `await` the
    /// returned [`tokio::sync::oneshot::Receiver`] (with a bounded
    /// timeout) to learn its final response.
    Bucketed(tokio::sync::oneshot::Receiver<MatchResponse>),
    /// The caller's `region` argument disagrees with the cohort
    /// record's already-set `region` tag. Refusal is the safe
    /// outcome: per §11 R-3 the gate cannot mix two regions inside
    /// one cohort's anonymity set. The handler maps this to
    /// `409 Conflict` so the caller learns to re-request with a
    /// fresh `cohort_id` aligned to its own region.
    RegionMismatch {
        /// Region the cohort was already tagged with.
        existing_region: String,
        /// Region the caller passed in. Always different from
        /// `existing_region`; the gate would not have returned this
        /// variant otherwise.
        requested_region: String,
    },
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
                  exceeded its bucket SLO. The field round-trips \
                  through drain_ready unmodified."
    )]
    enqueued_at: Timestamp,
    response_tx: tokio::sync::oneshot::Sender<MatchResponse>,
}

/// In-memory anonymity-set admission gate.
///
/// One instance per coordinator process. Wrap in [`std::sync::Arc`]
/// if the gate needs to be shared across axum handlers and the
/// rotation scheduler.
///
/// The wait list is a [`HashMap`] keyed by region string; each
/// region's `Vec<PendingAdmission>` is released independently when
/// the region's cohort clears the floor.
#[derive(Debug)]
pub struct AdmissionGate {
    floor: u32,
    pending: Mutex<HashMap<String, Vec<PendingAdmission>>>,
}

impl AdmissionGate {
    /// Construct a gate enforcing the given anonymity-set `floor`.
    #[must_use]
    pub fn new(floor: u32) -> Self {
        Self {
            floor,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Floor enforced by this gate.
    #[must_use]
    pub const fn floor(&self) -> u32 {
        self.floor
    }

    /// Add `peer_id` to `cohort` (identified by `cohort_id`) for
    /// `region` and decide whether it should be admitted immediately
    /// or bucketed.
    ///
    /// Stamps the cohort's `region` field on first admission. If
    /// the cohort is already tagged with a DIFFERENT region the
    /// gate refuses with
    /// [`AdmissionOutcome::RegionMismatch`] — neither members nor
    /// waiters are mutated. This is the §11 R-3 invariant against
    /// cross-region pollution of an anonymity set.
    ///
    /// Otherwise behaves idempotently on `cohort.members`: a peer
    /// already in the member list is not duplicated, AND any stale
    /// pending entry for the same `(region, cohort_id, peer_id)`
    /// triple is replaced (its `response_tx` is dropped, surfacing
    /// to its awaiter as `RecvError`). The replace-on-retry rule
    /// prevents dead senders accumulating when a peer re-issues
    /// `MatchRequest` after an HTTP timeout — each fresh request
    /// gets a fresh waiter, and the previous attempt's stale
    /// receiver collapses promptly to a `503`-equivalent on the
    /// peer side.
    ///
    /// The caller is responsible for persisting the updated
    /// `cohort` back to the redb cohort store outside the gate.
    /// The `region` argument must match the registrant's declared
    /// [`bibeam_discovery::PeerRecord::region`]; the gate keys its
    /// pending bucket on this string verbatim.
    ///
    /// `exit_region_lookup` resolves each cohort exit's [`NodeId`]
    /// to its operator-tagged region string for the emitted
    /// [`MatchResponse`]; see [`ExitRegionLookup`] for the contract.
    #[allow(
        clippy::too_many_arguments,
        reason = "R-REGION.3 widened the gate's admit entry point with the \
                  exit_region_lookup callback; the other five arguments are \
                  the pre-existing F-COORD.5 contract surface (peer_id, \
                  cohort_id, region, &mut cohort, &self). Bundling them \
                  into a struct only shifts the same six fields onto a \
                  literal at every call site and obscures the trailing \
                  lookup pointer the rotation scheduler threads in by Arc."
    )]
    pub fn admit_or_bucket(
        &self,
        peer_id: PeerId,
        cohort_id: CohortId,
        region: &str,
        cohort: &mut CohortRecord,
        exit_region_lookup: ExitRegionLookup<'_>,
    ) -> AdmissionOutcome {
        // R-3 cross-region safety: a cohort already tagged with a
        // different region must NOT accept the new peer. Refusal
        // is the safe outcome — admitting `peer_id` here would
        // mix two regions inside one anonymity set and let the
        // smaller bucket piggy-back on the larger region's floor
        // crossing (the union-fallback failure mode the
        // §11 R-3 codex-corrected text explicitly rejected).
        if !cohort.region.is_empty() && cohort.region != region {
            return AdmissionOutcome::RegionMismatch {
                existing_region: cohort.region.clone(),
                requested_region: region.to_owned(),
            };
        }
        if cohort.region.is_empty() {
            region.clone_into(&mut cohort.region);
        }
        if !cohort.members.contains(&peer_id) {
            cohort.members.push(peer_id);
        }
        let live_count = u32::try_from(cohort.members.len()).unwrap_or(u32::MAX);
        if live_count >= self.floor {
            return AdmissionOutcome::Admitted(Box::new(build_response(
                cohort_id,
                cohort,
                exit_region_lookup,
            )));
        }
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let pending_entry = PendingAdmission {
            peer_id,
            cohort_id,
            enqueued_at: Timestamp::now(),
            response_tx,
        };
        self.upsert_pending_entry(region, pending_entry);
        AdmissionOutcome::Bucketed(response_rx)
    }

    /// Insert `pending_entry` into the wait list under `region`,
    /// replacing any prior entry for the same
    /// `(region, cohort_id, peer_id)` triple. Replacing (rather
    /// than appending) keeps the bucket bounded under retry
    /// pressure — a peer that re-issues `MatchRequest` after an
    /// HTTP timeout does not accumulate dead `response_tx` senders
    /// in the bucket. Dropping the prior `response_tx` surfaces to
    /// its awaiting handler as `oneshot::error::RecvError`, which
    /// the handler maps to a 503 so the peer learns to retry.
    fn upsert_pending_entry(&self, region: &str, pending_entry: PendingAdmission) {
        // Scope the lock guard explicitly so the parking_lot mutex
        // is released the instant the bucket update commits. The
        // clippy::significant_drop_tightening lint catches lock
        // guards held into the rest of the function body, which
        // would matter if a future drop_value with a noisy `Drop`
        // landed in `pending_entry`'s tail.
        let mut waiters = self.pending.lock();
        let bucket = waiters.entry(region.to_owned()).or_default();
        // Drop any previous waiter for the same (cohort_id, peer_id).
        // The drop releases the old response_tx, collapsing the prior
        // attempt's receiver to RecvError.
        bucket.retain(|prior| {
            !(prior.cohort_id == pending_entry.cohort_id && prior.peer_id == pending_entry.peer_id)
        });
        bucket.push(pending_entry);
        drop(waiters);
    }

    /// Release every bucketed peer parked under `region` whose
    /// `(peer_id, cohort_id)` pair matches `cohort_id` and appears
    /// in `cohort.members`, but only when the cohort meets the
    /// floor. Returns the count of waiters that were released.
    ///
    /// If the region's bucket is non-empty but the cohort does NOT
    /// meet the floor, the gate emits an
    /// [`super::audit::AuditKind::NoAnonymousPathAvailable`] audit
    /// entry via `audit_log` (when supplied) — one entry per poll —
    /// and leaves the waiters in place for a future attempt. This
    /// is the §11 R-3 refusal path: no union fallback.
    ///
    /// `audit_log` is `Option<&AuditLog>` because the gate's
    /// in-module unit tests do not own an audit log instance; the
    /// rotation scheduler always passes `Some(&log)` in production
    /// callsites.
    ///
    /// `exit_region_lookup` resolves each cohort exit's [`NodeId`]
    /// to its operator-tagged region string for the emitted
    /// [`MatchResponse`]; see [`ExitRegionLookup`] for the contract.
    ///
    /// The matchmaker calls this after every successful admission
    /// plus persistence so a peer that flipped a cohort over the
    /// floor releases every other peer it brought along for the
    /// same `(region, cohort_id)` pair. Waiters bucketed under a
    /// different `cohort_id` or a different region are untouched.
    #[allow(
        clippy::too_many_arguments,
        reason = "R-REGION.3 widened the drain entry point with the \
                  exit_region_lookup callback; the other five arguments are \
                  the pre-existing F-COORD.5 + F-COORD.8 contract surface \
                  (region, cohort_id, &cohort, audit_log, &self). Bundling \
                  them into a struct only shifts the same six fields onto \
                  a literal at every call site and obscures the trailing \
                  lookup pointer the rotation scheduler threads in by Arc."
    )]
    pub fn drain_ready(
        &self,
        region: &str,
        cohort_id: CohortId,
        cohort: &CohortRecord,
        audit_log: Option<&AuditLog>,
        exit_region_lookup: ExitRegionLookup<'_>,
    ) -> usize {
        let live_count = u32::try_from(cohort.members.len()).unwrap_or(u32::MAX);
        if live_count < self.floor {
            self.emit_no_anonymous_path_if_pending(region, audit_log);
            return 0;
        }
        let response = build_response(cohort_id, cohort, exit_region_lookup);
        let drained = self.partition_waiters_for(region, cohort_id, cohort);
        let released = drained.len();
        for waiter in drained {
            // Fire-and-forget: a closed receiver means the axum
            // handler timed out before we could deliver, which is
            // a benign drop.
            let _previously_sent = waiter.response_tx.send(response.clone());
        }
        released
    }

    /// §11 R-3 refusal-path side-effect: when a drain finds the
    /// region's bucket non-empty but under-floor, emit a fresh
    /// [`super::audit::AuditKind::NoAnonymousPathAvailable`] entry
    /// — one per poll so operator dashboards see one row per
    /// stalled tick, not a single "first noticed" entry. The
    /// waiters stay in the bucket: refusal is the correct outcome
    /// per the §11 R-3 codex-corrected text (no union fallback).
    fn emit_no_anonymous_path_if_pending(&self, region: &str, audit_log: Option<&AuditLog>) {
        let Some(log) = audit_log else {
            return;
        };
        let pending_count = self.pending_count_for_region(region);
        if pending_count == 0 {
            return;
        }
        let pending_count_u32 = u32::try_from(pending_count).unwrap_or(u32::MAX);
        if let Err(err) = log.record_no_anonymous_path(region, pending_count_u32) {
            tracing::error!(
                error = %err,
                region = region,
                pending_count = pending_count,
                "audit: NoAnonymousPathAvailable append failed",
            );
        }
    }

    /// Partition the wait list under the gate lock. Waiters in
    /// `region` whose `(peer_id, cohort_id)` matches the given
    /// cohort are returned; everyone else (including the region's
    /// own non-matching waiters) is left on the list.
    fn partition_waiters_for(
        &self,
        region: &str,
        cohort_id: CohortId,
        cohort: &CohortRecord,
    ) -> Vec<PendingAdmission> {
        let mut waiters = self.pending.lock();
        let Some(bucket) = waiters.get_mut(region) else {
            return Vec::new();
        };
        let mut ready: Vec<PendingAdmission> = Vec::with_capacity(bucket.len());
        let mut still_waiting: Vec<PendingAdmission> = Vec::new();
        for entry in bucket.drain(..) {
            let matches_cohort = entry.cohort_id == cohort_id;
            let matches_member = cohort.members.contains(&entry.peer_id);
            if matches_cohort && matches_member {
                ready.push(entry);
            } else {
                still_waiting.push(entry);
            }
        }
        *bucket = still_waiting;
        // Tidy: an empty bucket is dropped so `pending_buckets`
        // does not surface dead regions to the rotation scheduler.
        if bucket.is_empty() {
            waiters.remove(region);
        }
        ready
    }

    /// Number of peers currently bucketed across all regions.
    /// Intended for metrics + tests; not load-bearing for the wire
    /// protocol.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.lock().values().map(Vec::len).sum()
    }

    /// Number of peers currently bucketed under `region`. Intended
    /// for the §11 R-3 audit emission (`pending_count` field) and
    /// for tests.
    #[must_use]
    pub fn pending_count_for_region(&self, region: &str) -> usize {
        self.pending.lock().get(region).map_or(0, Vec::len)
    }

    /// Read-only snapshot of every peer currently bucketed under
    /// `region`. Returns the [`PeerId`]s in arrival order (the same
    /// order the gate would release them on a drain).
    ///
    /// Added for R-MULTIHOP-COORD's per-position floor check at
    /// path-assembly time: the multi-hop assembler counts how many
    /// in-role flows sit in a region's bucket today, then refuses
    /// the request when the cohort is short of the per-position
    /// floor. The accessor is read-only — the gate is never mutated
    /// from the path-assembly module (separation of concerns: the
    /// gate owns the wait-list shape, the assembler owns the
    /// cohort-picking shape).
    ///
    /// Returns an empty [`Vec`] when the region has no bucketed
    /// peers; callers MUST treat absent-region and empty-bucket as
    /// the same case (the gate clears empty buckets eagerly so a
    /// region that drained on the previous tick disappears from
    /// the map).
    #[must_use]
    pub fn members_in_region(&self, region: &str) -> Vec<PeerId> {
        self.pending
            .lock()
            .get(region)
            .map(|bucket| bucket.iter().map(|entry| entry.peer_id).collect())
            .unwrap_or_default()
    }

    /// Snapshot of every `(region, cohort_id)` pair currently
    /// represented on the wait list, sorted for determinism.
    ///
    /// The rotation scheduler (F-COORD.6) reads this set so it can
    /// call [`AdmissionGate::drain_ready`] against every region's
    /// cohort that has at least one bucketed waiter, without
    /// scanning the full redb cohort store. The returned [`Vec`] is
    /// a snapshot — fresh waiters bucketed after the call are not
    /// reflected (that is fine; the next tick picks them up).
    #[must_use]
    pub fn pending_buckets(&self) -> Vec<(String, CohortId)> {
        let mut pairs = self.snapshot_pending_pairs_under_lock();
        pairs.sort_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.as_ulid().cmp(right.1.as_ulid()))
        });
        pairs.dedup();
        pairs
    }

    /// Hold the pending-list lock just long enough to snapshot
    /// every `(region, cohort_id)` pair into an owned [`Vec`], then
    /// release. Sorting + dedup happen outside the lock so the
    /// hot lock window stays tight.
    fn snapshot_pending_pairs_under_lock(&self) -> Vec<(String, CohortId)> {
        let waiters = self.pending.lock();
        let mut acc: Vec<(String, CohortId)> = Vec::new();
        for (region, bucket) in waiters.iter() {
            extend_pairs_from_bucket(&mut acc, region, bucket);
        }
        drop(waiters);
        acc
    }

    /// Cancel every waiter whose `cohort_id` is not present in
    /// `live_cohort_ids`. Drops the matching
    /// [`tokio::sync::oneshot::Sender`]s, which surfaces to the
    /// awaiting axum handler as `oneshot::error::RecvError` — the
    /// handler maps that to `503 Service Unavailable` so the peer
    /// learns to retry rather than hang forever.
    ///
    /// Walks every region's bucket. Returns the count of waiters
    /// that were cancelled. Called by the rotation scheduler after
    /// a cohort eviction so a peer bucketed under a cohort that has
    /// since been evicted does not leak its sender into the next
    /// epoch.
    pub fn cancel_orphans<CohortIdSlice>(&self, live_cohort_ids: CohortIdSlice) -> usize
    where
        CohortIdSlice: AsRef<[CohortId]>,
    {
        let live = live_cohort_ids.as_ref();
        let mut waiters = self.pending.lock();
        let mut cancelled: usize = 0;
        let mut empty_regions: Vec<String> = Vec::new();
        for (region, bucket) in waiters.iter_mut() {
            cancelled = cancelled.saturating_add(cancel_orphans_in_bucket(bucket, live));
            if bucket.is_empty() {
                empty_regions.push(region.clone());
            }
        }
        for region in empty_regions {
            waiters.remove(&region);
        }
        cancelled
    }
}

/// Partition one region's bucket into surviving entries (cohort
/// still live) and dropped entries (cohort orphaned). Dropped
/// entries' `response_tx` is released, which the awaiting handler
/// observes as `RecvError`. Returns the count of cancelled
/// entries.
fn cancel_orphans_in_bucket(bucket: &mut Vec<PendingAdmission>, live: &[CohortId]) -> usize {
    let mut surviving: Vec<PendingAdmission> = Vec::with_capacity(bucket.len());
    let mut cancelled: usize = 0;
    for entry in bucket.drain(..) {
        if live.contains(&entry.cohort_id) {
            surviving.push(entry);
        } else {
            // Dropping `entry` drops `response_tx`, which the
            // awaiting handler observes as RecvError.
            cancelled = cancelled.saturating_add(1);
            drop(entry);
        }
    }
    *bucket = surviving;
    cancelled
}

/// Append every `(region, cohort_id)` pair from `bucket` into
/// `acc`. Extracted so [`AdmissionGate::pending_buckets`]
/// stays under the `clippy::excessive_nesting` threshold without
/// introducing a manual scope nest inside the hot lock window.
fn extend_pairs_from_bucket(
    acc: &mut Vec<(String, CohortId)>,
    region: &str,
    bucket: &[PendingAdmission],
) {
    for entry in bucket {
        acc.push((region.to_owned(), entry.cohort_id));
    }
}

/// Build a wire [`MatchResponse`] from the cohort id + record.
///
/// Phase 1's admission gate only emits the single-hop branch
/// ([`MatchResponse::SingleHop`]); multi-hop assignments arrive in
/// R-MULTIHOP-COORD when the coordinator-side path assembly lands.
///
/// `exit_region_lookup` resolves each exit [`NodeId`] to its
/// operator-tagged region string at admit / drain time, populating the
/// per-exit [`SingleHopMatch::exit_regions`] map. Exits with no entry
/// in the lookup do not appear in the emitted map; the client's
/// `pick_exit(..., ExitFilter::Region(region), ..)` treats those as
/// non-matches per F-CLI.4b. When the caller has no lookup (in-module
/// tests, MVP boot-time stub), pass a closure that always returns
/// `None` — the emitted map will be empty and any region-filtered
/// pick falls back to the §11 R-3 refusal path.
fn build_response(
    cohort_id: CohortId,
    cohort: &CohortRecord,
    exit_region_lookup: ExitRegionLookup<'_>,
) -> MatchResponse {
    let mut exit_regions: HashMap<NodeId, String> = HashMap::with_capacity(cohort.exits.len());
    for exit in &cohort.exits {
        if let Some(region) = exit_region_lookup(*exit) {
            exit_regions.insert(*exit, region);
        }
    }
    MatchResponse::SingleHop(SingleHopMatch {
        cohort: cohort_id,
        exit_set: cohort.exits.clone(),
        exit_regions,
        rotation_deadline: cohort.rotation_deadline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::{CohortId, NodeId, PeerId, RedactionKey, Timestamp};
    use std::sync::Arc;
    use time::Duration;

    use crate::coordinator::audit::{AuditKind, AuditLog};

    fn cohort_with(members: Vec<PeerId>) -> CohortRecord {
        CohortRecord {
            members,
            exits: vec![NodeId::new()],
            rotation_deadline: Timestamp::from_offset_date_time(
                time::OffsetDateTime::now_utc() + Duration::minutes(15),
            ),
            region: String::new(),
        }
    }

    /// Test stub: every exit's region is unknown. Mirrors the
    /// MVP boot-time default and exercises the empty-map branch on
    /// the emitted `MatchResponse.exit_regions`.
    fn no_region_lookup() -> ExitRegionLookup<'static> {
        &|_| None
    }

    fn audit_log_with_temp() -> (AuditLog, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let key = Arc::new(RedactionKey::from_bytes([0x42; 32]));
        let log = AuditLog::open(temp.path(), key).expect("open audit log");
        (log, temp)
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
        let outcome =
            gate.admit_or_bucket(peer, cohort_id, "us-east", &mut cohort, no_region_lookup());
        match outcome {
            AdmissionOutcome::Admitted(response) => match *response {
                MatchResponse::SingleHop(single_hop) => {
                    assert_eq!(single_hop.cohort, cohort_id);
                    assert_eq!(single_hop.exit_set, cohort.exits);
                    assert!(
                        single_hop.exit_regions.is_empty(),
                        "no-region lookup must emit empty exit_regions, got {:?}",
                        single_hop.exit_regions,
                    );
                },
                MatchResponse::MultiHopAssignment(_) => {
                    panic!("admission gate must emit single-hop only at this phase")
                },
            },
            AdmissionOutcome::Bucketed(_) => panic!("must admit immediately"),
            AdmissionOutcome::RegionMismatch { .. } => {
                panic!("single-region happy path must not see RegionMismatch")
            },
        }
        assert_eq!(gate.pending_count(), 0);
        assert!(cohort.members.contains(&peer));
        assert_eq!(cohort.region, "us-east");
    }

    #[test]
    fn admit_buckets_below_floor_then_drains_when_floor_met() {
        // Contract: peers arriving below the floor are bucketed;
        // a later admission that pushes the cohort over the floor
        // releases every bucketed peer via drain_ready. Catches a
        // regression that lost a waiter inside drain (which would
        // strand peers in the bucket forever). Single-region happy
        // path: matches the pre-R-FLOOR behavior when all peers
        // declare the same region.
        let gate = AdmissionGate::new(3);
        let cohort_id = CohortId::new();
        let mut cohort = cohort_with(Vec::new());
        let region = "us-east";

        let first = PeerId::new();
        let outcome_first =
            gate.admit_or_bucket(first, cohort_id, region, &mut cohort, no_region_lookup());
        let mut receiver_first = match outcome_first {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            AdmissionOutcome::Admitted(_) => panic!("first peer must bucket"),
            AdmissionOutcome::RegionMismatch { .. } => {
                panic!("single-region must not mismatch")
            },
        };

        let second = PeerId::new();
        let outcome_second =
            gate.admit_or_bucket(second, cohort_id, region, &mut cohort, no_region_lookup());
        let mut receiver_second = match outcome_second {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            AdmissionOutcome::Admitted(_) => panic!("second peer must bucket"),
            AdmissionOutcome::RegionMismatch { .. } => {
                panic!("single-region must not mismatch")
            },
        };

        // Third peer pushes the cohort to 3 — at the floor.
        let third = PeerId::new();
        let outcome_third =
            gate.admit_or_bucket(third, cohort_id, region, &mut cohort, no_region_lookup());
        assert!(matches!(outcome_third, AdmissionOutcome::Admitted(_)));
        let released = gate.drain_ready(region, cohort_id, &cohort, None, no_region_lookup());
        assert_eq!(released, 2);
        assert_eq!(gate.pending_count(), 0);
        assert_eq!(cohort.region, region);

        // Both receivers must now resolve to a MatchResponse with
        // the real cohort id.
        let response_first = receiver_first.try_recv().expect("first receiver should resolve");
        let response_second = receiver_second.try_recv().expect("second receiver should resolve");
        let MatchResponse::SingleHop(first) = response_first else {
            panic!("admission gate must emit single-hop only at this phase");
        };
        let MatchResponse::SingleHop(second) = response_second else {
            panic!("admission gate must emit single-hop only at this phase");
        };
        assert_eq!(first.cohort, cohort_id);
        assert_eq!(first.exit_set, cohort.exits);
        assert_eq!(second.cohort, cohort_id);
        assert_eq!(second.exit_set, cohort.exits);
    }

    #[test]
    fn drain_is_no_op_when_floor_still_unmet() {
        // Contract: drain_ready with a sub-floor cohort releases
        // nobody and leaves every waiter on the list.
        let gate = AdmissionGate::new(5);
        let cohort_id = CohortId::new();
        let mut cohort = cohort_with(Vec::new());
        let _outcome = gate.admit_or_bucket(
            PeerId::new(),
            cohort_id,
            "us-east",
            &mut cohort,
            no_region_lookup(),
        );
        let _outcome_second = gate.admit_or_bucket(
            PeerId::new(),
            cohort_id,
            "us-east",
            &mut cohort,
            no_region_lookup(),
        );
        let released = gate.drain_ready("us-east", cohort_id, &cohort, None, no_region_lookup());
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
        let _outcome =
            gate.admit_or_bucket(peer, cohort_id, "us-east", &mut cohort, no_region_lookup());
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
        let outcome = gate.admit_or_bucket(
            shared_peer,
            cohort_old,
            "us-east",
            &mut old_record,
            no_region_lookup(),
        );
        let mut receiver = match outcome {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            AdmissionOutcome::Admitted(_) => panic!("must bucket"),
            AdmissionOutcome::RegionMismatch { .. } => {
                panic!("fresh cohort must not mismatch")
            },
        };

        // Construct a *separate* new cohort that already meets the
        // floor and happens to list `shared_peer` among its
        // members. The matchmaker should never call drain_ready on
        // a cohort the peer was not bucketed under, but a
        // regression that ignored entry.cohort_id would release
        // the old-cohort waiter against the new cohort's response
        // here. The drain call models that buggy path; the test
        // asserts the gate refuses to release the waiter anyway.
        let new_record = CohortRecord {
            members: vec![shared_peer, PeerId::new()],
            exits: vec![NodeId::new()],
            rotation_deadline: Timestamp::from_offset_date_time(
                time::OffsetDateTime::now_utc() + Duration::minutes(15),
            ),
            region: "us-east".to_owned(),
        };
        let released =
            gate.drain_ready("us-east", cohort_new, &new_record, None, no_region_lookup());
        assert_eq!(released, 0, "old-cohort waiter must not be released");
        assert_eq!(gate.pending_count(), 1, "old-cohort waiter must remain");
        // Old waiter still genuinely pending (Empty, not Closed) —
        // its sender is alive in the bucket. A regression that
        // drained across cohorts would have either resolved (Ok) or
        // closed (Closed); both must be rejected here.
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty),
        ));
    }

    #[test]
    fn admit_refuses_when_cohort_already_tagged_with_different_region() {
        // Contract: a cohort already tagged with `eu-de` rejects a
        // peer arriving with `us-east`. Refusal is the safe
        // outcome — admitting would let two regions share one
        // anonymity set (the union-fallback failure mode the
        // §11 R-3 codex-corrected text rejected). Catches a
        // regression that trusted the caller's region argument
        // and overwrote / mixed.
        let gate = AdmissionGate::new(3);
        let cohort_id = CohortId::new();
        let mut cohort = cohort_with(Vec::new());

        // First admission stamps the cohort with `eu-de`.
        let first = PeerId::new();
        let outcome_first =
            gate.admit_or_bucket(first, cohort_id, "eu-de", &mut cohort, no_region_lookup());
        assert!(matches!(outcome_first, AdmissionOutcome::Bucketed(_)));
        assert_eq!(cohort.region, "eu-de");

        // Second admission with a different region must refuse.
        let second = PeerId::new();
        let outcome_second =
            gate.admit_or_bucket(second, cohort_id, "us-east", &mut cohort, no_region_lookup());
        match outcome_second {
            AdmissionOutcome::RegionMismatch {
                existing_region,
                requested_region,
            } => {
                assert_eq!(existing_region, "eu-de");
                assert_eq!(requested_region, "us-east");
            },
            other => panic!("expected RegionMismatch, got {other:?}"),
        }
        // Members and region are unchanged by the refusal.
        assert_eq!(cohort.members, vec![first]);
        assert_eq!(cohort.region, "eu-de");
        // The refused peer is NOT in any pending bucket.
        assert_eq!(gate.pending_count_for_region("us-east"), 0);
        assert_eq!(gate.pending_count_for_region("eu-de"), 1);
    }

    #[test]
    fn admit_replaces_prior_waiter_on_retry_for_same_peer_and_cohort() {
        // Contract: a peer that re-issues admit_or_bucket for the
        // same (region, cohort_id) replaces its prior waiter — the
        // bucket stays size-1 for that peer, not size-2. Catches a
        // memory regression: HTTP-timeout-triggered retries would
        // otherwise accumulate dead `response_tx` senders
        // indefinitely in an under-floor region's bucket.
        let gate = AdmissionGate::new(30);
        let cohort_id = CohortId::new();
        let mut cohort = cohort_with(Vec::new());
        let peer = PeerId::new();

        let outcome_first =
            gate.admit_or_bucket(peer, cohort_id, "us-east", &mut cohort, no_region_lookup());
        let mut receiver_first = match outcome_first {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            other => panic!("first admit must bucket, got {other:?}"),
        };
        assert_eq!(gate.pending_count_for_region("us-east"), 1);

        // Same peer, same cohort, same region — simulates a retry
        // after HTTP timeout.
        let outcome_second =
            gate.admit_or_bucket(peer, cohort_id, "us-east", &mut cohort, no_region_lookup());
        let mut receiver_second = match outcome_second {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            other => panic!("retry admit must bucket, got {other:?}"),
        };
        // Bucket stays size-1 — the prior entry was replaced.
        assert_eq!(gate.pending_count_for_region("us-east"), 1);
        // Prior receiver collapses to RecvError (sender dropped).
        assert!(matches!(
            receiver_first.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed),
        ));
        // New receiver is genuinely pending (Empty, not Closed) —
        // its sender is still alive in the bucket waiting for the
        // floor to clear. Distinguishing Empty from Closed is
        // load-bearing: a regression that also dropped the new
        // sender would show up as Closed here.
        assert!(matches!(
            receiver_second.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty),
        ));
    }

    /// Bucket `count` fresh peers into `gate` for `region` against
    /// the supplied `cohort_id`, accumulating their oneshot
    /// receivers. Panics if any admit returns `Admitted` or
    /// `RegionMismatch` — used by the two-region happy-path test
    /// where every admit below the floor must bucket cleanly.
    fn bucket_peers(
        gate: &AdmissionGate,
        region: &str,
        cohort_id: CohortId,
        cohort: &mut CohortRecord,
        count: u32,
    ) -> Vec<tokio::sync::oneshot::Receiver<MatchResponse>> {
        let mut receivers: Vec<tokio::sync::oneshot::Receiver<MatchResponse>> = Vec::new();
        for _index in 0..count {
            let outcome =
                gate.admit_or_bucket(PeerId::new(), cohort_id, region, cohort, no_region_lookup());
            match outcome {
                AdmissionOutcome::Bucketed(receiver) => receivers.push(receiver),
                AdmissionOutcome::Admitted(_) => {
                    panic!("{region} should bucket below floor")
                },
                AdmissionOutcome::RegionMismatch { .. } => {
                    panic!("{region} must not mismatch on {region} admits")
                },
            }
        }
        receivers
    }

    /// Drive `count` admissions against `gate` for a region that
    /// will cross the floor — i.e. the first `floor - 1` admissions
    /// bucket, the `floor`th onward admit. Returns only the
    /// bucketed receivers (the admitted ones already got their
    /// `MatchResponse` via the admit return).
    #[allow(
        clippy::too_many_arguments,
        reason = "Test helper: the floor-crossing drive needs every \
                  parameter the production `admit_or_bucket` needs \
                  plus the count of admissions and the floor itself. \
                  Test-side helpers are exempt from the strict five- \
                  argument bound the production-path helpers honour."
    )]
    fn admit_to_floor_crossing(
        gate: &AdmissionGate,
        region: &str,
        cohort_id: CohortId,
        cohort: &mut CohortRecord,
        count: u32,
        floor: u32,
    ) -> Vec<tokio::sync::oneshot::Receiver<MatchResponse>> {
        let mut receivers: Vec<tokio::sync::oneshot::Receiver<MatchResponse>> = Vec::new();
        let pre_floor = floor.saturating_sub(1);
        for index in 0..count {
            let outcome =
                gate.admit_or_bucket(PeerId::new(), cohort_id, region, cohort, no_region_lookup());
            match outcome {
                AdmissionOutcome::RegionMismatch { .. } => {
                    panic!("{region} must not mismatch on {region} admits")
                },
                AdmissionOutcome::Bucketed(receiver) => {
                    assert!(
                        index < pre_floor,
                        "{region} waiter beyond floor must admit, not bucket",
                    );
                    receivers.push(receiver);
                },
                AdmissionOutcome::Admitted(_) => {
                    assert!(
                        index >= pre_floor,
                        "{region} admission below floor must bucket, not admit",
                    );
                },
            }
        }
        receivers
    }

    /// Count the [`AuditKind::NoAnonymousPathAvailable`] rows in
    /// `log` and return their `(region, pending_count)` payloads,
    /// in stored order. Extracted so callers do not have to
    /// inline the filter (which would otherwise re-trigger the
    /// cognitive-complexity lint on bigger test bodies).
    fn collect_refusals(log: &AuditLog) -> Vec<(String, u32)> {
        let rows = log.snapshot().expect("snapshot audit log");
        rows.into_iter()
            .filter_map(|entry| match entry.kind {
                AuditKind::NoAnonymousPathAvailable { region, pending_count } => {
                    Some((region, pending_count))
                },
                _ => None,
            })
            .collect()
    }

    #[test]
    fn two_regions_release_independently_when_one_meets_floor() {
        // Contract: us-east 5 members + eu-de 35 members → only
        // eu-de releases; us-east buckets remain pending. The
        // gate's partitioning by region must be honoured at drain.
        // Catches a regression that drained across regions (which
        // would let a small region piggy-back on a large region's
        // floor-crossing — exactly the union fallback the §11 R-3
        // codex-corrected text refused).
        const FLOOR: u32 = 30;
        let gate = AdmissionGate::new(FLOOR);
        let (audit, _audit_temp) = audit_log_with_temp();

        // us-east cohort: 5 members, all bucketed (under-floor).
        let us_east_cohort_id = CohortId::new();
        let mut us_east_cohort = cohort_with(Vec::new());
        let mut us_east_receivers =
            bucket_peers(&gate, "us-east", us_east_cohort_id, &mut us_east_cohort, 5);

        // eu-de cohort: 35 admits, first 29 bucket, 30th onward admit.
        let eu_de_cohort_id = CohortId::new();
        let mut eu_de_cohort = cohort_with(Vec::new());
        let eu_de_receivers =
            admit_to_floor_crossing(&gate, "eu-de", eu_de_cohort_id, &mut eu_de_cohort, 35, FLOOR);

        // Drain eu-de — every bucketed waiter resolves.
        let eu_de_released = gate.drain_ready(
            "eu-de",
            eu_de_cohort_id,
            &eu_de_cohort,
            Some(&audit),
            no_region_lookup(),
        );
        assert_eq!(eu_de_released, 29);
        for mut receiver in eu_de_receivers {
            let response = receiver.try_recv().expect("eu-de waiter resolves");
            let MatchResponse::SingleHop(single_hop) = response else {
                panic!("admission gate must emit single-hop only at this phase");
            };
            assert_eq!(single_hop.cohort, eu_de_cohort_id);
        }

        // Drain us-east — none release; one refusal emitted.
        let us_east_released = gate.drain_ready(
            "us-east",
            us_east_cohort_id,
            &us_east_cohort,
            Some(&audit),
            no_region_lookup(),
        );
        assert_eq!(us_east_released, 0);
        assert_eq!(
            gate.pending_count_for_region("us-east"),
            5,
            "us-east waiters must remain bucketed",
        );
        for receiver in &mut us_east_receivers {
            // Empty (not Closed) — waiter is still parked.
            assert!(
                matches!(
                    receiver.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty),
                ),
                "us-east waiter must remain pending, not resolve or close",
            );
        }

        // Cohort tagging: each released cohort carries its region.
        assert_eq!(eu_de_cohort.region, "eu-de");
        assert_eq!(us_east_cohort.region, "us-east");

        // Audit: exactly one NoAnonymousPathAvailable for us-east
        // (the under-floor drain), and zero for eu-de (met floor).
        let refusals = collect_refusals(&audit);
        assert_eq!(refusals.len(), 1, "exactly one refusal entry expected");
        let (refusal_region, refusal_count) = &refusals[0];
        assert_eq!(refusal_region, "us-east");
        assert_eq!(*refusal_count, 5);
    }

    #[test]
    fn under_floor_region_emits_one_audit_entry_per_drain_poll() {
        // Contract: an under-floor non-empty region emits a fresh
        // NoAnonymousPathAvailable entry on every drain_ready
        // poll. Catches a regression that deduped audit emissions
        // (which would mask a stuck region from operator
        // dashboards).
        const FLOOR: u32 = 30;
        let gate = AdmissionGate::new(FLOOR);
        let (audit, _audit_temp) = audit_log_with_temp();

        let cohort_id = CohortId::new();
        let mut cohort = cohort_with(Vec::new());
        // Park 5 peers in us-east — under-floor, non-empty.
        for _index in 0..5 {
            let outcome = gate.admit_or_bucket(
                PeerId::new(),
                cohort_id,
                "us-east",
                &mut cohort,
                no_region_lookup(),
            );
            assert!(
                matches!(outcome, AdmissionOutcome::Bucketed(_)),
                "us-east must bucket below floor",
            );
        }

        // Poll the gate three times. Each poll must emit one
        // refusal entry.
        for _poll in 0..3 {
            let released =
                gate.drain_ready("us-east", cohort_id, &cohort, Some(&audit), no_region_lookup());
            assert_eq!(released, 0);
        }

        let refusals = collect_refusals(&audit);
        assert_eq!(refusals.len(), 3, "one refusal per poll, no dedup");
        for (region, pending_count) in &refusals {
            assert_eq!(region, "us-east");
            assert_eq!(*pending_count, 5);
        }
        // Bucket survives every refusal poll.
        assert_eq!(gate.pending_count_for_region("us-east"), 5);
    }

    #[test]
    fn empty_under_floor_bucket_emits_no_refusal() {
        // Contract: a poll against a cohort that is under the floor
        // but whose region's bucket is empty (e.g. waiters were
        // already cancelled by rotation, or no peer ever bucketed)
        // must NOT emit a NoAnonymousPathAvailable. Catches a
        // regression that emitted refusals for the empty case
        // (which would flood the audit log with phantom rows).
        const FLOOR: u32 = 30;
        let gate = AdmissionGate::new(FLOOR);
        let (audit, _audit_temp) = audit_log_with_temp();

        let cohort_id = CohortId::new();
        let cohort = cohort_with(Vec::new());

        let released =
            gate.drain_ready("us-east", cohort_id, &cohort, Some(&audit), no_region_lookup());
        assert_eq!(released, 0);

        let rows = audit.snapshot().expect("snapshot");
        let refusal_count = rows
            .iter()
            .filter(|entry| matches!(entry.kind, AuditKind::NoAnonymousPathAvailable { .. }))
            .count();
        assert_eq!(refusal_count, 0);
    }
}
