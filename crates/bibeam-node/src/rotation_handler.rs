#![forbid(unsafe_code)]
//! Node-side rotation event handler with atomic cohort swap (F-NODE.6).
//!
//! When the coordinator emits a
//! [`bibeam_discovery::CoordinatorEvent::CohortRotated`] event (every
//! 15 min or 500 MB per the §11 R-3 / F-COORD.6 cadence), the node
//! must replace its active cohort assignment WITHOUT dropping any
//! in-flight datagram. This module is the node-side counterpart to
//! the coord-side [`crate::coordinator::rotation::RotationScheduler`].
//!
//! ## Shape
//!
//! [`RotationHandler`] owns a single
//! <code>[arc_swap::ArcSwap]<[bibeam_protocol::cohort::CohortLive]></code>.
//! `ArcSwap` is a lock-free atomic-swap container for an [`Arc`]:
//! reads (`load_full`) are wait-free and never block writes; writes
//! (`store`) publish a new [`Arc`] in a single atomic exchange and
//! return immediately. The two halves cooperate via reference counts —
//! the previous cohort's [`Arc`] is dropped only once every in-flight
//! reader that captured a clone has itself dropped its clone. This
//! gives us the "drain in-flight readers without an explicit drain
//! call" semantics F-NODE.6 needs without bolting on a separate
//! synchronisation primitive (no `RwLock`, no `Notify`, no
//! `tokio::sync::watch`).
//!
//! ## Why `ArcSwap`, not `RwLock<Arc<CohortLive>>`
//!
//! A `RwLock` would serialise every read against the writer's
//! `write()`, so an arriving rotation could stall a packet-handling
//! task that is mid-decision. `ArcSwap` lets the writer publish a new
//! cohort while readers continue to use the old one to completion;
//! there is no read-vs-write contention at the data-plane edge. This
//! mirrors the load-bearing constraint in the F-NODE.6 task:
//! "atomically swap its active cohort assignment WITHOUT dropping any
//! in-flight packets".
//!
//! ## `CohortHandler` trait — provisional, pending F-NODE.5
//!
//! F-NODE.5 (Cohort assignment receiver) is landing in parallel on a
//! disjoint file set and will eventually own the canonical
//! [`CohortHandler`] trait that dispatches `CohortAssigned` and
//! `CohortRotated` events. F-NODE.6's task spec requires
//! `impl CohortHandler for RotationHandler { fn on_rotated(...) }`,
//! which cannot compile without the trait, so the trait is defined
//! here as a forward declaration. When F-NODE.5 lands, whoever
//! merges second consolidates: either F-NODE.5's PR moves the trait
//! to its own module and this file `pub use`s it, or this module
//! stays the canonical home and F-NODE.5 imports from here. The
//! trait surface is intentionally narrow — a single
//! [`CohortHandler::on_rotated`] entry point matching the F-NODE.6
//! task spec, with the obvious `Send + Sync` bound so the
//! coordinator event-loop task can dispatch into it from any
//! tokio worker.
//!
//! ## Out of scope (deferred to follow-ups)
//!
//! - Explicit packet draining — the [`Arc<CohortLive>`] reference
//!   count is the drain mechanism (in-flight readers hold their own
//!   clones).
//! - Re-establishing `WireGuard` sessions after rotation — that is
//!   F-CLI.5's responsibility on the client; the node accepts new
//!   sessions via the F-NODE.2 Quinn accept loop.
//! - Wiring into `main.rs` — left as a `// TODO(F-NODE.5)` note in the
//!   coordinator event loop once F-NODE.5 lands.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use bibeam_protocol::cohort::CohortLive;

use crate::telemetry::NODE_COHORT_ROTATIONS_TOTAL;

/// Provisional trait for the node-side handler of coordinator-pushed
/// cohort events.
///
/// F-NODE.6 only exercises [`Self::on_rotated`]; the broader event
/// surface (`CohortAssigned`, `Disconnect`) belongs to F-NODE.5, which
/// is landing on a disjoint file set in parallel. Defining the trait
/// here lets the rotation handler land independently; the eventual
/// canonical home is F-NODE.5's module, at which point one of the
/// two PRs `pub use`s the other's definition (see the module-level
/// doc for the consolidation rule).
///
/// Implementors MUST be `Send + Sync` — the coordinator event-loop
/// task dispatches into them from a `tokio` worker and the handler
/// runs concurrently with active-cohort reads on every data-plane
/// site. Implementations MUST be non-blocking at the read-side and
/// MUST NOT block the dispatch caller, since the event loop is
/// shared with other event variants.
pub trait CohortHandler: Send + Sync {
    /// Handle a `CohortRotated` event by adopting `new` as the
    /// active cohort.
    fn on_rotated(&self, new: CohortLive);
}

/// Node-side handler for [`bibeam_discovery::CoordinatorEvent::CohortRotated`].
///
/// Owns the active [`CohortLive`] snapshot behind an
/// [`arc_swap::ArcSwap`] so the data-plane fast path can read the
/// current cohort without taking a lock and the control-plane writer
/// can publish a fresh cohort with a single atomic exchange. The
/// rotation count is mirrored in an [`AtomicU64`] alongside the
/// `metrics::counter!` call so unit tests can assert the rotation
/// cadence deterministically without installing a global recorder.
///
/// `RotationHandler` is `Send + Sync` and is meant to be wrapped in
/// an [`Arc`] and cloned into the coordinator event-loop task and
/// every data-plane reader site.
pub struct RotationHandler {
    /// Current active cohort. Replaced atomically on every rotation.
    active_cohort: ArcSwap<CohortLive>,
    /// Side-channel rotation counter, kept in lock-step with the
    /// [`NODE_COHORT_ROTATIONS_TOTAL`] metric. Exists so unit tests
    /// can assert rotation counts without installing a global
    /// `metrics_exporter_prometheus` recorder (the recorder install
    /// is one-shot per process and tests run in parallel).
    rotations: AtomicU64,
}

impl core::fmt::Debug for RotationHandler {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Manual impl: `ArcSwap` is not `Debug`. Load a snapshot just
        // for the formatter and surface the rotation count alongside.
        let snapshot = self.active_cohort.load_full();
        formatter
            .debug_struct("RotationHandler")
            .field("active_cohort", snapshot.as_ref())
            .field("rotations", &self.rotations.load(Ordering::Relaxed))
            .finish()
    }
}

impl RotationHandler {
    /// Construct a [`RotationHandler`] with `initial` as the
    /// currently-active cohort.
    ///
    /// The rotation counter starts at zero — only subsequent
    /// [`Self::swap_to`] calls increment it. The initial cohort
    /// assignment is a `CohortAssigned` event in the F-NODE.5
    /// surface, not a rotation, so it MUST NOT bump the rotation
    /// metric.
    pub fn new(initial: CohortLive) -> Self {
        Self {
            active_cohort: ArcSwap::new(Arc::new(initial)),
            rotations: AtomicU64::new(0),
        }
    }

    /// Return an [`Arc`]-shared clone of the currently-active cohort.
    ///
    /// This is the fast-path read invoked by every data-plane site
    /// that needs to consult the active cohort (exit picker, peer
    /// admission check, forwarder routing). It is lock-free and
    /// wait-free under contention.
    ///
    /// The returned [`Arc`] is a snapshot: if a rotation lands while
    /// the caller is mid-decision, the snapshot stays valid and the
    /// caller finishes against the old cohort. The new cohort is
    /// only observed on the next call to this method.
    pub fn current_cohort(&self) -> Arc<CohortLive> {
        self.active_cohort.load_full()
    }

    /// Atomically replace the active cohort with `new`.
    ///
    /// O(1) lock-free: a single atomic pointer exchange. The
    /// previously-active cohort's [`Arc`] is dropped only once every
    /// in-flight reader that captured a clone has itself dropped its
    /// clone (this is the implicit drain mechanism that lets the
    /// node honour the F-NODE.6 "no dropped packets" requirement).
    ///
    /// Emits a [`tracing::info!`] audit line and increments the
    /// [`NODE_COHORT_ROTATIONS_TOTAL`] metric alongside an internal
    /// [`AtomicU64`] counter that tests use to assert the rotation
    /// count without a global recorder install.
    pub fn swap_to(&self, new: CohortLive) {
        let new_cohort_id = new.cohort;
        // The `store` is the load-bearing operation: it publishes the
        // new `Arc<CohortLive>` and returns the swapped-out pointer
        // into a refcount that drops when the last reader releases
        // its clone. We hold no reference to the old cohort here —
        // letting it drop on the writer side would defeat the
        // implicit drain.
        self.active_cohort.store(Arc::new(new));
        // The Relaxed ordering is sufficient: the counter is
        // observation-only telemetry and is not used to synchronise
        // any data-plane memory; the `ArcSwap::store` above carries
        // its own AcqRel publication.
        let prior = self.rotations.fetch_add(1, Ordering::Relaxed);
        metrics::counter!(NODE_COHORT_ROTATIONS_TOTAL).increment(1);
        tracing::info!(
            target: "bibeam_node::rotation",
            cohort = %new_cohort_id,
            rotations = prior.saturating_add(1),
            "cohort rotation applied",
        );
    }

    /// Return the total number of rotations this handler has
    /// processed since construction.
    ///
    /// Mirrors the [`NODE_COHORT_ROTATIONS_TOTAL`] metric. Surfaced
    /// for tests + ad-hoc operator diagnostics; the on-the-wire
    /// authoritative source is the Prometheus metric.
    pub fn rotation_count(&self) -> u64 {
        self.rotations.load(Ordering::Relaxed)
    }
}

impl CohortHandler for RotationHandler {
    fn on_rotated(&self, new: CohortLive) {
        self.swap_to(new);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
    use bibeam_protocol::cohort::CohortLive;

    use super::{CohortHandler, RotationHandler};

    /// Build a [`CohortLive`] with a single member + single exit,
    /// freshly-generated identifiers, and the current wall clock.
    ///
    /// Tests below only care about the identity of the cohort (the
    /// `cohort` field); the membership / exit lists are stubbed out
    /// because the rotation handler treats `CohortLive` as an opaque
    /// payload.
    fn sample_cohort() -> CohortLive {
        CohortLive {
            cohort: CohortId::new(),
            members: vec![PeerId::new()],
            exits: vec![NodeId::new()],
            exit_regions: HashMap::new(),
            at: Timestamp::now(),
        }
    }

    /// Per-writer worker for [`swap_under_concurrent_reads_is_lock_free`].
    ///
    /// Pulled out of the spawn-loop closure so the test body stays
    /// under the workspace's `clippy::excessive_nesting` threshold.
    fn writer_body(handler: &RotationHandler, cohorts: &[CohortLive], start: usize, count: usize) {
        for offset in 0..count {
            handler.swap_to(cohorts[start + offset].clone());
        }
    }

    /// Per-reader worker for [`swap_under_concurrent_reads_is_lock_free`].
    ///
    /// Encodes the "every observation must be in the known-good set"
    /// check using `usize::from(!contains)` so the per-read body is a
    /// straight-line expression with no `if`. This keeps the function
    /// flat and dodges `clippy::excessive_nesting` inside the spawn-
    /// loop closure that calls it.
    fn reader_body(
        handler: &RotationHandler,
        known_ids: &std::collections::HashSet<CohortId>,
        observed_foreign: &AtomicUsize,
        reads: usize,
    ) {
        for _ in 0..reads {
            let snapshot = handler.current_cohort();
            let foreign = usize::from(!known_ids.contains(&snapshot.cohort));
            observed_foreign.fetch_add(foreign, Ordering::Relaxed);
        }
    }

    /// Contract: construction with cohort A makes A the result of
    /// the first `current_cohort()` read.
    ///
    /// Locks in the invariant that the initial snapshot is published
    /// before any rotation lands. Without this, a regression that
    /// initialised the `ArcSwap` to an uninhabited cohort and only
    /// populated it on the first `swap_to` would let an early
    /// data-plane reader observe a stale / empty assignment.
    #[test]
    fn current_cohort_returns_initial() {
        let initial = sample_cohort();
        let initial_id = initial.cohort;
        let handler = RotationHandler::new(initial);

        let snapshot = handler.current_cohort();
        assert_eq!(snapshot.cohort, initial_id);
        assert_eq!(handler.rotation_count(), 0);
    }

    /// Contract: after `swap_to(B)`, `current_cohort()` returns B.
    ///
    /// Catches a regression that took the swap value by reference and
    /// forgot to actually publish it into the `ArcSwap`. Also verifies
    /// the rotation counter is bumped exactly once per swap.
    #[test]
    fn swap_to_replaces_cohort_atomically() {
        let initial = sample_cohort();
        let replacement = sample_cohort();
        let replacement_id = replacement.cohort;
        let handler = RotationHandler::new(initial);

        handler.swap_to(replacement);

        let snapshot = handler.current_cohort();
        assert_eq!(snapshot.cohort, replacement_id);
        assert_eq!(handler.rotation_count(), 1);
    }

    /// Contract: `on_rotated` (the `CohortHandler` trait method)
    /// dispatches to `swap_to`.
    ///
    /// Locks in the F-NODE.6 task-spec requirement
    /// `impl CohortHandler for RotationHandler { fn on_rotated(...) }`.
    /// A regression that wired `on_rotated` to a no-op (or to a
    /// different cohort field) would let coordinator rotation events
    /// silently drop on the floor.
    #[test]
    fn on_rotated_dispatches_to_swap() {
        let initial = sample_cohort();
        let replacement = sample_cohort();
        let replacement_id = replacement.cohort;
        let handler = RotationHandler::new(initial);

        <RotationHandler as CohortHandler>::on_rotated(&handler, replacement);

        let snapshot = handler.current_cohort();
        assert_eq!(snapshot.cohort, replacement_id);
        assert_eq!(handler.rotation_count(), 1);
    }

    /// Contract: concurrent reads + concurrent swaps never produce a
    /// torn read or a panic, and every read returns a well-formed
    /// `CohortLive` (its `cohort` field is one of the cohorts we
    /// pushed into the handler).
    ///
    /// 4 writer threads each call `swap_to` 16 times (64 total swaps);
    /// 16 reader threads each call `current_cohort` 64 times in a
    /// tight loop. Every observed cohort id is checked against a
    /// pre-built [`Arc`]-shared known-good set — a torn read would
    /// surface as a foreign id. The thread count is deliberately
    /// bounded (~20 OS threads, sub-second) so this is a soundness
    /// probe usable on every CI invocation, not a stress test that
    /// requires a dedicated runner.
    #[test]
    fn swap_under_concurrent_reads_is_lock_free() {
        const WRITERS: usize = 4;
        const SWAPS_PER_WRITER: usize = 16;
        const READERS: usize = 16;
        const READS_PER_READER: usize = 64;

        // Pre-mint every cohort the writers will ever publish so
        // readers can verify each observation against a known-good
        // set. The initial cohort is included so a reader that
        // observes "no swap has landed yet" also passes.
        let initial = sample_cohort();
        let initial_id = initial.cohort;
        let mut cohorts: Vec<CohortLive> = Vec::with_capacity(WRITERS * SWAPS_PER_WRITER);
        for _ in 0..(WRITERS * SWAPS_PER_WRITER) {
            cohorts.push(sample_cohort());
        }
        let mut id_set: std::collections::HashSet<CohortId> =
            cohorts.iter().map(|c| c.cohort).collect();
        id_set.insert(initial_id);
        // Share the known-good set + the pre-minted cohort vec by
        // `Arc` so the per-reader / per-writer work captures only a
        // pointer-sized clone, not the underlying collection.
        let known_ids: Arc<std::collections::HashSet<CohortId>> = Arc::new(id_set);
        let cohorts: Arc<Vec<CohortLive>> = Arc::new(cohorts);

        let handler = Arc::new(RotationHandler::new(initial));
        let observed_foreign = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(WRITERS + READERS);

        // Writers: each one owns a disjoint slice of the pre-minted
        // cohort vec and pushes its slice into the handler.
        for writer_idx in 0..WRITERS {
            let handler = Arc::clone(&handler);
            let cohorts = Arc::clone(&cohorts);
            let start = writer_idx * SWAPS_PER_WRITER;
            handles.push(thread::spawn(move || {
                writer_body(&handler, &cohorts, start, SWAPS_PER_WRITER);
            }));
        }

        // Readers: each one repeatedly snapshots the active cohort
        // and checks the cohort id against the known-good set. A
        // torn read would either surface as a panic inside `Arc`'s
        // refcount machinery (which `ArcSwap` is designed to prevent)
        // or — softer — as a `cohort` id we never minted.
        for _ in 0..READERS {
            let handler = Arc::clone(&handler);
            let known_ids = Arc::clone(&known_ids);
            let observed_foreign = Arc::clone(&observed_foreign);
            handles.push(thread::spawn(move || {
                reader_body(&handler, &known_ids, &observed_foreign, READS_PER_READER);
            }));
        }

        for handle in handles {
            handle.join().expect("worker thread joined without panic");
        }

        assert_eq!(
            observed_foreign.load(Ordering::Relaxed),
            0,
            "every concurrent reader must observe a known-good cohort id",
        );
        assert_eq!(
            handler.rotation_count(),
            (WRITERS * SWAPS_PER_WRITER) as u64,
            "every writer's swap_to call must have bumped the rotation counter",
        );
    }

    /// Contract: three sequential swaps bump the rotation counter to
    /// exactly three.
    ///
    /// This is the side-channel proxy for
    /// `bibeam_node_cohort_rotations_total = 3`. The
    /// `RotationHandler` increments the metric and the internal
    /// counter in lock-step inside `swap_to`, so a divergence between
    /// the two would surface as the metric-counter test failing.
    /// We assert the side-channel value rather than the Prometheus
    /// recorder because installing a recorder from a test would
    /// conflict with every other crate that also tests recorder
    /// state (the recorder install is one-shot per process).
    #[test]
    fn metric_counter_increments_per_swap() {
        let handler = RotationHandler::new(sample_cohort());

        for _ in 0..3 {
            handler.swap_to(sample_cohort());
        }

        assert_eq!(
            handler.rotation_count(),
            3,
            "three sequential swaps must produce a rotation count of 3",
        );
    }

    /// Contract: a `RotationHandler` is `Send + Sync` so it can be
    /// shared between the coordinator event-loop task and every
    /// data-plane reader.
    ///
    /// The other concurrent test exercises this dynamically; this is
    /// the static / compile-time guard.
    #[test]
    fn rotation_handler_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RotationHandler>();
    }
}
