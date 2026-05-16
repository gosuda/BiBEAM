#![forbid(unsafe_code)]
//! Cohort rotation scheduler (F-COORD.6).
//!
//! Per plan §2: the coordinator re-pools every 15 minutes or every
//! 500 MB (admission-time cap). The 15-minute wall clock is the
//! primary trigger at MVP; the 500-MB cap is informational and
//! tracked off-band (per-token byte counter in a future side
//! table). Each tick the scheduler:
//!
//! 1. Evicts stale peers from [`crate::registry::PeerRegistry`]
//!    (peers whose last heartbeat is older than the heartbeat SLO).
//! 2. Evicts expired cohorts from [`crate::cohorts::CohortStore`]
//!    (cohorts whose `rotation_deadline` has elapsed).
//! 3. Re-enforces the [`crate::admission_gate::AdmissionGate`]
//!    floor by draining ready waiters against any cohort that has
//!    cleared it since the last tick.
//!
//! ## Lifecycle
//!
//! [`RotationScheduler::run`] consumes the scheduler and loops
//! until the supplied [`tokio_util::sync::CancellationToken`]
//! fires. The daemon's main hands the same token clone to every
//! background task so a single shutdown signal collapses the
//! background fan-out cleanly.

use std::sync::Arc;
use std::time::Duration;

use bibeam_core::Timestamp;
use tokio::time::{Instant, interval_at};
use tokio_util::sync::CancellationToken;

use crate::admission_gate::AdmissionGate;
use crate::cohorts::{CohortStore, CohortStoreError};
use crate::registry::{PeerRegistry, RegistryError};

/// Re-pool cadence: the wall-clock window between rotation ticks.
/// 15 minutes per plan §2.
pub const ROTATION_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Heartbeat SLO. Peers whose last heartbeat is older than this
/// are evicted on the next tick. Set to twice the rotation interval
/// so a peer that missed a single heartbeat round is still retained.
pub const PEER_HEARTBEAT_SLO: Duration = Duration::from_secs(30 * 60);

/// Failure modes propagated out of a single rotation tick.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// Forwarded from [`PeerRegistry::evict_stale`].
    #[error("peer registry eviction failed: {0}")]
    Registry(#[from] RegistryError),
    /// Forwarded from [`CohortStore::evict_expired`].
    #[error("cohort store eviction failed: {0}")]
    CohortStore(#[from] CohortStoreError),
}

/// Background scheduler that drives cohort rotation.
///
/// Construct one instance per coordinator process; clone the
/// [`Arc`]-wrapped fields freely into the axum handlers that
/// share state with this loop.
#[derive(Debug)]
pub struct RotationScheduler {
    registry: Arc<PeerRegistry>,
    cohorts: Arc<CohortStore>,
    gate: Arc<AdmissionGate>,
    interval: Duration,
    heartbeat_slo: Duration,
}

impl RotationScheduler {
    /// Construct a scheduler with the default cadence
    /// ([`ROTATION_INTERVAL`]) and heartbeat SLO
    /// ([`PEER_HEARTBEAT_SLO`]).
    #[must_use]
    pub fn new(
        registry: Arc<PeerRegistry>,
        cohorts: Arc<CohortStore>,
        gate: Arc<AdmissionGate>,
    ) -> Self {
        Self::with_cadence(registry, cohorts, gate, ROTATION_INTERVAL, PEER_HEARTBEAT_SLO)
    }

    /// Construct a scheduler with custom timing. Intended for
    /// tests that drive the tick manually.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Arc<…> field types preclude const-eval; making this \
                  const adds an API promise we cannot honour at call \
                  sites that already hold runtime-allocated Arcs."
    )]
    pub fn with_cadence(
        registry: Arc<PeerRegistry>,
        cohorts: Arc<CohortStore>,
        gate: Arc<AdmissionGate>,
        interval: Duration,
        heartbeat_slo: Duration,
    ) -> Self {
        Self {
            registry,
            cohorts,
            gate,
            interval,
            heartbeat_slo,
        }
    }

    /// Drive the scheduler until `cancel` fires.
    ///
    /// One tick runs immediately at startup so a fresh deployment
    /// does not wait 15 minutes for its first eviction sweep.
    /// Errors inside a tick are logged via [`tracing::error!`]
    /// and the loop continues — a single redb hiccup must not
    /// take the rotation thread down for the process lifetime.
    pub async fn run(self, cancel: CancellationToken) {
        let start_at = Instant::now() + self.interval;
        let mut ticker = interval_at(start_at, self.interval);
        // Run one immediate tick so a fresh daemon does not wait a
        // full interval for its first sweep.
        self.tick_once_logged();
        loop {
            if self.wait_for_tick_or_cancel(&cancel, &mut ticker).await {
                return;
            }
            self.tick_once_logged();
        }
    }

    /// Drive one tick, logging the error if it fails. Used by both
    /// the immediate-startup tick and the in-loop tick so the
    /// surface that the cognitive-complexity gate sees in
    /// [`RotationScheduler::run`] stays minimal.
    fn tick_once_logged(&self) {
        if let Err(err) = self.tick_once() {
            tracing::error!(error = %err, "rotation tick failed");
        }
    }

    /// Wait for either the next tick or the cancellation token,
    /// whichever fires first. Returns `true` if the scheduler
    /// should stop, `false` if it should continue with another
    /// tick.
    async fn wait_for_tick_or_cancel(
        &self,
        cancel: &CancellationToken,
        ticker: &mut tokio::time::Interval,
    ) -> bool {
        tokio::select! {
            () = cancel.cancelled() => {
                tracing::info!("rotation scheduler shutting down");
                true
            },
            _ = ticker.tick() => false,
        }
    }

    /// Run a single rotation pass — the unit of work the test
    /// suite exercises directly and the production loop calls per
    /// tick. Exposed so a deterministic integration test (and the
    /// F-COORD-crate gate's end-to-end test) can advance the loop
    /// without coupling to wall-clock virtual time.
    ///
    /// # Errors
    ///
    /// Returns [`RotationError::Registry`] if the peer-registry
    /// eviction transaction fails and
    /// [`RotationError::CohortStore`] if the cohort-store
    /// eviction transaction fails. The gate's `drain_ready` step
    /// is infallible.
    pub fn tick_once(&self) -> Result<RotationStats, RotationError> {
        let now_offset = time::OffsetDateTime::now_utc();
        let now = Timestamp::from_offset_date_time(now_offset);
        let stale_cutoff = Timestamp::from_offset_date_time(now_offset - self.heartbeat_slo);
        let peers_evicted = self.registry.evict_stale(stale_cutoff)?;
        let cohorts_evicted = self.cohorts.evict_expired(now)?;
        let (waiters_released, waiters_cancelled) = self.reconcile_gate_with_cohort_store()?;
        let stats = RotationStats {
            peers_evicted,
            cohorts_evicted,
            waiters_released,
            waiters_cancelled,
            floor: self.gate.floor(),
        };
        tracing::info!(
            peers_evicted = stats.peers_evicted,
            cohorts_evicted = stats.cohorts_evicted,
            waiters_released = stats.waiters_released,
            waiters_cancelled = stats.waiters_cancelled,
            floor = stats.floor,
            "rotation tick completed",
        );
        Ok(stats)
    }

    /// Reconcile the gate's wait list with the (post-eviction)
    /// cohort store: drain waiters whose cohort still exists and
    /// meets the floor, and cancel waiters whose cohort no longer
    /// exists in the store.
    ///
    /// Returns `(released, cancelled)`. A cancelled waiter has its
    /// oneshot sender dropped, which surfaces to the awaiting axum
    /// handler as `RecvError`; the handler maps that to a 503 so
    /// the peer learns to retry rather than hang forever.
    fn reconcile_gate_with_cohort_store(&self) -> Result<(usize, usize), RotationError> {
        let pending_cohort_ids = self.gate.pending_cohort_ids();
        let mut live_cohort_ids: Vec<bibeam_core::CohortId> =
            Vec::with_capacity(pending_cohort_ids.len());
        let mut released_total: usize = 0;
        for cohort_id in pending_cohort_ids {
            let Some(record) = self.cohorts.get(&cohort_id)? else {
                continue;
            };
            live_cohort_ids.push(cohort_id);
            released_total =
                released_total.saturating_add(self.gate.drain_ready(cohort_id, &record));
        }
        let cancelled = self.gate.cancel_orphans(&live_cohort_ids);
        Ok((released_total, cancelled))
    }
}

/// Per-tick statistics surfaced to operators (via tracing) and to
/// the rotation tests that assert on the eviction counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationStats {
    /// Number of stale peers evicted from
    /// [`PeerRegistry::evict_stale`].
    pub peers_evicted: usize,
    /// Number of expired cohorts evicted from
    /// [`CohortStore::evict_expired`].
    pub cohorts_evicted: usize,
    /// Number of bucketed waiters released by
    /// [`AdmissionGate::drain_ready`] during this tick.
    pub waiters_released: usize,
    /// Number of orphaned waiters cancelled (their cohort had
    /// been evicted from the store). Cancelled waiters observe a
    /// `RecvError` on their oneshot receiver; the axum handler
    /// surfaces that as a 503 so the peer learns to retry.
    pub waiters_cancelled: usize,
    /// Gate floor at the time of the tick — surfaced so the
    /// audit log can confirm the running invariant.
    pub floor: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::{CohortId, NodeId, PeerId};
    use bibeam_discovery::PeerRecord;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use time::Duration as TimeDuration;

    use crate::admission_gate::AdmissionOutcome;
    use crate::cohorts::CohortRecord;

    fn fixture_registry() -> (Arc<PeerRegistry>, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().expect("registry tempfile");
        let registry = PeerRegistry::open(temp.path()).expect("open registry");
        (Arc::new(registry), temp)
    }

    fn fixture_cohort_store() -> (Arc<CohortStore>, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().expect("cohort tempfile");
        let store = CohortStore::open(temp.path()).expect("open cohort store");
        (Arc::new(store), temp)
    }

    fn fixture_peer(last_seen: Timestamp) -> PeerRecord {
        PeerRecord {
            peer_id: PeerId::new(),
            addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 41_443),
            can_exit: false,
            capacity_hint: 0,
            last_seen,
        }
    }

    fn fixture_cohort(deadline: Timestamp) -> CohortRecord {
        CohortRecord {
            members: vec![PeerId::new()],
            exits: vec![NodeId::new()],
            rotation_deadline: deadline,
        }
    }

    #[test]
    fn tick_evicts_stale_peers_and_expired_cohorts() {
        // Contract: a single tick removes every peer past the
        // heartbeat SLO and every cohort past its deadline.
        let (registry, _registry_temp) = fixture_registry();
        let (cohorts, _cohorts_temp) = fixture_cohort_store();
        let gate = Arc::new(AdmissionGate::new(30));
        let scheduler = RotationScheduler::with_cadence(
            registry.clone(),
            cohorts.clone(),
            gate,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );

        let now_offset = time::OffsetDateTime::now_utc();
        let stale_at = Timestamp::from_offset_date_time(now_offset - TimeDuration::minutes(10));
        let fresh_at = Timestamp::from_offset_date_time(now_offset);
        let expired_deadline =
            Timestamp::from_offset_date_time(now_offset - TimeDuration::minutes(5));
        let live_deadline = Timestamp::from_offset_date_time(now_offset + TimeDuration::minutes(5));

        registry.upsert(&fixture_peer(stale_at)).expect("upsert stale");
        registry.upsert(&fixture_peer(fresh_at)).expect("upsert fresh");
        cohorts
            .upsert(&CohortId::new(), &fixture_cohort(expired_deadline))
            .expect("upsert expired cohort");
        cohorts
            .upsert(&CohortId::new(), &fixture_cohort(live_deadline))
            .expect("upsert live cohort");

        let stats = scheduler.tick_once().expect("tick");
        assert_eq!(stats.peers_evicted, 1);
        assert_eq!(stats.cohorts_evicted, 1);
        assert_eq!(stats.waiters_released, 0);
        assert_eq!(stats.waiters_cancelled, 0);
        assert_eq!(stats.floor, 30);
    }

    #[test]
    fn tick_cancels_waiters_whose_cohort_was_evicted() {
        // Contract: a peer bucketed under a cohort whose record is
        // evicted in the same tick observes its oneshot receiver
        // close — not a hang. Catches a regression where orphan
        // waiters leaked across rotation epochs.
        let (registry, _registry_temp) = fixture_registry();
        let (cohorts, _cohorts_temp) = fixture_cohort_store();
        let gate = Arc::new(AdmissionGate::new(30));
        let scheduler = RotationScheduler::with_cadence(
            registry,
            cohorts.clone(),
            gate.clone(),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );

        // Cohort exists in store; bucket a waiter under it.
        let cohort_id = CohortId::new();
        let now_offset = time::OffsetDateTime::now_utc();
        let expired_deadline =
            Timestamp::from_offset_date_time(now_offset - TimeDuration::minutes(5));
        cohorts
            .upsert(&cohort_id, &fixture_cohort(expired_deadline))
            .expect("upsert expired cohort");

        let peer = PeerId::new();
        let mut mutable_record = fixture_cohort(expired_deadline);
        let outcome = gate.admit_or_bucket(peer, cohort_id, &mut mutable_record);
        let mut receiver = match outcome {
            AdmissionOutcome::Bucketed(receiver) => receiver,
            AdmissionOutcome::Admitted(_) => panic!("must bucket below floor of 30"),
        };

        let stats = scheduler.tick_once().expect("tick");
        assert_eq!(stats.cohorts_evicted, 1);
        assert_eq!(stats.waiters_released, 0);
        assert_eq!(stats.waiters_cancelled, 1);
        assert_eq!(gate.pending_count(), 0);
        // Receiver sees the sender drop as RecvError.
        let recv = receiver.try_recv();
        assert!(matches!(recv, Err(tokio::sync::oneshot::error::TryRecvError::Closed)));
    }

    #[tokio::test(start_paused = true)]
    async fn run_exits_on_cancellation() {
        // Contract: the scheduler honours the cancellation token
        // without waiting out a tick. Catches a regression that
        // dropped the `select!` arm and made the daemon stall on
        // shutdown for the entire rotation interval.
        let (registry, _registry_temp) = fixture_registry();
        let (cohorts, _cohorts_temp) = fixture_cohort_store();
        let gate = Arc::new(AdmissionGate::new(2));
        let scheduler = RotationScheduler::with_cadence(
            registry,
            cohorts,
            gate,
            Duration::from_secs(60),
            Duration::from_secs(120),
        );
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let run_handle = tokio::spawn(async move {
            scheduler.run(cancel_clone).await;
        });

        // Yield once so the run() future reaches its first await.
        tokio::task::yield_now().await;
        cancel.cancel();
        // Bounded wait — the run loop must collapse promptly.
        let timeout = tokio::time::timeout(Duration::from_secs(5), run_handle).await;
        assert!(timeout.is_ok(), "run did not exit on cancellation");
    }
}
