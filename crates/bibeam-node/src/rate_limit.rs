#![forbid(unsafe_code)]
//! Node-side data-plane rate limiting (F-NODE.8).
//!
//! Caps the per-[`CohortId`] and per-[`PeerId`] packet rate the node
//! accepts on its data plane. **Distinct** from the coord
//! control-plane rate limit (F-COORD.9, [`crate::coordinator::rate_limit`]),
//! which keys on source IP + [`PeerId`] and applies to the four
//! control-plane HTTP verbs; this module enforces UDP-side
//! throughput caps and is consumed by the forwarder and exit
//! ingress paths.
//!
//! ## Shape
//!
//! Two independent [`DashMap`]s, one keyed by [`CohortId`] and one
//! keyed by [`PeerId`]. Each map's value is a
//! [`governor::DefaultDirectRateLimiter`] (un-keyed,
//! [`governor::clock::DefaultClock`]) constructed from a per-second
//! [`Quota`] derived at startup from the operator-supplied
//! [`RateLimitConfig`]. The two maps are deliberately decoupled:
//! exhausting a cohort's bucket does not consume any peer's budget
//! and vice versa, because the two caps protect different
//! invariants (per-cohort = neighbour-fair admission control,
//! per-peer = single-misbehaving-peer containment).
//!
//! ## Why a `DashMap<_, DefaultDirectRateLimiter>` over `RateLimiter::keyed`
//!
//! `governor::state::keyed::DefaultKeyedStateStore` is the natural
//! one-line answer and would suffice for correctness. We deviate
//! because the keyed store evicts entries on a heuristic that does
//! not let us inspect or bound the map's residency from the
//! outside, while [`DashMap`] gives us a single concurrent map
//! whose entry-count is observable for the telemetry surface
//! F-NODE.9 will mount on top of it. Both options use the same
//! GCRA logic per cell; the contention shape is `DashMap`'s shard
//! lock vs. the keyed store's per-bucket atomic.
//!
//! ## Concurrency
//!
//! [`NodeRateLimiter`] is `Send + Sync`. Wrap it in [`Arc`] and
//! clone the [`Arc`] into the forwarder + exit hot paths. Every
//! [`DefaultDirectRateLimiter`] is itself `Send + Sync` and the
//! [`DashMap`] handles the inter-thread synchronisation; this
//! module never takes a `&mut self`.
//!
//! ## Map residency
//!
//! Both [`DashMap`]s grow lazily on first reference to an unseen
//! key and never auto-evict. Residency is bounded by the
//! coord-issued cohort and peer population that has actually
//! exchanged data-plane traffic with this node — i.e. by
//! admission, not by arbitrary input — which mirrors the
//! `governor::DefaultKeyedStateStore` shape used in
//! [`crate::coordinator::rate_limit`]. An explicit residency
//! cap + eviction policy will land alongside the F-NODE.9
//! telemetry surface that needs a `.len()` gauge anyway; until
//! then operators rely on the per-cohort/per-peer GCRA itself to
//! contain a misbehaving peer.
//!
//! ## Out of scope
//!
//! - Token-bucket warm-up tuning beyond the [`Quota::per_second`]
//!   default burst = rate.
//! - Metrics export for denials / map residency — that is
//!   F-NODE.9's telemetry concern.
//! - Explicit residency cap / eviction (see above).

use core::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;

use bibeam_core::{CohortId, PeerId};
use bibeam_runtime::RateLimitConfig;
use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use thiserror::Error;

/// Internal alias for an un-keyed in-memory limiter on the default
/// clock. `governor` re-exports the same shape as
/// [`DefaultDirectRateLimiter`]; we name it locally so the
/// `DashMap` value type stays short at use sites.
type DirectLimiter = DefaultDirectRateLimiter;

/// Configuration error returned when a per-second cap is zero
/// (which would mean "block everyone" and is never a valid input).
///
/// Construction is fallible by design: an operator who edits the
/// TOML config and types `per_cohort_pps = 0` should get a typed
/// startup failure rather than a silently-broken data plane.
#[derive(Debug, Error)]
pub enum RateLimitConfigError {
    /// Caller supplied a zero cap for the named field.
    #[error("rate-limit configuration error: `{field}` must be non-zero")]
    ZeroBudget {
        /// Name of the cap field that was zero.
        field: &'static str,
    },
}

/// A single denial returned by [`NodeRateLimiter::check_cohort`] /
/// [`NodeRateLimiter::check_peer`].
///
/// Carries the scope string (`"cohort:<id>"` / `"peer:<id>"`) so
/// the caller can log which key was throttled without re-deriving
/// it. Mirrors the coord [`crate::coordinator::rate_limit::RateLimitDenied`]
/// shape on purpose: operators reading mixed control-plane +
/// data-plane denial logs should not have to context-switch
/// between two error vocabularies.
#[derive(Debug, Error)]
#[error("node rate-limit: {scope}")]
pub struct RateLimited {
    /// What was throttled: `"cohort:<id>"` or `"peer:<id>"`.
    pub scope: String,
}

/// Node-side data-plane rate limiter.
///
/// Holds the per-[`CohortId`] and per-[`PeerId`] maps of
/// [`DefaultDirectRateLimiter`] instances plus the [`Quota`]
/// values used to lazily construct a new limiter on first
/// reference to an unseen key.
///
/// The map values are `Arc<DefaultDirectRateLimiter>` rather
/// than the limiter directly so the `check_*` hot paths can
/// clone the [`Arc`] out, drop the [`DashMap`] shard guard,
/// and only then invoke GCRA's `check()` — keeping unrelated
/// keys that hash into the same shard from serialising on a
/// shard-level lock. This mirrors the
/// [`crate::coordinator::rate_limit`] limiter, which wraps its
/// keyed `RateLimiter` in `Arc<…>` for the same reason.
/// Wrap the whole [`NodeRateLimiter`] in `Arc<…>` to share it
/// between the forwarder + exit hot paths.
pub struct NodeRateLimiter {
    per_cohort: DashMap<CohortId, Arc<DirectLimiter>>,
    per_peer: DashMap<PeerId, Arc<DirectLimiter>>,
    cohort_quota: Quota,
    peer_quota: Quota,
}

impl fmt::Debug for NodeRateLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeRateLimiter")
            .field("per_cohort_keys", &self.per_cohort.len())
            .field("per_peer_keys", &self.per_peer.len())
            .finish_non_exhaustive()
    }
}

impl NodeRateLimiter {
    /// Build a node rate limiter from the supplied [`RateLimitConfig`].
    ///
    /// The maps start empty; per-key limiters are constructed lazily
    /// on first reference so an idle node does not allocate one
    /// limiter per known cohort up front.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitConfigError::ZeroBudget`] if either
    /// `config.per_cohort_pps` or `config.per_peer_pps` is zero.
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitConfigError> {
        let cohort_quota = quota_per_second(config.per_cohort_pps, "per_cohort_pps")?;
        let peer_quota = quota_per_second(config.per_peer_pps, "per_peer_pps")?;
        Ok(Self {
            per_cohort: DashMap::new(),
            per_peer: DashMap::new(),
            cohort_quota,
            peer_quota,
        })
    }

    /// Build a node rate limiter from the F-NODE.8 MVP defaults
    /// (`per_cohort_pps = 10_000`, `per_peer_pps = 1_000`).
    ///
    /// # Errors
    ///
    /// The defaults are non-zero compile-time constants, so this
    /// only ever returns `Ok`; the fallible signature is forwarded
    /// from [`Self::new`] so the call site stays uniform with the
    /// operator-override path.
    pub fn with_default_config() -> Result<Self, RateLimitConfigError> {
        Self::new(RateLimitConfig::default())
    }

    /// Check whether `cohort` may send another packet right now.
    ///
    /// The per-cohort limiter is created on first reference. The
    /// returned `Ok(())` means "one cell consumed from the cohort's
    /// bucket"; `Err(RateLimited { .. })` means the bucket is
    /// empty and the caller should drop the packet.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimited`] when the cohort's GCRA bucket is
    /// empty.
    pub fn check_cohort(&self, cohort: CohortId) -> Result<(), RateLimited> {
        let limiter = self.cohort_limiter(cohort);
        limiter.check().map_err(|_throttled_until| RateLimited {
            scope: format!("cohort:{cohort}"),
        })
    }

    /// Check whether `peer` may send another packet right now.
    ///
    /// The per-peer limiter is created on first reference. The
    /// returned `Ok(())` means "one cell consumed from the peer's
    /// bucket"; `Err(RateLimited { .. })` means the bucket is
    /// empty and the caller should drop the packet.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimited`] when the peer's GCRA bucket is
    /// empty.
    pub fn check_peer(&self, peer: PeerId) -> Result<(), RateLimited> {
        let limiter = self.peer_limiter(peer);
        limiter
            .check()
            .map_err(|_throttled_until| RateLimited { scope: format!("peer:{peer}") })
    }

    /// Look up (or insert) the per-cohort limiter without holding a
    /// `DashMap` shard lock across the GCRA `check()` call.
    fn cohort_limiter(&self, cohort: CohortId) -> Arc<DirectLimiter> {
        if let Some(existing) = self.per_cohort.get(&cohort) {
            return Arc::clone(existing.value());
        }
        let entry = self
            .per_cohort
            .entry(cohort)
            .or_insert_with(|| Arc::new(direct_limiter(self.cohort_quota)));
        Arc::clone(entry.value())
    }

    /// Look up (or insert) the per-peer limiter without holding a
    /// `DashMap` shard lock across the GCRA `check()` call.
    fn peer_limiter(&self, peer: PeerId) -> Arc<DirectLimiter> {
        if let Some(existing) = self.per_peer.get(&peer) {
            return Arc::clone(existing.value());
        }
        let entry = self
            .per_peer
            .entry(peer)
            .or_insert_with(|| Arc::new(direct_limiter(self.peer_quota)));
        Arc::clone(entry.value())
    }
}

/// Build a `Quota::per_second` from a non-zero `u32`, surfacing
/// [`RateLimitConfigError::ZeroBudget`] on zero input.
fn quota_per_second(pps: u32, field: &'static str) -> Result<Quota, RateLimitConfigError> {
    let max_burst = NonZeroU32::new(pps).ok_or(RateLimitConfigError::ZeroBudget { field })?;
    Ok(Quota::per_second(max_burst))
}

/// Construct a fresh un-keyed in-memory limiter on the default
/// clock for `quota`. Centralised so the `Arc` + `RateLimiter`
/// shape stays in one place; both maps go through this helper.
fn direct_limiter(quota: Quota) -> DirectLimiter {
    // `RateLimiter::direct` returns a concrete `RateLimiter<NotKeyed,
    // InMemoryState, DefaultClock, NoOpMiddleware>`; the
    // `RateLimiter::<NotKeyed, _, _, _>::direct` path is the only
    // public constructor for the default-clock un-keyed shape.
    RateLimiter::<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>::direct(quota)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-cohort and per-peer caps small enough that a single
    /// burst exhausts the GCRA bucket without any test-side
    /// timing trickery. governor 0.10's `DefaultClock` is the
    /// system monotonic clock; we deliberately do NOT try to
    /// pause/advance it from tests.
    const TINY_CONFIG: RateLimitConfig = RateLimitConfig {
        per_cohort_pps: 2,
        per_peer_pps: 3,
    };

    #[test]
    fn check_cohort_allows_under_quota() {
        // Contract: a freshly-constructed limiter must let the
        // first `per_cohort_pps` requests through in a single
        // burst. Sanity check against a regression that
        // initialised the bucket empty.
        let limiter = NodeRateLimiter::new(TINY_CONFIG).expect("build");
        let cohort = CohortId::new();
        for attempt in 0..TINY_CONFIG.per_cohort_pps {
            limiter
                .check_cohort(cohort)
                .unwrap_or_else(|err| panic!("attempt {attempt} should pass: {err}"));
        }
    }

    #[test]
    fn check_cohort_blocks_over_quota() {
        // Contract: the (N+1)th request inside a burst must deny
        // with a `RateLimited` whose scope identifies the cohort
        // key. Catches a regression that dropped the GCRA check
        // (which would let any cohort exceed its budget unchecked).
        let limiter = NodeRateLimiter::new(TINY_CONFIG).expect("build");
        let cohort = CohortId::new();
        for _attempt in 0..TINY_CONFIG.per_cohort_pps {
            limiter.check_cohort(cohort).expect("under-quota passes");
        }
        let denied =
            limiter.check_cohort(cohort).expect_err("burst-and-deny: must deny over quota");
        assert_eq!(denied.scope, format!("cohort:{cohort}"));
    }

    #[test]
    fn check_peer_allows_under_quota() {
        // Contract: same shape as `check_cohort_allows_under_quota`
        // but on the per-peer map.
        let limiter = NodeRateLimiter::new(TINY_CONFIG).expect("build");
        let peer = PeerId::new();
        for attempt in 0..TINY_CONFIG.per_peer_pps {
            limiter
                .check_peer(peer)
                .unwrap_or_else(|err| panic!("attempt {attempt} should pass: {err}"));
        }
    }

    #[test]
    fn check_peer_blocks_over_quota() {
        // Contract: same shape as `check_cohort_blocks_over_quota`
        // but on the per-peer map. Verifies the scope-string
        // distinguishes peer denials from cohort denials so a
        // mixed-source log can be triaged.
        let limiter = NodeRateLimiter::new(TINY_CONFIG).expect("build");
        let peer = PeerId::new();
        for _attempt in 0..TINY_CONFIG.per_peer_pps {
            limiter.check_peer(peer).expect("under-quota passes");
        }
        let denied = limiter.check_peer(peer).expect_err("burst-and-deny: must deny over quota");
        assert_eq!(denied.scope, format!("peer:{peer}"));
    }

    #[test]
    fn per_cohort_independent_of_per_peer() {
        // Contract: the per-cohort and per-peer maps are
        // independent. Exhausting cohort A's bucket must not
        // consume any peer's budget; a different peer remains
        // fully available; the original peer is still rate-limited
        // by the cohort bucket (since `check_cohort` is the
        // limiter the caller would invoke first on that flow).
        //
        // Catches a regression that accidentally collapsed the two
        // maps into one shared GCRA — which would let a single
        // chatty cohort throttle every peer's per-peer budget at
        // the same time, or vice versa.
        let limiter = NodeRateLimiter::new(TINY_CONFIG).expect("build");
        let cohort_a = CohortId::new();
        let peer_a = PeerId::new();
        let peer_b = PeerId::new();

        // Exhaust cohort A's bucket. Per-peer maps must remain
        // untouched.
        for _attempt in 0..TINY_CONFIG.per_cohort_pps {
            limiter.check_cohort(cohort_a).expect("cohort under quota");
        }
        limiter.check_cohort(cohort_a).expect_err("cohort A is exhausted");

        // A different peer is fully available — exhausting cohort
        // A did not touch the per-peer map.
        for _attempt in 0..TINY_CONFIG.per_peer_pps {
            limiter.check_peer(peer_b).expect("peer B fully available");
        }

        // The original peer ID also has its own intact per-peer
        // bucket (independence runs both ways): cohort exhaustion
        // did not consume the peer-A budget.
        for _attempt in 0..TINY_CONFIG.per_peer_pps {
            limiter
                .check_peer(peer_a)
                .expect("peer A's per-peer bucket is untouched by cohort A's exhaustion");
        }

        // But `check_cohort` on the SAME exhausted cohort still
        // denies — the cohort bucket has not magically refilled
        // through any peer activity. This is the load-bearing
        // assertion: per-cohort enforcement is on the cohort key,
        // not the peer key.
        let denied = limiter.check_cohort(cohort_a).expect_err("cohort A is still rate-limited");
        assert_eq!(denied.scope, format!("cohort:{cohort_a}"));
    }

    #[test]
    fn zero_per_cohort_budget_is_rejected() {
        // Contract: a zero cap is a configuration error, never a
        // closed-route policy. Catches a regression that silently
        // mapped zero to "deny everything" (which would break the
        // data plane on the first packet).
        let err = NodeRateLimiter::new(RateLimitConfig {
            per_cohort_pps: 0,
            per_peer_pps: 1_000,
        })
        .expect_err("zero per-cohort cap must be rejected");
        assert!(
            matches!(err, RateLimitConfigError::ZeroBudget { field } if field == "per_cohort_pps"),
        );
    }

    #[test]
    fn zero_per_peer_budget_is_rejected() {
        // Contract: same shape as `zero_per_cohort_budget_is_rejected`
        // for the per-peer cap. Both fields are independently
        // validated; a non-zero cohort cap must not paper over a
        // zero peer cap.
        let err = NodeRateLimiter::new(RateLimitConfig {
            per_cohort_pps: 10_000,
            per_peer_pps: 0,
        })
        .expect_err("zero per-peer cap must be rejected");
        assert!(
            matches!(err, RateLimitConfigError::ZeroBudget { field } if field == "per_peer_pps"),
        );
    }

    #[test]
    fn default_config_builds_successfully() {
        // Contract: `with_default_config` must succeed on the MVP
        // defaults. Catches a regression that broke the constant
        // path (e.g. by inadvertently setting one of the defaults
        // to zero — which would fail every node startup).
        let limiter = NodeRateLimiter::with_default_config().expect("MVP defaults build");
        let cohort = CohortId::new();
        limiter.check_cohort(cohort).expect("first request passes");
        let peer = PeerId::new();
        limiter.check_peer(peer).expect("first request passes");
    }
}
