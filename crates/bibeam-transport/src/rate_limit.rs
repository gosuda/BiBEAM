#![forbid(unsafe_code)]
//! Per-session rate limiter for `WireGuard` data-plane traffic.
//!
//! F-TRANS.8 caps the per-second byte budget each session is allowed
//! to push through the tunnel. The budget is set by the coordinator
//! and enforced locally on every send, so a hostile or buggy peer
//! cannot saturate a shared upstream link.
//!
//! ## Session key choice
//!
//! `bibeam-core` does not (yet) define a `SessionId` newtype. Per the
//! D-4 architecture line, a session is keyed by the peer the local
//! node is talking to — one tunnel per cohort partner. We therefore
//! reuse [`bibeam_core::PeerId`] as the session key for the rate
//! limiter. The rustdoc here records that choice so a later
//! introduction of `SessionId(Ulid)` lands as a single-type swap
//! rather than a semantic change.
//!
//! Deviation from the spec template: the spec illustrated
//! `governor::state::keyed::DefaultKeyedStateStore<SessionId>`. We
//! resolve `SessionId` to `PeerId` for this MVP.
//!
//! ## API shape
//!
//! [`SessionRateLimiter::new`] builds a fresh limiter.
//! [`SessionRateLimiter::check_bytes`] asks the limiter "may this
//! session burn `byte_count` cells right now?" — returns `Ok(())` if
//! the budget allows, or `Err(RateLimitDenied { peer })` if the next
//! cell would overflow the bucket.
//!
//! The limiter is `Send + Sync` so it can be wrapped in `Arc` and
//! shared across the many `WgTunnel` tasks that push bytes per
//! session.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use thiserror::Error;

use bibeam_core::PeerId;

/// One session's rate-limit denial.
///
/// `governor` itself returns its own `NotUntil` info on denial; we
/// strip it down to "which session was throttled" for the call-side.
/// Callers that need the throttle-until time can wrap us; the MVP
/// just drops the over-budget bytes.
#[derive(Debug, Error)]
#[error("rate-limit: session {peer} over budget")]
pub struct RateLimitDenied {
    /// Peer ID of the session whose budget was exceeded.
    pub peer: PeerId,
}

/// Internal type alias for the `governor` keyed-rate-limiter shape we
/// hold.
///
/// The full generic shape is `RateLimiter<PeerId, S, C>` for state
/// store `S` and clock `C`. We pin both to `governor`'s defaults; the
/// alias lets the public API expose `SessionRateLimiter` without
/// leaking three type parameters into every call-site.
type Inner = RateLimiter<
    PeerId,
    DefaultKeyedStateStore<PeerId>,
    DefaultClock,
    governor::middleware::NoOpMiddleware,
>;

/// Per-session bytes-per-second rate limiter.
///
/// Keyed by [`PeerId`] (see module docs for the MVP rationale).
/// Wraps a `governor::RateLimiter` under an [`Arc`] so handles can
/// fan out across tasks without re-deriving the same shared state.
#[derive(Clone)]
pub struct SessionRateLimiter {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for SessionRateLimiter {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("SessionRateLimiter").finish_non_exhaustive()
    }
}

impl SessionRateLimiter {
    /// Build a new limiter with `per_second_bytes` as the steady-state
    /// budget per session.
    ///
    /// `governor` requires the rate to be a [`NonZeroU32`]; a zero
    /// budget would mean "deny everything," which is what a closed
    /// session looks like and is not what this layer is for.
    /// Passing zero yields [`RateLimitConfigError::ZeroBudget`].
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitConfigError::ZeroBudget`] if
    /// `per_second_bytes == 0`.
    pub fn new(per_second_bytes: u32) -> Result<Self, RateLimitConfigError> {
        let quota_size =
            NonZeroU32::new(per_second_bytes).ok_or(RateLimitConfigError::ZeroBudget)?;
        let quota = Quota::per_second(quota_size);
        let inner = RateLimiter::keyed(quota);
        Ok(Self { inner: Arc::new(inner) })
    }

    /// Ask the limiter to charge `byte_count` cells against `peer`'s
    /// bucket. Returns `Ok(())` if the bucket can absorb the cells
    /// right now, or [`RateLimitDenied`] if not.
    ///
    /// `byte_count` is the wire size of the WG datagram the caller
    /// is about to send (or has just received) — one cell per byte
    /// is the simplest accounting and matches the
    /// `per_second_bytes` quota directly. A `byte_count` of zero
    /// always passes (no work to charge).
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitDenied`] when the session is over budget
    /// for the requested cell count.
    pub fn check_bytes(&self, peer: PeerId, byte_count: u32) -> Result<(), RateLimitDenied> {
        let Some(non_zero) = NonZeroU32::new(byte_count) else {
            return Ok(());
        };
        match self.inner.check_key_n(&peer, non_zero) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(RateLimitDenied { peer }),
        }
    }
}

/// Configuration-time errors emitted by [`SessionRateLimiter::new`].
#[derive(Debug, Error)]
pub enum RateLimitConfigError {
    /// Coordinator handed us a zero budget. A zero budget is a
    /// terminated session, not a rate-limited one — callers must
    /// gate on session liveness elsewhere.
    #[error("rate-limit: per-second byte budget cannot be zero")]
    ZeroBudget,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_budget_is_rejected_at_construction() {
        let outcome = SessionRateLimiter::new(0);
        assert!(matches!(outcome, Err(RateLimitConfigError::ZeroBudget)));
    }

    #[test]
    fn budget_within_limit_passes() {
        let limiter = SessionRateLimiter::new(1_000_000).expect("build");
        let peer = PeerId::new();
        for _attempt in 0..10 {
            limiter.check_bytes(peer, 1_000).expect("under-budget call passes");
        }
    }

    #[test]
    fn over_budget_is_denied() {
        // 100 bytes/s budget; a single 1_000-byte request should be
        // denied because the per-second quota is below the requested
        // cell count.
        let limiter = SessionRateLimiter::new(100).expect("build");
        let peer = PeerId::new();
        let outcome = limiter.check_bytes(peer, 1_000);
        assert!(
            matches!(outcome, Err(RateLimitDenied { peer: denied_peer }) if denied_peer == peer)
        );
    }

    #[test]
    fn zero_byte_count_passes_trivially() {
        let limiter = SessionRateLimiter::new(100).expect("build");
        let peer = PeerId::new();
        limiter.check_bytes(peer, 0).expect("zero-byte call is a no-op");
    }

    #[test]
    fn distinct_peers_have_independent_buckets() {
        let limiter = SessionRateLimiter::new(100_000).expect("build");
        let peer_one = PeerId::new();
        let peer_two = PeerId::new();
        // Spend most of peer_one's budget …
        limiter.check_bytes(peer_one, 100_000).expect("peer_one fills bucket");
        // … and peer_two should still be able to push the same.
        limiter.check_bytes(peer_two, 100_000).expect("peer_two has its own bucket");
    }
}
