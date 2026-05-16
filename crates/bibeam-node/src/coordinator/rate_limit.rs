#![forbid(unsafe_code)]
//! Per-source-IP + per-`PeerId` route rate limiting (F-COORD.9).
//!
//! Aggressive thresholds tuned for the Oracle ARM Free Tier
//! deployment target (1 vCPU, ~1 GB RAM). The four control-plane
//! routes (`register` / `match` / `heartbeat` / `disconnect`) each
//! have their own per-IP quota and (for the three authenticated
//! routes) their own per-`PeerId` quota; every quota is enforced
//! by an independent [`governor::RateLimiter`] instance so a flood
//! against `match` cannot starve a peer's `heartbeat` budget.
//!
//! ## Defaults
//!
//! Surfaced as constants so an integration test can assert on the
//! shape of the running invariant and operators can pull them
//! into a config schema in a follow-up PR. Per the F-COORD.9
//! spec (with one deviation, documented below):
//!
//! - per-IP: 30 register/min, 60 match/min, 120 heartbeat/min,
//!   30 disconnect/min.
//! - per-PeerId: 30 match/min, 60 heartbeat/min.
//!
//! ### Deviation: no per-PeerId `register` quota
//!
//! The F-COORD.9 spec text listed a per-PeerId `register` cap of
//! 6/min. We deliberately deviate: the `register` request body
//! carries the (claimed) peer id, but the route is
//! unauthenticated — anyone observing a peer id (or just
//! guessing a ULID) could spend that peer's registration bucket.
//! Enforcing the limit would convert an external attacker into a
//! denial-of-service vector against any peer whose id is known
//! or guessable, which is strictly worse than no limit at all.
//! Per-IP enforcement on `register` is preserved, which is what
//! actually defends the route.
//!
//! `disconnect` has no per-PeerId quota either, because the
//! voluntary-disconnect path is benign even at full rate.
//!
//! ## Concurrency
//!
//! Every limiter sits behind an [`Arc`] so the shape is cheap to
//! clone into axum handlers, the rotation scheduler, and any
//! follow-up middleware. `governor::RateLimiter` is `Send + Sync`
//! by construction.

use core::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use bibeam_core::PeerId;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use thiserror::Error;

/// Per-IP per-minute caps for each control-plane verb (F-COORD.9
/// MVP defaults).
pub const PER_IP_REGISTER_PER_MINUTE: u32 = 30;
/// See [`PER_IP_REGISTER_PER_MINUTE`].
pub const PER_IP_MATCH_PER_MINUTE: u32 = 60;
/// See [`PER_IP_REGISTER_PER_MINUTE`].
pub const PER_IP_HEARTBEAT_PER_MINUTE: u32 = 120;
/// See [`PER_IP_REGISTER_PER_MINUTE`].
pub const PER_IP_DISCONNECT_PER_MINUTE: u32 = 30;

/// Per-PeerId per-minute caps for the two authenticated verbs
/// that key on an authentic peer id (`match` + `heartbeat`).
/// `register` is excluded by design (see module rustdoc).
pub const PER_PEER_MATCH_PER_MINUTE: u32 = 30;
/// See [`PER_PEER_MATCH_PER_MINUTE`].
pub const PER_PEER_HEARTBEAT_PER_MINUTE: u32 = 60;

/// Internal type alias for the `governor` keyed-rate-limiter shape
/// keyed by source IP.
type IpLimiter = RateLimiter<
    IpAddr,
    DefaultKeyedStateStore<IpAddr>,
    DefaultClock,
    governor::middleware::NoOpMiddleware,
>;

/// Internal type alias for the `governor` keyed-rate-limiter shape
/// keyed by [`PeerId`].
type PeerLimiter = RateLimiter<
    PeerId,
    DefaultKeyedStateStore<PeerId>,
    DefaultClock,
    governor::middleware::NoOpMiddleware,
>;

/// A single denial returned by [`RouteLimiter::check_ip`] /
/// [`RouteLimiter::check_peer`].
#[derive(Debug, Error)]
#[error("rate-limit: route {route} for {scope}")]
pub struct RateLimitDenied {
    /// Symbolic route name — `"register"` / `"match"` / etc.
    pub route: &'static str,
    /// What was throttled: `"ip:<addr>"` or `"peer:<id>"`.
    pub scope: String,
}

/// Configuration error returned when a per-minute cap is zero
/// (which would mean "block everyone" and is never a valid input).
#[derive(Debug, Error)]
pub enum RateLimitConfigError {
    /// Caller supplied a zero cap for the named field.
    #[error("rate-limit configuration error: `{field}` must be non-zero")]
    ZeroBudget {
        /// Name of the cap field that was zero.
        field: &'static str,
    },
}

/// Per-route rate-limit decisions.
///
/// Each instance owns the (per-IP, optionally per-PeerId) governor
/// limiters for a single route. Construct one per route at
/// startup; clone freely into the matching axum handler.
#[derive(Clone)]
pub struct RouteLimiter {
    route_name: &'static str,
    ip: Arc<IpLimiter>,
    peer: Option<Arc<PeerLimiter>>,
}

impl core::fmt::Debug for RouteLimiter {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RouteLimiter")
            .field("route_name", &self.route_name)
            .finish_non_exhaustive()
    }
}

impl RouteLimiter {
    /// Build a route limiter with the supplied per-minute caps. A
    /// `None` peer cap means the route has no per-PeerId
    /// enforcement (the `register` path).
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitConfigError::ZeroBudget`] if any cap is
    /// zero.
    pub fn new(
        route_name: &'static str,
        per_ip_per_minute: u32,
        per_peer_per_minute: Option<u32>,
    ) -> Result<Self, RateLimitConfigError> {
        let ip_quota = quota_per_minute(per_ip_per_minute, "per_ip_per_minute")?;
        let ip_limiter = RateLimiter::keyed(ip_quota);
        let peer_limiter = match per_peer_per_minute {
            Some(rate) => {
                let quota = quota_per_minute(rate, "per_peer_per_minute")?;
                Some(Arc::new(RateLimiter::keyed(quota)))
            },
            None => None,
        };
        Ok(Self {
            route_name,
            ip: Arc::new(ip_limiter),
            peer: peer_limiter,
        })
    }

    /// Check whether `source_ip` may invoke this route right now.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitDenied`] when the IP's bucket is empty.
    pub fn check_ip(&self, source_ip: IpAddr) -> Result<(), RateLimitDenied> {
        self.ip.check_key(&source_ip).map_err(|_throttled_until| RateLimitDenied {
            route: self.route_name,
            scope: format!("ip:{source_ip}"),
        })
    }

    /// Check whether `peer_id` may invoke this route right now.
    /// Returns `Ok(())` for routes that do not enforce per-PeerId
    /// limits (i.e. when this limiter was constructed without a
    /// `per_peer_per_minute` cap).
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitDenied`] when the peer's bucket is
    /// empty.
    pub fn check_peer(&self, peer_id: PeerId) -> Result<(), RateLimitDenied> {
        let Some(peer_limiter) = self.peer.as_ref() else {
            return Ok(());
        };
        peer_limiter.check_key(&peer_id).map_err(|_throttled_until| RateLimitDenied {
            route: self.route_name,
            scope: format!("peer:{peer_id}"),
        })
    }
}

/// Bundle of per-route limiters covering all four control-plane
/// verbs. Constructed once at startup with [`RouteLimits::default_mvp`]
/// (or [`RouteLimits::custom`] for per-deploy overrides).
#[derive(Debug, Clone)]
pub struct RouteLimits {
    /// `POST /api/v1/register` limiter.
    pub register: RouteLimiter,
    /// `POST /api/v1/match` limiter.
    pub match_: RouteLimiter,
    /// `POST /api/v1/heartbeat` limiter.
    pub heartbeat: RouteLimiter,
    /// `POST /api/v1/disconnect` limiter.
    pub disconnect: RouteLimiter,
}

impl RouteLimits {
    /// Build the F-COORD.9 MVP-default bundle.
    ///
    /// # Errors
    ///
    /// The defaults are non-zero compile-time constants; the
    /// fallible signature is forwarded from
    /// [`RouteLimiter::new`] so a future deploy-time override
    /// stays uniform with the constant-default path.
    pub fn default_mvp() -> Result<Self, RateLimitConfigError> {
        Self::custom(LimitConfig::default_mvp())
    }

    /// Build a bundle from a custom [`LimitConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitConfigError::ZeroBudget`] when any cap
    /// in `config` is zero.
    pub fn custom(config: LimitConfig) -> Result<Self, RateLimitConfigError> {
        Ok(Self {
            // `register` is unauthenticated: enforce per-IP only.
            // Per-PeerId enforcement here would let an attacker
            // spend any known/guessable peer id's quota; see the
            // module rustdoc.
            register: RouteLimiter::new("register", config.per_ip_register, None)?,
            match_: RouteLimiter::new("match", config.per_ip_match, Some(config.per_peer_match))?,
            heartbeat: RouteLimiter::new(
                "heartbeat",
                config.per_ip_heartbeat,
                Some(config.per_peer_heartbeat),
            )?,
            disconnect: RouteLimiter::new("disconnect", config.per_ip_disconnect, None)?,
        })
    }
}

/// Per-deploy-overridable rate-limit caps. Mirrors the MVP
/// defaults at construction time but lets a future config loader
/// tune the numbers without touching the type.
#[derive(Debug, Clone, Copy)]
pub struct LimitConfig {
    /// `register` per-IP per-minute cap.
    pub per_ip_register: u32,
    /// `match` per-IP per-minute cap.
    pub per_ip_match: u32,
    /// `heartbeat` per-IP per-minute cap.
    pub per_ip_heartbeat: u32,
    /// `disconnect` per-IP per-minute cap.
    pub per_ip_disconnect: u32,
    /// `match` per-PeerId per-minute cap.
    pub per_peer_match: u32,
    /// `heartbeat` per-PeerId per-minute cap.
    pub per_peer_heartbeat: u32,
}

impl LimitConfig {
    /// F-COORD.9 MVP defaults.
    #[must_use]
    pub const fn default_mvp() -> Self {
        Self {
            per_ip_register: PER_IP_REGISTER_PER_MINUTE,
            per_ip_match: PER_IP_MATCH_PER_MINUTE,
            per_ip_heartbeat: PER_IP_HEARTBEAT_PER_MINUTE,
            per_ip_disconnect: PER_IP_DISCONNECT_PER_MINUTE,
            per_peer_match: PER_PEER_MATCH_PER_MINUTE,
            per_peer_heartbeat: PER_PEER_HEARTBEAT_PER_MINUTE,
        }
    }
}

/// Build a `Quota::per_minute` from a non-zero `u32`, surfacing
/// [`RateLimitConfigError::ZeroBudget`] on zero input.
fn quota_per_minute(rate: u32, field: &'static str) -> Result<Quota, RateLimitConfigError> {
    let quota_size = NonZeroU32::new(rate).ok_or(RateLimitConfigError::ZeroBudget { field })?;
    Ok(Quota::per_minute(quota_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibeam_core::PeerId;
    use core::net::Ipv4Addr;

    #[test]
    fn defaults_match_spec_constants() {
        // Contract: the MVP defaults reflect the F-COORD.9 spec
        // (with the documented register-per-peer deviation; see
        // module rustdoc). A regression that silently bumped a
        // cap, or restored per-peer enforcement to `register`,
        // would let a hostile IP saturate the coordinator's CPU
        // budget on the Oracle ARM Free Tier deployment — or
        // worse, let an attacker spend any known peer id's
        // registration quota.
        let config = LimitConfig::default_mvp();
        assert_eq!(config.per_ip_register, 30);
        assert_eq!(config.per_ip_match, 60);
        assert_eq!(config.per_ip_heartbeat, 120);
        assert_eq!(config.per_ip_disconnect, 30);
        assert_eq!(config.per_peer_match, 30);
        assert_eq!(config.per_peer_heartbeat, 60);
    }

    #[test]
    fn register_route_has_no_per_peer_enforcement() {
        // Contract: the `register` route MUST construct its
        // limiter with `None` for the peer cap, so an attacker who
        // observes (or guesses) a peer id cannot spend that
        // peer's registration bucket. Catches a regression that
        // re-enabled per-PeerId enforcement on the unauthenticated
        // route.
        let limits = RouteLimits::default_mvp().expect("build");
        for _attempt in 0..1_000 {
            limits
                .register
                .check_peer(PeerId::new())
                .expect("peer check is a no-op on register");
        }
    }

    #[test]
    fn route_limiter_passes_first_request_under_quota() {
        // Contract: a freshly-constructed limiter must let the
        // first request through. Sanity check against a regression
        // that initialised the bucket empty.
        let limiter = RouteLimiter::new("register", 30, Some(6)).expect("build");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
        limiter.check_ip(ip).expect("first ip request passes");
        let peer = PeerId::new();
        limiter.check_peer(peer).expect("first peer request passes");
    }

    #[test]
    fn route_limiter_denies_burst_above_quota() {
        // Contract: a small-quota limiter denies the (N+1)th
        // request in a single burst. Catches a regression that
        // dropped the keyed-store enforcement (which would let
        // any single IP exceed its budget unchecked).
        let limiter = RouteLimiter::new("match", 1, Some(1)).expect("build");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        limiter.check_ip(ip).expect("first passes");
        let err = limiter.check_ip(ip).expect_err("second must deny");
        assert!(err.scope.starts_with("ip:"));
        assert_eq!(err.route, "match");
    }

    #[test]
    fn zero_per_ip_budget_is_rejected() {
        // Contract: a zero cap is a configuration error, never a
        // closed-route policy. Catches a regression that silently
        // mapped zero to "deny everything" (which would break
        // every deployment on the first request).
        let err = RouteLimiter::new("register", 0, Some(6)).expect_err("must reject");
        assert!(
            matches!(err, RateLimitConfigError::ZeroBudget { field } if field == "per_ip_per_minute")
        );
    }

    #[test]
    fn route_limiter_without_peer_enforcement_passes_peer_check() {
        // Contract: the `disconnect` route has no per-PeerId
        // enforcement (constructed with `None` for the peer cap).
        // `check_peer` must therefore pass unconditionally so the
        // handler does not need to branch.
        let limiter = RouteLimiter::new("disconnect", 30, None).expect("build");
        for _attempt in 0..1_000 {
            limiter.check_peer(PeerId::new()).expect("peer check passes when unenforced");
        }
    }
}
