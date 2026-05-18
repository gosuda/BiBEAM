#![forbid(unsafe_code)]
//! Multi-coordinator leader-election scaffolding (P2A-1; F-COORD.12).
//!
//! Per the architecture document the production deployment shape
//! is one *leader* coordinator plus N *standbys* that take over
//! when the leader's lease expires. This module declares the
//! [`LeaderLease`] trait — the public API every backend
//! implementation (etcd, consul, a bespoke gossip layer, …) will
//! satisfy — plus a [`SoleLeaderLease`] MVP implementation that
//! claims sole leadership for a single-process deployment.
//!
//! ## Out of scope
//!
//! The actual lease backend is a follow-up PR per
//! `docs/architecture.md`. This commit scaffolds the trait shape,
//! the [`LeaseHandle`] opaque token, and the [`SoleLeaderLease`]
//! no-op implementation so downstream call sites (the rotation
//! scheduler, the audit log, the redemption ledger) can be
//! written against a stable interface today and have their
//! production backend swapped in tomorrow.
//!
//! ## Async trait
//!
//! Rust 2024 + Rust ≥ 1.75 has `async fn` in traits natively, so
//! the trait below uses that surface directly. The trait is
//! `Send + Sync` so handles can fan out across tokio tasks.

use core::future::Future;
use std::time::Duration;

use thiserror::Error;

/// Opaque handle returned by [`LeaderLease::acquire`].
///
/// The internal representation is intentionally hidden so
/// different backends can extend it without breaking the public
/// API. A backend will typically carry an internal id, a
/// generation counter, or a backend-specific session token. The
/// MVP no-op backend stores nothing.
#[derive(Debug, Clone)]
pub struct LeaseHandle {
    #[allow(
        dead_code,
        reason = "MVP no-op backend has nothing to read out of the \
                  handle yet; production backends (etcd, consul, Raft) \
                  will overlay typed fields here in a follow-up PR. \
                  Keeping the field present + private locks the wire \
                  shape so the public API stays stable across the \
                  switch."
    )]
    inner: LeaseHandleRepr,
}

/// Internal representation of a [`LeaseHandle`]. Hidden inside
/// the module so the wire shape can change without breaking the
/// public API.
#[derive(Debug, Clone)]
enum LeaseHandleRepr {
    /// Sole-leader lease for the MVP single-coordinator path.
    /// Carries no payload — the backend always grants the lease.
    SoleLeader,
}

impl LeaseHandle {
    /// Construct the MVP sole-leader handle. The constructor is
    /// crate-private so production backends cannot accidentally
    /// fabricate a sole-leader handle.
    #[must_use]
    pub(crate) const fn sole_leader() -> Self {
        Self {
            inner: LeaseHandleRepr::SoleLeader,
        }
    }
}

/// Failure modes returned by [`LeaderLease`] operations.
#[derive(Debug, Error)]
pub enum LeaseError {
    /// Another coordinator holds the lease. Standbys observe this
    /// while polling [`LeaderLease::acquire`] in the retry loop.
    #[error("lease is held by another coordinator")]
    Held,
    /// The supplied [`LeaseHandle`] does not match a live lease —
    /// either the lease already expired or the backend lost
    /// track of it.
    #[error("lease handle does not match a live lease")]
    Lost,
    /// Transport / backend-specific failure surfaced as a string.
    /// A future backend-specific [`LeaseError::Backend`] variant
    /// may carry a typed payload.
    #[error("lease backend error: {0}")]
    Backend(String),
}

/// Trait for a lease-based leader-election backend.
///
/// One implementation per deployment shape. The MVP supplies
/// [`SoleLeaderLease`] for single-coordinator deployments; a
/// follow-up PR adds an etcd / consul / Raft backend that
/// satisfies the same trait.
///
/// ## Generic-only contract
///
/// The trait uses return-position `impl Future`, so it is
/// **not** object-safe — callers cannot hold `Arc<dyn LeaderLease>`.
/// The intentional design is generic-only: every consumer of a
/// lease backend takes `L: LeaderLease` as a type parameter on
/// its constructor. The single-implementation MVP keeps generics
/// near the call site cheap, and the etcd / consul follow-up
/// will swap the type without disturbing the call sites.
/// A future backend-injection point (e.g. a tagged enum
/// dispatching between concrete backends) can be added without
/// changing this trait.
pub trait LeaderLease: Send + Sync {
    /// Acquire the lease for the given TTL. Returns a
    /// [`LeaseHandle`] the holder must `heartbeat` before the TTL
    /// expires.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Held`] when another coordinator
    /// owns the lease; [`LeaseError::Backend`] for transport or
    /// backend-internal failures.
    fn acquire(
        &self,
        ttl: Duration,
    ) -> impl Future<Output = Result<LeaseHandle, LeaseError>> + Send;

    /// Renew an existing lease. The backend extends the TTL by
    /// the same window the lease was acquired under.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Lost`] if `handle` does not match a
    /// live lease (i.e. the lease has already expired or the
    /// backend revoked it); [`LeaseError::Backend`] for transport
    /// failures.
    fn heartbeat(
        &self,
        handle: &LeaseHandle,
    ) -> impl Future<Output = Result<(), LeaseError>> + Send;

    /// Release the lease early. Standby coordinators can take
    /// over without waiting for the TTL to expire.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Lost`] if `handle` does not match a
    /// live lease; [`LeaseError::Backend`] for transport
    /// failures.
    fn release(&self, handle: LeaseHandle) -> impl Future<Output = Result<(), LeaseError>> + Send;
}

/// MVP no-op lease backend.
///
/// Always claims sole leadership. Use this in single-coordinator
/// deployments. Production multi-coordinator deployments replace
/// it with a real backend in a follow-up PR per
/// `docs/architecture.md`.
#[derive(Debug, Clone, Copy)]
pub struct SoleLeaderLease;

impl LeaderLease for SoleLeaderLease {
    async fn acquire(&self, _ttl: Duration) -> Result<LeaseHandle, LeaseError> {
        Ok(LeaseHandle::sole_leader())
    }

    async fn heartbeat(&self, _handle: &LeaseHandle) -> Result<(), LeaseError> {
        Ok(())
    }

    async fn release(&self, _handle: LeaseHandle) -> Result<(), LeaseError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sole_leader_lease_acquires_and_releases() {
        // Contract: the MVP no-op backend always grants the lease
        // and never fails. Catches a regression that wired an
        // unimplemented stub into the production single-coordinator
        // path (which would deadlock the daemon's startup
        // sequence).
        let backend = SoleLeaderLease;
        let handle = backend.acquire(Duration::from_secs(60)).await.expect("acquire");
        backend.heartbeat(&handle).await.expect("heartbeat");
        backend.release(handle).await.expect("release");
    }
}
