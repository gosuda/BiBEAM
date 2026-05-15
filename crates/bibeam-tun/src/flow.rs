#![forbid(unsafe_code)]
//! Per-flow tracking.
//!
//! [`FlowTable`] is a concurrent map from 5-tuple [`FlowKey`] to a
//! shared [`FlowState`]. State carries directional byte counters and a
//! last-seen timestamp in epoch seconds, stored as
//! [`std::sync::atomic::AtomicU64`] so reads do not need a lock.
//!
//! ## Why `DashMap`
//!
//! Flow lookups happen on every packet in both directions. A single
//! [`std::sync::Mutex`] would serialize the whole table. [`dashmap`]
//! shards the table internally so concurrent reads on different keys
//! run in parallel; that is a good fit for the read-heavy hot path.
//!
//! ## Why `Arc<FlowState>`
//!
//! Callers that update counters take an [`std::sync::Arc<FlowState>`]
//! reference and hold it across the atomic stores. Storing values
//! directly inside the map would force callers to hold a `DashMap`
//! shard guard for the duration of the update, which blocks
//! concurrent updates of OTHER keys on the same shard.
//!
//! ## GC
//!
//! [`FlowTable::gc`] is the only retire path. Callers pick a periodic
//! cadence (e.g. once per second) and an idle window, and the table
//! drops any entry that has not been touched within that window. There
//! is no per-flow timer.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

/// 5-tuple identifying a unidirectional or bidirectional flow.
///
/// Bidirectional flows share the same key in both directions because
/// callers either canonicalise (always store the connection initiator's
/// `(src, dst)` ordering) or use [`Self::reversed`] to look up the
/// reverse direction without re-hashing fields the caller already has.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowKey {
    /// IP protocol number (`6` for TCP, `17` for UDP, etc.).
    pub proto: u8,
    /// Source IP address.
    pub src: IpAddr,
    /// Source port (`0` for transports that lack ports).
    pub src_port: u16,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Destination port (`0` for transports that lack ports).
    pub dst_port: u16,
}

impl FlowKey {
    /// Return the flow key with src/dst (address and port) swapped.
    #[must_use]
    pub const fn reversed(&self) -> Self {
        Self {
            proto: self.proto,
            src: self.dst,
            src_port: self.dst_port,
            dst: self.src,
            dst_port: self.src_port,
        }
    }
}

/// Mutable state carried for each flow.
///
/// Counters are [`AtomicU64`] so updates can happen without a lock.
/// `last_seen` is the epoch second of the most recent touch (in or out).
#[derive(Debug, Default)]
pub struct FlowState {
    /// Cumulative bytes observed on the inbound side.
    pub bytes_in: AtomicU64,
    /// Cumulative bytes observed on the outbound side.
    pub bytes_out: AtomicU64,
    /// Epoch-seconds timestamp of the most recent observation.
    pub last_seen: AtomicU64,
}

/// Concurrent flow-state table.
///
/// Cloning a [`FlowTable`] shares the underlying [`DashMap`] (it is
/// wrapped in an [`Arc`]). Spawn one task that reads outbound packets
/// and one that reads inbound packets, hand both a clone of the same
/// `FlowTable`, and they will see each other's updates without further
/// synchronisation.
#[derive(Default, Clone, Debug)]
pub struct FlowTable {
    inner: Arc<DashMap<FlowKey, Arc<FlowState>>>,
}

impl FlowTable {
    /// Create a fresh empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `bytes` on the outbound side of `key`, refreshing
    /// `last_seen` to `now_secs`. Allocates a fresh [`FlowState`] if
    /// the key is unknown.
    pub fn touch_out(&self, key: FlowKey, bytes: u64, now_secs: u64) {
        // Hold the shard write guard through the atomic update so a
        // concurrent gc() cannot retire the entry between the lookup
        // and the store. dashmap's `entry` API acquires the shard
        // write lock; gc()'s `retain` also takes a write lock — the
        // two are mutually exclusive at the shard granularity.
        let entry = self.inner.entry(key).or_insert_with(|| Arc::new(FlowState::default()));
        entry.value().bytes_out.fetch_add(bytes, Ordering::Relaxed);
        entry.value().last_seen.store(now_secs, Ordering::Relaxed);
    }

    /// Record `bytes` on the inbound side of `key`, refreshing
    /// `last_seen` to `now_secs`. Allocates a fresh [`FlowState`] if
    /// the key is unknown.
    pub fn touch_in(&self, key: FlowKey, bytes: u64, now_secs: u64) {
        let entry = self.inner.entry(key).or_insert_with(|| Arc::new(FlowState::default()));
        entry.value().bytes_in.fetch_add(bytes, Ordering::Relaxed);
        entry.value().last_seen.store(now_secs, Ordering::Relaxed);
    }

    /// Look up the state for `key` without creating it.
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<Arc<FlowState>> {
        self.inner.get(key).map(|guard| Arc::clone(guard.value()))
    }

    /// Number of tracked flows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if no flows are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Drop flows whose `last_seen` is older than `now_secs - idle_secs`.
    /// Returns the number of dropped entries.
    ///
    /// The predicate runs while [`DashMap::retain`] holds each shard's
    /// write lock. Concurrent `touch_in` / `touch_out` calls on the
    /// same shard block until the predicate finishes, which means a
    /// touch that races with a gc decision either:
    ///
    /// - lands before the predicate evaluation (entry refreshed,
    ///   predicate sees fresh `last_seen`, entry kept), or
    /// - lands after the entry has been retired (touch's
    ///   `or_insert_with` allocates a fresh `FlowState` and stores it
    ///   back into the map).
    ///
    /// Either path leaves the table self-consistent. The packet's
    /// counter update cannot "land on an orphaned state" because the
    /// fresh insert puts the new `FlowState` back into the live map.
    pub fn gc(&self, now_secs: u64, idle_secs: u64) -> usize {
        let cutoff = now_secs.saturating_sub(idle_secs);
        let mut dropped = 0usize;
        self.inner.retain(|_, state| {
            let last_seen = state.last_seen.load(Ordering::Relaxed);
            let keep = last_seen >= cutoff;
            if !keep {
                dropped += 1;
            }
            keep
        });
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_key() -> FlowKey {
        FlowKey {
            proto: 17,
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 1000,
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 53,
        }
    }

    #[test]
    fn touch_creates_then_updates_counters() {
        let table = FlowTable::new();
        let key = sample_key();
        table.touch_out(key, 100, 1000);
        table.touch_in(key, 200, 1001);
        let state = table.get(&key).expect("state exists");
        assert_eq!(state.bytes_out.load(Ordering::Relaxed), 100);
        assert_eq!(state.bytes_in.load(Ordering::Relaxed), 200);
        assert_eq!(state.last_seen.load(Ordering::Relaxed), 1001);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn gc_drops_stale_entries() {
        let table = FlowTable::new();
        let fresh = FlowKey { dst_port: 1, ..sample_key() };
        let stale = FlowKey { dst_port: 2, ..sample_key() };
        table.touch_out(fresh, 1, 1_000);
        table.touch_out(stale, 1, 100);
        let dropped = table.gc(1_000, 60);
        assert_eq!(dropped, 1);
        assert!(table.get(&fresh).is_some());
        assert!(table.get(&stale).is_none());
    }

    #[test]
    fn reversed_swaps_src_and_dst() {
        let key = sample_key();
        let rev = key.reversed();
        assert_eq!(rev.src, key.dst);
        assert_eq!(rev.dst, key.src);
        assert_eq!(rev.src_port, key.dst_port);
        assert_eq!(rev.dst_port, key.src_port);
        assert_eq!(rev.proto, key.proto);
    }
}
