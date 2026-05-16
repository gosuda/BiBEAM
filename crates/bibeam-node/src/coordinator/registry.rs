#![forbid(unsafe_code)]
//! redb-backed peer registry (F-COORD.2).
//!
//! Stores one [`bibeam_discovery::PeerRecord`] per known peer, keyed
//! by the peer's 16-byte ULID. Values are postcard-encoded so the
//! on-disk shape stays compact and the round-trip is identical to
//! every other byte-level representation the discovery plane uses
//! (pkarr TXT, postcard frame envelopes).
//!
//! ## redb 4 layout
//!
//! `peers` is the single fixed-name table. `redb::TableDefinition`
//! is a `const`; the same definition object is shared by every
//! transaction. The handle returned by [`PeerRegistry::open`] holds
//! the [`redb::Database`] inside an [`Arc`] so the registry is
//! cheap to clone into axum handlers, the rotation scheduler
//! (F-COORD.6), and the audit log (F-COORD.8) without re-opening
//! the file.
//!
//! ## Eviction
//!
//! [`PeerRegistry::evict_stale`] walks the table inside one write
//! transaction and removes every record whose `last_seen` is older
//! than the supplied threshold. The scan is full because redb does
//! not index secondary fields; the table is expected to stay small
//! enough at MVP that the cost is dominated by the I/O budget of
//! the underlying mmap, not the in-process comparison loop.

use std::path::Path;
use std::sync::Arc;

use bibeam_core::{PeerId, Timestamp};
use bibeam_discovery::PeerRecord;
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use thiserror::Error;

/// redb table holding one postcard-encoded
/// [`bibeam_discovery::PeerRecord`] per registered peer, keyed by
/// the peer's 16-byte ULID.
const PEERS_TABLE: TableDefinition<'_, &[u8; 16], &[u8]> = TableDefinition::new("peers");

/// Failure modes for the redb-backed peer registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// redb reported a failure during database open, transaction
    /// begin / commit, or table operation.
    #[error("redb error: {0}")]
    Redb(String),
    /// postcard failed to encode or decode the stored
    /// [`PeerRecord`] value.
    #[error("postcard codec error: {0}")]
    Codec(#[from] postcard::Error),
}

impl RegistryError {
    fn redb<DisplayErr: core::fmt::Display>(err: DisplayErr) -> Self {
        Self::Redb(err.to_string())
    }
}

/// Cheap-to-clone handle on the redb-backed peer registry.
///
/// Clone freely into axum handlers, schedulers, and audit hooks —
/// the underlying [`redb::Database`] sits behind an [`Arc`] so the
/// file is opened exactly once for the lifetime of the process.
#[derive(Clone)]
pub struct PeerRegistry {
    db: Arc<Database>,
}

impl core::fmt::Debug for PeerRegistry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("PeerRegistry").finish_non_exhaustive()
    }
}

impl PeerRegistry {
    /// Open (or create) the redb file at `path` and return a handle
    /// that owns the underlying [`redb::Database`] for the rest of
    /// the process.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Redb`] if redb cannot create the
    /// file, replay its journal, or initialise its B-tree state.
    pub fn open(path: &Path) -> Result<Self, RegistryError> {
        let database = Database::create(path).map_err(RegistryError::redb)?;
        let registry = Self { db: Arc::new(database) };
        registry.ensure_peers_table_exists()?;
        Ok(registry)
    }

    /// Insert or replace `record` in the registry.
    ///
    /// The peer's 16-byte ULID is the key; the postcard-encoded
    /// [`PeerRecord`] is the value. A second call with the same
    /// `record.peer_id` overwrites the previous value.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Codec`] when postcard rejects the
    /// shape (vanishingly unlikely — `PeerRecord` is plain data),
    /// and [`RegistryError::Redb`] on any redb transaction
    /// failure.
    pub fn upsert(&self, record: &PeerRecord) -> Result<(), RegistryError> {
        let encoded = postcard::to_allocvec(record)?;
        let key = record.peer_id.into_ulid().to_bytes();
        let txn = self.db.begin_write().map_err(RegistryError::redb)?;
        {
            let mut table = txn.open_table(PEERS_TABLE).map_err(RegistryError::redb)?;
            table.insert(&key, encoded.as_slice()).map_err(RegistryError::redb)?;
        }
        txn.commit().map_err(RegistryError::redb)?;
        Ok(())
    }

    /// Return the registry's stored snapshot for `peer_id`, or
    /// [`None`] when no record exists.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Codec`] when the stored bytes fail
    /// postcard decode (indicating on-disk corruption or a wire-form
    /// regression), and [`RegistryError::Redb`] on any redb
    /// transaction failure.
    pub fn get(&self, peer_id: &PeerId) -> Result<Option<PeerRecord>, RegistryError> {
        let key = peer_id.into_ulid().to_bytes();
        let txn = self.db.begin_read().map_err(RegistryError::redb)?;
        let table = txn.open_table(PEERS_TABLE).map_err(RegistryError::redb)?;
        let Some(guard) = table.get(&key).map_err(RegistryError::redb)? else {
            return Ok(None);
        };
        let record = postcard::from_bytes::<PeerRecord>(guard.value())?;
        Ok(Some(record))
    }

    /// Remove every record whose `last_seen` is strictly older than
    /// `older_than`. Returns the count of evicted entries.
    ///
    /// The scan and the per-row removal both run inside a single
    /// redb write transaction so a concurrent
    /// [`PeerRegistry::upsert`] cannot refresh a peer's `last_seen`
    /// between the two phases and have its fresh row deleted
    /// anyway. redb serialises write transactions, so the scan sees
    /// the same committed state the removals operate on.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Codec`] when a stored row fails
    /// postcard decode (a single bad row aborts the eviction
    /// transaction; the redb commit is not partial), and
    /// [`RegistryError::Redb`] on any redb transaction failure.
    pub fn evict_stale(&self, older_than: Timestamp) -> Result<usize, RegistryError> {
        let txn = self.db.begin_write().map_err(RegistryError::redb)?;
        let evicted = {
            let mut table = txn.open_table(PEERS_TABLE).map_err(RegistryError::redb)?;
            collect_and_remove_stale(&mut table, older_than)?
        };
        txn.commit().map_err(RegistryError::redb)?;
        Ok(evicted)
    }

    /// Open + commit a write transaction so the table physically
    /// exists on disk after [`PeerRegistry::open`] returns. Without
    /// this an immediately-following `begin_read` would surface
    /// [`redb::Error::TableDoesNotExist`].
    fn ensure_peers_table_exists(&self) -> Result<(), RegistryError> {
        let txn = self.db.begin_write().map_err(RegistryError::redb)?;
        {
            let _table = txn.open_table(PEERS_TABLE).map_err(RegistryError::redb)?;
        }
        txn.commit().map_err(RegistryError::redb)?;
        Ok(())
    }
}

/// Iterate the mutable table once, collecting every stale key, then
/// remove each in turn — all inside the caller's write transaction.
///
/// Extracted from [`PeerRegistry::evict_stale`] so the
/// cognitive-complexity gate stays under threshold; the function is
/// `pub(super)`-private to the registry module so the locking
/// contract (single write transaction) cannot be violated from
/// outside.
fn collect_and_remove_stale(
    table: &mut redb::Table<'_, &[u8; 16], &[u8]>,
    older_than: Timestamp,
) -> Result<usize, RegistryError> {
    let mut stale: Vec<[u8; 16]> = Vec::new();
    for entry in table.iter().map_err(RegistryError::redb)? {
        let (key_guard, value_guard) = entry.map_err(RegistryError::redb)?;
        let record = postcard::from_bytes::<PeerRecord>(value_guard.value())?;
        if record.last_seen.as_offset_date_time() < older_than.as_offset_date_time() {
            stale.push(*key_guard.value());
        }
    }
    for key in &stale {
        table.remove(key).map_err(RegistryError::redb)?;
    }
    Ok(stale.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use time::Duration;

    fn fixture_record() -> PeerRecord {
        PeerRecord {
            peer_id: PeerId::new(),
            addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 41_443),
            can_exit: false,
            capacity_hint: 0,
            last_seen: Timestamp::now(),
            region: String::new(),
            region_last_verified_at: Timestamp::now(),
            wg_public_key: None,
        }
    }

    fn registry_with_temp_file() -> (PeerRegistry, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let registry = PeerRegistry::open(temp.path()).expect("open registry");
        (registry, temp)
    }

    #[test]
    fn upsert_then_get_round_trips() {
        // Contract: a value upserted under a peer id must read back
        // byte-identical via `get`. Catches a regression that flipped
        // the key encoding (which would silently lose every peer the
        // moment the registry restarted on a fresh process).
        let (registry, _temp) = registry_with_temp_file();
        let record = fixture_record();
        registry.upsert(&record).expect("upsert");
        let recovered = registry.get(&record.peer_id).expect("get").expect("present");
        assert_eq!(recovered, record);
    }

    #[test]
    fn get_returns_none_for_unknown_peer() {
        let (registry, _temp) = registry_with_temp_file();
        let missing = registry.get(&PeerId::new()).expect("get");
        assert!(missing.is_none());
    }

    #[test]
    fn second_upsert_overwrites_first() {
        // Contract: re-registration must overwrite the previous
        // snapshot, not append. A regression that double-stored
        // would let stale `last_seen` values shadow the freshest one
        // and break eviction.
        let (registry, _temp) = registry_with_temp_file();
        let mut record = fixture_record();
        registry.upsert(&record).expect("first upsert");
        record.capacity_hint = 99;
        registry.upsert(&record).expect("second upsert");
        let recovered = registry.get(&record.peer_id).expect("get").expect("present");
        assert_eq!(recovered.capacity_hint, 99);
    }

    #[test]
    fn evict_stale_removes_only_older_records() {
        // Contract: eviction is strictly comparison-based on
        // `last_seen`; a record with `last_seen >= older_than`
        // must survive. Catches a regression that swapped the
        // inequality (which would evict the freshest peer first
        // and let stale ones live).
        let (registry, _temp) = registry_with_temp_file();
        let now = Timestamp::now();
        let one_hour_ago = Timestamp::from_offset_date_time(now.into_inner() - Duration::hours(1));
        let stale = PeerRecord {
            last_seen: one_hour_ago,
            ..fixture_record()
        };
        let fresh = PeerRecord {
            last_seen: now,
            ..fixture_record()
        };
        registry.upsert(&stale).expect("upsert stale");
        registry.upsert(&fresh).expect("upsert fresh");
        let threshold = Timestamp::from_offset_date_time(now.into_inner() - Duration::minutes(30));
        let evicted = registry.evict_stale(threshold).expect("evict");
        assert_eq!(evicted, 1);
        assert!(registry.get(&stale.peer_id).expect("get stale").is_none());
        assert!(registry.get(&fresh.peer_id).expect("get fresh").is_some());
    }
}
