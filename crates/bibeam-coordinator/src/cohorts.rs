#![forbid(unsafe_code)]
//! redb-backed cohort assignments store (F-COORD.3).
//!
//! Where [`crate::registry`] tracks per-peer state, [`CohortStore`]
//! tracks per-cohort state: which peers belong to a cohort, which
//! exits serve it, and when the cohort must rotate. The matchmaker
//! (F-COORD.5) reads + writes records here as it admits peers; the
//! rotation scheduler (F-COORD.6) reads them to decide which cohorts
//! need fresh assignments.
//!
//! ## redb 4 layout
//!
//! Single `cohorts` table; key is the cohort's 16-byte ULID,
//! value is a postcard-encoded [`CohortRecord`]. The same
//! `Arc<redb::Database>` shape as
//! [`crate::registry::PeerRegistry`] — cheap to clone, opened once
//! per process.
//!
//! ## Eviction
//!
//! [`CohortStore::evict_expired`] removes every cohort whose
//! `rotation_deadline` is strictly older than the supplied `now`.
//! The scan + delete runs inside a single write transaction so a
//! concurrent [`CohortStore::upsert`] that extends a deadline
//! cannot have its row deleted by an in-progress eviction.

use std::path::Path;
use std::sync::Arc;

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// redb table holding one postcard-encoded [`CohortRecord`] per
/// cohort, keyed by the cohort's 16-byte ULID.
const COHORTS_TABLE: TableDefinition<'_, &[u8; 16], &[u8]> = TableDefinition::new("cohorts");

/// Canonical per-cohort state owned by the coordinator.
///
/// Stored postcard-encoded inside the module-private cohorts table.
/// Mirrors the shape downstream consumers (admissioner, rotation
/// scheduler, audit log) expect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortRecord {
    /// Peers currently assigned to this cohort.
    pub members: Vec<PeerId>,
    /// Exit nodes serving this cohort's egress traffic.
    pub exits: Vec<NodeId>,
    /// Wall-clock instant after which the cohort must rotate.
    pub rotation_deadline: Timestamp,
}

/// Failure modes for [`CohortStore`].
#[derive(Debug, Error)]
pub enum CohortStoreError {
    /// redb reported a failure during open, transaction begin /
    /// commit, or table operation.
    #[error("redb error: {0}")]
    Redb(String),
    /// postcard failed to encode or decode the stored
    /// [`CohortRecord`].
    #[error("postcard codec error: {0}")]
    Codec(#[from] postcard::Error),
}

impl CohortStoreError {
    fn redb<DisplayErr: core::fmt::Display>(err: DisplayErr) -> Self {
        Self::Redb(err.to_string())
    }
}

/// Cheap-to-clone handle on the redb-backed cohort store.
#[derive(Clone)]
pub struct CohortStore {
    db: Arc<Database>,
}

impl core::fmt::Debug for CohortStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("CohortStore").finish_non_exhaustive()
    }
}

impl CohortStore {
    /// Open (or create) the redb file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`CohortStoreError::Redb`] if redb cannot create the
    /// file or initialise the `cohorts` table.
    pub fn open(path: &Path) -> Result<Self, CohortStoreError> {
        let database = Database::create(path).map_err(CohortStoreError::redb)?;
        let store = Self { db: Arc::new(database) };
        store.ensure_table_exists()?;
        Ok(store)
    }

    /// Insert or replace the record for `cohort`.
    ///
    /// # Errors
    ///
    /// Returns [`CohortStoreError::Codec`] when postcard rejects the
    /// shape, and [`CohortStoreError::Redb`] on any redb transaction
    /// failure.
    pub fn upsert(&self, cohort: &CohortId, record: &CohortRecord) -> Result<(), CohortStoreError> {
        let encoded = postcard::to_allocvec(record)?;
        let key = cohort.into_ulid().to_bytes();
        let txn = self.db.begin_write().map_err(CohortStoreError::redb)?;
        {
            let mut table = txn.open_table(COHORTS_TABLE).map_err(CohortStoreError::redb)?;
            table.insert(&key, encoded.as_slice()).map_err(CohortStoreError::redb)?;
        }
        txn.commit().map_err(CohortStoreError::redb)?;
        Ok(())
    }

    /// Return the stored record for `cohort`, or [`None`] when no
    /// record exists.
    ///
    /// # Errors
    ///
    /// Returns [`CohortStoreError::Codec`] when the stored bytes
    /// fail postcard decode, and [`CohortStoreError::Redb`] on any
    /// redb transaction failure.
    pub fn get(&self, cohort: &CohortId) -> Result<Option<CohortRecord>, CohortStoreError> {
        let key = cohort.into_ulid().to_bytes();
        let txn = self.db.begin_read().map_err(CohortStoreError::redb)?;
        let table = txn.open_table(COHORTS_TABLE).map_err(CohortStoreError::redb)?;
        let Some(guard) = table.get(&key).map_err(CohortStoreError::redb)? else {
            return Ok(None);
        };
        let record = postcard::from_bytes::<CohortRecord>(guard.value())?;
        Ok(Some(record))
    }

    /// Remove every cohort whose `rotation_deadline` is strictly
    /// older than `now`. Returns the count of evicted entries.
    ///
    /// Scan and removal share a single write transaction so a
    /// concurrent [`CohortStore::upsert`] that extends a cohort's
    /// deadline cannot have its row evicted by an in-progress
    /// sweep.
    ///
    /// # Errors
    ///
    /// Returns [`CohortStoreError::Codec`] when a stored row fails
    /// postcard decode, and [`CohortStoreError::Redb`] on any redb
    /// transaction failure.
    pub fn evict_expired(&self, now: Timestamp) -> Result<usize, CohortStoreError> {
        let txn = self.db.begin_write().map_err(CohortStoreError::redb)?;
        let evicted = {
            let mut table = txn.open_table(COHORTS_TABLE).map_err(CohortStoreError::redb)?;
            collect_and_remove_expired(&mut table, now)?
        };
        txn.commit().map_err(CohortStoreError::redb)?;
        Ok(evicted)
    }

    /// Open + commit a write transaction so the table physically
    /// exists on disk before any read transaction is attempted.
    fn ensure_table_exists(&self) -> Result<(), CohortStoreError> {
        let txn = self.db.begin_write().map_err(CohortStoreError::redb)?;
        {
            let _table = txn.open_table(COHORTS_TABLE).map_err(CohortStoreError::redb)?;
        }
        txn.commit().map_err(CohortStoreError::redb)?;
        Ok(())
    }
}

/// Iterate the mutable table once, collecting every expired key,
/// then remove each in turn — all inside the caller's write
/// transaction. Module-private so the single-transaction contract
/// cannot be violated from outside.
fn collect_and_remove_expired(
    table: &mut redb::Table<'_, &[u8; 16], &[u8]>,
    now: Timestamp,
) -> Result<usize, CohortStoreError> {
    let mut expired: Vec<[u8; 16]> = Vec::new();
    for entry in table.iter().map_err(CohortStoreError::redb)? {
        let (key_guard, value_guard) = entry.map_err(CohortStoreError::redb)?;
        let record = postcard::from_bytes::<CohortRecord>(value_guard.value())?;
        if record.rotation_deadline.as_offset_date_time() < now.as_offset_date_time() {
            expired.push(*key_guard.value());
        }
    }
    for key in &expired {
        table.remove(key).map_err(CohortStoreError::redb)?;
    }
    Ok(expired.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn fixture_record(deadline: Timestamp) -> CohortRecord {
        CohortRecord {
            members: vec![PeerId::new(), PeerId::new()],
            exits: vec![NodeId::new()],
            rotation_deadline: deadline,
        }
    }

    fn store_with_temp_file() -> (CohortStore, tempfile::NamedTempFile) {
        let temp = tempfile::NamedTempFile::new().expect("tempfile");
        let store = CohortStore::open(temp.path()).expect("open store");
        (store, temp)
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let (store, _temp) = store_with_temp_file();
        let cohort = CohortId::new();
        let record = fixture_record(Timestamp::now());
        store.upsert(&cohort, &record).expect("upsert");
        let recovered = store.get(&cohort).expect("get").expect("present");
        assert_eq!(recovered, record);
    }

    #[test]
    fn get_returns_none_for_unknown_cohort() {
        let (store, _temp) = store_with_temp_file();
        let missing = store.get(&CohortId::new()).expect("get");
        assert!(missing.is_none());
    }

    #[test]
    fn second_upsert_overwrites_first() {
        // Contract: re-assignment must overwrite, not append. A
        // regression that appended would let an old member list
        // shadow the current one and break rotation policy.
        let (store, _temp) = store_with_temp_file();
        let cohort = CohortId::new();
        let mut record = fixture_record(Timestamp::now());
        store.upsert(&cohort, &record).expect("first upsert");
        record.members.clear();
        store.upsert(&cohort, &record).expect("second upsert");
        let recovered = store.get(&cohort).expect("get").expect("present");
        assert!(recovered.members.is_empty());
    }

    #[test]
    fn evict_expired_removes_only_past_deadlines() {
        // Contract: a cohort with `rotation_deadline >= now` must
        // survive eviction; one with `rotation_deadline < now` must
        // be removed. Catches inequality regressions.
        let (store, _temp) = store_with_temp_file();
        let now = Timestamp::now();
        let past = Timestamp::from_offset_date_time(now.into_inner() - Duration::hours(1));
        let future = Timestamp::from_offset_date_time(now.into_inner() + Duration::hours(1));
        let stale = CohortId::new();
        let live = CohortId::new();
        store.upsert(&stale, &fixture_record(past)).expect("upsert stale");
        store.upsert(&live, &fixture_record(future)).expect("upsert live");
        let evicted = store.evict_expired(now).expect("evict");
        assert_eq!(evicted, 1);
        assert!(store.get(&stale).expect("get stale").is_none());
        assert!(store.get(&live).expect("get live").is_some());
    }
}
