//! # IndexStore — Redb-backed ACID Chunk Index
//!
//! Wraps a Redb 2.1 database for ACID-compliant chunk indexing during
//! archive creation. Replaces the custom LSM-Tree (Spiller + TieredMerger)
//! with a single embedded B-tree database.
//!
//! ## Lifecycle
//!
//! - **Staging**: Created via `IndexStore::create()` during ingest.
//!   Entries are inserted via `insert()`. Redb provides ACID guarantees.
//! - **Finalization**: `drain_sorted()` returns all entries in hash order
//!   for writing as encrypted IndexPage blocks to the volume.
//! - **Cleanup**: `destroy()` removes the temp Redb file.

use std::path::{Path, PathBuf};

use bloomfilter::Bloom;
use redb::{Database, ReadableTable, ReadableTableMetadata};

use era_common::{ChunkHash, EraError, Result};

use crate::schema::TABLE_CHUNKS;
use crate::IndexEntry;

/// Bloom filter false positive rate (1%)
const BLOOM_FP_RATE: f64 = 0.01;

/// Deserialize an IndexEntry from potentially unaligned bytes.
///
/// Redb value bytes are not guaranteed to be 8-byte aligned, but rkyv
/// requires alignment for `check_archived_root` and `from_bytes`.
/// This helper copies to an aligned buffer before deserializing.
fn deserialize_entry_aligned(bytes: &[u8]) -> Result<IndexEntry> {
    // rkyv::AlignedVec provides 16-byte alignment
    let mut aligned = rkyv::AlignedVec::with_capacity(bytes.len());
    aligned.extend_from_slice(bytes);
    rkyv::from_bytes(&aligned).map_err(|e| EraError::Deserialization(e.to_string()))
}

/// IndexStore wraps a Redb database for ACID-compliant chunk indexing.
pub struct IndexStore {
    /// Redb database handle
    db: Database,
    /// Path to the Redb file (for cleanup)
    db_path: PathBuf,
    /// In-memory Bloom filter (survives across transactions)
    bloom: Bloom<ChunkHash>,
    /// Total entries inserted
    entry_count: usize,
}

impl IndexStore {
    /// Create a new staging IndexStore at the given path.
    pub fn create(path: &Path, bloom_capacity: usize) -> Result<Self> {
        let db = Database::create(path)
            .map_err(|e| EraError::IndexError(format!("Redb create failed: {}", e)))?;

        // Pre-create the table so reads don't fail on empty DB
        let write_txn = db
            .begin_write()
            .map_err(|e| EraError::IndexError(format!("Redb begin_write failed: {}", e)))?;
        {
            let _table = write_txn
                .open_table(TABLE_CHUNKS)
                .map_err(|e| EraError::IndexError(format!("Redb open_table failed: {}", e)))?;
        }
        write_txn
            .commit()
            .map_err(|e| EraError::IndexError(format!("Redb commit failed: {}", e)))?;

        let items = bloom_capacity.max(1024);
        Ok(Self {
            db,
            db_path: path.to_path_buf(),
            bloom: Bloom::new_for_fp_rate(items, BLOOM_FP_RATE),
            entry_count: 0,
        })
    }

    /// Open an existing Redb file in read-only mode (for crash recovery tests).
    pub fn open_readonly(path: &Path) -> Result<Self> {
        let db = Database::open(path)
            .map_err(|e| EraError::IndexError(format!("Redb open failed: {}", e)))?;

        // Rebuild bloom and count from existing data
        let read_txn = db
            .begin_read()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let table = read_txn
            .open_table(TABLE_CHUNKS)
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let len = table
            .len()
            .map_err(|e: redb::StorageError| EraError::IndexError(e.to_string()))? as usize;

        let mut bloom = Bloom::new_for_fp_rate(len.max(1024), BLOOM_FP_RATE);
        for result in table
            .iter()
            .map_err(|e| EraError::IndexError(e.to_string()))?
        {
            let (key, _) = result.map_err(|e| EraError::IndexError(e.to_string()))?;
            let hash = ChunkHash::from_bytes(*key.value());
            bloom.set(&hash);
        }

        Ok(Self {
            db,
            db_path: path.to_path_buf(),
            bloom,
            entry_count: len,
        })
    }

    /// Insert a single chunk entry (one write transaction per call).
    pub fn insert(&mut self, entry: &IndexEntry) -> Result<()> {
        self.bloom.set(&entry.hash);

        let value_bytes = rkyv::to_bytes::<_, 256>(entry)
            .map_err(|e| EraError::Serialization(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CHUNKS)
                .map_err(|e| EraError::IndexError(e.to_string()))?;
            table
                .insert(entry.hash.as_bytes(), value_bytes.as_slice())
                .map_err(|e| EraError::IndexError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        self.entry_count += 1;
        Ok(())
    }

    /// Batch insert entries in a single transaction (much faster for bulk loads).
    pub fn insert_batch(&mut self, entries: &[IndexEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CHUNKS)
                .map_err(|e| EraError::IndexError(e.to_string()))?;
            for entry in entries {
                self.bloom.set(&entry.hash);
                let value_bytes = rkyv::to_bytes::<_, 256>(entry)
                    .map_err(|e| EraError::Serialization(e.to_string()))?;
                table
                    .insert(entry.hash.as_bytes(), value_bytes.as_slice())
                    .map_err(|e| EraError::IndexError(e.to_string()))?;
            }
        }
        write_txn
            .commit()
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        self.entry_count += entries.len();
        Ok(())
    }

    /// Point lookup via Bloom filter + Redb read transaction.
    ///
    /// Uses `rkyv::check_archived_root` for zero-copy validation (Iron Law 1).
    pub fn get(&self, hash: &ChunkHash) -> Result<Option<IndexEntry>> {
        // Fast negative: bloom filter
        if !self.bloom.check(hash) {
            return Ok(None);
        }

        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let table = read_txn
            .open_table(TABLE_CHUNKS)
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        match table
            .get(hash.as_bytes())
            .map_err(|e| EraError::IndexError(e.to_string()))?
        {
            Some(access) => {
                let bytes = access.value();
                let entry = deserialize_entry_aligned(bytes)?;
                Ok(Some(entry))
            }
            None => Ok(None), // Bloom false positive
        }
    }

    /// Check bloom filter only (O(1) negative lookup).
    #[inline]
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        self.bloom.check(hash)
    }

    /// Get reference to bloom filter.
    pub fn bloom(&self) -> &Bloom<ChunkHash> {
        &self.bloom
    }

    /// Get entry count.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Drain all entries in sorted hash order for finalization.
    ///
    /// Redb's B-tree stores keys in sorted order, so iteration
    /// yields entries sorted by ChunkHash bytes — exactly what
    /// the finalization pipeline needs.
    pub fn drain_sorted(&self) -> Result<Vec<IndexEntry>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let table = read_txn
            .open_table(TABLE_CHUNKS)
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        let mut entries = Vec::with_capacity(self.entry_count);
        for result in table
            .iter()
            .map_err(|e| EraError::IndexError(e.to_string()))?
        {
            let (_, value) = result.map_err(|e| EraError::IndexError(e.to_string()))?;
            let bytes = value.value();
            let entry = deserialize_entry_aligned(bytes)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Compact the database (call before finalization for optimal read perf).
    pub fn compact(&mut self) -> Result<()> {
        self.db
            .compact()
            .map_err(|e| EraError::IndexError(format!("Redb compact failed: {}", e)))?;
        Ok(())
    }

    /// Destroy the staging database file.
    pub fn destroy(self) -> Result<()> {
        let path = self.db_path.clone();
        drop(self.db); // Close database first
        if path.exists() {
            std::fs::remove_file(&path).map_err(EraError::Io)?;
        }
        Ok(())
    }

    /// Get the database path.
    pub fn path(&self) -> &Path {
        &self.db_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::{BlockId, VolumeId};
    use tempfile::TempDir;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        ChunkHash::from_bytes(bytes)
    }

    fn make_entry(i: u64) -> IndexEntry {
        IndexEntry::new(
            test_hash(i),
            VolumeId::new(),
            BlockId::new(i / 100),
            (i % 100) as u32 * 1024,
            1024,
        )
    }

    #[test]
    fn test_store_create_and_insert() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let mut store = IndexStore::create(&db_path, 1024).unwrap();

        store.insert(&make_entry(42)).unwrap();
        assert_eq!(store.entry_count(), 1);
        assert!(store.bloom_contains(&test_hash(42)));
        assert!(!store.bloom_contains(&test_hash(999)));
    }

    #[test]
    fn test_store_get() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let mut store = IndexStore::create(&db_path, 1024).unwrap();

        let entry = make_entry(42);
        store.insert(&entry).unwrap();

        let result = store.get(&test_hash(42)).unwrap();
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found.hash, entry.hash);
        assert_eq!(found.length, entry.length);

        // Non-existent key
        let result = store.get(&test_hash(999)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_store_batch_insert() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let mut store = IndexStore::create(&db_path, 10_000).unwrap();

        let entries: Vec<IndexEntry> = (0..1000).map(make_entry).collect();
        store.insert_batch(&entries).unwrap();

        assert_eq!(store.entry_count(), 1000);
        for i in 0..1000u64 {
            assert!(store.bloom_contains(&test_hash(i)));
        }
    }

    #[test]
    fn test_store_drain_sorted() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let mut store = IndexStore::create(&db_path, 1024).unwrap();

        // Insert in reverse order
        for i in (0..100u64).rev() {
            store.insert(&make_entry(i)).unwrap();
        }

        let sorted = store.drain_sorted().unwrap();
        assert_eq!(sorted.len(), 100);

        // Verify sorted by hash
        for i in 1..sorted.len() {
            assert!(sorted[i - 1].hash <= sorted[i].hash);
        }
    }

    #[test]
    fn test_store_crash_recovery() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        // Create, insert, drop (simulate crash)
        {
            let mut store = IndexStore::create(&db_path, 1024).unwrap();
            for i in 0..100u64 {
                store.insert(&make_entry(i)).unwrap();
            }
            // Drop without explicit cleanup — Redb auto-commits
        }

        // Reopen and verify
        let store = IndexStore::open_readonly(&db_path).unwrap();
        assert_eq!(store.entry_count(), 100);
        let entries = store.drain_sorted().unwrap();
        assert_eq!(entries.len(), 100);
    }

    #[test]
    fn test_store_destroy() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");

        let store = IndexStore::create(&db_path, 1024).unwrap();
        assert!(db_path.exists());

        store.destroy().unwrap();
        assert!(!db_path.exists());
    }

    #[test]
    fn test_store_dedup_last_write_wins() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let mut store = IndexStore::create(&db_path, 1024).unwrap();

        // Insert same hash twice with different offsets
        let entry1 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 1024);
        let entry2 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 4096, 2048);

        store.insert(&entry1).unwrap();
        store.insert(&entry2).unwrap();

        // Last write wins in Redb
        let result = store.get(&test_hash(1)).unwrap().unwrap();
        assert_eq!(result.offset, 4096);
        assert_eq!(result.length, 2048);

        // drain_sorted should have exactly 1 entry (deduped by key)
        let sorted = store.drain_sorted().unwrap();
        assert_eq!(sorted.len(), 1);
    }
}
