//! # IndexStore — Redb-backed ACID Chunk Index
//!
//! Wraps a Redb 2.1 database for ACID-compliant chunk indexing during
//! archive creation. Uses a single embedded Redb B-tree database.
//! with a single embedded B-tree database.
//!
//! ## Lifecycle
//!
//! - **Staging**: Created via `IndexStore::create()` during ingest.
//!   Entries are inserted via `insert()`. Redb provides ACID guarantees.
//! - **Finalization**: `read_sorted()` returns all entries in hash order
//!   for writing as encrypted IndexPage blocks to the volume.
//! - **Cleanup**: `destroy()` removes the temp Redb file.

use std::path::{Path, PathBuf};

use bloomfilter::Bloom;
use redb::{Database, ReadableTable, ReadableTableMetadata};
use rkyv::Deserialize;

use era_common::{ChunkHash, EraError, Result};

use crate::schema::TABLE_CHUNKS;
use crate::IndexEntry;

/// Bloom filter false positive rate (1%)
const BLOOM_FP_RATE: f64 = 0.01;

/// Maximum number of entries allowed in sorted operations to prevent OOM (V7-F6)
pub const MAX_SORTED_ENTRIES: usize = 2_000_000;

/// Deserialize an IndexEntry using a caller-provided aligned buffer.
///
/// Reuses `buf` across calls to avoid per-entry heap allocation in loops.
/// The buffer is cleared and refilled on each call, so alignment is maintained.
fn deserialize_entry_with_buf(bytes: &[u8], buf: &mut rkyv::AlignedVec) -> Result<IndexEntry> {
    buf.clear();
    buf.extend_from_slice(bytes);
    let archived = rkyv::check_archived_root::<IndexEntry>(buf)
        .map_err(|e| EraError::Deserialization(e.to_string()))?;
    Ok(match archived.deserialize(&mut rkyv::Infallible) {
        Ok(val) => val,
        Err(never) => match never {},
    })
}

/// Deserialize an IndexEntry from potentially unaligned bytes.
///
/// Convenience wrapper over [`deserialize_entry_with_buf`] for single-call
/// sites (e.g. `get()`). For hot loops, prefer the buffered variant directly.
fn deserialize_entry_aligned(bytes: &[u8]) -> Result<IndexEntry> {
    let mut buf = rkyv::AlignedVec::with_capacity(bytes.len());
    deserialize_entry_with_buf(bytes, &mut buf)
}

/// IndexStore wraps a Redb database for ACID-compliant chunk indexing.
pub struct IndexStore {
    /// Redb database handle
    db: Database,
    /// Path to the Redb file (for cleanup)
    db_path: PathBuf,
    /// In-memory Bloom filter (survives across transactions)
    bloom: Bloom<ChunkHash>,
    /// Current bloom filter capacity (number of items it was sized for)
    bloom_capacity: usize,
    /// Total entries inserted
    entry_count: usize,
    /// Whether to keep the file on drop (prevents deletion for read-only stores or explicit keep)
    should_keep_on_drop: bool,
    /// Whether this store was opened in read-only mode
    read_only: bool,
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
            bloom_capacity: items,
            entry_count: 0,
            should_keep_on_drop: false,
            read_only: false,
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
            .map_err(|e: redb::StorageError| EraError::IndexError(e.to_string()))?
            as usize;

        if len > 1_000_000 {
            tracing::warn!(
                "open_readonly: rebuilding bloom filter for {} entries — this may be slow",
                len
            );
        }

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
            bloom_capacity: len,
            entry_count: len,
            should_keep_on_drop: true,
            read_only: true,
        })
    }

    /// Insert a single chunk entry (one write transaction per call).
    ///
    /// Uses first-write-wins semantics: if the hash already exists, the
    /// existing entry is preserved and the new one is silently dropped.
    pub fn insert(&mut self, entry: &IndexEntry) -> Result<()> {
        if self.read_only {
            return Err(EraError::IndexError(
                "Cannot insert into a read-only IndexStore".into(),
            ));
        }
        // SAFETY: Bloom filter is updated BEFORE the Redb commit.
        // This creates a <1ms window where bloom.check() returns true but store.get() returns None.
        // This is SAFE for dedup: false positive = redundant storage, not data loss.
        // A false negative (bloom says no when entry exists) would cause data loss,
        // but cannot happen here because bloom entries are only added, never removed.
        // Reference: V7-F11 / V6-F9 — bloom-before-commit is intentional and correct.
        self.bloom.set(&entry.hash);

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TABLE_CHUNKS)
                .map_err(|e| EraError::IndexError(e.to_string()))?;
            let is_new = table
                .get(entry.hash.as_bytes())
                .map_err(|e| EraError::IndexError(e.to_string()))?
                .is_none();
            if is_new {
                let value_bytes = rkyv::to_bytes::<_, 256>(entry)
                    .map_err(|e| EraError::Serialization(e.to_string()))?;
                table
                    .insert(entry.hash.as_bytes(), value_bytes.as_slice())
                    .map_err(|e| EraError::IndexError(e.to_string()))?;
                self.entry_count += 1;
            }
        }
        write_txn
            .commit()
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        self.rebuild_bloom_if_needed()?;

        Ok(())
    }

    /// Batch insert entries in a single transaction (much faster for bulk loads).
    ///
    /// Uses first-write-wins semantics: existing entries are preserved.
    pub fn insert_batch(&mut self, entries: &[IndexEntry]) -> Result<()> {
        if self.read_only {
            return Err(EraError::IndexError(
                "Cannot insert into a read-only IndexStore".into(),
            ));
        }
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
            let mut new_count = 0usize;
            for entry in entries {
                // SAFETY: See bloom-before-commit invariant in insert().
                self.bloom.set(&entry.hash);
                let is_new = table
                    .get(entry.hash.as_bytes())
                    .map_err(|e| EraError::IndexError(e.to_string()))?
                    .is_none();
                if is_new {
                    let value_bytes = rkyv::to_bytes::<_, 256>(entry)
                        .map_err(|e| EraError::Serialization(e.to_string()))?;
                    table
                        .insert(entry.hash.as_bytes(), value_bytes.as_slice())
                        .map_err(|e| EraError::IndexError(e.to_string()))?;
                    new_count += 1;
                }
            }
            self.entry_count += new_count;
        }
        write_txn
            .commit()
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        // Resize bloom if overcapacity
        self.rebuild_bloom_if_needed()?;

        Ok(())
    }

    /// Rebuild the bloom filter at a larger capacity if entry count exceeds 1.5× the current capacity.
    ///
    /// New capacity is set to 4× the current entry count to avoid frequent rebuilds.
    fn rebuild_bloom_if_needed(&mut self) -> Result<()> {
        if self.entry_count <= self.bloom_capacity * 3 / 2 {
            return Ok(());
        }

        let new_capacity = self.entry_count * 4;
        let mut new_bloom = Bloom::new_for_fp_rate(new_capacity.max(1024), BLOOM_FP_RATE);

        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let table = read_txn
            .open_table(TABLE_CHUNKS)
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        for result in table
            .iter()
            .map_err(|e| EraError::IndexError(e.to_string()))?
        {
            let (key, _) = result.map_err(|e| EraError::IndexError(e.to_string()))?;
            let hash = ChunkHash::from_bytes(*key.value());
            new_bloom.set(&hash);
        }

        self.bloom = new_bloom;
        self.bloom_capacity = new_capacity;
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

    /// Eagerly set a hash in the bloom filter (for buffered insert paths).
    #[inline]
    pub fn bloom_set(&mut self, hash: &ChunkHash) {
        self.bloom.set(hash);
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
    pub fn read_sorted(&self) -> Result<Vec<IndexEntry>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let table = read_txn
            .open_table(TABLE_CHUNKS)
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        // Guard against malicious/oversized indexes (V7-F6)
        if self.entry_count > MAX_SORTED_ENTRIES {
            return Err(EraError::IndexError(format!(
                "read_sorted: entry count {} exceeds maximum {} (V7-F6)",
                self.entry_count, MAX_SORTED_ENTRIES
            )));
        }

        let mut entries = Vec::with_capacity(self.entry_count);
        let mut align_buf = rkyv::AlignedVec::with_capacity(256);
        for result in table
            .iter()
            .map_err(|e| EraError::IndexError(e.to_string()))?
        {
            let (_, value) = result.map_err(|e| EraError::IndexError(e.to_string()))?;
            let bytes = value.value();
            let entry = deserialize_entry_with_buf(bytes, &mut align_buf)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Drain entries in sorted order, chunked into IndexPages of ENTRIES_PER_PAGE.
    ///
    /// Returns all pages in sorted order, paired with their sequential BlockIds.
    /// Note: all pages are collected into a Vec before returning.
    ///
    /// For production callers that process pages one at a time, prefer
    /// [`for_each_sorted_page`] which uses O(ENTRIES_PER_PAGE) memory per invocation.
    pub fn read_sorted_pages(&self) -> Result<Vec<(crate::IndexPage, era_common::BlockId)>> {
        let entries_per_page = crate::ENTRIES_PER_PAGE;
        let estimated_pages = (self.entry_count + entries_per_page - 1) / entries_per_page.max(1);
        let mut pages = Vec::with_capacity(estimated_pages);
        self.for_each_sorted_page(|page, block_id| {
            pages.push((page, block_id));
            Ok(())
        })?;
        Ok(pages)
    }

    /// Process sorted pages one at a time via callback. Memory usage O(ENTRIES_PER_PAGE).
    ///
    /// Same logic as `read_sorted_pages`, but instead of collecting all pages into a Vec,
    /// each completed page is passed to `callback` and can be dropped before the next is built.
    /// Sorted ordering is preserved (Redb B-tree iteration is already sorted).
    pub fn for_each_sorted_page<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(crate::IndexPage, era_common::BlockId) -> Result<()>,
    {
        use era_common::BlockId;

        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let table = read_txn
            .open_table(TABLE_CHUNKS)
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        let entries_per_page = crate::ENTRIES_PER_PAGE;
        // Guard against malicious/oversized indexes (V7-F6)
        if self.entry_count > MAX_SORTED_ENTRIES {
            return Err(EraError::IndexError(format!(
                "for_each_sorted_page: entry count {} exceeds maximum {} (V7-F6)",
                self.entry_count, MAX_SORTED_ENTRIES
            )));
        }

        let mut chunk = Vec::with_capacity(entries_per_page);
        let mut block_id_counter = 0u64;
        let mut align_buf = rkyv::AlignedVec::with_capacity(256);
        for result in table
            .iter()
            .map_err(|e| EraError::IndexError(e.to_string()))?
        {
            let (_, value) = result.map_err(|e| EraError::IndexError(e.to_string()))?;
            let bytes = value.value();
            let entry = deserialize_entry_with_buf(bytes, &mut align_buf)?;
            chunk.push(entry);

            if chunk.len() >= entries_per_page {
                let page = crate::IndexPage::try_new(std::mem::replace(
                    &mut chunk,
                    Vec::with_capacity(entries_per_page),
                ))?;
                callback(page, BlockId::new(block_id_counter))?;
                block_id_counter += 1;
            }
        }

        // Flush remaining entries
        if !chunk.is_empty() {
            let page = crate::IndexPage::try_new(chunk)?;
            callback(page, BlockId::new(block_id_counter))?;
        }

        Ok(())
    }

    /// Destroy the staging database file.
    ///
    /// Consuming `self` triggers `Drop`, which handles file removal.
    pub fn destroy(self) -> Result<()> {
        // Drop impl handles file cleanup
        Ok(())
    }

    /// Get the database path.
    pub fn path(&self) -> &Path {
        &self.db_path
    }

    /// Prevent the staging file from being removed on drop.
    ///
    /// Used for crash recovery scenarios where the file must persist
    /// beyond the lifetime of this store instance.
    pub fn keep_on_drop(&mut self) {
        self.should_keep_on_drop = true;
    }

    /// Discard the staging database: remove the file while still holding the DB lock.
    ///
    /// This eliminates the TOCTOU window in Drop where another process could
    /// open the file between DB handle release and file removal (V6-F10 fix).
    /// On Unix, remove_file on an open fd unlinks the directory entry immediately;
    /// the file data persists until the last fd is closed.
    pub fn discard(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        if let Err(e) = std::fs::remove_file(&self.db_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(EraError::Io(e));
            }
        }
        self.should_keep_on_drop = true;
        Ok(())
    }
}

impl Drop for IndexStore {
    fn drop(&mut self) {
        // Clean up staging Redb file to prevent /tmp leakage.
        // Read-only stores (opened via open_readonly for crash recovery)
        // don't own the file lifecycle.
        if !self.should_keep_on_drop {
            if let Err(e) = std::fs::remove_file(&self.db_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to remove staging file {:?}: {}", self.db_path, e);
                }
            }
        }
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
    fn test_store_read_sorted() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let mut store = IndexStore::create(&db_path, 1024).unwrap();

        // Insert in reverse order
        for i in (0..100u64).rev() {
            store.insert(&make_entry(i)).unwrap();
        }

        let sorted = store.read_sorted().unwrap();
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

        // Create, insert, drop without cleanup (simulate crash)
        {
            let mut store = IndexStore::create(&db_path, 1024).unwrap();
            for i in 0..100u64 {
                store.insert(&make_entry(i)).unwrap();
            }
            // Mark keep_on_drop so Drop releases the DB lock but skips file deletion,
            // simulating a crash where the staging file persists on disk.
            store.keep_on_drop();
        }

        // Reopen and verify
        let store = IndexStore::open_readonly(&db_path).unwrap();
        assert_eq!(store.entry_count(), 100);
        let entries = store.read_sorted().unwrap();
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
    fn test_store_dedup_first_write_wins() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.redb");
        let mut store = IndexStore::create(&db_path, 1024).unwrap();

        // Insert same hash twice with different offsets
        let entry1 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 1024);
        let entry2 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 4096, 2048);

        store.insert(&entry1).unwrap();
        store.insert(&entry2).unwrap();

        // First write wins — entry1's values are preserved
        let result = store.get(&test_hash(1)).unwrap().unwrap();
        assert_eq!(result.offset, 0);
        assert_eq!(result.length, 1024);

        // read_sorted should have exactly 1 entry (deduped by key)
        let sorted = store.read_sorted().unwrap();
        assert_eq!(sorted.len(), 1);
    }
}
