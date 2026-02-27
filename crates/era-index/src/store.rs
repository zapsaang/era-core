//! # IndexStore — Redb-backed ACID Chunk Index
//!
//! Wraps a Redb 2.1 database for ACID-compliant chunk indexing during
//! archive creation. Uses a single embedded Redb B-tree database.
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

/// Maximum number of entries allowed in open_readonly to prevent DoS (V13-F10)
const MAX_READONLY_ENTRIES: usize = 100_000_000;

/// Deserialize an IndexEntry using a caller-provided aligned buffer.
///
/// Reuses `buf` across calls to avoid per-entry heap allocation in loops.
/// The buffer is cleared and refilled on each call, so alignment is maintained.
fn deserialize_entry_with_buf(bytes: &[u8], buf: &mut rkyv::AlignedVec) -> Result<IndexEntry> {
    // V24-F10: size limit (4x ~80B)
    if bytes.len() > std::mem::size_of::<IndexEntry>() * 4 {
        return Err(EraError::Deserialization("oversized".to_string()));
    }
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
    /// Total entries inserted
    entry_count: usize,
    /// Number of entries the bloom filter was sized for (for rebuild threshold)
    bloom_sized_for: usize,
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
            entry_count: 0,
            bloom_sized_for: items,
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

        // V13-F10 fix: hard limit to prevent DoS via crafted staging files
        if len > MAX_READONLY_ENTRIES {
            return Err(EraError::IndexError(format!(
                "open_readonly: {} entries exceeds maximum {} (V13-F10)",
                len, MAX_READONLY_ENTRIES
            )));
        }

        if len > 1_000_000 {
            tracing::warn!(
                "open_readonly: rebuilding bloom filter for {} entries — this may be slow",
                len
            );
        }
        // Iterate keys only — we only need the hash bytes for the bloom filter.
        // Value deserialization is intentionally skipped because we only need
        // ChunkHash keys for bloom membership; full IndexEntry values are not used.
        // V18-F8 fix: Cap bloom sizing to prevent excessive memory allocation.
        // Even within MAX_READONLY_ENTRIES, sizing a bloom filter for 100M entries
        // at 1% FPR would allocate ~114MB. Cap at 10M entries (~11.4MB).
        const MAX_READONLY_BLOOM_ENTRIES: usize = 10_000_000;
        let bloom_size = len.clamp(1024, MAX_READONLY_BLOOM_ENTRIES);
        if len > MAX_READONLY_BLOOM_ENTRIES {
            tracing::warn!(
                "open_readonly: capping bloom filter size from {} to {} entries (V18-F8)",
                len,
                MAX_READONLY_BLOOM_ENTRIES
            );
        }
        let mut bloom = Bloom::new_for_fp_rate(bloom_size, BLOOM_FP_RATE);
        for (idx, result) in table
            .iter()
            .map_err(|e| EraError::IndexError(e.to_string()))?
            .enumerate()
        {
            let (key, _) = result.map_err(|e| EraError::IndexError(e.to_string()))?;
            let hash = ChunkHash::from_bytes(*key.value());
            bloom.set(&hash);
            // V20-F11 fix: Periodic progress logging for large bloom rebuilds.
            if idx % 100_000 == 0 && idx > 0 {
                tracing::debug!(
                    "open_readonly: bloom rebuild progress — {} entries processed",
                    idx
                );
            }
        }

        Ok(Self {
            db,
            db_path: path.to_path_buf(),
            bloom,
            entry_count: len,
            bloom_sized_for: len.max(1024),
            should_keep_on_drop: true,
            read_only: true,
        })
    }

    /// Insert a single chunk entry (one write transaction per call).
    ///
    /// **Performance note (V14-F10):** Opens a new write transaction per call.
    /// For bulk inserts, prefer `insert_batch()` which amortizes transaction overhead.
    /// Uses first-write-wins semantics: if the hash already exists, the
    /// existing entry is preserved and the new one is silently dropped.
    pub fn insert(&mut self, entry: &IndexEntry) -> Result<()> {
        if self.read_only {
            return Err(EraError::IndexError(
                "Cannot insert into a read-only IndexStore".into(),
            ));
        }

        // V21-F1 fix: Inline the read_txn logic directly instead of calling get(),
        // which would redundantly check the bloom filter a second time (bloom.check
        // is already performed above). This avoids the double bloom check overhead.
        // V20-F3 fix: Early-return duplicate check before opening write transaction.
        if self.bloom.check(&entry.hash) {
            let read_txn = self
                .db
                .begin_read()
                .map_err(|e| EraError::IndexError(e.to_string()))?;
            let table = read_txn
                .open_table(TABLE_CHUNKS)
                .map_err(|e| EraError::IndexError(e.to_string()))?;
            if table
                .get(entry.hash.as_bytes())
                .map_err(|e| EraError::IndexError(e.to_string()))?
                .is_some()
            {
                return Ok(());
            }
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let is_new;
        {
            let mut table = write_txn
                .open_table(TABLE_CHUNKS)
                .map_err(|e| EraError::IndexError(e.to_string()))?;
            is_new = table
                .get(entry.hash.as_bytes())
                .map_err(|e| EraError::IndexError(e.to_string()))?
                .is_none();
            if is_new {
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

        // V14-F7 fix: increment entry_count AFTER successful commit to prevent drift
        if is_new {
            self.entry_count += 1;
        }

        // V13-F4 fix: set bloom AFTER successful commit to avoid phantom entries
        // on commit failure. False positive in bloom only causes redundant storage
        // (not data loss), and bloom entries are only added, never removed.
        self.bloom.set(&entry.hash);
        // SAFETY (V11-F8 / V13-F4): bloom-before-commit is intentional and correct
        // was the prior invariant; V13-F4 moved bloom.set AFTER commit to avoid phantom
        // entries on commit failure. Bloom FP is harmless; false negatives remain impossible.
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

        // V21-F9 fix: Filter out bloom-confirmed duplicates before opening the
        // write transaction. For batches with many duplicates, this avoids
        // wasting write transaction overhead on entries already in the store.
        // V22-F1 fix: Use a single read transaction for all bloom-confirmed candidates
        // instead of opening a separate read_txn per candidate. This reduces Redb
        // transaction overhead from O(bloom_hits) to O(1) for duplicate checking.
        let candidates: Vec<&IndexEntry> = if self.entry_count > 0 {
            let mut filtered = Vec::with_capacity(entries.len());
            let bloom_hits: Vec<&IndexEntry> = entries
                .iter()
                .filter(|e| self.bloom.check(&e.hash))
                .collect();
            if !bloom_hits.is_empty() {
                let read_txn = self
                    .db
                    .begin_read()
                    .map_err(|e| EraError::IndexError(e.to_string()))?;
                let table = read_txn
                    .open_table(TABLE_CHUNKS)
                    .map_err(|e| EraError::IndexError(e.to_string()))?;
                for entry in bloom_hits {
                    if table
                        .get(entry.hash.as_bytes())
                        .map_err(|e| EraError::IndexError(e.to_string()))?
                        .is_none()
                    {
                        filtered.push(entry);
                    }
                }
            }
            // Entries not in bloom are definitely new — add them directly
            for entry in entries {
                if !self.bloom.check(&entry.hash) {
                    filtered.push(entry);
                }
            }
            filtered
        } else {
            entries.iter().collect()
        };
        if candidates.is_empty() {
            return Ok(());
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| EraError::IndexError(e.to_string()))?;
        let mut new_count = 0usize;
        {
            let mut table = write_txn
                .open_table(TABLE_CHUNKS)
                .map_err(|e| EraError::IndexError(e.to_string()))?;
            for entry in &candidates {
                let is_new = table
                    .get(entry.hash.as_bytes())
                    .map_err(|e| EraError::IndexError(e.to_string()))?
                    .is_none();
                if is_new {
                    let value_bytes = rkyv::to_bytes::<_, 256>(*entry)
                        .map_err(|e| EraError::Serialization(e.to_string()))?;
                    table
                        .insert(entry.hash.as_bytes(), value_bytes.as_slice())
                        .map_err(|e| EraError::IndexError(e.to_string()))?;
                    new_count += 1;
                }
            }
        }
        write_txn
            .commit()
            .map_err(|e| EraError::IndexError(e.to_string()))?;

        // V14-F7 fix: increment entry_count AFTER successful commit to prevent drift
        self.entry_count += new_count;

        // V13-F4 fix: set bloom bits AFTER successful commit to avoid phantom entries.
        // We set ALL entries (including duplicates that already exist in the DB) to ensure
        // the bloom filter reflects all entries present in the store.
        for entry in entries {
            self.bloom.set(&entry.hash);
        }
        self.rebuild_bloom_if_needed()?;
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
    #[must_use]
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        self.bloom.check(hash)
    }

    /// Eagerly set a hash in the bloom filter (for buffered insert paths).
    #[inline]
    /// V19-F11: Renamed from `bloom_set` to make the unchecked nature explicit.
    /// This method sets a bit in the bloom filter without verifying that the
    /// corresponding entry has been committed to the Redb store.
    pub(crate) fn bloom_set_unchecked(&mut self, hash: &ChunkHash) {
        self.bloom.set(hash);
    }

    /// Get reference to bloom filter.
    #[must_use]
    pub fn bloom(&self) -> &Bloom<ChunkHash> {
        &self.bloom
    }

    /// Get entry count.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Rebuild the bloom filter when entry count exceeds 2× the size it was built for.
    ///
    /// V13-F6: This performs a full table scan and is O(n) in the number of stored entries.
    /// Called from both `insert()` and `insert_batch()` to maintain bloom FPR guarantees.
    fn rebuild_bloom_if_needed(&mut self) -> Result<()> {
        if self.entry_count <= self.bloom_sized_for * 2 {
            return Ok(());
        }
        // V21-F5 fix: Log when bloom rebuild triggers for observability.
        // This can be a silent performance cliff for callers.
        let old_capacity = self.bloom_sized_for;
        // V19-F8 fix: Cap new_capacity at MAX_BLOOM_ITEMS to prevent unbounded
        // memory allocation. Without this cap, a store with 50M entries would
        // try to allocate a bloom filter sized for 100M entries (~120MB).
        const MAX_BLOOM_ITEMS: usize = 100_000_000;
        let new_capacity = (self.entry_count * 2).min(MAX_BLOOM_ITEMS);
        tracing::info!(
            "rebuild_bloom_if_needed: rebuilding bloom filter (old_capacity={}, new_capacity={}, entry_count={})",
            old_capacity,
            new_capacity,
            self.entry_count
        );
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
        self.bloom_sized_for = new_capacity;
        Ok(())
    }
    /// Drain all entries in sorted hash order for finalization.
    ///
    /// Redb's B-tree stores keys in sorted order, so iteration
    /// yields entries sorted by ChunkHash bytes — exactly what
    /// the finalization pipeline needs.
    pub fn read_sorted(&self) -> Result<Vec<IndexEntry>> {
        // V20-F4 fix: Delegate to for_each_sorted_page() to avoid duplicating
        // the iteration logic. Collects entries via extend_from_slice(page.entries()).
        let mut entries = Vec::new();
        self.for_each_sorted_page(|page, _block_id| {
            entries.extend_from_slice(page.entries());
            Ok(())
        })?;
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
    ///
    /// V22-F6 fix: Added periodic progress logging for large iterations.
    /// Without this, callers had no visibility into long-running page scans.
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
        // V13-F11 fix: use Redb table.len() as ground truth for the guard check
        let table_len = table
            .len()
            .map_err(|e: redb::StorageError| EraError::IndexError(e.to_string()))?
            as usize;
        if table_len > MAX_SORTED_ENTRIES {
            return Err(EraError::IndexError(format!(
                "for_each_sorted_page: entry count {} exceeds maximum {} (V7-F6)",
                table_len, MAX_SORTED_ENTRIES
            )));
        }

        let mut chunk = Vec::with_capacity(entries_per_page);
        let mut block_id_counter = 0u64;
        // V21-F12 fix: Initialize align_buf with a capacity based on actual IndexEntry
        // memory size to reduce reallocations. 256 bytes was often too small.
        let mut align_buf = rkyv::AlignedVec::with_capacity(IndexEntry::memory_size() * 2);
        for result in table
            .iter()
            .map_err(|e| EraError::IndexError(e.to_string()))?
        {
            let (_, value) = result.map_err(|e| EraError::IndexError(e.to_string()))?;
            let bytes = value.value();
            let entry = deserialize_entry_with_buf(bytes, &mut align_buf)?;
            chunk.push(entry);

            if chunk.len() >= entries_per_page {
                // V17-F2 fix: use try_new_presorted since Redb B-tree yields sorted keys
                let page = crate::IndexPage::try_new_presorted(std::mem::take(&mut chunk))?;
                chunk = Vec::with_capacity(entries_per_page);
                callback(page, BlockId::new(block_id_counter))?;
                block_id_counter += 1;
                // V23-F8 fix: Progress logging moved AFTER page callback emission.
                // Previously, this check was inside the inner entry loop and fired on
                // every entry after a page boundary, not once per 100 pages.
                if block_id_counter > 0 && block_id_counter.is_multiple_of(100) {
                    tracing::debug!(
                        "for_each_sorted_page: processed {} pages so far",
                        block_id_counter
                    );
                }
            }
        }

        // Flush remaining entries
        if !chunk.is_empty() {
            let page = crate::IndexPage::try_new_presorted(chunk)?;
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
    #[must_use]
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

    /// V22-F10 fix: Get the on-disk size of the Redb database file in bytes.
    ///
    /// Returns `None` if the file does not exist or metadata cannot be read.
    /// Useful for monitoring staging database growth and diagnosing disk usage.
    #[must_use]
    pub fn db_file_size(&self) -> Option<u64> {
        std::fs::metadata(&self.db_path).ok().map(|m| m.len())
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
        .expect("valid entry")
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
        let entry1 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 0, 1024)
            .expect("valid entry");
        let entry2 = IndexEntry::new(test_hash(1), VolumeId::new(), BlockId::new(0), 4096, 2048)
            .expect("valid entry");

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
