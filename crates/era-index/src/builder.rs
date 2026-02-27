//! # IndexBuilder — Redb-backed Index Construction
//!
//! Manages index construction with ACID guarantees via Redb.
//! Entries are inserted into a staging Redb database during archive creation.
//! At finalization, entries are read in sorted order and written as encrypted
//! IndexPage blocks to the volume.

use bloomfilter::Bloom;

use era_common::{BlockType, ChunkHash, EncryptedMacroBlock, EraError, Result};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageWriter;

use crate::store::IndexStore;
use crate::IndexEntry;

/// Default memory limit (64MB) — used for bloom filter sizing
const DEFAULT_MEM_LIMIT: usize = 64 * 1024 * 1024;

/// Maximum bloom filter items to prevent excessive memory allocation (V12-F4 fix)
const MAX_BLOOM_ITEMS: usize = 100_000_000;
/// Compute bloom filter expected items from memory limit.
///
/// Returns the estimated number of unique index entries that will fit within
/// `mem_limit` bytes, clamped to `[1024, MAX_BLOOM_ITEMS]`. This value is
/// used to size the Bloom filter for the target false-positive rate.
///
/// V17-F12 fix: When `mem_limit` is very small (< entry_size), the division
/// yields 0 which clamps to 128. This is technically correct but the Bloom
/// filter will be undersized for any real workload. We use `max(1024, ...)`
/// as the lower bound to ensure a minimally useful Bloom filter even for
/// tiny memory limits.
fn bloom_expected_items(mem_limit: usize) -> usize {
    let entry_size = std::mem::size_of::<IndexEntry>().max(1);
    (mem_limit / entry_size).clamp(1024, MAX_BLOOM_ITEMS)
}

/// Default number of entries to buffer before flushing to Redb in a single batch transaction
const DEFAULT_BATCH_SIZE: usize = 1000;

/// IndexBuilder manages index construction with Redb-backed ACID storage.
///
/// During archive creation, entries are buffered in memory and flushed to the
/// staging Redb database in batches of 1000 for optimal write performance.
/// At finalization, all entries are read in sorted order (Redb B-tree guarantees
/// this) and written as encrypted IndexPage/IndexManifest blocks to the volume.
pub struct IndexBuilder {
    /// Redb-backed index store
    store: IndexStore,
    /// In-memory buffer for batch writes
    buffer: Vec<IndexEntry>,
    /// V21-F8 fix: Configurable batch size for Redb flush threshold.
    /// Defaults to DEFAULT_BATCH_SIZE (1000). Callers can override via
    /// `with_batch_size()` for workloads that benefit from larger/smaller batches.
    batch_size: usize,
}

impl IndexBuilder {
    /// Create a new IndexBuilder with specified memory limit.
    ///
    /// Creates a temporary Redb file for staging entries.
    /// Returns an error if temp file creation or database initialization fails.
    pub fn new(mem_limit: usize) -> Result<Self> {
        let temp_file = tempfile::Builder::new()
            .prefix("era-staging-")
            .suffix(".redb")
            .tempfile()
            .map_err(EraError::Io)?;
        let (_, temp_path) = temp_file.keep().map_err(|e| EraError::Io(e.error))?;
        let store = IndexStore::create(&temp_path, bloom_expected_items(mem_limit))?;
        Ok(Self {
            store,
            buffer: Vec::with_capacity(DEFAULT_BATCH_SIZE),
            batch_size: DEFAULT_BATCH_SIZE,
        })
    }

    /// Create a new IndexBuilder with a specific path for the Redb file.
    pub fn with_path(path: &std::path::Path, mem_limit: usize) -> Result<Self> {
        let store = IndexStore::create(path, bloom_expected_items(mem_limit))?;
        Ok(Self {
            store,
            buffer: Vec::with_capacity(DEFAULT_BATCH_SIZE),
            batch_size: DEFAULT_BATCH_SIZE,
        })
    }

    /// Create with default memory limit (64MB)
    pub fn new_default() -> Result<Self> {
        Self::new(DEFAULT_MEM_LIMIT)
    }

    /// V21-F8 fix: Set a custom batch size for Redb flush threshold.
    ///
    /// The batch size controls how many entries are buffered in memory before
    /// flushing to the Redb staging database. Larger batches reduce transaction
    /// overhead but increase memory usage. Must be >= 1.
    ///
    /// V22-F12 fix: Log a warning when batch_size=0 is silently clamped to 1.
    /// Previously, `batch_size.max(1)` silently transformed 0 into 1, which could
    /// confuse callers expecting exact control over batch behavior.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        if batch_size == 0 {
            tracing::warn!("with_batch_size(0) is invalid — clamping to 1. Use batch_size >= 1.");
        }
        let size = batch_size.max(1);
        self.batch_size = size;
        self.buffer = Vec::with_capacity(size);
        self
    }

    /// Insert an entry into the index.
    ///
    /// Entries are buffered in memory and flushed to the Redb staging database
    /// in batches of 1000 for optimal write performance.
    pub fn insert(&mut self, entry: IndexEntry) -> Result<()> {
        // NOTE (V6-F9 / V15-F4): bloom_set is called BEFORE flush_buffer, unlike
        // store.insert() which sets bloom AFTER commit (V13-F4). This is intentional —
        // the builder's bloom must reflect buffered entries for early dedup detection.
        // Phantom entries on flush failure are harmless: they only cause redundant lookups.
        // Push to buffer first, then update bloom — ensures bloom never
        // contains entries that aren't at least in the buffer (V6-F9 fix)
        let hash = entry.hash;
        self.buffer.push(entry);
        self.store.bloom_set_unchecked(&hash);
        if self.buffer.len() >= self.batch_size {
            self.flush_buffer()?;
        }
        Ok(())
    }

    /// Flush the in-memory buffer to the Redb staging database.
    fn flush_buffer(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            self.store.insert_batch(&self.buffer)?;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Get total number of unique entries in the index.
    ///
    /// Flushes any buffered entries to the Redb store first so that
    /// first-write-wins deduplication produces an exact unique count.
    /// After flush, `store.entry_count()` is O(1).
    ///
    /// **Takes `&mut self`** because it calls `flush_buffer()` to ensure
    /// the count reflects all buffered entries after deduplication.
    pub fn entry_count(&mut self) -> usize {
        // Flush buffer so Redb deduplicates via first-write-wins,
        // then return the store's O(1) counter.
        if let Err(e) = self.flush_buffer() {
            tracing::error!("entry_count: flush_buffer failed: {}", e);
            // V13-F1: return store count (safe minimum) on flush failure
            return self.store.entry_count();
        }
        self.store.entry_count()
    }

    /// Check if a hash exists in the Bloom filter
    #[must_use]
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        self.store.bloom_contains(hash)
    }

    /// Get reference to the bloom filter
    #[must_use]
    pub fn bloom(&self) -> &Bloom<ChunkHash> {
        self.store.bloom()
    }

    /// Get reference to the underlying IndexStore
    pub fn store(&self) -> &IndexStore {
        &self.store
    }

    /// Flush any buffered entries and drain all entries in sorted order.
    pub fn read_sorted(&mut self) -> Result<Vec<IndexEntry>> {
        self.flush_buffer()?;
        self.store.read_sorted()
    }

    /// Flush any buffered entries and drain as pre-built pages (streaming, low-memory).
    pub fn read_sorted_pages(&mut self) -> Result<Vec<(crate::IndexPage, era_common::BlockId)>> {
        self.flush_buffer()?;
        self.store.read_sorted_pages()
    }

    /// Flush any buffered entries and process sorted pages one at a time via callback.
    ///
    /// Memory usage is O(ENTRIES_PER_PAGE) per callback invocation, avoiding
    /// the O(all_entries) allocation of `read_sorted_pages()`.
    pub fn for_each_sorted_page<F>(&mut self, callback: F) -> Result<()>
    where
        F: FnMut(crate::IndexPage, era_common::BlockId) -> Result<()>,
    {
        self.flush_buffer()?;
        self.store.for_each_sorted_page(callback)
    }

    /// Finalize the index (EMBEDDED MODE — writes to volume)
    ///
    /// Reads all entries from the Redb staging database as pre-built pages
    /// (streaming, low-memory), then writes encrypted IndexPage blocks and
    /// an IndexManifest block to the volume. Returns the MetaIndex and its
    /// BlockLocation.
    pub async fn finalize<W: StorageWriter>(
        &mut self,
        volume_writer: &mut era_volume::VolumeWriter<W>,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: [u8; 16],
    ) -> Result<(super::MetaIndex, era_common::BlockLocation)> {
        use era_common::BlockId;

        // V19-F7: Note on spawn_blocking for finalize().
        // The CPU-heavy work (rkyv serialization + AEAD encryption per page) runs
        // synchronously inside `for_each_sorted_page`. Ideally this would use
        // `spawn_blocking` to avoid stalling the async runtime. However:
        //   1. The Redb `ReadTransaction` is !Send (tied to the thread that created it),
        //      so it cannot be moved into a spawn_blocking closure.
        //   2. The volume_writer requires &mut and is also !Send in some backends.
        // Deferring to a future refactor that separates the Redb read phase (sync,
        // collect pages into memory) from the encrypt+write phase (can be async).
        // Risk is low: finalize() runs once per archive, not per-block.

        // Flush any remaining buffered entries, then stream pages from Redb.
        // Uses for_each_sorted_page to process one page at a time: each page is
        // serialized + encrypted inside the callback, so raw IndexEntry memory
        // is O(ENTRIES_PER_PAGE) rather than O(all_entries).
        // The encrypted blocks (much smaller) are collected for async volume writes.
        self.flush_buffer()?;

        // Build L1 MetaIndex
        let mut meta = super::MetaIndex::new();

        // V14-F1 fix: Multi-byte domain separation for index blocks.
        // Overwriting a single byte with XOR was weak domain separation.
        // Now we use a 4-byte domain tag that clearly distinguishes index nonces.
        let mut index_nonce_context = nonce_context;
        index_nonce_context[0..4].copy_from_slice(b"IDX\x01");

        // V22-F2 fix: Pre-allocate encrypted_blocks Vec based on estimated page count.
        // Previously Vec::new() caused repeated reallocations as pages were pushed.
        // The store's entry_count / ENTRIES_PER_PAGE gives a reasonable estimate.
        let estimated_pages = (self.store.entry_count() / crate::ENTRIES_PER_PAGE).max(1);
        let mut encrypted_blocks: Vec<(EncryptedMacroBlock, ChunkHash, ChunkHash, BlockId)> =
            Vec::with_capacity(estimated_pages);
        let mut block_id_counter = 0u64;
        {
            let idx_nonce = index_nonce_context;
            self.store.for_each_sorted_page(|page, _page_block_id| {
                // Serialize page to rkyv
                let page_bytes = rkyv::to_bytes::<_, 4096>(&page)
                    .map_err(|e| EraError::Serialization(e.to_string()))?;

                // Encrypt page with session keys
                let block_id = BlockId::new(block_id_counter);
                let block_key =
                    session.derive_block_key(volume_key, block_id.sequence(), &idx_nonce)?;
                let derived_key = block_key.to_derived_key()?;
                let encrypted_data = era_crypto::encrypt_with_context(
                    &derived_key,
                    &idx_nonce,
                    block_id,
                    &page_bytes,
                )?;

                // Create EncryptedMacroBlock
                let encrypted_block = EncryptedMacroBlock {
                    block_id,
                    data: encrypted_data,
                    original_size: u32::try_from(page_bytes.len()).map_err(|_| {
                        EraError::IndexError(format!(
                            "IndexPage size {} exceeds u32::MAX",
                            page_bytes.len()
                        ))
                    })?,
                    compressed_size: u32::try_from(page_bytes.len()).map_err(|_| {
                        EraError::IndexError(format!(
                            "IndexPage size {} exceeds u32::MAX",
                            page_bytes.len()
                        ))
                    })?,
                    // V14-F8: chunk_count here represents IndexPage entry count,
                    // not the number of data chunks. This reuses EncryptedMacroBlock's
                    // field with different semantics for index blocks vs data blocks.
                    chunk_count: u16::try_from(page.len()).map_err(|_| {
                        EraError::IndexError(format!(
                            "IndexPage entry count {} exceeds u16::MAX",
                            page.len()
                        ))
                    })?,
                };

                let min_h = *page.min_hash();
                let max_h = *page.max_hash();
                encrypted_blocks.push((encrypted_block, min_h, max_h, block_id));
                block_id_counter += 1;
                Ok(())
            })?;
        }

        // Write encrypted blocks to volume (async) and build MetaIndex
        for (encrypted_block, min_hash, max_hash, block_id) in encrypted_blocks {
            let _location = volume_writer
                .write_canonical_block(&encrypted_block, BlockType::IndexPage)
                .await?;

            // Add PagePointer to L1
            meta.add_page(min_hash, max_hash, block_id)?;
        }

        // Reuse the builder's existing bloom — it already contains all entries.
        let bloom_bytes = super::serialize_bloom(self.store.bloom())?;
        meta.set_bloom_filter(bloom_bytes)?;

        // Encrypt and write MetaIndex as IndexManifest block
        let meta_bytes =
            rkyv::to_bytes::<_, 4096>(&meta).map_err(|e| EraError::Serialization(e.to_string()))?;

        let manifest_block_id = BlockId::new(block_id_counter);
        let manifest_key = session.derive_block_key(
            volume_key,
            manifest_block_id.sequence(),
            &index_nonce_context,
        )?;
        let manifest_derived_key = manifest_key.to_derived_key()?;
        let encrypted_manifest = era_crypto::encrypt_with_context(
            &manifest_derived_key,
            &index_nonce_context,
            manifest_block_id,
            &meta_bytes,
        )?;

        let manifest_encrypted_block = EncryptedMacroBlock {
            block_id: manifest_block_id,
            data: encrypted_manifest,
            original_size: u32::try_from(meta_bytes.len()).map_err(|_| {
                EraError::IndexError(format!(
                    "MetaIndex size {} exceeds u32::MAX",
                    meta_bytes.len()
                ))
            })?,
            compressed_size: u32::try_from(meta_bytes.len()).map_err(|_| {
                EraError::IndexError(format!(
                    "MetaIndex size {} exceeds u32::MAX",
                    meta_bytes.len()
                ))
            })?,
            chunk_count: 0,
        };

        // Write MetaIndex as IndexManifest block
        let manifest_location = volume_writer
            .write_canonical_block(&manifest_encrypted_block, BlockType::IndexManifest)
            .await?;

        Ok((meta, manifest_location))
    }
}

impl Drop for IndexBuilder {
    fn drop(&mut self) {
        if self.is_dirty() {
            tracing::warn!(
                "IndexBuilder dropped with {} unflushed entries",
                self.buffer.len()
            );
        }
        if let Err(e) = self.flush_buffer() {
            tracing::error!("Failed to flush buffer in Drop: {}", e);
            // V20-F7 fix: Preserve staging file for forensic analysis when flush fails.
            // Without this, Drop would delete the staging file, losing evidence of what
            // caused the flush failure.
            self.store.keep_on_drop();
        }
    }
}

impl IndexBuilder {
    /// Returns `true` if there are unflushed entries in the in-memory buffer.
    pub fn is_dirty(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Consume the builder, flushing any remaining buffered entries.
    ///
    /// Unlike `Drop`, this method propagates flush errors to the caller.
    /// After `close()` returns, Drop still runs but the buffer is empty,
    /// so no data is at risk.
    pub fn close(mut self) -> Result<()> {
        self.flush_buffer()?;
        Ok(())
    }

    /// Explicitly discard the builder and remove the staging file.
    ///
    /// Removes the staging file while the DB handle is still held,
    /// eliminating the TOCTOU window in Drop (V6-F10 fix).
    pub fn discard(mut self) -> Result<()> {
        // V13-F9 fix: skip flush — buffer entries are about to be deleted anyway.
        // Clear the buffer to prevent the Drop warning about unflushed entries.
        self.buffer.clear();
        self.store.discard()?;
        Ok(())
        // Drop runs but store.read_only=true, so no double-remove
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::{BlockId, VolumeId};

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_builder_insert() {
        let mut builder = IndexBuilder::new(1024 * 1024).unwrap();

        for i in 0..100u64 {
            let entry = IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 1024,
                1024,
            )
            .expect("valid entry");
            builder.insert(entry).unwrap();
        }

        assert_eq!(builder.entry_count(), 100);
    }

    #[test]
    fn test_bloom_filter() {
        let mut builder = IndexBuilder::new_default().unwrap();

        for i in 0..1000u64 {
            let entry = IndexEntry::new(
                test_hash(i),
                VolumeId::new(),
                BlockId::new(i / 100),
                (i % 100) as u32 * 1024,
                1024,
            )
            .expect("valid entry");
            builder.insert(entry).unwrap();
        }

        // Check all inserted hashes are found
        for i in 0..1000u64 {
            assert!(builder.bloom_contains(&test_hash(i)));
        }

        // Check false positive rate on non-existent hashes
        let mut false_positives = 0;
        for i in 1000..2000u64 {
            if builder.bloom_contains(&test_hash(i)) {
                false_positives += 1;
            }
        }

        // Should be < 20 false positives (2% of 1000 queries)
        assert!(false_positives < 20);
    }
}
