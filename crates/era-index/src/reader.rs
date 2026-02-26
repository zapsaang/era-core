//! # IndexReader - Bloom + L1 + L2 Lookup
//!
//! Reads the finalized index structure efficiently.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use bloomfilter::Bloom;
use quick_cache::sync::Cache;

use era_common::{BlockId, BlockLocation, BlockType, ChunkHash, EraError, Result, VolumeId};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageReader;
use era_volume::VolumeReader;
use rkyv::Deserialize;

#[allow(unused_imports)] // Used in tests
use super::{IndexEntry, IndexPage, MetaIndex};

/// Simplified location result — includes volume_id for multi-volume lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexLocation {
    pub volume_id: VolumeId,
    pub block_id: BlockId,
    pub offset: u32,
    pub length: u32,
}

/// IndexReader provides fast lookups via Bloom + L1 + L2
pub struct IndexReader {
    /// L1 Meta-Index (sparse directory)
    meta: MetaIndex,
    /// Bloom filter (deserialized)
    bloom: Bloom<ChunkHash>,
    /// Cache of loaded L2 pages (lock-free concurrent reads)
    page_cache: Cache<BlockId, IndexPage>,
    /// In-memory page storage (for cold recovery mode)
    embedded_pages: HashMap<BlockId, IndexPage>,
}

/// Default page cache capacity
const PAGE_CACHE_CAP: usize = 256;

/// Minimum valid serialized IndexPage size (~40 bytes: rkyv overhead + at least 1 entry header)
const MIN_INDEX_PAGE_SIZE: usize = 40;

/// Maximum valid serialized IndexPage size.
/// ENTRIES_PER_PAGE (8192) × sizeof(archived IndexEntry) (~64 bytes) + rkyv overhead
/// = ~524,288 + overhead = 1MB (revised from 512KB due to rkyv alignment/header)
const MAX_INDEX_PAGE_SIZE: usize = 1024 * 1024;

/// Minimum valid serialized MetaIndex size (~40 bytes: rkyv overhead + bloom filter header)
const MIN_META_INDEX_SIZE: usize = 40;

/// Maximum valid serialized MetaIndex size.
/// 10,000 pages × PagePointer (~80 bytes each) + bloom filter data = ~1MB + margin
const MAX_META_INDEX_SIZE: usize = 2 * 1024 * 1024;

/// Validate that serialized rkyv data falls within expected size bounds.
/// Returns `EraError::IndexError` if the data is outside the valid range.
fn validate_rkyv_size(data: &[u8], min: usize, max: usize, type_name: &str) -> Result<()> {
    if data.len() < min || data.len() > max {
        return Err(EraError::IndexError(format!(
            "{} data size {} is outside valid range [{}, {}]",
            type_name,
            data.len(),
            min,
            max,
        )));
    }
    Ok(())
}

/// Maximum entries allowed in from_memory() to prevent OOM (V6-F3)
pub const MAX_MEMORY_ENTRIES: usize = crate::ENTRIES_PER_PAGE * 10_000;

/// Maximum pages allowed in from_pages() to prevent OOM (V6-F3)
pub const MAX_PAGES: usize = 10_000;

impl IndexReader {
    /// Open an index from a directory
    pub fn open(meta: MetaIndex) -> Result<Self> {
        // Deserialize Bloom filter using rkyv via bloom_serde
        let bloom = super::deserialize_bloom(meta.bloom_filter())?;

        Ok(Self {
            meta,
            bloom,
            page_cache: Cache::new(PAGE_CACHE_CAP),
            embedded_pages: HashMap::new(),
        })
    }

    /// Create an in-memory index reader from finalized entries
    ///
    /// This is used by ChunkIndex::finalize() to create a reader from Redb entries
    /// from merged entries without disk I/O. Entries are chunked into pages of
    /// ENTRIES_PER_PAGE to respect the L2 cache optimization.
    pub fn from_memory(
        meta: MetaIndex,
        bloom: Bloom<ChunkHash>,
        entries: Vec<IndexEntry>,
    ) -> Result<Self> {
        if entries.len() > MAX_MEMORY_ENTRIES {
            return Err(EraError::IndexError(format!(
                "from_memory: {} entries exceeds maximum {} (V6-F3)",
                entries.len(),
                MAX_MEMORY_ENTRIES
            )));
        }
        let mut meta = meta;
        let embedded_pages = if !entries.is_empty() {
            let mut pages = HashMap::new();
            for (block_id, chunk) in entries.chunks(super::ENTRIES_PER_PAGE).enumerate() {
                let page = IndexPage::try_new(chunk.to_vec())?;
                let bid = BlockId::new(block_id as u64);
                meta.add_page(*page.min_hash(), *page.max_hash(), bid)?;
                pages.insert(bid, page);
            }
            pages
        } else {
            HashMap::new()
        };

        Ok(Self {
            meta,
            bloom,
            page_cache: Cache::new(PAGE_CACHE_CAP),
            embedded_pages,
        })
    }

    /// Create an in-memory index reader from pre-built pages.
    ///
    /// This avoids materializing all entries into a single Vec — each page
    /// is already chunked at ENTRIES_PER_PAGE boundaries by the caller.
    pub fn from_pages(
        meta: MetaIndex,
        bloom: Bloom<ChunkHash>,
        pages: Vec<(IndexPage, BlockId)>,
    ) -> Result<Self> {
        if pages.len() > MAX_PAGES {
            return Err(EraError::IndexError(format!(
                "from_pages: {} pages exceeds maximum {} (V6-F3)",
                pages.len(),
                MAX_PAGES
            )));
        }
        let mut meta = meta;
        let mut embedded_pages = HashMap::new();
        for (page, block_id) in pages {
            meta.add_page(*page.min_hash(), *page.max_hash(), block_id)?;
            embedded_pages.insert(block_id, page);
        }

        Ok(Self {
            meta,
            bloom,
            page_cache: Cache::new(PAGE_CACHE_CAP),
            embedded_pages,
        })
    }

    /// Recover index from a volume using cold recovery (CRITICAL FOR SELF-CONTAINMENT)
    ///
    /// **Zero-Knowledge Recovery:** Reconstructs the index by:
    /// 1. Scanning volume for IndexManifest blocks (MetaIndex)
    /// 2. Scanning for IndexPage blocks
    /// 3. Decrypting and loading all pages into memory
    ///
    /// This enables recovery from an orphaned .era file with NO external metadata.
    pub async fn recover_from_volume<R: StorageReader>(
        volume_reader: &VolumeReader<R>,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: [u8; 16],
        timeout: Option<Duration>,
    ) -> Result<Self> {
        tracing::info!("Starting cold recovery from volume");
        let deadline = timeout.map(|d| Instant::now() + d);

        // Domain-separated nonce context for index blocks (must match builder::finalize)
        let mut index_nonce_context = nonce_context;
        index_nonce_context[0] ^= 0xFF;

        // Step 1: Try to read MetaIndex from footer (fast path)
        let meta = if let Some(footer) = volume_reader.footer() {
            if footer.has_index() {
                // Footer has index location
                let location = BlockLocation::single(
                    era_common::VolumeId::new(),
                    footer.index_block_id,
                    footer.index_offset,
                    footer.index_size,
                );

                tracing::info!("Found index in footer at offset {}", footer.index_offset);

                // Read and decrypt MetaIndex
                let (block_type, encrypted_block) =
                    volume_reader.read_typed_block(&location).await?;
                if block_type != BlockType::IndexManifest {
                    return Err(EraError::InvalidFormat(format!(
                        "Expected IndexManifest, found {:?}",
                        block_type
                    )));
                }

                // Decrypt MetaIndex
                let block_id = BlockId::new(footer.index_block_id as u64);
                let block_key = session.derive_block_key(
                    volume_key,
                    block_id.sequence(),
                    &index_nonce_context,
                )?;
                let derived_key = block_key.to_derived_key()?;
                let decrypted_data = era_crypto::decrypt_with_context(
                    &derived_key,
                    &index_nonce_context,
                    block_id,
                    &encrypted_block.data,
                )?;

                // Pre-validate size before rkyv deserialization to prevent allocation bombs
                validate_rkyv_size(
                    &decrypted_data,
                    MIN_META_INDEX_SIZE,
                    MAX_META_INDEX_SIZE,
                    "MetaIndex",
                )?;

                // Deserialize MetaIndex using rkyv (check_archived_root + deserialize)
                let archived = rkyv::check_archived_root::<MetaIndex>(&decrypted_data)
                    .map_err(|e| EraError::Deserialization(e.to_string()))?;
                let meta: MetaIndex = match archived.deserialize(&mut rkyv::Infallible) {
                    Ok(val) => val,
                    Err(never) => match never {},
                };

                Some(meta)
            } else {
                None
            }
        } else {
            None
        };

        // Step 2: If footer doesn't have index, scan for IndexManifest (slow path)
        let meta = if let Some(m) = meta {
            tracing::info!("MetaIndex loaded from footer (fast path)");
            m
        } else {
            tracing::warn!("Footer missing or no index_root - scanning for IndexManifest blocks");
            let manifest_blocks = volume_reader
                .scan_for_typed_blocks(BlockType::IndexManifest)
                .await?;

            if manifest_blocks.is_empty() {
                return Err(EraError::InvalidFormat(
                    "No IndexManifest blocks found in volume - cannot recover".into(),
                ));
            }

            // Use the first (should be only) manifest
            let location = &manifest_blocks[0];
            let (_, encrypted_block) = volume_reader.read_typed_block(location).await?;

            // Scan for IndexPage blocks first to estimate the manifest block ID.
            // The manifest is written after all pages, so its block_id = page_count.
            let page_blocks_for_hint = volume_reader
                .scan_for_typed_blocks(BlockType::IndexPage)
                .await
                .unwrap_or_default();
            let page_count_hint = page_blocks_for_hint.len() as u64;

            // Build candidate block IDs: start with the most likely (page_count),
            // then try nearby values, then expand outward. Uses HashSet for O(1) dedup.
            let mut seen: HashSet<u64> = HashSet::new();
            let mut candidates: Vec<u64> = Vec::with_capacity(512);
            // Most likely: manifest block_id == number of index pages
            if seen.insert(page_count_hint) {
                candidates.push(page_count_hint);
            }
            // Try nearby values (off-by-one errors, partial writes)
            for delta in 1..=10 {
                let above = page_count_hint + delta;
                if seen.insert(above) {
                    candidates.push(above);
                }
                if page_count_hint >= delta {
                    let below = page_count_hint - delta;
                    if seen.insert(below) {
                        candidates.push(below);
                    }
                }
            }
            // Fallback: use volume block_count as upper bound when available,
            // otherwise use a generous estimate. This ensures manifests at any
            // block_id are recoverable (fixes V6-F2: hint=0 missed block_id>=256).
            let volume_block_count = volume_reader.block_count() as u64;
            let upper_bound = if volume_block_count > 0 {
                volume_block_count + 1
            } else {
                (page_count_hint + 1).saturating_mul(4).max(1024)
            };
            for id in 0..upper_bound {
                if seen.insert(id) {
                    candidates.push(id);
                }
            }

            let mut manifest_data = None;
            for candidate_id in candidates {
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        return Err(EraError::IndexError(
                            "Cold recovery timed out during candidate iteration".into(),
                        ));
                    }
                }
                let block_id = BlockId::new(candidate_id);
                let block_key = session.derive_block_key(
                    volume_key,
                    block_id.sequence(),
                    &index_nonce_context,
                )?;
                let derived_key = block_key.to_derived_key()?;

                if let Ok(decrypted_data) = era_crypto::decrypt_with_context(
                    &derived_key,
                    &index_nonce_context,
                    block_id,
                    &encrypted_block.data,
                ) {
                    // Pre-validate size before rkyv deserialization
                    if validate_rkyv_size(
                        &decrypted_data,
                        MIN_META_INDEX_SIZE,
                        MAX_META_INDEX_SIZE,
                        "MetaIndex",
                    )
                    .is_err()
                    {
                        continue;
                    }
                    // Try to deserialize as MetaIndex using rkyv
                    if let Ok(archived) = rkyv::check_archived_root::<MetaIndex>(&decrypted_data) {
                        let meta_candidate: MetaIndex =
                            match archived.deserialize(&mut rkyv::Infallible) {
                                Ok(val) => val,
                                Err(never) => match never {},
                            };
                        // Verify this looks like a valid MetaIndex
                        if !meta_candidate.pages().is_empty() {
                            tracing::info!(
                                "MetaIndex decrypted successfully with block_id={}",
                                candidate_id
                            );
                            manifest_data = Some(meta_candidate);
                            break;
                        }
                    }
                }
            }

            manifest_data.ok_or_else(|| {
                EraError::Decryption(
                    "Could not decrypt IndexManifest with any candidate block ID".into(),
                )
            })?
        };

        // Step 3: Scan for all IndexPage blocks
        tracing::info!("Scanning for IndexPage blocks");
        let page_blocks = volume_reader
            .scan_for_typed_blocks(BlockType::IndexPage)
            .await?;
        tracing::info!("Found {} IndexPage blocks", page_blocks.len());

        // Step 4: Load all pages — content-addressed matching (order-independent)
        // Instead of assuming page_blocks[i] == meta.pages[i] (positional matching),
        // we try each scanned block against all unrecovered meta entries. This is
        // robust against volume scanners returning pages in any order.
        let mut embedded_pages = HashMap::new();

        for location in page_blocks.iter() {
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Err(EraError::IndexError(
                        "Cold recovery timed out during page recovery".into(),
                    ));
                }
            }
            let (_, encrypted_block) = volume_reader.read_typed_block(location).await?;
            let mut matched = false;

            // Try every unrecovered meta.pages entry until one decrypts + validates
            for page_ptr in meta.pages() {
                if embedded_pages.contains_key(&page_ptr.block_id) {
                    continue; // Already recovered this page
                }

                let block_key = session.derive_block_key(
                    volume_key,
                    page_ptr.block_id.sequence(),
                    &index_nonce_context,
                )?;
                let derived_key = block_key.to_derived_key()?;

                if let Ok(decrypted_data) = era_crypto::decrypt_with_context(
                    &derived_key,
                    &index_nonce_context,
                    page_ptr.block_id,
                    &encrypted_block.data,
                ) {
                    // Pre-validate size before rkyv deserialization
                    if validate_rkyv_size(
                        &decrypted_data,
                        MIN_INDEX_PAGE_SIZE,
                        MAX_INDEX_PAGE_SIZE,
                        "IndexPage",
                    )
                    .is_err()
                    {
                        continue;
                    }
                    if let Ok(archived) = rkyv::check_archived_root::<IndexPage>(&decrypted_data) {
                        let page: IndexPage = match archived.deserialize(&mut rkyv::Infallible) {
                            Ok(val) => val,
                            Err(never) => match never {},
                        };
                        if *page.min_hash() == page_ptr.min_hash
                            && *page.max_hash() == page_ptr.max_hash
                        {
                            embedded_pages.insert(page_ptr.block_id, page);
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if !matched {
                tracing::warn!(
                    "Failed to match IndexPage block at offset {}",
                    location.physical_offset
                );
            }
        }

        // Completeness check: all expected pages must be recovered
        if embedded_pages.len() < meta.pages().len() {
            return Err(EraError::IndexError(format!(
                "Incomplete recovery: expected {} pages, recovered {}",
                meta.pages().len(),
                embedded_pages.len()
            )));
        }

        // Step 5: Deserialize Bloom filter using rkyv via bloom_serde
        let bloom = super::deserialize_bloom(meta.bloom_filter())?;

        tracing::info!(
            "Cold recovery complete: {} pages loaded, bloom filter restored",
            embedded_pages.len()
        );

        Ok(Self {
            // No external directory in recovery mode
            meta,
            bloom,
            page_cache: Cache::new(PAGE_CACHE_CAP),
            embedded_pages,
        })
    }

    /// Lookup a chunk hash
    pub fn lookup(&self, hash: &ChunkHash) -> Result<Option<IndexLocation>> {
        // Step 1: Bloom filter check (fast negative lookup)
        if !self.bloom.check(hash) {
            return Ok(None);
        }

        // Step 2: Find candidate L2 page via L1 meta-index
        let page_ptr = match self.meta.find_page(hash) {
            Some(ptr) => ptr,
            None => return Ok(None), // Hash not in index range
        };

        // Step 3: Load L2 page (with caching)
        let page = self.load_page(page_ptr.block_id)?;

        // Step 4: Binary search within L2 page
        match page.find(hash) {
            Some(entry) => Ok(Some(IndexLocation {
                volume_id: entry.volume_id,
                block_id: entry.block_id,
                offset: entry.offset,
                length: entry.length,
            })),
            None => Ok(None), // Bloom false positive
        }
    }

    /// Check if a hash might exist in the index (fast O(1) bloom filter check)
    ///
    /// This is a fast negative lookup - if this returns `false`, the hash
    /// is definitely NOT in the index. If it returns `true`, the hash
    /// MAY be in the index (bloom filters have false positives).
    ///
    /// Use this for fast deduplication checks before performing a full lookup.
    #[inline]
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        self.bloom.check(hash)
    }

    /// Get the number of pages in the L1 meta-index
    pub fn meta_page_count(&self) -> usize {
        self.meta.pages().len()
    }

    /// Load an L2 page (with caching)
    fn load_page(&self, block_id: BlockId) -> Result<IndexPage> {
        // Check embedded pages first (recovery mode)
        if let Some(page) = self.embedded_pages.get(&block_id) {
            return Ok(page.clone());
        }

        // Check cache (lock-free read via quick_cache)
        if let Some(page) = self.page_cache.get(&block_id) {
            return Ok(page);
        }

        // Page not found
        Err(EraError::InvalidFormat(format!(
            "Page {} not found in embedded index",
            block_id.sequence()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::VolumeId;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_reader_basic() {
        // Create a simple L2 page
        let entries: Vec<IndexEntry> = (0..100)
            .map(|i| IndexEntry {
                hash: test_hash(i),
                volume_id: VolumeId::new(),
                block_id: BlockId::new(0),
                offset: i as u32 * 1024,
                length: 1024,
            })
            .collect();

        let page = IndexPage::try_new(entries.clone()).unwrap();

        // Create meta-index
        let mut meta = MetaIndex::new();

        // Create a simple bloom filter
        let mut bloom = Bloom::new_for_fp_rate(1000, 0.01);
        for entry in &entries {
            bloom.set(&entry.hash);
        }
        // Serialize bloom filter using rkyv via bloom_serde
        let bloom_bytes = crate::serialize_bloom(&bloom).unwrap();
        meta.set_bloom_filter(bloom_bytes).unwrap();

        // Create reader using from_pages (in-memory, no filesystem)
        let reader = IndexReader::from_pages(meta, bloom, vec![(page, BlockId::new(0))]).unwrap();

        // Test positive lookup
        let result = reader.lookup(&test_hash(50)).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().offset, 50 * 1024);

        // Test negative lookup
        let result = reader.lookup(&test_hash(500)).unwrap();
        assert!(result.is_none());
    }
}
