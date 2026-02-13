//! # IndexReader - Bloom + L1 + L2 Lookup
//!
//! Reads the finalized index structure efficiently.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use bloomfilter::Bloom;

use era_common::{BlockId, BlockLocation, BlockType, ChunkHash, EraError, Result};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageReader;
use era_volume::VolumeReader;

#[allow(unused_imports)] // Used in tests
use super::{IndexEntry, IndexPage, MetaIndex};

/// Simplified location result (for now, just the key fields)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexLocation {
    pub block_id: BlockId,
    pub offset: u32,
    pub length: u32,
}

/// IndexReader provides fast lookups via Bloom + L1 + L2
pub struct IndexReader {
    /// Root directory containing index files (legacy mode)
    index_dir: Option<PathBuf>,
    /// L1 Meta-Index (sparse directory)
    meta: MetaIndex,
    /// Bloom filter (deserialized)
    bloom: Bloom<ChunkHash>,
    /// Cache of loaded L2 pages
    page_cache: HashMap<BlockId, IndexPage>,
    /// In-memory page storage (for cold recovery mode)
    embedded_pages: HashMap<BlockId, IndexPage>,
}

impl IndexReader {
    /// Open an index from a directory
    pub fn open(index_dir: &Path, meta: MetaIndex) -> Result<Self> {
        // Deserialize Bloom filter using rkyv via bloom_serde
        let bloom = super::deserialize_bloom(&meta.bloom_filter)?;

        Ok(Self {
            index_dir: Some(index_dir.to_path_buf()),
            meta,
            bloom,
            page_cache: HashMap::new(),
            embedded_pages: HashMap::new(),
        })
    }

    /// Create an in-memory index reader from finalized entries
    ///
    /// This is used by LsmTree::finalize() to create a reader from Redb entries
    /// from merged entries without disk I/O.
    pub fn from_memory(
        meta: MetaIndex,
        bloom: Bloom<ChunkHash>,
        entries: Vec<IndexEntry>,
    ) -> Result<Self> {
        // For in-memory mode, we store all entries as a single "page"
        // This is simpler than creating actual pages for small indices
        let mut meta = meta;
        let embedded_pages = if !entries.is_empty() {
            let mut pages = HashMap::new();
            let page = IndexPage::new(entries);
            // CRITICAL: Register this page in the MetaIndex so lookup() can find it.
            // Without this, meta.find_page() returns None and lookup() always fails.
            meta.add_page(page.min_hash, page.max_hash, BlockId::new(0));
            pages.insert(BlockId::new(0), page);
            pages
        } else {
            HashMap::new()
        };

        Ok(Self {
            index_dir: None,
            meta,
            bloom,
            page_cache: HashMap::new(),
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
    ) -> Result<Self> {
        tracing::info!("Starting cold recovery from volume");

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
                let block_key =
                    session.derive_block_key(volume_key, block_id.sequence(), &nonce_context);
                let derived_key = block_key.to_derived_key();
                let decrypted_data = era_crypto::decrypt_with_context(
                    &derived_key,
                    &nonce_context,
                    block_id,
                    &encrypted_block.data,
                )?;

                // Deserialize MetaIndex using rkyv
                let meta = rkyv::from_bytes::<MetaIndex>(&decrypted_data)
                    .map_err(|e| EraError::Deserialization(e.to_string()))?;

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
            // then try nearby values, then expand outward. This replaces the old
            // hard-coded 0..100 limit that failed for indices with >100 pages.
            let mut candidates: Vec<u64> = Vec::with_capacity(512);
            // Most likely: manifest block_id == number of index pages
            candidates.push(page_count_hint);
            // Try nearby values (off-by-one errors, partial writes)
            for delta in 1..=10 {
                candidates.push(page_count_hint + delta);
                if page_count_hint >= delta {
                    candidates.push(page_count_hint - delta);
                }
            }
            // Fallback: scan 0..max(256, page_count_hint * 2) for robustness
            let upper_bound = (page_count_hint * 2).max(256);
            for id in 0..upper_bound {
                if !candidates.contains(&id) {
                    candidates.push(id);
                }
            }

            let mut manifest_data = None;
            for candidate_id in candidates {
                let block_id = BlockId::new(candidate_id);
                let block_key =
                    session.derive_block_key(volume_key, block_id.sequence(), &nonce_context);
                let derived_key = block_key.to_derived_key();

                if let Ok(decrypted_data) = era_crypto::decrypt_with_context(
                    &derived_key,
                    &nonce_context,
                    block_id,
                    &encrypted_block.data,
                ) {
                    // Try to deserialize as MetaIndex using rkyv
                    if let Ok(meta_candidate) = rkyv::from_bytes::<MetaIndex>(&decrypted_data) {
                        // Verify this looks like a valid MetaIndex
                        if !meta_candidate.pages.is_empty() {
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

        // Step 4: Load all pages into memory
        // CRITICAL: We must try all possible block IDs from MetaIndex since scanner assigns arbitrary slot_index
        let mut embedded_pages = HashMap::new();

        for location in &page_blocks {
            let (_, encrypted_block) = volume_reader.read_typed_block(location).await?;

            // Try to decrypt with each block ID from MetaIndex
            let mut successfully_decrypted = false;
            for page_ptr in &meta.pages {
                let block_id = page_ptr.block_id;
                let block_key =
                    session.derive_block_key(volume_key, block_id.sequence(), &nonce_context);
                let derived_key = block_key.to_derived_key();

                // Try decryption - if it fails, this isn't the right block ID
                if let Ok(decrypted_data) = era_crypto::decrypt_with_context(
                    &derived_key,
                    &nonce_context,
                    block_id,
                    &encrypted_block.data,
                ) {
                    // Try to deserialize as IndexPage using rkyv
                    if let Ok(page) = rkyv::from_bytes::<IndexPage>(&decrypted_data) {
                        // Verify this is the right page by checking hash range
                        if page.min_hash == page_ptr.min_hash && page.max_hash == page_ptr.max_hash
                        {
                            embedded_pages.insert(block_id, page);
                            successfully_decrypted = true;
                            break;
                        }
                    }
                }
            }

            if !successfully_decrypted {
                tracing::warn!("Found IndexPage block at offset {} but couldn't decrypt with any known block ID",
                    location.physical_offset);
            }
        }

        // Step 5: Deserialize Bloom filter using rkyv via bloom_serde
        let bloom = super::deserialize_bloom(&meta.bloom_filter)?;

        tracing::info!(
            "Cold recovery complete: {} pages loaded, bloom filter restored",
            embedded_pages.len()
        );

        Ok(Self {
            index_dir: None, // No external directory in recovery mode
            meta,
            bloom,
            page_cache: HashMap::new(),
            embedded_pages,
        })
    }

    /// Lookup a chunk hash
    pub fn lookup(&mut self, hash: &ChunkHash) -> Result<Option<IndexLocation>> {
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

    /// Load an L2 page (with caching)
    fn load_page(&mut self, block_id: BlockId) -> Result<&IndexPage> {
        // Check embedded pages first (cold recovery mode)
        if self.embedded_pages.contains_key(&block_id) {
            return Ok(self.embedded_pages.get(&block_id).unwrap());
        }

        // Load from filesystem (legacy mode)
        if !self.page_cache.contains_key(&block_id) {
            let index_dir = self.index_dir.as_ref().ok_or_else(|| {
                EraError::InvalidFormat(
                    "IndexReader in recovery mode - pages should be embedded".into(),
                )
            })?;

            let page_path = index_dir.join(format!("page_{}.bin", block_id.sequence()));

            let page_bytes = fs::read(&page_path).map_err(|e| {
                EraError::InvalidFormat(format!("Failed to read page {:?}: {}", page_path, e))
            })?;

            // Deserialize IndexPage using rkyv
            let page = rkyv::from_bytes::<IndexPage>(&page_bytes)
                .map_err(|e| EraError::Deserialization(e.to_string()))?;

            self.page_cache.insert(block_id, page);
        }

        Ok(self.page_cache.get(&block_id).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::VolumeId;
    use tempfile::TempDir;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_reader_basic() {
        let temp_dir = TempDir::new().unwrap();
        let index_dir = temp_dir.path().join("index");
        fs::create_dir_all(&index_dir).unwrap();

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

        let page = IndexPage::new(entries.clone());
        // Serialize page using rkyv
        let page_bytes = rkyv::to_bytes::<_, 4096>(&page).unwrap();
        fs::write(index_dir.join("page_0.bin"), &page_bytes).unwrap();

        // Create meta-index
        let mut meta = MetaIndex::new();
        meta.add_page(test_hash(0), test_hash(99), BlockId::new(0));

        // Create a simple bloom filter
        let mut bloom = Bloom::new_for_fp_rate(1000, 0.01);
        for entry in &entries {
            bloom.set(&entry.hash);
        }
        // Serialize bloom filter using rkyv via bloom_serde
        let bloom_bytes = crate::serialize_bloom(&bloom).unwrap();
        meta.set_bloom_filter(bloom_bytes);

        // Create reader
        let mut reader = IndexReader::open(&index_dir, meta).unwrap();

        // Test positive lookup
        let result = reader.lookup(&test_hash(50)).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().offset, 50 * 1024);

        // Test negative lookup
        let result = reader.lookup(&test_hash(500)).unwrap();
        assert!(result.is_none());
    }
}
