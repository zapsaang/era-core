//! # LsmTree - Native Log-Structured Merge Tree
//!
//! Unified orchestrator for the ERA native index implementation.
//! Replaces the deleted RocksDB wrapper with a 100% Rust-native solution.
//!
//! ## Architecture
//!
//! - **MemTable**: In-memory buffer (64MB default, configurable)
//! - **Spiller**: Ephemeral encryption for temporary segments
//! - **Merger**: Tiered k-way merge (MAX_FAN_IN=64)
//! - **Reader**: Bloom + L1 + L2 hierarchical lookup
//!
//! ## Security
//!
//! - All spill files are encrypted with ephemeral session keys
//! - Keys are generated at runtime and never persisted
//! - Zero plaintext leakage during intermediate stages

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use era_common::{ChunkHash, Result};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageReader;
use era_volume::VolumeReader;

use crate::{IndexBuilder, IndexEntry, IndexLocation, IndexReader, MetaIndex};

/// Configuration for LsmTree
#[derive(Debug, Clone)]
pub struct LsmTreeConfig {
    /// Memory limit for MemTable (bytes)
    pub mem_limit: usize,
    /// Temporary directory for spill files
    pub temp_dir: PathBuf,
}

impl Default for LsmTreeConfig {
    fn default() -> Self {
        Self {
            mem_limit: 64 * 1024 * 1024, // 64MB
            temp_dir: std::env::temp_dir(),
        }
    }
}

/// Native Log-Structured Merge Tree
///
/// This is the primary index structure for ERA v2.1, providing:
/// - Bounded memory usage during construction
/// - Secure spilling with ephemeral encryption
/// - Fast lookups via Bloom filters and hierarchical indexing
///
/// ## Usage
///
/// ```no_run
/// use era_index::{LsmTree, LsmTreeConfig, IndexEntry};
/// use era_common::{ChunkHash, VolumeId, BlockId};
///
/// # fn example() -> era_common::Result<()> {
/// let config = LsmTreeConfig::default();
/// let mut tree = LsmTree::new(config);
///
/// // Insert entries during archive creation
/// let entry = IndexEntry::new(
///     ChunkHash::from_bytes([0u8; 32]),
///     VolumeId::new(),
///     BlockId::new(0),
///     0,
///     4096,
/// );
/// tree.insert(entry)?;
///
/// // Finalize and get reader
/// let reader = tree.finalize()?;
///
/// // Lookup entries
/// let hash = ChunkHash::from_bytes([0u8; 32]);
/// if let Some(location) = reader.lookup(&hash)? {
///     println!("Found at block {} offset {}", location.block_id, location.offset);
/// }
/// # Ok(())
/// # }
/// ```
pub struct LsmTree {
    /// Configuration
    config: LsmTreeConfig,
    /// Index builder (write path)
    builder: Option<IndexBuilder>,
    /// Index reader (read path)
    reader: Option<Arc<RwLock<IndexReader>>>,
    /// State tracking
    state: TreeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeState {
    /// Building index (write mode)
    Building,
    /// Index finalized (read mode)
    Finalized,
}

impl LsmTree {
    /// Create a new LsmTree for index construction
    pub fn new(config: LsmTreeConfig) -> Self {
        let builder = IndexBuilder::new(config.mem_limit);

        Self {
            config,
            builder: Some(builder),
            reader: None,
            state: TreeState::Building,
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(LsmTreeConfig::default())
    }

    /// Insert an entry into the index
    ///
    /// This will automatically spill to disk when memory limit is reached.
    pub fn insert(&mut self, entry: IndexEntry) -> Result<()> {
        if self.state != TreeState::Building {
            return Err(era_common::EraError::InvalidFormat(
                "Cannot insert into finalized index".to_string(),
            ));
        }

        let builder = self
            .builder
            .as_mut()
            .expect("Builder must exist in Building state");

        builder.insert(entry, &self.config.temp_dir)
    }

    /// Check if a hash exists in the Bloom filter (fast negative lookup)
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        match self.state {
            TreeState::Building => self
                .builder
                .as_ref()
                .map(|b| b.bloom_contains(hash))
                .unwrap_or(false),
            TreeState::Finalized => {
                // Use the IndexReader's bloom_contains method
                self.reader
                    .as_ref()
                    .map(|r| r.read().bloom_contains(hash))
                    .unwrap_or(false)
            }
        }
    }

    /// Get the number of spill files created
    pub fn spill_count(&self) -> usize {
        self.builder.as_ref().map(|b| b.spill_count()).unwrap_or(0)
    }

    /// Get current MemTable memory usage
    pub fn memtable_size_bytes(&self) -> usize {
        self.builder
            .as_ref()
            .map(|b| b.memtable_size_bytes())
            .unwrap_or(0)
    }

    /// Finalize the index and transition to read mode
    ///
    /// This performs the final merge of all spill segments and builds
    /// the hierarchical index structure (Bloom + L1 + L2).
    pub fn finalize(mut self) -> Result<LsmTreeReader> {
        if self.state != TreeState::Building {
            return Err(era_common::EraError::InvalidFormat(
                "Index already finalized".to_string(),
            ));
        }

        let mut builder = self
            .builder
            .take()
            .expect("Builder must exist in Building state");

        // STEP 1: Flush remaining MemTable to spill segment
        if !builder.memtable().is_empty() {
            tracing::info!(
                "Flushing final MemTable ({} entries)",
                builder.memtable().len()
            );
            builder.flush_memtable(&self.config.temp_dir)?;
        }

        // STEP 2: Merge all spill segments using TieredMerger
        tracing::info!(
            "Merging {} spill segments",
            builder.spilled_segments().len()
        );
        let merged_entries: Vec<IndexEntry> = if !builder.spilled_segments().is_empty() {
            let merger = crate::merger::TieredMerger::new(
                builder.spilled_segments().to_vec(),
                builder.spiller(),
            )?;
            merger.collect()
        } else {
            Vec::new()
        };

        // STEP 3: Build MetaIndex from merged entries
        // For in-memory index, we don't create pages, just store entries directly in reader
        let meta = MetaIndex::new();

        // STEP 4: Create IndexReader with Bloom filter
        // Serialize the Bloom filter using rkyv via bloom_serde
        let bloom_bytes = crate::serialize_bloom(builder.bloom())?;

        let mut meta_with_bloom = meta;
        meta_with_bloom.set_bloom_filter(bloom_bytes);

        // Create reader from memory (entries embedded, not on disk)
        // We need to clone the bloom filter since we're consuming the builder
        let bloom_clone = builder.bloom().clone();
        let entries_count = merged_entries.len();
        let reader = IndexReader::from_memory(meta_with_bloom, bloom_clone, merged_entries)?;

        // STEP 5: Clean up temporary spill files
        for spill_path in builder.spilled_segments() {
            if spill_path.exists() {
                if let Err(e) = std::fs::remove_file(spill_path) {
                    tracing::warn!("Failed to remove spill file {:?}: {}", spill_path, e);
                }
            }
        }

        tracing::info!("Index finalized: {} total entries", entries_count);

        self.reader = Some(Arc::new(RwLock::new(reader)));
        self.state = TreeState::Finalized;

        Ok(LsmTreeReader {
            reader: self.reader.clone().unwrap(),
        })
    }

    /// Recover an index from a volume (cold recovery)
    ///
    /// This enables zero-knowledge recovery from an orphaned .era file
    /// with no external metadata.
    pub async fn recover_from_volume<R: StorageReader>(
        volume_reader: &VolumeReader<R>,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: [u8; 16],
    ) -> Result<LsmTreeReader> {
        let reader =
            IndexReader::recover_from_volume(volume_reader, session, volume_key, nonce_context)
                .await?;

        Ok(LsmTreeReader {
            reader: Arc::new(RwLock::new(reader)),
        })
    }
}

/// Read-only view of a finalized LsmTree
///
/// Provides fast lookups via Bloom filters and hierarchical indexing.
#[derive(Clone)]
pub struct LsmTreeReader {
    reader: Arc<RwLock<IndexReader>>,
}

impl LsmTreeReader {
    /// Lookup a chunk hash in the index
    ///
    /// Returns `None` if the chunk is not found (fast via Bloom filter).
    pub fn lookup(&self, hash: &ChunkHash) -> Result<Option<IndexLocation>> {
        self.reader.write().lookup(hash)
    }

    /// Check if a hash exists in the Bloom filter (fast O(1) negative lookup)
    ///
    /// This is much faster than `lookup()` as it only checks the bloom filter
    /// without performing the full index traversal. Use this for fast
    /// deduplication checks.
    ///
    /// Returns `false` if the hash is definitely NOT in the index.
    /// Returns `true` if the hash MAY be in the index (bloom filters have false positives).
    #[inline]
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        self.reader.read().bloom_contains(hash)
    }

    /// Get the underlying reader (for advanced use cases)
    pub fn reader(&self) -> Arc<RwLock<IndexReader>> {
        Arc::clone(&self.reader)
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
    fn test_lsm_tree_creation() {
        let tree = LsmTree::new_default();
        assert_eq!(tree.state, TreeState::Building);
        assert_eq!(tree.spill_count(), 0);
    }

    #[test]
    fn test_lsm_tree_insert() {
        let mut tree = LsmTree::new_default();

        let entry = IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 4096);

        tree.insert(entry).unwrap();
        assert!(tree.bloom_contains(&test_hash(100)));
        assert!(!tree.bloom_contains(&test_hash(999)));
    }

    #[test]
    fn test_lsm_tree_memory_tracking() {
        let mut tree = LsmTree::new_default();

        let initial_size = tree.memtable_size_bytes();
        assert_eq!(initial_size, 0);

        let entry = IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 4096);

        tree.insert(entry).unwrap();

        let after_insert = tree.memtable_size_bytes();
        assert!(after_insert > initial_size);
        assert_eq!(after_insert, IndexEntry::memory_size());
    }

    /// P0 BUG TEST: LsmTreeReader.bloom_contains() must use actual bloom filter
    ///
    /// This test proves the critical bug where LsmTreeReader.bloom_contains()
    /// uses an inefficient workaround (calling lookup()) instead of directly
    /// checking the bloom filter via IndexReader.bloom_contains().
    ///
    /// The current implementation in LsmTreeReader::bloom_contains():
    /// ```
    /// self.lookup(hash).ok().flatten().is_some()
    /// ```
    /// This is O(log n) instead of O(1) and defeats the purpose of bloom filters.
    ///
    /// Expected behavior: bloom_contains() should directly check the bloom filter
    /// without performing a full lookup.
    #[test]
    fn test_lsm_tree_reader_bloom_contains_efficiency() {
        let mut tree = LsmTree::new_default();

        // Insert entries
        for i in 0..100u64 {
            let entry = IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(i), 0, 4096);
            tree.insert(entry).unwrap();
        }

        // Verify bloom works BEFORE finalization
        assert!(
            tree.bloom_contains(&test_hash(50)),
            "bloom_contains should return true for inserted hash BEFORE finalize"
        );
        assert!(
            !tree.bloom_contains(&test_hash(9999)),
            "bloom_contains should return false for non-inserted hash BEFORE finalize"
        );

        // Finalize and get reader
        let reader = tree.finalize().expect("finalize should succeed");

        // Reader's bloom_contains should work correctly
        assert!(
            reader.bloom_contains(&test_hash(50)),
            "LsmTreeReader.bloom_contains should return true for inserted hash"
        );
        assert!(
            reader.bloom_contains(&test_hash(0)),
            "LsmTreeReader.bloom_contains should return true for first inserted hash"
        );
        assert!(
            reader.bloom_contains(&test_hash(99)),
            "LsmTreeReader.bloom_contains should return true for last inserted hash"
        );

        // Non-inserted hashes should return false
        assert!(
            !reader.bloom_contains(&test_hash(9999)),
            "LsmTreeReader.bloom_contains should return false for non-inserted hash"
        );
    }

    /// P0 BUG TEST: IndexReader must expose bloom_contains() method
    ///
    /// This test verifies that IndexReader has a direct bloom_contains() method
    /// that can be called without going through the full lookup() path.
    ///
    /// Currently IndexReader does NOT expose this method, forcing LsmTreeReader
    /// to use the inefficient lookup() workaround.
    #[test]
    fn test_index_reader_bloom_contains_exists() {
        use crate::reader::IndexReader;

        // Create a minimal IndexReader using from_memory
        let meta = crate::MetaIndex::new();
        let bloom = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
        let reader = IndexReader::from_memory(meta, bloom, vec![])
            .expect("IndexReader creation should succeed");

        // P0 BUG: IndexReader should have bloom_contains() method
        // This test will fail to compile if the method doesn't exist
        let _result = reader.bloom_contains(&test_hash(25));
    }
}
