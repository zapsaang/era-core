//! # LsmTree — Redb-backed Index Orchestrator
//!
//! Unified orchestrator for the ERA index implementation.
//! Uses Redb 2.1 for ACID-compliant staging per RFC-023.
//!
//! ## Architecture
//!
//! - **IndexBuilder**: Redb-backed staging database
//! - **IndexReader**: Bloom + L1 + L2 hierarchical lookup
//! - **No Spiller/Merger**: Redb handles durability and sorted iteration

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
    /// Memory limit for bloom filter sizing (bytes)
    pub mem_limit: usize,
    /// Directory for Redb staging file
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

/// Redb-backed index tree
///
/// This is the primary index structure for ERA, providing:
/// - ACID-compliant staging via Redb
/// - Fast lookups via Bloom filters and hierarchical indexing
/// - Sorted iteration for volume finalization
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
    /// Index builder (write path) — backed by Redb
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
        // Use IndexBuilder::new() which creates a unique temp Redb file
        // via tempfile::Builder (avoids filename collisions in parallel tests)
        let builder = IndexBuilder::new(config.mem_limit);

        Self {
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
    pub fn insert(&mut self, entry: IndexEntry) -> Result<()> {
        if self.state != TreeState::Building {
            return Err(era_common::EraError::InvalidFormat(
                "Cannot insert into finalized index".to_string(),
            ));
        }

        let builder = self
            .builder
            .as_mut()
            .ok_or_else(|| {
                era_common::EraError::InvalidFormat(
                    "Builder must exist in Building state".to_string(),
                )
            })?;

        builder.insert(entry)
    }

    /// Check if a hash exists in the Bloom filter (fast negative lookup)
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        match self.state {
            TreeState::Building => self
                .builder
                .as_ref()
                .map(|b| b.bloom_contains(hash))
                .unwrap_or(false),
            TreeState::Finalized => self
                .reader
                .as_ref()
                .map(|r| r.read().bloom_contains(hash))
                .unwrap_or(false),
        }
    }

    /// Get the number of spill files created (always 0 with Redb — kept for API compat)
    pub fn spill_count(&self) -> usize {
        0
    }

    /// Get current memory usage estimate (kept for API compat)
    pub fn memtable_size_bytes(&self) -> usize {
        // With Redb, entries are on disk. Return entry_count * entry_size as estimate.
        self.builder
            .as_ref()
            .map(|b| b.entry_count() * IndexEntry::memory_size())
            .unwrap_or(0)
    }

    /// Finalize the index and transition to read mode
    ///
    /// Reads all entries from the Redb staging database, builds the
    /// hierarchical index structure (Bloom + L1 + L2), and returns
    /// a read-only view.
    pub fn finalize(mut self) -> Result<LsmTreeReader> {
        if self.state != TreeState::Building {
            return Err(era_common::EraError::InvalidFormat(
                "Index already finalized".to_string(),
            ));
        }

        let builder = self
            .builder
            .take()
            .ok_or_else(|| {
                era_common::EraError::InvalidFormat(
                    "Builder must exist in Building state".to_string(),
                )
            })?;

        // Read all entries from Redb in sorted order
        let merged_entries = builder.store().drain_sorted()?;
        let bloom_clone = builder.bloom().clone();
        let entries_count = merged_entries.len();

        // Build MetaIndex + IndexReader from entries
        let meta = MetaIndex::new();
        let bloom_bytes = crate::serialize_bloom(&bloom_clone)?;
        let mut meta_with_bloom = meta;
        meta_with_bloom.set_bloom_filter(bloom_bytes);

        let reader = IndexReader::from_memory(meta_with_bloom, bloom_clone, merged_entries)?;

        tracing::info!("Index finalized: {} total entries", entries_count);

        self.reader = Some(Arc::new(RwLock::new(reader)));
        self.state = TreeState::Finalized;

        let reader_arc = self
            .reader
            .as_ref()
            .ok_or_else(|| {
                era_common::EraError::InvalidFormat("Reader must exist after finalization".into())
            })?
            .clone();

        Ok(LsmTreeReader {
            reader: reader_arc,
        })
    }

    /// Recover an index from a volume (cold recovery)
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

/// Read-only view of a finalized index
///
/// Provides fast lookups via Bloom filters and hierarchical indexing.
#[derive(Clone)]
pub struct LsmTreeReader {
    reader: Arc<RwLock<IndexReader>>,
}

impl LsmTreeReader {
    /// Lookup a chunk hash in the index
    pub fn lookup(&self, hash: &ChunkHash) -> Result<Option<IndexLocation>> {
        self.reader.write().lookup(hash)
    }

    /// Check if a hash exists in the Bloom filter (fast O(1) negative lookup)
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
    fn test_lsm_tree_reader_bloom_contains_efficiency() {
        let mut tree = LsmTree::new_default();

        for i in 0..100u64 {
            let entry = IndexEntry::new(test_hash(i), VolumeId::new(), BlockId::new(i), 0, 4096);
            tree.insert(entry).unwrap();
        }

        assert!(tree.bloom_contains(&test_hash(50)));
        assert!(!tree.bloom_contains(&test_hash(9999)));

        let reader = tree.finalize().expect("finalize should succeed");

        assert!(reader.bloom_contains(&test_hash(50)));
        assert!(reader.bloom_contains(&test_hash(0)));
        assert!(reader.bloom_contains(&test_hash(99)));
        assert!(!reader.bloom_contains(&test_hash(9999)));
    }

    #[test]
    fn test_index_reader_bloom_contains_exists() {
        use crate::reader::IndexReader;

        let meta = crate::MetaIndex::new();
        let bloom = bloomfilter::Bloom::new_for_fp_rate(1000, 0.01);
        let reader = IndexReader::from_memory(meta, bloom, vec![])
            .expect("IndexReader creation should succeed");

        let _result = reader.bloom_contains(&test_hash(25));
    }
}
