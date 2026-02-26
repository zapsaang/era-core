//! # ChunkIndex — Redb-backed Index Orchestrator
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

/// Configuration for ChunkIndex
#[derive(Debug, Clone)]
pub struct ChunkIndexConfig {
    /// Memory limit for bloom filter sizing (bytes)
    pub mem_limit: usize,
    /// Directory for Redb staging file
    pub temp_dir: PathBuf,
}

impl Default for ChunkIndexConfig {
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
/// use era_index::{ChunkIndex, ChunkIndexConfig, IndexEntry};
/// use era_common::{ChunkHash, VolumeId, BlockId};
///
/// # fn example() -> era_common::Result<()> {
/// let config = ChunkIndexConfig::default();
/// let mut tree = ChunkIndex::new(config)?;
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
pub struct ChunkIndex {
    /// Index builder (write path) — backed by Redb
    builder: Option<IndexBuilder>,
    /// Index reader (read path)
    reader: Option<Arc<RwLock<IndexReader>>>,
    /// State tracking
    state: IndexState,
}

/// Runtime state machine for `ChunkIndex`.
///
/// # State Transitions
///
/// ```text
///   Building ──▶ Finalized   (via finalize())
/// ```
///
/// - **`Building`**: The index is accepting writes. `insert()` and `finalize()` are valid.
/// - **`Finalized`**: The index is read-only. Only lookups (`bloom_contains`, via reader) are valid.
///
/// Invalid transitions produce runtime errors:
/// - `insert()` after `finalize()` → `EraError::InvalidFormat`
/// - `finalize()` after `finalize()` → `EraError::InvalidFormat`
///
/// A typestate approach was considered but rejected because adversarial tests
/// (V11-F7) assert runtime errors from invalid transitions; consuming `self`
/// in `finalize()` would make those tests fail to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexState {
    /// Index is open for writes (`insert`, `finalize`).
    Building,
    /// Index is sealed; only read operations are valid.
    Finalized,
}

impl ChunkIndex {
    /// Create a new ChunkIndex for index construction
    pub fn new(config: ChunkIndexConfig) -> Result<Self> {
        // Use IndexBuilder::new() which creates a unique temp Redb file
        // via tempfile::Builder (avoids filename collisions in parallel tests)
        let builder = IndexBuilder::new(config.mem_limit)?;

        Ok(Self {
            builder: Some(builder),
            reader: None,
            state: IndexState::Building,
        })
    }

    /// Create with default configuration
    pub fn new_default() -> Result<Self> {
        Self::new(ChunkIndexConfig::default())
    }

    /// Returns `Ok(())` if the index is in `Building` state, or an error if finalized.
    ///
    /// Consolidates the state guard used by `insert()` and `finalize()` so that
    /// error messages and transition logic live in one place.
    fn require_building(&self, operation: &str) -> Result<()> {
        if self.state != IndexState::Building {
            return Err(era_common::EraError::InvalidFormat(format!(
                "Cannot {operation}: index already finalized"
            )));
        }
        Ok(())
    }

    /// Insert an entry into the index.
    ///
    /// Only valid in `Building` state. Returns `EraError::InvalidFormat` if
    /// the index has already been finalized.
    pub fn insert(&mut self, entry: IndexEntry) -> Result<()> {
        self.require_building("insert")?;

        // Defensive: builder must be Some when state == Building.
        // The state guard above already validates this invariant.
        let builder = self.builder.as_mut().ok_or_else(|| {
            era_common::EraError::InvalidFormat("Builder must exist in Building state".to_string())
        })?;

        builder.insert(entry)
    }

    /// Check if a hash exists in the Bloom filter (fast negative lookup).
    ///
    /// Works in both states:
    /// - **`Building`**: checks the builder's in-memory Bloom filter.
    /// - **`Finalized`**: checks the reader's serialized Bloom filter.
    ///
    /// Returns `false` if the backing object is unexpectedly absent.
    pub fn bloom_contains(&self, hash: &ChunkHash) -> bool {
        match self.state {
            IndexState::Building => self
                .builder
                .as_ref()
                .map(|b| b.bloom_contains(hash))
                .unwrap_or(false),
            IndexState::Finalized => self
                .reader
                .as_ref()
                .map(|r| r.read().bloom_contains(hash))
                .unwrap_or(false),
        }
    }

    /// Finalize the index and transition to read mode.
    ///
    /// Reads all entries from the Redb staging database, builds the
    /// hierarchical index structure (Bloom + L1 + L2), and returns
    /// a read-only view.
    ///
    /// On success the index transitions to `Finalized` state; further
    /// inserts or finalizations will return errors. On failure the index
    /// remains in `Building` state and `finalize` can be retried.
    pub fn finalize(&mut self) -> Result<ChunkIndexReader> {
        self.require_building("finalize")?;

        // Defensive: builder must be Some when state == Building.
        // The state guard above already validates this invariant.
        let builder = self.builder.as_mut().ok_or_else(|| {
            era_common::EraError::InvalidFormat("Builder must exist in Building state".to_string())
        })?;

        // Flush buffer and drain entries as pre-built pages.
        let bloom_clone = builder.bloom().clone();
        let pages = builder.read_sorted_pages()?;
        // NOTE: This path keeps using read_sorted_pages() (Vec materialization) because
        // IndexReader::from_pages() requires all pages in memory to build the L2 lookup.
        // The streaming for_each_sorted_page() is used in builder.rs finalize() which
        // writes pages to volume one at a time and doesn't need them all in memory.
        let entries_count: usize = pages.iter().map(|(p, _)| p.len()).sum();

        // Build MetaIndex + IndexReader from pages
        let meta = MetaIndex::new();
        let bloom_bytes = crate::serialize_bloom(&bloom_clone)?;
        let mut meta_with_bloom = meta;
        meta_with_bloom.set_bloom_filter(bloom_bytes)?;

        let reader = IndexReader::from_pages(meta_with_bloom, bloom_clone, pages)?;

        tracing::info!("Index finalized: {} total entries", entries_count);

        self.reader = Some(Arc::new(RwLock::new(reader)));
        self.state = IndexState::Finalized;

        let reader_arc = self
            .reader
            .as_ref()
            .ok_or_else(|| {
                era_common::EraError::InvalidFormat("Reader must exist after finalization".into())
            })?
            .clone();

        Ok(ChunkIndexReader { reader: reader_arc })
    }

    /// Recover an index from a volume (cold recovery)
    pub async fn recover_from_volume<R: StorageReader>(
        volume_reader: &VolumeReader<R>,
        session: &KeySession,
        volume_key: &VolumeKey,
        nonce_context: [u8; 16],
        timeout: Option<std::time::Duration>,
    ) -> Result<ChunkIndexReader> {
        let reader = IndexReader::recover_from_volume(
            volume_reader,
            session,
            volume_key,
            nonce_context,
            timeout,
        )
        .await?;

        Ok(ChunkIndexReader {
            reader: Arc::new(RwLock::new(reader)),
        })
    }
}

/// Read-only view of a finalized index
///
/// Provides fast lookups via Bloom filters and hierarchical indexing.
#[derive(Clone)]
pub struct ChunkIndexReader {
    reader: Arc<RwLock<IndexReader>>,
}

impl ChunkIndexReader {
    /// Lookup a chunk hash in the index
    pub fn lookup(&self, hash: &ChunkHash) -> Result<Option<IndexLocation>> {
        self.reader.read().lookup(hash)
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
    fn test_chunk_index_creation() {
        let tree = ChunkIndex::new_default().unwrap();
        assert_eq!(tree.state, IndexState::Building);
    }

    #[test]
    fn test_chunk_index_insert() {
        let mut tree = ChunkIndex::new_default().unwrap();

        let entry = IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 4096);

        tree.insert(entry).unwrap();
        assert!(tree.bloom_contains(&test_hash(100)));
        assert!(!tree.bloom_contains(&test_hash(999)));
    }

    #[test]
    fn test_chunk_index_reader_bloom_contains_efficiency() {
        let mut tree = ChunkIndex::new_default().unwrap();

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
