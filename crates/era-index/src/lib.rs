//! # ERA Index V2.1 - Native Log-Structured Indexing
//!
//! Native, log-structured indexing engine for the ERA archive system.
//! Replaces RocksDB with a custom, zero-trust implementation.
//!
//! ## Key Features
//!
//! - **Native Implementation**: No external database dependencies
//! - **Secure Spilling**: Ephemeral encryption for temporary files
//! - **Bloom Filters**: Fast negative lookups (>99% rejection rate)
//! - **Memory Bounded**: Fixed 64MB MemTable limit
//! - **Tiered Merging**: Prevents file descriptor exhaustion
//!
//! ## Usage
//!
//! ```no_run
//! use era_index::{LsmTree, LsmTreeConfig, IndexEntry};
//! use era_common::{ChunkHash, VolumeId, BlockId};
//!
//! # fn example() -> era_common::Result<()> {
//! // Create a new index
//! let mut tree = LsmTree::new_default();
//!
//! // Insert entries
//! let entry = IndexEntry::new(
//!     ChunkHash::from_bytes([0u8; 32]),
//!     VolumeId::new(),
//!     BlockId::new(0),
//!     0,
//!     4096,
//! );
//! tree.insert(entry)?;
//!
//! // Finalize and query
//! let reader = tree.finalize()?;
//! if let Some(location) = reader.lookup(&ChunkHash::from_bytes([0u8; 32]))? {
//!     println!("Found at block {}", location.block_id);
//! }
//! # Ok(())
//! # }
//! ```

mod builder;
mod config;
mod error;
mod lsm_tree;
mod merger;
mod metrics;
mod reader;
mod spiller;

pub use builder::IndexBuilder;
pub use config::{IndexConfig, IndexConfigBuilder};
pub use error::IndexError;
pub use lsm_tree::{LsmTree, LsmTreeConfig, LsmTreeReader};
pub use merger::TieredMerger;
pub use metrics::IndexMetrics;
pub use reader::{IndexLocation, IndexReader};
pub use spiller::Spiller;

// Re-export for convenience
pub use era_common::{BlockId, BlockLocation, ChunkHash, VolumeId};

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Number of entries per L2 Index Page
/// Targets ~320KB uncompressed (fits in CPU L2 cache)
pub const ENTRIES_PER_PAGE: usize = 8192;

/// A single entry mapping a chunk hash to its physical location
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
)]
#[archive(check_bytes)]
pub struct IndexEntry {
    /// Hash of the chunk (primary key)
    pub hash: ChunkHash,
    /// Volume containing the chunk
    pub volume_id: VolumeId,
    /// Block containing the chunk
    pub block_id: BlockId,
    /// Offset within the block
    pub offset: u32,
    /// Length of the chunk
    pub length: u32,
}

impl IndexEntry {
    /// Create a new index entry
    pub fn new(
        hash: ChunkHash,
        volume_id: VolumeId,
        block_id: BlockId,
        offset: u32,
        length: u32,
    ) -> Self {
        Self {
            hash,
            volume_id,
            block_id,
            offset,
            length,
        }
    }

    /// Get the memory size of this entry
    pub fn memory_size() -> usize {
        std::mem::size_of::<Self>()
    }
}

/// An L2 Index Page (fundamental unit of storage)
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct IndexPage {
    /// Minimum hash in this page (for range queries)
    pub min_hash: ChunkHash,
    /// Maximum hash in this page (for range queries)
    pub max_hash: ChunkHash,
    /// Sorted list of entries
    pub entries: Vec<IndexEntry>,
}

impl IndexPage {
    /// Create a new index page from sorted entries
    pub fn new(mut entries: Vec<IndexEntry>) -> Self {
        // Ensure entries are sorted
        entries.sort_unstable_by_key(|e| e.hash);

        let min_hash = entries.first().expect("IndexPage cannot be empty").hash;
        let max_hash = entries.last().expect("IndexPage cannot be empty").hash;

        Self {
            min_hash,
            max_hash,
            entries,
        }
    }

    /// Binary search for a hash within this page
    pub fn find(&self, hash: &ChunkHash) -> Option<&IndexEntry> {
        match self.entries.binary_search_by_key(hash, |e| e.hash) {
            Ok(idx) => Some(&self.entries[idx]),
            Err(_) => None,
        }
    }

    /// Check if a hash could be in this page's range
    pub fn contains_range(&self, hash: &ChunkHash) -> bool {
        hash >= &self.min_hash && hash <= &self.max_hash
    }
}

/// A pointer to an L2 Index Page
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct PagePointer {
    /// Minimum hash in the target page
    pub min_hash: ChunkHash,
    /// Maximum hash in the target page
    pub max_hash: ChunkHash,
    /// Block ID of the L2 page
    pub block_id: BlockId,
}

/// The L1 Meta-Index (root directory)
#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct MetaIndex {
    /// Sparse index of L2 pages
    pub pages: Vec<PagePointer>,
    /// Serialized Bloom filter (for fast negative lookups)
    pub bloom_filter: Vec<u8>,
}

impl MetaIndex {
    /// Create a new empty meta-index
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            bloom_filter: Vec::new(),
        }
    }

    /// Add a page pointer to the meta-index
    pub fn add_page(&mut self, min_hash: ChunkHash, max_hash: ChunkHash, block_id: BlockId) {
        self.pages.push(PagePointer {
            min_hash,
            max_hash,
            block_id,
        });
    }

    /// Find the page that might contain a given hash
    pub fn find_page(&self, hash: &ChunkHash) -> Option<&PagePointer> {
        self.pages
            .iter()
            .find(|page_ptr| hash >= &page_ptr.min_hash && hash <= &page_ptr.max_hash)
    }

    /// Set the Bloom filter data
    pub fn set_bloom_filter(&mut self, bloom_data: Vec<u8>) {
        self.bloom_filter = bloom_data;
    }
}

impl Default for MetaIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_index_entry_ordering() {
        let e1 = IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024);
        let e2 = IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 0, 1024);

        assert!(e1 < e2);
    }

    #[test]
    fn test_index_page_sorting() {
        let entries = vec![
            IndexEntry::new(test_hash(300), VolumeId::new(), BlockId::new(0), 0, 1024),
            IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024),
            IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 0, 1024),
        ];

        let page = IndexPage::new(entries);

        assert_eq!(page.min_hash, test_hash(100));
        assert_eq!(page.max_hash, test_hash(300));
        assert_eq!(page.entries.len(), 3);
        assert_eq!(page.entries[0].hash, test_hash(100));
        assert_eq!(page.entries[1].hash, test_hash(200));
        assert_eq!(page.entries[2].hash, test_hash(300));
    }

    #[test]
    fn test_index_page_find() {
        let entries = vec![
            IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024),
            IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 1024, 1024),
            IndexEntry::new(test_hash(300), VolumeId::new(), BlockId::new(0), 2048, 1024),
        ];

        let page = IndexPage::new(entries);

        assert!(page.find(&test_hash(200)).is_some());
        assert!(page.find(&test_hash(150)).is_none());
        assert_eq!(page.find(&test_hash(200)).unwrap().offset, 1024);
    }

    #[test]
    fn test_meta_index_find() {
        let mut meta = MetaIndex::new();
        meta.add_page(test_hash(0), test_hash(999), BlockId::new(0));
        meta.add_page(test_hash(1000), test_hash(1999), BlockId::new(1));
        meta.add_page(test_hash(2000), test_hash(2999), BlockId::new(2));

        assert_eq!(
            meta.find_page(&test_hash(500)).unwrap().block_id,
            BlockId::new(0)
        );
        assert_eq!(
            meta.find_page(&test_hash(1500)).unwrap().block_id,
            BlockId::new(1)
        );
        assert_eq!(
            meta.find_page(&test_hash(2500)).unwrap().block_id,
            BlockId::new(2)
        );
        assert!(meta.find_page(&test_hash(3000)).is_none());
    }
}
