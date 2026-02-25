//! # ERA Index — Redb-backed Chunk Deduplication Index
//!
//! ACID-compliant chunk deduplication index for the ERA archive system.
//! Uses Redb 2.1 as the staging database per RFC-023.
//!
//! ## Key Features
//!
//! - **Redb 2.1**: ACID-compliant embedded B-tree database
//! - **Bloom Filters**: Fast negative lookups (>99% rejection rate)
//! - **Zero-Copy**: rkyv serialization with `check_archived_root` validation
//! - **Self-Contained**: Index embedded as encrypted blocks in `.era` volume
//!
//! ## Usage
//!
//! ```no_run
//! use era_index::{ChunkIndex, ChunkIndexConfig, IndexEntry};
//! use era_common::{ChunkHash, VolumeId, BlockId};
//!
//! # fn example() -> era_common::Result<()> {
//! // Create a new index
//! let mut tree = ChunkIndex::new_default()?;
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

mod bloom_serde;
mod builder;
mod error;
mod chunk_index;
mod reader;
mod schema;
mod store;

pub use bloom_serde::{deserialize_bloom, serialize_bloom, BloomFilterData};
pub use builder::IndexBuilder;
pub use chunk_index::{ChunkIndex, ChunkIndexConfig, ChunkIndexReader};
pub use error::IndexError;
pub use reader::{IndexLocation, IndexReader};
pub use store::IndexStore;

// Re-export for convenience
pub use era_common::{BlockId, BlockLocation, ChunkHash, VolumeId};

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

/// Number of entries per L2 Index Page
/// Targets ~320KB uncompressed (fits in CPU L2 cache)
pub const ENTRIES_PER_PAGE: usize = 8192;

/// A single entry mapping a chunk hash to its physical location
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Archive, RkyvDeserialize, RkyvSerialize,
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
#[derive(Debug, Clone, Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct IndexPage {
    /// Minimum hash in this page (for range queries)
    min_hash: ChunkHash,
    /// Maximum hash in this page (for range queries)
    max_hash: ChunkHash,
    /// Sorted list of entries
    entries: Vec<IndexEntry>,
}

impl IndexPage {
    /// Create a new index page from sorted entries, returning an error if entries is empty
    /// or exceeds ENTRIES_PER_PAGE.
    pub fn try_new(mut entries: Vec<IndexEntry>) -> era_common::Result<Self> {
        if entries.is_empty() {
            return Err(era_common::EraError::InvalidFormat(
                "IndexPage cannot be empty".into(),
            ));
        }
        if entries.len() > ENTRIES_PER_PAGE {
            return Err(era_common::EraError::InvalidFormat(format!(
                "IndexPage too large: {} entries (max {})",
                entries.len(),
                ENTRIES_PER_PAGE
            )));
        }
        entries.sort_unstable_by_key(|e| e.hash);
        // Remove duplicates by hash (keep first occurrence)
        entries.dedup_by_key(|e| e.hash);
        let min_hash = entries.first().unwrap().hash;
        let max_hash = entries.last().unwrap().hash;
        Ok(Self {
            min_hash,
            max_hash,
            entries,
        })
    }

    /// Get the minimum hash in this page
    pub fn min_hash(&self) -> &ChunkHash {
        &self.min_hash
    }

    /// Get the maximum hash in this page
    pub fn max_hash(&self) -> &ChunkHash {
        &self.max_hash
    }

    /// Get the sorted entries in this page
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// Get the number of entries in this page
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if this page is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
#[derive(Debug, Clone, Copy, Archive, RkyvDeserialize, RkyvSerialize)]
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
#[derive(Debug, Clone, Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct MetaIndex {
    /// Sparse index of L2 pages
    pages: Vec<PagePointer>,
    /// Serialized Bloom filter (for fast negative lookups)
    bloom_filter: Vec<u8>,
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
    ///
    /// Pages must be added in ascending, non-overlapping order (by min_hash).
    /// Returns an error if this invariant is violated.
    pub fn add_page(
        &mut self,
        min_hash: ChunkHash,
        max_hash: ChunkHash,
        block_id: BlockId,
    ) -> era_common::Result<()> {
        if let Some(last) = self.pages.last() {
            if min_hash <= last.max_hash {
                return Err(era_common::EraError::InvalidFormat(
                    "Pages must be added in ascending, non-overlapping order".into(),
                ));
            }
        }
        self.pages.push(PagePointer {
            min_hash,
            max_hash,
            block_id,
        });
        Ok(())
    }

    /// Find the page that might contain a given hash
    ///
    /// Uses binary search on sorted page boundaries for O(log n) lookup.
    /// Pages must be sorted by min_hash (guaranteed by IndexBuilder which
    /// processes entries in sorted order).
    pub fn find_page(&self, hash: &ChunkHash) -> Option<&PagePointer> {
        if self.pages.is_empty() {
            return None;
        }

        // Binary search: find the last page whose min_hash <= hash
        let idx = match self.pages.binary_search_by_key(hash, |p| p.min_hash) {
            Ok(i) => i,
            Err(0) => return None, // hash is before all pages
            Err(i) => i - 1,       // page at i-1 has the largest min_hash <= hash
        };

        let page = &self.pages[idx];
        if hash >= &page.min_hash && hash <= &page.max_hash {
            Some(page)
        } else {
            None
        }
    }

    /// Get read-only access to the page pointers
    pub fn pages(&self) -> &[PagePointer] {
        &self.pages
    }

    /// Get read-only access to the serialized bloom filter data
    pub fn bloom_filter(&self) -> &[u8] {
        &self.bloom_filter
    }

    /// Set the Bloom filter data, validating it deserializes correctly
    pub fn set_bloom_filter(&mut self, bloom_data: Vec<u8>) -> era_common::Result<()> {
        crate::deserialize_bloom(&bloom_data)?;
        self.bloom_filter = bloom_data;
        Ok(())
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

        let page = IndexPage::try_new(entries).unwrap();

        assert_eq!(*page.min_hash(), test_hash(100));
        assert_eq!(*page.max_hash(), test_hash(300));
        assert_eq!(page.len(), 3);
        assert_eq!(page.entries()[0].hash, test_hash(100));
        assert_eq!(page.entries()[1].hash, test_hash(200));
        assert_eq!(page.entries()[2].hash, test_hash(300));
    }

    #[test]
    fn test_index_page_find() {
        let entries = vec![
            IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024),
            IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 1024, 1024),
            IndexEntry::new(test_hash(300), VolumeId::new(), BlockId::new(0), 2048, 1024),
        ];

        let page = IndexPage::try_new(entries).unwrap();

        assert!(page.find(&test_hash(200)).is_some());
        assert!(page.find(&test_hash(150)).is_none());
        assert_eq!(page.find(&test_hash(200)).unwrap().offset, 1024);
    }

    #[test]
    fn test_meta_index_find() {
        let mut meta = MetaIndex::new();
        meta.add_page(test_hash(0), test_hash(999), BlockId::new(0))
            .unwrap();
        meta.add_page(test_hash(1000), test_hash(1999), BlockId::new(1))
            .unwrap();
        meta.add_page(test_hash(2000), test_hash(2999), BlockId::new(2))
            .unwrap();

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
