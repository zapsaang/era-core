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
//! )?;
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

mod chunk_index;
mod reader;
mod schema;
mod store;

pub use bloom_serde::{deserialize_bloom, serialize_bloom, BloomFilterData};
pub use builder::IndexBuilder;
pub use chunk_index::{ChunkIndex, ChunkIndexConfig, ChunkIndexReader};

pub use reader::{IndexLocation, IndexReader};
pub use store::IndexStore;

// Re-export for convenience
pub use era_common::{BlockId, BlockLocation, ChunkHash, VolumeId};

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

/// Number of entries per L2 Index Page
/// Targets ~320KB uncompressed (fits in CPU L2 cache)
pub const ENTRIES_PER_PAGE: usize = 8192;
/// V24-F7 fix: Maximum number of L1 meta-index pages.
/// Consolidated from duplicate definitions in add_page() and validate_meta_index().
pub(crate) const MAX_META_PAGES: usize = 10_000;
/// V25-F3 fix: consolidate MAX_BLOOM_ITEMS to single pub(crate) const.
/// Maximum bloom filter items to prevent excessive memory allocation.
/// Previously duplicated in builder.rs and store.rs.
pub(crate) const MAX_BLOOM_ITEMS: usize = 100_000_000;

/// A single entry mapping a chunk hash to its physical location
///
/// V24-F1 fix: Fields are `pub(crate)` to prevent external consumers from
/// bypassing the validated `new()` constructor via struct literal construction.
/// Use `new()` to create instances and accessor methods to read fields.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Archive, RkyvDeserialize, RkyvSerialize,
)]
#[archive(check_bytes)]
pub struct IndexEntry {
    /// Hash of the chunk (primary key)
    pub(crate) hash: ChunkHash, // V24-F1 fix
    /// Volume containing the chunk
    pub(crate) volume_id: VolumeId, // V24-F1 fix
    /// Block containing the chunk
    pub(crate) block_id: BlockId, // V24-F1 fix
    /// Offset within the block
    pub(crate) offset: u32, // V24-F1 fix
    /// Length of the chunk
    pub(crate) length: u32, // V24-F1 fix
}

impl IndexEntry {
    /// Create a new index entry.
    ///
    /// Returns an error if `length` is zero (V19-F3 / V17-F5) or if
    /// `offset + length` would overflow `u32` (V19-F3 / V17-F6).
    /// These conditions indicate a bug in the caller and are rejected
    /// as hard errors since backward compatibility is not required.
    pub fn new(
        hash: ChunkHash,
        volume_id: VolumeId,
        block_id: BlockId,
        offset: u32,
        length: u32,
    ) -> era_common::Result<Self> {
        // V19-F3 / V17-F5: Zero-length entries are nonsensical — reject.
        if length == 0 {
            return Err(era_common::EraError::InvalidFormat(
                "IndexEntry::new: length must not be 0".into(),
            ));
        }
        // V19-F3 / V17-F6: Detect offset+length overflow that would corrupt range queries.
        if offset.checked_add(length).is_none() {
            return Err(era_common::EraError::InvalidFormat(format!(
                "IndexEntry::new: offset({}) + length({}) overflows u32",
                offset, length
            )));
        }
        Ok(Self {
            hash,
            volume_id,
            block_id,
            offset,
            length,
        })
    }

    /// Get the memory size of this entry
    pub fn memory_size() -> usize {
        std::mem::size_of::<Self>()
    }

    // V24-F1 fix: Public accessor methods for encapsulated fields.

    /// Get the chunk hash (primary key).
    #[must_use]
    pub fn hash(&self) -> &ChunkHash {
        &self.hash
    }

    /// Get the volume ID containing this chunk.
    #[must_use]
    pub fn volume_id(&self) -> VolumeId {
        self.volume_id
    }

    /// Get the block ID containing this chunk.
    #[must_use]
    pub fn block_id(&self) -> BlockId {
        self.block_id
    }

    /// Get the offset within the block.
    #[must_use]
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Get the length of the chunk.
    #[must_use]
    pub fn length(&self) -> u32 {
        self.length
    }
}

// V22-F9 fix: Add Display impl for IndexEntry to enable human-readable logging.
// Previously, logging an IndexEntry required Debug formatting which shows raw byte arrays.
// Display provides a concise summary suitable for tracing::info! and similar contexts.
impl std::fmt::Display for IndexEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IndexEntry(hash={:x}{:x}..{:x}{:x}, vol={}, blk={}, off={}, len={})",
            self.hash.as_bytes()[0],
            self.hash.as_bytes()[1],
            self.hash.as_bytes()[30],
            self.hash.as_bytes()[31],
            self.volume_id,
            self.block_id.sequence(),
            self.offset,
            self.length,
        )
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
    ///
    /// **Note:** Entries are sorted by hash and deduplicated (first-write-wins semantics).
    /// Duplicate hashes are silently removed, keeping only the first occurrence.
    /// The returned page may contain fewer entries than the input Vec.
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
        // V18-F5 fix: Use stable sort to preserve first-write-wins determinism
        entries.sort_by_key(|e| e.hash);
        let pre_dedup_len = entries.len();
        // Remove duplicates by hash (keep first occurrence)
        entries.dedup_by_key(|e| e.hash);
        // V17-F11 fix: Log when duplicates are silently removed for observability
        if entries.len() < pre_dedup_len {
            tracing::debug!(
                "IndexPage::try_new removed {} duplicate entries",
                pre_dedup_len - entries.len()
            );
        }
        // V19-F9 fix: Assert strict sorted order after dedup.
        // After dedup, all remaining entries must have strictly increasing hashes.
        // This catches subtle bugs where dedup_by_key fails to merge all duplicates.
        debug_assert!(
            entries.windows(2).all(|w| w[0].hash < w[1].hash),
            "post-dedup entries must be strictly sorted (try_new)"
        );
        let min_hash = entries
            .first()
            .expect("guaranteed non-empty after is_empty check")
            .hash;
        let max_hash = entries
            .last()
            .expect("guaranteed non-empty after is_empty check")
            .hash;
        Ok(Self {
            min_hash,
            max_hash,
            entries,
        })
    }

    /// Create a new index page from entries that are ALREADY sorted by hash.
    ///
    /// V17-F2 fix: Skips the O(n log n) sort when the caller guarantees sorted input
    /// (e.g., from Redb B-tree iteration which yields keys in sorted order).
    /// Entries are still deduplicated. Returns an error if entries is empty or
    /// exceeds ENTRIES_PER_PAGE.
    /// V21-F3 fix: Made public so external consumers (like era-engine) can use it
    /// when they know input is already sorted, avoiding the O(n log n) sort in try_new().
    ///
    pub fn try_new_presorted(mut entries: Vec<IndexEntry>) -> era_common::Result<Self> {
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
        // V18-F11 fix: Runtime sorted invariant check (was debug_assert only).
        // Unsorted input silently breaks binary search in release builds.
        if !entries.windows(2).all(|w| w[0].hash <= w[1].hash) {
            return Err(era_common::EraError::InvalidFormat(
                "try_new_presorted: entries must be sorted by hash".into(),
            ));
        }
        let pre_dedup_len = entries.len();
        entries.dedup_by_key(|e| e.hash);
        if entries.len() < pre_dedup_len {
            tracing::debug!(
                "IndexPage::try_new_presorted removed {} duplicate entries",
                pre_dedup_len - entries.len()
            );
        }
        // V19-F9 fix: Assert strict sorted order after dedup (presorted path).
        debug_assert!(
            entries.windows(2).all(|w| w[0].hash < w[1].hash),
            "post-dedup entries must be strictly sorted (try_new_presorted)"
        );
        let min_hash = entries
            .first()
            .expect("guaranteed non-empty after is_empty check")
            .hash;
        let max_hash = entries
            .last()
            .expect("guaranteed non-empty after is_empty check")
            .hash;
        Ok(Self {
            min_hash,
            max_hash,
            entries,
        })
    }

    /// Get the minimum hash in this page
    #[must_use]
    pub fn min_hash(&self) -> &ChunkHash {
        &self.min_hash
    }

    /// Get the maximum hash in this page
    #[must_use]
    pub fn max_hash(&self) -> &ChunkHash {
        &self.max_hash
    }

    /// Get the sorted entries in this page
    #[must_use]
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// Get the number of entries in this page
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if this page is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Binary search for a hash within this page
    #[must_use]
    pub fn find(&self, hash: &ChunkHash) -> Option<&IndexEntry> {
        match self.entries.binary_search_by_key(hash, |e| e.hash) {
            Ok(idx) => Some(&self.entries[idx]),
            Err(_) => None,
        }
    }

    /// Check if a hash could be in this page's range (inclusive bounds).
    ///
    /// Available as a utility method for external consumers and test coverage.
    /// The production lookup path uses `MetaIndex::find_page()` for range selection
    /// and `IndexPage::find()` for exact match.
    #[must_use]
    pub fn contains_range(&self, hash: &ChunkHash) -> bool {
        hash >= &self.min_hash && hash <= &self.max_hash
    }
}

/// A pointer to an L2 Index Page
///
/// V24-F2 fix: Fields are `pub(crate)` to prevent external consumers from
/// constructing PagePointers directly, bypassing MetaIndex::add_page() validation.
/// Use accessor methods to read fields.
#[derive(Debug, Clone, Copy, Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct PagePointer {
    pub(crate) min_hash: ChunkHash,
    pub(crate) max_hash: ChunkHash,
    pub(crate) block_id: BlockId,
    pub(crate) physical_offset: u64,
    pub(crate) encrypted_size: u32,
}

// V24-F2 fix: Public accessor methods for encapsulated fields.
impl PagePointer {
    /// Get the minimum hash in the target page.
    #[must_use]
    pub fn min_hash(&self) -> &ChunkHash {
        &self.min_hash
    }

    /// Get the maximum hash in the target page.
    #[must_use]
    pub fn max_hash(&self) -> &ChunkHash {
        &self.max_hash
    }

    /// Get the block ID of the L2 page.
    #[must_use]
    pub fn block_id(&self) -> BlockId {
        self.block_id
    }

    #[must_use]
    pub fn physical_offset(&self) -> u64 {
        self.physical_offset
    }

    #[must_use]
    pub fn encrypted_size(&self) -> u32 {
        self.encrypted_size
    }

    #[must_use]
    pub fn has_location(&self) -> bool {
        self.physical_offset != 0
    }
}

/// The L1 Meta-Index (root directory)
#[derive(Debug, Clone, Archive, RkyvDeserialize, RkyvSerialize)]
#[archive(check_bytes)]
pub struct MetaIndex {
    /// Sparse index of L2 pages
    pages: Vec<PagePointer>,
    /// Serialized Bloom filter (for fast negative lookups).
    /// **Must be set via `set_bloom_filter()` before use.** The default (empty Vec)
    /// will cause `deserialize_bloom()` to return a deserialization error.
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
    ///
    /// # Design Decision (V13-F5)
    ///
    /// Uses `<=` (not `<`) to reject shared boundary hashes. This prevents
    /// ambiguous ownership where the same hash could be looked up in two pages.
    /// The trade-off is that legitimate adjacent pages sharing an exact boundary
    /// hash are rejected; callers must ensure page boundaries are strictly
    /// non-overlapping.
    pub fn add_page(
        &mut self,
        min_hash: ChunkHash,
        max_hash: ChunkHash,
        block_id: BlockId,
        physical_offset: u64,
        encrypted_size: u32,
    ) -> era_common::Result<()> {
        // V18-F9 fix: Reject inverted hash ranges that would break binary search
        if min_hash > max_hash {
            return Err(era_common::EraError::InvalidFormat(
                "PagePointer min_hash must be <= max_hash".into(),
            ));
        }
        if let Some(last) = self.pages.last() {
            if min_hash <= last.max_hash {
                return Err(era_common::EraError::InvalidFormat(
                    "Pages must be added in ascending, non-overlapping order".into(),
                ));
            }
        }
        // V19-F2 fix: Runtime check for duplicate block_ids (was debug_assert only).
        // Duplicate block_ids cause ambiguous page resolution in IndexReader.
        // V22-F4 fix: Document bounded O(n) cost. This linear scan is bounded by
        // MAX_META_PAGES (10,000) checked below, making worst-case cost 10K comparisons.
        // A HashSet would reduce to O(1) but MetaIndex derives rkyv serialization,
        // preventing non-serializable fields. The bounded cost is acceptable.
        if self.pages.iter().any(|p| p.block_id == block_id) {
            return Err(era_common::EraError::InvalidFormat(format!(
                "MetaIndex::add_page: duplicate block_id {}",
                block_id.sequence()
            )));
        }
        // V19-F10 fix: Enforce maximum page count at the add_page() call site.
        if self.pages.len() >= MAX_META_PAGES {
            return Err(era_common::EraError::InvalidFormat(format!(
                "MetaIndex::add_page: page count {} would exceed maximum {}",
                self.pages.len() + 1,
                MAX_META_PAGES
            )));
        }
        self.pages.push(PagePointer {
            min_hash,
            max_hash,
            block_id,
            physical_offset,
            encrypted_size,
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
            Err(0) => {
                // V21-F10 fix: Trace-level log for hashes before the first page's range.
                // This is expected behavior but useful for debugging range misses.
                tracing::trace!("find_page: hash falls before first page range (Err(0))");
                return None;
            }
            Err(i) => i - 1, // page at i-1 has the largest min_hash <= hash
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
        // V23-F10 fix: Use BloomFilterData::from_bytes() for lightweight validation
        // instead of full deserialization via deserialize_bloom(). The prior code
        // deserialized the entire Bloom<ChunkHash> struct (allocating the bitmap
        // and rebuilding hash functions) only to validate and then drop it.
        // from_bytes() validates the rkyv archive and parameters without constructing
        // the runtime Bloom filter.
        crate::bloom_serde::BloomFilterData::from_bytes(&bloom_data)?;
        self.bloom_filter = bloom_data;
        Ok(())
    }

    /// Clear all existing page pointers.
    ///
    /// Used by `IndexReader::from_memory()` and `from_pages()` to prevent stale
    /// page pointers from a caller-provided MetaIndex (V13-F2 fix).
    pub fn clear_pages(&mut self) {
        self.pages.clear();
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
        let e1 = IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024)
            .expect("valid entry");
        let e2 = IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 0, 1024)
            .expect("valid entry");

        assert!(e1 < e2);
    }

    #[test]
    fn test_index_page_sorting() {
        let entries = vec![
            IndexEntry::new(test_hash(300), VolumeId::new(), BlockId::new(0), 0, 1024)
                .expect("valid entry"),
            IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024)
                .expect("valid entry"),
            IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 0, 1024)
                .expect("valid entry"),
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
            IndexEntry::new(test_hash(100), VolumeId::new(), BlockId::new(0), 0, 1024)
                .expect("valid entry"),
            IndexEntry::new(test_hash(200), VolumeId::new(), BlockId::new(0), 1024, 1024)
                .expect("valid entry"),
            IndexEntry::new(test_hash(300), VolumeId::new(), BlockId::new(0), 2048, 1024)
                .expect("valid entry"),
        ];
        let page = IndexPage::try_new(entries).unwrap();

        assert!(page.find(&test_hash(200)).is_some());
        assert!(page.find(&test_hash(150)).is_none());
        assert_eq!(page.find(&test_hash(200)).unwrap().offset, 1024);
    }

    #[test]
    fn test_meta_index_find() {
        let mut meta = MetaIndex::new();
        meta.add_page(test_hash(0), test_hash(999), BlockId::new(0), 0, 0)
            .unwrap();
        meta.add_page(test_hash(1000), test_hash(1999), BlockId::new(1), 0, 0)
            .unwrap();
        meta.add_page(test_hash(2000), test_hash(2999), BlockId::new(2), 0, 0)
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
