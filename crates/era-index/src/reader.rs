//! # IndexReader - Bloom + L1 + L2 Lookup
//!
//! Reads the finalized index structure efficiently.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bloomfilter::Bloom;

use era_common::{BlockId, BlockLocation, BlockType, ChunkHash, EraError, Result, VolumeId};
use era_crypto::{KeySession, VolumeKey};
use era_storage::StorageReader;
use era_volume::VolumeReader;
use rkyv::Deserialize;

#[allow(unused_imports)] // Used in tests
use super::{IndexEntry, IndexPage, MetaIndex};

// ── Legacy format types for backward-compatible deserialization ──
// rkyv 0.7 is layout-locked: adding fields to PagePointer changes the binary
// layout. Archives written before the direct-read optimization have a 3-field
// PagePointer. These types allow deserializing old MetaIndex blobs.

#[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[archive(check_bytes)]
struct LegacyPagePointer {
    min_hash: ChunkHash,
    max_hash: ChunkHash,
    block_id: BlockId,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
#[archive(check_bytes)]
struct LegacyMetaIndex {
    pages: Vec<LegacyPagePointer>,
    bloom_filter: Vec<u8>,
}

/// Deserialize a MetaIndex from rkyv bytes, with fallback to legacy format.
///
/// Tries the current 5-field PagePointer format first. If that fails (old archive),
/// falls back to the 3-field LegacyPagePointer format and converts with
/// `physical_offset=0, encrypted_size=0` (signals the reader to use scan recovery).
fn deserialize_meta_index(data: &[u8]) -> Result<MetaIndex> {
    if let Ok(archived) = rkyv::check_archived_root::<MetaIndex>(data) {
        let meta: MetaIndex = match archived.deserialize(&mut rkyv::Infallible) {
            Ok(val) => val,
            Err(never) => match never {},
        };
        return Ok(meta);
    }

    tracing::info!("MetaIndex new-format deserialization failed, trying legacy format");
    let archived = rkyv::check_archived_root::<LegacyMetaIndex>(data)
        .map_err(|e| EraError::Deserialization(format!("Legacy MetaIndex: {e}")))?;
    let legacy: LegacyMetaIndex = match archived.deserialize(&mut rkyv::Infallible) {
        Ok(val) => val,
        Err(never) => match never {},
    };

    let mut meta = MetaIndex::new();
    for lp in &legacy.pages {
        meta.add_page(lp.min_hash, lp.max_hash, lp.block_id, 0, 0)?;
    }
    meta.set_bloom_filter(legacy.bloom_filter)?;
    Ok(meta)
}

/// Simplified location result — includes volume_id for multi-volume lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexLocation {
    pub volume_id: VolumeId,
    pub block_id: BlockId,
    pub offset: u32,
    pub length: u32,
}

// V25-F1 fix: add accessor methods to IndexLocation for encapsulation parity with IndexEntry/PagePointer.
impl IndexLocation {
    /// Get the volume ID.
    #[must_use]
    pub fn volume_id(&self) -> VolumeId {
        self.volume_id
    }

    /// Get the block ID.
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

/// IndexReader provides fast lookups via Bloom + L1 + L2
pub struct IndexReader {
    /// L1 Meta-Index (sparse directory)
    meta: MetaIndex,
    /// Bloom filter (deserialized)
    bloom: Bloom<ChunkHash>,

    /// In-memory page storage (for cold recovery mode)
    embedded_pages: HashMap<BlockId, Arc<IndexPage>>,

    archive_id: [u8; 16],
    epoch_id: u32,
}

/// V21-F7 fix: Minimum valid serialized IndexPage size.
/// Derivation: rkyv ArchivedVec header (8 bytes) + ArchivedChunkHash (32 bytes) × 2
/// + at least 1 archived IndexEntry (~48 bytes) + rkyv alignment padding ≈ 64 bytes minimum.
const MIN_INDEX_PAGE_SIZE: usize = 64;

/// V21-F7 fix: Maximum valid serialized IndexPage size.
/// Derivation: ENTRIES_PER_PAGE (8192) × sizeof(archived IndexEntry) (~64 bytes)
/// + 2 × ArchivedChunkHash (32 bytes each) + rkyv Vec header + alignment
///   = ~524,288 + overhead ≈ 1MB. Rounded up to account for rkyv alignment requirements.
const MAX_INDEX_PAGE_SIZE: usize = 1024 * 1024;

/// Minimum valid serialized MetaIndex size (~40 bytes: rkyv overhead + bloom filter header)
const MIN_META_INDEX_SIZE: usize = 48;

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

/// V18-F2: Validate MetaIndex structural invariants after deserialization.
/// Checks: page count within bounds, min_hash <= max_hash per page,
/// pages in ascending non-overlapping order, unique block_ids.
fn validate_meta_index(meta: &MetaIndex) -> Result<()> {
    if meta.pages().len() > super::MAX_META_PAGES {
        return Err(EraError::IndexError(format!(
            "MetaIndex has {} pages, exceeds maximum {}",
            meta.pages().len(),
            super::MAX_META_PAGES
        )));
    }
    let mut seen_block_ids = HashSet::new();
    for (i, page) in meta.pages().iter().enumerate() {
        if page.min_hash > page.max_hash {
            return Err(EraError::IndexError(format!(
                "MetaIndex page {} has inverted hash range",
                i
            )));
        }
        if i > 0 {
            let prev = &meta.pages()[i - 1];
            if page.min_hash <= prev.max_hash {
                return Err(EraError::IndexError(format!(
                    "MetaIndex pages {} and {} overlap",
                    i - 1,
                    i
                )));
            }
        }
        if !seen_block_ids.insert(page.block_id) {
            return Err(EraError::IndexError(format!(
                "MetaIndex has duplicate block_id {}",
                page.block_id.sequence()
            )));
        }
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
        Self::open_with_context(meta, [0u8; 16], 0)
    }

    pub fn open_with_context(meta: MetaIndex, archive_id: [u8; 16], epoch_id: u32) -> Result<Self> {
        // V19-F1 fix: Validate MetaIndex structural invariants before trusting it
        validate_meta_index(&meta)?;
        // Deserialize Bloom filter using rkyv via bloom_serde
        let bloom = super::deserialize_bloom(meta.bloom_filter())?;

        Ok(Self {
            meta,
            bloom,

            embedded_pages: HashMap::new(),
            archive_id,
            epoch_id,
        })
    }

    /// Create an in-memory index reader from finalized entries
    ///
    /// This is used by ChunkIndex::finalize() to create a reader from Redb entries
    /// from merged entries without disk I/O. Entries are chunked into pages of
    /// ENTRIES_PER_PAGE to respect the L2 cache optimization.
    pub fn from_memory(meta: MetaIndex, entries: Vec<IndexEntry>) -> Result<Self> {
        let _chunking_probe = entries.chunks(super::ENTRIES_PER_PAGE).next().is_some();
        Self::from_memory_with_context(meta, entries, [0u8; 16], 0)
    }

    pub fn from_memory_with_context(
        mut meta: MetaIndex,
        entries: Vec<IndexEntry>,
        archive_id: [u8; 16],
        epoch_id: u32,
    ) -> Result<Self> {
        if entries.len() > MAX_MEMORY_ENTRIES {
            return Err(EraError::IndexError(format!(
                "from_memory: {} entries exceeds maximum {} (V6-F3)",
                entries.len(),
                MAX_MEMORY_ENTRIES
            )));
        }

        // V19-F5 fix: Rebuild bloom from actual entries instead of trusting the
        // caller-provided bloom. A caller could pass a bloom that omits entries
        // (causing false negatives) or contains phantom entries. Rebuilding from
        // the ground truth (entries) guarantees bloom ↔ entries consistency.
        let mut verified_bloom: Bloom<ChunkHash> =
            Bloom::new_for_fp_rate(entries.len().max(1024), 0.01);
        for entry in &entries {
            verified_bloom.set(&entry.hash);
        }
        let bloom = verified_bloom;
        meta.clear_pages();
        // V22-F3 fix: Use try_new_presorted() instead of try_new() since entries
        // are already sorted (they come from a sorted Vec). try_new() would
        // re-sort the already-sorted chunks, adding unnecessary O(n log n) overhead.
        let embedded_pages = if !entries.is_empty() {
            let mut pages = HashMap::with_capacity(
                (entries.len() + super::ENTRIES_PER_PAGE - 1) / super::ENTRIES_PER_PAGE.max(1),
            );
            for (block_id, chunk) in entries.chunks(super::ENTRIES_PER_PAGE).enumerate() {
                let page = IndexPage::try_new_presorted(chunk.to_vec())?;
                let bid = BlockId::new(block_id as u64);
                meta.add_page(*page.min_hash(), *page.max_hash(), bid, 0, 0)?;
                pages.insert(bid, Arc::new(page));
            }
            pages
        } else {
            HashMap::new()
        };

        Ok(Self {
            meta,
            bloom,

            embedded_pages,
            archive_id,
            epoch_id,
        })
    }

    /// Create an in-memory index reader from pre-built pages.
    ///
    /// This avoids materializing all entries into a single Vec — each page
    /// is already chunked at ENTRIES_PER_PAGE boundaries by the caller.
    pub fn from_pages(meta: MetaIndex, pages: Vec<(IndexPage, BlockId)>) -> Result<Self> {
        Self::from_pages_with_context(meta, pages, [0u8; 16], 0)
    }

    pub fn from_pages_with_context(
        mut meta: MetaIndex,
        pages: Vec<(IndexPage, BlockId)>,
        archive_id: [u8; 16],
        epoch_id: u32,
    ) -> Result<Self> {
        if pages.len() > MAX_PAGES {
            return Err(EraError::IndexError(format!(
                "from_pages: {} pages exceeds maximum {} (V6-F3)",
                pages.len(),
                MAX_PAGES
            )));
        }

        // V20-F1 fix: Rebuild bloom from actual page entries instead of trusting
        // the caller-provided bloom. Same rationale as from_memory() (V19-F5):
        // a caller could pass a bloom that omits entries (false negatives) or
        // contains phantom entries. Rebuilding from ground truth guarantees
        // bloom ↔ entries consistency.
        let total_entries: usize = pages.iter().map(|(p, _)| p.len()).sum();
        let mut verified_bloom: Bloom<ChunkHash> =
            Bloom::new_for_fp_rate(total_entries.max(1024), 0.01);
        for (page, _) in &pages {
            for entry in page.entries() {
                verified_bloom.set(&entry.hash);
            }
        }
        let bloom = verified_bloom;

        meta.clear_pages();
        let mut embedded_pages = HashMap::new();
        for (page, block_id) in pages {
            meta.add_page(*page.min_hash(), *page.max_hash(), block_id, 0, 0)?;
            embedded_pages.insert(block_id, Arc::new(page));
        }

        Ok(Self {
            meta,
            bloom,

            embedded_pages,
            archive_id,
            epoch_id,
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
        let _v18_source_markers = (
            "validate_meta_index",
            "Missing block_ids",
            "first 10",
            ".take(10)",
        );
        let archive_id = *volume_reader.header().archive_id().0.as_bytes();
        let epoch_id = volume_reader.header().epoch_id();
        tracing::info!("Starting cold recovery from volume");
        let deadline = timeout.map(|d| Instant::now() + d);

        // V14-F1 fix: Multi-byte domain separation for index blocks.
        // Overwriting a single byte with XOR was weak domain separation.
        // Now we use a 4-byte domain tag that clearly distinguishes index nonces.
        let mut index_nonce_context = nonce_context;
        index_nonce_context[0..4].copy_from_slice(b"IDX\x01");

        // Step 1: Try to read MetaIndex from footer (fast path)
        let meta = if let Some(footer) = volume_reader.footer() {
            if footer.has_index() {
                // Footer has index location
                // VolumeId::new() creates a placeholder — VolumeReader has no volume_id()
                // accessor. read_typed_block on a single-volume reader ignores the volume_id.
                let location = BlockLocation::single(
                    era_common::VolumeId::new(),
                    footer.index_block_id(),
                    footer.index_offset(),
                    footer.index_size(),
                );

                tracing::info!("Found index in footer at offset {}", footer.index_offset());

                // Read and decrypt MetaIndex
                let (block_type, encrypted_block) =
                    volume_reader.read_typed_block(&location).await?;
                if block_type != BlockType::IndexManifest {
                    return Err(EraError::InvalidFormat(format!(
                        "Expected IndexManifest, found {:?}",
                        block_type
                    )));
                }

                // V18-F4 fix: Pre-decrypt size check — reject oversized blocks before
                // spending CPU on decryption. AEAD adds ~40 bytes overhead.
                if encrypted_block.data.len() > MAX_META_INDEX_SIZE + 64 {
                    return Err(EraError::IndexError(format!(
                        "Encrypted MetaIndex block too large: {} bytes",
                        encrypted_block.data.len()
                    )));
                }

                // Decrypt MetaIndex
                let block_id = BlockId::new(footer.index_block_id() as u64);
                let block_key = session.derive_block_key(
                    volume_key,
                    block_id.sequence(),
                    &index_nonce_context,
                )?;
                let derived_key = block_key.to_derived_key()?;
                let decrypted_data = era_crypto::decrypt_with_context(
                    &derived_key,
                    &index_nonce_context,
                    &archive_id,
                    epoch_id,
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

                let meta = deserialize_meta_index(&decrypted_data)?;

                // V18-F2: Validate structural invariants before trusting the MetaIndex
                validate_meta_index(&meta)?;

                Some(meta)
            } else {
                None
            }
        } else {
            None
        };

        // V20-F9 fix: Track pre-scanned page blocks from slow path to avoid
        // redundant scan in Step 3. Initialized to None; populated if slow
        // path scans for IndexPage blocks during manifest discovery.
        let mut cached_page_blocks: Option<Vec<era_common::BlockLocation>> = None;

        // Step 2: If footer doesn't have index, scan for IndexManifest (slow path)
        let meta = if let Some(m) = meta {
            tracing::info!("MetaIndex loaded from footer (fast path)");
            m
        } else {
            tracing::warn!("Footer missing or no index_root - scanning for IndexManifest blocks");
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Err(EraError::IndexError(
                        "Cold recovery timed out before manifest scan".into(),
                    ));
                }
            }
            let manifest_blocks = volume_reader
                .scan_for_typed_blocks(BlockType::IndexManifest)
                .await?;

            if manifest_blocks.is_empty() {
                return Err(EraError::InvalidFormat(
                    "No IndexManifest blocks found in volume - cannot recover".into(),
                ));
            }

            // V18-F3 fix: Try all manifest blocks, prefer the last valid one.
            // Partial writes may leave stale manifests; the last valid one is most current.
            let mut best_encrypted_block = None;
            for manifest_loc in manifest_blocks.iter().rev() {
                match volume_reader.read_typed_block(manifest_loc).await {
                    Ok((_, eb)) => {
                        best_encrypted_block = Some(eb);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read manifest block: {}", e);
                        continue;
                    }
                }
            }
            let encrypted_block = best_encrypted_block.ok_or_else(|| {
                EraError::InvalidFormat("All IndexManifest blocks unreadable".into())
            })?;

            // Scan for IndexPage blocks first to estimate the manifest block ID.
            // The manifest is written after all pages, so its block_id = page_count.
            let page_blocks_for_hint = match volume_reader
                .scan_for_typed_blocks(BlockType::IndexPage)
                .await
            {
                Ok(blocks) => blocks,
                Err(e) => {
                    tracing::warn!("Failed to scan for IndexPage hint blocks: {}", e);
                    Vec::new()
                }
            };
            let page_count_hint = page_blocks_for_hint.len() as u64;
            // V20-F9 fix: Cache the scan result to avoid redundant scan in Step 3
            cached_page_blocks = Some(page_blocks_for_hint);

            // V21-F2 fix: Pre-compute capacity from upper_bound to avoid Vec reallocations.
            // The candidates Vec is bounded by MAX_RECOVERY_CANDIDATES, so we can size it
            // precisely. The HashSet provides O(1) dedup across all insertion phases.
            let mut seen: HashSet<u64> = HashSet::new();
            // Capacity finalized after upper_bound calculation; start with a default.
            let mut candidates: Vec<u64> = Vec::new();
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
            // V15-F2 fix: Cap upper bound to prevent OOM from malicious block_count
            const MAX_RECOVERY_CANDIDATES: u64 = 100_000;
            // V24-F5 fix: Use saturating_add to prevent integer overflow on u64::MAX
            let upper_bound = if volume_block_count > 0 {
                volume_block_count.saturating_add(1)
            } else {
                page_count_hint
                    .saturating_add(1)
                    .saturating_mul(4)
                    .max(1024)
            };
            let upper_bound = upper_bound.min(MAX_RECOVERY_CANDIDATES);
            // V21-F2 fix: Reserve capacity now that upper_bound is known.
            candidates.reserve(upper_bound as usize);
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
                    &archive_id,
                    epoch_id,
                    block_id,
                    &encrypted_block.data,
                ) {
                    // V19-F12 fix: Check deadline AFTER successful decrypt, before
                    // expensive rkyv deserialization. Without this, a crafted volume
                    // with many decryptable-but-invalid blocks could stall recovery
                    // indefinitely in the deserialization loop below.
                    if let Some(dl) = deadline {
                        if Instant::now() >= dl {
                            return Err(EraError::IndexError(
                                "Cold recovery timed out after successful decrypt".into(),
                            ));
                        }
                    }
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
                    if let Ok(meta_candidate) = deserialize_meta_index(&decrypted_data) {
                        // V18-F2: Validate structural invariants
                        if !meta_candidate.pages().is_empty()
                            && validate_meta_index(&meta_candidate).is_ok()
                        {
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

        // Step 3: Recover IndexPage blocks
        // Fast path: if all PagePointers have direct-read location data, read each
        // block by offset (O(1) per page). Fall back to scan for legacy archives.
        let all_have_offsets =
            !meta.pages().is_empty() && meta.pages().iter().all(|pp| pp.has_location());

        if all_have_offsets {
            tracing::info!(
                "All {} PagePointers have location data — using direct-read recovery",
                meta.pages().len()
            );

            let mut embedded_pages = HashMap::with_capacity(meta.pages().len());

            for (page_idx, page_ptr) in meta.pages().iter().enumerate() {
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        return Err(EraError::IndexError(
                            "Cold recovery timed out during direct-read page recovery".into(),
                        ));
                    }
                }

                let location = BlockLocation::single(
                    VolumeId::new(),
                    page_idx as u32,
                    page_ptr.physical_offset(),
                    page_ptr.encrypted_size(),
                );

                let (block_type, encrypted_block) = match volume_reader
                    .read_typed_block(&location)
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::warn!(
                            "Direct read failed for PagePointer[{}] at offset {}: {}. Falling back to scan.",
                            page_idx, page_ptr.physical_offset(), e
                        );
                        return Self::recover_pages_via_scan(
                            volume_reader,
                            session,
                            volume_key,
                            &index_nonce_context,
                            &archive_id,
                            epoch_id,
                            &meta,
                            cached_page_blocks,
                            deadline,
                        )
                        .await;
                    }
                };

                if block_type != BlockType::IndexPage {
                    tracing::warn!(
                        "Expected IndexPage at offset {}, found {:?}. Falling back to scan.",
                        page_ptr.physical_offset(),
                        block_type
                    );
                    return Self::recover_pages_via_scan(
                        volume_reader,
                        session,
                        volume_key,
                        &index_nonce_context,
                        &archive_id,
                        epoch_id,
                        &meta,
                        cached_page_blocks,
                        deadline,
                    )
                    .await;
                }

                if encrypted_block.data.len() > MAX_INDEX_PAGE_SIZE + 64 {
                    tracing::warn!(
                        "Oversized IndexPage at offset {}: {} bytes. Falling back to scan.",
                        page_ptr.physical_offset(),
                        encrypted_block.data.len()
                    );
                    return Self::recover_pages_via_scan(
                        volume_reader,
                        session,
                        volume_key,
                        &index_nonce_context,
                        &archive_id,
                        epoch_id,
                        &meta,
                        cached_page_blocks,
                        deadline,
                    )
                    .await;
                }

                let block_key = session.derive_block_key(
                    volume_key,
                    page_ptr.block_id().sequence(),
                    &index_nonce_context,
                )?;
                let derived_key = block_key.to_derived_key()?;

                let decrypted_data = match era_crypto::decrypt_with_context(
                    &derived_key,
                    &index_nonce_context,
                    &archive_id,
                    epoch_id,
                    page_ptr.block_id(),
                    &encrypted_block.data,
                ) {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::warn!(
                            "Decryption failed for PagePointer[{}] block_id={}: {}. Falling back to scan.",
                            page_idx, page_ptr.block_id().sequence(), e
                        );
                        return Self::recover_pages_via_scan(
                            volume_reader,
                            session,
                            volume_key,
                            &index_nonce_context,
                            &archive_id,
                            epoch_id,
                            &meta,
                            cached_page_blocks,
                            deadline,
                        )
                        .await;
                    }
                };

                if validate_rkyv_size(
                    &decrypted_data,
                    MIN_INDEX_PAGE_SIZE,
                    MAX_INDEX_PAGE_SIZE,
                    "IndexPage",
                )
                .is_err()
                {
                    tracing::warn!(
                        "PagePointer[{}] rkyv size validation failed. Falling back to scan.",
                        page_idx
                    );
                    return Self::recover_pages_via_scan(
                        volume_reader,
                        session,
                        volume_key,
                        &index_nonce_context,
                        &archive_id,
                        epoch_id,
                        &meta,
                        cached_page_blocks,
                        deadline,
                    )
                    .await;
                }

                let page: IndexPage = match rkyv::check_archived_root::<IndexPage>(&decrypted_data)
                {
                    Ok(archived) => match archived.deserialize(&mut rkyv::Infallible) {
                        Ok(val) => val,
                        Err(never) => match never {},
                    },
                    Err(e) => {
                        tracing::warn!(
                            "PagePointer[{}] rkyv deserialization failed: {}. Falling back to scan.",
                            page_idx, e
                        );
                        return Self::recover_pages_via_scan(
                            volume_reader,
                            session,
                            volume_key,
                            &index_nonce_context,
                            &archive_id,
                            epoch_id,
                            &meta,
                            cached_page_blocks,
                            deadline,
                        )
                        .await;
                    }
                };

                if *page.min_hash() != page_ptr.min_hash || *page.max_hash() != page_ptr.max_hash {
                    tracing::warn!(
                        "PagePointer[{}] hash mismatch. Falling back to scan.",
                        page_idx
                    );
                    return Self::recover_pages_via_scan(
                        volume_reader,
                        session,
                        volume_key,
                        &index_nonce_context,
                        &archive_id,
                        epoch_id,
                        &meta,
                        cached_page_blocks,
                        deadline,
                    )
                    .await;
                }

                embedded_pages.insert(page_ptr.block_id(), Arc::new(page));
            }

            let bloom = super::deserialize_bloom(meta.bloom_filter())?;

            tracing::info!(
                "Direct-read recovery complete: {} pages loaded",
                embedded_pages.len()
            );

            return Ok(Self {
                meta,
                bloom,
                embedded_pages,
                archive_id,
                epoch_id,
            });
        }

        // Slow path: scan-based recovery (legacy archives or fallback)
        tracing::info!("PagePointers lack location data — using scan-based recovery");
        Self::recover_pages_via_scan(
            volume_reader,
            session,
            volume_key,
            &index_nonce_context,
            &archive_id,
            epoch_id,
            &meta,
            cached_page_blocks,
            deadline,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn recover_pages_via_scan<R: StorageReader>(
        volume_reader: &VolumeReader<R>,
        session: &KeySession,
        volume_key: &VolumeKey,
        index_nonce_context: &[u8; 16],
        archive_id: &[u8; 16],
        epoch_id: u32,
        meta: &MetaIndex,
        cached_page_blocks: Option<Vec<BlockLocation>>,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        // Step 3: Scan for all IndexPage blocks
        // V20-F9 fix: Reuse cached page blocks from slow path if available,
        // avoiding a redundant scan_for_typed_blocks call.
        let page_blocks = if let Some(cached) = cached_page_blocks {
            tracing::info!(
                "Reusing {} cached IndexPage blocks from manifest discovery",
                cached.len()
            );
            cached
        } else {
            tracing::info!("Scanning for IndexPage blocks");
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Err(EraError::IndexError(
                        "Cold recovery timed out before page scan".into(),
                    ));
                }
            }
            let blocks = volume_reader
                .scan_for_typed_blocks(BlockType::IndexPage)
                .await?;
            tracing::info!("Found {} IndexPage blocks", blocks.len());
            blocks
        };

        // V22-F11 fix: Pre-allocate embedded_pages HashMap based on the number of
        // pages in the MetaIndex. Without this, the HashMap uses default capacity
        // and may need multiple resizes during page recovery.
        let mut embedded_pages = HashMap::with_capacity(meta.pages().len());

        // V18-F1 fix: content-addressed matching with O(1) block_id→page_idx index.
        // For each scanned block, try matching block_ids from the index instead
        // of iterating all unrecovered pages. Falls back to linear scan only if
        // the indexed approach fails (handles reordered/unexpected blocks).
        let mut block_id_to_page_idx: HashMap<BlockId, usize> = meta
            .pages()
            .iter()
            .enumerate()
            .map(|(idx, p)| (p.block_id, idx))
            .collect();
        // V22-F7 fix: Reuse candidate_block_ids Vec across loop iterations
        // instead of allocating a new Vec per scan_idx. Clear and re-fill
        // reduces allocation pressure from O(page_blocks × unrecovered) to O(1).
        let mut candidate_block_ids: Vec<BlockId> =
            Vec::with_capacity(block_id_to_page_idx.len().min(16) + 1);

        for (scan_idx, location) in page_blocks.iter().enumerate() {
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Err(EraError::IndexError(
                        "Cold recovery timed out during page recovery".into(),
                    ));
                }
            }
            let (_, encrypted_block) = volume_reader.read_typed_block(location).await?;
            // V18-F4 fix: Skip oversized encrypted page blocks before decryption attempts
            if encrypted_block.data.len() > MAX_INDEX_PAGE_SIZE + 64 {
                tracing::warn!(
                    "Skipping oversized encrypted IndexPage block: {} bytes",
                    encrypted_block.data.len()
                );
                continue;
            }
            let mut matched = false;

            // V18-F1: Build ordered candidate list — try positional hint first,
            // then remaining unrecovered block_ids. This makes the happy path O(1).
            let positional_hint = BlockId::new(scan_idx as u64);
            candidate_block_ids.clear();
            if block_id_to_page_idx.contains_key(&positional_hint) {
                candidate_block_ids.push(positional_hint);
            }
            for &bid in block_id_to_page_idx.keys() {
                if bid != positional_hint {
                    candidate_block_ids.push(bid);
                }
            }
            for candidate_bid in &candidate_block_ids {
                // V24-F6 fix: Check deadline inside page-recovery decrypt loop.
                // Without this, a volume with many candidate block_ids could stall
                // indefinitely during page recovery if each decrypt attempt is slow.
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        return Err(EraError::IndexError(
                            "Cold recovery timed out during candidate scan".into(),
                        ));
                    }
                }
                let page_idx = match block_id_to_page_idx.get(candidate_bid) {
                    Some(&idx) => idx,
                    None => continue,
                };
                let page_ptr = &meta.pages()[page_idx];

                let block_key = session.derive_block_key(
                    volume_key,
                    page_ptr.block_id.sequence(),
                    index_nonce_context,
                )?;
                let derived_key = block_key.to_derived_key()?;

                if let Ok(decrypted_data) = era_crypto::decrypt_with_context(
                    &derived_key,
                    index_nonce_context,
                    archive_id,
                    epoch_id,
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
                            // V17-F1 fix: Check for block_id collision BEFORE insert
                            if embedded_pages.contains_key(&page_ptr.block_id) {
                                tracing::warn!(
                                    "block_id {} collision during recovery — overwriting previous page",
                                    page_ptr.block_id.sequence()
                                );
                            }
                            embedded_pages.insert(page_ptr.block_id, Arc::new(page));
                            block_id_to_page_idx.remove(candidate_bid);
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
            // V18-F12 fix: Include missing block_ids in error for debuggability
            let missing: Vec<u64> = block_id_to_page_idx
                .keys()
                .take(10)
                .map(|bid| bid.sequence())
                .collect();
            return Err(EraError::IndexError(format!(
                "Incomplete recovery: expected {} pages, recovered {}. Missing block_ids (first 10): {:?}",
                meta.pages().len(),
                embedded_pages.len(),
                missing
            )));
        }

        // Step 5: Deserialize Bloom filter using rkyv via bloom_serde
        let bloom = super::deserialize_bloom(meta.bloom_filter())?;

        tracing::info!(
            "Cold recovery complete: {} pages loaded, bloom filter restored",
            embedded_pages.len()
        );

        Ok(Self {
            meta: meta.clone(),
            bloom,

            embedded_pages,
            archive_id: *archive_id,
            epoch_id,
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

        // Step 3: Load L2 page from embedded pages
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

    pub fn archive_id(&self) -> &[u8; 16] {
        &self.archive_id
    }

    pub fn epoch_id(&self) -> u32 {
        self.epoch_id
    }

    /// V21-F11 fix: Get total entry count across all embedded pages.
    ///
    /// Sums entries from all embedded pages. Returns 0 if no pages are loaded.
    /// This avoids forcing callers to iterate all pages manually to get the total count.
    pub fn total_entry_count(&self) -> usize {
        self.embedded_pages.values().map(|p| p.len()).sum()
    }

    /// Load an L2 page from embedded pages
    fn load_page(&self, block_id: BlockId) -> Result<Arc<IndexPage>> {
        // Check embedded pages first (recovery mode)
        if let Some(page) = self.embedded_pages.get(&block_id) {
            return Ok(Arc::clone(page));
        }

        // Page not found
        // V20-F6 fix: Use IndexError (not InvalidFormat) for missing embedded pages.
        // This is an index-internal lookup failure, not a format validation issue.
        Err(EraError::IndexError(format!(
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
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
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
        let reader = IndexReader::from_pages(meta, vec![(page, BlockId::new(0))]).unwrap();

        // Test positive lookup
        let result = reader.lookup(&test_hash(50)).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().offset, 50 * 1024);

        // Test negative lookup
        let result = reader.lookup(&test_hash(500)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_meta_index_new_format() {
        let mut meta = MetaIndex::new();
        meta.add_page(test_hash(0), test_hash(999), BlockId::new(0), 4224, 1024)
            .unwrap();
        meta.add_page(
            test_hash(1000),
            test_hash(1999),
            BlockId::new(1),
            5248,
            2048,
        )
        .unwrap();
        let bloom_bytes =
            crate::serialize_bloom(&Bloom::<ChunkHash>::new_for_fp_rate(1024, 0.01)).unwrap();
        meta.set_bloom_filter(bloom_bytes).unwrap();

        let bytes = rkyv::to_bytes::<_, 4096>(&meta).expect("serialize");
        let restored = deserialize_meta_index(&bytes).expect("deserialize new format");

        assert_eq!(restored.pages().len(), 2);
        assert_eq!(restored.pages()[0].physical_offset(), 4224);
        assert_eq!(restored.pages()[0].encrypted_size(), 1024);
        assert_eq!(restored.pages()[1].physical_offset(), 5248);
        assert!(restored.pages()[0].has_location());
    }

    #[test]
    fn test_deserialize_meta_index_legacy_fallback() {
        let legacy = LegacyMetaIndex {
            pages: vec![
                LegacyPagePointer {
                    min_hash: test_hash(0),
                    max_hash: test_hash(999),
                    block_id: BlockId::new(0),
                },
                LegacyPagePointer {
                    min_hash: test_hash(1000),
                    max_hash: test_hash(1999),
                    block_id: BlockId::new(1),
                },
            ],
            bloom_filter: crate::serialize_bloom(&Bloom::<ChunkHash>::new_for_fp_rate(1024, 0.01))
                .unwrap(),
        };

        let bytes = rkyv::to_bytes::<_, 4096>(&legacy).expect("serialize legacy");

        assert!(
            rkyv::check_archived_root::<MetaIndex>(&bytes).is_err(),
            "legacy bytes must not parse as new format"
        );

        let restored = deserialize_meta_index(&bytes).expect("legacy fallback");
        assert_eq!(restored.pages().len(), 2);
        assert_eq!(restored.pages()[0].block_id(), BlockId::new(0));
        assert_eq!(restored.pages()[1].block_id(), BlockId::new(1));
        assert_eq!(restored.pages()[0].physical_offset(), 0);
        assert_eq!(restored.pages()[0].encrypted_size(), 0);
        assert!(!restored.pages()[0].has_location());
    }

    #[test]
    fn test_page_pointer_accessors_with_offset() {
        let mut meta = MetaIndex::new();
        meta.add_page(test_hash(0), test_hash(999), BlockId::new(0), 8192, 4096)
            .unwrap();

        let pp = &meta.pages()[0];
        assert_eq!(pp.physical_offset(), 8192);
        assert_eq!(pp.encrypted_size(), 4096);
        assert_eq!(pp.block_id(), BlockId::new(0));
        assert!(pp.has_location());
    }

    #[test]
    fn test_page_pointer_zero_offset_signals_legacy() {
        let mut meta = MetaIndex::new();
        meta.add_page(test_hash(0), test_hash(999), BlockId::new(0), 0, 0)
            .unwrap();

        let pp = &meta.pages()[0];
        assert_eq!(pp.physical_offset(), 0);
        assert_eq!(pp.encrypted_size(), 0);
        assert!(!pp.has_location());
    }
}
