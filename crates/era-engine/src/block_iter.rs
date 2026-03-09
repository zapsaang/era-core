//! Block iterator abstraction for unified block reading.
//!
//! This module provides a common interface for iterating over blocks
//! in both standard and erasure-coded archives, eliminating code duplication.
//!
//! ## Security
//!
//! Session-based iterators (`SessionBlockIterator`, `SessionErasureBlockIterator`)
//! use the HKDF "Onion Model" for per-block key derivation:
//! - Each block is decrypted with a unique key derived from the volume key
//! - This provides forward and backward security isolation
//!
//! Basic iterators (`StandardBlockIterator`, `ErasureBlockIterator`) use a single
//! key for all blocks and are provided for simpler use cases.

use async_trait::async_trait;
use bytes::Bytes;
use era_codec::{ErasureCoder, ErasureConfig};
use era_common::{
    BlockHeader, BlockId, BlockLocation, BlockType, ChunkVec, EraError, ErasureBlockInfo,
    MatrixDistributionStrategy, Result, ShardHeader, VerifiedShard,
};
use era_crypto::{KeySession, VolumeKey};
use era_packing::{ErasureBlockUnpacker, MacroBlockUnpacker, SessionBlockUnpacker};
use era_volume::{DistributionCalculator, VolumeReader};
use std::collections::VecDeque;

/// Result of reading and decoding a block
#[derive(Debug)]
pub struct DecodedBlock {
    /// Block index (for error reporting)
    pub block_index: u32,
    /// Chunks extracted from the block: (hash, data)
    /// Uses SmallVec for stack allocation optimization to avoid per-block heap allocation.
    /// Most blocks contain ≤16 chunks, which fit entirely on the stack.
    pub chunks: ChunkVec,
    /// Number of corrupted shards (erasure mode only)
    pub corrupted_shards: usize,
}

/// Statistics about block iteration
#[derive(Debug, Default)]
pub struct BlockIterStats {
    /// Number of blocks successfully read
    pub blocks_read: u32,
    /// Number of blocks that failed to decode
    pub blocks_failed: u32,
    /// Number of corrupted shards detected (erasure mode)
    pub corrupted_shards: u32,
}

/// Common trait for block iterators
#[async_trait(?Send)]
pub trait BlockIterator {
    /// Get the next block's decoded chunks
    /// Returns None when iteration is complete
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>>;

    /// Check if there are more blocks to read
    fn has_more(&self) -> bool;

    /// Get iteration statistics
    fn stats(&self) -> &BlockIterStats;
}

/// Maximum allowed block size (64 MB) — read-path sanity check (~16x typical block sizes)
const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;
const MAX_PROBE_ATTEMPTS: usize = 256;

/// Iterator for standard (non-erasure) blocks
pub struct StandardBlockIterator<'a, R: era_storage::StorageReader> {
    volume_reader: &'a VolumeReader<R>,
    unpacker: &'a MacroBlockUnpacker,
    /// Current offset in the data region
    current_offset: u64,
    /// End of data region
    data_end: u64,
    /// Current block index
    block_index: u32,
    /// Iteration statistics
    stats: BlockIterStats,
}

impl<'a, R: era_storage::StorageReader> StandardBlockIterator<'a, R> {
    /// Create a new standard block iterator
    pub fn new(volume_reader: &'a VolumeReader<R>, unpacker: &'a MacroBlockUnpacker) -> Self {
        let (data_start, data_end) = volume_reader.data_region();
        Self {
            volume_reader,
            unpacker,
            current_offset: data_start,
            data_end,
            block_index: 0,
            stats: BlockIterStats::default(),
        }
    }

    /// Create with custom end offset (e.g., stop before catalog)
    pub fn with_end_offset(
        volume_reader: &'a VolumeReader<R>,
        unpacker: &'a MacroBlockUnpacker,
        end_offset: u64,
    ) -> Self {
        let (data_start, _) = volume_reader.data_region();
        Self {
            volume_reader,
            unpacker,
            current_offset: data_start,
            data_end: end_offset,
            block_index: 0,
            stats: BlockIterStats::default(),
        }
    }
}

#[async_trait(?Send)]
impl<'a, R: era_storage::StorageReader> BlockIterator for StandardBlockIterator<'a, R> {
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        if self.current_offset >= self.data_end {
            return None;
        }

        // Read BlockHeader (16 bytes)
        let header_bytes = match self
            .volume_reader
            .read_raw(self.current_offset, BlockHeader::SIZE)
            .await
        {
            Ok(bytes) if bytes.len() == BlockHeader::SIZE => bytes,
            Ok(bytes) if bytes.is_empty() => return None,
            Ok(bytes) => {
                return Some(Err(EraError::IntegrityError(format!(
                    "Unexpected partial read: expected {} bytes, got {}",
                    BlockHeader::SIZE,
                    bytes.len()
                ))));
            }
            Err(e) => return Some(Err(e)),
        };

        let header = match BlockHeader::from_bytes(&header_bytes) {
            Some(h) => h,
            None => {
                self.stats.blocks_failed += 1;
                self.current_offset += BlockHeader::SIZE as u64;
                return Some(Err(EraError::CorruptedHeader(format!(
                    "Invalid BlockHeader at offset {}",
                    self.current_offset - BlockHeader::SIZE as u64
                ))));
            }
        };

        let block_size = header.length;

        // Validate block size
        if block_size == 0 {
            self.stats.blocks_failed += 1;
            // Advance offset to avoid infinite loop
            self.current_offset += BlockHeader::SIZE as u64;
            return Some(Err(EraError::CorruptedHeader(format!(
                "Zero-length block at offset {}",
                self.current_offset - BlockHeader::SIZE as u64
            ))));
        }
        if block_size > MAX_BLOCK_SIZE {
            self.stats.blocks_failed += 1;
            // Impossible to know where next block starts, so abort iteration
            self.current_offset = self.data_end;
            return Some(Err(EraError::BlockTooLarge {
                size: block_size as usize,
                max_size: MAX_BLOCK_SIZE as usize,
            }));
        }

        let location = BlockLocation::single(
            self.volume_reader.header().volume_id(),
            self.block_index,
            self.current_offset,
            block_size,
        );

        // Read and decrypt block
        let result = match self.volume_reader.read_block(&location).await {
            Ok(encrypted_block) => match self.unpacker.extract_all_chunks(&encrypted_block) {
                Ok(chunks) => {
                    self.stats.blocks_read += 1;
                    Ok(DecodedBlock {
                        block_index: self.block_index,
                        chunks,
                        corrupted_shards: 0,
                    })
                }
                Err(e) => {
                    self.stats.blocks_failed += 1;
                    Err(e)
                }
            },
            Err(e) => {
                self.stats.blocks_failed += 1;
                Err(e)
            }
        };

        // Advance to next block (BlockHeader::SIZE + data)
        self.current_offset += BlockHeader::SIZE as u64 + block_size as u64;
        self.block_index += 1;

        Some(result)
    }

    fn has_more(&self) -> bool {
        self.current_offset < self.data_end
    }

    fn stats(&self) -> &BlockIterStats {
        &self.stats
    }
}

/// Iterator for erasure-coded blocks
pub struct ErasureBlockIterator<'a, R: era_storage::StorageReader> {
    volume_readers: &'a [VolumeReader<R>],
    erasure_unpacker: &'a ErasureBlockUnpacker,
    /// Erasure configuration
    data_shards: u8,
    parity_shards: u8,
    total_shards: usize,
    /// Maps volume index in original sequence to index in volume_readers
    /// e.g., if original volumes 0 and 2 are present, vol_index_map[0] = Some(0), vol_index_map[1] = None, vol_index_map[2] = Some(1)
    vol_index_map: Vec<Option<usize>>,
    /// Total number of volumes in original archive
    original_volume_count: usize,
    /// Current offsets in the data region for each volume
    current_offsets: Vec<u64>,
    /// End of data region for each volume
    data_ends: Vec<u64>,
    /// Current block index
    block_index: u32,
    /// Iteration statistics
    stats: BlockIterStats,
}

impl<'a, R: era_storage::StorageReader> ErasureBlockIterator<'a, R> {
    /// Create a new erasure block iterator
    ///
    /// # Arguments
    /// * `volume_readers` - Available volume readers
    /// * `volume_indices` - Original index of each volume in the multi-volume sequence
    ///   e.g., [0, 2] means volume 0 and volume 2 are present
    /// * `erasure_unpacker` - Unpacker for erasure-coded blocks  
    /// * `data_shards` - Number of data shards in erasure config
    /// * `parity_shards` - Number of parity shards in erasure config
    pub fn new(
        volume_readers: &'a [VolumeReader<R>],
        volume_indices: &[usize],
        erasure_unpacker: &'a ErasureBlockUnpacker,
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Self> {
        if volume_readers.is_empty() {
            return Err(EraError::InvalidFormat("No volume readers provided".into()));
        }
        if volume_readers.len() != volume_indices.len() {
            return Err(EraError::InvalidFormat(
                "volume_readers and volume_indices length mismatch".to_string(),
            ));
        }

        let mut current_offsets = Vec::with_capacity(volume_readers.len());
        let mut data_ends = Vec::with_capacity(volume_readers.len());

        for reader in volume_readers {
            let (start, end) = reader.data_region();
            let footer = reader.footer();
            let mut limit = if let Some(f) = footer {
                if f.has_catalog_location() {
                    f.catalog_offset()
                } else {
                    end
                }
            } else {
                end
            };

            if let Some(f) = footer {
                if f.has_index() && f.index_offset() < limit {
                    limit = f.index_offset();
                }
            }
            current_offsets.push(start);
            data_ends.push(limit);
        }

        let total_shards = data_shards as usize + parity_shards as usize;

        // Build reverse map: original_vol_index -> position in volume_readers
        // The original volume count is determined by the maximum index present + any gaps
        let original_volume_count = volume_indices.iter().copied().max().unwrap_or(0) + 1;
        let mut vol_index_map = vec![None; original_volume_count];
        for (reader_idx, &orig_idx) in volume_indices.iter().enumerate() {
            if orig_idx < original_volume_count {
                vol_index_map[orig_idx] = Some(reader_idx);
            }
        }

        Ok(Self {
            volume_readers,
            erasure_unpacker,
            data_shards,
            parity_shards,
            total_shards,
            vol_index_map,
            original_volume_count,
            current_offsets,
            data_ends,
            block_index: 0,
            stats: BlockIterStats::default(),
        })
    }
}

#[async_trait(?Send)]
impl<'a, R: era_storage::StorageReader> BlockIterator for ErasureBlockIterator<'a, R> {
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        if self
            .current_offsets
            .iter()
            .zip(self.data_ends.iter())
            .any(|(offset, end)| offset >= end)
        {
            return None;
        }

        // Read erasure block header (4 bytes original_len) from the first available volume
        // All volumes now have this header written before their first shard of each block
        let header_bytes = match self.volume_readers[0]
            .read_raw(self.current_offsets[0], 4)
            .await
        {
            Ok(bytes) if bytes.len() == 4 => bytes,
            Ok(bytes) if bytes.is_empty() => return None,
            Ok(bytes) => {
                return Some(Err(EraError::IntegrityError(format!(
                    "Unexpected partial read: expected {} bytes, got {}",
                    4,
                    bytes.len()
                ))));
            }
            Err(e) => return Some(Err(e)),
        };
        let original_len = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);

        // Advance past the header on the first available volume
        self.current_offsets[0] += 4;

        // Read all shards for this block, preserving CRC verification status
        let mut verified_shards: Vec<VerifiedShard> = Vec::with_capacity(self.total_shards);
        let mut corrupted_count = 0usize;
        let mut first_shard_size = 0u32;

        // Track which volumes have had their block header read
        // We already read it from volume_readers[0], so mark that
        let mut header_read_for_volume = vec![false; self.volume_readers.len()];
        header_read_for_volume[0] = true;

        for shard_idx in 0..self.total_shards {
            // Use original volume count for shard distribution mapping
            let orig_vol_idx = shard_idx % self.original_volume_count;

            // Look up if this volume is available
            let reader_idx = match self.vol_index_map.get(orig_vol_idx) {
                Some(Some(idx)) => *idx,
                _ => {
                    // Volume is missing - shard unavailable, count as corrupted
                    corrupted_count += 1;
                    continue;
                }
            };

            let reader = &self.volume_readers[reader_idx];
            let mut offset = self.current_offsets[reader_idx];

            // If this is the first shard for this volume in this block,
            // skip the original_len header (4 bytes)
            if !header_read_for_volume[reader_idx] {
                offset += 4;
                self.current_offsets[reader_idx] += 4;
                header_read_for_volume[reader_idx] = true;
            }

            // Read shard header (8 bytes: 4 length + 4 CRC)
            let header_bytes = match reader.read_raw(offset, ShardHeader::SIZE).await {
                Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                Ok(_) => {
                    corrupted_count += 1;
                    continue;
                }
                Err(_) => {
                    corrupted_count += 1;
                    continue;
                }
            };

            let shard_header = match ShardHeader::from_bytes(&header_bytes) {
                Some(h) => h,
                None => {
                    corrupted_count += 1;
                    continue;
                }
            };

            // Advance past header
            self.current_offsets[reader_idx] += ShardHeader::SIZE as u64;

            let shard_len = shard_header.length as usize;

            if first_shard_size == 0 {
                first_shard_size = shard_header.length;
            }

            // Read shard data
            match reader
                .read_raw(self.current_offsets[reader_idx], shard_len)
                .await
            {
                Ok(shard_data) => {
                    // Verify CRC and collect as VerifiedShard (don't drop failures)
                    let crc_valid = shard_header.verify(&shard_data);
                    if !crc_valid {
                        corrupted_count += 1;
                    }
                    verified_shards.push(VerifiedShard {
                        index: shard_idx,
                        data: shard_data,
                        expected_crc: shard_header.crc,
                        crc_valid,
                    });
                }
                Err(_) => {
                    corrupted_count += 1;
                }
            }

            // Advance past data
            self.current_offsets[reader_idx] += shard_len as u64;
        }

        self.stats.corrupted_shards += corrupted_count as u32;

        if verified_shards.is_empty() {
            // If we failed to read ANY shards, verification fails.
            // Also if we failed to update offsets correctly, subsequent blocks will fail.
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::ErasureError(format!(
                "No valid shards for block {}",
                self.block_index
            ))));
        }

        if first_shard_size == 0 {
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::InvalidFormat(
                "first_shard_size is 0 — cannot proceed with RS decode".to_string(),
            )));
        }

        // Create erasure info for decoding
        let erasure_info = ErasureBlockInfo {
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            shard_size: first_shard_size,
            original_len,
        };

        let block_id = BlockId::new(self.block_index as u64);

        // Extract only CRC-valid shards for decoding (non-session path has no resilient AEAD)
        let valid_shards: Vec<(usize, Bytes)> = verified_shards
            .into_iter()
            .filter(|s| s.crc_valid)
            .map(|s| (s.index, s.data))
            .collect();

        // Decode and extract chunks
        let valid_shard_count = valid_shards.len();

        let result = match self.erasure_unpacker.decode_and_extract_all(
            valid_shards,
            &erasure_info,
            block_id,
        ) {
            Ok(chunks) => {
                self.stats.blocks_read += 1;
                Ok(DecodedBlock {
                    block_index: self.block_index,
                    chunks,
                    corrupted_shards: corrupted_count,
                })
            }
            Err(e) => {
                self.stats.blocks_failed += 1;
                tracing::warn!(
                    "Erasure block {} decode failed: {}. Valid shards: {}/{}, first shard size: {}",
                    self.block_index,
                    e,
                    valid_shard_count,
                    self.total_shards,
                    first_shard_size
                );
                Err(e)
            }
        };

        self.block_index += 1;
        Some(result)
    }

    fn has_more(&self) -> bool {
        self.current_offsets
            .iter()
            .zip(self.data_ends.iter())
            .all(|(offset, end)| offset + 4 <= *end)
    }

    fn stats(&self) -> &BlockIterStats {
        &self.stats
    }
}

// =============================================================================
// Session-based iterators with per-block key derivation
// =============================================================================

/// Iterator for standard (non-erasure) blocks with per-block key derivation.
///
/// Unlike `StandardBlockIterator`, this iterator uses the HKDF "Onion Model"
/// to derive a unique key for each block, providing forward and backward security.
pub struct SessionBlockIterator<'a, R: era_storage::StorageReader> {
    volume_reader: &'a VolumeReader<R>,
    unpacker: SessionBlockUnpacker<'a>,
    /// Current offset in the data region
    current_offset: u64,
    /// End of data region
    data_end: u64,
    /// Current block index
    block_index: u32,
    /// Iteration statistics
    stats: BlockIterStats,
}

impl<'a, R: era_storage::StorageReader> SessionBlockIterator<'a, R> {
    /// Create a new session-based block iterator.
    ///
    /// # Arguments
    /// * `volume_reader` - The volume reader to read blocks from
    /// * `session` - The key session for per-block key derivation
    /// * `volume_key` - The volume key for this volume
    /// * `nonce_context` - The 16-byte nonce context (archive salt)
    /// * `compressor` - The compressor for decompression
    pub fn new(
        volume_reader: &'a VolumeReader<R>,
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        nonce_context: [u8; 16],
        archive_id: [u8; 16],
        epoch_id: u32,
        compressor: Box<dyn era_codec::Compressor>,
    ) -> Self {
        let (data_start, data_end) = volume_reader.data_region();
        let unpacker = SessionBlockUnpacker::new(
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            compressor,
        );
        Self {
            volume_reader,
            unpacker,
            current_offset: data_start,
            data_end,
            block_index: 0,
            stats: BlockIterStats::default(),
        }
    }

    /// Create with custom end offset (e.g., stop before catalog)
    #[allow(clippy::too_many_arguments)]
    pub fn with_end_offset(
        volume_reader: &'a VolumeReader<R>,
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        nonce_context: [u8; 16],
        archive_id: [u8; 16],
        epoch_id: u32,
        compressor: Box<dyn era_codec::Compressor>,
        end_offset: u64,
    ) -> Self {
        let (data_start, _) = volume_reader.data_region();
        let unpacker = SessionBlockUnpacker::new(
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            compressor,
        );
        Self {
            volume_reader,
            unpacker,
            current_offset: data_start,
            data_end: end_offset,
            block_index: 0,
            stats: BlockIterStats::default(),
        }
    }
}

#[async_trait(?Send)]
impl<'a, R: era_storage::StorageReader> BlockIterator for SessionBlockIterator<'a, R> {
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        if self.current_offset >= self.data_end {
            return None;
        }

        // Read BlockHeader (16 bytes)
        let header_bytes = match self
            .volume_reader
            .read_raw(self.current_offset, BlockHeader::SIZE)
            .await
        {
            Ok(bytes) if bytes.len() == BlockHeader::SIZE => bytes,
            Ok(bytes) if bytes.is_empty() => return None,
            Ok(bytes) => {
                return Some(Err(EraError::IntegrityError(format!(
                    "Unexpected partial read: expected {} bytes, got {}",
                    BlockHeader::SIZE,
                    bytes.len()
                ))));
            }
            Err(e) => return Some(Err(e)),
        };

        let header = match BlockHeader::from_bytes(&header_bytes) {
            Some(h) => h,
            None => {
                self.stats.blocks_failed += 1;
                self.current_offset += BlockHeader::SIZE as u64;
                return Some(Err(EraError::CorruptedHeader(format!(
                    "Invalid BlockHeader at offset {}",
                    self.current_offset - BlockHeader::SIZE as u64
                ))));
            }
        };

        let block_size = header.length;

        // Skip non-data blocks (e.g., IndexPage, IndexManifest) — they are
        // encrypted with different keys and are not part of the data stream.
        if header.block_type != BlockType::Data && header.block_type != BlockType::Catalog {
            self.current_offset += BlockHeader::SIZE as u64 + block_size as u64;
            // Don't increment block_index — index blocks use their own ID space
            return self.next_block().await;
        }

        // Validate block size
        if block_size == 0 {
            self.stats.blocks_failed += 1;
            // Advance offset to avoid infinite loop
            self.current_offset += BlockHeader::SIZE as u64;
            return Some(Err(EraError::CorruptedHeader(format!(
                "Zero-length block at offset {}",
                self.current_offset - BlockHeader::SIZE as u64
            ))));
        }
        if block_size > MAX_BLOCK_SIZE {
            self.stats.blocks_failed += 1;
            // Impossible to know where next block starts, so abort iteration
            self.current_offset = self.data_end;
            return Some(Err(EraError::BlockTooLarge {
                size: block_size as usize,
                max_size: MAX_BLOCK_SIZE as usize,
            }));
        }

        let location = BlockLocation::single(
            self.volume_reader.header().volume_id(),
            self.block_index,
            self.current_offset,
            block_size,
        );

        // Read and decrypt block with per-block key derivation
        let result = match self.volume_reader.read_block(&location).await {
            Ok(encrypted_block) => match self.unpacker.extract_all_chunks(&encrypted_block) {
                Ok(chunks) => {
                    self.stats.blocks_read += 1;
                    Ok(DecodedBlock {
                        block_index: self.block_index,
                        chunks,
                        corrupted_shards: 0,
                    })
                }
                Err(e) => {
                    self.stats.blocks_failed += 1;
                    Err(e)
                }
            },
            Err(e) => {
                self.stats.blocks_failed += 1;
                Err(e)
            }
        };

        // Advance to next block (BlockHeader::SIZE + data)
        self.current_offset += BlockHeader::SIZE as u64 + block_size as u64;
        self.block_index += 1;

        Some(result)
    }

    fn has_more(&self) -> bool {
        self.current_offset < self.data_end
    }

    fn stats(&self) -> &BlockIterStats {
        &self.stats
    }
}

/// Iterator for erasure-coded blocks with per-block key derivation.
///
/// Unlike `ErasureBlockIterator`, this iterator uses the HKDF "Onion Model"
/// to derive a unique key for each block, providing forward and backward security.
pub struct SessionErasureBlockIterator<'a, R: era_storage::StorageReader> {
    volume_readers: &'a [VolumeReader<R>],
    unpacker: SessionBlockUnpacker<'a>,
    /// Erasure configuration
    data_shards: u8,
    parity_shards: u8,
    total_shards: usize,
    /// Maps volume index in original sequence to index in volume_readers
    vol_index_map: Vec<Option<usize>>,
    /// Total number of volumes in original archive
    original_volume_count: usize,
    /// Current offsets in the data region for each volume
    current_offsets: Vec<u64>,
    /// End of data region for each volume
    data_ends: Vec<u64>,
    /// Current block index
    block_index: u32,
    /// Current stripe index (Virtual Striping)
    current_stripe_index: usize,
    /// Matrix distribution strategy
    distribution_strategy: MatrixDistributionStrategy,
    /// Iteration statistics
    stats: BlockIterStats,
    /// Pending decoded blocks from the current stripe
    pending_blocks: VecDeque<Result<DecodedBlock>>,
}

/// Arguments for creating a SessionErasureBlockIterator
pub struct SessionErasureBlockIteratorArgs<'a, R: era_storage::StorageReader> {
    pub volume_readers: &'a [VolumeReader<R>],
    pub volume_indices: &'a [usize],
    pub original_volume_count: usize,
    pub session: &'a KeySession,
    pub volume_key: &'a VolumeKey,
    pub nonce_context: [u8; 16],
    pub archive_id: [u8; 16],
    pub epoch_id: u32,
    pub compressor: Box<dyn era_codec::Compressor>,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub distribution_strategy: MatrixDistributionStrategy,
}

impl<'a, R: era_storage::StorageReader> SessionErasureBlockIterator<'a, R> {
    /// Create a new session-based erasure block iterator.
    ///
    /// # Arguments
    /// * `volume_readers` - Available volume readers
    /// * `volume_indices` - Original index of each volume in the multi-volume sequence
    /// * `session` - The key session for per-block key derivation
    /// * `volume_key` - The volume key for this volume
    /// * `nonce_context` - The 16-byte nonce context (archive salt)
    /// * `compressor` - The compressor for decompression
    /// * `data_shards` - Number of data shards in erasure config
    /// * `parity_shards` - Number of parity shards in erasure config
    pub fn new(args: SessionErasureBlockIteratorArgs<'a, R>) -> Result<Self> {
        let SessionErasureBlockIteratorArgs {
            volume_readers,
            volume_indices,
            original_volume_count,
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            compressor,
            data_shards,
            parity_shards,
            distribution_strategy,
        } = args;
        if volume_readers.is_empty() {
            return Err(EraError::InvalidFormat("No volume readers provided".into()));
        }
        if volume_readers.len() != volume_indices.len() {
            return Err(EraError::InvalidFormat(
                "volume_readers and volume_indices length mismatch".to_string(),
            ));
        }

        let mut current_offsets = Vec::with_capacity(volume_readers.len());
        let mut data_ends = Vec::with_capacity(volume_readers.len());

        for reader in volume_readers {
            let (start, end) = reader.data_region();
            let footer = reader.footer();
            let mut limit = if let Some(f) = footer {
                if f.has_catalog_location() {
                    f.catalog_offset()
                } else {
                    end
                }
            } else {
                end
            };

            if let Some(f) = footer {
                if f.has_index() && f.index_offset() < limit {
                    limit = f.index_offset();
                }
            }
            current_offsets.push(start);
            data_ends.push(limit);
        }

        let total_shards = data_shards as usize + parity_shards as usize;

        // Build reverse map: original_vol_index -> position in volume_readers
        let inferred_volume_count = volume_indices.iter().copied().max().unwrap_or(0) + 1;
        let original_volume_count = original_volume_count.max(inferred_volume_count).max(1);
        let mut vol_index_map = vec![None; original_volume_count];
        for (reader_idx, &orig_idx) in volume_indices.iter().enumerate() {
            if orig_idx < original_volume_count {
                vol_index_map[orig_idx] = Some(reader_idx);
            }
        }

        let unpacker = SessionBlockUnpacker::new(
            session,
            volume_key,
            nonce_context,
            archive_id,
            epoch_id,
            compressor,
        );

        Ok(Self {
            volume_readers,
            unpacker,
            data_shards,
            parity_shards,
            total_shards,
            vol_index_map,
            original_volume_count,
            current_offsets,
            data_ends,
            block_index: 0,
            current_stripe_index: 0,
            distribution_strategy,
            stats: BlockIterStats::default(),
            pending_blocks: VecDeque::new(),
        })
    }
}

#[async_trait(?Send)]
impl<'a, R: era_storage::StorageReader> BlockIterator
    for Result<SessionErasureBlockIterator<'a, R>>
{
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        match self {
            Ok(iter) => iter.next_block().await,
            Err(e) => Some(Err(std::mem::replace(
                e,
                EraError::InvalidFormat("Session erasure iterator initialization failed".into()),
            ))),
        }
    }

    fn has_more(&self) -> bool {
        match self {
            Ok(iter) => iter.has_more(),
            Err(_) => true,
        }
    }

    fn stats(&self) -> &BlockIterStats {
        static EMPTY_STATS: BlockIterStats = BlockIterStats {
            blocks_read: 0,
            blocks_failed: 0,
            corrupted_shards: 0,
        };

        match self {
            Ok(iter) => iter.stats(),
            Err(_) => &EMPTY_STATS,
        }
    }
}

#[async_trait(?Send)]
impl<'a, R: era_storage::StorageReader> BlockIterator for SessionErasureBlockIterator<'a, R> {
    async fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        if let Some(result) = self.pending_blocks.pop_front() {
            return Some(result);
        }

        let stripe_size = self.total_shards;
        let data_shards = self.data_shards as usize;
        let parity_shards = self.parity_shards as usize;

        let mut available_shards: Vec<VerifiedShard> = Vec::with_capacity(stripe_size);
        let mut data_lengths: Vec<Option<u32>> = vec![None; data_shards];
        let mut max_len: usize = 0;
        let mut stripe_lengths: Option<Vec<u32>> = None;
        let header_prefix_len = data_shards * 4;

        let mut any_shard_seen = false;

        for shard_idx in 0..stripe_size {
            let vol_idx = match self.distribution_strategy.calculate_volume(
                shard_idx,
                self.current_stripe_index as u64,
                self.original_volume_count,
            ) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            let reader_idx_opt = self.vol_index_map.get(vol_idx).copied().flatten();
            if let Some(idx) = reader_idx_opt {
                let reader = &self.volume_readers[idx];

                if self.current_offsets[idx] >= self.data_ends[idx] {
                    continue;
                }

                let prefix_bytes = match reader
                    .read_raw(self.current_offsets[idx], header_prefix_len)
                    .await
                {
                    Ok(bytes) if bytes.len() == header_prefix_len => {
                        any_shard_seen = true;
                        bytes
                    }
                    Ok(_) => {
                        self.current_offsets[idx] = self.data_ends[idx];
                        continue;
                    }
                    Err(_) => {
                        self.current_offsets[idx] = self.data_ends[idx];
                        continue;
                    }
                };

                if stripe_lengths.is_none() {
                    let mut lengths = Vec::with_capacity(data_shards);
                    for chunk in prefix_bytes.chunks_exact(4) {
                        lengths.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                    }
                    stripe_lengths = Some(lengths);
                }

                let header_bytes = match reader
                    .read_raw(
                        self.current_offsets[idx] + header_prefix_len as u64,
                        ShardHeader::SIZE,
                    )
                    .await
                {
                    Ok(bytes) if bytes.len() == ShardHeader::SIZE => bytes,
                    Ok(_) => {
                        self.current_offsets[idx] = self.data_ends[idx];
                        continue;
                    }
                    Err(_) => {
                        self.current_offsets[idx] = self.data_ends[idx];
                        continue;
                    }
                };

                let shard_header = match ShardHeader::from_bytes(&header_bytes) {
                    Some(h) => h,
                    None => {
                        self.current_offsets[idx] = self.data_ends[idx];
                        continue;
                    }
                };

                let shard_len = shard_header.length as usize;
                if let Some(slot) = data_lengths.get_mut(shard_idx) {
                    *slot = Some(shard_header.length);
                }
                if shard_len > max_len {
                    max_len = shard_len;
                }

                let shard_data = match reader
                    .read_raw(
                        self.current_offsets[idx]
                            + header_prefix_len as u64
                            + ShardHeader::SIZE as u64,
                        shard_len,
                    )
                    .await
                {
                    Ok(data) => data,
                    Err(_) => {
                        self.current_offsets[idx] +=
                            header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
                        continue;
                    }
                };

                if shard_header.verify(&shard_data) {
                    available_shards.push(VerifiedShard {
                        index: shard_idx,
                        data: shard_data,
                        expected_crc: shard_header.crc,
                        crc_valid: true,
                    });
                } else {
                    self.stats.corrupted_shards += 1;
                    available_shards.push(VerifiedShard {
                        index: shard_idx,
                        data: shard_data,
                        expected_crc: shard_header.crc,
                        crc_valid: false,
                    });
                }

                self.current_offsets[idx] +=
                    header_prefix_len as u64 + ShardHeader::SIZE as u64 + shard_len as u64;
            }
        }

        if let Some(lengths) = stripe_lengths {
            if let Some(stripe_max) = lengths.iter().copied().max() {
                if stripe_max as usize > max_len {
                    max_len = stripe_max as usize;
                }
            }

            for (idx, len) in lengths.into_iter().enumerate().take(data_shards) {
                if data_lengths[idx].is_none() && len > 0 {
                    data_lengths[idx] = Some(len);
                }
            }
        }

        if max_len == 0 {
            return if any_shard_seen {
                self.pending_blocks.push_back(Err(EraError::ErasureError(
                    "Unexpected EOF while reading stripe".into(),
                )));
                self.pending_blocks.pop_front()
            } else {
                None
            };
        }

        let shard_size = if max_len.is_multiple_of(2) {
            max_len
        } else {
            max_len + 1
        };
        let total_shards = data_shards + parity_shards;
        let mut shard_array: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        let crc_failed_count = available_shards.iter().filter(|s| !s.crc_valid).count();
        for shard in available_shards.iter() {
            // Only use CRC-valid shards for RS recovery
            if shard.crc_valid {
                shard_array[shard.index] = Some(shard.data.to_vec());
            }
        }

        let coder = match ErasureConfig::new(data_shards, parity_shards).and_then(ErasureCoder::new)
        {
            Ok(c) => c,
            Err(e) => {
                self.pending_blocks.push_back(Err(e));
                return self.pending_blocks.pop_front();
            }
        };

        let recovered = match coder.recover_data_shards(&shard_array, shard_size) {
            Ok(data) => data,
            Err(e) => {
                let msg = e.to_string();
                for _ in 0..data_shards {
                    self.pending_blocks
                        .push_back(Err(EraError::ErasureError(msg.clone())));
                    self.stats.blocks_failed += 1;
                    self.block_index += 1;
                }
                self.current_stripe_index += 1;
                return self.pending_blocks.pop_front();
            }
        };

        for (i, shard_data) in recovered.into_iter().enumerate().take(data_shards) {
            let block_index = (self.current_stripe_index * data_shards + i) as u32;
            let build_candidate_lengths = |data: &[u8]| {
                // Heuristic for recovered data-shard length:
                // 1) Prefer explicit per-shard lengths (from headers) when available.
                // 2) Otherwise, reuse observed lengths from other data shards in stripe.
                // 3) Fall back to trimmed length after removing trailing zero padding,
                //    assuming RS-recovered shards may retain zeroed tail bytes.
                // 4) Finally try full shard_size as a conservative fallback.
                let mut candidate_lengths: Vec<usize> = Vec::new();
                let mut trimmed_len = data.len();

                if let Some(len) = data_lengths[i] {
                    candidate_lengths.push(len as usize);
                } else {
                    for len in data_lengths.iter().flatten() {
                        candidate_lengths.push(*len as usize);
                    }

                    while trimmed_len > 0 && data[trimmed_len - 1] == 0 {
                        trimmed_len -= 1;
                    }
                    if trimmed_len > 0 {
                        candidate_lengths.push(trimmed_len);
                    }

                    if shard_size > 0 && shard_size <= data.len() {
                        candidate_lengths.push(shard_size);
                    }
                }

                candidate_lengths.sort_unstable_by(|a, b| b.cmp(a));
                candidate_lengths.dedup();
                candidate_lengths
            };

            let mut decoded = None;
            let mut last_err = None;

            let mut attempt_decode = |data: &[u8]| -> Option<ChunkVec> {
                let candidate_lengths = build_candidate_lengths(data);
                let candidate_count = candidate_lengths.len();
                for original_len in candidate_lengths.iter().copied() {
                    if original_len == 0 || original_len > data.len() {
                        continue;
                    }

                    let trimmed = &data[..original_len];

                    if trimmed.iter().all(|&b| b == 0) {
                        return Some(ChunkVec::new());
                    }

                    let encrypted_block = era_common::EncryptedMacroBlock {
                        block_id: BlockId::new(block_index as u64),
                        data: Bytes::copy_from_slice(trimmed),
                        original_size: original_len as u32,
                        compressed_size: original_len as u32,
                        chunk_count: 0,
                    };

                    match self.unpacker.extract_all_chunks(&encrypted_block) {
                        Ok(chunks) => return Some(chunks),
                        Err(e) => last_err = Some(e),
                    }
                }
                tracing::warn!(
                    "No valid candidate length found after scanning {} candidates",
                    candidate_count
                );
                None
            };

            if let Some(chunks) = attempt_decode(&shard_data) {
                decoded = Some(chunks);
            }

            if decoded.is_none() && parity_shards > 0 {
                let original = shard_array[i].take();
                let result = coder.recover_data_shards(&shard_array, shard_size);
                shard_array[i] = original;
                if let Ok(alt_recovered) = result {
                    if let Some(chunks) = attempt_decode(&alt_recovered[i]) {
                        decoded = Some(chunks);
                        self.stats.corrupted_shards += 1;
                    }
                }
            }

            let mut trimmed_len = shard_data.len();
            while trimmed_len > 0 && shard_data[trimmed_len - 1] == 0 {
                trimmed_len -= 1;
            }

            let candidate_lengths = build_candidate_lengths(&shard_data);

            if decoded.is_none() && data_lengths[i].is_none() && trimmed_len < shard_size {
                let padding = shard_size.saturating_sub(trimmed_len);
                let step = if padding > MAX_PROBE_ATTEMPTS {
                    (padding / MAX_PROBE_ATTEMPTS).max(1)
                } else {
                    1
                };

                let mut probe_len = shard_size;
                let mut probe_attempts = 0usize;
                let mut warned_halfway = false;
                while probe_len >= trimmed_len {
                    if !candidate_lengths.contains(&probe_len)
                        && probe_len <= shard_data.len()
                        && probe_len > 0
                    {
                        probe_attempts += 1;
                        if !warned_halfway && probe_attempts > (MAX_PROBE_ATTEMPTS / 2) {
                            tracing::warn!(
                                "Virtual striping probing crossed half limit ({} / {}) for block {}",
                                probe_attempts,
                                MAX_PROBE_ATTEMPTS,
                                block_index
                            );
                            warned_halfway = true;
                        }
                        if probe_attempts > MAX_PROBE_ATTEMPTS {
                            last_err = Some(EraError::ErasureError(format!(
                                "Virtual striping probe limit exceeded for block {} ({} > {})",
                                block_index, probe_attempts, MAX_PROBE_ATTEMPTS
                            )));
                            break;
                        }

                        let data = &shard_data[..probe_len];

                        if data.iter().all(|&b| b == 0) {
                            decoded = Some(ChunkVec::new());
                            break;
                        }

                        let encrypted_block = era_common::EncryptedMacroBlock {
                            block_id: BlockId::new(block_index as u64),
                            data: Bytes::copy_from_slice(data),
                            original_size: probe_len as u32,
                            compressed_size: probe_len as u32,
                            chunk_count: 0,
                        };

                        match self.unpacker.extract_all_chunks(&encrypted_block) {
                            Ok(chunks) => {
                                decoded = Some(chunks);
                                break;
                            }
                            Err(e) => {
                                last_err = Some(e);
                            }
                        }
                    }

                    if probe_len < step {
                        break;
                    }
                    probe_len = probe_len.saturating_sub(step);
                }
            }

            match decoded {
                Some(chunks) => {
                    self.stats.blocks_read += 1;
                    self.pending_blocks.push_back(Ok(DecodedBlock {
                        block_index,
                        chunks,
                        corrupted_shards: crc_failed_count,
                    }));
                }
                None => {
                    self.stats.blocks_failed += 1;
                    self.pending_blocks
                        .push_back(Err(last_err.unwrap_or_else(|| {
                            EraError::ErasureError("Missing data shard length".into())
                        })));
                }
            }

            self.block_index += 1;
        }

        self.current_stripe_index += 1;
        self.pending_blocks.pop_front()
    }

    fn has_more(&self) -> bool {
        self.current_offsets
            .iter()
            .zip(self.data_ends.iter())
            .any(|(offset, end)| offset < end)
    }

    fn stats(&self) -> &BlockIterStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_iter_stats_default() {
        let stats = BlockIterStats::default();
        assert_eq!(stats.blocks_read, 0);
        assert_eq!(stats.blocks_failed, 0);
        assert_eq!(stats.corrupted_shards, 0);
    }
}
