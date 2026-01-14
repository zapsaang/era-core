//! Block iterator abstraction for unified block reading.
//!
//! This module provides a common interface for iterating over blocks
//! in both standard and erasure-coded archives, eliminating code duplication.
//!
//! ## Security (ERA v8.1)
//!
//! Session-based iterators (`SessionBlockIterator`, `SessionErasureBlockIterator`)
//! use the HKDF "Onion Model" for per-block key derivation:
//! - Each block is decrypted with a unique key derived from the volume key
//! - This provides forward and backward security isolation
//!
//! Legacy iterators (`StandardBlockIterator`, `ErasureBlockIterator`) use a single
//! key for all blocks and are kept for backward compatibility.

use bytes::Bytes;
use era_common::{
    BlockId, BlockLocation, ChunkHash, EraError, ErasureBlockInfo, Result, ShardHeader,
};
use era_crypto::{KeySession, VolumeKey};
use era_packing::{
    ErasureBlockUnpacker, MacroBlockUnpacker, SessionBlockUnpacker, SessionErasureBlockUnpacker,
};
use era_volume::VolumeReader;

/// Result of reading and decoding a block
#[derive(Debug)]
pub struct DecodedBlock {
    /// Block index (for error reporting)
    pub block_index: u32,
    /// Chunks extracted from the block: (hash, data)
    pub chunks: Vec<(ChunkHash, Bytes)>,
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
pub trait BlockIterator {
    /// Get the next block's decoded chunks
    /// Returns None when iteration is complete
    fn next_block(&mut self) -> Option<Result<DecodedBlock>>;

    /// Check if there are more blocks to read
    fn has_more(&self) -> bool;

    /// Get iteration statistics
    fn stats(&self) -> &BlockIterStats;
}

/// Maximum allowed block size (16 MB) - prevents malicious archives from causing OOM
const MAX_BLOCK_SIZE: u32 = 16 * 1024 * 1024;

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

impl<'a, R: era_storage::StorageReader> BlockIterator for StandardBlockIterator<'a, R> {
    fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        if self.current_offset >= self.data_end {
            return None;
        }

        // Read block length prefix
        let len_bytes = match self.volume_reader.read_raw(self.current_offset, 4) {
            Ok(bytes) if bytes.len() == 4 => bytes,
            Ok(_) => return None,
            Err(e) => return Some(Err(e)),
        };

        let block_size =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);

        // Validate block size
        if block_size == 0 {
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::CorruptedHeader(format!(
                "Zero-length block at offset {}",
                self.current_offset
            ))));
        }
        if block_size > MAX_BLOCK_SIZE {
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::BlockTooLarge {
                size: block_size as usize,
                max_size: MAX_BLOCK_SIZE as usize,
            }));
        }

        let location = BlockLocation {
            volume_id: self.volume_reader.header().volume_id,
            slot_index: self.block_index,
            physical_offset: self.current_offset,
            encrypted_size: block_size,
            erasure_info: None,
            shard_offsets: None,
        };

        // Read and decrypt block
        let result = match self.volume_reader.read_block(&location) {
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

        // Advance to next block
        self.current_offset += 4 + block_size as u64;
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
    ///                      e.g., [0, 2] means volume 0 and volume 2 are present
    /// * `erasure_unpacker` - Unpacker for erasure-coded blocks  
    /// * `data_shards` - Number of data shards in erasure config
    /// * `parity_shards` - Number of parity shards in erasure config
    pub fn new(
        volume_readers: &'a [VolumeReader<R>],
        volume_indices: &[usize],
        erasure_unpacker: &'a ErasureBlockUnpacker,
        data_shards: u8,
        parity_shards: u8,
    ) -> Self {
        let mut current_offsets = Vec::with_capacity(volume_readers.len());
        let mut data_ends = Vec::with_capacity(volume_readers.len());

        for reader in volume_readers {
            let (start, end) = reader.data_region();
            let footer = reader.footer();
            let limit = if footer.has_catalog_location() {
                footer.catalog_offset
            } else {
                end
            };
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

        Self {
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
        }
    }
}

impl<'a, R: era_storage::StorageReader> BlockIterator for ErasureBlockIterator<'a, R> {
    fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        // Find the first available volume to check if there's more data
        // We need to use the first reader in volume_readers (which is the lowest available volume)
        // Since each volume has original_len header for each block, we can read from any volume
        if self.current_offsets[0] >= self.data_ends[0] {
            return None;
        }

        // Read erasure block header (4 bytes original_len) from the first available volume
        // All volumes now have this header written before their first shard of each block
        let header_bytes = match self.volume_readers[0].read_raw(self.current_offsets[0], 4) {
            Ok(bytes) if bytes.len() == 4 => bytes,
            Ok(_) => return None,
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

        // Read all shards for this block
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(self.total_shards);
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
            let header_bytes = match reader.read_raw(offset, ShardHeader::SIZE) {
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
            match reader.read_raw(self.current_offsets[reader_idx], shard_len) {
                Ok(shard_data) => {
                    // Verify CRC
                    if shard_header.verify(&shard_data) {
                        shards.push((shard_idx, shard_data));
                    } else {
                        corrupted_count += 1;
                    }
                }
                Err(_) => {
                    corrupted_count += 1;
                }
            }

            // Advance past data
            self.current_offsets[reader_idx] += shard_len as u64;
        }

        self.stats.corrupted_shards += corrupted_count as u32;

        if shards.is_empty() {
            // If we failed to read ANY shards, verification fails.
            // Also if we failed to update offsets correctly, subsequent blocks will fail.
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::ErasureError(format!(
                "No valid shards for block {}",
                self.block_index
            ))));
        }

        // Create erasure info for decoding
        let erasure_info = ErasureBlockInfo {
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            shard_size: first_shard_size,
            original_len,
        };

        let block_id = BlockId::new(self.block_index as u64);

        // Decode and extract chunks
        let result =
            match self
                .erasure_unpacker
                .decode_and_extract_all(shards, &erasure_info, block_id)
            {
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
                    Err(e)
                }
            };

        self.block_index += 1;
        Some(result)
    }

    fn has_more(&self) -> bool {
        // Check the first available volume for more data (at least 4 bytes for next header)
        // volume_readers[0] is always the first available volume in sorted order
        self.current_offsets[0] + 4 <= self.data_ends[0]
    }

    fn stats(&self) -> &BlockIterStats {
        &self.stats
    }
}

// =============================================================================
// Session-based iterators with per-block key derivation (ERA v8.1)
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
        compressor: Box<dyn era_codec::Compressor>,
    ) -> Self {
        let (data_start, data_end) = volume_reader.data_region();
        let unpacker = SessionBlockUnpacker::new(session, volume_key, nonce_context, compressor);
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
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        nonce_context: [u8; 16],
        compressor: Box<dyn era_codec::Compressor>,
        end_offset: u64,
    ) -> Self {
        let (data_start, _) = volume_reader.data_region();
        let unpacker = SessionBlockUnpacker::new(session, volume_key, nonce_context, compressor);
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

impl<'a, R: era_storage::StorageReader> BlockIterator for SessionBlockIterator<'a, R> {
    fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        if self.current_offset >= self.data_end {
            return None;
        }

        // Read block length prefix
        let len_bytes = match self.volume_reader.read_raw(self.current_offset, 4) {
            Ok(bytes) if bytes.len() == 4 => bytes,
            Ok(_) => return None,
            Err(e) => return Some(Err(e)),
        };

        let block_size =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);

        // Validate block size
        if block_size == 0 {
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::CorruptedHeader(format!(
                "Zero-length block at offset {}",
                self.current_offset
            ))));
        }
        if block_size > MAX_BLOCK_SIZE {
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::BlockTooLarge {
                size: block_size as usize,
                max_size: MAX_BLOCK_SIZE as usize,
            }));
        }

        let location = BlockLocation {
            volume_id: self.volume_reader.header().volume_id,
            slot_index: self.block_index,
            physical_offset: self.current_offset,
            encrypted_size: block_size,
            erasure_info: None,
            shard_offsets: None,
        };

        // Read and decrypt block with per-block key derivation
        let result = match self.volume_reader.read_block(&location) {
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

        // Advance to next block
        self.current_offset += 4 + block_size as u64;
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
    erasure_unpacker: SessionErasureBlockUnpacker<'a>,
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
    /// Iteration statistics
    stats: BlockIterStats,
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
    pub fn new(
        volume_readers: &'a [VolumeReader<R>],
        volume_indices: &[usize],
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        nonce_context: [u8; 16],
        compressor: Box<dyn era_codec::Compressor>,
        data_shards: u8,
        parity_shards: u8,
    ) -> Self {
        let mut current_offsets = Vec::with_capacity(volume_readers.len());
        let mut data_ends = Vec::with_capacity(volume_readers.len());

        for reader in volume_readers {
            let (start, end) = reader.data_region();
            let footer = reader.footer();
            let limit = if footer.has_catalog_location() {
                footer.catalog_offset
            } else {
                end
            };
            current_offsets.push(start);
            data_ends.push(limit);
        }

        let total_shards = data_shards as usize + parity_shards as usize;

        // Build reverse map: original_vol_index -> position in volume_readers
        let original_volume_count = volume_indices.iter().copied().max().unwrap_or(0) + 1;
        let mut vol_index_map = vec![None; original_volume_count];
        for (reader_idx, &orig_idx) in volume_indices.iter().enumerate() {
            if orig_idx < original_volume_count {
                vol_index_map[orig_idx] = Some(reader_idx);
            }
        }

        let erasure_unpacker =
            SessionErasureBlockUnpacker::new(session, volume_key, nonce_context, compressor);

        Self {
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
        }
    }
}

impl<'a, R: era_storage::StorageReader> BlockIterator for SessionErasureBlockIterator<'a, R> {
    fn next_block(&mut self) -> Option<Result<DecodedBlock>> {
        // Find the first available volume to check if there's more data
        if self.current_offsets[0] >= self.data_ends[0] {
            return None;
        }

        // Read erasure block header (4 bytes original_len) from the first available volume
        let header_bytes = match self.volume_readers[0].read_raw(self.current_offsets[0], 4) {
            Ok(bytes) if bytes.len() == 4 => bytes,
            Ok(_) => return None,
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

        // Read all shards for this block
        let mut shards: Vec<(usize, Bytes)> = Vec::with_capacity(self.total_shards);
        let mut corrupted_count = 0usize;
        let mut first_shard_size = 0u32;

        // Track which volumes have had their block header read
        let mut header_read_for_volume = vec![false; self.volume_readers.len()];
        header_read_for_volume[0] = true;

        for shard_idx in 0..self.total_shards {
            let orig_vol_idx = shard_idx % self.original_volume_count;

            // Look up if this volume is available
            let reader_idx = match self.vol_index_map.get(orig_vol_idx) {
                Some(Some(idx)) => *idx,
                _ => {
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
            let header_bytes = match reader.read_raw(offset, ShardHeader::SIZE) {
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
            match reader.read_raw(self.current_offsets[reader_idx], shard_len) {
                Ok(shard_data) => {
                    // Verify CRC
                    if shard_header.verify(&shard_data) {
                        shards.push((shard_idx, shard_data));
                    } else {
                        corrupted_count += 1;
                    }
                }
                Err(_) => {
                    corrupted_count += 1;
                }
            }

            // Advance past data
            self.current_offsets[reader_idx] += shard_len as u64;
        }

        self.stats.corrupted_shards += corrupted_count as u32;

        if shards.is_empty() {
            self.stats.blocks_failed += 1;
            return Some(Err(EraError::ErasureError(format!(
                "No valid shards for block {}",
                self.block_index
            ))));
        }

        // Create erasure info for decoding
        let erasure_info = ErasureBlockInfo {
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            shard_size: first_shard_size,
            original_len,
        };

        let block_id = BlockId::new(self.block_index as u64);

        // Decode and extract chunks with per-block key derivation
        let result =
            match self
                .erasure_unpacker
                .decode_and_extract_all(shards, &erasure_info, block_id)
            {
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
                    Err(e)
                }
            };

        self.block_index += 1;
        Some(result)
    }

    fn has_more(&self) -> bool {
        self.current_offsets[0] + 4 <= self.data_ends[0]
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
