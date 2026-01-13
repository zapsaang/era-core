//! MacroBlock-related types.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::{BlockId, ChunkHash, VolumeId};

/// Default MacroBlock size: 4MB
pub const DEFAULT_MACRO_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// A packed MacroBlock before compression/encryption
#[derive(Debug, Clone)]
pub struct PackedMacroBlock {
    /// Block ID
    pub block_id: BlockId,
    /// Serialized data (chunk index + chunk data)
    pub data: Bytes,
    /// Number of chunks in this block
    pub chunk_count: u16,
    /// List of chunk hashes in order
    pub chunk_hashes: Vec<ChunkHash>,
}

/// An encrypted MacroBlock ready for storage
#[derive(Debug, Clone)]
pub struct EncryptedMacroBlock {
    /// Block ID
    pub block_id: BlockId,
    /// Encrypted data
    pub data: Bytes,
    /// Original (uncompressed) size
    pub original_size: u32,
    /// Compressed size (before encryption)
    pub compressed_size: u32,
    /// Number of chunks
    pub chunk_count: u16,
}

impl EncryptedMacroBlock {
    /// Get the size of the encrypted data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the block is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Location of a block in the archive
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockLocation {
    /// Volume containing this block
    pub volume_id: VolumeId,
    /// Slot index within the volume
    pub slot_index: u32,
    /// Physical offset in the volume file
    pub physical_offset: u64,
    /// Size of the encrypted block
    pub encrypted_size: u32,
}

/// Chunk index entry within a MacroBlock
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChunkIndexEntry {
    /// Hash of the chunk
    pub hash: ChunkHash,
    /// Offset within the block data
    pub offset: u32,
    /// Length of the chunk
    pub length: u32,
}

/// Index of all chunks within a MacroBlock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockChunkIndex {
    /// Number of chunks
    pub count: u16,
    /// Chunk entries
    pub entries: Vec<ChunkIndexEntry>,
}

/// Configuration for erasure coding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureCodeConfig {
    /// Number of data shards
    pub data_shards: u8,
    /// Number of parity shards
    pub parity_shards: u8,
}

impl Default for ErasureCodeConfig {
    fn default() -> Self {
        Self {
            data_shards: 4,
            parity_shards: 2,
        }
    }
}

impl ErasureCodeConfig {
    /// Create a new erasure configuration
    pub fn new(data_shards: u8, parity_shards: u8) -> Self {
        Self {
            data_shards,
            parity_shards,
        }
    }

    /// Total number of shards
    pub fn total_shards(&self) -> usize {
        self.data_shards as usize + self.parity_shards as usize
    }
}

/// An erasure-coded block with data and parity shards
#[derive(Debug, Clone)]
pub struct ErasureShardedBlock {
    /// Block ID
    pub block_id: BlockId,
    /// Erasure configuration
    pub config: ErasureCodeConfig,
    /// Original data length (before padding)
    pub original_len: u32,
    /// Shards (data shards first, then parity shards)
    pub shards: Vec<Bytes>,
}

/// Location of all shards for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardLocations {
    /// Block ID
    pub block_id: BlockId,
    /// Erasure configuration
    pub config: ErasureCodeConfig,
    /// Original data length
    pub original_len: u32,
    /// Locations of each shard (indexed by shard number)
    pub shard_locations: Vec<ShardLocation>,
}

/// Location of a single shard
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ShardLocation {
    /// Shard index (0..data_shards for data, data_shards..total for parity)
    pub shard_index: u8,
    /// Volume containing this shard
    pub volume_id: VolumeId,
    /// Physical offset in the volume
    pub physical_offset: u64,
    /// Size of the shard
    pub shard_size: u32,
}
