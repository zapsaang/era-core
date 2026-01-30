//! MacroBlock-related types.

use bytes::Bytes;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
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
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvDeserialize, RkyvSerialize,
)]
#[archive(check_bytes)]
pub struct BlockLocation {
    /// Volume containing this block
    pub volume_id: VolumeId,
    /// Slot index within the volume
    pub slot_index: u32,
    /// Physical offset in the volume file
    pub physical_offset: u64,
    /// Size of the encrypted block (or first shard if erasure-coded)
    pub encrypted_size: u32,
    /// Erasure coding info (None = not erasure-coded)
    pub erasure_info: Option<ErasureBlockInfo>,
    /// Offsets for additional shards in distributed storage
    /// (Shard 0 is at physical_offset, Shard 1 at offsets[0], etc.)
    pub shard_offsets: Option<Vec<u64>>,
    /// Volume sequence numbers for each shard (for matrix distribution)
    /// When present, shard i is on volume_sequences[i].
    /// When None, uses legacy round-robin: shard i on volume (i % num_volumes).
    pub shard_volumes: Option<Vec<u16>>,
}

/// Information about an erasure-coded block
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
)]
#[archive(check_bytes)]
pub struct ErasureBlockInfo {
    /// Number of data shards
    pub data_shards: u8,
    /// Number of parity shards  
    pub parity_shards: u8,
    /// Size of each shard (all shards are same size)
    pub shard_size: u32,
    /// Original data length before padding
    pub original_len: u32,
}

impl BlockLocation {
    /// Check if this block is erasure-coded
    pub fn is_erasure_coded(&self) -> bool {
        self.erasure_info.is_some()
    }

    /// Get total number of shards (data + parity)
    pub fn total_shards(&self) -> usize {
        self.erasure_info
            .map(|e| e.data_shards as usize + e.parity_shards as usize)
            .unwrap_or(1)
    }
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

/// CRC32 checksum for shard integrity validation
pub fn compute_shard_crc(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Shard header containing metadata and CRC for integrity
#[derive(Debug, Clone, Copy)]
pub struct ShardHeader {
    /// Shard data length
    pub length: u32,
    /// CRC32 checksum of shard data
    pub crc: u32,
}

impl ShardHeader {
    /// Size of serialized shard header in bytes
    pub const SIZE: usize = 8; // 4 bytes length + 4 bytes CRC

    /// Create a new shard header
    pub fn new(length: u32, crc: u32) -> Self {
        Self { length, crc }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&self.length.to_le_bytes());
        buf[4..8].copy_from_slice(&self.crc.to_le_bytes());
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let length = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let crc = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(Self { length, crc })
    }

    /// Verify shard data against stored CRC
    pub fn verify(&self, data: &[u8]) -> bool {
        if data.len() != self.length as usize {
            return false;
        }
        compute_shard_crc(data) == self.crc
    }
}

/// Block type identifier for self-describing volume structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlockType {
    /// Standard data block containing encrypted chunks
    Data = 0x01,
    /// Index page containing chunk→location mappings (V2.1)
    IndexPage = 0x02,
    /// Index manifest root (MetaIndex)
    IndexManifest = 0x03,
    /// File catalog containing metadata
    Catalog = 0x04,
    /// LSM manifest (legacy RocksDB index)
    LsmManifest = 0x05,
    /// Checkpoint block for crash recovery (WAL)
    Checkpoint = 0x06,
    /// Reserved for future use
    Reserved = 0xFF,
}

impl BlockType {
    /// Convert to raw byte value
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse from raw byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Data),
            0x02 => Some(Self::IndexPage),
            0x03 => Some(Self::IndexManifest),
            0x04 => Some(Self::Catalog),
            0x05 => Some(Self::LsmManifest),
            0x06 => Some(Self::Checkpoint),
            0xFF => Some(Self::Reserved),
            _ => None,
        }
    }

    /// Check if this block type is an index-related block
    pub fn is_index_block(self) -> bool {
        matches!(self, Self::IndexPage | Self::IndexManifest)
    }
}

/// Block header for self-identifying blocks
/// Replaces ShardHeader with type discrimination
#[derive(Debug, Clone, Copy)]
pub struct BlockHeader {
    /// Block format version (current: 1)
    pub version: u8,
    /// Block type identifier
    pub block_type: BlockType,
    /// Reserved for alignment (2 bytes)
    pub reserved: [u8; 2],
    /// Encrypted payload length
    pub length: u32,
    /// CRC32 checksum of encrypted payload
    pub crc: u32,
    /// Reserved for future expansion (4 bytes)
    pub reserved2: [u8; 4],
}

impl BlockHeader {
    /// Size of serialized block header (16 bytes for cache alignment)
    pub const SIZE: usize = 16;

    /// Current header version
    pub const VERSION: u8 = 1;

    /// Create a new block header
    pub fn new(block_type: BlockType, length: u32, crc: u32) -> Self {
        Self {
            version: Self::VERSION,
            block_type,
            reserved: [0u8; 2],
            length,
            crc,
            reserved2: [0u8; 4],
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0] = self.version;
        buf[1] = self.block_type.to_u8();
        buf[2..4].copy_from_slice(&self.reserved);
        buf[4..8].copy_from_slice(&self.length.to_le_bytes());
        buf[8..12].copy_from_slice(&self.crc.to_le_bytes());
        buf[12..16].copy_from_slice(&self.reserved2);
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let version = buf[0];
        let block_type = BlockType::from_u8(buf[1])?;
        let reserved = [buf[2], buf[3]];
        let length = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let crc = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let reserved2 = [buf[12], buf[13], buf[14], buf[15]];

        Some(Self {
            version,
            block_type,
            reserved,
            length,
            crc,
            reserved2,
        })
    }

    /// Verify payload against stored CRC
    pub fn verify(&self, data: &[u8]) -> bool {
        if data.len() != self.length as usize {
            return false;
        }
        compute_shard_crc(data) == self.crc
    }

    /// Check if this is a legacy ShardHeader (version 0)
    pub fn is_legacy(&self) -> bool {
        self.version == 0
    }
}
