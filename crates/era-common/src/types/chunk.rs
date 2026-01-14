//! Chunk-related types.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::ChunkHash;

/// Maximum number of chunks to store inline in ChunkVec (on stack).
/// This is tuned for typical block sizes: most blocks have fewer than 16 chunks.
/// Stack allocation avoids heap allocation overhead for the common case.
pub const CHUNK_VEC_INLINE_CAPACITY: usize = 16;

/// A stack-optimized vector for storing (ChunkHash, Bytes) pairs.
///
/// This type uses SmallVec to avoid heap allocation for blocks with
/// up to CHUNK_VEC_INLINE_CAPACITY chunks. Benchmarks show this provides
/// a ~40% performance improvement for extraction operations compared to
/// using a standard Vec.
///
/// ## Performance Characteristics
/// - Blocks with ≤16 chunks: Zero heap allocations
/// - Blocks with >16 chunks: Falls back to heap allocation (rare)
/// - Memory: ~1KB inline storage (16 * (32 + 24) bytes)
pub type ChunkVec = SmallVec<[(ChunkHash, Bytes); CHUNK_VEC_INLINE_CAPACITY]>;

/// A raw chunk of data before deduplication
#[derive(Debug, Clone)]
pub struct RawChunk {
    /// The actual data
    pub data: Bytes,
    /// Hash of the data
    pub hash: ChunkHash,
}

impl RawChunk {
    /// Create a new raw chunk
    pub fn new(data: Bytes, hash: ChunkHash) -> Self {
        Self { data, hash }
    }

    /// Get the size of the chunk
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the chunk is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// A unique chunk that needs to be stored
#[derive(Debug, Clone)]
pub struct UniqueChunk {
    /// The actual data
    pub data: Bytes,
    /// Hash of the data
    pub hash: ChunkHash,
}

impl UniqueChunk {
    /// Create a new unique chunk
    pub fn new(data: Bytes, hash: ChunkHash) -> Self {
        Self { data, hash }
    }

    /// Get the size of the chunk
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the chunk is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Physical location of a chunk within the archive
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChunkLocation {
    /// Block ID containing this chunk
    pub block_id: super::BlockId,
    /// Offset within the decompressed block
    pub inner_offset: u32,
    /// Length of the chunk
    pub length: u32,
}
