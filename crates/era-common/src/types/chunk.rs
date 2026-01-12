//! Chunk-related types.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::ChunkHash;

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
