//! Chunk deduplication index abstraction layer.
//!
//! This module provides a unified interface for chunk deduplication that can use
//! either in-memory HashMap (for backward compatibility) or persistent LSM-Tree
//! storage (recommended for production).

use std::collections::HashMap;
use std::sync::Arc;

use era_common::{BlockLocation, ChunkHash, Result as EraResult};
use parking_lot::RwLock;

/// Trait for chunk deduplication index implementations.
///
/// Both HashMap and LsmChunkIndex implement this trait, allowing
/// ArchiveWriter to use either backend.
pub trait ChunkIndex: Send + Sync {
    /// Check if a chunk exists in the index.
    fn contains(&self, hash: &ChunkHash) -> EraResult<bool>;

    /// Get the location of a chunk.
    fn get(&self, hash: &ChunkHash) -> EraResult<Option<BlockLocation>>;

    /// Store a chunk location.
    fn put(&self, hash: ChunkHash, location: BlockLocation) -> EraResult<()>;

    /// Delete a chunk from the index.
    fn delete(&self, hash: &ChunkHash) -> EraResult<()>;

    /// Get the approximate number of entries.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Flush any pending writes to stable storage.
    fn flush(&self) -> EraResult<()>;

    /// Start batch mode for improved write throughput.
    fn start_batch(&self);

    /// Commit batch writes.
    fn commit_batch(&self) -> EraResult<()>;
}

/// In-memory HashMap-based chunk index (legacy, for testing or small archives).
///
/// ⚠️ WARNING: This implementation does NOT provide:
/// - Persistence (all data lost on process exit)
/// - Incremental backup support
/// - Memory efficiency for large archives
///
/// Use `LsmChunkIndex` for production workloads.
pub struct MemoryChunkIndex {
    inner: RwLock<HashMap<ChunkHash, BlockLocation>>,
}

impl MemoryChunkIndex {
    /// Create a new empty in-memory index.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Create with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(capacity)),
        }
    }

    /// Get direct access to the underlying HashMap (for migration).
    pub fn into_inner(self) -> HashMap<ChunkHash, BlockLocation> {
        self.inner.into_inner()
    }
}

impl Default for MemoryChunkIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkIndex for MemoryChunkIndex {
    fn contains(&self, hash: &ChunkHash) -> EraResult<bool> {
        Ok(self.inner.read().contains_key(hash))
    }

    fn get(&self, hash: &ChunkHash) -> EraResult<Option<BlockLocation>> {
        Ok(self.inner.read().get(hash).cloned())
    }

    fn put(&self, hash: ChunkHash, location: BlockLocation) -> EraResult<()> {
        self.inner.write().insert(hash, location);
        Ok(())
    }

    fn delete(&self, hash: &ChunkHash) -> EraResult<()> {
        self.inner.write().remove(hash);
        Ok(())
    }

    fn len(&self) -> usize {
        self.inner.read().len()
    }

    fn flush(&self) -> EraResult<()> {
        // No-op for in-memory implementation
        Ok(())
    }

    fn start_batch(&self) {
        // No-op for in-memory implementation
    }

    fn commit_batch(&self) -> EraResult<()> {
        // No-op for in-memory implementation
        Ok(())
    }
}

#[cfg(feature = "lsm")]
mod lsm_impl {
    use super::*;
    use era_index::LsmChunkIndex;

    impl ChunkIndex for LsmChunkIndex {
        fn contains(&self, hash: &ChunkHash) -> EraResult<bool> {
            self.contains(hash).map_err(Into::into)
        }

        fn get(&self, hash: &ChunkHash) -> EraResult<Option<BlockLocation>> {
            self.get(hash).map_err(Into::into)
        }

        fn put(&self, hash: ChunkHash, location: BlockLocation) -> EraResult<()> {
            LsmChunkIndex::put(self, hash, location).map_err(Into::into)
        }

        fn delete(&self, hash: &ChunkHash) -> EraResult<()> {
            LsmChunkIndex::delete(self, hash).map_err(Into::into)
        }

        fn len(&self) -> usize {
            LsmChunkIndex::len(self) as usize
        }

        fn flush(&self) -> EraResult<()> {
            LsmChunkIndex::flush(self).map_err(Into::into)
        }

        fn start_batch(&self) {
            LsmChunkIndex::start_batch(self);
        }

        fn commit_batch(&self) -> EraResult<()> {
            LsmChunkIndex::commit_batch(self).map_err(Into::into)
        }
    }
}

/// Chunk index backend selection.
#[derive(Debug, Clone)]
pub enum ChunkIndexBackend {
    /// In-memory HashMap (legacy, not recommended for production)
    Memory,
    /// LSM-Tree with RocksDB (recommended)
    #[cfg(feature = "lsm")]
    Lsm { path: std::path::PathBuf },
}

impl Default for ChunkIndexBackend {
    fn default() -> Self {
        Self::Memory
    }
}

/// Create a chunk index with the specified backend.
pub fn create_chunk_index(backend: ChunkIndexBackend) -> EraResult<Arc<dyn ChunkIndex>> {
    match backend {
        ChunkIndexBackend::Memory => Ok(Arc::new(MemoryChunkIndex::new())),
        #[cfg(feature = "lsm")]
        ChunkIndexBackend::Lsm { path } => {
            let index = era_index::LsmChunkIndex::open(path)
                .map_err(|e| era_common::EraError::IndexError(e.to_string()))?;
            Ok(Arc::new(index))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::VolumeId;

    fn create_test_location(slot: u32) -> BlockLocation {
        BlockLocation {
            volume_id: VolumeId::new(),
            slot_index: slot,
            physical_offset: slot as u64 * 4096,
            encrypted_size: 4096,
            erasure_info: None,
            shard_offsets: None,
            shard_volumes: None,
        }
    }

    #[test]
    fn test_memory_index() {
        let index = MemoryChunkIndex::new();

        let hash = ChunkHash::from_bytes([1u8; 32]);
        let location = create_test_location(0);

        assert!(!index.contains(&hash).unwrap());

        index.put(hash, location.clone()).unwrap();

        assert!(index.contains(&hash).unwrap());
        let retrieved = index.get(&hash).unwrap().unwrap();
        assert_eq!(retrieved.slot_index, location.slot_index);

        index.delete(&hash).unwrap();
        assert!(!index.contains(&hash).unwrap());
    }
}
