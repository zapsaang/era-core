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

// NOTE: Legacy LsmChunkIndex trait implementation removed during V2.1 migration.
// The V2 index uses a different architecture (IndexBuilder/IndexReader) that doesn't
// implement the ChunkIndex trait. For production use, migrate to V2 APIs directly.

/// Chunk index backend selection.
///
/// NOTE: LSM backends have been removed during V2.1 migration. Only Memory backend
/// is supported. For persistent indexing, use era_index::v2 APIs directly.
#[derive(Debug, Clone, Default)]
pub enum ChunkIndexBackend {
    /// In-memory HashMap (legacy, not recommended for production)
    #[default]
    Memory,
    /// DEPRECATED: LSM-Tree backend removed. Use Memory or migrate to V2 APIs.
    #[deprecated(note = "LSM backend removed in V2.1. Use Memory or era_index::v2 APIs.")]
    Lsm { path: std::path::PathBuf },
    /// DEPRECATED: Embedded LSM backend removed. Use Memory or migrate to V2 APIs.
    #[deprecated(note = "Embedded LSM backend removed in V2.1. Use Memory or era_index::v2 APIs.")]
    EmbeddedLsm { path: std::path::PathBuf },
}

/// Create a chunk index with the specified backend.
///
/// NOTE: Only Memory backend is supported after V2.1 migration.
/// LSM backends will fall back to Memory with a warning.
#[allow(deprecated)] // Intentional: handling deprecated variants for backward compatibility
pub fn create_chunk_index(backend: ChunkIndexBackend) -> EraResult<Arc<dyn ChunkIndex>> {
    match backend {
        ChunkIndexBackend::Memory => Ok(Arc::new(MemoryChunkIndex::new())),
        ChunkIndexBackend::Lsm { .. } | ChunkIndexBackend::EmbeddedLsm { .. } => {
            // Fallback to Memory mode - LSM backends removed in V2.1
            eprintln!(
                "WARNING: LSM backend requested but removed in V2.1. Falling back to Memory mode."
            );
            eprintln!("         For persistent indexing, migrate to era_index::v2 APIs.");
            Ok(Arc::new(MemoryChunkIndex::new()))
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
