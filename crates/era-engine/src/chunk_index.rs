//! Chunk deduplication index abstraction layer.
//!
//! This module provides a unified interface for chunk deduplication that can use
//! either in-memory HashMap (for backward compatibility) or persistent LSM-Tree
//! storage (recommended for production).
//!
//! NOTE: MemoryChunkIndex is now internal only.
//! For production use, migrate to era_index::v2 APIs directly.

use std::any::Any;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use era_common::{BlockId, BlockLocation, ChunkHash, Result as EraResult};
use era_index::{IndexBuilder, IndexEntry};
use parking_lot::{Mutex, RwLock};

/// Trait for chunk deduplication index implementations.
///
/// Both HashMap and LsmChunkIndex implement this trait, allowing
/// ArchiveWriter to use either backend.
#[allow(dead_code)]
pub(crate) trait ChunkIndex: Send + Sync {
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

    /// Downcast to concrete type for extraction.
    fn as_any(&self) -> &dyn Any;
}

/// In-memory HashMap-based chunk index (legacy, for testing or small archives).
///
/// ⚠️ WARNING: This implementation does NOT provide:
/// - Persistence (all data lost on process exit)
/// - Incremental backup support
/// - Memory efficiency for large archives
///
/// Use `LsmChunkIndex` for production workloads.
///
/// This is internal only. Use era_index::v2 APIs for production.
#[allow(dead_code)]
pub(crate) struct MemoryChunkIndex {
    inner: RwLock<HashMap<ChunkHash, BlockLocation>>,
}

#[allow(dead_code)]
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
        Ok(())
    }

    fn start_batch(&self) {
    }

    fn commit_batch(&self) -> EraResult<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// LSM-Tree backed chunk index for production use.
///
/// Wraps an `IndexBuilder` (for accumulating entries destined for the volume)
/// alongside a `HashMap` (for fast point lookups during the write session).
///
/// At finalization the `IndexBuilder` is extracted via `take_builder()` and
/// finalized into typed index blocks written to the volume.
pub(crate) struct LsmChunkIndex {
    /// IndexBuilder accumulates entries for volume-embedded finalization.
    builder: Mutex<Option<IndexBuilder>>,
    /// Fast point-lookup map for dedup during the write session.
    lookup: RwLock<HashMap<ChunkHash, BlockLocation>>,
    /// Temp directory for IndexBuilder spill files.
    temp_dir: PathBuf,
}

impl LsmChunkIndex {
    /// Create a new LSM chunk index.
    pub fn new(temp_dir: PathBuf) -> Self {
        Self {
            builder: Mutex::new(Some(IndexBuilder::new_default())),
            lookup: RwLock::new(HashMap::new()),
            temp_dir,
        }
    }

    /// Take the `IndexBuilder` out for finalization.
    ///
    /// Returns `None` if the builder was already taken.
    pub fn take_builder(&self) -> Option<IndexBuilder> {
        self.builder.lock().take()
    }
}

impl ChunkIndex for LsmChunkIndex {
    fn contains(&self, hash: &ChunkHash) -> EraResult<bool> {
        Ok(self.lookup.read().contains_key(hash))
    }

    fn get(&self, hash: &ChunkHash) -> EraResult<Option<BlockLocation>> {
        Ok(self.lookup.read().get(hash).cloned())
    }

    fn put(&self, hash: ChunkHash, location: BlockLocation) -> EraResult<()> {
        // Insert into lookup map for point queries
        self.lookup.write().insert(hash, location.clone());

        // Insert into IndexBuilder for volume finalization
        if let Some(ref mut builder) = *self.builder.lock() {
            let entry = IndexEntry::new(
                hash,
                location.volume_id,
                BlockId::new(location.slot_index as u64),
                0, // offset within block (not tracked at this level)
                location.encrypted_size,
            );
            builder.insert(entry, &self.temp_dir)?;
        }

        Ok(())
    }

    fn delete(&self, hash: &ChunkHash) -> EraResult<()> {
        self.lookup.write().remove(hash);
        // No delete on IndexBuilder (append-only)
        Ok(())
    }

    fn len(&self) -> usize {
        self.lookup.read().len()
    }

    fn flush(&self) -> EraResult<()> {
        Ok(())
    }

    fn start_batch(&self) {
    }

    fn commit_batch(&self) -> EraResult<()> {
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Create a chunk index backed by LSM-Tree (default for production).
pub(crate) fn create_chunk_index() -> EraResult<Arc<dyn ChunkIndex>> {
    let temp_dir = std::env::temp_dir().join("era_index_spill");
    let _ = std::fs::create_dir_all(&temp_dir);
    Ok(Arc::new(LsmChunkIndex::new(temp_dir)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::VolumeId;

    fn create_test_location(slot: u32) -> BlockLocation {
        BlockLocation::single(VolumeId::new(), slot, slot as u64 * 4096, 4096)
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

    #[test]
    fn test_lsm_chunk_index() {
        let temp_dir = std::env::temp_dir().join("era_test_lsm_index");
        let _ = std::fs::create_dir_all(&temp_dir);
        let index = LsmChunkIndex::new(temp_dir);

        let hash = ChunkHash::from_bytes([2u8; 32]);
        let location = create_test_location(1);

        assert!(!index.contains(&hash).unwrap());

        index.put(hash, location.clone()).unwrap();

        assert!(index.contains(&hash).unwrap());
        let retrieved = index.get(&hash).unwrap().unwrap();
        assert_eq!(retrieved.slot_index, location.slot_index);

        // Builder should have the entry
        assert!(index.take_builder().is_some());
        // Second take returns None
        assert!(index.take_builder().is_none());
    }
}
