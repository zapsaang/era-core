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
/// Provides a unified interface for looking up and recording chunk locations,
/// whether backed by an in-memory HashMap or a persistent LSM-Tree.
pub(crate) trait ChunkIndex: Send + Sync {
    /// Check if a chunk hash exists in the index.
    fn contains(&self, hash: &ChunkHash) -> EraResult<bool>;

    /// Get the block location for a chunk hash, if it exists.
    fn get(&self, hash: &ChunkHash) -> EraResult<Option<BlockLocation>>;

    /// Record a chunk hash → block location mapping.
    fn put(&self, hash: ChunkHash, location: BlockLocation) -> EraResult<()>;

    /// Remove a chunk hash from the index.
    fn delete(&self, hash: &ChunkHash) -> EraResult<()>;

    /// Return the number of entries in the index.
    fn len(&self) -> usize;

    /// Flush any pending writes to stable storage.
    fn flush(&self) -> EraResult<()>;

    /// Begin a batch of operations (for transactional backends).
    fn start_batch(&self);

    /// Commit the current batch of operations.
    fn commit_batch(&self) -> EraResult<()>;

    /// Downcast support for accessing concrete implementations.
    fn as_any(&self) -> &dyn Any;
}

/// Simple in-memory chunk index backed by a HashMap.
///
/// Suitable for tests and small archives. Does not persist across restarts.
pub(crate) struct MemoryChunkIndex {
    map: RwLock<HashMap<ChunkHash, BlockLocation>>,
}

impl MemoryChunkIndex {
    /// Create a new empty in-memory chunk index.
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }
}

impl ChunkIndex for MemoryChunkIndex {
    fn contains(&self, hash: &ChunkHash) -> EraResult<bool> {
        Ok(self.map.read().contains_key(hash))
    }

    fn get(&self, hash: &ChunkHash) -> EraResult<Option<BlockLocation>> {
        Ok(self.map.read().get(hash).cloned())
    }

    fn put(&self, hash: ChunkHash, location: BlockLocation) -> EraResult<()> {
        self.map.write().insert(hash, location);
        Ok(())
    }

    fn delete(&self, hash: &ChunkHash) -> EraResult<()> {
        self.map.write().remove(hash);
        Ok(())
    }

    fn len(&self) -> usize {
        self.map.read().len()
    }

    fn flush(&self) -> EraResult<()> {
        Ok(())
    }

    fn start_batch(&self) {}

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

        // Insert into IndexBuilder for volume finalization.
        // If builder has been taken (finalization started), reject the insert
        // to prevent silent data loss in the volume index.
        match *self.builder.lock() {
            Some(ref mut builder) => {
                let entry = IndexEntry::new(
                    hash,
                    location.volume_id,
                    BlockId::new(location.slot_index as u64),
                    0, // offset within block (not tracked at this level)
                    location.encrypted_size,
                );
                builder.insert(entry, &self.temp_dir)?;
            }
            None => {
                return Err(era_common::EraError::InvalidConfig(
                    "Cannot insert after builder taken — finalization already started".into(),
                ));
            }
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

    fn start_batch(&self) {}

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
