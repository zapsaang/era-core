//! Index stage module.
//!
//! Consolidates the index systems used during archive creation:
//! - Chunk deduplication index (LSM-Tree or Memory-based)
//! - Checkpoint manager (for crash recovery)
//!
//! This module is part of the God Object decomposition effort (Phase 2).

use std::sync::Arc;

use era_common::{BlockLocation, ChunkHash, Result};
use era_index::IndexBuilder;

use crate::checkpoint::CheckpointManager;
use crate::chunk_index::{ChunkIndex, LsmChunkIndex};

/// Index stage for managing chunk deduplication and recovery indexes.
///
/// This stage consolidates related index systems:
/// ```text
/// Ingestion → Dedup Check → [IndexStage] → Location Recording
/// ```
///
/// ## Index Systems
///
/// 1. **Chunk Index**: Primary deduplication index (LSM-Tree or Memory)
///    - Used for fast chunk existence checks
///    - Supports persistent incremental backups
///
/// 2. **Checkpoint Manager**: Crash recovery support
///    - Tracks in-progress files and written chunks
///    - Enables resumption after interruption
#[allow(dead_code)]
pub struct IndexStage {
    /// LSM-Tree or Memory-based chunk deduplication index
    chunk_index: Arc<dyn ChunkIndex>,
    /// Checkpoint for crash recovery
    checkpoint_manager: Option<CheckpointManager>,
}

#[allow(dead_code)]
impl IndexStage {
    /// Create a new index stage.
    pub fn new(
        chunk_index: Arc<dyn ChunkIndex>,
        checkpoint_manager: Option<CheckpointManager>,
    ) -> Self {
        Self {
            chunk_index,
            checkpoint_manager,
        }
    }

    /// Create an index stage without checkpoint support.
    pub fn without_checkpoint(chunk_index: Arc<dyn ChunkIndex>) -> Self {
        Self::new(chunk_index, None)
    }

    /// Check if a chunk exists in the index (deduplication check).
    pub fn contains(&self, hash: &ChunkHash) -> Result<bool> {
        self.chunk_index.contains(hash)
    }

    /// Get the location of a chunk.
    pub fn get(&self, hash: &ChunkHash) -> Result<Option<BlockLocation>> {
        self.chunk_index.get(hash)
    }

    /// Record a chunk location in all index systems.
    pub fn record_location(&mut self, hash: ChunkHash, location: BlockLocation) -> Result<()> {
        self.chunk_index.put(hash, location.clone())?;

        if let Some(ref mut mgr) = self.checkpoint_manager {
            mgr.record_chunk(hash, location)?;
        }

        Ok(())
    }

    /// Record multiple chunk locations at once.
    pub fn record_locations(
        &mut self,
        entries: impl IntoIterator<Item = (ChunkHash, BlockLocation)>,
    ) -> Result<()> {
        for (hash, location) in entries {
            self.record_location(hash, location)?;
        }
        Ok(())
    }

    /// Get the number of entries in the primary chunk index.
    pub fn chunk_index_len(&self) -> usize {
        self.chunk_index.len()
    }

    /// Sync the checkpoint to stable storage.
    pub fn sync_checkpoint(&mut self) -> Result<()> {
        if let Some(ref mut mgr) = self.checkpoint_manager {
            mgr.sync()?;
        }
        Ok(())
    }

    /// Check if checkpoint support is enabled.
    pub fn has_checkpoint(&self) -> bool {
        self.checkpoint_manager.is_some()
    }

    /// Get a reference to the checkpoint manager, if available.
    pub fn checkpoint_manager(&self) -> Option<&CheckpointManager> {
        self.checkpoint_manager.as_ref()
    }

    /// Get a mutable reference to the checkpoint manager, if available.
    pub fn checkpoint_manager_mut(&mut self) -> Option<&mut CheckpointManager> {
        self.checkpoint_manager.as_mut()
    }

    /// Flush the primary chunk index to stable storage.
    pub fn flush(&self) -> Result<()> {
        self.chunk_index.flush()
    }

    /// Start batch mode for improved write throughput.
    pub fn start_batch(&self) {
        self.chunk_index.start_batch();
    }

    /// Commit batch writes to the index.
    pub fn commit_batch(&self) -> Result<()> {
        self.chunk_index.commit_batch()
    }

    /// Get a reference to the underlying chunk index.
    pub fn chunk_index(&self) -> &Arc<dyn ChunkIndex> {
        &self.chunk_index
    }

    /// Extract the `IndexBuilder` from the underlying chunk index.
    ///
    /// This only succeeds when the chunk index is an `LsmChunkIndex`.
    /// Returns `None` for `MemoryChunkIndex` or if the builder was already taken.
    pub fn take_index_builder(&self) -> Option<IndexBuilder> {
        self.chunk_index
            .as_any()
            .downcast_ref::<LsmChunkIndex>()
            .and_then(|lsm| lsm.take_builder())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_index::MemoryChunkIndex;
    use era_common::VolumeId;

    fn create_test_location(slot: u32) -> BlockLocation {
        BlockLocation::single(VolumeId::new(), slot, slot as u64 * 4096, 4096)
    }

    #[test]
    fn test_index_stage_creation() {
        let chunk_index = Arc::new(MemoryChunkIndex::new());
        let stage = IndexStage::without_checkpoint(chunk_index);

        assert_eq!(stage.chunk_index_len(), 0);
        assert!(!stage.has_checkpoint());
    }

    #[test]
    fn test_record_location() {
        let chunk_index = Arc::new(MemoryChunkIndex::new());
        let mut stage = IndexStage::without_checkpoint(chunk_index);

        let hash = ChunkHash::from_bytes([1u8; 32]);
        let location = create_test_location(0);

        assert!(!stage.contains(&hash).unwrap());

        stage.record_location(hash, location.clone()).unwrap();

        assert!(stage.contains(&hash).unwrap());

        let retrieved = stage.get(&hash).unwrap().unwrap();
        assert_eq!(retrieved.slot_index, location.slot_index);
    }

    #[test]
    fn test_record_multiple_locations() {
        let chunk_index = Arc::new(MemoryChunkIndex::new());
        let mut stage = IndexStage::without_checkpoint(chunk_index);

        let entries: Vec<(ChunkHash, BlockLocation)> = (0..5)
            .map(|i| {
                let mut hash_bytes = [0u8; 32];
                hash_bytes[0] = i;
                (
                    ChunkHash::from_bytes(hash_bytes),
                    create_test_location(i as u32),
                )
            })
            .collect();

        stage.record_locations(entries).unwrap();

        assert_eq!(stage.chunk_index_len(), 5);
    }

    #[test]
    fn test_deduplication() {
        let chunk_index = Arc::new(MemoryChunkIndex::new());
        let mut stage = IndexStage::without_checkpoint(chunk_index);

        let hash = ChunkHash::from_bytes([42u8; 32]);
        let location = create_test_location(0);

        assert!(!stage.contains(&hash).unwrap());

        stage.record_location(hash, location).unwrap();

        assert!(stage.contains(&hash).unwrap());
    }
}
