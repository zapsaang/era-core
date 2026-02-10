//! Index stage module.
//!
//! Consolidates the three index systems used during archive creation:
//! - Chunk deduplication index (LSM-Tree or Memory-based)
//! - Embedded index snapshot (for self-contained recovery)
//! - Checkpoint manager (for crash recovery)
//!
//! This module is part of the God Object decomposition effort (Phase 2).

use std::collections::HashMap;
use std::sync::Arc;

use era_common::{BlockLocation, ChunkHash, Result};

use crate::checkpoint::CheckpointManager;
use crate::chunk_index::ChunkIndex;

/// Index stage for managing chunk deduplication and recovery indexes.
///
/// This stage consolidates three related index systems:
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
/// 2. **Embedded Index**: In-archive snapshot for self-contained recovery
///    - Written to the archive during finalization
///    - Allows archive extraction without external index
///
/// 3. **Checkpoint Manager**: Crash recovery support
///    - Tracks in-progress files and written chunks
///    - Enables resumption after interruption
#[allow(dead_code)]
pub struct IndexStage {
    /// LSM-Tree or Memory-based chunk deduplication index
    chunk_index: Arc<dyn ChunkIndex>,
    /// Embedded snapshot for self-contained recovery
    embedded_index: HashMap<ChunkHash, BlockLocation>,
    /// Checkpoint for crash recovery
    checkpoint_manager: Option<CheckpointManager>,
}

#[allow(dead_code)]
impl IndexStage {
    /// Create a new index stage.
    ///
    /// # Arguments
    /// * `chunk_index` - The primary chunk deduplication index
    /// * `checkpoint_manager` - Optional checkpoint manager for crash recovery
    pub fn new(
        chunk_index: Arc<dyn ChunkIndex>,
        checkpoint_manager: Option<CheckpointManager>,
    ) -> Self {
        Self {
            chunk_index,
            embedded_index: HashMap::new(),
            checkpoint_manager,
        }
    }

    /// Create an index stage without checkpoint support.
    pub fn without_checkpoint(chunk_index: Arc<dyn ChunkIndex>) -> Self {
        Self::new(chunk_index, None)
    }

    /// Check if a chunk exists in the index (deduplication check).
    ///
    /// This is the primary method for deduplication during ingestion.
    /// Returns `true` if the chunk already exists and doesn't need to be written.
    pub fn contains(&self, hash: &ChunkHash) -> Result<bool> {
        self.chunk_index.contains(hash)
    }

    /// Get the location of a chunk.
    ///
    /// Returns `Some(location)` if the chunk exists, `None` otherwise.
    pub fn get(&self, hash: &ChunkHash) -> Result<Option<BlockLocation>> {
        self.chunk_index.get(hash)
    }

    /// Record a chunk location in all index systems.
    ///
    /// This updates:
    /// 1. The primary chunk index (for deduplication)
    /// 2. The embedded index (for self-contained recovery)
    /// 3. The checkpoint manager (for crash recovery, if enabled)
    ///
    /// # Arguments
    /// * `hash` - The chunk hash
    /// * `location` - The physical location where the chunk was written
    pub fn record_location(&mut self, hash: ChunkHash, location: BlockLocation) -> Result<()> {
        // Update primary index
        self.chunk_index.put(hash, location.clone())?;

        // Update embedded index for self-contained recovery
        self.embedded_index.insert(hash, location.clone());

        // Update checkpoint for crash recovery
        if let Some(ref mut mgr) = self.checkpoint_manager {
            mgr.record_chunk(hash, location)?;
        }

        Ok(())
    }

    /// Record multiple chunk locations at once.
    ///
    /// This is more efficient than calling `record_location` multiple times
    /// when recording locations for all chunks in a block.
    pub fn record_locations(
        &mut self,
        entries: impl IntoIterator<Item = (ChunkHash, BlockLocation)>,
    ) -> Result<()> {
        for (hash, location) in entries {
            self.record_location(hash, location)?;
        }
        Ok(())
    }

    /// Get the embedded index snapshot for finalization.
    ///
    /// This returns a reference to the embedded index which should be
    /// serialized and written to the archive during finalization.
    pub fn embedded_snapshot(&self) -> &HashMap<ChunkHash, BlockLocation> {
        &self.embedded_index
    }

    /// Get the number of entries in the embedded index.
    pub fn embedded_count(&self) -> usize {
        self.embedded_index.len()
    }

    /// Get the number of entries in the primary chunk index.
    pub fn chunk_index_len(&self) -> usize {
        self.chunk_index.len()
    }

    /// Sync the checkpoint to stable storage.
    ///
    /// This should be called at safe points during archiving to enable
    /// crash recovery.
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
    ///
    /// This is a no-op for in-memory indexes but important for LSM-Tree indexes.
    pub fn flush(&self) -> Result<()> {
        self.chunk_index.flush()
    }

    /// Start batch mode for improved write throughput.
    ///
    /// Call this before recording many locations, then call `commit_batch`.
    pub fn start_batch(&self) {
        self.chunk_index.start_batch();
    }

    /// Commit batch writes to the index.
    pub fn commit_batch(&self) -> Result<()> {
        self.chunk_index.commit_batch()
    }

    /// Get a reference to the underlying chunk index.
    ///
    /// Prefer using the stage methods when possible.
    pub fn chunk_index(&self) -> &Arc<dyn ChunkIndex> {
        &self.chunk_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_index::MemoryChunkIndex;
    use era_common::VolumeId;

    fn create_test_location(slot: u32) -> BlockLocation {
        BlockLocation {
            volume_id: VolumeId::new(),
            slot_index: slot,
            physical_offset: slot as u64 * 4096,
            encrypted_size: 4096,
            erasure_info: None,
            shard_offsets: Vec::new(),
            shard_volumes: Vec::new(),
        }
    }

    #[test]
    fn test_index_stage_creation() {
        let chunk_index = Arc::new(MemoryChunkIndex::new());
        let stage = IndexStage::without_checkpoint(chunk_index);

        assert_eq!(stage.embedded_count(), 0);
        assert_eq!(stage.chunk_index_len(), 0);
        assert!(!stage.has_checkpoint());
    }

    #[test]
    fn test_record_location() {
        let chunk_index = Arc::new(MemoryChunkIndex::new());
        let mut stage = IndexStage::without_checkpoint(chunk_index);

        let hash = ChunkHash::from_bytes([1u8; 32]);
        let location = create_test_location(0);

        // Initially not present
        assert!(!stage.contains(&hash).unwrap());

        // Record location
        stage.record_location(hash, location.clone()).unwrap();

        // Now present in both indexes
        assert!(stage.contains(&hash).unwrap());
        assert_eq!(stage.embedded_count(), 1);
        assert!(stage.embedded_snapshot().contains_key(&hash));

        // Can retrieve location
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

        assert_eq!(stage.embedded_count(), 5);
        assert_eq!(stage.chunk_index_len(), 5);
    }

    #[test]
    fn test_deduplication() {
        let chunk_index = Arc::new(MemoryChunkIndex::new());
        let mut stage = IndexStage::without_checkpoint(chunk_index);

        let hash = ChunkHash::from_bytes([42u8; 32]);
        let location = create_test_location(0);

        // First time: not a duplicate
        assert!(!stage.contains(&hash).unwrap());

        stage.record_location(hash, location).unwrap();

        // Second time: is a duplicate
        assert!(stage.contains(&hash).unwrap());
    }
}
