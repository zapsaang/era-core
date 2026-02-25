//! Index stage for the write pipeline.
//!
//! Manages deduplication index lookups, location recording, and checkpoint
//! synchronization. This is one of the four stages in the write pipeline
//! (encryption → erasure → volume → **index**).
//!
//! The `IndexStage` wraps:
//! - A `ChunkIndex` (either in-memory or LSM-backed) for dedup lookups
//! - An optional `CheckpointManager` for crash recovery
//!
//! At finalization, the embedded `IndexBuilder` (if using `LsmChunkIndex`)
//! is extracted and serialized into typed index blocks written to the volume.

use std::sync::Arc;

use era_common::{BlockLocation, ChunkHash, Result};
use era_index::IndexBuilder;

use crate::checkpoint::CheckpointManager;
use crate::chunk_index::{ChunkIndex, LsmChunkIndex};

/// Index stage: wraps chunk index and optional checkpoint manager.
///
/// Provides a unified interface for the write pipeline to:
/// - Check for duplicate chunks (deduplication)
/// - Record new chunk → block location mappings
/// - Sync checkpoint state for crash recovery
/// - Extract the `IndexBuilder` at finalization for V2.1 embedded index
pub struct IndexStage {
    /// The chunk deduplication index (in-memory or LSM-backed).
    chunk_index: Arc<dyn ChunkIndex>,
    /// Optional checkpoint manager for crash recovery.
    checkpoint_manager: Option<CheckpointManager>,
}

impl IndexStage {
    /// Create a new `IndexStage` with a chunk index and optional checkpoint manager.
    ///
    /// Used in production paths where crash recovery may or may not be enabled.
    pub fn new(
        chunk_index: Arc<dyn ChunkIndex>,
        checkpoint_manager: Option<CheckpointManager>,
    ) -> Self {
        Self {
            chunk_index,
            checkpoint_manager,
        }
    }

    /// Create a new `IndexStage` without checkpoint support.
    ///
    /// Used in tests and scenarios where crash recovery is not needed.
    #[allow(dead_code)]
    pub fn without_checkpoint(chunk_index: Arc<dyn ChunkIndex>) -> Self {
        Self {
            chunk_index,
            checkpoint_manager: None,
        }
    }

    /// Check if a chunk hash exists in the index (deduplication check).
    pub fn contains(&self, hash: &ChunkHash) -> Result<bool> {
        self.chunk_index.contains(hash)
    }

    /// Get the block location for a chunk hash, if it exists.
    pub fn get(&self, hash: &ChunkHash) -> Result<Option<BlockLocation>> {
        self.chunk_index.get(hash)
    }

    /// Record a chunk hash → block location mapping in the index.
    ///
    /// This updates both the dedup lookup index and the `IndexBuilder`
    /// (if backed by `LsmChunkIndex`).
    pub fn record_location(&self, hash: ChunkHash, location: BlockLocation) -> Result<()> {
        self.chunk_index.put(hash, location)
    }

    /// Sync checkpoint state to stable storage.
    ///
    /// No-op if no checkpoint manager is configured.
    pub fn sync_checkpoint(&mut self) -> Result<()> {
        if let Some(ref mut mgr) = self.checkpoint_manager {
            mgr.sync()?;
        }
        Ok(())
    }

    /// Extract the `IndexBuilder` for V2.1 embedded index finalization.
    ///
    /// This downcasts the inner chunk index to `LsmChunkIndex` and takes
    /// the builder. Returns `None` if the index is not LSM-backed or the
    /// builder was already taken.
    pub fn take_index_builder(&self) -> Option<IndexBuilder> {
        self.chunk_index
            .as_any()
            .downcast_ref::<LsmChunkIndex>()
            .and_then(|lsm| lsm.take_builder())
    }

    /// Get a reference to the checkpoint manager, if configured.
    pub fn checkpoint_manager(&self) -> Option<&CheckpointManager> {
        self.checkpoint_manager.as_ref()
    }

    /// Get a reference to the underlying chunk index.
    pub fn chunk_index(&self) -> &Arc<dyn ChunkIndex> {
        &self.chunk_index
    }
}
