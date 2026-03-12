//! Packing stage module.
//!
//! Implements k-Bounded Best-Fit bin packing for optimal block utilization.
//! This stage aggregates small chunks into larger blocks (default 4MB) to
//! improve storage efficiency from ~55% to ~95%.
//!
//! This module is part of the God Object decomposition effort (Phase 3).

use era_common::UniqueChunk;
use era_packing::{PackedBlock, StagingPool};

/// Packing stage for k-Bounded Best-Fit bin packing.
///
/// This stage sits between ingestion and encryption in the pipeline:
/// ```text
/// Ingestion → [PackingStage] → Encryption → Storage
/// ```
///
/// ## Algorithm
///
/// The k-Bounded Best-Fit algorithm maintains K bins, each targeting
/// `target_block_size`. When a chunk arrives:
/// 1. Find the best-fit bin (smallest remaining space that fits the chunk)
/// 2. If no bin fits, use the emptiest bin
/// 3. When a bin reaches `flush_threshold` capacity, it's returned for writing
///
/// ## Performance
///
/// - Space utilization: ~95% (vs ~55% with naive packing)
/// - Oversized chunks bypass bins and are written directly
pub struct PackingStage {
    /// k-Bounded Best-Fit staging pool
    staging_pool: StagingPool,
    /// Target block size for batching (default 4MB)
    target_block_size: usize,
}

impl PackingStage {
    /// Create a new packing stage.
    ///
    /// # Arguments
    /// * `k_factor` - Number of bins to maintain (higher = better packing, more memory)
    /// * `target_block_size` - Target size for each packed block
    /// * `flush_threshold_percent` - Percentage (1-100) at which to flush bins
    ///
    /// # Errors
    /// Returns `InvalidConfig` if flush_threshold_percent is not in range 1-100.
    pub fn new(
        k_factor: usize,
        target_block_size: usize,
        flush_threshold_percent: usize,
    ) -> era_common::Result<Self> {
        // Local validation at engine boundary
        if flush_threshold_percent == 0 || flush_threshold_percent > 100 {
            return Err(era_common::EraError::InvalidConfig(format!(
                "flush_threshold_percent must be in range 1-100, got {}",
                flush_threshold_percent
            )));
        }

        Ok(Self {
            staging_pool: StagingPool::new(k_factor, target_block_size)?
                .with_flush_threshold(flush_threshold_percent),
            target_block_size,
        })
    }

    /// Create a packing stage with default flush threshold (95%).
    #[allow(dead_code)]
    pub fn with_defaults(k_factor: usize, target_block_size: usize) -> era_common::Result<Self> {
        Self::new(k_factor, target_block_size, 95)
    }

    /// Get the target block size.
    ///
    /// This is useful for chunking large in-memory data before adding to the stage.
    pub fn target_block_size(&self) -> usize {
        self.target_block_size
    }

    /// Push a chunk into the staging pool.
    ///
    /// Returns `Some(PackedBlock)` if a bin reached the flush threshold and
    /// should be written to storage. Returns `None` if the chunk was buffered.
    ///
    /// # Arguments
    /// * `chunk` - The unique chunk to add
    pub fn push(&mut self, chunk: UniqueChunk) -> Option<PackedBlock> {
        self.staging_pool.push(chunk)
    }

    /// Flush all bins, returning all packed blocks.
    ///
    /// Call this at finalization to ensure all buffered chunks are written.
    pub fn flush_all(&mut self) -> Vec<PackedBlock> {
        self.staging_pool.flush_all()
    }

    /// Check if the staging pool is empty (no buffered chunks).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.staging_pool.stats().total_chunks == 0
    }

    /// Get the number of bins in the staging pool.
    #[allow(dead_code)]
    pub fn bin_count(&self) -> usize {
        self.staging_pool.bin_count()
    }

    /// Get statistics about the staging pool.
    #[allow(dead_code)]
    pub fn stats(&self) -> era_packing::StagingPoolStats {
        self.staging_pool.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_common::ChunkHash;

    fn make_chunk(size: usize) -> UniqueChunk {
        let data = vec![0u8; size];
        let hash = ChunkHash([0u8; 32]);
        UniqueChunk {
            hash,
            data: Bytes::from(data),
        }
    }

    #[test]
    fn test_new_packing_stage() {
        let stage = PackingStage::new(4, 4 * 1024 * 1024, 95).unwrap();
        assert_eq!(stage.target_block_size(), 4 * 1024 * 1024);
        assert!(stage.is_empty());
    }

    #[test]
    fn test_push_small_chunk() {
        let mut stage = PackingStage::new(4, 1024, 95).unwrap();

        // Small chunk should be buffered
        let result = stage.push(make_chunk(100));
        assert!(result.is_none());
        assert!(!stage.is_empty());
    }

    #[test]
    fn test_flush_threshold() {
        let mut stage = PackingStage::new(4, 1000, 50).unwrap(); // 50% threshold

        // First chunk (50% of target) should trigger flush
        let result = stage.push(make_chunk(500));
        assert!(result.is_some());

        let packed = result.unwrap();
        assert_eq!(packed.chunks.len(), 1);
    }

    #[test]
    fn test_flush_all() {
        let mut stage = PackingStage::new(4, 1024, 95).unwrap();

        // Add some chunks
        stage.push(make_chunk(100));
        stage.push(make_chunk(200));

        // Flush all
        let blocks = stage.flush_all();
        assert!(!blocks.is_empty());
        assert!(stage.is_empty());
    }

    #[test]
    fn test_oversized_chunk() {
        let mut stage = PackingStage::new(4, 100, 95).unwrap();

        // Oversized chunk should be returned immediately
        let result = stage.push(make_chunk(200));
        assert!(result.is_some());
    }

    #[test]
    fn test_invalid_config_zero_flush_threshold() {
        let result = PackingStage::new(4, 4 * 1024 * 1024, 0);
        assert!(result.is_err());
        if let Err(era_common::EraError::InvalidConfig(msg)) = result {
            assert!(msg.contains("flush_threshold_percent"));
        } else {
            panic!("Expected InvalidConfig error");
        }
    }

    #[test]
    fn test_invalid_config_flush_threshold_exceeds_100() {
        let result = PackingStage::new(4, 4 * 1024 * 1024, 101);
        assert!(result.is_err());
        if let Err(era_common::EraError::InvalidConfig(msg)) = result {
            assert!(msg.contains("flush_threshold_percent"));
        } else {
            panic!("Expected InvalidConfig error");
        }
    }

    #[test]
    fn test_valid_config_flush_threshold_at_boundaries() {
        let result1 = PackingStage::new(4, 4 * 1024 * 1024, 1);
        assert!(result1.is_ok());

        let result100 = PackingStage::new(4, 4 * 1024 * 1024, 100);
        assert!(result100.is_ok());
    }
}
