//! Matrix distribution types for true distributed erasure coding.
//!
//! This module provides types for implementing true matrix distribution
//! of erasure-coded shards across multiple volumes, ensuring optimal
//! fault tolerance.

use serde::{Deserialize, Serialize};

use super::{BlockId, ErasureCodeConfig};

/// Matrix distribution strategy for shard placement.
///
/// Determines how shards are distributed across volumes to maximize
/// fault tolerance. The default strategy rotates shard placement
/// based on block sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MatrixDistributionStrategy {
    /// Rotate shard assignment by block sequence number
    /// Formula: volume_idx = (shard_idx + block_sequence) % volume_count
    ///
    /// This ensures that consecutive blocks use different starting volumes,
    /// distributing shards more evenly and preventing correlated failures.
    #[default]
    RotatingOffset,

    /// Striped distribution (legacy behavior)
    /// Formula: volume_idx = shard_idx % volume_count
    ///
    /// All blocks use the same shard-to-volume mapping.
    /// Less fault-tolerant but simpler.
    Striped,
}

impl MatrixDistributionStrategy {
    /// Calculate which volume a shard should be written to.
    ///
    /// # Arguments
    /// * `shard_idx` - The shard index (0..total_shards)
    /// * `block_sequence` - The block sequence number
    /// * `volume_count` - Total number of available volumes
    ///
    /// # Returns
    /// The volume index (0..volume_count) where this shard should be stored.
    pub fn calculate_volume(
        &self,
        shard_idx: usize,
        block_sequence: u64,
        volume_count: usize,
    ) -> usize {
        if volume_count == 0 {
            return 0;
        }
        match self {
            MatrixDistributionStrategy::RotatingOffset => {
                (shard_idx + (block_sequence as usize)) % volume_count
            }
            MatrixDistributionStrategy::Striped => shard_idx % volume_count,
        }
    }
}

/// Configuration for matrix distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixDistributionConfig {
    /// Distribution strategy
    pub strategy: MatrixDistributionStrategy,
    /// Minimum number of volumes required
    /// Should be >= parity_shards + 1 for optimal fault tolerance
    pub min_volumes: usize,
    /// Target number of volumes (ideally equals total_shards)
    pub target_volumes: usize,
}

impl Default for MatrixDistributionConfig {
    fn default() -> Self {
        Self {
            strategy: MatrixDistributionStrategy::RotatingOffset,
            min_volumes: 3,    // Minimum for 4+2 erasure
            target_volumes: 6, // Optimal for 4+2 erasure
        }
    }
}

impl MatrixDistributionConfig {
    /// Create configuration based on erasure config.
    ///
    /// Automatically calculates optimal volume counts.
    pub fn from_erasure_config(erasure: ErasureCodeConfig) -> Self {
        let total_shards = erasure.total_shards();
        let min_volumes = (erasure.parity_shards as usize + 1).max(2);
        Self {
            strategy: MatrixDistributionStrategy::RotatingOffset,
            min_volumes,
            target_volumes: total_shards,
        }
    }

    /// Validate volume count against this configuration.
    pub fn validate_volume_count(&self, volume_count: usize) -> Result<(), String> {
        if volume_count < self.min_volumes {
            Err(format!(
                "Insufficient volumes: have {}, need at least {}",
                volume_count, self.min_volumes
            ))
        } else {
            Ok(())
        }
    }
}

/// Location entry for a single shard in matrix distribution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixShardEntry {
    /// Volume sequence number (not index, for persistence)
    pub volume_sequence: u16,
    /// Physical offset within the volume
    pub physical_offset: u64,
    /// Shard data size
    pub shard_size: u32,
    /// CRC32 for integrity verification
    pub crc: u32,
}

impl MatrixShardEntry {
    /// Create a new shard entry.
    pub fn new(volume_sequence: u16, physical_offset: u64, shard_size: u32, crc: u32) -> Self {
        Self {
            volume_sequence,
            physical_offset,
            shard_size,
            crc,
        }
    }
}

/// Complete location information for all shards of a block.
///
/// This structure supports true matrix distribution where shards
/// are distributed across volumes using the configured strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixBlockLocation {
    /// Block ID for this block
    pub block_id: BlockId,
    /// Block sequence number (used for rotation calculation)
    pub block_sequence: u64,
    /// Erasure configuration
    pub erasure_config: ErasureCodeConfig,
    /// Original data length before erasure encoding
    pub original_len: u32,
    /// Shard locations, indexed by shard number (0..total_shards)
    /// Each entry contains the volume and offset for that shard
    pub shards: Vec<MatrixShardEntry>,
}

impl MatrixBlockLocation {
    /// Create a new matrix block location.
    pub fn new(
        block_id: BlockId,
        block_sequence: u64,
        erasure_config: ErasureCodeConfig,
        original_len: u32,
    ) -> Self {
        Self {
            block_id,
            block_sequence,
            erasure_config,
            original_len,
            shards: Vec::with_capacity(erasure_config.total_shards()),
        }
    }

    /// Add a shard entry.
    pub fn add_shard(&mut self, entry: MatrixShardEntry) {
        self.shards.push(entry);
    }

    /// Check if all shards have been recorded.
    pub fn is_complete(&self) -> bool {
        self.shards.len() == self.erasure_config.total_shards()
    }

    /// Get shards grouped by volume sequence.
    ///
    /// Returns a map from volume_sequence to list of (shard_index, entry) pairs.
    pub fn shards_by_volume(
        &self,
    ) -> std::collections::HashMap<u16, Vec<(usize, &MatrixShardEntry)>> {
        let mut map = std::collections::HashMap::new();
        for (idx, entry) in self.shards.iter().enumerate() {
            map.entry(entry.volume_sequence)
                .or_insert_with(Vec::new)
                .push((idx, entry));
        }
        map
    }

    /// Get the volume sequence where the primary (first) shard is stored.
    pub fn primary_volume_sequence(&self) -> Option<u16> {
        self.shards.first().map(|s| s.volume_sequence)
    }
}

/// Volume pool status for tracking available volumes.
#[derive(Debug, Clone, Default)]
pub struct VolumePoolStatus {
    /// Number of active volumes
    pub active_volumes: usize,
    /// Volume sequence numbers currently in use
    pub volume_sequences: Vec<u16>,
    /// Current sizes of each volume (indexed same as volume_sequences)
    pub volume_sizes: Vec<u64>,
    /// Maximum size per volume
    pub max_volume_size: u64,
}

impl VolumePoolStatus {
    /// Check if a volume can fit a block of given size.
    pub fn can_fit(&self, volume_idx: usize, block_size: u64) -> bool {
        if volume_idx >= self.volume_sizes.len() {
            return false;
        }
        self.volume_sizes[volume_idx] + block_size <= self.max_volume_size
    }

    /// Find next volume that can fit a block.
    /// Returns None if no volume has space (need to create new one).
    pub fn find_available_volume(&self, start_idx: usize, block_size: u64) -> Option<usize> {
        for i in 0..self.active_volumes {
            let idx = (start_idx + i) % self.active_volumes;
            if self.can_fit(idx, block_size) {
                return Some(idx);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotating_offset_distribution() {
        let strategy = MatrixDistributionStrategy::RotatingOffset;

        // 3 volumes, block 0
        assert_eq!(strategy.calculate_volume(0, 0, 3), 0);
        assert_eq!(strategy.calculate_volume(1, 0, 3), 1);
        assert_eq!(strategy.calculate_volume(2, 0, 3), 2);
        assert_eq!(strategy.calculate_volume(3, 0, 3), 0);
        assert_eq!(strategy.calculate_volume(4, 0, 3), 1);
        assert_eq!(strategy.calculate_volume(5, 0, 3), 2);

        // 3 volumes, block 1 (rotated by 1)
        assert_eq!(strategy.calculate_volume(0, 1, 3), 1);
        assert_eq!(strategy.calculate_volume(1, 1, 3), 2);
        assert_eq!(strategy.calculate_volume(2, 1, 3), 0);

        // 3 volumes, block 2 (rotated by 2)
        assert_eq!(strategy.calculate_volume(0, 2, 3), 2);
        assert_eq!(strategy.calculate_volume(1, 2, 3), 0);
        assert_eq!(strategy.calculate_volume(2, 2, 3), 1);
    }

    #[test]
    fn test_striped_distribution() {
        let strategy = MatrixDistributionStrategy::Striped;

        // All blocks use same distribution
        for block in 0..5 {
            assert_eq!(strategy.calculate_volume(0, block, 3), 0);
            assert_eq!(strategy.calculate_volume(1, block, 3), 1);
            assert_eq!(strategy.calculate_volume(2, block, 3), 2);
            assert_eq!(strategy.calculate_volume(3, block, 3), 0);
        }
    }

    #[test]
    fn test_matrix_config_from_erasure() {
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = MatrixDistributionConfig::from_erasure_config(erasure);

        assert_eq!(config.min_volumes, 3); // parity + 1
        assert_eq!(config.target_volumes, 6); // total shards
    }

    #[test]
    fn test_matrix_block_location() {
        let block_id = BlockId::new(0);
        let erasure = ErasureCodeConfig::new(4, 2);
        let mut loc = MatrixBlockLocation::new(block_id, 0, erasure, 4096);

        assert!(!loc.is_complete());

        for i in 0..6 {
            loc.add_shard(MatrixShardEntry::new(i as u16, i as u64 * 1024, 1024, 0));
        }

        assert!(loc.is_complete());

        let by_volume = loc.shards_by_volume();
        assert_eq!(by_volume.len(), 6);
    }
}
