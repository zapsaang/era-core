//! Matrix distribution types for true distributed erasure coding.
//!
//! This module provides types for implementing true matrix distribution
//! of erasure-coded shards across multiple volumes, ensuring optimal
//! fault tolerance.
//!
//! Note: This module only contains type definitions. Calculation logic
//! (e.g., `calculate_volume`) is implemented in `era-volume` via extension traits.

use serde::{Deserialize, Serialize};

use super::BlockId;

/// Matrix distribution strategy for shard placement.
///
/// Determines how shards are distributed across volumes to maximize
/// fault tolerance. The default strategy rotates shard placement
/// based on block sequence number.
///
/// ## Formula (implemented in era-volume)
/// - `RotatingOffset`: `volume_idx = (shard_idx + block_sequence) % volume_count`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MatrixDistributionStrategy {
    /// Rotate shard assignment by block sequence number.
    ///
    /// This ensures that consecutive blocks use different starting volumes,
    /// distributing shards more evenly and preventing correlated failures.
    #[default]
    RotatingOffset,
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
    /// Erasure configuration (data_shards, parity_shards)
    pub data_shards: u8,
    pub parity_shards: u8,
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
        data_shards: u8,
        parity_shards: u8,
        original_len: u32,
    ) -> Self {
        let total_shards = data_shards as usize + parity_shards as usize;
        Self {
            block_id,
            block_sequence,
            data_shards,
            parity_shards,
            original_len,
            shards: Vec::with_capacity(total_shards),
        }
    }

    /// Add a shard entry.
    pub fn add_shard(&mut self, entry: MatrixShardEntry) {
        self.shards.push(entry);
    }

    /// Get total number of shards.
    pub fn total_shards(&self) -> usize {
        self.data_shards as usize + self.parity_shards as usize
    }

    /// Check if all shards have been recorded.
    pub fn is_complete(&self) -> bool {
        self.shards.len() == self.total_shards()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_distribution_config_default() {
        let config = MatrixDistributionConfig::default();
        assert_eq!(config.strategy, MatrixDistributionStrategy::RotatingOffset);
        assert_eq!(config.min_volumes, 3);
        assert_eq!(config.target_volumes, 6);
    }

    #[test]
    fn test_matrix_shard_entry() {
        let entry = MatrixShardEntry::new(1, 4096, 1024, 0xDEADBEEF);
        assert_eq!(entry.volume_sequence, 1);
        assert_eq!(entry.physical_offset, 4096);
        assert_eq!(entry.shard_size, 1024);
        assert_eq!(entry.crc, 0xDEADBEEF);
    }

    #[test]
    fn test_matrix_block_location() {
        let block_id = BlockId::new(0);
        let mut loc = MatrixBlockLocation::new(block_id, 0, 4, 2, 4096);

        assert_eq!(loc.total_shards(), 6);
        assert!(!loc.is_complete());

        for i in 0..6 {
            loc.add_shard(MatrixShardEntry::new(i as u16, i as u64 * 1024, 1024, 0));
        }

        assert!(loc.is_complete());
        assert_eq!(loc.primary_volume_sequence(), Some(0));
    }
}
