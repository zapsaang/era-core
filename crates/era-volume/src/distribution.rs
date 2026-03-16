//! Matrix distribution calculation logic.
//!
//! This module provides the calculation logic for matrix distribution strategies.
//! The type definitions are in `era-common`, but the calculation logic lives here
//! in the volume layer (L1).

use crate::{FOOTER_SIZE, HEADER_SIZE};
use era_common::{
    ErasureCodeConfig, MatrixDistributionConfig, MatrixDistributionStrategy, VolumePoolStatus,
};

fn is_canonical_erasure_volume_count(total_shards: usize, volume_count: usize) -> bool {
    if volume_count == 0 || total_shards == 0 {
        return false;
    }

    if volume_count >= total_shards {
        return true;
    }

    total_shards.is_multiple_of(volume_count)
}

pub fn canonical_erasure_volume_count_error(total_shards: usize, volume_count: usize) -> String {
    format!(
        "Invalid volume count {} for erasure layout with {} total shards; \
         volume count must be >= total shards ({}) or divide total shards evenly",
        volume_count, total_shards, total_shards
    )
}

pub fn validate_canonical_erasure_volume_count(
    total_shards: usize,
    volume_count: usize,
) -> era_common::Result<()> {
    if is_canonical_erasure_volume_count(total_shards, volume_count) {
        Ok(())
    } else {
        Err(era_common::EraError::InvalidConfig(
            canonical_erasure_volume_count_error(total_shards, volume_count),
        ))
    }
}

pub fn validate_erasure_volume_count(
    erasure: ErasureCodeConfig,
    volume_count: usize,
) -> era_common::Result<()> {
    validate_canonical_erasure_volume_count(erasure.total_shards(), volume_count)
}

/// Extension trait for `MatrixDistributionStrategy` providing calculation logic.
pub trait DistributionCalculator {
    /// Calculate which volume a shard should be written to.
    ///
    /// # Arguments
    /// * `shard_idx` - The shard index (0..total_shards)
    /// * `block_sequence` - The block sequence number
    /// * `volume_count` - Total number of available volumes
    ///
    /// # Returns
    /// The volume index (0..volume_count) where this shard should be stored.
    fn calculate_volume(
        &self,
        shard_idx: usize,
        block_sequence: u64,
        volume_count: usize,
    ) -> era_common::Result<usize>;
}

impl DistributionCalculator for MatrixDistributionStrategy {
    fn calculate_volume(
        &self,
        shard_idx: usize,
        block_sequence: u64,
        volume_count: usize,
    ) -> era_common::Result<usize> {
        if volume_count == 0 {
            return Err(era_common::EraError::InvalidConfig(
                "volume_count must be > 0".into(),
            ));
        }
        match self {
            MatrixDistributionStrategy::RotatingOffset => {
                let result = (shard_idx + (block_sequence as usize)) % volume_count;
                debug_assert!(result < volume_count, "modulo postcondition violated");
                Ok(result)
            }
        }
    }
}

/// Extension trait for `MatrixDistributionConfig` providing factory and validation logic.
pub trait DistributionConfigExt {
    /// Create configuration based on erasure config.
    ///
    /// Automatically calculates optimal volume counts.
    fn from_erasure_config(erasure: ErasureCodeConfig) -> Self;

    /// Validate volume count against this configuration.
    fn validate_volume_count(&self, volume_count: usize) -> era_common::Result<()>;
}

impl DistributionConfigExt for MatrixDistributionConfig {
    fn from_erasure_config(erasure: ErasureCodeConfig) -> Self {
        let total_shards = erasure.total_shards();
        Self {
            strategy: MatrixDistributionStrategy::RotatingOffset,
            min_volumes: 1,
            target_volumes: total_shards,
        }
    }

    fn validate_volume_count(&self, volume_count: usize) -> era_common::Result<()> {
        if volume_count < self.min_volumes {
            Err(era_common::EraError::InvalidConfig(format!(
                "Insufficient volumes: have {}, need at least {}",
                volume_count, self.min_volumes
            )))
        } else if self.target_volumes == 0 {
            Err(era_common::EraError::InvalidConfig(
                "target_volumes must be > 0".into(),
            ))
        } else {
            validate_canonical_erasure_volume_count(self.target_volumes, volume_count)
        }
    }
}

/// Extension trait for `VolumePoolStatus` providing volume management logic.
pub trait VolumePoolStatusExt {
    /// Check if a volume can fit a block of given size.
    fn can_fit(&self, volume_idx: usize, block_size: u64) -> bool;

    /// Find next volume that can fit a block.
    /// Returns None if no volume has space (need to create new one).
    fn find_available_volume(&self, start_idx: usize, block_size: u64) -> Option<usize>;
}

impl VolumePoolStatusExt for VolumePoolStatus {
    fn can_fit(&self, volume_idx: usize, block_size: u64) -> bool {
        if volume_idx >= self.volume_sizes.len() {
            return false;
        }
        // Reserve space for footer + backup header + block/shard headers
        // to be consistent with VolumePool::volume_can_fit()
        let reserved = FOOTER_SIZE as u64
            + HEADER_SIZE as u64
            + era_common::BlockHeader::SIZE as u64
            + era_common::ShardHeader::SIZE as u64;
        self.volume_sizes[volume_idx]
            .saturating_add(block_size)
            .saturating_add(reserved)
            <= self.max_volume_size
    }

    fn find_available_volume(&self, start_idx: usize, block_size: u64) -> Option<usize> {
        debug_assert!(
            self.active_volumes > 0,
            "active_volumes must be non-zero for modulo"
        );
        if self.active_volumes == 0 {
            return None;
        }
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
        assert_eq!(strategy.calculate_volume(0, 0, 3).unwrap(), 0);
        assert_eq!(strategy.calculate_volume(1, 0, 3).unwrap(), 1);
        assert_eq!(strategy.calculate_volume(2, 0, 3).unwrap(), 2);
        assert_eq!(strategy.calculate_volume(3, 0, 3).unwrap(), 0);
        assert_eq!(strategy.calculate_volume(4, 0, 3).unwrap(), 1);
        assert_eq!(strategy.calculate_volume(5, 0, 3).unwrap(), 2);

        // 3 volumes, block 1 (rotated by 1)
        assert_eq!(strategy.calculate_volume(0, 1, 3).unwrap(), 1);
        assert_eq!(strategy.calculate_volume(1, 1, 3).unwrap(), 2);
        assert_eq!(strategy.calculate_volume(2, 1, 3).unwrap(), 0);

        // 3 volumes, block 2 (rotated by 2)
        assert_eq!(strategy.calculate_volume(0, 2, 3).unwrap(), 2);
        assert_eq!(strategy.calculate_volume(1, 2, 3).unwrap(), 0);
        assert_eq!(strategy.calculate_volume(2, 2, 3).unwrap(), 1);
    }

    #[test]
    fn test_zero_volume_count() {
        let strategy = MatrixDistributionStrategy::RotatingOffset;
        assert!(strategy.calculate_volume(0, 0, 0).is_err());
        // Test the safe path (volume_count=1) still works
        assert_eq!(strategy.calculate_volume(0, 0, 1).unwrap(), 0);
    }

    #[test]
    fn test_matrix_config_from_erasure() {
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = MatrixDistributionConfig::from_erasure_config(erasure);

        assert_eq!(config.min_volumes, 1);
        assert_eq!(config.target_volumes, 6); // total shards
    }

    #[test]
    fn test_validate_volume_count_canonical_4_plus_2() {
        let config = MatrixDistributionConfig::from_erasure_config(ErasureCodeConfig::new(4, 2));

        for count in [1usize, 2, 3, 6, 7, 8] {
            assert!(
                config.validate_volume_count(count).is_ok(),
                "expected {count} to be valid for 4+2"
            );
        }

        for count in [4usize, 5] {
            assert!(
                config.validate_volume_count(count).is_err(),
                "expected {count} to be invalid for 4+2"
            );
        }
    }

    #[test]
    fn test_validate_volume_count_canonical_6_plus_3() {
        let config = MatrixDistributionConfig::from_erasure_config(ErasureCodeConfig::new(6, 3));

        for count in [1usize, 3, 9, 10] {
            assert!(
                config.validate_volume_count(count).is_ok(),
                "expected {count} to be valid for 6+3"
            );
        }

        for count in [2usize, 4, 5, 6, 7, 8] {
            assert!(
                config.validate_volume_count(count).is_err(),
                "expected {count} to be invalid for 6+3"
            );
        }
    }

    #[test]
    fn test_validate_erasure_volume_count_helper_error_text() {
        let err = validate_erasure_volume_count(ErasureCodeConfig::new(4, 2), 4)
            .expect_err("4 should be invalid for 4+2")
            .to_string();
        assert!(err.contains("divide") || err.contains("total shards"));
    }

    #[test]
    fn test_rotating_offset_even_grouping_for_divisible_low_volume_counts() {
        let strategy = MatrixDistributionStrategy::RotatingOffset;

        let mut counts_4_plus_2 = [0usize; 3];
        for shard_idx in 0..6 {
            let vol = strategy.calculate_volume(shard_idx, 0, 3).unwrap();
            counts_4_plus_2[vol] += 1;
        }
        assert_eq!(counts_4_plus_2, [2, 2, 2]);

        let mut counts_6_plus_3 = [0usize; 3];
        for shard_idx in 0..9 {
            let vol = strategy.calculate_volume(shard_idx, 2, 3).unwrap();
            counts_6_plus_3[vol] += 1;
        }
        assert_eq!(counts_6_plus_3, [3, 3, 3]);
    }

    #[test]
    fn test_volume_pool_status_can_fit() {
        let status = VolumePoolStatus {
            active_volumes: 3,
            volume_sequences: vec![0, 1, 2],
            volume_sizes: vec![100, 200, 300],
            max_volume_size: 4448, // Accounts for footer (128) + header (4096) + block header (16) + shard header (8) reservation
        };

        // With 4248-byte reservation: can_fit checks if size + block_size + 4248 <= max
        assert!(status.can_fit(0, 100)); // 100 + 100 + 4248 = 4448 <= 4448
        assert!(!status.can_fit(0, 101)); // 100 + 101 + 4248 = 4449 > 4448
        assert!(!status.can_fit(2, 201)); // 300 + 201 + 4248 = 4749 > 4448
        assert!(!status.can_fit(5, 100)); // invalid index
    }

    #[test]
    fn test_volume_pool_status_find_available() {
        let status = VolumePoolStatus {
            active_volumes: 3,
            volume_sequences: vec![0, 1, 2],
            volume_sizes: vec![400, 200, 300],
            max_volume_size: 4648, // 400 + 4248 reservation = 4648
        };

        // With 4248-byte reservation:
        // Volume 0: 400 + 100 + 4248 = 4748 > 4648 (doesn't fit)
        // Volume 1: 200 + 100 + 4248 = 4548 <= 4648 (fits)
        assert_eq!(status.find_available_volume(0, 100), Some(1));

        // Volume 0: 400 + 150 + 4248 = 4798 > 4648 (doesn't fit)
        // Volume 1: 200 + 150 + 4248 = 4598 <= 4648 (fits)
        assert_eq!(status.find_available_volume(0, 150), Some(1));

        // Volume 1: 200 + 250 + 4248 = 4698 > 4648 (doesn't fit)
        // Volume 2: 300 + 250 + 4248 = 4798 > 4648 (doesn't fit)
        assert_eq!(status.find_available_volume(0, 250), None);

        // No volume can fit 400
        assert_eq!(status.find_available_volume(0, 400), None);
    }
}
