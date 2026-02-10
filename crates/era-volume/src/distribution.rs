//! Matrix distribution calculation logic.
//!
//! This module provides the calculation logic for matrix distribution strategies.
//! The type definitions are in `era-common`, but the calculation logic lives here
//! in the volume layer (L1).

use era_common::{
    ErasureCodeConfig, MatrixDistributionConfig, MatrixDistributionStrategy, VolumePoolStatus,
};

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
    fn calculate_volume(&self, shard_idx: usize, block_sequence: u64, volume_count: usize)
        -> usize;
}

impl DistributionCalculator for MatrixDistributionStrategy {
    fn calculate_volume(
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
    fn validate_volume_count(&self, volume_count: usize) -> Result<(), String>;
}

impl DistributionConfigExt for MatrixDistributionConfig {
    fn from_erasure_config(erasure: ErasureCodeConfig) -> Self {
        let total_shards = erasure.total_shards();
        let min_volumes = (erasure.parity_shards as usize + 1).max(2);
        Self {
            strategy: MatrixDistributionStrategy::RotatingOffset,
            min_volumes,
            target_volumes: total_shards,
        }
    }

    fn validate_volume_count(&self, volume_count: usize) -> Result<(), String> {
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
        self.volume_sizes[volume_idx] + block_size <= self.max_volume_size
    }

    fn find_available_volume(&self, start_idx: usize, block_size: u64) -> Option<usize> {
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
    fn test_zero_volume_count() {
        let strategy = MatrixDistributionStrategy::RotatingOffset;
        assert_eq!(strategy.calculate_volume(0, 0, 0), 0);
    }

    #[test]
    fn test_matrix_config_from_erasure() {
        let erasure = ErasureCodeConfig::new(4, 2);
        let config = MatrixDistributionConfig::from_erasure_config(erasure);

        assert_eq!(config.min_volumes, 3); // parity + 1
        assert_eq!(config.target_volumes, 6); // total shards
    }

    #[test]
    fn test_validate_volume_count() {
        let config = MatrixDistributionConfig {
            strategy: MatrixDistributionStrategy::RotatingOffset,
            min_volumes: 3,
            target_volumes: 6,
        };

        assert!(config.validate_volume_count(3).is_ok());
        assert!(config.validate_volume_count(6).is_ok());
        assert!(config.validate_volume_count(2).is_err());
    }

    #[test]
    fn test_volume_pool_status_can_fit() {
        let status = VolumePoolStatus {
            active_volumes: 3,
            volume_sequences: vec![0, 1, 2],
            volume_sizes: vec![100, 200, 300],
            max_volume_size: 500,
        };

        assert!(status.can_fit(0, 400)); // 100 + 400 = 500 <= 500
        assert!(!status.can_fit(0, 401)); // 100 + 401 = 501 > 500
        assert!(!status.can_fit(2, 201)); // 300 + 201 = 501 > 500
        assert!(!status.can_fit(5, 100)); // invalid index
    }

    #[test]
    fn test_volume_pool_status_find_available() {
        let status = VolumePoolStatus {
            active_volumes: 3,
            volume_sequences: vec![0, 1, 2],
            volume_sizes: vec![400, 200, 300],
            max_volume_size: 500,
        };

        // Starting from 0, volume 0 can fit 100 bytes
        assert_eq!(status.find_available_volume(0, 100), Some(0));

        // Starting from 0, volume 0 can't fit 150, but volume 1 can (200+150=350<=500)
        assert_eq!(status.find_available_volume(0, 150), Some(1));

        // Volume 1 can fit 250 (200+250=450<=500)
        assert_eq!(status.find_available_volume(0, 250), Some(1));

        // No volume can fit 301 (400+301>500, 200+301>500, 300+301>500)
        assert_eq!(status.find_available_volume(0, 301), None);
    }
}
