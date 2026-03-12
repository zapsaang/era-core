//! Reed-Solomon erasure coding for data redundancy.
//!
//! This module provides erasure coding capabilities using Reed-Solomon algorithm.
//! It allows data to be split into data shards and parity shards, enabling
//! recovery of lost shards.
//!
//! # Configuration
//!
//! The default configuration is 4+2:
//! - 4 data shards (original data split into 4 parts)
//! - 2 parity shards (can recover from loss of any 2 shards)

use era_common::{EraError, Result};

/// Default number of data shards
pub const DEFAULT_DATA_SHARDS: usize = 4;

/// Default number of parity shards  
pub const DEFAULT_PARITY_SHARDS: usize = 2;

/// Maximum supported shards (data + parity)
pub const MAX_TOTAL_SHARDS: usize = 255;

/// Configuration for Reed-Solomon erasure coding
///
/// Constraints:
/// - data_shards: range 1-255
/// - parity_shards: range 1-255
/// - total shards must not exceed MAX_TOTAL_SHARDS (255)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasureConfig {
    /// Number of data shards (1-255)
    pub data_shards: usize,
    /// Number of parity shards (1-255)
    pub parity_shards: usize,
}

impl Default for ErasureConfig {
    fn default() -> Self {
        Self {
            data_shards: DEFAULT_DATA_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
        }
    }
}

impl ErasureConfig {
    /// Create a new erasure configuration
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 {
            return Err(EraError::InvalidConfig("data_shards must be > 0".into()));
        }
        if parity_shards == 0 {
            return Err(EraError::InvalidConfig("parity_shards must be > 0".into()));
        }
        if data_shards + parity_shards > MAX_TOTAL_SHARDS {
            return Err(EraError::InvalidConfig(format!(
                "total shards ({}) exceeds maximum ({})",
                data_shards + parity_shards,
                MAX_TOTAL_SHARDS
            )));
        }
        Ok(Self {
            data_shards,
            parity_shards,
        })
    }

    /// Total number of shards (data + parity)
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Calculate the shard size for given data length
    /// Shards are padded to equal size, and must be a multiple of 2
    pub fn shard_size(&self, data_len: usize) -> usize {
        // Each shard contains data_len / data_shards bytes (rounded up)
        let base_size = data_len.div_ceil(self.data_shards);
        // Round up to multiple of 2 (required by reed-solomon-simd)
        (base_size + 1) & !1
    }
}

/// Reed-Solomon encoder/decoder
pub struct ErasureCoder {
    config: ErasureConfig,
}

impl ErasureCoder {
    /// Create a new erasure coder with the given configuration
    pub fn new(config: ErasureConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Create a new erasure coder with default 4+2 configuration
    pub fn default_config() -> Result<Self> {
        Self::new(ErasureConfig::default())
    }

    /// Get the configuration
    pub fn config(&self) -> &ErasureConfig {
        &self.config
    }

    /// Encode data into data shards and parity shards
    ///
    /// Returns a vector of shards where:
    /// - First `data_shards` entries are data shards
    /// - Last `parity_shards` entries are parity shards
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Err(EraError::InvalidConfig("Cannot encode empty data".into()));
        }

        let shard_size = self.config.shard_size(data.len());

        // Create encoder for this operation
        let mut encoder = reed_solomon_simd::ReedSolomonEncoder::new(
            self.config.data_shards,
            self.config.parity_shards,
            shard_size,
        )
        .map_err(|e| EraError::ErasureError(format!("Failed to create RS encoder: {}", e)))?;

        // Prepare data shards (split and pad)
        let mut data_shards: Vec<Vec<u8>> = Vec::with_capacity(self.config.data_shards);
        for i in 0..self.config.data_shards {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(data.len());

            let mut shard = if start < data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            };

            // Pad to shard_size
            shard.resize(shard_size, 0);
            data_shards.push(shard);
        }

        // Add shards to encoder
        for shard in &data_shards {
            encoder
                .add_original_shard(shard)
                .map_err(|e| EraError::ErasureError(format!("Failed to add shard: {}", e)))?;
        }

        // Generate parity shards
        let result = encoder
            .encode()
            .map_err(|e| EraError::ErasureError(format!("Encoding failed: {}", e)))?;

        // Collect all shards
        let mut all_shards = data_shards;
        for parity in result.recovery_iter() {
            all_shards.push(parity.to_vec());
        }

        Ok(all_shards)
    }

    /// Encode existing shards into parity shards
    ///
    /// The input `shards` will be treated as the data shards.
    /// If fewer than `data_shards` are provided, they will be padded with zeros?
    /// No, the caller should provide exactly `data_shards` or we should handle it.
    /// For standard usage, we expect `data_shards` inputs.
    ///
    /// Returns a vector containing the original data shards (padded if necessary) followed by parity shards.
    pub fn encode_shards(&self, shards: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        if shards.is_empty() {
            return Err(EraError::InvalidConfig("Cannot encode empty shards".into()));
        }
        if shards.len() > self.config.data_shards {
            return Err(EraError::InvalidConfig(format!(
                "Too many shards: expected max {}, got {}",
                self.config.data_shards,
                shards.len()
            )));
        }

        // 1. Determine shard size (max length of input shards, aligned to 2 bytes)
        let max_len = shards.iter().map(|s| s.len()).max().unwrap_or(0);
        // Round up to multiple of 2 (required by reed-solomon-simd)
        let shard_size = if max_len == 0 { 2 } else { (max_len + 1) & !1 };

        // 2. Prepare data shards (pad to consistent size)
        let mut data_shards = Vec::with_capacity(self.config.data_shards);
        for i in 0..self.config.data_shards {
            let mut shard = if i < shards.len() {
                shards[i].clone()
            } else {
                vec![0u8; shard_size] // Empty padding shard for missing slots
            };

            if shard.len() < shard_size {
                shard.resize(shard_size, 0);
            }
            data_shards.push(shard);
        }

        // 3. Create encoder
        let mut encoder = reed_solomon_simd::ReedSolomonEncoder::new(
            self.config.data_shards,
            self.config.parity_shards,
            shard_size,
        )
        .map_err(|e| EraError::ErasureError(format!("Failed to create RS encoder: {}", e)))?;

        // 4. Add shards
        for shard in &data_shards {
            encoder
                .add_original_shard(shard)
                .map_err(|e| EraError::ErasureError(format!("Failed to add shard: {}", e)))?;
        }

        // 5. Generate parity
        let result = encoder
            .encode()
            .map_err(|e| EraError::ErasureError(format!("Encoding failed: {}", e)))?;

        // 6. Collect result
        let mut all_shards = data_shards;
        for parity in result.recovery_iter() {
            all_shards.push(parity.to_vec());
        }

        Ok(all_shards)
    }

    /// Decode/recover data from available shards
    ///
    /// `shards` is a vector of Option<Vec<u8>>:
    /// - Some(data) for available shards
    /// - None for missing shards
    ///
    /// Returns the original data if recovery is possible.
    pub fn decode(&self, shards: &[Option<Vec<u8>>], original_len: usize) -> Result<Vec<u8>> {
        if shards.len() != self.config.total_shards() {
            return Err(EraError::InvalidConfig(format!(
                "Expected {} shards, got {}",
                self.config.total_shards(),
                shards.len()
            )));
        }

        let available_count = shards.iter().filter(|s| s.is_some()).count();
        if available_count < self.config.data_shards {
            return Err(EraError::ErasureError(format!(
                "Not enough shards for recovery: have {}, need {}",
                available_count, self.config.data_shards
            )));
        }

        // Check if we have all data shards (no recovery needed)
        let all_data_present = shards[..self.config.data_shards]
            .iter()
            .all(|s| s.is_some());

        if all_data_present {
            // Just concatenate data shards
            let mut result = Vec::with_capacity(original_len);
            for data in shards[..self.config.data_shards].iter().flatten() {
                result.extend_from_slice(data);
            }
            result.truncate(original_len);
            return Ok(result);
        }

        // Need to recover missing shards
        let shard_size = shards
            .iter()
            .find_map(|s| s.as_ref())
            .map(|s| s.len())
            .ok_or_else(|| EraError::ErasureError("No shards available".into()))?;

        // Create decoder for this operation
        let mut decoder = reed_solomon_simd::ReedSolomonDecoder::new(
            self.config.data_shards,
            self.config.parity_shards,
            shard_size,
        )
        .map_err(|e| EraError::ErasureError(format!("Failed to create RS decoder: {}", e)))?;

        // Add available shards
        for (i, shard) in shards.iter().enumerate() {
            if let Some(data) = shard {
                if i < self.config.data_shards {
                    decoder.add_original_shard(i, data).map_err(|e| {
                        EraError::ErasureError(format!("Failed to add original shard: {}", e))
                    })?;
                } else {
                    decoder
                        .add_recovery_shard(i - self.config.data_shards, data)
                        .map_err(|e| {
                            EraError::ErasureError(format!("Failed to add recovery shard: {}", e))
                        })?;
                }
            }
        }

        // Decode
        let result = decoder
            .decode()
            .map_err(|e| EraError::ErasureError(format!("Decoding failed: {}", e)))?;

        // Reconstruct original data
        let mut output = Vec::with_capacity(original_len);
        for (i, shard) in shards[..self.config.data_shards].iter().enumerate() {
            let shard_data = if let Some(data) = shard {
                data.as_slice()
            } else {
                result.restored_original(i).ok_or_else(|| {
                    EraError::ErasureError(format!("Failed to restore shard {}", i))
                })?
            };
            output.extend_from_slice(shard_data);
        }
        output.truncate(original_len);

        Ok(output)
    }

    /// Recover all data shards (padded) from available shards.
    ///
    /// This is used for virtual striping, where each data shard is a full block
    /// and shards on disk may be unpadded. The caller provides the intended
    /// `shard_size` (padded size) to normalize all shards before decoding.
    pub fn recover_data_shards(
        &self,
        shards: &[Option<Vec<u8>>],
        shard_size: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if shards.len() != self.config.total_shards() {
            return Err(EraError::InvalidConfig(format!(
                "Expected {} shards, got {}",
                self.config.total_shards(),
                shards.len()
            )));
        }

        let available_count = shards.iter().filter(|s| s.is_some()).count();
        if available_count < self.config.data_shards {
            return Err(EraError::ErasureError(format!(
                "Not enough shards for recovery: have {}, need {}",
                available_count, self.config.data_shards
            )));
        }

        // Normalize shard lengths to shard_size for RS decoding
        let mut normalized: Vec<Option<Vec<u8>>> = Vec::with_capacity(shards.len());
        for shard in shards {
            let padded = shard.as_ref().map(|data| {
                if data.len() > shard_size {
                    // Reject oversized shards to avoid silent truncation
                    return Err(EraError::ErasureError(format!(
                        "Shard length {} exceeds shard_size {}",
                        data.len(),
                        shard_size
                    )));
                }
                let mut out = data.clone();
                if out.len() < shard_size {
                    out.resize(shard_size, 0);
                }
                Ok(out)
            });

            match padded {
                Some(Ok(p)) => normalized.push(Some(p)),
                Some(Err(e)) => return Err(e),
                None => normalized.push(None),
            }
        }

        // If all data shards are present, return them directly (padded)
        let all_data_present = normalized[..self.config.data_shards]
            .iter()
            .all(|s| s.is_some());
        if all_data_present {
            return Ok(normalized[..self.config.data_shards]
                .iter()
                .map(|s| s.as_ref().unwrap().clone())
                .collect());
        }

        // Decode missing shards
        // Decode missing shards
        let mut decoder = reed_solomon_simd::ReedSolomonDecoder::new(
            self.config.data_shards,
            self.config.parity_shards,
            shard_size,
        )
        .map_err(|e| EraError::ErasureError(format!("Failed to create RS decoder: {}", e)))?;

        for (i, shard) in normalized.iter().enumerate() {
            if let Some(data) = shard {
                if i < self.config.data_shards {
                    decoder.add_original_shard(i, data).map_err(|e| {
                        EraError::ErasureError(format!("Failed to add original shard: {}", e))
                    })?;
                } else {
                    decoder
                        .add_recovery_shard(i - self.config.data_shards, data)
                        .map_err(|e| {
                            EraError::ErasureError(format!("Failed to add recovery shard: {}", e))
                        })?;
                }
            }
        }

        let result = decoder
            .decode()
            .map_err(|e| EraError::ErasureError(format!("Decoding failed: {}", e)))?;

        let mut recovered = Vec::with_capacity(self.config.data_shards);
        for (i, shard) in normalized[..self.config.data_shards].iter().enumerate() {
            let shard_data = if let Some(data) = shard {
                data.as_slice()
            } else {
                result.restored_original(i).ok_or_else(|| {
                    EraError::ErasureError(format!("Failed to restore shard {}", i))
                })?
            };
            recovered.push(shard_data.to_vec());
        }

        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ Configuration Tests ============

    #[test]
    fn test_default_config() {
        let config = ErasureConfig::default();
        assert_eq!(config.data_shards, 4);
        assert_eq!(config.parity_shards, 2);
        assert_eq!(config.total_shards(), 6);
    }

    #[test]
    fn test_config_validation() {
        // Valid config
        assert!(ErasureConfig::new(4, 2).is_ok());
        assert!(ErasureConfig::new(8, 4).is_ok());

        // Invalid: zero shards
        assert!(ErasureConfig::new(0, 2).is_err());
        assert!(ErasureConfig::new(4, 0).is_err());

        // Invalid: too many shards
        assert!(ErasureConfig::new(200, 100).is_err());
    }

    #[test]
    fn test_shard_size_calculation() {
        let config = ErasureConfig::new(4, 2).unwrap();

        // 1000 bytes / 4 shards = 250 bytes per shard (already even)
        assert_eq!(config.shard_size(1000), 250);

        // 1001 bytes / 4 shards = 251 -> rounded up to 252 (must be even)
        assert_eq!(config.shard_size(1001), 252);

        // 4 bytes / 4 shards = 1 byte -> rounded up to 2 (must be even)
        assert_eq!(config.shard_size(4), 2);
    }

    // ============ Encoding Tests ============

    #[test]
    fn test_encode_basic() {
        let coder = ErasureCoder::default_config().unwrap();
        let data = b"Hello, Reed-Solomon erasure coding!";

        let shards = coder.encode(data).unwrap();

        // Should have 4 data + 2 parity = 6 shards
        assert_eq!(shards.len(), 6);

        // All shards should have the same size
        let shard_size = shards[0].len();
        for shard in &shards {
            assert_eq!(shard.len(), shard_size);
        }
    }

    #[test]
    fn test_encode_empty_data() {
        let coder = ErasureCoder::default_config().unwrap();
        let result = coder.encode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_various_sizes() {
        let coder = ErasureCoder::default_config().unwrap();

        for size in [1, 10, 100, 1000, 10000, 100000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let shards = coder.encode(&data).unwrap();
            assert_eq!(shards.len(), 6);
        }
    }

    // ============ Decoding Tests ============

    #[test]
    fn test_decode_no_loss() {
        let coder = ErasureCoder::default_config().unwrap();
        let original = b"Test data for Reed-Solomon encoding and decoding";

        let shards = coder.encode(original).unwrap();
        let shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        let recovered = coder.decode(&shard_options, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_decode_with_one_data_shard_lost() {
        let coder = ErasureCoder::default_config().unwrap();
        let original = b"Data recovery test - lose one data shard";

        let shards = coder.encode(original).unwrap();
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose shard 0 (first data shard)
        shard_options[0] = None;

        let recovered = coder.decode(&shard_options, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_decode_with_two_shards_lost() {
        let coder = ErasureCoder::default_config().unwrap();
        let original = b"Data recovery test - lose two shards (max for 4+2)";

        let shards = coder.encode(original).unwrap();
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose shards 1 and 3
        shard_options[1] = None;
        shard_options[3] = None;

        let recovered = coder.decode(&shard_options, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_decode_with_parity_shards_lost() {
        let coder = ErasureCoder::default_config().unwrap();
        let original = b"Losing parity shards is fine as long as data is intact";

        let shards = coder.encode(original).unwrap();
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose both parity shards (indices 4 and 5)
        shard_options[4] = None;
        shard_options[5] = None;

        let recovered = coder.decode(&shard_options, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_recover_data_shards_from_partial() {
        let config = ErasureConfig::new(4, 2).unwrap();
        let coder = ErasureCoder::new(config).unwrap();

        let shards = vec![vec![1u8; 10], vec![2u8; 12], vec![3u8; 8], vec![4u8; 11]];

        let all_shards = coder.encode_shards(&shards).unwrap();
        let shard_size = all_shards[0].len();

        let mut shard_options: Vec<Option<Vec<u8>>> =
            all_shards.iter().map(|s| Some(s.clone())).collect();

        // Lose a data shard (index 2)
        shard_options[2] = None;

        let recovered = coder
            .recover_data_shards(&shard_options, shard_size)
            .unwrap();

        assert_eq!(recovered.len(), 4);
        assert_eq!(recovered[2], all_shards[2]);
    }

    #[test]
    fn test_decode_too_many_lost() {
        let coder = ErasureCoder::default_config().unwrap();
        let original = b"Too many shards lost - cannot recover";

        let shards = coder.encode(original).unwrap();
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose 3 shards (more than parity_shards=2)
        shard_options[0] = None;
        shard_options[1] = None;
        shard_options[2] = None;

        let result = coder.decode(&shard_options, original.len());
        assert!(result.is_err());
    }

    // ============ Large Data Tests ============

    #[test]
    fn test_large_data_encode_decode() {
        let coder = ErasureCoder::default_config().unwrap();

        // 1MB of data
        let original: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();

        let shards = coder.encode(&original).unwrap();

        // Lose one shard
        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_options[2] = None;

        let recovered = coder.decode(&shard_options, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    // ============ Custom Configuration Tests ============

    #[test]
    fn test_custom_config_8_4() {
        let config = ErasureConfig::new(8, 4).unwrap();
        let coder = ErasureCoder::new(config).unwrap();

        let original = b"Testing 8+4 configuration - can lose up to 4 shards";

        let shards = coder.encode(original).unwrap();
        assert_eq!(shards.len(), 12); // 8 data + 4 parity

        let mut shard_options: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose 4 shards
        shard_options[0] = None;
        shard_options[3] = None;
        shard_options[5] = None;
        shard_options[7] = None;

        let recovered = coder.decode(&shard_options, original.len()).unwrap();
        assert_eq!(recovered, original);
    }
}
