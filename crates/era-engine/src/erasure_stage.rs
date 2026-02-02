//! Erasure coding stage module.
//!
//! Manages stripe buffering and erasure coding configuration for
//! Reed-Solomon based data protection.
//!
//! This module is part of the God Object decomposition effort (Phase 4).

use era_common::{EncryptedMacroBlock, ErasureCodeConfig, Result};
use era_packing::{BlockMeta, Stripe, StripeBuffer};

/// Erasure coding stage for stripe buffering and parity computation.
///
/// This stage sits between encryption and volume writing in the pipeline:
/// ```text
/// Encryption → [ErasureStage] → VolumeStage
/// ```
///
/// ## How It Works
///
/// When erasure coding is enabled:
/// 1. Encrypted blocks are buffered until K blocks are collected
/// 2. When K blocks are ready, a complete Stripe is returned
/// 3. The Stripe contains data blocks + metadata for parity computation
/// 4. VolumeStage computes parity and writes all shards
///
/// When erasure coding is disabled:
/// - Blocks pass through directly to VolumeStage
/// - No buffering occurs
pub struct ErasureStage {
    /// Stripe buffer for collecting K data blocks
    stripe_buffer: Option<StripeBuffer>,
    /// Erasure coding configuration (K data shards, M parity shards)
    config: Option<ErasureCodeConfig>,
}

impl ErasureStage {
    /// Create a new erasure stage with the given configuration.
    ///
    /// If `config` is `Some`, erasure coding is enabled and blocks will be buffered.
    /// If `config` is `None`, erasure coding is disabled and this stage is a no-op.
    pub fn new(config: Option<ErasureCodeConfig>) -> Self {
        let stripe_buffer = config.map(StripeBuffer::new);
        Self {
            stripe_buffer,
            config,
        }
    }

    /// Create a disabled erasure stage (no erasure coding).
    pub fn disabled() -> Self {
        Self {
            stripe_buffer: None,
            config: None,
        }
    }

    /// Check if erasure coding is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.is_some()
    }

    /// Get the erasure coding configuration, if enabled.
    #[allow(dead_code)]
    pub fn config(&self) -> Option<&ErasureCodeConfig> {
        self.config.as_ref()
    }

    /// Buffer an encrypted block for stripe formation.
    ///
    /// Returns `Some(Stripe)` when K blocks have been collected and a complete
    /// stripe is ready for writing. Returns `None` if more blocks are needed.
    ///
    /// # Arguments
    /// * `block` - The encrypted block to buffer
    /// * `meta` - Block metadata (chunk hashes for index updates)
    ///
    /// # Returns
    /// * `Ok(Some(Stripe))` - A complete stripe ready for parity computation
    /// * `Ok(None)` - Block buffered, waiting for more blocks
    /// * `Err(_)` - Erasure coding is disabled (should not call this method)
    pub fn buffer_block(
        &mut self,
        block: EncryptedMacroBlock,
        meta: BlockMeta,
    ) -> Result<Option<Stripe>> {
        match &mut self.stripe_buffer {
            Some(buffer) => buffer.push(block, meta),
            None => Err(era_common::EraError::InvalidFormat(
                "Erasure coding is not enabled".into(),
            )),
        }
    }

    /// Flush any partial stripe (for finalization).
    ///
    /// This should be called during archive finalization to ensure any
    /// buffered blocks are written. The returned stripe may have fewer
    /// than K data blocks and will be padded during writing.
    ///
    /// Returns `None` if the buffer is empty or erasure coding is disabled.
    pub fn flush(&mut self) -> Result<Option<Stripe>> {
        match &mut self.stripe_buffer {
            Some(buffer) if !buffer.is_empty() => Ok(Some(buffer.flush()?)),
            _ => Ok(None),
        }
    }

    /// Check if there are buffered blocks waiting to be flushed.
    #[allow(dead_code)]
    pub fn has_pending(&self) -> bool {
        self.stripe_buffer
            .as_ref()
            .map(|b| !b.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_stage() {
        let stage = ErasureStage::disabled();
        assert!(!stage.is_enabled());
        assert!(stage.config().is_none());
        assert!(!stage.has_pending());
    }

    #[test]
    fn test_enabled_stage() {
        let config = ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 1,
        };
        let stage = ErasureStage::new(Some(config));
        assert!(stage.is_enabled());
        assert!(stage.config().is_some());
        assert_eq!(stage.config().unwrap().data_shards, 4);
        assert_eq!(stage.config().unwrap().parity_shards, 1);
        assert!(!stage.has_pending());
    }

    #[test]
    fn test_flush_empty() {
        let config = ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 1,
        };
        let mut stage = ErasureStage::new(Some(config));

        // Flushing empty buffer should return None
        let result = stage.flush().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_buffer_block_disabled() {
        let mut stage = ErasureStage::disabled();
        let block = EncryptedMacroBlock {
            block_id: era_common::BlockId::new(0),
            data: bytes::Bytes::new(),
            original_size: 0,
            compressed_size: 0,
            chunk_count: 0,
        };
        let meta = BlockMeta {
            chunk_hashes: vec![],
            chunk_entries: vec![],
        };

        // Should error when erasure coding is disabled
        let result = stage.buffer_block(block, meta);
        assert!(result.is_err());
    }
}
