//! Erasure-coded block builder - wraps MacroBlockBuilder with RS coding.

use era_codec::{ErasureCoder, ErasureConfig};
use era_common::{ErasureCodeConfig, ErasureShardedBlock, Result, UniqueChunk};
use era_crypto::DerivedKey;

use crate::MacroBlockBuilder;

/// Builder that creates erasure-coded blocks
pub struct ErasureBlockBuilder {
    /// Inner block builder
    inner: MacroBlockBuilder,
    /// Erasure coder
    coder: ErasureCoder,
    /// Erasure configuration for output
    config: ErasureCodeConfig,
}

impl ErasureBlockBuilder {
    /// Create a new erasure block builder
    pub fn new(
        key: DerivedKey,
        nonce_context: [u8; 16],
        compressor: Box<dyn era_codec::Compressor>,
        erasure_config: ErasureCodeConfig,
    ) -> Result<Self> {
        let inner = MacroBlockBuilder::new(key, nonce_context, compressor);
        let codec_config = ErasureConfig::new(
            erasure_config.data_shards as usize,
            erasure_config.parity_shards as usize,
        )?;
        let coder = ErasureCoder::new(codec_config)?;

        Ok(Self {
            inner,
            coder,
            config: erasure_config,
        })
    }

    /// Set the target block size
    pub fn with_target_size(mut self, size: usize) -> Self {
        self.inner = self.inner.with_target_size(size);
        self
    }

    /// Pack a single chunk into an erasure-coded block
    pub fn pack_single(&self, chunk: UniqueChunk) -> Result<ErasureShardedBlock> {
        // First, create the encrypted block
        let encrypted = self.inner.pack_single(chunk)?;

        // Apply erasure coding
        self.encode_block(encrypted.block_id, &encrypted.data)
    }

    /// Pack multiple chunks into an erasure-coded block
    pub fn pack_chunks(&self, chunks: Vec<UniqueChunk>) -> Result<ErasureShardedBlock> {
        let encrypted = self.inner.pack_chunks(chunks)?;
        self.encode_block(encrypted.block_id, &encrypted.data)
    }

    /// Apply erasure coding to encrypted block data
    fn encode_block(
        &self,
        block_id: era_common::BlockId,
        data: &[u8],
    ) -> Result<ErasureShardedBlock> {
        let original_len = data.len() as u32;

        // Encode with Reed-Solomon
        let shards = self.coder.encode(data)?;

        // Convert to Bytes
        let shards = shards.into_iter().map(bytes::Bytes::from).collect();

        Ok(ErasureShardedBlock {
            block_id,
            config: self.config,
            original_len,
            shards,
        })
    }

    /// Get statistics about the builder
    pub fn blocks_created(&self) -> u64 {
        self.inner.blocks_created()
    }

    /// Get the erasure configuration
    pub fn erasure_config(&self) -> ErasureCodeConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_codec::ZstdCompressor;
    use era_common::ChunkHash;
    use era_crypto::{derive_key, KdfParams, Salt};

    fn test_key() -> DerivedKey {
        let salt = Salt::from_bytes([0u8; 16]);
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        derive_key(b"test_password", &salt, &params).unwrap()
    }

    #[test]
    fn test_erasure_pack_single() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let config = ErasureCodeConfig::new(4, 2);

        let builder = ErasureBlockBuilder::new(key, [0u8; 16], compressor, config).unwrap();

        let chunk = UniqueChunk::new(
            Bytes::from(vec![42u8; 1024]),
            ChunkHash::from_bytes([1u8; 32]),
        );

        let block = builder.pack_single(chunk).unwrap();

        // Should have 6 shards (4 data + 2 parity)
        assert_eq!(block.shards.len(), 6);
        assert_eq!(block.config.data_shards, 4);
        assert_eq!(block.config.parity_shards, 2);
    }

    #[test]
    fn test_erasure_pack_multiple_chunks() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let config = ErasureCodeConfig::new(4, 2);

        let builder = ErasureBlockBuilder::new(key, [0u8; 16], compressor, config).unwrap();

        let chunks = vec![
            UniqueChunk::new(
                Bytes::from(vec![1u8; 512]),
                ChunkHash::from_bytes([1u8; 32]),
            ),
            UniqueChunk::new(
                Bytes::from(vec![2u8; 512]),
                ChunkHash::from_bytes([2u8; 32]),
            ),
        ];

        let block = builder.pack_chunks(chunks).unwrap();
        assert_eq!(block.shards.len(), 6);
    }

    #[test]
    fn test_erasure_shards_can_recover() {
        use era_codec::{ErasureCoder, ErasureConfig};

        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let config = ErasureCodeConfig::new(4, 2);

        let builder = ErasureBlockBuilder::new(key, [0u8; 16], compressor, config).unwrap();

        let original_data = vec![42u8; 1024];
        let chunk = UniqueChunk::new(Bytes::from(original_data), ChunkHash::from_bytes([1u8; 32]));

        let block = builder.pack_single(chunk).unwrap();
        let original_len = block.original_len as usize;

        // Simulate losing 2 shards (parity shards)
        let mut shards_with_loss: Vec<Option<Vec<u8>>> =
            block.shards.iter().map(|s| Some(s.to_vec())).collect();

        // Remove 2 shards (the last 2 which are parity)
        shards_with_loss[4] = None;
        shards_with_loss[5] = None;

        // Recover
        let coder = ErasureCoder::new(ErasureConfig::new(4, 2).unwrap()).unwrap();
        let recovered = coder.decode(&shards_with_loss, original_len).unwrap();

        // Should match original encrypted block data
        let all_shards: Vec<_> = block.shards.iter().map(|s| Some(s.to_vec())).collect();
        let original = coder.decode(&all_shards, original_len).unwrap();
        assert_eq!(recovered, original);
    }
}
