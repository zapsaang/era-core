//! Erasure-coded block unpacker - reads and decodes RS-coded blocks.

use bytes::Bytes;
use era_codec::{Compressor, ErasureCoder, ErasureConfig};
use era_common::{
    BlockId, ChunkHash, ChunkVec, EncryptedMacroBlock, EraError, ErasureBlockInfo, Result,
};
use era_crypto::DerivedKey;

use crate::MacroBlockUnpacker;

/// Unpacker for erasure-coded blocks
///
/// This unpacker reads multiple shards, uses Reed-Solomon decoding to recover
/// the original encrypted MacroBlock (handling shard loss if any), and then
/// delegates to MacroBlockUnpacker for decryption and decompression.
pub struct ErasureBlockUnpacker {
    /// Inner unpacker for decryption/decompression
    inner: MacroBlockUnpacker,
}

impl ErasureBlockUnpacker {
    /// Create a new erasure block unpacker
    pub fn new(key: DerivedKey, nonce_context: [u8; 16], compressor: Box<dyn Compressor>) -> Self {
        let inner = MacroBlockUnpacker::new(key, nonce_context, compressor);
        Self { inner }
    }

    /// Decode shards and extract all chunks from the recovered block
    ///
    /// # Arguments
    /// * `shards` - Vector of (shard_index, shard_data) for available shards
    /// * `erasure_info` - Metadata about the erasure configuration
    /// * `block_id` - The block ID for this block
    ///
    /// # Returns
    /// ChunkVec of (hash, data) pairs for all chunks in the block.
    /// Uses SmallVec for stack allocation optimization.
    pub fn decode_and_extract_all(
        &self,
        shards: Vec<(usize, Bytes)>,
        erasure_info: &ErasureBlockInfo,
        block_id: BlockId,
    ) -> Result<ChunkVec> {
        let encrypted_block = self.decode_shards(shards, erasure_info, block_id)?;
        self.inner.extract_all_chunks(&encrypted_block)
    }

    /// Decode shards and extract a specific chunk by hash
    pub fn decode_and_extract_chunk(
        &self,
        shards: Vec<(usize, Bytes)>,
        erasure_info: &ErasureBlockInfo,
        block_id: BlockId,
        chunk_hash: &ChunkHash,
    ) -> Result<Option<Bytes>> {
        let encrypted_block = self.decode_shards(shards, erasure_info, block_id)?;
        self.inner.extract_chunk(&encrypted_block, chunk_hash)
    }

    /// Decode available shards into the original EncryptedMacroBlock
    ///
    /// This is the core RS decoding logic that reconstructs the original
    /// encrypted block from available shards.
    pub fn decode_shards(
        &self,
        shards: Vec<(usize, Bytes)>,
        erasure_info: &ErasureBlockInfo,
        block_id: BlockId,
    ) -> Result<EncryptedMacroBlock> {
        let data_shards = erasure_info.data_shards as usize;
        let parity_shards = erasure_info.parity_shards as usize;
        let total_shards = data_shards + parity_shards;
        let original_len = erasure_info.original_len as usize;

        // Create erasure coder
        let config = ErasureConfig::new(data_shards, parity_shards)?;
        let coder = ErasureCoder::new(config)?;

        // Build shard array with None for missing shards
        let mut shard_array: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        for (idx, data) in shards {
            if idx < total_shards {
                shard_array[idx] = Some(data.to_vec());
            }
        }

        // Check if we have enough shards
        let available = shard_array.iter().filter(|s| s.is_some()).count();
        if available < data_shards {
            return Err(EraError::ErasureError(format!(
                "Not enough shards for recovery: have {}, need {}",
                available, data_shards
            )));
        }

        // Decode
        let recovered_data = coder.decode(&shard_array, original_len)?;

        // Note: original_size, compressed_size, chunk_count are embedded in the
        // encrypted block's internal structure and will be parsed during unpack()
        Ok(EncryptedMacroBlock {
            block_id,
            data: Bytes::from(recovered_data),
            // These metadata fields are embedded in the compressed data
            // and will be extracted during unpacking
            original_size: original_len as u32,
            compressed_size: original_len as u32,
            chunk_count: 0, // Unknown until unpacked
        })
    }

    /// Get the inner unpacker for direct access when needed
    pub fn inner(&self) -> &MacroBlockUnpacker {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErasureBlockBuilder;
    use bytes::Bytes;
    use era_codec::ZstdCompressor;
    use era_common::ErasureCodeConfig;
    use era_common::UniqueChunk;
    use era_crypto::{derive_key, KdfParams, Salt};

    fn setup_keys() -> (DerivedKey, [u8; 16]) {
        let salt = Salt::generate();
        let params = KdfParams::default();
        let key = derive_key(b"test_password", &salt, &params).unwrap();
        let nonce_context = *salt.as_bytes();
        (key, nonce_context)
    }

    #[test]
    fn test_erasure_roundtrip_no_loss() {
        let (key, nonce_context) = setup_keys();

        // Create test data
        let test_data = b"Hello, erasure coding world! This is test data.";
        let hash = era_crypto::hash(test_data);
        let chunk = UniqueChunk::new(Bytes::copy_from_slice(test_data), hash);

        // Encode
        let erasure_config = ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        };
        let builder = ErasureBlockBuilder::new(
            key.clone(),
            nonce_context,
            Box::new(ZstdCompressor::new(3)),
            erasure_config,
        )
        .unwrap();

        let sharded_block = builder.pack_single(chunk).unwrap();

        // Decode with all shards present
        let unpacker =
            ErasureBlockUnpacker::new(key, nonce_context, Box::new(ZstdCompressor::new(3)));

        let shards: Vec<(usize, Bytes)> = sharded_block.shards.into_iter().enumerate().collect();

        let erasure_info = ErasureBlockInfo {
            data_shards: sharded_block.config.data_shards,
            parity_shards: sharded_block.config.parity_shards,
            shard_size: shards[0].1.len() as u32,
            original_len: sharded_block.original_len,
        };

        let chunks = unpacker
            .decode_and_extract_all(shards, &erasure_info, sharded_block.block_id)
            .unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, hash);
        assert_eq!(chunks[0].1.as_ref(), test_data);
    }

    #[test]
    fn test_erasure_roundtrip_with_loss() {
        let (key, nonce_context) = setup_keys();

        // Create test data
        let test_data = b"Recovery test data - should survive shard loss!";
        let hash = era_crypto::hash(test_data);
        let chunk = UniqueChunk::new(Bytes::copy_from_slice(test_data), hash);

        // Encode with 4+2 (can recover from 2 lost shards)
        let erasure_config = ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        };
        let builder = ErasureBlockBuilder::new(
            key.clone(),
            nonce_context,
            Box::new(ZstdCompressor::new(3)),
            erasure_config,
        )
        .unwrap();

        let sharded_block = builder.pack_single(chunk).unwrap();

        // Simulate losing 2 shards (shard 1 and shard 3)
        let shards: Vec<(usize, Bytes)> = sharded_block
            .shards
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 1 && *i != 3) // Lose shards 1 and 3
            .collect();

        assert_eq!(shards.len(), 4); // 4 remaining shards

        let erasure_info = ErasureBlockInfo {
            data_shards: sharded_block.config.data_shards,
            parity_shards: sharded_block.config.parity_shards,
            shard_size: shards[0].1.len() as u32,
            original_len: sharded_block.original_len,
        };

        // Decode - should recover successfully
        let unpacker =
            ErasureBlockUnpacker::new(key, nonce_context, Box::new(ZstdCompressor::new(3)));

        let chunks = unpacker
            .decode_and_extract_all(shards, &erasure_info, sharded_block.block_id)
            .unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, hash);
        assert_eq!(chunks[0].1.as_ref(), test_data);
    }

    #[test]
    fn test_erasure_insufficient_shards() {
        let (key, nonce_context) = setup_keys();

        // Create test data
        let test_data = b"This will fail due to too many lost shards";
        let hash = era_crypto::hash(test_data);
        let chunk = UniqueChunk::new(Bytes::copy_from_slice(test_data), hash);

        // Encode with 4+2
        let erasure_config = ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        };
        let builder = ErasureBlockBuilder::new(
            key.clone(),
            nonce_context,
            Box::new(ZstdCompressor::new(3)),
            erasure_config,
        )
        .unwrap();

        let sharded_block = builder.pack_single(chunk).unwrap();

        // Lose 3 shards - too many for 4+2 to recover
        let shards: Vec<(usize, Bytes)> = sharded_block
            .shards
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 0 && *i != 2 && *i != 4)
            .collect();

        assert_eq!(shards.len(), 3); // Only 3 remaining

        let erasure_info = ErasureBlockInfo {
            data_shards: sharded_block.config.data_shards,
            parity_shards: sharded_block.config.parity_shards,
            shard_size: shards[0].1.len() as u32,
            original_len: sharded_block.original_len,
        };

        let unpacker =
            ErasureBlockUnpacker::new(key, nonce_context, Box::new(ZstdCompressor::new(3)));

        // Should fail due to insufficient shards
        let result = unpacker.decode_and_extract_all(shards, &erasure_info, sharded_block.block_id);
        assert!(result.is_err());
    }
}
