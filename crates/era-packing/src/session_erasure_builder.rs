//! Session-aware erasure-coded block builder with per-block key derivation.
//!
//! This module combines the security of `SessionBlockBuilder` (per-block keys)
//! with the redundancy of erasure coding (Reed-Solomon).
//!
//! ## Security
//!
//! Each block is encrypted with a unique key derived via HKDF from the volume key,
//! providing:
//! - **Forward Security**: Compromise of one block key doesn't affect others
//! - **Backward Security**: Past blocks remain secure
//! - **Key Isolation**: Blocks are cryptographically independent
//!
//! ## Redundancy
//!
//! After encryption, each block is encoded with Reed-Solomon erasure coding,
//! allowing recovery from up to `parity_shards` lost shards.

use era_codec::{Compressor, ErasureCoder, ErasureConfig};
use era_common::{ChunkVec, ErasureCodeConfig, ErasureShardedBlock, Result, UniqueChunk};
use era_crypto::{KeySession, VolumeKey};

use crate::SessionBlockBuilder;

/// Session-aware erasure block builder with per-block key derivation.
///
/// This builder wraps `SessionBlockBuilder` and adds Reed-Solomon erasure coding.
/// Each block gets a unique encryption key AND erasure redundancy.
///
/// # Example
///
/// ```ignore
/// let session = KeySession::new(password, &salt, &params)?;
/// let volume_key = session.derive_volume_key(0);
/// let builder = SessionErasureBlockBuilder::new(
///     &session,
///     &volume_key,
///     nonce_context,
///     compressor,
///     ErasureCodeConfig::new(4, 2),
/// )?;
///
/// // Each block gets unique key + erasure coding
/// let sharded = builder.pack_chunks(chunks)?;
/// ```
pub struct SessionErasureBlockBuilder<'a> {
    /// Inner session block builder (handles per-block key derivation)
    inner: SessionBlockBuilder<'a>,
    /// Erasure coder
    coder: ErasureCoder,
    /// Erasure configuration for output
    config: ErasureCodeConfig,
}

impl<'a> SessionErasureBlockBuilder<'a> {
    /// Create a new session-aware erasure block builder.
    ///
    /// # Arguments
    /// * `session` - The key session containing the master key
    /// * `volume_key` - The volume key for this volume
    /// * `nonce_context` - A unique 16-byte context for nonce derivation (e.g., archive salt)
    /// * `compressor` - The compressor to use
    /// * `erasure_config` - Reed-Solomon configuration (data_shards, parity_shards)
    pub fn new(
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        nonce_context: [u8; 16],
        compressor: Box<dyn Compressor>,
        erasure_config: ErasureCodeConfig,
    ) -> Result<Self> {
        let inner = SessionBlockBuilder::new(session, volume_key, nonce_context, compressor);

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

    /// Set the target block size.
    pub fn with_target_size(mut self, size: usize) -> Self {
        self.inner = self.inner.with_target_size(size);
        self
    }

    /// Set the starting block ID (for resuming from checkpoint).
    pub fn with_starting_block_id(mut self, id: u64) -> Self {
        self.inner = self.inner.with_starting_block_id(id);
        self
    }

    /// Pack a single chunk into an erasure-coded block with per-block key.
    pub fn pack_single(&self, chunk: UniqueChunk) -> Result<ErasureShardedBlock> {
        // First, create the encrypted block with per-block key
        let encrypted = self.inner.pack_single(chunk)?;

        // Apply erasure coding
        self.encode_block(encrypted.block_id, &encrypted.data)
    }

    /// Pack multiple chunks into an erasure-coded block with per-block key.
    pub fn pack_chunks(&self, chunks: Vec<UniqueChunk>) -> Result<ErasureShardedBlock> {
        let encrypted = self.inner.pack_chunks(chunks)?;
        self.encode_block(encrypted.block_id, &encrypted.data)
    }

    /// Apply erasure coding to encrypted block data.
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

    /// Get statistics about the builder.
    pub fn blocks_created(&self) -> u64 {
        self.inner.blocks_created()
    }

    /// Get the erasure configuration.
    pub fn config(&self) -> ErasureCodeConfig {
        self.config
    }
}

/// Session-aware erasure block unpacker with per-block key derivation.
///
/// This unpacker reads erasure-coded shards, recovers the encrypted block via
/// Reed-Solomon decoding, then decrypts using a per-block key derived from the
/// volume key.
///
/// ## Security
///
/// Each block is decrypted with a unique key derived via HKDF, providing
/// cryptographic isolation between blocks.
pub struct SessionErasureBlockUnpacker<'a> {
    /// Inner session block unpacker (handles per-block key derivation + decryption)
    inner: crate::SessionBlockUnpacker<'a>,
}

impl<'a> SessionErasureBlockUnpacker<'a> {
    /// Create a new session-aware erasure block unpacker.
    ///
    /// # Arguments
    /// * `session` - The key session containing the master key
    /// * `volume_key` - The volume key for this volume
    /// * `nonce_context` - The 16-byte context used during encryption (e.g., archive salt)
    /// * `compressor` - The compressor to use for decompression
    pub fn new(
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        nonce_context: [u8; 16],
        compressor: Box<dyn Compressor>,
    ) -> Self {
        let inner =
            crate::SessionBlockUnpacker::new(session, volume_key, nonce_context, compressor);
        Self { inner }
    }

    /// Decode shards and extract all chunks from the recovered block.
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
        shards: Vec<(usize, bytes::Bytes)>,
        erasure_info: &era_common::ErasureBlockInfo,
        block_id: era_common::BlockId,
    ) -> Result<ChunkVec> {
        let encrypted_block = self.decode_shards(shards, erasure_info, block_id)?;
        let unpacked = self.inner.unpack(&encrypted_block)?;
        crate::block_codec::extract_all_chunks(&unpacked.index, &unpacked.data)
    }

    /// Decode shards and extract a specific chunk by hash.
    pub fn decode_and_extract_chunk(
        &self,
        shards: Vec<(usize, bytes::Bytes)>,
        erasure_info: &era_common::ErasureBlockInfo,
        block_id: era_common::BlockId,
        chunk_hash: &era_common::ChunkHash,
    ) -> Result<Option<bytes::Bytes>> {
        let encrypted_block = self.decode_shards(shards, erasure_info, block_id)?;
        let unpacked = self.inner.unpack(&encrypted_block)?;
        crate::block_codec::extract_chunk_by_hash(&unpacked.index, &unpacked.data, chunk_hash)
    }

    /// Decode available shards into the original EncryptedMacroBlock.
    ///
    /// This is the core RS decoding logic that reconstructs the original
    /// encrypted block from available shards.
    pub fn decode_shards(
        &self,
        shards: Vec<(usize, bytes::Bytes)>,
        erasure_info: &era_common::ErasureBlockInfo,
        block_id: era_common::BlockId,
    ) -> Result<era_common::EncryptedMacroBlock> {
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
            return Err(era_common::EraError::ErasureError(format!(
                "Not enough shards for recovery: have {}, need {}",
                available, data_shards
            )));
        }

        // Decode
        let recovered_data = coder.decode(&shard_array, original_len)?;

        Ok(era_common::EncryptedMacroBlock {
            block_id,
            data: bytes::Bytes::from(recovered_data),
            original_size: original_len as u32,
            compressed_size: original_len as u32,
            chunk_count: 0, // Unknown until unpacked
        })
    }

    /// Get the inner unpacker for direct access when needed.
    pub fn inner(&self) -> &crate::SessionBlockUnpacker<'a> {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_codec::ZstdCompressor;
    use era_common::ChunkHash;
    use era_crypto::{derive_key, KdfParams, Salt};

    fn test_session() -> (KeySession, Salt) {
        let salt = Salt::generate();
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let key = derive_key(b"test_password", &salt, &params).unwrap();
        (KeySession::from_derived_key(&key), salt)
    }

    #[test]
    fn test_session_erasure_pack_single() {
        let (session, salt) = test_session();
        let volume_key = session.derive_volume_key(0);
        let compressor = Box::new(ZstdCompressor::default());
        let config = ErasureCodeConfig::new(4, 2);

        let builder = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            *salt.as_bytes(),
            compressor,
            config,
        )
        .unwrap();

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
    fn test_session_erasure_pack_multiple_chunks() {
        let (session, salt) = test_session();
        let volume_key = session.derive_volume_key(0);
        let compressor = Box::new(ZstdCompressor::default());
        let config = ErasureCodeConfig::new(4, 2);

        let builder = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            *salt.as_bytes(),
            compressor,
            config,
        )
        .unwrap();

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
    fn test_different_blocks_have_different_ciphertext() {
        let (session, salt) = test_session();
        let volume_key = session.derive_volume_key(0);

        let compressor1 = Box::new(ZstdCompressor::default());
        let compressor2 = Box::new(ZstdCompressor::default());
        let config = ErasureCodeConfig::new(4, 2);

        let builder1 = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            *salt.as_bytes(),
            compressor1,
            config,
        )
        .unwrap();

        let builder2 = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            *salt.as_bytes(),
            compressor2,
            config,
        )
        .unwrap();

        // Same data, different block IDs -> different ciphertext
        let data = vec![42u8; 1024];
        let chunk1 = UniqueChunk::new(Bytes::from(data.clone()), ChunkHash::from_bytes([1u8; 32]));
        let chunk2 = UniqueChunk::new(Bytes::from(data), ChunkHash::from_bytes([2u8; 32]));

        let block1 = builder1.pack_single(chunk1).unwrap();
        let block2 = builder2.pack_single(chunk2).unwrap();

        // Different block IDs mean different keys, so shards should differ
        assert_ne!(block1.shards[0], block2.shards[0]);
    }

    #[test]
    fn test_session_erasure_shards_can_recover() {
        use era_codec::{ErasureCoder, ErasureConfig};

        let (session, salt) = test_session();
        let volume_key = session.derive_volume_key(0);
        let compressor = Box::new(ZstdCompressor::default());
        let config = ErasureCodeConfig::new(4, 2);

        let builder = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            *salt.as_bytes(),
            compressor,
            config,
        )
        .unwrap();

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
