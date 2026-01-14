//! Session-aware MacroBlock builder with per-block key derivation.
//!
//! This module implements the multi-level key derivation ("Onion Model")
//! as specified in the security optimization document (Section 3).
//!
//! ## Key Hierarchy
//!
//! ```text
//! MasterKey (Argon2id) → VolumeKey (HKDF) → BlockKey (HKDF)
//! ```
//!
//! Each block is encrypted with a unique BlockKey, providing:
//! - **Forward Security**: Compromise of one block key doesn't affect others
//! - **Backward Security**: Past blocks remain secure
//! - **Key Isolation**: Blocks are cryptographically independent

use bytes::{BufMut, BytesMut};
use era_codec::Compressor;
use era_common::{
    BlockChunkIndex, BlockId, ChunkIndexEntry, ChunkVec, EncryptedMacroBlock, Result, UniqueChunk,
};
use era_crypto::{BlockKey, KeySession, VolumeKey};
use std::sync::atomic::{AtomicU64, Ordering};

/// A session-aware MacroBlock builder that derives a unique key for each block.
///
/// Unlike `MacroBlockBuilder` which uses a single key for all blocks, this builder
/// implements the HKDF multi-level key derivation for cryptographic isolation.
///
/// # Example
///
/// ```ignore
/// let session = KeySession::new(password, &salt, &params)?;
/// let volume_key = session.derive_volume_key(0);
/// let builder = SessionBlockBuilder::new(&session, &volume_key, nonce_context, compressor);
///
/// // Each block gets a unique key
/// let block = builder.pack_chunks(chunks)?;
/// ```
pub struct SessionBlockBuilder<'a> {
    /// Reference to the key session (for block key derivation)
    session: &'a KeySession,
    /// The volume key for this volume
    volume_key: &'a VolumeKey,
    /// Target block size (default 4MB)
    target_size: usize,
    /// Compressor to use
    compressor: Box<dyn Compressor>,
    /// Nonce context (must be unique per archive, e.g., salt)
    nonce_context: [u8; 16],
    /// Next block ID
    next_block_id: AtomicU64,
}

impl<'a> SessionBlockBuilder<'a> {
    /// Create a new session-aware block builder.
    ///
    /// # Arguments
    /// * `session` - The key session containing the master key
    /// * `volume_key` - The volume key for this volume (pre-derived for efficiency)
    /// * `nonce_context` - A unique 16-byte context for nonce derivation (e.g., archive salt)
    /// * `compressor` - The compressor to use
    pub fn new(
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        nonce_context: [u8; 16],
        compressor: Box<dyn Compressor>,
    ) -> Self {
        Self {
            session,
            volume_key,
            target_size: 4 * 1024 * 1024, // 4MB
            compressor,
            nonce_context,
            next_block_id: AtomicU64::new(0),
        }
    }

    /// Set the target block size.
    pub fn with_target_size(mut self, size: usize) -> Self {
        self.target_size = size;
        self
    }

    /// Set the starting block ID (for resuming from checkpoint).
    pub fn with_starting_block_id(self, id: u64) -> Self {
        self.next_block_id.store(id, Ordering::SeqCst);
        self
    }

    /// Derive a unique block key for the given block ID.
    fn derive_block_key(&self, block_id: BlockId) -> BlockKey {
        self.session
            .derive_block_key(self.volume_key, block_id.sequence(), &self.nonce_context)
    }

    /// Pack a single chunk into a MacroBlock with per-block key derivation.
    pub fn pack_single(&self, chunk: UniqueChunk) -> Result<EncryptedMacroBlock> {
        self.pack_chunks(vec![chunk])
    }

    /// Pack multiple chunks into a single MacroBlock with per-block key derivation.
    ///
    /// Each block is encrypted with a unique key derived via HKDF from the volume key.
    pub fn pack_chunks(&self, chunks: Vec<UniqueChunk>) -> Result<EncryptedMacroBlock> {
        let block_id = BlockId::new(self.next_block_id.fetch_add(1, Ordering::SeqCst));

        // 1. Derive a unique key for this block
        let block_key = self.derive_block_key(block_id);

        // 2. Build chunk index
        let mut index_entries = Vec::with_capacity(chunks.len());
        let mut data = BytesMut::new();

        for chunk in &chunks {
            let entry = ChunkIndexEntry {
                hash: chunk.hash,
                offset: data.len() as u32,
                length: chunk.data.len() as u32,
            };
            index_entries.push(entry);
            data.put_slice(&chunk.data);
        }

        let chunk_index = BlockChunkIndex {
            count: chunks.len() as u16,
            entries: index_entries,
        };

        // 3. Serialize: [index_length(4) | index_data | chunk_data]
        let index_bytes = era_common::serialize(&chunk_index)?;
        let original_size = 4 + index_bytes.len() + data.len();

        let mut full_data = BytesMut::with_capacity(original_size);
        full_data.put_u32_le(index_bytes.len() as u32);
        full_data.put_slice(&index_bytes);
        full_data.put_slice(&data);

        // 4. Compress
        let compressed = self.compressor.compress(&full_data)?;
        let compressed_size = compressed.len();

        // 5. Encrypt with the per-block key
        let derived_key = block_key.to_derived_key();
        let encrypted = era_crypto::encrypt_with_context(
            &derived_key,
            &self.nonce_context,
            block_id,
            &compressed,
        )?;

        Ok(EncryptedMacroBlock {
            block_id,
            data: encrypted,
            original_size: original_size as u32,
            compressed_size: compressed_size as u32,
            chunk_count: chunks.len() as u16,
        })
    }

    /// Get statistics about the builder.
    pub fn blocks_created(&self) -> u64 {
        self.next_block_id.load(Ordering::SeqCst)
    }
}

/// A session-aware MacroBlock unpacker that derives per-block keys for decryption.
pub struct SessionBlockUnpacker<'a> {
    /// Reference to the key session (for block key derivation)
    session: &'a KeySession,
    /// The volume key for this volume
    volume_key: &'a VolumeKey,
    /// Compressor for decompression
    compressor: Box<dyn Compressor>,
    /// Nonce context (must match the one used during encryption)
    nonce_context: [u8; 16],
}

impl<'a> SessionBlockUnpacker<'a> {
    /// Create a new session-aware block unpacker.
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
        Self {
            session,
            volume_key,
            compressor,
            nonce_context,
        }
    }

    /// Derive a unique block key for the given block ID.
    fn derive_block_key(&self, block_id: BlockId) -> BlockKey {
        self.session
            .derive_block_key(self.volume_key, block_id.sequence(), &self.nonce_context)
    }

    /// Decrypt and decompress a MacroBlock, returning raw data and index.
    pub fn unpack(&self, block: &EncryptedMacroBlock) -> Result<crate::unpacker::UnpackedBlock> {
        // 1. Derive the block key
        let block_key = self.derive_block_key(block.block_id);
        let derived_key = block_key.to_derived_key();

        // 2. Decrypt with the per-block key
        let compressed = era_crypto::decrypt_with_context(
            &derived_key,
            &self.nonce_context,
            block.block_id,
            &block.data,
        )?;

        // 3. Decompress
        let decompressed = self.compressor.decompress(&compressed)?;

        // 4. Parse index
        if decompressed.len() < 4 {
            return Err(era_common::EraError::decompression("Block too small"));
        }

        let index_len = u32::from_le_bytes([
            decompressed[0],
            decompressed[1],
            decompressed[2],
            decompressed[3],
        ]) as usize;

        if decompressed.len() < 4 + index_len {
            return Err(era_common::EraError::decompression(
                "Index length exceeds block size",
            ));
        }

        let index: BlockChunkIndex = era_common::deserialize(&decompressed[4..4 + index_len])?;
        let data_start = 4 + index_len;
        let data = bytes::Bytes::copy_from_slice(&decompressed[data_start..]);

        Ok(crate::unpacker::UnpackedBlock {
            block_id: block.block_id,
            index,
            data,
        })
    }

    /// Extract all chunks from a block with per-block key derivation.
    ///
    /// Returns a ChunkVec (SmallVec) which avoids heap allocation for blocks
    /// with up to 16 chunks. This provides significant performance improvement
    /// for extraction operations.
    pub fn extract_all_chunks(&self, block: &EncryptedMacroBlock) -> Result<ChunkVec> {
        let unpacked = self.unpack(block)?;
        let mut chunks = ChunkVec::new();

        for entry in &unpacked.index.entries {
            let start = entry.offset as usize;
            let end = start + entry.length as usize;

            if end > unpacked.data.len() {
                return Err(era_common::EraError::decompression(
                    "Chunk offset exceeds data size",
                ));
            }

            chunks.push((entry.hash, unpacked.data.slice(start..end)));
        }

        Ok(chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use era_codec::ZstdCompressor;
    use era_common::ChunkHash;
    use era_crypto::{KdfParams, Salt};

    const TEST_NONCE_CONTEXT: [u8; 16] = [42u8; 16];

    fn test_session() -> (KeySession, Salt) {
        let salt = Salt::from_bytes([0u8; 16]);
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let session = KeySession::new(b"test_password", &salt, &params).unwrap();
        (session, salt)
    }

    #[test]
    fn test_session_builder_pack_unpack_roundtrip() {
        let (session, _salt) = test_session();
        let volume_key = session.derive_volume_key(0);

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );

        let original_data = vec![42u8; 1024];
        let chunk_hash = era_crypto::hash(&original_data);
        let chunk = UniqueChunk::new(Bytes::from(original_data.clone()), chunk_hash);

        let encrypted = builder.pack_single(chunk).unwrap();

        // Unpack with session
        let unpacker = SessionBlockUnpacker::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );
        let unpacked = unpacker.unpack(&encrypted).unwrap();

        assert_eq!(unpacked.chunk_count(), 1);
        let extracted = unpacked.get_chunk(0).unwrap();
        assert_eq!(extracted.as_ref(), &original_data);
    }

    #[test]
    fn test_different_blocks_different_keys() {
        let (session, _salt) = test_session();
        let volume_key = session.derive_volume_key(0);

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );

        // Create two blocks with identical data
        let data = vec![42u8; 256];
        let chunk1 = UniqueChunk::new(Bytes::from(data.clone()), ChunkHash::from_bytes([1u8; 32]));
        let chunk2 = UniqueChunk::new(Bytes::from(data.clone()), ChunkHash::from_bytes([2u8; 32]));

        let block1 = builder.pack_single(chunk1).unwrap();
        let block2 = builder.pack_single(chunk2).unwrap();

        // Blocks should have different IDs
        assert_eq!(block1.block_id.sequence(), 0);
        assert_eq!(block2.block_id.sequence(), 1);

        // The ciphertext should be different (different keys + different nonces)
        assert_ne!(block1.data, block2.data);
    }

    #[test]
    fn test_key_isolation_prevents_cross_decryption() {
        let (session, _salt) = test_session();
        let volume_key = session.derive_volume_key(0);

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );

        let data = vec![42u8; 256];
        let chunk = UniqueChunk::new(Bytes::from(data), ChunkHash::from_bytes([1u8; 32]));
        let block = builder.pack_single(chunk).unwrap();

        // Try to decrypt with the wrong volume key
        let wrong_volume_key = session.derive_volume_key(1); // Different volume
        let wrong_unpacker = SessionBlockUnpacker::new(
            &session,
            &wrong_volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );

        // Decryption should fail with AEAD authentication error
        let result = wrong_unpacker.unpack(&block);
        assert!(result.is_err());
    }

    #[test]
    fn test_volume_key_isolation() {
        let (session, _salt) = test_session();

        // Derive keys for two different volumes
        let vk0 = session.derive_volume_key(0);
        let vk1 = session.derive_volume_key(1);

        // Keys should be different
        assert_ne!(vk0.as_bytes(), vk1.as_bytes());

        // Block keys derived from different volume keys should also differ
        let bk0_0 = session.derive_block_key(&vk0, 0, &TEST_NONCE_CONTEXT);
        let bk1_0 = session.derive_block_key(&vk1, 0, &TEST_NONCE_CONTEXT);
        assert_ne!(bk0_0.as_bytes(), bk1_0.as_bytes());
    }

    #[test]
    fn test_pack_multiple_chunks() {
        let (session, _salt) = test_session();
        let volume_key = session.derive_volume_key(0);

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );

        let chunks = vec![
            UniqueChunk::new(
                Bytes::from(vec![1u8; 512]),
                ChunkHash::from_bytes([1u8; 32]),
            ),
            UniqueChunk::new(
                Bytes::from(vec![2u8; 512]),
                ChunkHash::from_bytes([2u8; 32]),
            ),
            UniqueChunk::new(
                Bytes::from(vec![3u8; 512]),
                ChunkHash::from_bytes([3u8; 32]),
            ),
        ];

        let block = builder.pack_chunks(chunks).unwrap();
        assert_eq!(block.chunk_count, 3);

        // Verify roundtrip
        let unpacker = SessionBlockUnpacker::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );
        let unpacked = unpacker.unpack(&block).unwrap();

        assert_eq!(unpacked.chunk_count(), 3);
        assert_eq!(unpacked.get_chunk(0).unwrap().as_ref(), &[1u8; 512]);
        assert_eq!(unpacked.get_chunk(1).unwrap().as_ref(), &[2u8; 512]);
        assert_eq!(unpacked.get_chunk(2).unwrap().as_ref(), &[3u8; 512]);
    }

    #[test]
    fn test_starting_block_id() {
        let (session, _salt) = test_session();
        let volume_key = session.derive_volume_key(0);

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        )
        .with_starting_block_id(100);

        let chunk = UniqueChunk::new(
            Bytes::from(vec![42u8; 64]),
            ChunkHash::from_bytes([1u8; 32]),
        );
        let block = builder.pack_single(chunk).unwrap();

        assert_eq!(block.block_id.sequence(), 100);
    }
}
