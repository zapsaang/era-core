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

use bytes::{BufMut, Bytes, BytesMut};
use era_codec::Compressor;
use era_common::{
    BlockChunkIndex, BlockId, BlockType, ChunkIndexEntry, ChunkVec, EncryptedMacroBlock, EraError,
    Result, UniqueChunk,
};
use era_crypto::{BlockKey, KeySession, VolumeKey};
use std::cell::Cell;

/// A serialized and compressed MacroBlock with volume-independent identity.
///
/// The block ID and key are allocated during preparation. Sealing binds this
/// preimage to a selected volume without reallocating either one.
pub struct PreparedMacroBlock {
    block_id: BlockId,
    block_key: BlockKey,
    compressed: Bytes,
    original_size: u32,
    compressed_size: u32,
    chunk_count: u16,
    sealed_len: usize,
}

impl PreparedMacroBlock {
    /// Return the block ID allocated during preparation.
    #[must_use]
    pub fn block_id(&self) -> BlockId {
        self.block_id
    }

    /// Return the uncompressed serialized size.
    #[must_use]
    pub fn original_size(&self) -> u32 {
        self.original_size
    }

    /// Return the compressed size before AEAD sealing.
    #[must_use]
    pub fn compressed_size(&self) -> u32 {
        self.compressed_size
    }

    /// Return the number of chunks in the block.
    #[must_use]
    pub fn chunk_count(&self) -> u16 {
        self.chunk_count
    }

    /// Return the exact sealed payload length, including the AEAD tag.
    ///
    /// This excludes the separate volume-level `BlockHeader`.
    #[must_use]
    pub fn sealed_len(&self) -> usize {
        self.sealed_len
    }
}

/// A session-aware MacroBlock builder that derives a unique key for each block.
///
/// Unlike `MacroBlockBuilder` which uses a single key for all blocks, this builder
/// implements the HKDF multi-level key derivation for cryptographic isolation.
///
/// # Example
///
/// ```ignore
/// let session = KeySession::new(password, &salt, &params)?;
/// let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
/// let builder = SessionBlockBuilder::new(
///     &session,
///     &volume_key,
///     nonce_context,
///     archive_id,
///     epoch_id,
///     volume_index,
///     compressor,
/// );
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
    archive_id: [u8; 16],
    epoch_id: u32,
    volume_index: u32,
    /// Next block ID (interior mutability for &self methods)
    next_block_id: Cell<u64>,
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
        archive_id: [u8; 16],
        epoch_id: u32,
        volume_index: u32,
        compressor: Box<dyn Compressor>,
    ) -> Self {
        Self {
            session,
            volume_key,
            target_size: 4 * 1024 * 1024, // 4MB
            compressor,
            nonce_context,
            archive_id,
            epoch_id,
            volume_index,
            next_block_id: Cell::new(0),
        }
    }

    /// Set the target block size.
    pub fn with_target_size(mut self, size: usize) -> Self {
        self.target_size = size;
        self
    }

    /// Set the starting block ID (for resuming from checkpoint).
    pub fn with_starting_block_id(self, id: u64) -> Self {
        self.next_block_id.set(id);
        self
    }

    /// Derive a unique block key for the given block ID.
    fn derive_block_key(&self, block_id: BlockId) -> Result<BlockKey> {
        self.session
            .derive_block_key(self.volume_key, block_id.sequence(), &self.nonce_context)
    }

    /// Pack a single chunk into a MacroBlock with per-block key derivation.
    pub fn pack_single(&self, chunk: UniqueChunk) -> Result<EncryptedMacroBlock> {
        self.pack_chunks(vec![chunk])
    }

    /// Pack a single typed metadata chunk into a MacroBlock.
    pub fn pack_single_with_type(
        &self,
        chunk: UniqueChunk,
        block_type: BlockType,
    ) -> Result<EncryptedMacroBlock> {
        self.pack_chunks_with_type(vec![chunk], block_type)
    }

    /// Pack multiple chunks into a single MacroBlock with per-block key derivation.
    ///
    /// Each block is encrypted with a unique key derived via HKDF from the volume key.
    pub fn pack_chunks(&self, chunks: Vec<UniqueChunk>) -> Result<EncryptedMacroBlock> {
        self.pack_chunks_with_type(chunks, BlockType::Data)
    }

    /// Pack multiple chunks into a typed MacroBlock with per-block key derivation.
    pub fn pack_chunks_with_type(
        &self,
        chunks: Vec<UniqueChunk>,
        block_type: BlockType,
    ) -> Result<EncryptedMacroBlock> {
        let prepared = self.prepare_chunks(&chunks)?;
        self.seal_prepared_with_type(&prepared, self.volume_index, block_type)
    }

    /// Serialize and compress chunks without binding them to a volume.
    ///
    /// This consumes the next block ID and derives its volume-independent key.
    ///
    /// # Errors
    ///
    /// Returns an error for block ID or size overflow, key derivation,
    /// serialization, or compression failures.
    pub fn prepare_chunks(&self, chunks: &[UniqueChunk]) -> Result<PreparedMacroBlock> {
        let id = self.next_block_id.get();
        self.next_block_id.set(
            id.checked_add(1)
                .ok_or_else(|| EraError::InvalidConfig("Block ID overflow".into()))?,
        );
        let block_id = BlockId::new(id);
        let block_key = self.derive_block_key(block_id)?;
        let chunk_count = u16::try_from(chunks.len())
            .map_err(|_| EraError::InvalidConfig("chunk count exceeds u16".into()))?;

        let mut index_entries = Vec::with_capacity(chunks.len());
        let mut data = BytesMut::new();
        for chunk in chunks {
            let entry = ChunkIndexEntry {
                hash: chunk.hash,
                offset: u32::try_from(data.len())
                    .map_err(|_| EraError::InvalidConfig("chunk offset exceeds u32".into()))?,
                length: u32::try_from(chunk.data.len())
                    .map_err(|_| EraError::InvalidConfig("chunk length exceeds u32".into()))?,
            };
            index_entries.push(entry);
            data.put_slice(&chunk.data);
        }

        let chunk_index = BlockChunkIndex {
            count: chunk_count,
            entries: index_entries,
        };
        let proto_index: era_common::proto::BlockChunkIndex = chunk_index.into();
        let index_bytes = era_common::serialize_proto(&proto_index)?;
        let index_len = u32::try_from(index_bytes.len())
            .map_err(|_| EraError::InvalidConfig("chunk index exceeds u32".into()))?;
        let original_size = 4usize
            .checked_add(index_bytes.len())
            .and_then(|size| size.checked_add(data.len()))
            .ok_or_else(|| EraError::InvalidConfig("MacroBlock plaintext size overflow".into()))?;
        let original_size_u32 = u32::try_from(original_size)
            .map_err(|_| EraError::InvalidConfig("MacroBlock plaintext exceeds u32".into()))?;

        let mut full_data = BytesMut::with_capacity(original_size);
        full_data.put_u32_le(index_len);
        full_data.put_slice(&index_bytes);
        full_data.put_slice(&data);

        let compressed = self.compressor.compress(&full_data)?;
        let compressed_size = u32::try_from(compressed.len())
            .map_err(|_| EraError::InvalidConfig("compressed block exceeds u32".into()))?;
        let sealed_len = compressed
            .len()
            .checked_add(era_crypto::TAG_SIZE)
            .ok_or_else(|| EraError::InvalidConfig("sealed block length overflow".into()))?;

        Ok(PreparedMacroBlock {
            block_id,
            block_key,
            compressed,
            original_size: original_size_u32,
            compressed_size,
            chunk_count,
            sealed_len,
        })
    }

    /// Seal a prepared data block for the selected volume.
    ///
    /// # Errors
    ///
    /// Returns an error if key conversion or AEAD encryption fails.
    pub fn seal_prepared(
        &self,
        prepared: &PreparedMacroBlock,
        volume_index: u32,
    ) -> Result<EncryptedMacroBlock> {
        self.seal_prepared_with_type(prepared, volume_index, BlockType::Data)
    }

    /// Seal a prepared block with its type and the selected volume as AEAD context.
    ///
    /// # Errors
    ///
    /// Returns an error if key conversion or AEAD encryption fails.
    pub fn seal_prepared_with_type(
        &self,
        prepared: &PreparedMacroBlock,
        volume_index: u32,
        block_type: BlockType,
    ) -> Result<EncryptedMacroBlock> {
        let derived_key = prepared.block_key.to_derived_key()?;
        let encrypted = era_crypto::encrypt_with_context_for_type(
            &derived_key,
            &self.nonce_context,
            &self.archive_id,
            self.epoch_id,
            volume_index,
            block_type,
            prepared.block_id,
            &prepared.compressed,
        )?;

        Ok(EncryptedMacroBlock {
            block_id: prepared.block_id,
            data: encrypted,
            original_size: prepared.original_size,
            compressed_size: prepared.compressed_size,
            chunk_count: prepared.chunk_count,
        })
    }

    /// Get statistics about the builder.
    pub fn blocks_created(&self) -> u64 {
        self.next_block_id.get()
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
    archive_id: [u8; 16],
    epoch_id: u32,
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
        archive_id: [u8; 16],
        epoch_id: u32,
        compressor: Box<dyn Compressor>,
    ) -> Self {
        Self {
            session,
            volume_key,
            compressor,
            nonce_context,
            archive_id,
            epoch_id,
        }
    }

    /// Derive a unique block key for the given block ID.
    fn derive_block_key(&self, block_id: BlockId) -> Result<BlockKey> {
        self.session
            .derive_block_key(self.volume_key, block_id.sequence(), &self.nonce_context)
    }

    /// Decrypt and decompress a MacroBlock, returning raw data and index.
    pub fn unpack(
        &self,
        block: &EncryptedMacroBlock,
        volume_index: u32,
    ) -> Result<crate::unpacker::UnpackedBlock> {
        self.unpack_with_type(block, volume_index, BlockType::Data)
    }

    /// Decrypt and decompress a typed MacroBlock, returning raw data and index.
    pub fn unpack_with_type(
        &self,
        block: &EncryptedMacroBlock,
        volume_index: u32,
        block_type: BlockType,
    ) -> Result<crate::unpacker::UnpackedBlock> {
        let block_key = self.derive_block_key(block.block_id)?;
        let derived_key = block_key.to_derived_key()?;
        let decrypt_context = crate::DecryptContext {
            key: &derived_key,
            nonce_context: &self.nonce_context,
            block_context: crate::BlockContext {
                archive_id: self.archive_id,
                epoch_id: self.epoch_id,
                volume_index,
            },
        };

        let (index, data) = crate::block_codec::decrypt_and_decompress_for_type(
            &decrypt_context,
            block.block_id,
            block_type,
            &block.data,
            self.compressor.as_ref(),
        )?;

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
    pub fn extract_all_chunks(
        &self,
        block: &EncryptedMacroBlock,
        volume_index: u32,
    ) -> Result<ChunkVec> {
        let unpacked = self.unpack(block, volume_index)?;
        crate::block_codec::extract_all_chunks(&unpacked.index, &unpacked.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::helpers::*;
    use bytes::Bytes;
    use era_common::ChunkHash;

    const TEST_ARCHIVE_ID: [u8; 16] = [7u8; 16];
    const TEST_EPOCH_ID: u32 = 1;
    const TEST_VOLUME_INDEX: u32 = 0;

    #[test]
    fn test_session_builder_pack_unpack_roundtrip() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            TEST_VOLUME_INDEX,
            crate::create_compressor(),
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
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            crate::create_compressor(),
        );
        let unpacked = unpacker.unpack(&encrypted, TEST_VOLUME_INDEX).unwrap();

        assert_eq!(unpacked.chunk_count(), 1);
        let extracted = unpacked.get_chunk(0).unwrap();
        assert_eq!(extracted.as_ref(), &original_data);
    }

    #[test]
    fn test_different_blocks_different_keys() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            TEST_VOLUME_INDEX,
            crate::create_compressor(),
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
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            TEST_VOLUME_INDEX,
            crate::create_compressor(),
        );

        let data = vec![42u8; 256];
        let chunk = UniqueChunk::new(Bytes::from(data), ChunkHash::from_bytes([1u8; 32]));
        let block = builder.pack_single(chunk).unwrap();

        // Try to decrypt with the wrong volume key
        let wrong_volume_key = session.generate_and_wrap_volume_key().unwrap().0; // Different volume
        let wrong_unpacker = SessionBlockUnpacker::new(
            &session,
            &wrong_volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            crate::create_compressor(),
        );

        // Decryption should fail with AEAD authentication error
        let result = wrong_unpacker.unpack(&block, TEST_VOLUME_INDEX);
        assert!(result.is_err());
    }

    #[test]
    fn test_volume_key_isolation() {
        let (session, _salt) = test_session();

        // Derive keys for two different volumes
        let vk0 = session.generate_and_wrap_volume_key().unwrap().0;
        let vk1 = session.generate_and_wrap_volume_key().unwrap().0;

        // Keys should be different
        assert_ne!(vk0.as_bytes(), vk1.as_bytes());

        // Block keys derived from different volume keys should also differ
        let bk0_0 = session
            .derive_block_key(&vk0, 0, &TEST_NONCE_CONTEXT)
            .unwrap();
        let bk1_0 = session
            .derive_block_key(&vk1, 0, &TEST_NONCE_CONTEXT)
            .unwrap();
        assert_ne!(bk0_0.as_bytes(), bk1_0.as_bytes());
    }

    #[test]
    fn test_pack_multiple_chunks() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            TEST_VOLUME_INDEX,
            crate::create_compressor(),
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
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            crate::create_compressor(),
        );
        let unpacked = unpacker.unpack(&block, TEST_VOLUME_INDEX).unwrap();

        assert_eq!(unpacked.chunk_count(), 3);
        assert_eq!(unpacked.get_chunk(0).unwrap().as_ref(), &[1u8; 512]);
        assert_eq!(unpacked.get_chunk(1).unwrap().as_ref(), &[2u8; 512]);
        assert_eq!(unpacked.get_chunk(2).unwrap().as_ref(), &[3u8; 512]);
    }

    fn prepared_test_builder<'a>(
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        compressor: Box<dyn Compressor>,
    ) -> SessionBlockBuilder<'a> {
        SessionBlockBuilder::new(
            session,
            volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            TEST_VOLUME_INDEX,
            compressor,
        )
    }

    fn prepared_test_unpacker<'a>(
        session: &'a KeySession,
        volume_key: &'a VolumeKey,
        compressor: Box<dyn Compressor>,
    ) -> SessionBlockUnpacker<'a> {
        SessionBlockUnpacker::new(
            session,
            volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            compressor,
        )
    }

    fn assert_same_block(expected: &EncryptedMacroBlock, actual: &EncryptedMacroBlock) {
        assert_eq!(expected.block_id, actual.block_id);
        assert_eq!(expected.data, actual.data);
        assert_eq!(expected.original_size, actual.original_size);
        assert_eq!(expected.compressed_size, actual.compressed_size);
        assert_eq!(expected.chunk_count, actual.chunk_count);
    }

    #[test]
    fn test_prepared_block_exact_sealed_len_for_supported_codecs() {
        use era_codec::{LZ4Compressor, NoCompressor, ZstdCompressor};

        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let compressors: Vec<Box<dyn Compressor>> = vec![
            Box::new(NoCompressor),
            Box::new(ZstdCompressor::default()),
            Box::new(LZ4Compressor::default()),
        ];

        for compressor in compressors {
            let algorithm = compressor.algorithm();
            let builder = prepared_test_builder(&session, &volume_key, compressor);
            let chunk = UniqueChunk::new(
                Bytes::from_static(b"prepared block size check"),
                ChunkHash::from_bytes([9u8; 32]),
            );

            let prepared = builder
                .prepare_chunks(std::slice::from_ref(&chunk))
                .unwrap();
            let expected_len = usize::try_from(prepared.compressed_size())
                .unwrap()
                .checked_add(era_crypto::TAG_SIZE)
                .unwrap();
            assert_eq!(prepared.sealed_len(), expected_len, "{algorithm:?}");

            let sealed = builder.seal_prepared(&prepared, 19).unwrap();
            assert_eq!(sealed.data.len(), expected_len, "{algorithm:?}");
            assert_eq!(sealed.block_id, prepared.block_id());
            assert_eq!(sealed.original_size, prepared.original_size());
            assert_eq!(sealed.compressed_size, prepared.compressed_size());
            assert_eq!(sealed.chunk_count, prepared.chunk_count());
        }
    }

    #[test]
    fn test_prepared_empty_padding_block_has_exact_sealed_len() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let builder =
            prepared_test_builder(&session, &volume_key, Box::new(era_codec::NoCompressor));

        let prepared = builder.prepare_chunks(&[]).unwrap();
        assert_eq!(prepared.original_size(), 4);
        assert_eq!(prepared.compressed_size(), 4);
        assert_eq!(prepared.chunk_count(), 0);
        assert_eq!(prepared.sealed_len(), 4 + era_crypto::TAG_SIZE);

        let sealed = builder.seal_prepared(&prepared, 23).unwrap();
        assert_eq!(sealed.data.len(), 4 + era_crypto::TAG_SIZE);
        let unpacker =
            prepared_test_unpacker(&session, &volume_key, Box::new(era_codec::NoCompressor));
        let unpacked = unpacker.unpack(&sealed, 23).unwrap();
        assert_eq!(unpacked.chunk_count(), 0);
    }

    #[test]
    fn test_prepared_block_roundtrips_at_nonzero_volume_sequence() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let builder =
            prepared_test_builder(&session, &volume_key, Box::new(era_codec::NoCompressor));
        let original_data = vec![42u8; 256];
        let chunk = UniqueChunk::new(
            Bytes::from(original_data.clone()),
            ChunkHash::from_bytes([3u8; 32]),
        );

        let prepared = builder
            .prepare_chunks(std::slice::from_ref(&chunk))
            .unwrap();
        let sealed = builder
            .seal_prepared_with_type(&prepared, 37, BlockType::Catalog)
            .unwrap();

        let unpacker =
            prepared_test_unpacker(&session, &volume_key, Box::new(era_codec::NoCompressor));
        let unpacked = unpacker
            .unpack_with_type(&sealed, 37, BlockType::Catalog)
            .unwrap();
        assert_eq!(unpacked.chunk_count(), 1);
        assert_eq!(
            unpacked.get_chunk(0).unwrap().as_ref(),
            original_data.as_slice()
        );
    }

    #[test]
    fn test_prepared_block_rejects_wrong_volume_sequence() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let builder =
            prepared_test_builder(&session, &volume_key, Box::new(era_codec::NoCompressor));
        let chunk = UniqueChunk::new(
            Bytes::from_static(b"volume bound"),
            ChunkHash::from_bytes([4u8; 32]),
        );

        let prepared = builder
            .prepare_chunks(std::slice::from_ref(&chunk))
            .unwrap();
        let sealed = builder.seal_prepared(&prepared, 41).unwrap();

        let unpacker =
            prepared_test_unpacker(&session, &volume_key, Box::new(era_codec::NoCompressor));
        let result = unpacker.unpack(&sealed, 42);
        assert!(matches!(result, Err(era_common::EraError::Decryption(_))));
    }

    #[test]
    fn test_pack_chunks_wrappers_match_prepare_then_seal() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let chunks = vec![UniqueChunk::new(
            Bytes::from_static(b"wrapper compatibility"),
            ChunkHash::from_bytes([5u8; 32]),
        )];

        let direct_data_builder =
            prepared_test_builder(&session, &volume_key, Box::new(era_codec::NoCompressor))
                .with_starting_block_id(41);
        let split_data_builder =
            prepared_test_builder(&session, &volume_key, Box::new(era_codec::NoCompressor))
                .with_starting_block_id(41);
        let direct_data = direct_data_builder.pack_chunks(chunks.clone()).unwrap();
        let prepared_data = split_data_builder.prepare_chunks(&chunks).unwrap();
        let split_data = split_data_builder
            .seal_prepared(&prepared_data, TEST_VOLUME_INDEX)
            .unwrap();
        assert_same_block(&direct_data, &split_data);
        assert_eq!(prepared_data.block_id(), direct_data.block_id);
        assert_eq!(
            direct_data_builder.blocks_created(),
            split_data_builder.blocks_created()
        );

        let direct_typed_builder =
            prepared_test_builder(&session, &volume_key, Box::new(era_codec::NoCompressor))
                .with_starting_block_id(41);
        let split_typed_builder =
            prepared_test_builder(&session, &volume_key, Box::new(era_codec::NoCompressor))
                .with_starting_block_id(41);
        let direct_typed = direct_typed_builder
            .pack_chunks_with_type(chunks.clone(), BlockType::Catalog)
            .unwrap();
        let prepared_typed = split_typed_builder.prepare_chunks(&chunks).unwrap();
        let split_typed = split_typed_builder
            .seal_prepared_with_type(&prepared_typed, TEST_VOLUME_INDEX, BlockType::Catalog)
            .unwrap();
        assert_same_block(&direct_typed, &split_typed);
        assert_eq!(
            direct_typed_builder.blocks_created(),
            split_typed_builder.blocks_created()
        );
    }

    #[test]
    fn test_starting_block_id() {
        let (session, _salt) = test_session();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

        let builder = SessionBlockBuilder::new(
            &session,
            &volume_key,
            TEST_NONCE_CONTEXT,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            TEST_VOLUME_INDEX,
            crate::create_compressor(),
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
