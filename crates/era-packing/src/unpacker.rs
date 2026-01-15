//! MacroBlock unpacker - extracts chunks from encrypted blocks.

use bytes::Bytes;
use era_codec::Compressor;
use era_common::{BlockChunkIndex, BlockId, ChunkHash, ChunkVec, EncryptedMacroBlock, Result};
use era_crypto::DerivedKey;

use crate::block_codec;

/// Unpacker for extracting chunks from MacroBlocks
pub struct MacroBlockUnpacker {
    /// Compressor for decompression
    compressor: Box<dyn Compressor>,
    /// Decryption key
    key: DerivedKey,
    /// Nonce context (must match the one used during encryption)
    nonce_context: [u8; 16],
}

impl MacroBlockUnpacker {
    /// Create a new unpacker with the given key and nonce context
    ///
    /// # Arguments
    /// * `key` - The derived decryption key
    /// * `nonce_context` - The 16-byte context used during encryption (e.g., archive salt)
    /// * `compressor` - The compressor to use for decompression
    pub fn new(key: DerivedKey, nonce_context: [u8; 16], compressor: Box<dyn Compressor>) -> Self {
        Self {
            compressor,
            key,
            nonce_context,
        }
    }

    /// Decrypt and decompress a MacroBlock, returning raw data and index
    pub fn unpack(&self, block: &EncryptedMacroBlock) -> Result<UnpackedBlock> {
        let (index, data) = block_codec::decrypt_and_decompress(
            &self.key,
            &self.nonce_context,
            block.block_id,
            &block.data,
            self.compressor.as_ref(),
        )?;

        Ok(UnpackedBlock {
            block_id: block.block_id,
            index,
            data,
        })
    }

    /// Extract a specific chunk from a block by its hash
    pub fn extract_chunk(
        &self,
        block: &EncryptedMacroBlock,
        chunk_hash: &ChunkHash,
    ) -> Result<Option<Bytes>> {
        let unpacked = self.unpack(block)?;
        block_codec::extract_chunk_by_hash(&unpacked.index, &unpacked.data, chunk_hash)
    }

    /// Extract all chunks from a block
    ///
    /// Returns a ChunkVec (SmallVec) which avoids heap allocation for blocks
    /// with up to 16 chunks. This provides significant performance improvement
    /// for extraction operations.
    pub fn extract_all_chunks(&self, block: &EncryptedMacroBlock) -> Result<ChunkVec> {
        let unpacked = self.unpack(block)?;
        block_codec::extract_all_chunks(&unpacked.index, &unpacked.data)
    }
}

/// An unpacked MacroBlock with parsed index
pub struct UnpackedBlock {
    /// Block ID
    pub block_id: BlockId,
    /// Chunk index
    pub index: BlockChunkIndex,
    /// Raw chunk data
    pub data: Bytes,
}

impl UnpackedBlock {
    /// Get the number of chunks in this block
    pub fn chunk_count(&self) -> usize {
        self.index.entries.len()
    }

    /// Get a chunk by its index position
    pub fn get_chunk(&self, idx: usize) -> Option<Bytes> {
        self.index.entries.get(idx).map(|entry| {
            let start = entry.offset as usize;
            let end = start + entry.length as usize;
            self.data.slice(start..end)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MacroBlockBuilder;
    use era_codec::ZstdCompressor;
    use era_common::UniqueChunk;
    use era_crypto::{derive_key, KdfParams, Salt};

    /// Test nonce context (must match the one used in builder tests)
    const TEST_NONCE_CONTEXT: [u8; 16] = [42u8; 16];

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
    fn test_pack_unpack_roundtrip() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key.clone(), TEST_NONCE_CONTEXT, compressor);

        let original_data = vec![42u8; 1024];
        let chunk_hash = era_crypto::hash(&original_data);
        let chunk = UniqueChunk::new(Bytes::from(original_data.clone()), chunk_hash);

        let encrypted = builder.pack_single(chunk).unwrap();

        // Unpack with same nonce context
        let unpacker =
            MacroBlockUnpacker::new(key, TEST_NONCE_CONTEXT, Box::new(ZstdCompressor::default()));
        let unpacked = unpacker.unpack(&encrypted).unwrap();

        assert_eq!(unpacked.chunk_count(), 1);
        let extracted = unpacked.get_chunk(0).unwrap();
        assert_eq!(extracted.as_ref(), &original_data);
    }

    #[test]
    fn test_extract_chunk_by_hash() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key.clone(), TEST_NONCE_CONTEXT, compressor);

        let data1 = vec![1u8; 256];
        let data2 = vec![2u8; 256];
        let hash1 = era_crypto::hash(&data1);
        let hash2 = era_crypto::hash(&data2);

        let chunks = vec![
            UniqueChunk::new(Bytes::from(data1.clone()), hash1),
            UniqueChunk::new(Bytes::from(data2.clone()), hash2),
        ];

        let encrypted = builder.pack_chunks(chunks).unwrap();

        let unpacker =
            MacroBlockUnpacker::new(key, TEST_NONCE_CONTEXT, Box::new(ZstdCompressor::default()));

        // Extract by hash
        let extracted1 = unpacker.extract_chunk(&encrypted, &hash1).unwrap().unwrap();
        assert_eq!(extracted1.as_ref(), &data1);

        let extracted2 = unpacker.extract_chunk(&encrypted, &hash2).unwrap().unwrap();
        assert_eq!(extracted2.as_ref(), &data2);

        // Non-existent hash
        let fake_hash = ChunkHash::from_bytes([99u8; 32]);
        let not_found = unpacker.extract_chunk(&encrypted, &fake_hash).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_corrupted_block_detection() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key.clone(), TEST_NONCE_CONTEXT, compressor);

        let original_data = vec![42u8; 1024];
        let chunk_hash = era_crypto::hash(&original_data);
        let chunk = UniqueChunk::new(Bytes::from(original_data), chunk_hash);

        let mut encrypted = builder.pack_single(chunk).unwrap();

        // Tamper with the encrypted data (flip a bit)
        if !encrypted.data.is_empty() {
            let mut tampered = encrypted.data.to_vec();
            let mid = tampered.len() / 2;
            tampered[mid] ^= 0xFF;
            encrypted.data = Bytes::from(tampered);
        }

        // Unpack should fail due to authentication failure
        let unpacker =
            MacroBlockUnpacker::new(key, TEST_NONCE_CONTEXT, Box::new(ZstdCompressor::default()));
        let result = unpacker.unpack(&encrypted);

        assert!(result.is_err(), "Tampered block should fail decryption");
    }

    #[test]
    fn test_wrong_key_detection() {
        let key1 = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key1.clone(), TEST_NONCE_CONTEXT, compressor);

        let original_data = vec![42u8; 1024];
        let chunk_hash = era_crypto::hash(&original_data);
        let chunk = UniqueChunk::new(Bytes::from(original_data), chunk_hash);

        let encrypted = builder.pack_single(chunk).unwrap();

        // Try to decrypt with a different key
        let salt2 = Salt::from_bytes([1u8; 16]);
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let key2 = derive_key(b"wrong_password", &salt2, &params).unwrap();

        let unpacker = MacroBlockUnpacker::new(
            key2,
            TEST_NONCE_CONTEXT,
            Box::new(ZstdCompressor::default()),
        );
        let result = unpacker.unpack(&encrypted);

        assert!(result.is_err(), "Wrong key should fail decryption");
    }

    #[test]
    fn test_wrong_nonce_context_detection() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key.clone(), TEST_NONCE_CONTEXT, compressor);

        let original_data = vec![42u8; 1024];
        let chunk_hash = era_crypto::hash(&original_data);
        let chunk = UniqueChunk::new(Bytes::from(original_data), chunk_hash);

        let encrypted = builder.pack_single(chunk).unwrap();

        // Try to decrypt with a different nonce context
        let wrong_context = [99u8; 16];
        let unpacker =
            MacroBlockUnpacker::new(key, wrong_context, Box::new(ZstdCompressor::default()));
        let result = unpacker.unpack(&encrypted);

        assert!(
            result.is_err(),
            "Wrong nonce context should fail decryption"
        );
    }

    #[test]
    fn test_truncated_block_detection() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key.clone(), TEST_NONCE_CONTEXT, compressor);

        let original_data = vec![42u8; 1024];
        let chunk_hash = era_crypto::hash(&original_data);
        let chunk = UniqueChunk::new(Bytes::from(original_data), chunk_hash);

        let mut encrypted = builder.pack_single(chunk).unwrap();

        // Truncate the block
        let truncated = encrypted.data[..encrypted.data.len() / 2].to_vec();
        encrypted.data = Bytes::from(truncated);

        let unpacker =
            MacroBlockUnpacker::new(key, TEST_NONCE_CONTEXT, Box::new(ZstdCompressor::default()));
        let result = unpacker.unpack(&encrypted);

        assert!(result.is_err(), "Truncated block should fail");
    }
}
