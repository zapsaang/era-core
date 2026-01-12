//! MacroBlock builder - packs chunks into encrypted blocks.

use bytes::{BufMut, BytesMut};
use era_codec::Compressor;
use era_common::{
    BlockChunkIndex, BlockId, ChunkIndexEntry, EncryptedMacroBlock, Result, UniqueChunk,
};
use era_crypto::DerivedKey;
use std::sync::atomic::{AtomicU64, Ordering};

/// Builder for creating MacroBlocks from chunks
pub struct MacroBlockBuilder {
    /// Target block size (default 4MB)
    target_size: usize,
    /// Compressor to use
    compressor: Box<dyn Compressor>,
    /// Encryption key
    key: DerivedKey,
    /// Nonce context (must be unique per archive, e.g., salt)
    nonce_context: [u8; 16],
    /// Next block ID
    next_block_id: AtomicU64,
}

impl MacroBlockBuilder {
    /// Create a new builder with the given key and nonce context
    ///
    /// # Arguments
    /// * `key` - The derived encryption key
    /// * `nonce_context` - A unique 16-byte context for nonce derivation (e.g., archive salt)
    /// * `compressor` - The compressor to use
    ///
    /// # Security
    /// The nonce_context MUST be unique per archive to prevent nonce reuse.
    /// Typically, use the archive's salt as the nonce context.
    pub fn new(key: DerivedKey, nonce_context: [u8; 16], compressor: Box<dyn Compressor>) -> Self {
        Self {
            target_size: 4 * 1024 * 1024, // 4MB
            compressor,
            key,
            nonce_context,
            next_block_id: AtomicU64::new(0),
        }
    }

    /// Set the target block size
    pub fn with_target_size(mut self, size: usize) -> Self {
        self.target_size = size;
        self
    }

    /// Pack a single chunk into a MacroBlock
    ///
    /// For MVP, each chunk becomes its own block. In later versions,
    /// multiple chunks will be packed together using k-Bounded Best-Fit.
    pub fn pack_single(&self, chunk: UniqueChunk) -> Result<EncryptedMacroBlock> {
        let chunks = vec![chunk];
        self.pack_chunks(chunks)
    }

    /// Pack multiple chunks into a single MacroBlock
    pub fn pack_chunks(&self, chunks: Vec<UniqueChunk>) -> Result<EncryptedMacroBlock> {
        let block_id = BlockId::new(self.next_block_id.fetch_add(1, Ordering::SeqCst));

        // Build chunk index
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

        // Serialize: [index_length(4) | index_data | chunk_data]
        let index_bytes = era_common::serialize(&chunk_index)?;
        let original_size = 4 + index_bytes.len() + data.len();

        let mut full_data = BytesMut::with_capacity(original_size);
        full_data.put_u32_le(index_bytes.len() as u32);
        full_data.put_slice(&index_bytes);
        full_data.put_slice(&data);

        // Compress
        let compressed = self.compressor.compress(&full_data)?;
        let compressed_size = compressed.len();

        // Encrypt with nonce context for safety
        let encrypted = era_crypto::encrypt_with_context(
            &self.key,
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

    /// Get statistics about the builder
    pub fn blocks_created(&self) -> u64 {
        self.next_block_id.load(Ordering::SeqCst)
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

    const TEST_NONCE_CONTEXT: [u8; 16] = [42u8; 16];

    #[test]
    fn test_pack_single_chunk() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key, TEST_NONCE_CONTEXT, compressor);

        let chunk = UniqueChunk::new(
            Bytes::from(vec![42u8; 1024]),
            ChunkHash::from_bytes([1u8; 32]),
        );

        let block = builder.pack_single(chunk).unwrap();
        assert_eq!(block.block_id.sequence(), 0);
        assert_eq!(block.chunk_count, 1);
        assert!(!block.data.is_empty());
    }

    #[test]
    fn test_pack_multiple_chunks() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key, TEST_NONCE_CONTEXT, compressor);

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
    }

    #[test]
    fn test_block_id_increment() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key, TEST_NONCE_CONTEXT, compressor);

        let chunk1 = UniqueChunk::new(Bytes::from(vec![1u8; 64]), ChunkHash::from_bytes([1u8; 32]));
        let chunk2 = UniqueChunk::new(Bytes::from(vec![2u8; 64]), ChunkHash::from_bytes([2u8; 32]));

        let block1 = builder.pack_single(chunk1).unwrap();
        let block2 = builder.pack_single(chunk2).unwrap();

        assert_eq!(block1.block_id.sequence(), 0);
        assert_eq!(block2.block_id.sequence(), 1);
        assert_eq!(builder.blocks_created(), 2);
    }

    #[test]
    fn test_empty_chunk() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key, TEST_NONCE_CONTEXT, compressor);

        // Empty data should still work
        let chunk = UniqueChunk::new(Bytes::from(vec![]), ChunkHash::from_bytes([0u8; 32]));

        let block = builder.pack_single(chunk).unwrap();
        assert_eq!(block.chunk_count, 1);
    }

    #[test]
    fn test_large_chunk() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key, TEST_NONCE_CONTEXT, compressor);

        // 1MB chunk
        let data = vec![0u8; 1024 * 1024];
        let chunk = UniqueChunk::new(Bytes::from(data), ChunkHash::from_bytes([42u8; 32]));

        let block = builder.pack_single(chunk).unwrap();
        assert_eq!(block.chunk_count, 1);
        // Compressed size should be much smaller for uniform data
        assert!(block.compressed_size < block.original_size);
    }

    #[test]
    fn test_with_target_size() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key, TEST_NONCE_CONTEXT, compressor)
            .with_target_size(1024 * 1024); // 1MB

        let chunk = UniqueChunk::new(
            Bytes::from(vec![1u8; 100]),
            ChunkHash::from_bytes([1u8; 32]),
        );

        let block = builder.pack_single(chunk).unwrap();
        assert!(!block.data.is_empty());
    }

    #[test]
    fn test_different_nonce_context_different_encryption() {
        let key = test_key();

        let compressor1 = Box::new(ZstdCompressor::default());
        let builder1 = MacroBlockBuilder::new(key.clone(), [1u8; 16], compressor1);

        let compressor2 = Box::new(ZstdCompressor::default());
        let builder2 = MacroBlockBuilder::new(key.clone(), [2u8; 16], compressor2);

        let chunk_data = vec![42u8; 256];
        let chunk1 = UniqueChunk::new(
            Bytes::from(chunk_data.clone()),
            ChunkHash::from_bytes([1u8; 32]),
        );
        let chunk2 = UniqueChunk::new(Bytes::from(chunk_data), ChunkHash::from_bytes([1u8; 32]));

        let block1 = builder1.pack_single(chunk1).unwrap();
        let block2 = builder2.pack_single(chunk2).unwrap();

        // Different nonce contexts should produce different ciphertext
        assert_ne!(block1.data, block2.data);
    }

    #[test]
    fn test_high_entropy_data() {
        let key = test_key();
        let compressor = Box::new(ZstdCompressor::default());
        let builder = MacroBlockBuilder::new(key, TEST_NONCE_CONTEXT, compressor);

        // Create high-entropy data (hard to compress)
        let mut data = vec![0u8; 4096];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i * 31 + i / 7) as u8;
        }

        let chunk = UniqueChunk::new(Bytes::from(data), ChunkHash::from_bytes([99u8; 32]));

        let block = builder.pack_single(chunk).unwrap();
        assert_eq!(block.chunk_count, 1);
        // High entropy data won't compress well
        assert!(block.compressed_size > 0);
    }
}
