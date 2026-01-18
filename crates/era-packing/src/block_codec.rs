//! Block-level codec operations - unified encryption/decryption and compression/decompression.
//!
//! This module consolidates the common pattern of:
//! 1. Encrypt/Decrypt data with context
//! 2. Compress/Decompress the result
//!
//! By unifying these operations, we reduce code duplication across session_builder,
//! unpacker, and erasure variants.

use bytes::Bytes;
use era_codec::Compressor;
use era_common::{BlockChunkIndex, BlockId, EraError, Result};
use era_crypto::DerivedKey;

/// Create a default compressor instance (Zstd with default settings)
///
/// Consolidates the repeated pattern: `Box::new(ZstdCompressor::default())`
pub fn create_compressor() -> Box<dyn Compressor> {
    use era_codec::ZstdCompressor;
    Box::new(ZstdCompressor::default())
}

/// Decrypt and decompress block data with unified error handling.
///
/// This consolidates the repeated pattern:
/// 1. decrypt_with_context()
/// 2. compressor.decompress()
/// 3. Parse 4-byte index length
/// 4. Extract index and data
///
/// # Returns
/// (index, data_bytes)
pub fn decrypt_and_decompress(
    key: &DerivedKey,
    nonce_context: &[u8; 16],
    block_id: BlockId,
    encrypted_data: &[u8],
    compressor: &dyn Compressor,
) -> Result<(BlockChunkIndex, Bytes)> {
    // Decrypt
    let compressed =
        era_crypto::decrypt_with_context(key, nonce_context, block_id, encrypted_data)?;

    // Decompress
    let decompressed = compressor.decompress(&compressed)?;

    // Parse index length prefix
    if decompressed.len() < 4 {
        return Err(EraError::decompression("Block too small"));
    }

    let index_len = u32::from_le_bytes([
        decompressed[0],
        decompressed[1],
        decompressed[2],
        decompressed[3],
    ]) as usize;

    if decompressed.len() < 4 + index_len {
        return Err(EraError::decompression("Index length exceeds block size"));
    }

    // Parse index (Protobuf)
    let index_bytes = &decompressed[4..4 + index_len];
    let proto_index: era_common::proto::BlockChunkIndex =
        era_common::deserialize_proto(index_bytes)?;
    let index: BlockChunkIndex = proto_index.try_into()?;
    let data_start = 4 + index_len;

    // Extract data (zero-copy slice)
    let data = decompressed.slice(data_start..);

    Ok((index, data))
}

/// Extract a chunk from decompressed block data by hash.
///
/// This consolidates the common pattern of:
/// 1. Finding entry by hash
/// 2. Extracting offset/length
/// 3. Bounds checking
/// 4. Returning slice
pub fn extract_chunk_by_hash(
    index: &BlockChunkIndex,
    data: &Bytes,
    chunk_hash: &era_common::ChunkHash,
) -> Result<Option<Bytes>> {
    for entry in &index.entries {
        if &entry.hash == chunk_hash {
            let start = entry.offset as usize;
            let end = start + entry.length as usize;

            if end > data.len() {
                return Err(EraError::decompression("Chunk offset exceeds data size"));
            }

            return Ok(Some(data.slice(start..end)));
        }
    }

    Ok(None)
}

/// Extract all chunks from decompressed block data.
///
/// This consolidates the common pattern of:
/// 1. Iterating entries
/// 2. Extracting offset/length
/// 3. Bounds checking
/// 4. Collecting into ChunkVec
pub fn extract_all_chunks(index: &BlockChunkIndex, data: &Bytes) -> Result<era_common::ChunkVec> {
    let mut chunks = era_common::ChunkVec::new();

    for entry in &index.entries {
        let start = entry.offset as usize;
        let end = start + entry.length as usize;

        if end > data.len() {
            return Err(EraError::decompression("Chunk offset exceeds data size"));
        }

        chunks.push((entry.hash, data.slice(start..end)));
    }

    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::{ChunkHash, ChunkIndexEntry};

    #[test]
    fn test_extract_chunk_by_hash() {
        let hash1 = ChunkHash::from_bytes([1u8; 32]);
        let hash2 = ChunkHash::from_bytes([2u8; 32]);

        let data = Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let index = BlockChunkIndex {
            count: 2,
            entries: vec![
                ChunkIndexEntry {
                    hash: hash1,
                    offset: 0,
                    length: 8,
                },
                ChunkIndexEntry {
                    hash: hash2,
                    offset: 8,
                    length: 8,
                },
            ],
        };

        let result = extract_chunk_by_hash(&index, &data, &hash1).unwrap();
        assert_eq!(result.unwrap().as_ref(), &[1, 2, 3, 4, 5, 6, 7, 8]);

        let result = extract_chunk_by_hash(&index, &data, &hash2).unwrap();
        assert_eq!(result.unwrap().as_ref(), &[9, 10, 11, 12, 13, 14, 15, 16]);

        let fake_hash = ChunkHash::from_bytes([99u8; 32]);
        let result = extract_chunk_by_hash(&index, &data, &fake_hash).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_all_chunks() {
        let hash1 = ChunkHash::from_bytes([1u8; 32]);
        let hash2 = ChunkHash::from_bytes([2u8; 32]);

        let data = Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let index = BlockChunkIndex {
            count: 2,
            entries: vec![
                ChunkIndexEntry {
                    hash: hash1,
                    offset: 0,
                    length: 8,
                },
                ChunkIndexEntry {
                    hash: hash2,
                    offset: 8,
                    length: 8,
                },
            ],
        };

        let chunks = extract_all_chunks(&index, &data).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].1.as_ref(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(chunks[1].1.as_ref(), &[9, 10, 11, 12, 13, 14, 15, 16]);
    }
}
