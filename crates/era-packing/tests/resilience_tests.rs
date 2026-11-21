//! Comprehensive resilience tests for AEAD recovery under corruption
//!
//! These tests validate the bulletproof AEAD recovery pipeline that handles
//! corrupted/missing shards gracefully through Reed-Solomon reconstruction.

#[cfg(test)]
mod aead_resilience {
    use bytes::Bytes;
    use era_codec::ZstdCompressor;
    use era_common::{ChunkHash, ErasureCodeConfig, UniqueChunk};
    use era_crypto::{KdfParams, Salt};
    use era_packing::SessionErasureBlockBuilder;

    /// Helper: Create test data chunk
    fn test_chunk(id: u8, size: usize) -> UniqueChunk {
        let data = vec![id; size];
        UniqueChunk {
            hash: ChunkHash::from_bytes([id; 32]),
            data: Bytes::from(data),
        }
    }

    /// Helper: Generate test key and session
    fn test_setup() -> (era_crypto::KeySession, era_crypto::VolumeKey, [u8; 16]) {
        let salt = Salt::generate();
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let session = era_crypto::KeySession::new(b"test_password", &salt, &params).unwrap();
        let volume_key = session.generate_and_wrap_volume_key().unwrap().0;
        let nonce_context = [42u8; 16];
        (session, volume_key, nonce_context)
    }

    const TEST_ARCHIVE_ID: [u8; 16] = [0x42u8; 16];
    const TEST_EPOCH_ID: u32 = 1;
    const TEST_VOLUME_INDEX: u32 = 0;

    #[test]
    fn test_resilient_unpacker_exists() {
        use era_common::VerifiedShard;
        use era_packing::{ResilientBlockUnpacker, SessionBlockUnpacker};

        let (session, volume_key, nonce_context) = test_setup();
        let builder = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            nonce_context,
            era_packing::BlockContext {
                archive_id: TEST_ARCHIVE_ID,
                epoch_id: TEST_EPOCH_ID,
                volume_index: TEST_VOLUME_INDEX,
            },
            Box::new(ZstdCompressor::default()),
            ErasureCodeConfig::new(4, 2),
        )
        .unwrap();

        let mut x = 0x1234_5678u32;
        let payload: Vec<u8> = (0..1024)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 16) as u8
            })
            .collect();
        let chunk = UniqueChunk {
            hash: ChunkHash::from_bytes([7; 32]),
            data: Bytes::from(payload),
        };
        let expected_hash = chunk.hash;
        let expected_data = chunk.data.clone();
        let sharded = builder.pack_chunks(vec![chunk]).unwrap();

        let session_unpacker = SessionBlockUnpacker::new(
            &session,
            &volume_key,
            nonce_context,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            Box::new(ZstdCompressor::default()),
        );
        let resilient = ResilientBlockUnpacker::new(&session_unpacker);

        let erasure_info = era_common::ErasureBlockInfo {
            data_shards: 4,
            parity_shards: 2,
            original_len: sharded.original_len,
            shard_size: 0,
        };

        // Corrupt shard 0 with an erased zero pattern and exercise unpack_resilient heuristic recovery.
        let mut erased_shards: Vec<(usize, Bytes)> = sharded
            .shards
            .iter()
            .enumerate()
            .map(|(idx, data)| (idx, data.clone()))
            .collect();
        erased_shards[0].1 = Bytes::from(vec![0u8; erased_shards[0].1.len()]);
        let (recovered, corrupted) = resilient
            .unpack_resilient(
                erased_shards,
                &erasure_info,
                sharded.block_id,
                TEST_VOLUME_INDEX,
            )
            .unwrap();
        assert_eq!(corrupted, vec![0]);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].0, expected_hash);
        assert_eq!(recovered[0].1, expected_data);

        // Also exercise unpack_resilient_verified with an explicit CRC-failed bitflip on shard 1.
        let verified_shards: Vec<VerifiedShard> = sharded
            .shards
            .iter()
            .enumerate()
            .map(|(idx, data)| {
                let expected_crc = era_common::compute_shard_crc(data);
                if idx == 1 {
                    let mut bad = data.to_vec();
                    bad[0] ^= 0xFF;
                    VerifiedShard {
                        index: idx,
                        expected_crc,
                        crc_valid: false,
                        data: Bytes::from(bad),
                    }
                } else {
                    VerifiedShard {
                        index: idx,
                        expected_crc,
                        crc_valid: true,
                        data: data.clone(),
                    }
                }
            })
            .collect();
        let (verified_recovered, verified_corrupted) = resilient
            .unpack_resilient_verified(
                verified_shards,
                &erasure_info,
                sharded.block_id,
                TEST_VOLUME_INDEX,
            )
            .unwrap();
        assert_eq!(verified_corrupted, vec![1]);
        assert_eq!(verified_recovered.len(), 1);
        assert_eq!(verified_recovered[0].0, expected_hash);
        assert_eq!(verified_recovered[0].1, expected_data);
    }

    #[test]
    fn test_non_corrupted_block_basic_extraction() {
        // Validates that uncorrupted blocks can be packed and unpacked with erasure
        let (session, volume_key, nonce_context) = test_setup();

        let builder = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            nonce_context,
            era_packing::BlockContext {
                archive_id: TEST_ARCHIVE_ID,
                epoch_id: TEST_EPOCH_ID,
                volume_index: TEST_VOLUME_INDEX,
            },
            Box::new(ZstdCompressor::default()),
            ErasureCodeConfig::new(4, 2),
        )
        .unwrap();

        // Pack chunks into a block
        let chunks = vec![test_chunk(1, 1024), test_chunk(2, 1024)];

        let sharded = builder.pack_chunks(chunks).unwrap();

        // Create unpacker
        let unpacker = era_packing::SessionErasureBlockUnpacker::new(
            &session,
            &volume_key,
            nonce_context,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            Box::new(ZstdCompressor::default()),
        );

        // Verify shards were created
        assert_eq!(sharded.shards.len(), 6); // 4 data + 2 parity
        assert!(sharded.original_len > 0);

        // Unpack without any shard loss
        let extracted = unpacker
            .decode_and_extract_all(
                sharded
                    .shards
                    .iter()
                    .enumerate()
                    .map(|(idx, data)| (idx, data.clone()))
                    .collect(),
                &era_common::ErasureBlockInfo {
                    data_shards: 4,
                    parity_shards: 2,
                    original_len: sharded.original_len,
                    shard_size: 0,
                },
                sharded.block_id,
                TEST_VOLUME_INDEX,
            )
            .unwrap();

        // Should extract all chunks
        assert_eq!(extracted.len(), 2);
    }

    #[test]
    fn test_erasure_recovery_single_shard_loss() {
        // When a complete shard is missing, RS recovery should reconstruct it
        let (session, volume_key, nonce_context) = test_setup();

        let builder = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            nonce_context,
            era_packing::BlockContext {
                archive_id: TEST_ARCHIVE_ID,
                epoch_id: TEST_EPOCH_ID,
                volume_index: TEST_VOLUME_INDEX,
            },
            Box::new(ZstdCompressor::default()),
            ErasureCodeConfig::new(4, 2),
        )
        .unwrap();

        let chunks = vec![test_chunk(1, 2048)];
        let sharded = builder.pack_chunks(chunks).unwrap();

        // Simulate shard loss: keep all but one data shard (can recover with 2 parity)
        let available_shards: Vec<(usize, Bytes)> = sharded
            .shards
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != 5) // Remove parity shard 5
            .map(|(idx, data)| (idx, data.clone()))
            .collect();

        assert_eq!(available_shards.len(), 5); // 4 data + 1 parity

        let unpacker = era_packing::SessionErasureBlockUnpacker::new(
            &session,
            &volume_key,
            nonce_context,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            Box::new(ZstdCompressor::default()),
        );

        let extracted = unpacker
            .decode_and_extract_all(
                available_shards,
                &era_common::ErasureBlockInfo {
                    data_shards: 4,
                    parity_shards: 2,
                    original_len: sharded.original_len,
                    shard_size: 0,
                },
                sharded.block_id,
                TEST_VOLUME_INDEX,
            )
            .unwrap();

        // Should recover successfully from one missing parity shard
        assert_eq!(extracted.len(), 1);
    }

    #[test]
    fn test_failure_insufficient_shards() {
        // When too many shards are lost, should fail gracefully
        let (session, volume_key, nonce_context) = test_setup();

        let builder = SessionErasureBlockBuilder::new(
            &session,
            &volume_key,
            nonce_context,
            era_packing::BlockContext {
                archive_id: TEST_ARCHIVE_ID,
                epoch_id: TEST_EPOCH_ID,
                volume_index: TEST_VOLUME_INDEX,
            },
            Box::new(ZstdCompressor::default()),
            ErasureCodeConfig::new(4, 2), // Can recover from 2 shard losses max
        )
        .unwrap();

        let chunks = vec![test_chunk(1, 1024)];
        let sharded = builder.pack_chunks(chunks).unwrap();

        // Keep only 3 shards (need 4 to decode)
        let available_shards: Vec<(usize, Bytes)> = sharded
            .shards
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx < 3)
            .map(|(idx, data)| (idx, data.clone()))
            .collect();

        let unpacker = era_packing::SessionErasureBlockUnpacker::new(
            &session,
            &volume_key,
            nonce_context,
            TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            Box::new(ZstdCompressor::default()),
        );

        let result = unpacker.decode_and_extract_all(
            available_shards,
            &era_common::ErasureBlockInfo {
                data_shards: 4,
                parity_shards: 2,
                original_len: sharded.original_len,
                shard_size: 0,
            },
            sharded.block_id,
            TEST_VOLUME_INDEX,
        );

        // Should fail with ErasureError
        assert!(
            result.is_err(),
            "Should fail when insufficient shards available"
        );
    }
}
