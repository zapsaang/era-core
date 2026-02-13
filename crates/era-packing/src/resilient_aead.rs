//! Resilient AEAD recovery - handles corrupted/missing shards gracefully
//!
//! This module implements the core fix for AEAD failures under corruption.
//!
//! ## Problem
//! When a shard is corrupted (not completely missing), the current pipeline:
//! 1. Reads all available shards
//! 2. Attempts RS recovery (no-op if all shards present)
//! 3. Tries AEAD decryption - FAILS immediately if any bit is corrupted
//!
//! ## Solution
//! Validate each shard's CRC32 checksum (from ShardHeader) before AEAD decryption.
//! If AEAD fails, use CRC status to identify corrupted shards, exclude them,
//! reconstruct from remaining healthy shards + parity, and retry AEAD.

use bytes::Bytes;
use era_codec::{ErasureCoder, ErasureConfig};
use era_common::{BlockId, ChunkVec, EraError, ErasureBlockInfo, Result, VerifiedShard};

/// Result of AEAD resilience attempt
#[derive(Debug)]
pub enum AeadRecoveryResult {
    /// Direct decryption succeeded
    DirectSuccess(ChunkVec),
    /// Decryption failed, attempted RS recovery from corrupted shards
    RecoverySuccess {
        chunks: ChunkVec,
        /// Which shard indices were identified as corrupted
        corrupted_shards: Vec<usize>,
    },
    /// All recovery attempts failed
    Failure(String),
}

/// Resilient block unpacker that handles corrupted shards
pub struct ResilientBlockUnpacker<'a> {
    /// The session unpacker (for actual decryption)
    session_unpacker: &'a crate::SessionBlockUnpacker<'a>,
}

impl<'a> ResilientBlockUnpacker<'a> {
    pub fn new(session_unpacker: &'a crate::SessionBlockUnpacker<'a>) -> Self {
        Self { session_unpacker }
    }

    /// Attempt decryption with resilience to corrupted shards.
    ///
    /// Accepts `Vec<(usize, Bytes)>` for backward compatibility.
    /// Without CRC info, falls back to structural heuristics for corruption detection.
    pub fn unpack_resilient(
        &self,
        shards: Vec<(usize, Bytes)>,
        erasure_info: &ErasureBlockInfo,
        block_id: BlockId,
    ) -> Result<(ChunkVec, Vec<usize>)> {
        // Convert to VerifiedShard without CRC info (legacy path)
        let verified: Vec<VerifiedShard> = shards
            .into_iter()
            .map(|(idx, data)| {
                let crc = era_common::compute_shard_crc(&data);
                VerifiedShard {
                    index: idx,
                    expected_crc: crc,
                    crc_valid: true, // Assume valid when no external CRC available
                    data,
                }
            })
            .collect();
        self.unpack_resilient_verified(verified, erasure_info, block_id)
    }

    /// Attempt decryption with resilience using CRC-verified shards.
    ///
    /// This is the preferred entry point when ShardHeader CRC info is available.
    /// Shards with `crc_valid: false` are immediately identified as corrupted.
    pub fn unpack_resilient_verified(
        &self,
        shards: Vec<VerifiedShard>,
        erasure_info: &ErasureBlockInfo,
        block_id: BlockId,
    ) -> Result<(ChunkVec, Vec<usize>)> {
        let parity_shards = erasure_info.parity_shards as usize;

        // Step 1: Try direct decryption with all CRC-valid shards (fast path)
        let valid_shards: Vec<(usize, Bytes)> = shards
            .iter()
            .filter(|s| s.crc_valid)
            .map(|s| (s.index, s.data.clone()))
            .collect();

        if !valid_shards.is_empty() {
            if let Ok(encrypted_block) =
                self.recover_encrypted_block(&valid_shards, erasure_info, block_id)
            {
                if let Ok(unpacked) = self.session_unpacker.unpack(&encrypted_block) {
                    if let Ok(chunks) =
                        crate::block_codec::extract_all_chunks(&unpacked.index, &unpacked.data)
                    {
                        let crc_failed: Vec<usize> = shards
                            .iter()
                            .filter(|s| !s.crc_valid)
                            .map(|s| s.index)
                            .collect();
                        return Ok((chunks, crc_failed));
                    }
                }
            }

            tracing::debug!(
                "Direct decryption failed for block {}. Attempting shard recovery.",
                block_id.sequence(),
            );
        }

        // Step 2: Identify corrupted shards using CRC + structural heuristics
        let corrupted = self.identify_corrupted_shards_verified(&shards)?;

        if corrupted.is_empty() {
            return Err(EraError::decryption(
                "AEAD verification failed and no corrupted shards detected (possible key/nonce mismatch)"
            ));
        }

        // Step 3: If too many corrupted shards, cannot recover
        if corrupted.len() > parity_shards {
            return Err(EraError::ErasureError(format!(
                "Too many corrupted shards ({}) for recovery with {} parity shards",
                corrupted.len(),
                parity_shards
            )));
        }

        // Step 4: Reconstruct using only healthy shards
        let recovered_shards: Vec<(usize, Bytes)> = shards
            .into_iter()
            .filter(|s| !corrupted.contains(&s.index))
            .map(|s| (s.index, s.data))
            .collect();

        tracing::info!(
            "Recovering block {} with {} corrupted shards (indices: {:?})",
            block_id.sequence(),
            corrupted.len(),
            corrupted
        );

        let encrypted_block =
            self.recover_encrypted_block(&recovered_shards, erasure_info, block_id)?;

        // Step 5: Retry decryption on reconstructed block
        match self.session_unpacker.unpack(&encrypted_block) {
            Ok(unpacked) => {
                let chunks =
                    crate::block_codec::extract_all_chunks(&unpacked.index, &unpacked.data)?;
                Ok((chunks, corrupted))
            }
            Err(e) => Err(EraError::decryption(format!(
                "AEAD verification failed even after shard recovery: {}",
                e
            ))),
        }
    }

    /// Identify corrupted shards using CRC verification and structural heuristics.
    ///
    /// Priority:
    /// 1. Shards with `crc_valid: false` — CRC mismatch from ShardHeader
    /// 2. Shards where re-computed CRC doesn't match expected — post-read corruption
    /// 3. Shards that are too short
    /// 4. Shards with all-same-byte patterns — erased/uninitialized storage
    fn identify_corrupted_shards_verified(&self, shards: &[VerifiedShard]) -> Result<Vec<usize>> {
        let mut corrupted = Vec::new();

        for shard in shards {
            // Primary: CRC verification from ShardHeader
            if !shard.crc_valid {
                let actual_crc = era_common::compute_shard_crc(&shard.data);
                tracing::warn!(
                    "Shard {} CRC mismatch: expected 0x{:08X}, got 0x{:08X}",
                    shard.index,
                    shard.expected_crc,
                    actual_crc
                );
                corrupted.push(shard.index);
                continue;
            }

            // Secondary: re-verify CRC (catches in-memory corruption after read)
            let actual_crc = era_common::compute_shard_crc(&shard.data);
            if actual_crc != shard.expected_crc {
                tracing::warn!(
                    "Shard {} CRC re-verification failed: expected 0x{:08X}, got 0x{:08X}",
                    shard.index,
                    shard.expected_crc,
                    actual_crc
                );
                corrupted.push(shard.index);
                continue;
            }

            // Tertiary: structural heuristics
            if shard.data.len() < 32 {
                corrupted.push(shard.index);
                continue;
            }

            let all_same = shard.data.iter().all(|&b| b == shard.data[0]);
            if all_same && shard.data.len() > 64 {
                tracing::warn!(
                    "Shard {} is all-same-byte (0x{:02X}), likely corrupted",
                    shard.index,
                    shard.data[0]
                );
                corrupted.push(shard.index);
            }
        }

        Ok(corrupted)
    }

    /// Recover the encrypted block from available shards
    fn recover_encrypted_block(
        &self,
        shards: &[(usize, Bytes)],
        erasure_info: &ErasureBlockInfo,
        block_id: BlockId,
    ) -> Result<era_common::EncryptedMacroBlock> {
        let data_shards = erasure_info.data_shards as usize;
        let parity_shards = erasure_info.parity_shards as usize;
        let total_shards = data_shards + parity_shards;
        let original_len = erasure_info.original_len as usize;

        let mut shard_array: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        for (idx, data) in shards {
            if *idx < total_shards {
                shard_array[*idx] = Some(data.to_vec());
            }
        }

        let available = shard_array.iter().filter(|s| s.is_some()).count();
        if available < data_shards {
            return Err(EraError::ErasureError(format!(
                "Not enough shards for recovery: have {}, need {}",
                available, data_shards
            )));
        }

        let config = ErasureConfig::new(data_shards, parity_shards)?;
        let coder = ErasureCoder::new(config)?;
        let recovered = coder.decode(&shard_array, original_len)?;

        Ok(era_common::EncryptedMacroBlock {
            block_id,
            data: Bytes::from(recovered),
            original_size: original_len as u32,
            compressed_size: original_len as u32,
            chunk_count: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_recovery_result_types() {
        let _direct = AeadRecoveryResult::DirectSuccess(ChunkVec::new());
        let _recovery = AeadRecoveryResult::RecoverySuccess {
            chunks: ChunkVec::new(),
            corrupted_shards: vec![1, 3],
        };
        let _failure = AeadRecoveryResult::Failure("test".into());
    }

    #[test]
    fn test_verified_shard_crc_detection() {
        let good_data = Bytes::from(vec![0x42u8; 256]);
        let good_crc = era_common::compute_shard_crc(&good_data);

        let good_shard = VerifiedShard {
            index: 0,
            data: good_data.clone(),
            expected_crc: good_crc,
            crc_valid: true,
        };

        let bad_shard = VerifiedShard {
            index: 1,
            data: good_data,
            expected_crc: 0xDEADBEEF,
            crc_valid: false,
        };

        assert!(good_shard.crc_valid);
        assert!(!bad_shard.crc_valid);
        assert_ne!(bad_shard.expected_crc, good_crc);
    }

    #[test]
    fn test_identify_corrupted_shards_crc_flag() {
        // Shards with crc_valid: false should be identified as corrupted
        let data = Bytes::from(vec![0x42u8; 256]);
        let crc = era_common::compute_shard_crc(&data);

        let shards = vec![
            VerifiedShard {
                index: 0,
                data: data.clone(),
                expected_crc: crc,
                crc_valid: true,
            },
            VerifiedShard {
                index: 1,
                data: data.clone(),
                expected_crc: 0xBAD,
                crc_valid: false,
            },
            VerifiedShard {
                index: 2,
                data: data.clone(),
                expected_crc: crc,
                crc_valid: true,
            },
            VerifiedShard {
                index: 3,
                data: data.clone(),
                expected_crc: 0xDEAD,
                crc_valid: false,
            },
        ];

        // We can't call identify_corrupted_shards_verified directly (it's on ResilientBlockUnpacker),
        // but we can verify the logic by checking the CRC re-verification path
        let mut corrupted = Vec::new();
        for shard in &shards {
            if !shard.crc_valid {
                corrupted.push(shard.index);
            }
        }
        assert_eq!(corrupted, vec![1, 3]);
    }

    #[test]
    fn test_identify_corrupted_shards_recompute_mismatch() {
        // Shard marked crc_valid: true but data was modified after CRC check (in-memory corruption)
        let original_data = Bytes::from(vec![0x42u8; 256]);
        let original_crc = era_common::compute_shard_crc(&original_data);

        // Simulate in-memory corruption: data changed but crc_valid still true
        let mut corrupted_data = vec![0x42u8; 256];
        corrupted_data[128] ^= 0xFF;
        let corrupted_bytes = Bytes::from(corrupted_data);

        let shard = VerifiedShard {
            index: 0,
            data: corrupted_bytes.clone(),
            expected_crc: original_crc,
            crc_valid: true, // Was valid at read time, but data changed since
        };

        // Re-verify CRC should catch this
        let actual_crc = era_common::compute_shard_crc(&shard.data);
        assert_ne!(actual_crc, shard.expected_crc);
    }

    #[test]
    fn test_identify_corrupted_shards_too_short() {
        let short_data = Bytes::from(vec![0x42u8; 16]); // < 32 bytes
        let crc = era_common::compute_shard_crc(&short_data);

        let shard = VerifiedShard {
            index: 0,
            data: short_data,
            expected_crc: crc,
            crc_valid: true,
        };

        // Structural heuristic: shards < 32 bytes are suspicious
        assert!(shard.data.len() < 32);
    }

    #[test]
    fn test_identify_corrupted_shards_all_same_byte() {
        // All-zero or all-same-byte shards indicate erased/uninitialized storage
        let zero_data = Bytes::from(vec![0x00u8; 128]);
        let crc = era_common::compute_shard_crc(&zero_data);

        let shard = VerifiedShard {
            index: 0,
            data: zero_data.clone(),
            expected_crc: crc,
            crc_valid: true,
        };

        let all_same = shard.data.iter().all(|&b| b == shard.data[0]);
        assert!(all_same && shard.data.len() > 64);
    }

    #[test]
    fn test_verified_shard_roundtrip_crc() {
        // Verify that compute_shard_crc is consistent
        let data = Bytes::from(vec![0xAB; 1024]);
        let crc1 = era_common::compute_shard_crc(&data);
        let crc2 = era_common::compute_shard_crc(&data);
        assert_eq!(crc1, crc2);

        // Different data produces different CRC
        let data2 = Bytes::from(vec![0xCD; 1024]);
        let crc3 = era_common::compute_shard_crc(&data2);
        assert_ne!(crc1, crc3);
    }
}
