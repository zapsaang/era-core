use crate::proto;
use crate::{
    ArchiveConfig, BlockConfig, ChunkingConfig, CompressionAlgorithm, CompressionConfig,
    EncryptionAlgorithm, EncryptionConfig, ErasureCodeConfig, MatrixDistributionConfig,
    MatrixDistributionStrategy, NormalizationLevel, PackingConfig, VolumeConfig,
};

impl From<ArchiveConfig> for proto::ArchiveConfig {
    fn from(config: ArchiveConfig) -> Self {
        Self {
            compression: Some(config.compression.into()),
            encryption: Some(config.encryption.into()),
            volume: Some(config.volume.into()),
            block: Some(config.block.into()),
            erasure: config.erasure.map(|e| e.into()),
            distribution: Some(config.distribution.into()),
            chunking: Some(config.chunking.into()),
            packing: Some(config.packing.into()),
        }
    }
}

impl TryFrom<proto::ArchiveConfig> for ArchiveConfig {
    type Error = crate::EraError;
    fn try_from(proto: proto::ArchiveConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            compression: proto
                .compression
                .ok_or_else(|| {
                    crate::EraError::CorruptedHeader("Missing compression config".into())
                })?
                .into(),
            encryption: proto
                .encryption
                .ok_or_else(|| {
                    crate::EraError::CorruptedHeader("Missing encryption config".into())
                })?
                .into(),
            volume: proto
                .volume
                .ok_or_else(|| crate::EraError::CorruptedHeader("Missing volume config".into()))?
                .into(),
            block: proto
                .block
                .ok_or_else(|| crate::EraError::CorruptedHeader("Missing block config".into()))?
                .into(),
            erasure: proto.erasure.map(TryInto::try_into).transpose()?,
            distribution: proto
                .distribution
                .ok_or_else(|| {
                    crate::EraError::CorruptedHeader("Missing distribution config".into())
                })?
                .into(),
            chunking: proto
                .chunking
                .ok_or_else(|| crate::EraError::CorruptedHeader("Missing chunking config".into()))?
                .into(),
            packing: proto
                .packing
                .ok_or_else(|| crate::EraError::CorruptedHeader("Missing packing config".into()))?
                .into(),
        })
    }
}

impl From<CompressionConfig> for proto::CompressionConfig {
    fn from(config: CompressionConfig) -> Self {
        Self {
            algorithm: match config.algorithm {
                CompressionAlgorithm::None => proto::compression_config::Algorithm::None.into(),
                CompressionAlgorithm::Zstd => proto::compression_config::Algorithm::Zstd.into(),
                CompressionAlgorithm::LZ4 => proto::compression_config::Algorithm::Lz4.into(),
            },
            level: config.level,
        }
    }
}

impl From<proto::CompressionConfig> for CompressionConfig {
    fn from(proto: proto::CompressionConfig) -> Self {
        Self {
            algorithm: match proto.algorithm() {
                proto::compression_config::Algorithm::None => CompressionAlgorithm::None,
                proto::compression_config::Algorithm::Zstd => CompressionAlgorithm::Zstd,
                proto::compression_config::Algorithm::Lz4 => CompressionAlgorithm::LZ4,
            },
            level: proto.level,
        }
    }
}

impl From<EncryptionConfig> for proto::EncryptionConfig {
    fn from(config: EncryptionConfig) -> Self {
        Self {
            algorithm: match config.algorithm {
                EncryptionAlgorithm::None => proto::encryption_config::Algorithm::None.into(),
                EncryptionAlgorithm::XChaCha20Poly1305 => {
                    proto::encryption_config::Algorithm::Xchacha20poly1305.into()
                }
            },
            kdf_memory_cost: config.kdf_memory_cost,
            kdf_time_cost: config.kdf_time_cost,
        }
    }
}

impl From<proto::EncryptionConfig> for EncryptionConfig {
    fn from(proto: proto::EncryptionConfig) -> Self {
        Self {
            algorithm: match proto.algorithm() {
                proto::encryption_config::Algorithm::None => EncryptionAlgorithm::None,
                proto::encryption_config::Algorithm::Xchacha20poly1305 => {
                    EncryptionAlgorithm::XChaCha20Poly1305
                }
            },
            kdf_memory_cost: proto.kdf_memory_cost,
            kdf_time_cost: proto.kdf_time_cost,
        }
    }
}

impl From<VolumeConfig> for proto::VolumeConfig {
    fn from(config: VolumeConfig) -> Self {
        Self {
            max_size: config.max_size,
            enable_padding: config.enable_padding,
            naming_template: config.naming_template,
        }
    }
}

impl From<proto::VolumeConfig> for VolumeConfig {
    fn from(proto: proto::VolumeConfig) -> Self {
        Self {
            max_size: proto.max_size,
            enable_padding: proto.enable_padding,
            naming_template: proto.naming_template,
        }
    }
}

impl From<BlockConfig> for proto::BlockConfig {
    fn from(config: BlockConfig) -> Self {
        Self {
            target_size: config.target_size as u32,
        }
    }
}

impl From<proto::BlockConfig> for BlockConfig {
    fn from(proto: proto::BlockConfig) -> Self {
        Self {
            target_size: proto.target_size as usize,
        }
    }
}

impl From<ErasureCodeConfig> for proto::ErasureCodeConfig {
    fn from(config: ErasureCodeConfig) -> Self {
        Self {
            data_shards: config.data_shards as u32,
            parity_shards: config.parity_shards as u32,
        }
    }
}

impl TryFrom<proto::ErasureCodeConfig> for ErasureCodeConfig {
    type Error = crate::EraError;
    fn try_from(proto: proto::ErasureCodeConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            data_shards: u8::try_from(proto.data_shards).map_err(|_| {
                crate::EraError::InvalidConfig("data_shards out of range (max 255)".into())
            })?,
            parity_shards: u8::try_from(proto.parity_shards).map_err(|_| {
                crate::EraError::InvalidConfig("parity_shards out of range (max 255)".into())
            })?,
        })
    }
}

use crate::types::{BlockChunkIndex, BlockLocation, ChunkIndexEntry, ErasureBlockInfo};

impl From<ErasureBlockInfo> for proto::ErasureBlockInfo {
    fn from(info: ErasureBlockInfo) -> Self {
        Self {
            data_shards: info.data_shards as u32,
            parity_shards: info.parity_shards as u32,
            shard_size: info.shard_size,
            original_len: info.original_len,
        }
    }
}

impl TryFrom<proto::ErasureBlockInfo> for ErasureBlockInfo {
    type Error = crate::EraError;
    fn try_from(proto: proto::ErasureBlockInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            data_shards: u8::try_from(proto.data_shards).map_err(|_| {
                crate::EraError::Deserialization(format!(
                    "ErasureBlockInfo data_shards {} exceeds u8 range",
                    proto.data_shards
                ))
            })?,
            parity_shards: u8::try_from(proto.parity_shards).map_err(|_| {
                crate::EraError::Deserialization(format!(
                    "ErasureBlockInfo parity_shards {} exceeds u8 range",
                    proto.parity_shards
                ))
            })?,
            shard_size: proto.shard_size,
            original_len: proto.original_len,
        })
    }
}

impl From<BlockLocation> for proto::BlockLocation {
    fn from(loc: BlockLocation) -> Self {
        match loc.shard_layout {
            crate::types::ShardLayout::Single => Self {
                volume_id: loc.volume_id.0.as_bytes().to_vec(),
                slot_index: loc.slot_index,
                physical_offset: loc.physical_offset,
                encrypted_size: loc.encrypted_size,
                erasure_info: None,
                shard_offsets: Vec::new(),
                shard_volumes: Vec::new(),
            },
            crate::types::ShardLayout::Erasure {
                info,
                shard_offsets,
                shard_volumes,
            } => Self {
                volume_id: loc.volume_id.0.as_bytes().to_vec(),
                slot_index: loc.slot_index,
                physical_offset: loc.physical_offset,
                encrypted_size: loc.encrypted_size,
                erasure_info: Some(info.into()),
                shard_offsets,
                shard_volumes: shard_volumes.into_iter().map(|v| v as u32).collect(),
            },
        }
    }
}

impl TryFrom<proto::BlockLocation> for BlockLocation {
    type Error = crate::EraError;
    fn try_from(proto: proto::BlockLocation) -> Result<Self, Self::Error> {
        let volume_id_bytes: [u8; 16] = proto.volume_id.try_into().map_err(|_| {
            crate::EraError::Deserialization("Invalid volume ID length".to_string())
        })?;
        let uuid = uuid::Uuid::from_bytes(volume_id_bytes);
        let volume_id = crate::types::VolumeId(uuid);

        let shard_layout = match proto.erasure_info {
            None => crate::types::ShardLayout::Single,
            Some(ei) => crate::types::ShardLayout::Erasure {
                info: ei.try_into()?,
                shard_offsets: proto.shard_offsets,
                shard_volumes: proto
                    .shard_volumes
                    .into_iter()
                    .map(|v| {
                        u16::try_from(v).map_err(|_| {
                            crate::EraError::Deserialization(format!(
                                "shard_volume {} exceeds u16 range",
                                v
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            },
        };

        Ok(Self {
            volume_id,
            slot_index: proto.slot_index,
            physical_offset: proto.physical_offset,
            encrypted_size: proto.encrypted_size,
            shard_layout,
        })
    }
}

impl From<ChunkIndexEntry> for proto::ChunkIndexEntry {
    fn from(entry: ChunkIndexEntry) -> Self {
        Self {
            hash: entry.hash.0.to_vec(),
            offset: entry.offset,
            length: entry.length,
        }
    }
}

impl TryFrom<proto::ChunkIndexEntry> for ChunkIndexEntry {
    type Error = crate::EraError;
    fn try_from(proto: proto::ChunkIndexEntry) -> Result<Self, Self::Error> {
        let hash: [u8; 32] = proto.hash.try_into().map_err(|_| {
            crate::EraError::Deserialization("Invalid hash length for ChunkIndexEntry".to_string())
        })?;
        Ok(Self {
            hash: crate::types::ChunkHash(hash),
            offset: proto.offset,
            length: proto.length,
        })
    }
}

impl From<BlockChunkIndex> for proto::BlockChunkIndex {
    fn from(index: BlockChunkIndex) -> Self {
        Self {
            count: index.count as u32,
            entries: index.entries.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<proto::BlockChunkIndex> for BlockChunkIndex {
    type Error = crate::EraError;
    fn try_from(proto: proto::BlockChunkIndex) -> Result<Self, Self::Error> {
        let entries: Result<Vec<_>, _> = proto.entries.into_iter().map(|e| e.try_into()).collect();
        Ok(Self {
            count: u16::try_from(proto.count).map_err(|_| {
                crate::EraError::Deserialization(format!(
                    "BlockChunkIndex count {} exceeds u16 range",
                    proto.count
                ))
            })?,
            entries: entries?,
        })
    }
}

impl From<MatrixDistributionConfig> for proto::MatrixDistributionConfig {
    fn from(config: MatrixDistributionConfig) -> Self {
        Self {
            strategy: match config.strategy {
                MatrixDistributionStrategy::RotatingOffset => {
                    proto::matrix_distribution_config::Strategy::RotatingOffset.into()
                }
            },
        }
    }
}

impl From<proto::MatrixDistributionConfig> for MatrixDistributionConfig {
    fn from(proto: proto::MatrixDistributionConfig) -> Self {
        Self {
            strategy: match proto.strategy() {
                proto::matrix_distribution_config::Strategy::RotatingOffset => {
                    MatrixDistributionStrategy::RotatingOffset
                }
            },
            ..Default::default()
        }
    }
}

impl From<ChunkingConfig> for proto::ChunkingConfig {
    fn from(config: ChunkingConfig) -> Self {
        Self {
            min_size: config.min_size as u32,
            avg_size: config.avg_size as u32,
            max_size: config.max_size as u32,
            normalization_level: match config.normalization_level {
                NormalizationLevel::Level0 => {
                    proto::chunking_config::NormalizationLevel::NormalizationLevel0.into()
                }
                NormalizationLevel::Level1 => {
                    proto::chunking_config::NormalizationLevel::NormalizationLevel1.into()
                }
                NormalizationLevel::Level2 => {
                    proto::chunking_config::NormalizationLevel::NormalizationLevel2.into()
                }
                NormalizationLevel::Level3 => {
                    proto::chunking_config::NormalizationLevel::NormalizationLevel3.into()
                }
            },
            rolling_hash_seed: config.rolling_hash_seed,
        }
    }
}

impl From<proto::ChunkingConfig> for ChunkingConfig {
    fn from(proto: proto::ChunkingConfig) -> Self {
        Self {
            min_size: proto.min_size as usize,
            avg_size: proto.avg_size as usize,
            max_size: proto.max_size as usize,
            normalization_level: match proto.normalization_level() {
                proto::chunking_config::NormalizationLevel::NormalizationLevel0 => {
                    NormalizationLevel::Level0
                }
                proto::chunking_config::NormalizationLevel::NormalizationLevel1 => {
                    NormalizationLevel::Level1
                }
                proto::chunking_config::NormalizationLevel::NormalizationLevel2 => {
                    NormalizationLevel::Level2
                }
                proto::chunking_config::NormalizationLevel::NormalizationLevel3 => {
                    NormalizationLevel::Level3
                }
            },
            rolling_hash_seed: proto.rolling_hash_seed,
        }
    }
}

impl From<PackingConfig> for proto::PackingConfig {
    fn from(config: PackingConfig) -> Self {
        Self {
            k_factor: config.k_factor as u32,
            flush_threshold: config.flush_threshold as u32,
        }
    }
}

impl From<proto::PackingConfig> for PackingConfig {
    fn from(proto: proto::PackingConfig) -> Self {
        Self {
            k_factor: proto.k_factor as usize,
            flush_threshold: proto.flush_threshold as usize,
        }
    }
}
