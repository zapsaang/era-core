use crate::proto;
use crate::{
    ArchiveConfig, BlockConfig, ChunkingConfig, CompressionAlgorithm, CompressionConfig,
    EncryptionAlgorithm, EncryptionConfig, ErasureCodeConfig, MatrixDistributionConfig,
    MatrixDistributionStrategy, PackingConfig, VolumeConfig,
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

impl From<proto::ArchiveConfig> for ArchiveConfig {
    fn from(proto: proto::ArchiveConfig) -> Self {
        Self {
            compression: proto.compression.map(Into::into).unwrap_or_default(),
            encryption: proto.encryption.map(Into::into).unwrap_or_default(),
            volume: proto.volume.map(Into::into).unwrap_or_default(),
            block: proto.block.map(Into::into).unwrap_or_default(),
            erasure: proto.erasure.map(Into::into),
            distribution: proto.distribution.map(Into::into).unwrap_or_default(),
            chunking: proto.chunking.map(Into::into).unwrap_or_default(),
            packing: proto.packing.map(Into::into).unwrap_or_default(),
        }
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

impl From<proto::ErasureCodeConfig> for ErasureCodeConfig {
    fn from(proto: proto::ErasureCodeConfig) -> Self {
        Self {
            data_shards: proto.data_shards as u8,
            parity_shards: proto.parity_shards as u8,
        }
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
            data_shards: proto.data_shards as u8,
            parity_shards: proto.parity_shards as u8,
            shard_size: proto.shard_size,
            original_len: proto.original_len,
        })
    }
}

impl From<BlockLocation> for proto::BlockLocation {
    fn from(loc: BlockLocation) -> Self {
        Self {
            volume_id: loc.volume_id.0.as_bytes().to_vec(),
            slot_index: loc.slot_index,
            physical_offset: loc.physical_offset,
            encrypted_size: loc.encrypted_size,
            erasure_info: loc.erasure_info.map(Into::into),
            shard_offsets: loc.shard_offsets.unwrap_or_default(),
            shard_volumes: loc
                .shard_volumes
                .unwrap_or_default()
                .into_iter()
                .map(|v| v as u32)
                .collect(),
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

        Ok(Self {
            volume_id,
            slot_index: proto.slot_index,
            physical_offset: proto.physical_offset,
            encrypted_size: proto.encrypted_size,
            erasure_info: proto.erasure_info.map(|e| e.try_into()).transpose()?,
            shard_offsets: if proto.shard_offsets.is_empty() {
                None
            } else {
                Some(proto.shard_offsets)
            },
            shard_volumes: if proto.shard_volumes.is_empty() {
                None
            } else {
                Some(proto.shard_volumes.into_iter().map(|v| v as u16).collect())
            },
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
            count: proto.count as u16,
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
                MatrixDistributionStrategy::Striped => {
                    proto::matrix_distribution_config::Strategy::Striped.into()
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
                proto::matrix_distribution_config::Strategy::Striped => {
                    MatrixDistributionStrategy::Striped
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
        }
    }
}

impl From<proto::ChunkingConfig> for ChunkingConfig {
    fn from(proto: proto::ChunkingConfig) -> Self {
        Self {
            min_size: proto.min_size as usize,
            avg_size: proto.avg_size as usize,
            max_size: proto.max_size as usize,
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
