use era_common::{CompressionAlgorithm, EraError, ErasureCodeConfig, Result, UniqueChunk};
use std::mem::size_of;

const CATALOG_PREFIX_SIZE: usize = 12;
const LZ4_FRAME_OVERHEAD: usize = 20;

/// Minimum supported archive volume size limit (1 MiB).
pub const MIN_ARCHIVE_VOLUME_SIZE: u64 = 1024 * 1024;

/// Validate that a configured or overridden `max_volume_size` meets [`MIN_ARCHIVE_VOLUME_SIZE`].
///
/// # Errors
/// Returns [`EraError::InvalidConfig`] when `size` is below [`MIN_ARCHIVE_VOLUME_SIZE`].
pub fn validate_max_volume_size(size: u64) -> Result<u64> {
    if size < MIN_ARCHIVE_VOLUME_SIZE {
        return Err(EraError::InvalidConfig(format!(
            "max_volume_size ({size} bytes) is below minimum supported archive volume size ({MIN_ARCHIVE_VOLUME_SIZE} bytes / 1 MiB)"
        )));
    }
    Ok(size)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VolumeCapacity {
    compression: CompressionAlgorithm,
    data_sealed_budget: usize,
    data_chunk_limit: usize,
    catalog_chunk_limit: usize,
}

impl VolumeCapacity {
    pub(crate) fn new(
        max_volume_size: u64,
        compression: CompressionAlgorithm,
        erasure: Option<ErasureCodeConfig>,
        volume_count: usize,
    ) -> Result<Self> {
        let max_volume_size = max_volume_size.max(era_volume::MIN_VOLUME_SIZE);
        let overhead = era_volume::DATA_REGION_START
            .checked_add(era_volume::PER_VOLUME_OVERHEAD)
            .ok_or_else(|| EraError::InvalidConfig("volume overhead overflow".into()))?;
        let data_region_budget =
            usize::try_from(max_volume_size.checked_sub(overhead).ok_or_else(|| {
                EraError::InvalidConfig(
                    "configured volume size cannot fit persistent headers".into(),
                )
            })?)
            .map_err(|_| EraError::InvalidConfig("volume data capacity exceeds usize".into()))?;

        let canonical_sealed_budget = data_region_budget
            .checked_sub(era_common::BlockHeader::SIZE)
            .ok_or_else(|| {
                EraError::InvalidConfig("configured volume size cannot fit a BlockHeader".into())
            })?
            .min(era_volume::MAX_SHARD_SIZE);
        let data_sealed_budget = if let Some(config) = erasure {
            if volume_count == 0 {
                return Err(EraError::InvalidConfig(
                    "erasure volume count must be positive".into(),
                ));
            }
            let total_shards = usize::from(config.data_shards)
                .checked_add(usize::from(config.parity_shards))
                .ok_or_else(|| EraError::InvalidConfig("erasure shard count overflow".into()))?;
            let max_colocated_shards = total_shards.div_ceil(volume_count);
            let frame_overhead = era_common::ShardHeader::SIZE
                .checked_add(
                    usize::from(config.data_shards)
                        .checked_mul(size_of::<u32>())
                        .ok_or_else(|| {
                            EraError::InvalidConfig("stripe prefix size overflow".into())
                        })?,
                )
                .ok_or_else(|| EraError::InvalidConfig("shard frame size overflow".into()))?;
            let per_shard_budget = data_region_budget / max_colocated_shards;
            let padded_payload_budget =
                per_shard_budget
                    .checked_sub(frame_overhead)
                    .ok_or_else(|| {
                        EraError::InvalidConfig(
                            "configured volume size cannot fit an EC shard frame".into(),
                        )
                    })?;
            let aligned_payload_budget = if padded_payload_budget % 2 == 0 {
                padded_payload_budget
            } else {
                padded_payload_budget - 1
            };
            aligned_payload_budget.min(era_volume::MAX_SHARD_SIZE)
        } else {
            canonical_sealed_budget
        };

        let data_chunk_limit = single_chunk_limit(compression, data_sealed_budget)?;
        let canonical_chunk_limit = single_chunk_limit(compression, canonical_sealed_budget)?;
        let catalog_chunk_limit = canonical_chunk_limit
            .checked_sub(CATALOG_PREFIX_SIZE)
            .filter(|&size| size > 0)
            .ok_or_else(|| {
                EraError::InvalidConfig("configured volume size cannot fit catalog framing".into())
            })?;

        Ok(Self {
            compression,
            data_sealed_budget,
            data_chunk_limit,
            catalog_chunk_limit,
        })
    }

    pub(crate) fn max_data_chunk_size(self) -> usize {
        self.data_chunk_limit
    }

    pub(crate) fn max_catalog_chunk_size(self) -> usize {
        self.catalog_chunk_limit
    }

    pub(crate) fn chunk_groups(self, chunks: Vec<UniqueChunk>) -> Result<Vec<Vec<UniqueChunk>>> {
        let mut groups = Vec::new();
        let mut current = Vec::new();
        let mut current_size = BatchSize::default();

        for chunk in chunks {
            let chunk_len = chunk.data.len();
            let mut projected = current_size.projected(chunk_len)?;
            let mut fits = projected.chunks <= usize::from(u16::MAX)
                && self.data_plaintext_fits(projected.plaintext()?)?;
            if !fits && !current.is_empty() {
                groups.push(std::mem::take(&mut current));
                current_size = BatchSize::default();
                projected = current_size.projected(chunk_len)?;
                fits = projected.chunks <= usize::from(u16::MAX)
                    && self.data_plaintext_fits(projected.plaintext()?)?;
            }
            if !fits {
                return Err(EraError::InvalidConfig(format!(
                    "chunk of {chunk_len} bytes cannot fit the configured volume capacity"
                )));
            }
            current.push(chunk);
            current_size = projected;
        }
        if !current.is_empty() {
            groups.push(current);
        }
        Ok(groups)
    }

    fn data_plaintext_fits(self, plaintext_size: usize) -> Result<bool> {
        let sealed_size = compression_bound(self.compression, plaintext_size)?
            .checked_add(era_crypto::TAG_SIZE)
            .ok_or_else(|| EraError::InvalidConfig("sealed block size overflow".into()))?;
        Ok(sealed_size <= self.data_sealed_budget)
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct BatchSize {
    chunks: usize,
    entries: usize,
    data: usize,
}

impl BatchSize {
    fn projected(self, chunk_len: usize) -> Result<Self> {
        let offset = u32::try_from(self.data)
            .map_err(|_| EraError::InvalidConfig("chunk offset exceeds u32".into()))?;
        let length = u32::try_from(chunk_len)
            .map_err(|_| EraError::InvalidConfig("chunk length exceeds u32".into()))?;
        let mut entry_size = 34usize;
        if offset != 0 {
            entry_size = entry_size
                .checked_add(1 + protobuf_varint_len(u64::from(offset)))
                .ok_or_else(|| EraError::InvalidConfig("chunk index size overflow".into()))?;
        }
        if length != 0 {
            entry_size = entry_size
                .checked_add(1 + protobuf_varint_len(u64::from(length)))
                .ok_or_else(|| EraError::InvalidConfig("chunk index size overflow".into()))?;
        }
        let encoded_entry_size = entry_size
            .checked_add(1)
            .and_then(|size| {
                u64::try_from(size)
                    .ok()
                    .map(|value| size + protobuf_varint_len(value))
            })
            .ok_or_else(|| EraError::InvalidConfig("chunk index entry size overflow".into()))?;
        Ok(Self {
            chunks: self
                .chunks
                .checked_add(1)
                .ok_or_else(|| EraError::InvalidConfig("chunk count overflow".into()))?,
            entries: self
                .entries
                .checked_add(encoded_entry_size)
                .ok_or_else(|| EraError::InvalidConfig("chunk index size overflow".into()))?,
            data: self
                .data
                .checked_add(chunk_len)
                .ok_or_else(|| EraError::InvalidConfig("chunk data size overflow".into()))?,
        })
    }

    fn plaintext(self) -> Result<usize> {
        let count_size = if self.chunks == 0 {
            0
        } else {
            1 + protobuf_varint_len(
                u64::try_from(self.chunks)
                    .map_err(|_| EraError::InvalidConfig("chunk count exceeds u64".into()))?,
            )
        };
        4usize
            .checked_add(count_size)
            .and_then(|size| size.checked_add(self.entries))
            .and_then(|size| size.checked_add(self.data))
            .ok_or_else(|| EraError::InvalidConfig("MacroBlock plaintext size overflow".into()))
    }
}

fn single_chunk_limit(compression: CompressionAlgorithm, sealed_budget: usize) -> Result<usize> {
    let compressed_budget = sealed_budget
        .checked_sub(era_crypto::TAG_SIZE)
        .ok_or_else(|| EraError::InvalidConfig("volume capacity cannot fit an AEAD tag".into()))?;
    let fits = |chunk_len| -> Result<bool> {
        let plaintext = BatchSize::default().projected(chunk_len)?.plaintext()?;
        let sealed = compression_bound(compression, plaintext)?
            .checked_add(era_crypto::TAG_SIZE)
            .ok_or_else(|| EraError::InvalidConfig("sealed block size overflow".into()))?;
        Ok(sealed <= sealed_budget)
    };
    if !fits(0)? {
        return Err(EraError::InvalidConfig(
            "volume capacity cannot fit an empty compressed block".into(),
        ));
    }
    let mut low = 0usize;
    let mut high = compressed_budget;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if fits(middle)? {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    if low == 0 {
        return Err(EraError::InvalidConfig(
            "volume capacity cannot fit a non-empty data chunk".into(),
        ));
    }
    Ok(low)
}

fn compression_bound(algorithm: CompressionAlgorithm, plaintext_size: usize) -> Result<usize> {
    match algorithm {
        CompressionAlgorithm::None => Ok(plaintext_size),
        CompressionAlgorithm::Zstd => Ok(zstd::zstd_safe::compress_bound(plaintext_size)),
        CompressionAlgorithm::LZ4 => plaintext_size
            .checked_add(plaintext_size / 255)
            .and_then(|size| size.checked_add(LZ4_FRAME_OVERHEAD))
            .ok_or_else(|| EraError::InvalidConfig("LZ4 compressed size overflow".into())),
    }
}

fn protobuf_varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}
