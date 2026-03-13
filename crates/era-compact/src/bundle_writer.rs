use crate::directory::{CompactDirectoryEntry, CompactRegionKind};
use crate::header::CompactSuperHeader;
use crate::set::plan_compact_volume_paths;
use crate::stripe::{CompactShardInput, CompactShardRecordHeader};
use crate::writer::{prepare_bundle_staging, CompactVolumeWriter};
use era_codec::{ErasureCoder, ErasureConfig};
use era_common::{BlockId, EraError, Result};
use era_volume::DistributionCalculator;
use std::path::Path;

pub struct CompactBundleWriter {
    writers: Vec<CompactVolumeWriter>,
    total_volumes: usize,
    stripe_counter: u32,
}

impl CompactBundleWriter {
    pub fn new(
        bundle_path: &Path,
        header: &CompactSuperHeader,
        data_shards: u16,
        parity_shards: u16,
    ) -> Result<Self> {
        let total_volumes = (data_shards as usize) + (parity_shards as usize);
        if total_volumes == 0 {
            return Err(EraError::InvalidConfig(
                "compact bundle requires at least one volume".into(),
            ));
        }

        prepare_bundle_staging(bundle_path)?;
        let paths = plan_compact_volume_paths(bundle_path, data_shards, parity_shards)?;

        let mut writers = Vec::with_capacity(total_volumes);
        for path in &paths {
            writers.push(CompactVolumeWriter::create(path, header)?);
        }

        Ok(Self {
            writers,
            total_volumes,
            stripe_counter: 0,
        })
    }

    /// Writes a stripe of data shards plus parity shards across volumes.
    ///
    /// The internal `stripe_counter` is the canonical ordinal stored in
    /// directory entries and shard headers. The input's `stripe_ordinal`
    /// is the source archive's ordinal, used only for volume distribution.
    pub fn write_stripe(&mut self, inputs: &[CompactShardInput]) -> Result<()> {
        if inputs.is_empty() {
            return Ok(());
        }

        let data_shards = inputs[0].data_shards;
        let parity_shards = inputs[0].parity_shards;
        let stripe_ordinal = inputs[0].stripe_ordinal;

        for input in &inputs[1..] {
            if input.data_shards != data_shards || input.parity_shards != parity_shards {
                return Err(EraError::InvalidFormat(format!(
                    "inconsistent shard params in stripe: expected {}/{}, got {}/{}",
                    data_shards, parity_shards, input.data_shards, input.parity_shards
                )));
            }
        }

        let mut sorted_inputs: Vec<&CompactShardInput> = inputs.iter().collect();
        sorted_inputs.sort_by_key(|i| i.member_position_in_stripe);

        if sorted_inputs.len() != data_shards as usize {
            return Err(EraError::InvalidFormat(format!(
                "stripe has {} inputs but expected {} data shards",
                sorted_inputs.len(),
                data_shards
            )));
        }

        let data_shard_vecs: Vec<Vec<u8>> = sorted_inputs
            .iter()
            .map(|i| i.encrypted_bytes.clone())
            .collect();

        let config = ErasureConfig::new(data_shards as usize, parity_shards as usize)?;
        let coder = ErasureCoder::new(config)?;
        let all_shards = coder.encode_shards(&data_shard_vecs)?;

        let strategy = era_common::MatrixDistributionStrategy::RotatingOffset;

        for (shard_idx, shard_data) in all_shards.iter().enumerate() {
            let shard_idx_u16 = u16::try_from(shard_idx).map_err(|_| {
                EraError::InvalidFormat(format!("shard index {} exceeds u16::MAX", shard_idx))
            })?;

            let vol_idx =
                strategy.calculate_volume(shard_idx, stripe_ordinal, self.total_volumes)?;

            let block_id = if shard_idx < data_shards as usize {
                sorted_inputs[shard_idx].block_id
            } else {
                BlockId::new(
                    crate::COMPACT_PARITY_BASE
                        - (self.stripe_counter as u64 * 256 + shard_idx as u64),
                )
            };

            let encrypted_len = if shard_idx < data_shards as usize {
                sorted_inputs[shard_idx].encrypted_bytes.len() as u32
            } else {
                0
            };

            let shard_len = u32::try_from(shard_data.len())
                .map_err(|_| EraError::InvalidFormat("shard data exceeds u32::MAX".into()))?;

            let shard_header = CompactShardRecordHeader::new(
                block_id,
                self.stripe_counter,
                shard_idx_u16,
                data_shards as u16,
                parity_shards as u16,
                encrypted_len,
                shard_len,
                shard_data,
            )?;

            let (offset, span) =
                self.writers[vol_idx].write_shard_record(&shard_header, shard_data)?;

            self.writers[vol_idx].add_directory_entry(CompactDirectoryEntry {
                block_id,
                block_type: 0,
                region_kind: CompactRegionKind::StripedData,
                offset,
                span,
                stripe_ordinal: self.stripe_counter,
            });
        }

        self.stripe_counter = self.stripe_counter.checked_add(1).ok_or_else(|| {
            EraError::InvalidFormat("stripe counter overflow (exceeded u32::MAX stripes)".into())
        })?;
        Ok(())
    }

    pub fn write_replicated_block(
        &mut self,
        block_type: u16,
        block_id: u64,
        data: &[u8],
    ) -> Result<()> {
        let data_len_u32 = u32::try_from(data.len())
            .map_err(|_| EraError::InvalidFormat("replicated block exceeds u32::MAX".into()))?;

        for writer in &mut self.writers {
            let (offset, _size) = writer.write_replicated_block(block_id, data)?;
            let span = 4 + 8 + data.len() as u64;

            writer.add_directory_entry(CompactDirectoryEntry {
                block_id: BlockId::new(block_id),
                block_type,
                region_kind: CompactRegionKind::ReplicatedTypedBlock,
                offset,
                span,
                stripe_ordinal: 0,
            });

            if block_type == 1 {
                writer.set_catalog(offset, data_len_u32, block_id);
            } else if block_type == 2 {
                writer.set_index(offset, data_len_u32, block_id);
            }
        }
        Ok(())
    }

    pub fn finalize(self) -> Result<()> {
        for writer in self.writers {
            writer.finalize()?;
        }
        Ok(())
    }
}
