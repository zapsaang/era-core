use crate::directory::CompactRegionKind;
use crate::header::CompactSuperHeader;
use crate::reader::CompactVolumeReader;
use crate::set::discover_bundle_volumes;
use era_codec::{ErasureCoder, ErasureConfig};
use era_common::{BlockId, EraError, Result};
use std::path::Path;

pub struct CompactBundleReader {
    volumes: Vec<CompactVolumeReader>,
    header: CompactSuperHeader,
}

impl CompactBundleReader {
    pub fn open(bundle_path: &Path) -> Result<Self> {
        let paths = discover_bundle_volumes(bundle_path)?;
        if paths.is_empty() {
            return Err(EraError::InvalidFormat(
                "no volumes found in compact bundle".into(),
            ));
        }

        let mut volumes = Vec::with_capacity(paths.len());
        for path in &paths {
            volumes.push(CompactVolumeReader::open(path)?);
        }

        let header = volumes[0].header().clone();
        for (i, vol) in volumes.iter().enumerate().skip(1) {
            if vol.header().archive_id() != header.archive_id() {
                return Err(EraError::InvalidFormat(format!(
                    "volume {i} archive_id mismatch"
                )));
            }
        }

        Ok(Self { volumes, header })
    }

    pub fn read_encrypted_block(&mut self, block_id: BlockId) -> Result<Vec<u8>> {
        let target_seq = block_id.sequence();

        let mut target_stripe = None;

        for vol in &self.volumes {
            for entry in vol.directory().entries() {
                if entry.block_id.sequence() == target_seq
                    && entry.region_kind == CompactRegionKind::StripedData
                {
                    target_stripe = Some(entry.stripe_ordinal);
                    break;
                }
            }
            if target_stripe.is_some() {
                break;
            }
        }

        let stripe_ordinal = target_stripe.ok_or_else(|| {
            EraError::InvalidFormat(format!("block {} not found in compact bundle", target_seq))
        })?;

        let mut shard_slots: Vec<Option<Vec<u8>>> = Vec::new();
        let mut data_shards = 0u16;
        let mut parity_shards = 0u16;
        let mut target_shard_index: Option<u16> = None;
        let mut target_encrypted_len: Option<u32> = None;
        let mut shard_size = 0usize;
        let mut initialized = false;

        for vol in &mut self.volumes {
            let entries = vol.directory().entries().to_vec();
            for entry in &entries {
                if entry.region_kind != CompactRegionKind::StripedData {
                    continue;
                }
                if entry.stripe_ordinal != stripe_ordinal {
                    continue;
                }

                let (shard_header, payload) = vol.read_shard_at(entry.offset)?;

                if !initialized {
                    data_shards = shard_header.data_shards;
                    parity_shards = shard_header.parity_shards;
                    shard_size = payload.len();
                    let total = data_shards as usize + parity_shards as usize;
                    shard_slots = vec![None; total];
                    initialized = true;
                }

                if shard_header.block_id.sequence() == target_seq {
                    target_shard_index = Some(shard_header.shard_index);
                    target_encrypted_len = Some(shard_header.encrypted_len);
                }

                let idx = shard_header.shard_index as usize;
                if idx < shard_slots.len() {
                    shard_slots[idx] = Some(payload);
                }
            }
        }

        if !initialized {
            return Err(EraError::InvalidFormat(format!(
                "no shards found for stripe {} in compact bundle",
                stripe_ordinal
            )));
        }

        let target_idx = target_shard_index.ok_or_else(|| {
            EraError::InvalidFormat(format!(
                "block {} shard not found in stripe {}",
                target_seq, stripe_ordinal
            ))
        })? as usize;

        let encrypted_len = target_encrypted_len.ok_or_else(|| {
            EraError::InvalidFormat(format!(
                "missing encrypted_len for block {} in stripe {}",
                target_seq, stripe_ordinal
            ))
        })? as usize;

        let config = ErasureConfig::new(data_shards as usize, parity_shards as usize)?;
        let coder = ErasureCoder::new(config)?;
        let data_shards_recovered = coder.recover_data_shards(&shard_slots, shard_size)?;

        if target_idx >= data_shards_recovered.len() {
            return Err(EraError::InvalidFormat(format!(
                "target shard index {} out of range",
                target_idx
            )));
        }

        let mut recovered = data_shards_recovered[target_idx].clone();
        if encrypted_len > 0 {
            if encrypted_len > recovered.len() {
                return Err(EraError::IntegrityError(format!(
                    "recovered shard ({} bytes) shorter than declared encrypted_len ({})",
                    recovered.len(),
                    encrypted_len
                )));
            }
            recovered.truncate(encrypted_len);
        }

        Ok(recovered)
    }

    pub fn read_replicated_block(&mut self, block_type: u16) -> Result<(u64, Vec<u8>)> {
        for vol in &mut self.volumes {
            let entries = vol.directory().entries().to_vec();
            for entry in &entries {
                if entry.region_kind != CompactRegionKind::ReplicatedTypedBlock {
                    continue;
                }
                if entry.block_type != block_type {
                    continue;
                }
                return vol.read_replicated_block_at(entry.offset);
            }
        }
        Err(EraError::InvalidFormat(format!(
            "replicated block type {block_type} not found"
        )))
    }

    pub fn read_catalog(&mut self) -> Result<(u64, Vec<u8>)> {
        self.read_replicated_block(1)
    }

    pub fn read_index(&mut self) -> Result<(u64, Vec<u8>)> {
        self.read_replicated_block(2)
    }

    pub fn header(&self) -> &CompactSuperHeader {
        &self.header
    }

    pub fn volume_count(&self) -> usize {
        self.volumes.len()
    }

    pub fn data_block_ids(&self) -> Vec<BlockId> {
        let mut ids = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for vol in &self.volumes {
            for entry in vol.directory().entries() {
                if entry.region_kind == CompactRegionKind::StripedData {
                    let seq = entry.block_id.sequence();
                    // filter out synthetic parity block IDs
                    if seq < crate::COMPACT_DATA_BLOCK_CEILING && seen.insert(seq) {
                        ids.push(entry.block_id);
                    }
                }
            }
        }
        ids.sort_by_key(|b| b.sequence());
        ids
    }
}
