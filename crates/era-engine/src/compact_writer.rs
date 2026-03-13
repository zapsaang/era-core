//! ERA archive → compact `.erac` bundle. Encrypted bytes preserved verbatim.

use crate::compact_compactor::CompactPreparedSource;
use crate::reader::ArchiveReader;
use crate::source_block_snapshot::SourceDataBlockSnapshot;
use era_common::{EraError, Result};
use era_compact::{
    CompactBundleWriter, CompactShardInput, CompactSuperHeader, COMPACT_CATALOG_BLOCK_ID,
    COMPACT_PADDING_BASE,
};
use era_volume::EncryptedVolumeKey;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct CompactStats {
    pub total_blocks: usize,
    pub total_stripes: usize,
    pub total_volumes: usize,
    pub catalog_bytes: usize,
    pub index_bytes: usize,
}

pub async fn compact_archive(
    source_path: &Path,
    bundle_path: &Path,
    password: &str,
) -> Result<CompactStats> {
    let mut reader = ArchiveReader::open(source_path, password).await?;
    let prepared = CompactPreparedSource::from_archive_reader(&mut reader).await?;

    let header = reader.header();
    let erasure_config = header.config().erasure.ok_or_else(|| {
        EraError::InvalidConfig("compact archive requires erasure-coded source".into())
    })?;

    let data_shards = erasure_config.data_shards;
    let parity_shards = erasure_config.parity_shards;
    let total_volumes = u16::from(data_shards) + u16::from(parity_shards);

    let compact_header = build_compact_header(&reader, total_volumes)?;

    let catalog = reader
        .catalog()
        .ok_or_else(|| EraError::IntegrityError("catalog not loaded after preflight".into()))?;
    let catalog_bytes = catalog.to_bytes()?;

    let bundle_path = bundle_path.to_path_buf();
    let snapshots = prepared.snapshots;
    let total_blocks = snapshots.len();

    let stats = tokio::task::spawn_blocking(move || -> Result<CompactStats> {
        let mut bundle_writer = CompactBundleWriter::new(
            &bundle_path,
            &compact_header,
            u16::from(data_shards),
            u16::from(parity_shards),
        )?;

        let stripes = group_snapshots_into_stripes(&snapshots);
        let total_stripes = stripes.len();

        for (stripe_idx, (_ordinal, members)) in stripes.iter().enumerate() {
            let mut inputs: Vec<CompactShardInput> = members
                .iter()
                .map(|snap| snapshot_to_shard_input(snap))
                .collect();
            pad_stripe_inputs(&mut inputs, data_shards, stripe_idx);
            bundle_writer.write_stripe(&inputs)?;
        }

        bundle_writer.write_replicated_block(1, COMPACT_CATALOG_BLOCK_ID, &catalog_bytes)?;
        bundle_writer.finalize()?;

        Ok(CompactStats {
            total_blocks,
            total_stripes,
            total_volumes: total_volumes as usize,
            catalog_bytes: catalog_bytes.len(),
            index_bytes: 0,
        })
    })
    .await
    .map_err(|e| EraError::Io(std::io::Error::other(e)))??;

    Ok(stats)
}

fn build_compact_header(
    reader: &ArchiveReader,
    total_compact_volumes: u16,
) -> Result<CompactSuperHeader> {
    let header = reader.header();

    let evk = header.encrypted_volume_key();
    let compact_evk =
        EncryptedVolumeKey::new(evk.algorithm(), *evk.nonce(), evk.ciphertext().to_vec());

    CompactSuperHeader::new(
        Uuid::new_v4(),
        header.archive_id(),
        header.volume_id(),
        0,
        total_compact_volumes,
        header.version(),
        header.total_volumes(),
        header.config().clone(),
        header.recipients().to_vec(),
        header.access_policy(),
        match header.access_policy() {
            era_volume::AccessPolicy::Threshold(t) => t,
            _ => 0,
        },
        *header.salt(),
        header.epoch_id(),
        compact_evk,
    )
}

fn group_snapshots_into_stripes(
    snapshots: &[SourceDataBlockSnapshot],
) -> Vec<(u64, Vec<&SourceDataBlockSnapshot>)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<u64, Vec<&SourceDataBlockSnapshot>> = BTreeMap::new();
    for snap in snapshots {
        map.entry(snap.stripe_ordinal).or_default().push(snap);
    }
    let mut result: Vec<(u64, Vec<&SourceDataBlockSnapshot>)> = map.into_iter().collect();
    for (_ordinal, members) in &mut result {
        members.sort_by_key(|s| s.member_position_in_stripe);
    }
    result
}

fn snapshot_to_shard_input(snap: &SourceDataBlockSnapshot) -> CompactShardInput {
    CompactShardInput {
        block_id: snap.block_id,
        encrypted_bytes: snap.encrypted_bytes.clone(),
        stripe_ordinal: snap.stripe_ordinal,
        member_position_in_stripe: snap.member_position_in_stripe,
        stripe_lengths: snap.stripe_lengths.clone(),
        data_shards: snap.data_shards,
        parity_shards: snap.parity_shards,
    }
}

/// Pad a stripe with zero-filled inputs when fewer than `data_shards` blocks exist.
/// The original archive pads stripes to fill all data shard slots; we must replicate
/// that behavior so `CompactBundleWriter::write_stripe` receives the expected count.
fn pad_stripe_inputs(inputs: &mut Vec<CompactShardInput>, data_shards: u8, stripe_idx: usize) {
    let expected = data_shards as usize;
    if inputs.len() >= expected || inputs.is_empty() {
        return;
    }

    let max_len = inputs
        .iter()
        .map(|i| i.encrypted_bytes.len())
        .max()
        .unwrap_or(0);

    let template = &inputs[0];
    let stripe_ordinal = template.stripe_ordinal;
    let ds = template.data_shards;
    let ps = template.parity_shards;
    let mut stripe_lengths = template.stripe_lengths.clone();
    while stripe_lengths.len() < expected {
        stripe_lengths.push(0);
    }

    let existing_positions: std::collections::HashSet<u16> =
        inputs.iter().map(|i| i.member_position_in_stripe).collect();

    for pos in 0..expected as u16 {
        if existing_positions.contains(&pos) {
            continue;
        }
        let synthetic_id = COMPACT_PADDING_BASE + (stripe_idx as u64) * 256 + pos as u64;
        inputs.push(CompactShardInput {
            block_id: era_common::BlockId::new(synthetic_id),
            encrypted_bytes: vec![0u8; max_len],
            stripe_ordinal,
            member_position_in_stripe: pos,
            stripe_lengths: stripe_lengths.clone(),
            data_shards: ds,
            parity_shards: ps,
        });
    }

    inputs.sort_by_key(|i| i.member_position_in_stripe);
}
