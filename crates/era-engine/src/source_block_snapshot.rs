use era_common::{BlockId, EraError, Result};
use era_packing::Stripe;
use era_volume::DistributionCalculator;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeBatchMember {
    pub block_id: BlockId,
    pub member_position_in_stripe: u16,
    pub canonical_encrypted_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeBatchSnapshot {
    pub stripe_ordinal: u64,
    pub stripe_lengths: Vec<u32>,
    pub members: Vec<StripeBatchMember>,
    pub data_shards: u8,
    pub parity_shards: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDataBlockSnapshot {
    pub block_id: BlockId,
    pub encrypted_bytes: Vec<u8>,
    pub stripe_ordinal: u64,
    pub member_position_in_stripe: u16,
    pub stripe_lengths: Vec<u32>,
    pub data_shards: u8,
    pub parity_shards: u8,
}

pub fn stripe_batch_from_stripe(
    stripe: &Stripe,
    stripe_ordinal: u64,
) -> Result<StripeBatchSnapshot> {
    if stripe.config.data_shards == 0 {
        return Err(EraError::InvalidConfig(
            "stripe data_shards must be > 0".into(),
        ));
    }

    let stripe_lengths: Vec<u32> = stripe
        .data_blocks
        .iter()
        .map(|b| b.data.len() as u32)
        .collect();
    let members = stripe
        .data_blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| StripeBatchMember {
            block_id: block.block_id,
            member_position_in_stripe: idx as u16,
            canonical_encrypted_bytes: block.data.to_vec(),
        })
        .collect();

    Ok(StripeBatchSnapshot {
        stripe_ordinal,
        stripe_lengths,
        members,
        data_shards: stripe.config.data_shards,
        parity_shards: stripe.config.parity_shards,
    })
}

pub fn ensure_complete_source_volume_set(
    expected_total_volumes: usize,
    available_volume_sequences: &[u16],
) -> Result<()> {
    if expected_total_volumes == 0 {
        return Err(EraError::InvalidConfig(
            "expected_total_volumes must be > 0".into(),
        ));
    }
    let available: BTreeSet<usize> = available_volume_sequences
        .iter()
        .map(|v| usize::from(*v))
        .collect();
    let missing: Vec<usize> = (0..expected_total_volumes)
        .filter(|seq| !available.contains(seq))
        .collect();
    if !missing.is_empty() {
        return Err(EraError::InvalidFormat(format!(
            "missing source volumes before compaction: {:?}",
            missing
        )));
    }
    Ok(())
}

pub fn source_data_block_snapshots_from_stripe(
    stripe: &Stripe,
    stripe_ordinal: u64,
) -> Result<Vec<SourceDataBlockSnapshot>> {
    let batch = stripe_batch_from_stripe(stripe, stripe_ordinal)?;

    Ok(batch
        .members
        .iter()
        .map(|member| SourceDataBlockSnapshot {
            block_id: member.block_id,
            encrypted_bytes: member.canonical_encrypted_bytes.clone(),
            stripe_ordinal: batch.stripe_ordinal,
            member_position_in_stripe: member.member_position_in_stripe,
            stripe_lengths: batch.stripe_lengths.clone(),
            data_shards: batch.data_shards,
            parity_shards: batch.parity_shards,
        })
        .collect())
}

pub fn compact_volume_for_shard(
    shard_idx: usize,
    stripe_ordinal: u64,
    total_compact_volumes: usize,
) -> Result<usize> {
    era_common::MatrixDistributionStrategy::RotatingOffset.calculate_volume(
        shard_idx,
        stripe_ordinal,
        total_compact_volumes,
    )
}
