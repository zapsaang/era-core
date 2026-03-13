use bytes::Bytes;
use era_common::{BlockId, EncryptedMacroBlock, ErasureCodeConfig};
use era_engine::source_block_snapshot::{
    compact_volume_for_shard, ensure_complete_source_volume_set,
    source_data_block_snapshots_from_stripe, stripe_batch_from_stripe,
};
use era_packing::{BlockMeta, Stripe};

fn block(block_id: u64, payload: &[u8]) -> EncryptedMacroBlock {
    EncryptedMacroBlock {
        block_id: BlockId::new(block_id),
        data: Bytes::copy_from_slice(payload),
        original_size: payload.len() as u32,
        compressed_size: payload.len() as u32,
        chunk_count: 1,
    }
}

#[test]
fn source_snapshot_preserves_data_block_ids_from_stripe_data_blocks() {
    let stripe = Stripe {
        data_blocks: vec![block(10, b"block-10"), block(11, b"block-11")],
        block_meta: vec![
            BlockMeta {
                chunk_hashes: vec![],
                chunk_entries: vec![],
            },
            BlockMeta {
                chunk_hashes: vec![],
                chunk_entries: vec![],
            },
        ],
        parity_shards: vec![vec![0u8; 7]],
        shard_size: 7,
        config: ErasureCodeConfig {
            data_shards: 2,
            parity_shards: 1,
        },
    };

    let snapshots = source_data_block_snapshots_from_stripe(&stripe, 3).expect("snapshot");
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].block_id.sequence(), 10);
    assert_eq!(snapshots[1].block_id.sequence(), 11);
    assert_eq!(snapshots[0].stripe_ordinal, 3);
    assert_eq!(snapshots[0].member_position_in_stripe, 0);
    assert_eq!(snapshots[1].member_position_in_stripe, 1);
    assert_eq!(snapshots[0].stripe_lengths, vec![8, 8]);
    assert_eq!(snapshots[1].stripe_lengths, vec![8, 8]);
    assert_eq!(snapshots[0].encrypted_bytes, b"block-10");
}

#[test]
fn stripe_batch_carries_group_contract_for_canonical_replay_without_reencrypt() {
    let stripe = Stripe {
        data_blocks: vec![block(100, b"abcd"), block(101, b"123456")],
        block_meta: vec![
            BlockMeta {
                chunk_hashes: vec![],
                chunk_entries: vec![],
            },
            BlockMeta {
                chunk_hashes: vec![],
                chunk_entries: vec![],
            },
        ],
        parity_shards: vec![vec![9; 6]],
        shard_size: 6,
        config: ErasureCodeConfig {
            data_shards: 2,
            parity_shards: 1,
        },
    };

    let batch = stripe_batch_from_stripe(&stripe, 9).expect("stripe batch");
    assert_eq!(batch.stripe_ordinal, 9);
    assert_eq!(batch.stripe_lengths, vec![4, 6]);
    assert_eq!(batch.members.len(), 2);
    assert_eq!(batch.members[0].member_position_in_stripe, 0);
    assert_eq!(batch.members[0].canonical_encrypted_bytes, b"abcd");
    assert_eq!(batch.members[1].member_position_in_stripe, 1);
    assert_eq!(batch.members[1].canonical_encrypted_bytes, b"123456");
}

#[test]
fn incomplete_source_volume_set_is_rejected_before_compaction() {
    let err = ensure_complete_source_volume_set(6, &[0, 1, 2, 4, 5])
        .expect_err("must reject incomplete set");
    assert!(format!("{err}").contains("missing source volumes"));
    assert!(ensure_complete_source_volume_set(6, &[0, 1, 2, 3, 4, 5]).is_ok());
}

#[test]
fn source_snapshot_reuses_rotating_offset_semantics() {
    assert_eq!(compact_volume_for_shard(0, 0, 3).unwrap(), 0);
    assert_eq!(compact_volume_for_shard(1, 0, 3).unwrap(), 1);
    assert_eq!(compact_volume_for_shard(2, 0, 3).unwrap(), 2);

    assert_eq!(compact_volume_for_shard(0, 1, 3).unwrap(), 1);
    assert_eq!(compact_volume_for_shard(1, 1, 3).unwrap(), 2);
    assert_eq!(compact_volume_for_shard(2, 1, 3).unwrap(), 0);
}
