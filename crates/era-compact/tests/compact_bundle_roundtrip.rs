use era_common::{ArchiveConfig, ArchiveId, BlockId, VolumeId};
use era_compact::{
    CompactBundleReader, CompactBundleWriter, CompactShardInput, CompactSuperHeader,
};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType,
};
use tempfile::TempDir;
use uuid::Uuid;

fn test_header(total_volumes: u16) -> CompactSuperHeader {
    let recipient = RecipientSlot::new(
        RecipientType::Argon2idPassword,
        Some([0x11; 8]),
        vec![0x22; 16],
        vec![0x33; 48],
    );
    let evk = EncryptedVolumeKey::new(
        KeyWrapAlgorithm::XChaCha20Poly1305,
        [0x44; 24],
        vec![0x55; 48],
    );
    CompactSuperHeader::new(
        Uuid::new_v4(),
        ArchiveId::new(),
        VolumeId::new(),
        0,
        total_volumes,
        3,
        4,
        ArchiveConfig::default(),
        vec![recipient.clone(), recipient.clone(), recipient],
        AccessPolicy::Threshold(2),
        2,
        [0x66; 16],
        7,
        evk,
    )
    .expect("valid test header")
}

fn make_shard_inputs(
    block_ids: &[u64],
    data_shards: u8,
    parity_shards: u8,
    stripe_ordinal: u64,
) -> Vec<CompactShardInput> {
    assert_eq!(block_ids.len(), data_shards as usize);
    block_ids
        .iter()
        .enumerate()
        .map(|(i, &id)| {
            let data = vec![(id & 0xFF) as u8; 1024];
            CompactShardInput {
                block_id: BlockId::new(id),
                encrypted_bytes: data,
                stripe_ordinal,
                member_position_in_stripe: i as u16,
                stripe_lengths: vec![1024; data_shards as usize],
                data_shards,
                parity_shards,
            }
        })
        .collect()
}

#[test]
fn compact_bundle_write_read_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let bundle_path = tmp.path().join("test.erac");

    let data_shards: u16 = 4;
    let parity_shards: u16 = 2;
    let total_volumes = data_shards + parity_shards;
    let header = test_header(total_volumes);

    let mut writer =
        CompactBundleWriter::new(&bundle_path, &header, data_shards, parity_shards).unwrap();

    let stripe0_inputs = make_shard_inputs(&[100, 101, 102, 103], 4, 2, 0);
    writer.write_stripe(&stripe0_inputs).unwrap();

    let stripe1_inputs = make_shard_inputs(&[200, 201, 202, 203], 4, 2, 1);
    writer.write_stripe(&stripe1_inputs).unwrap();

    let catalog_data = b"test-catalog-encrypted-bytes";
    writer.write_replicated_block(1, 999, catalog_data).unwrap();

    let index_data = b"test-index-encrypted-bytes";
    writer.write_replicated_block(2, 998, index_data).unwrap();

    writer.finalize().unwrap();

    let mut reader = CompactBundleReader::open(&bundle_path).unwrap();
    assert_eq!(reader.volume_count(), total_volumes as usize);

    for &block_id in &[100u64, 101, 102, 103] {
        let recovered = reader.read_encrypted_block(BlockId::new(block_id)).unwrap();
        let expected = vec![(block_id & 0xFF) as u8; 1024];
        assert_eq!(recovered, expected, "block {block_id} data mismatch");
    }

    for &block_id in &[200u64, 201, 202, 203] {
        let recovered = reader.read_encrypted_block(BlockId::new(block_id)).unwrap();
        let expected = vec![(block_id & 0xFF) as u8; 1024];
        assert_eq!(recovered, expected, "block {block_id} data mismatch");
    }

    let (cat_id, cat_data) = reader.read_catalog().unwrap();
    assert_eq!(cat_id, 999);
    assert_eq!(cat_data, catalog_data);

    let (idx_id, idx_data) = reader.read_index().unwrap();
    assert_eq!(idx_id, 998);
    assert_eq!(idx_data, index_data);
}

#[test]
fn compact_bundle_roundtrip_with_variable_block_sizes() {
    let tmp = TempDir::new().unwrap();
    let bundle_path = tmp.path().join("varsize.erac");

    let data_shards: u16 = 4;
    let parity_shards: u16 = 2;
    let header = test_header(data_shards + parity_shards);

    let mut writer =
        CompactBundleWriter::new(&bundle_path, &header, data_shards, parity_shards).unwrap();

    let max_len = 4096usize;
    let inputs: Vec<CompactShardInput> = (0..4)
        .map(|i| {
            let size = 512 * (i + 1);
            let mut data = vec![0u8; max_len];
            data[..size].fill((i + 1) as u8);
            CompactShardInput {
                block_id: BlockId::new(i as u64 + 10),
                encrypted_bytes: data,
                stripe_ordinal: 0,
                member_position_in_stripe: i as u16,
                stripe_lengths: vec![max_len as u32; 4],
                data_shards: 4,
                parity_shards: 2,
            }
        })
        .collect();

    writer.write_stripe(&inputs).unwrap();
    writer.finalize().unwrap();

    let mut reader = CompactBundleReader::open(&bundle_path).unwrap();
    for i in 0..4u64 {
        let recovered = reader.read_encrypted_block(BlockId::new(i + 10)).unwrap();
        assert_eq!(recovered.len(), max_len);
        let size = 512 * (i as usize + 1);
        assert!(recovered[..size].iter().all(|&b| b == (i + 1) as u8));
    }
}
