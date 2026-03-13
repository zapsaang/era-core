use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{compact_compactor::CompactPreparedSource, ArchiveReader, ArchiveWriterBuilder};
use tempfile::TempDir;

const PASSWORD: &str = "compact-source-materialization-pass";

#[tokio::test]
async fn compact_materialization_collects_snapshots_for_live_blocks() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_materialized.era");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .password(PASSWORD)
        .config(ArchiveConfig {
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::None,
                level: 0,
            },
            ..Default::default()
        })
        .enable_erasure(true)
        .enable_cdc(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .build()
        .await
        .unwrap();

    for i in 0..3 {
        let payload = vec![0x40 + i as u8; 768 * 1024];
        let name = format!("materialized_{i}.bin");
        writer.add_bytes(&name, &payload).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&base_path, PASSWORD).await.unwrap();
    let prepared = CompactPreparedSource::from_archive_reader(&mut reader)
        .await
        .expect("prepare compact source");

    let snapshot_ids: Vec<u64> = prepared
        .snapshots
        .iter()
        .map(|snapshot| snapshot.block_id.sequence())
        .collect();
    let live_ids: Vec<u64> = prepared
        .live_data_blocks
        .block_ids
        .iter()
        .map(|block_id| block_id.sequence())
        .collect();

    assert_eq!(
        snapshot_ids, live_ids,
        "snapshots must match live keep-set order"
    );
    assert!(
        prepared
            .snapshots
            .iter()
            .all(|snapshot| !snapshot.encrypted_bytes.is_empty()),
        "archive-backed snapshots must retain canonical encrypted bytes"
    );
    assert!(
        prepared
            .snapshots
            .iter()
            .all(|snapshot| snapshot.stripe_lengths.len() == 4),
        "erasure snapshots must carry full stripe length vector"
    );
}

#[tokio::test]
async fn compact_materialization_excludes_padding_but_keeps_partial_stripe_context() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_materialized_partial.era");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .password(PASSWORD)
        .config(ArchiveConfig {
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::None,
                level: 0,
            },
            ..Default::default()
        })
        .enable_erasure(true)
        .enable_cdc(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .target_block_size(4 * 1024 * 1024)
        .build()
        .await
        .unwrap();

    writer.add_bytes("tiny.bin", &[0xAB; 1024]).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&base_path, PASSWORD).await.unwrap();
    let prepared = CompactPreparedSource::from_archive_reader(&mut reader)
        .await
        .expect("prepare compact source");

    assert_eq!(
        prepared.snapshots.len(),
        1,
        "padding members must not materialize"
    );
    assert_eq!(prepared.live_data_blocks.block_ids.len(), 1);
    assert_eq!(
        prepared.snapshots[0].block_id,
        prepared.live_data_blocks.block_ids[0]
    );
    assert_eq!(prepared.snapshots[0].stripe_lengths.len(), 4);
    assert_eq!(prepared.snapshots[0].data_shards, 4);
    assert_eq!(prepared.snapshots[0].parity_shards, 2);
}
