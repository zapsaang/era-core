use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{
    compact_compactor::{CompactLiveBlockDiscovery, CompactSourcePreflight},
    ArchiveReader, ArchiveWriterBuilder,
};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn compact_preflight_accepts_complete_erasure_volume_set() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_preflight_ok.era");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(ArchiveConfig {
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::None,
                level: 0,
            },
            ..Default::default()
        })
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("data.bin", &[0xAB; 512 * 1024])
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let reader = ArchiveReader::open(&base_path, "").await.unwrap();
    let preflight =
        CompactSourcePreflight::from_archive_reader(&reader).expect("preflight must pass");
    assert_eq!(preflight.expected_total_volumes, 6);
    assert_eq!(preflight.available_volume_indices, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(
        preflight.archive_id,
        *reader.header().archive_id().0.as_bytes()
    );
}

#[tokio::test]
async fn compact_preflight_rejects_incomplete_erasure_volume_set() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_preflight_missing.era");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(ArchiveConfig {
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::None,
                level: 0,
            },
            ..Default::default()
        })
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("data.bin", &[0xCD; 512 * 1024])
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let vol2 = base_path.with_extension("era.002");
    fs::remove_file(&vol2).unwrap();

    let reader = ArchiveReader::open(&base_path, "").await.unwrap();
    let err = CompactSourcePreflight::from_archive_reader(&reader)
        .expect_err("preflight must reject incomplete source set");
    assert!(format!("{err}").contains("missing source volumes"));
}

#[tokio::test]
async fn compact_preflight_live_data_block_ids_are_unique_and_sorted() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_live_ids.era");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(ArchiveConfig {
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::None,
                level: 0,
            },
            ..Default::default()
        })
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .build()
        .await
        .unwrap();

    for i in 0..5 {
        let payload = vec![0x10 + i as u8; 2 * 1024 * 1024];
        let name = format!("file_{i}.bin");
        writer.add_bytes(&name, &payload).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&base_path, "").await.unwrap();
    let discovered = CompactSourcePreflight::discover_live_data_blocks(&mut reader)
        .await
        .expect("live data block ids");
    let sequences: Vec<u64> = discovered
        .block_ids
        .iter()
        .map(|id| id.sequence())
        .collect();

    assert!(
        matches!(
            discovered.source,
            CompactLiveBlockDiscovery::EmbeddedIndex | CompactLiveBlockDiscovery::IteratorFallback
        ),
        "preflight discovery must report whether index or iterator recovery supplied the live set"
    );

    assert!(
        !sequences.is_empty(),
        "live data block ids should not be empty"
    );
    assert!(
        sequences.len() > 1,
        "fixture should produce more than one live data block id"
    );

    let mut expected = sequences.clone();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(sequences, expected, "block ids must be sorted and unique");
}

#[tokio::test]
async fn compact_preflight_live_data_block_ids_exclude_partial_stripe_padding() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_partial_ids.era");

    let mut writer = ArchiveWriterBuilder::new(&base_path)
        .config(ArchiveConfig {
            compression: CompressionConfig {
                algorithm: CompressionAlgorithm::None,
                level: 0,
            },
            ..Default::default()
        })
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .build()
        .await
        .unwrap();

    writer
        .add_bytes("small.bin", &[0xAB; 8 * 1024])
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&base_path, "").await.unwrap();
    let block_ids = CompactSourcePreflight::discover_live_data_blocks(&mut reader)
        .await
        .expect("live data block ids");
    let sequences: Vec<u64> = block_ids.block_ids.iter().map(|id| id.sequence()).collect();

    assert_eq!(
        sequences,
        vec![0],
        "only the single real data block should be discovered; final stripe padding must be excluded"
    );
}
