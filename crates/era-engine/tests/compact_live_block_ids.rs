use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{
    compact_compactor::{CompactLiveBlockDiscovery, CompactSourcePreflight},
    ArchiveReader, ArchiveWriterBuilder,
};
use tempfile::TempDir;

const PASSWORD: &str = "compact-live-ids-pass";

#[tokio::test]
async fn compact_discovers_live_data_block_ids_from_archive_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_live_ids.era");

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

    writer.add_bytes("a.bin", &[1u8; 512 * 1024]).await.unwrap();
    writer.add_bytes("b.bin", &[2u8; 512 * 1024]).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&base_path, PASSWORD).await.unwrap();
    assert!(
        reader
            .primary_footer()
            .map(|f| f.has_index())
            .unwrap_or(false),
        "test archive must expose embedded index in footer"
    );
    let first = CompactSourcePreflight::discover_live_data_blocks(&mut reader)
        .await
        .expect("discover live block ids");
    let second = CompactSourcePreflight::discover_live_data_blocks(&mut reader)
        .await
        .expect("discover live block ids again");

    assert!(
        matches!(
            first.source,
            CompactLiveBlockDiscovery::EmbeddedIndex | CompactLiveBlockDiscovery::IteratorFallback
        ),
        "discovery must report which recovery path supplied the live block set"
    );
    assert!(
        !first.block_ids.is_empty(),
        "must discover at least one live block id"
    );
    assert_eq!(first, second, "discovered live block-id set must be stable");

    let mut sorted = first.block_ids.clone();
    sorted.sort_by_key(|b| b.sequence());
    sorted.dedup_by_key(|b| b.sequence());
    assert_eq!(first.block_ids, sorted, "set must be sorted and unique");
}

#[tokio::test]
async fn compact_live_data_block_ids_exclude_partial_stripe_padding_members() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_partial_stripe.era");

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

    writer.add_bytes("tiny.bin", &[9u8; 1024]).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&base_path, PASSWORD).await.unwrap();
    assert!(
        reader
            .primary_footer()
            .map(|f| f.has_index())
            .unwrap_or(false),
        "test archive must expose embedded index in footer"
    );
    let ids = CompactSourcePreflight::discover_live_data_blocks(&mut reader)
        .await
        .expect("discover live block ids");

    assert!(!ids.block_ids.is_empty(), "must include real data blocks");
    assert!(
        ids.block_ids.len() < 4,
        "partial-stripe padding members must not appear in live set"
    );
}

#[tokio::test]
async fn compact_live_data_block_ids_match_iterator_equivalent_set() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path().join("compact_equivalent_live_ids.era");

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
        let payload = vec![0x30 + i as u8; 768 * 1024];
        let name = format!("equiv_{i}.bin");
        writer.add_bytes(&name, &payload).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&base_path, PASSWORD).await.unwrap();
    reader.preflight_metadata_recovery().await.unwrap();
    let live_hashes = reader.live_catalog_chunk_hashes().expect("catalog hashes");
    let via_iterator = reader
        .live_data_block_ids_from_hashes_via_iterator(&live_hashes)
        .await
        .expect("iterator live ids");
    let discovered = CompactSourcePreflight::discover_live_data_blocks(&mut reader)
        .await
        .expect("discover live block ids");

    assert_eq!(
        discovered.block_ids, via_iterator,
        "compaction live block ids must match iterator-derived keep-set"
    );
}
