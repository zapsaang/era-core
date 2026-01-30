use bytes::Bytes;
use era_common::{ArchiveConfig, ArchiveId, BlockId, EncryptedMacroBlock};
use era_storage::LocalStorageBackend;
use era_volume::header::{RecipientSlot, SuperHeader};
use era_volume::{MultiVolumeConfig, MultiVolumeWriter};
use std::time::Instant;
use tempfile::tempdir;

#[tokio::test]
async fn test_rotation_latency_under_load() {
    let dir = tempdir().unwrap();
    let base_path = dir.path().join("bench_volume");

    // Set a very small volume size to force frequent rotations
    // 64KB volume size
    let max_vol_size = 64 * 1024;
    let config = MultiVolumeConfig::new(&base_path, max_vol_size).unwrap();
    let backend = LocalStorageBackend::new(dir.path());

    // Construct SuperHeader
    let recipients: Vec<RecipientSlot> = vec![];
    let archive_config = ArchiveConfig::default();
    let salt = [0u8; 16];

    let template_header = SuperHeader::new(ArchiveId::new(), recipients, archive_config, salt);

    let mut writer = MultiVolumeWriter::create(&backend, config, template_header)
        .await
        .expect("Failed to create writer");

    let block_size = 4096;
    let dummy_data = Bytes::from(vec![0u8; block_size]);

    println!("Benchmarking rotation latency...");

    let mut max_latency_us = 0;
    let mut total_latency_us = 0;

    for i in 0..100 {
        let block = EncryptedMacroBlock {
            block_id: BlockId::new(i as u64),
            data: dummy_data.clone(),
            original_size: block_size as u32,
            compressed_size: block_size as u32,
            chunk_count: 1,
        };

        let start = Instant::now();
        writer
            .write_block(&backend, &block)
            .await
            .expect("Failed to append block");
        let duration = start.elapsed();

        let latency_us = duration.as_micros();
        max_latency_us = max_latency_us.max(latency_us);
        total_latency_us += latency_us;
    }

    println!("Max Latency: {} us", max_latency_us);
    println!("Avg Latency: {} us", total_latency_us / 100);

    // Assert - Fail if rotation stall > 20ms
    assert!(
        max_latency_us < 20_000,
        "Latency exceeded 20ms constraint, measured: {} us",
        max_latency_us
    );
}
