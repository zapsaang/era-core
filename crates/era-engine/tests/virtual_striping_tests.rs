use era_common::{ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_volume::DistributionCalculator;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_virtual_striping_end_to_end() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("striped.era");
    let password = "test_password";

    // Configure 2+1 erasure coding (Virtual Striping: 2 Data Blocks + 1 Parity Block)
    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None, // Use None to make sizes predictable
            level: 0,
        },
        ..Default::default()
    };

    // 1. Create Archive with Erasure Coding
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .target_block_size(1024) // 1KB blocks to trigger striping frequently
        .build()
        .await
        .unwrap();

    // Write 5 chunks of 800 bytes each.
    // 800 bytes < 1024, but each write might become a chunk.
    // Since we disabled CDC in builder (default), but we didn't enable CDC.
    // Actually, `add_bytes` creates a chunk.
    // `process_packed_block` will pack them.
    // Staging Pool k=8.
    // If we write 1 file of 800 bytes -> Bin Best Fit.
    // We want to force *multiple* blocks.
    // StagingPool flushes bin when > 95% of target (1KB).

    // Let's write larger files to ensure they fill blocks.
    // File 1: 1024 bytes -> Block 1.
    // File 2: 1024 bytes -> Block 2.
    // Stripe 1 (Block 1, Block 2) fits K=2. Should flush -> Writes Block 1, Block 2, Parity 1.

    // File 3: 1024 bytes -> Block 3.
    // File 4: 1024 bytes -> Block 4.
    // Stripe 2 (Block 3, Block 4) fits K=2. Should flush -> Writes Block 3, Block 4, Parity 2.

    // File 5: 1024 bytes -> Block 5.
    // Finalize -> Stripe 3 (Block 5, Padding, Parity 3).

    let mut expected_data = Vec::new();
    for i in 1..=5 {
        let content = vec![i as u8; 1024]; // 1KB
        let name = format!("file_{}.bin", i);
        writer.add_bytes(&name, &content).await.unwrap();
        expected_data.push(content);
    }

    let stats = writer.finalize().await.unwrap();

    assert_eq!(stats.total_files, 5);

    // 2. Verify physical file structure (Basic Check)
    // We expect 5 Data Blocks + 3 Parity Blocks = 8 "Physical Blocks" written to volume.
    // Each block approx 1024 + overhead.
    let file_len = fs::metadata(&archive_path).unwrap().len();
    println!("Archive size: {} bytes", file_len);
    // 8 * 1024 = 8192. Plus headers.
    assert!(
        file_len > 8000,
        "File too small, implies data missing or not written"
    );

    // 3. Read and Extract
    let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
    let files = reader.list_files().await.unwrap();
    assert_eq!(files.len(), 5);

    let extract_dir = temp_dir.path().join("extracted");
    let options = ExtractOptions::new(&extract_dir);

    // This expects the Reader to handle the Virtual Striping layout correctly
    // i.e., skip parity blocks and read data blocks.
    let extract_stats = reader
        .extract_all(&options)
        .await
        .expect("Extraction failed");

    assert_eq!(extract_stats.extracted, 5);

    // Verify content
    for i in 1..=5 {
        let name = format!("file_{}.bin", i);
        let extracted = fs::read(extract_dir.join(name)).unwrap();
        assert_eq!(extracted, expected_data[i - 1]);
    }
}

#[tokio::test]
async fn test_virtual_striping_reconciles_corrupted_first_prefix_copy() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("striped_prefix.era");
    let password = "test_password";

    let erasure_config = ErasureCodeConfig {
        data_shards: 4,
        parity_shards: 2,
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .volume_count(6)
        .build()
        .await
        .unwrap();

    let payload = vec![0xABu8; 256 * 1024];
    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    let strategy = era_common::MatrixDistributionStrategy::RotatingOffset;
    let vol_idx = strategy.calculate_volume(0, 0, 6).unwrap();
    let vol0_path = if vol_idx == 0 {
        archive_path.clone()
    } else {
        archive_path.with_extension(format!("era.{:03}", vol_idx))
    };

    // Corrupt the prefix copy on the first readable shard to a bogus in-bounds length.
    {
        use era_storage::LocalStorageBackend;
        use era_volume::VolumeReader;
        use std::io::{Seek, SeekFrom, Write};
        use std::path::Path;

        let backend = LocalStorageBackend::new(vol0_path.parent().unwrap());
        let filename = vol0_path.file_name().unwrap();
        let reader = VolumeReader::open(&backend, Path::new(filename))
            .await
            .unwrap();
        let (data_start, _) = reader.data_region();

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&vol0_path)
            .unwrap();
        file.seek(SeekFrom::Start(data_start)).unwrap();
        file.write_all(&1024u32.to_le_bytes()).unwrap();
        file.flush().unwrap();
    }

    // Verify and extract must succeed because prefix reconciliation
    // falls back to header lengths when the first prefix copy is corrupted.
    let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert!(
        verify_stats.is_ok(),
        "must verify despite corrupted first prefix copy"
    );

    let extract_dir = temp_dir.path().join("extracted");
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .expect("Extraction failed");
    assert_eq!(extract_stats.extracted, 1);

    let extracted = fs::read(extract_dir.join("payload.bin")).unwrap();
    assert_eq!(extracted, payload);
}
