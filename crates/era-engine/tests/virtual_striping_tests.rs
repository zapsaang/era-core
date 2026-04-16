use era_common::{
    ArchiveConfig, CompressionAlgorithm, CompressionConfig, ErasureCodeConfig, ShardHeader,
};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_storage::LocalStorageBackend;
use era_volume::{DistributionCalculator, VolumeReader};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

async fn corrupt_shard_header_length(
    volume_path: &std::path::Path,
    data_shards: usize,
    target_shard_idx: usize,
    new_length: u32,
) {
    let backend = LocalStorageBackend::new(volume_path.parent().unwrap());
    let filename = volume_path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(filename))
        .await
        .unwrap();
    let (data_start, _) = reader.data_region();
    let header_prefix_len = data_shards * 4;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(volume_path)
        .unwrap();

    let mut offset = data_start;
    for shard_idx in 0..=target_shard_idx {
        offset += header_prefix_len as u64;
        let header_offset = offset;
        let mut header_bytes = [0u8; ShardHeader::SIZE];
        file.seek(SeekFrom::Start(header_offset)).unwrap();
        file.read_exact(&mut header_bytes).unwrap();
        let length = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);

        if shard_idx == target_shard_idx {
            file.seek(SeekFrom::Start(header_offset)).unwrap();
            file.write_all(&new_length.to_le_bytes()).unwrap();
            file.flush().unwrap();
            return;
        }
        offset += ShardHeader::SIZE as u64 + length as u64;
    }
}

#[tokio::test]
async fn test_virtual_striping_end_to_end() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("striped.era");
    let password = "test_password";

    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .target_block_size(1024)
        .build()
        .await
        .unwrap();

    let mut expected_data = Vec::new();
    for i in 1..=5 {
        let content = vec![i as u8; 1024];
        let name = format!("file_{}.bin", i);
        writer.add_bytes(&name, &content).await.unwrap();
        expected_data.push(content);
    }

    let stats = writer.finalize().await.unwrap();

    assert_eq!(stats.total_files, 5);

    let file_len = fs::metadata(&archive_path).unwrap().len();
    println!("Archive size: {} bytes", file_len);
    assert!(
        file_len > 8000,
        "File too small, implies data missing or not written"
    );

    let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
    let files = reader.list_files().await.unwrap();
    assert_eq!(files.len(), 5);

    let extract_dir = temp_dir.path().join("extracted");
    let options = ExtractOptions::new(&extract_dir);

    let extract_stats = reader
        .extract_all(&options)
        .await
        .expect("Extraction failed");

    assert_eq!(extract_stats.extracted, 5);

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

    {
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

#[tokio::test]
async fn test_virtual_striping_corrupted_parity_length_does_not_drift() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("striped_parity.era");
    let password = "test_password";

    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .target_block_size(1024)
        .enable_small_file_packing(false)
        .volume_count(1)
        .build()
        .await
        .unwrap();

    let mut expected_data = Vec::new();
    for i in 1..=5 {
        let content = vec![i as u8; 1024];
        let name = format!("file_{}.bin", i);
        writer.add_bytes(&name, &content).await.unwrap();
        expected_data.push(content);
    }

    writer.finalize().await.unwrap();

    corrupt_shard_header_length(&archive_path, 2, 2, 1).await;

    let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert!(
        verify_stats.is_ok(),
        "must verify despite corrupted parity length"
    );

    let extract_dir = temp_dir.path().join("extracted");
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .expect("Extraction failed");
    assert_eq!(extract_stats.extracted, 5);

    for i in 1..=5 {
        let name = format!("file_{}.bin", i);
        let extracted = fs::read(extract_dir.join(name)).unwrap();
        assert_eq!(extracted, expected_data[i - 1]);
    }
}

#[tokio::test]
async fn test_virtual_striping_clamps_inflated_parity_length() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("striped_parity_large.era");
    let password = "test_password";

    let erasure_config = ErasureCodeConfig {
        data_shards: 2,
        parity_shards: 1,
    };

    let config = ArchiveConfig {
        compression: CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: 0,
        },
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .config(config)
        .enable_erasure(true)
        .erasure_config(erasure_config)
        .target_block_size(1024)
        .enable_small_file_packing(false)
        .volume_count(1)
        .build()
        .await
        .unwrap();

    let mut expected_data = Vec::new();
    for i in 1..=5 {
        let content = vec![i as u8; 1024];
        let name = format!("file_{}.bin", i);
        writer.add_bytes(&name, &content).await.unwrap();
        expected_data.push(content);
    }

    writer.finalize().await.unwrap();

    corrupt_shard_header_length(&archive_path, 2, 2, 2048).await;

    let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert!(
        verify_stats.is_ok(),
        "must verify despite inflated parity length"
    );

    let extract_dir = temp_dir.path().join("extracted");
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .expect("Extraction failed");
    assert_eq!(extract_stats.extracted, 5);

    for i in 1..=5 {
        let name = format!("file_{}.bin", i);
        let extracted = fs::read(extract_dir.join(name)).unwrap();
        assert_eq!(extracted, expected_data[i - 1]);
    }
}
