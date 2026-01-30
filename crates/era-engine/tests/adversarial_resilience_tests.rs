use era_common::{ArchiveConfig, ErasureCodeConfig, ShardHeader};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_storage::LocalStorageBackend;
use era_volume::VolumeReader;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

fn flip_byte_at(path: &Path, offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
}

async fn corrupt_standard_block(path: &Path) {
    let parent = path.parent().unwrap();
    let backend = LocalStorageBackend::new(parent);
    let volume_path = path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(volume_path)).await.unwrap();
    let (data_start, _) = reader.data_region();
    let header_bytes = reader.read_raw(data_start, ShardHeader::SIZE).unwrap();
    let header = ShardHeader::from_bytes(&header_bytes).unwrap();
    let corrupt_offset = data_start + ShardHeader::SIZE as u64 + (header.length as u64 / 2);
    flip_byte_at(path, corrupt_offset);
}

async fn corrupt_erasure_shard(path: &Path, data_shards: usize) {
    let parent = path.parent().unwrap();
    let backend = LocalStorageBackend::new(parent);
    let volume_path = path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(volume_path)).await.unwrap();
    let (data_start, _) = reader.data_region();
    let header_prefix_len = (data_shards * 4) as u64;
    let header_offset = data_start + header_prefix_len;
    let header_bytes = reader.read_raw(header_offset, ShardHeader::SIZE).unwrap();
    let header = ShardHeader::from_bytes(&header_bytes).unwrap();
    let corrupt_offset = header_offset + ShardHeader::SIZE as u64 + (header.length as u64 / 2);
    flip_byte_at(path, corrupt_offset);
}

async fn truncate_erasure_shard_payload(path: &Path, data_shards: usize) {
    let parent = path.parent().unwrap();
    let backend = LocalStorageBackend::new(parent);
    let volume_path = path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(volume_path)).await.unwrap();
    let (data_start, _) = reader.data_region();
    let header_prefix_len = (data_shards * 4) as u64;
    let header_offset = data_start + header_prefix_len;
    let header_bytes = reader.read_raw(header_offset, ShardHeader::SIZE).unwrap();
    let header = ShardHeader::from_bytes(&header_bytes).unwrap();
    let data_offset = header_offset + ShardHeader::SIZE as u64;
    let tail_len = 16u64.min(header.length as u64);
    let truncate_offset = data_offset + header.length as u64 - tail_len;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(truncate_offset)).unwrap();
    file.write_all(&vec![0u8; tail_len as usize]).unwrap();
}

#[tokio::test]
async fn test_standard_block_crc_detection() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("standard_crc.era");

    // Explicitly disable EC to test standard block CRC detection
    let config_no_ec = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("crc_test")
        .config(config_no_ec)
        .enable_small_file_packing(false)
        .build().await
        .await
        .unwrap();

    writer
        .add_bytes("data.bin", &vec![0xA5u8; 64 * 1024])
        .await
        .unwrap();
    writer.finalize().await.await.unwrap();

    corrupt_standard_block(&archive_path).await;

    let mut reader = ArchiveReader::open(&archive_path, "crc_test").await.unwrap();
    let stats = reader.verify().await.await.unwrap();

    assert!(!stats.is_ok(), "CRC corruption should fail verification");
    assert!(stats.blocks_failed > 0);
}

#[tokio::test]
async fn test_single_shard_crc_auto_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("erasure_crc.era");
    let payload = vec![0x5Cu8; 256 * 1024];

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("erasure_test")
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .enable_small_file_packing(false)
        .build().await
        .await
        .unwrap();

    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.await.unwrap();

    corrupt_erasure_shard(&archive_path, 4).await;

    let output_dir = temp_dir.path().join("output_crc");
    let mut reader = ArchiveReader::open(&archive_path, "erasure_test").await.unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();

    assert_eq!(extract_stats.extracted, 1);
    let extracted = fs::read(output_dir.join("payload.bin")).unwrap();
    assert_eq!(extracted, payload);

    let mut reader = ArchiveReader::open(&archive_path, "erasure_test").await.unwrap();
    let verify_stats = reader.verify().await.await.unwrap();
    assert!(verify_stats.is_ok());
}

#[tokio::test]
async fn test_single_shard_truncation_auto_recovery() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("erasure_trunc.era");
    let payload = vec![0x3Du8; 128 * 1024];

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("erasure_test")
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .enable_small_file_packing(false)
        .build().await
        .await
        .unwrap();

    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.await.unwrap();

    truncate_erasure_shard_payload(&archive_path, 4).await;

    let output_dir = temp_dir.path().join("output_trunc");
    let mut reader = ArchiveReader::open(&archive_path, "erasure_test").await.unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();

    assert_eq!(extract_stats.extracted, 1);
    let extracted = fs::read(output_dir.join("payload.bin")).unwrap();
    assert_eq!(extracted, payload);
}
