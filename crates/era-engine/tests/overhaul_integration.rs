use era_common::ErasureCodeConfig;
use era_common::ShardHeader;
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_volume::DATA_REGION_START;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &str = "test-pass";
const INTERNAL_META_PREFIX: &str = ".era/meta/";

fn archive_volumes(base: &Path) -> Vec<PathBuf> {
    let mut volumes = Vec::new();
    if base.exists() {
        volumes.push(base.to_path_buf());
    }
    if let Some(parent) = base.parent() {
        let prefix = base.file_name().unwrap().to_string_lossy().to_string();
        for entry in fs::read_dir(parent).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("{}.", prefix)) {
                volumes.push(entry.path());
            }
        }
    }
    volumes.sort();
    volumes
}

#[tokio::test]
async fn dedup_audit_small_files() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("dedup.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .enable_cdc(true)
        .build()
        .await
        .unwrap();

    for i in 0..10 {
        let file_path = temp.path().join(format!("file_{i}.txt"));
        fs::write(&file_path, b"identical-content").unwrap();
        writer.add_file(&file_path).await.unwrap();
    }

    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let catalog = reader.load_catalog().await.unwrap();

    let mut unique_hashes = HashSet::new();
    for entry in &catalog.entries {
        if entry
            .path
            .to_string_lossy()
            .starts_with(INTERNAL_META_PREFIX)
        {
            continue;
        }
        for chunk in &entry.chunks {
            unique_hashes.insert(chunk.hash);
        }
    }

    assert_eq!(
        unique_hashes.len(),
        1,
        "Expected full dedup across identical inputs"
    );
}

#[tokio::test]
async fn missing_volume_recovery_extracts_successfully() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("missing.era");

    let source_path = temp.path().join("source.bin");
    let source_data = vec![0xA5u8; 2 * 1024 * 1024];
    fs::write(&source_path, &source_data).unwrap();

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .enable_cdc(true)
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig::new(4, 2))
        .volume_count(6)
        .max_volume_size(256 * 1024)
        .build()
        .await
        .unwrap();

    writer.add_file(&source_path).await.unwrap();
    writer.finalize().await.unwrap();

    let mut volumes = archive_volumes(&archive_path);
    assert!(volumes.len() > 1, "Expected multi-volume archive");
    let removed = volumes.pop().unwrap();
    fs::remove_file(&removed).unwrap();

    let output_dir = temp.path().join("extracted");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert!(stats.extracted > 0);

    let restored = fs::read(output_dir.join("source.bin")).unwrap();
    assert_eq!(restored, source_data);
}

#[tokio::test]
async fn aware_read_recovers_aead_corruption() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("aware.era");

    let source_path = temp.path().join("payload.bin");
    let source_data = vec![0x42u8; 512 * 1024];
    fs::write(&source_path, &source_data).unwrap();

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .enable_cdc(true)
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig::new(2, 1))
        .volume_count(3)
        .max_volume_size(256 * 1024)
        .build()
        .await
        .unwrap();

    writer.add_file(&source_path).await.unwrap();
    writer.finalize().await.unwrap();

    let volumes = archive_volumes(&archive_path);
    let target = volumes.first().unwrap();

    let data_shards = 2usize;
    let header_prefix_len = data_shards * 4;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target)
        .unwrap();
    let mut offset = DATA_REGION_START;

    // Read prefix (stripe lengths)
    let mut prefix = vec![0u8; header_prefix_len];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut prefix).unwrap();
    offset += header_prefix_len as u64;

    // Read shard header
    let mut header_bytes = [0u8; ShardHeader::SIZE];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut header_bytes).unwrap();
    let mut header = ShardHeader::from_bytes(&header_bytes).unwrap();
    offset += ShardHeader::SIZE as u64;

    // Read shard data
    let mut shard_data = vec![0u8; header.length as usize];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut shard_data).unwrap();

    // Corrupt data but fix CRC to force AEAD failure path
    shard_data[0] ^= 0xFF;
    header = ShardHeader::new(header.length, era_common::compute_shard_crc(&shard_data));

    // Write updated header + data
    file.seek(SeekFrom::Start(offset - ShardHeader::SIZE as u64))
        .unwrap();
    file.write_all(&header.to_bytes()).unwrap();
    file.write_all(&shard_data).unwrap();
    file.flush().unwrap();

    let output_dir = temp.path().join("recovered");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert!(stats.extracted > 0);

    let restored = fs::read(output_dir.join("payload.bin")).unwrap();
    assert_eq!(restored, source_data);
}
