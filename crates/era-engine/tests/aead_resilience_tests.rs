use era_common::{ArchiveConfig, BlockHeader, ErasureCodeConfig};
use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RepairOptions};
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

async fn corrupt_standard_block_payload(path: &Path) {
    let parent = path.parent().unwrap();
    let backend = LocalStorageBackend::new(parent);
    let volume_path = path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(volume_path))
        .await
        .unwrap();
    let (data_start, _) = reader.data_region();
    let header_bytes = reader
        .read_raw(data_start, BlockHeader::SIZE)
        .await
        .unwrap();
    let header = BlockHeader::from_bytes(&header_bytes).expect("valid BlockHeader at data_start");
    let corrupt_offset = data_start + BlockHeader::SIZE as u64 + (header.length as u64 / 2);
    flip_byte_at(path, corrupt_offset);
}

#[tokio::test]
async fn test_repair_single_shard_corruption_no_erasure() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("no_erasure_corrupt.era");

    let config_no_erasure = ArchiveConfig {
        erasure: None,
        ..Default::default()
    };

    let payload = vec![0xA7u8; 128 * 1024];
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("resilience")
        .config(config_no_erasure)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    corrupt_standard_block_payload(&archive_path).await;

    let mut reader = ArchiveReader::open(&archive_path, "resilience")
        .await
        .unwrap();
    let verify = reader.verify().await.unwrap();
    assert!(
        !verify.is_ok(),
        "Corrupted non-erasure archive must fail verify"
    );
    assert!(verify.blocks_failed > 0, "Must report failed block(s)");

    let repair_result = repair_archive(
        &archive_path,
        "resilience",
        RepairOptions {
            create_backup: false,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await;
    assert!(
        repair_result.is_err(),
        "Repair should reject non-erasure archives"
    );
    let err = repair_result.unwrap_err().to_string();
    assert!(
        err.contains("erasure coding"),
        "Expected recovery guidance mentioning erasure coding, got: {err}"
    );
}

#[tokio::test]
async fn test_repair_erasure_coded_single_volume_loss() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("erasure_loss.era");
    let payload = vec![0x4Cu8; 512 * 1024];

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("resilience")
        .erasure_config(ErasureCodeConfig {
            data_shards: 4,
            parity_shards: 2,
        })
        .volume_count(6)
        .max_volume_size(256 * 1024)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    let lost_volume = temp_dir.path().join("erasure_loss.era.002");
    assert!(lost_volume.exists(), "Expected secondary volume to exist");
    fs::remove_file(&lost_volume).unwrap();

    let repair_stats = repair_archive(
        &archive_path,
        "resilience",
        RepairOptions {
            create_backup: false,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(repair_stats.unrecoverable_blocks, 0);

    let output_dir = temp_dir.path().join("output");
    let mut reader = ArchiveReader::open(&archive_path, "resilience")
        .await
        .unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(extract_stats.extracted, 1);

    let restored = fs::read(output_dir.join("payload.bin")).unwrap();
    assert_eq!(restored, payload);
}
