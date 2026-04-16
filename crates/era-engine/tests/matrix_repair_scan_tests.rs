use era_common::ErasureCodeConfig;
use era_engine::{
    repair_archive_matrix, ArchiveReader, ArchiveWriterBuilder, ExtractOptions, RepairOptions,
};
use era_storage::LocalStorageBackend;
use era_volume::{DistributionCalculator, VolumeReader};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &str = "matrix-repair-test";
const ERASURE_4_PLUS_2: ErasureCodeConfig = ErasureCodeConfig {
    data_shards: 4,
    parity_shards: 2,
};

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| ((idx as u32).wrapping_mul(29) ^ 0x5Au32) as u8)
        .collect()
}

async fn create_matrix_archive(
    temp_dir: &TempDir,
    name: &str,
    payload_len: usize,
    enable_checkpoint: bool,
) -> (PathBuf, Vec<u8>) {
    let archive_path = temp_dir.path().join(name);
    let payload = deterministic_payload(payload_len);

    let mut builder = ArchiveWriterBuilder::new(&archive_path)
        .password(PASSWORD)
        .enable_erasure(true)
        .erasure_config(ERASURE_4_PLUS_2)
        .volume_count(6);

    if enable_checkpoint {
        builder = builder.enable_checkpoint(true);
    }

    let mut writer = builder.build().await.unwrap();
    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    (archive_path, payload)
}

async fn corrupt_shard_header_field(volume_path: &Path, field_offset: u64, new_value: u32) {
    let backend = LocalStorageBackend::new(volume_path.parent().unwrap());
    let filename = volume_path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(filename))
        .await
        .unwrap();

    let (data_start, _) = reader.data_region();
    let header_offset = data_start + (ERASURE_4_PLUS_2.data_shards as u64 * 4) + field_offset;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(volume_path)
        .unwrap();
    file.seek(SeekFrom::Start(header_offset)).unwrap();
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf).unwrap();
    buf.copy_from_slice(&new_value.to_le_bytes());
    file.seek(SeekFrom::Start(header_offset)).unwrap();
    file.write_all(&buf).unwrap();
    file.flush().unwrap();
}

#[tokio::test]
async fn test_matrix_repair_with_checkpoint_boundary() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) =
        create_matrix_archive(&temp_dir, "matrix_ckpt.era", 512 * 1024, true).await;

    for i in 0..6 {
        let vol_path = if i == 0 {
            archive_path.clone()
        } else {
            archive_path.with_extension(format!("era.{:03}", i))
        };
        assert!(vol_path.exists(), "Volume {} missing", i);
    }

    let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
    let reader = VolumeReader::open(&backend, Path::new(archive_path.file_name().unwrap()))
        .await
        .unwrap();
    let footer = reader.footer().expect("footer should exist");
    assert!(
        footer.last_checkpoint_offset() > 0,
        "expected checkpoint in primary volume"
    );

    eprintln!("Opening archive for verify before repair...");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    eprintln!("Running verify before repair...");
    let verify_before = reader.verify().await.unwrap();
    eprintln!("Verify before: {:?}", verify_before);
    drop(reader);

    let vol1 = archive_path.with_extension("era.001");
    corrupt_shard_header_field(&vol1, 4, 0xDEAD_BEEF).await;

    eprintln!("Running repair...");
    let repair_stats = repair_archive_matrix(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert!(
        repair_stats.corrupted_shards_found > 0,
        "repair should detect injected corruption"
    );
    assert_eq!(
        repair_stats.unrecoverable_blocks, 0,
        "archive should be fully recoverable"
    );
    assert!(
        repair_stats.fully_repaired(),
        "repair should fully restore the archive"
    );

    eprintln!("REPAIR_STATS: {:?}", repair_stats);
    eprintln!("Opening archive for verify after repair...");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    eprintln!("Running verify after repair...");
    let verify_stats = reader.verify().await.unwrap();
    eprintln!("Verify after: {:?}", verify_stats);
    assert!(verify_stats.is_ok(), "archive should verify after repair");
    assert!(!verify_stats.needs_repair(), "no repair needed after fix");

    let extract_dir = temp_dir.path().join("extract");
    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(extract_dir.join("payload.bin")).unwrap(), payload);
}

#[tokio::test]
async fn test_matrix_repair_corrupted_data_shard_header_length_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) =
        create_matrix_archive(&temp_dir, "matrix_header.era", 256 * 1024, false).await;

    let strategy = era_common::MatrixDistributionStrategy::RotatingOffset;
    let vol_idx = strategy.calculate_volume(0, 0, 6).unwrap();
    assert_eq!(vol_idx, 0, "block 0 shard 0 should be on volume 0");

    let vol0 = &archive_path;
    // Damage the length field of the data-shard header. Repair uses the
    // stripe-prefix length as authoritative for data shards, so it must not
    // drift and must not report unrecoverable blocks.
    corrupt_shard_header_field(vol0, 0, 1024).await;

    let repair_stats = repair_archive_matrix(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        repair_stats.unrecoverable_blocks, 0,
        "must not drift or mis-advance offsets"
    );
    assert!(
        repair_stats.errors.is_empty(),
        "no repair errors: {:?}",
        repair_stats.errors
    );

    // Re-run repair: if offset advancement were wrong, the second pass
    // would encounter garbled data and report new problems.
    let second_pass = repair_archive_matrix(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        second_pass.unrecoverable_blocks, 0,
        "second pass must also be clean"
    );
    assert!(
        second_pass.errors.is_empty(),
        "second pass errors: {:?}",
        second_pass.errors
    );

    // End-to-end: verify and extract must succeed because the authoritative
    // stripe-prefix length prevents reader drift for data shards.
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert!(verify_stats.is_ok(), "must verify after repair");
    assert!(!verify_stats.needs_repair(), "must not need repair");

    let extract_dir = temp_dir.path().join("extract");
    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(extract_dir.join("payload.bin")).unwrap(), payload);
}

#[tokio::test]
async fn test_matrix_repair_large_layout_payload_corruption_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("matrix_large.era");
    let payload = deterministic_payload(16 * 1024 * 1024);

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password(PASSWORD)
        .enable_erasure(true)
        .erasure_config(ERASURE_4_PLUS_2)
        .volume_count(6)
        .build()
        .await
        .unwrap();

    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    let strategy = era_common::MatrixDistributionStrategy::RotatingOffset;
    let vol_idx = strategy.calculate_volume(0, 0, 6).unwrap();
    let vol0_path = if vol_idx == 0 {
        archive_path.clone()
    } else {
        archive_path.with_extension(format!("era.{:03}", vol_idx))
    };

    let backend = LocalStorageBackend::new(vol0_path.parent().unwrap());
    let reader = VolumeReader::open(&backend, Path::new(vol0_path.file_name().unwrap()))
        .await
        .unwrap();
    let (data_start, _) = reader.data_region();
    let header_prefix_len = ERASURE_4_PLUS_2.data_shards as u64 * 4;

    let header_bytes = reader
        .read_raw(
            data_start + header_prefix_len,
            era_common::ShardHeader::SIZE,
        )
        .await
        .unwrap();
    let shard_header = era_common::ShardHeader::from_bytes(&header_bytes).unwrap();

    let payload_offset = data_start + header_prefix_len + era_common::ShardHeader::SIZE as u64;
    let payload_len = shard_header.length as u64;

    let original_bytes = reader
        .read_raw(payload_offset, payload_len.min(1024) as usize)
        .await
        .unwrap();

    let corrupt_offset = payload_offset + (payload_len / 2);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&vol0_path)
        .unwrap();
    file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.flush().unwrap();
    drop(file);

    let repair_stats = repair_archive_matrix(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert!(
        repair_stats.corrupted_shards_found > 0,
        "repair should detect injected corruption"
    );
    assert_eq!(
        repair_stats.unrecoverable_blocks, 0,
        "archive should be fully recoverable"
    );

    let backend_after = LocalStorageBackend::new(vol0_path.parent().unwrap());
    let reader_after =
        VolumeReader::open(&backend_after, Path::new(vol0_path.file_name().unwrap()))
            .await
            .unwrap();
    let repaired_bytes = reader_after
        .read_raw(payload_offset, payload_len.min(1024) as usize)
        .await
        .unwrap();

    assert_eq!(
        repaired_bytes, original_bytes,
        "repaired bytes should exactly match original"
    );

    let mut archive_reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_stats = archive_reader.verify().await.unwrap();
    assert!(verify_stats.is_ok(), "archive should verify after repair");
    assert!(!verify_stats.needs_repair(), "should not need repair");

    let extract_dir = temp_dir.path().join("extract");
    archive_reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(
        fs::read(extract_dir.join("payload.bin")).unwrap(),
        payload,
        "extracted payload should match original"
    );
}

#[tokio::test]
async fn test_matrix_repair_cli_style_offset_5000_corruption() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("matrix_cli.era");
    let payload = deterministic_payload(128 * 1024 * 1024);

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password(PASSWORD)
        .enable_erasure(true)
        .erasure_config(ERASURE_4_PLUS_2)
        .volume_count(6)
        .build()
        .await
        .unwrap();

    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    let vol0_path = &archive_path;

    let backend = LocalStorageBackend::new(vol0_path.parent().unwrap());
    let reader = VolumeReader::open(&backend, Path::new(vol0_path.file_name().unwrap()))
        .await
        .unwrap();
    drop(reader);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(vol0_path)
        .unwrap();
    file.seek(SeekFrom::Start(5000)).unwrap();
    let mut buf = vec![0u8; 100];
    let n = file.read(&mut buf).unwrap();
    for b in &mut buf[..n] {
        *b = !*b;
    }
    file.seek(SeekFrom::Start(5000)).unwrap();
    file.write_all(&buf[..n]).unwrap();
    file.flush().unwrap();
    drop(file);

    let repair_stats = repair_archive_matrix(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        repair_stats.unrecoverable_blocks, 0,
        "archive should be fully recoverable"
    );

    let mut archive_reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_stats = archive_reader.verify().await.unwrap();
    assert!(verify_stats.is_ok(), "archive should verify after repair");
    assert!(!verify_stats.needs_repair(), "should not need repair");

    let extract_dir = temp_dir.path().join("extract");
    archive_reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(
        fs::read(extract_dir.join("payload.bin")).unwrap(),
        payload,
        "extracted payload should match original"
    );
}

#[tokio::test]
async fn test_matrix_repair_corrupted_parity_length_does_not_drift() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) =
        create_matrix_archive(&temp_dir, "matrix_parity.era", 256 * 1024, false).await;

    let strategy = era_common::MatrixDistributionStrategy::RotatingOffset;
    let vol_idx = strategy.calculate_volume(4, 0, 6).unwrap();
    assert_eq!(vol_idx, 4, "block 0 shard 4 should be on volume 4");

    let vol4 = archive_path.with_extension("era.004");
    corrupt_shard_header_field(&vol4, 0, 1).await;

    eprintln!("Starting parity repair...");
    let repair_stats = repair_archive_matrix(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();
    eprintln!("Parity repair stats: {:?}", repair_stats);

    assert_eq!(
        repair_stats.unrecoverable_blocks, 0,
        "archive should remain recoverable"
    );

    eprintln!("Opening for verify...");
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_stats = reader.verify().await.unwrap();
    assert!(verify_stats.is_ok(), "archive should verify");
    assert!(!verify_stats.needs_repair(), "should not need repair");

    let extract_dir = temp_dir.path().join("extract");
    reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(extract_dir.join("payload.bin")).unwrap(), payload);
}
