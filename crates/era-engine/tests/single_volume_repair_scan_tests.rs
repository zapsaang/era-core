use era_common::{ErasureCodeConfig, ShardHeader};
use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RepairOptions};
use era_storage::LocalStorageBackend;
use era_volume::VolumeReader;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &str = "single-volume-repair";
const ERASURE_4_PLUS_2: ErasureCodeConfig = ErasureCodeConfig {
    data_shards: 4,
    parity_shards: 2,
};

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| ((idx as u32).wrapping_mul(29) ^ 0x5Au32) as u8)
        .collect()
}

fn archive_volume_paths(base_path: &Path) -> Vec<PathBuf> {
    let parent = base_path.parent().unwrap_or_else(|| Path::new("."));
    let base_name = base_path.file_name().unwrap().to_string_lossy().to_string();
    let mut paths: Vec<_> = fs::read_dir(parent)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .map(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with(&base_name) && !name.ends_with(".idx")
                })
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    paths
}

async fn create_erasure_archive(
    temp_dir: &TempDir,
    name: &str,
    payload_len: usize,
    volume_count: Option<usize>,
) -> (PathBuf, Vec<u8>) {
    let archive_path = temp_dir.path().join(name);
    let payload = deterministic_payload(payload_len);

    let mut builder = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .erasure_config(ERASURE_4_PLUS_2)
        .enable_small_file_packing(false);

    if let Some(volume_count) = volume_count {
        builder = builder.volume_count(volume_count);
    }

    let mut writer = builder.build().await.unwrap();
    writer.add_bytes("payload.bin", &payload).await.unwrap();
    writer.finalize().await.unwrap();

    (archive_path, payload)
}

async fn corrupt_first_shard_payload(archive_path: &Path) {
    let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
    let volume_path = archive_path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(volume_path))
        .await
        .unwrap();
    let (data_start, _) = reader.data_region();
    let header_prefix_len = ERASURE_4_PLUS_2.data_shards as u64 * 4;
    let header_bytes = reader
        .read_raw(data_start + header_prefix_len, ShardHeader::SIZE)
        .await
        .unwrap();
    let shard_header = ShardHeader::from_bytes(&header_bytes).expect("valid shard header");
    let corrupt_offset = data_start
        + header_prefix_len
        + ShardHeader::SIZE as u64
        + (shard_header.length as u64 / 2);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive_path)
        .unwrap();
    file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
    file.write_all(&byte).unwrap();
}

fn corrupt_byte_range(path: &Path, offset: u64, len: usize) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).unwrap();
    for byte in &mut bytes {
        *byte ^= 0xFF;
    }
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&bytes).unwrap();
}

async fn corrupt_single_volume_shard_prefix(archive_path: &Path, new_shard_0_length: u32) {
    let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
    let volume_path = archive_path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(volume_path))
        .await
        .unwrap();
    let (data_start, _) = reader.data_region();

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive_path)
        .unwrap();
    file.seek(SeekFrom::Start(data_start)).unwrap();
    file.write_all(&new_shard_0_length.to_le_bytes()).unwrap();
    file.flush().unwrap();
}

#[tokio::test]
async fn test_single_volume_erasure_archive_stays_single_file() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) =
        create_erasure_archive(&temp_dir, "single_volume_ec.era", 96 * 1024, Some(1)).await;

    let volume_paths = archive_volume_paths(&archive_path);
    assert_eq!(volume_paths, vec![archive_path.clone()]);

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    assert_eq!(reader.header().volume_sequence(), 0);
    assert_eq!(reader.header().total_volumes(), 1);

    let verify_stats = reader.verify().await.unwrap();
    assert!(
        verify_stats.is_ok(),
        "single-volume EC archive should verify"
    );
    assert!(
        verify_stats.is_healthy(),
        "single-volume EC archive should be healthy"
    );

    let extract_dir = temp_dir.path().join("single_extract");
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(extract_stats.extracted, 1);
    assert_eq!(fs::read(extract_dir.join("payload.bin")).unwrap(), payload);
}

#[tokio::test]
async fn test_default_erasure_archive_uses_multi_volume_layout() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) =
        create_erasure_archive(&temp_dir, "default_multi_volume.era", 96 * 1024, None).await;

    let volume_paths = archive_volume_paths(&archive_path);
    assert_eq!(
        volume_paths.len(),
        6,
        "default 4+2 EC should create 6 volume files"
    );
    assert!(
        volume_paths
            .iter()
            .any(|path| path.ends_with("default_multi_volume.era.001")),
        "default multi-volume layout should create secondary volume files"
    );

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    assert_eq!(reader.header().volume_sequence(), 0);
    assert_eq!(reader.header().total_volumes(), 6);

    let verify_stats = reader.verify().await.unwrap();
    assert!(
        verify_stats.is_ok(),
        "default multi-volume EC archive should verify"
    );
    assert!(
        verify_stats.is_healthy(),
        "default multi-volume EC archive should be healthy"
    );

    let extract_dir = temp_dir.path().join("default_extract");
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(extract_stats.extracted, 1);
    assert_eq!(fs::read(extract_dir.join("payload.bin")).unwrap(), payload);
}

#[tokio::test]
async fn test_single_volume_repair_roundtrip_repro() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) =
        create_erasure_archive(&temp_dir, "single_volume_repair.era", 128 * 1024, Some(1)).await;

    corrupt_first_shard_payload(&archive_path).await;

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_before_repair = reader.verify().await.unwrap();
    drop(reader);

    assert!(
        verify_before_repair.is_ok(),
        "RS recovery should keep archive readable"
    );
    assert!(
        verify_before_repair.has_warnings(),
        "corrupted single-volume shard should surface repair-needed warnings"
    );
    assert!(
        verify_before_repair.needs_repair(),
        "corrupted single-volume shard should require repair before roundtrip is clean"
    );

    let repair_stats = repair_archive(
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
        "repair should detect the injected shard corruption"
    );
    assert_eq!(repair_stats.unrecoverable_blocks, 0);
    assert!(
        repair_stats.fully_repaired(),
        "repair should fully restore the archive"
    );

    let mut repaired_reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_after_repair = repaired_reader.verify().await.unwrap();
    assert!(
        verify_after_repair.is_ok(),
        "archive should verify after repair"
    );
    assert!(
        !verify_after_repair.has_warnings(),
        "warnings should be gone after successful single-volume repair"
    );
    assert!(
        !verify_after_repair.needs_repair(),
        "post-repair archive should no longer report repair-needed state"
    );

    let extract_dir = temp_dir.path().join("repaired_extract");
    let extract_stats = repaired_reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(extract_stats.extracted, 1);
    assert_eq!(fs::read(extract_dir.join("payload.bin")).unwrap(), payload);
}

#[tokio::test]
async fn test_single_volume_footer_boundaries_show_catalog_inside_data_region() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, _) =
        create_erasure_archive(&temp_dir, "single_volume_footer.era", 128 * 1024, Some(1)).await;

    let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
    let volume_path = archive_path.file_name().unwrap();
    let reader = VolumeReader::open(&backend, Path::new(volume_path))
        .await
        .unwrap();

    let footer = reader
        .footer()
        .expect("single-volume archive should have footer");
    let (data_start, data_end) = reader.data_region();

    assert_eq!(data_end, footer.data_end_offset());
    assert!(footer.data_end_offset() > data_start);
    assert!(
        footer.catalog_offset() < footer.data_end_offset(),
        "catalog block should live inside the data region, before data_end_offset"
    );
}

#[tokio::test]
async fn test_single_volume_repair_exact_offset_5000_release_style_repro() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) = create_erasure_archive(
        &temp_dir,
        "single_volume_offset_5000.era",
        8 * 1024 * 1024,
        Some(1),
    )
    .await;

    corrupt_byte_range(&archive_path, 5000, 100);

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_before_repair = reader.verify().await.unwrap();
    drop(reader);

    assert!(
        verify_before_repair.is_ok(),
        "archive should remain readable via RS recovery"
    );
    assert!(
        verify_before_repair.needs_repair(),
        "corruption at offset 5000 should require repair"
    );

    let repair_stats = repair_archive(
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

    assert!(repair_stats.corrupted_shards_found > 0);
    assert_eq!(repair_stats.unrecoverable_blocks, 0);

    let mut repaired_reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let verify_after_repair = repaired_reader.verify().await.unwrap();
    assert!(
        verify_after_repair.is_ok(),
        "archive should verify after repair"
    );
    assert!(!verify_after_repair.needs_repair());

    let extract_dir = temp_dir.path().join("offset_5000_extract");
    repaired_reader
        .extract_all(&ExtractOptions::new(&extract_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(extract_dir.join("payload.bin")).unwrap(), payload);
}

#[tokio::test]
async fn test_single_volume_repair_reconciles_corrupted_first_prefix_copy() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) =
        create_erasure_archive(&temp_dir, "single_prefix.era", 128 * 1024, Some(1)).await;

    // Corrupt the prefix copy on shard 0 to a bogus in-bounds length.
    // The true length is larger; trusting this prefix would cause offset drift.
    corrupt_single_volume_shard_prefix(&archive_path, 1024).await;

    let repair_stats = repair_archive(
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
        "must not drift or report unrecoverable blocks"
    );
    assert!(
        repair_stats.errors.is_empty(),
        "no repair errors: {:?}",
        repair_stats.errors
    );

    let second_pass = repair_archive(
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
async fn test_single_volume_repair_does_not_trust_non_consensus_prefixes() {
    let temp_dir = TempDir::new().unwrap();
    let (archive_path, payload) = create_erasure_archive(
        &temp_dir,
        "single_prefix_consensus.era",
        128 * 1024,
        Some(1),
    )
    .await;

    {
        let backend = LocalStorageBackend::new(archive_path.parent().unwrap());
        let volume_path = archive_path.file_name().unwrap();
        let reader = VolumeReader::open(&backend, Path::new(volume_path))
            .await
            .unwrap();
        let (data_start, _) = reader.data_region();
        let header_prefix_len = ERASURE_4_PLUS_2.data_shards as u64 * 4;
        let mut offset = data_start;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive_path)
            .unwrap();

        for shard_idx in 0..(ERASURE_4_PLUS_2.data_shards + ERASURE_4_PLUS_2.parity_shards) {
            file.seek(SeekFrom::Start(offset)).unwrap();
            let bogus_len = 1024u32 * (shard_idx as u32 + 1);
            file.write_all(&bogus_len.to_le_bytes()).unwrap();

            let header_bytes = reader
                .read_raw(offset + header_prefix_len, ShardHeader::SIZE)
                .await
                .unwrap();
            let shard_header = ShardHeader::from_bytes(&header_bytes).expect("valid shard header");
            offset += header_prefix_len + ShardHeader::SIZE as u64 + shard_header.length as u64;
        }
        file.flush().unwrap();
    }

    let repair_stats = repair_archive(
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
        "must fall back to headers and not drift"
    );
    assert!(
        repair_stats.errors.is_empty(),
        "no repair errors: {:?}",
        repair_stats.errors
    );

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
