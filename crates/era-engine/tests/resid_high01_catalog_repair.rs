//! RESID-HIGH-01: repair must restore damaged primary Catalog copies.

use era_common::{ArchiveConfig, BlockHeader, BlockType, CompressionAlgorithm, ErasureCodeConfig};
use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RepairOptions};
use era_volume::{volume_path, Footer, FOOTER_SIZE};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "resid-high01-catalog-repair";
const PAYLOAD: &[u8] = b"catalog repair must preserve payload bytes";
const MATRIX_VOLUMES: u16 = 6;

struct CatalogLayout {
    primary: Vec<u64>,
    backup: Vec<u64>,
}

async fn create_archive(path: &Path, names: &[String], volume_count: usize) {
    let mut config = ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.erasure = Some(ErasureCodeConfig::new(4, 2));
    config.compression.algorithm = CompressionAlgorithm::Zstd;

    let mut writer = ArchiveWriter::builder(path)
        .password(PASSWORD)
        .config(config)
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig::new(4, 2))
        .volume_count(volume_count)
        .max_volume_size(1024 * 1024)
        .enable_cdc(false)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    for name in names {
        writer.add_bytes(name, PAYLOAD).await.unwrap();
    }
    writer.finalize().await.unwrap();
}

fn split_catalog_names() -> Vec<String> {
    let segment = "m".repeat(220);
    let prefix = (0..10)
        .map(|_| segment.as_str())
        .collect::<Vec<_>>()
        .join("/");
    (0..500)
        .map(|index| format!("{prefix}/{index:03}_{}.bin", "x".repeat(180)))
        .collect()
}

fn header_at(bytes: &[u8], offset: u64) -> BlockHeader {
    let start = usize::try_from(offset).unwrap();
    BlockHeader::from_bytes(&bytes[start..start + BlockHeader::SIZE]).unwrap()
}

fn copy_headers(bytes: &[u8], start: u64, count: usize) -> (Vec<u64>, u64) {
    let mut offset = start;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        let header = header_at(bytes, offset);
        assert_eq!(header.block_type, BlockType::Catalog);
        let payload_start = usize::try_from(offset).unwrap() + BlockHeader::SIZE;
        let payload_end = payload_start + usize::try_from(header.length).unwrap();
        assert!(header.verify(&bytes[payload_start..payload_end]));
        offsets.push(offset);
        offset += u64::try_from(BlockHeader::SIZE).unwrap() + u64::from(header.length);
    }
    (offsets, offset)
}

fn catalog_layout(path: &Path, chunk_count: usize) -> CatalogLayout {
    let bytes = fs::read(path).unwrap();
    let footer = Footer::from_bytes(&bytes[bytes.len() - FOOTER_SIZE..]).unwrap();
    let (primary, backup_offset) = copy_headers(&bytes, footer.catalog_offset(), chunk_count);
    let (backup, _) = copy_headers(&bytes, backup_offset, chunk_count);
    CatalogLayout { primary, backup }
}

// The same ordinary payload corruption used by find04_catalog_recovery.
fn flip_payload_byte(path: &Path, block_offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let offset = block_offset + u64::try_from(BlockHeader::SIZE).unwrap() + 24;
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
}

fn damage_blocks(path: &Path, offsets: &[u64]) {
    for &offset in offsets {
        flip_payload_byte(path, offset);
    }
}

async fn assert_backup_recovery(path: &Path, names: &[String]) {
    let mut reader = ArchiveReader::open(path, PASSWORD).await.unwrap();
    assert!(reader.manifest().is_some());
    assert_eq!(
        reader.load_catalog().await.unwrap().entries.len(),
        names.len()
    );
    let stats = reader.verify().await.unwrap();
    assert!(stats.is_ok());
    assert!(
        stats.is_degraded(),
        "intact EC backup must be the recovery source"
    );
    assert_eq!(stats.warnings.len(), 1);
    assert!(stats.errors.is_empty());
}

async fn assert_healthy_and_extract(path: &Path, output: &Path, names: &[String]) {
    let mut reader = ArchiveReader::open(path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_healthy(),
        "fresh verification must be Healthy: {stats:?}"
    );
    assert!(stats.warnings.is_empty());
    assert!(stats.errors.is_empty());

    let extracted = reader
        .extract_all(&ExtractOptions::new(output))
        .await
        .unwrap();
    assert_eq!(extracted.extracted, u64::try_from(names.len()).unwrap());
    for name in names {
        assert_eq!(fs::read(output.join(name)).unwrap(), PAYLOAD);
    }
}

async fn repair(path: &Path) {
    repair_archive(
        path,
        PASSWORD,
        RepairOptions {
            create_backup: false,
            dry_run: false,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn resid_high01_single_catalog_repair_restores_health_and_extract() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("single.era");
    let names = vec!["payload.txt".to_string()];
    create_archive(&archive_path, &names, 1).await;
    let layout = catalog_layout(&archive_path, 1);
    damage_blocks(&archive_path, &layout.primary);
    assert_backup_recovery(&archive_path, &names).await;

    repair(&archive_path).await;

    assert_healthy_and_extract(&archive_path, &temp_dir.path().join("output"), &names).await;
}

#[tokio::test]
async fn resid_high01_split_catalog_repair_restores_health_and_extract() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("split.era");
    let names = split_catalog_names();
    create_archive(&archive_path, &names, 1).await;
    let original = fs::read(&archive_path).unwrap();
    let layout = catalog_layout(&archive_path, 2);
    damage_blocks(&archive_path, &layout.primary);
    assert_backup_recovery(&archive_path, &names).await;

    repair(&archive_path).await;

    assert!(fs::read(&archive_path).unwrap() == original);
    assert_healthy_and_extract(&archive_path, &temp_dir.path().join("output"), &names).await;
}

#[tokio::test]
async fn resid_high01_catalog_repair_dry_run_preserves_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("dry-run.era");
    let names = vec!["payload.txt".to_string()];
    create_archive(&archive_path, &names, 1).await;
    let layout = catalog_layout(&archive_path, 1);
    damage_blocks(&archive_path, &layout.primary);
    assert_backup_recovery(&archive_path, &names).await;
    let damaged = fs::read(&archive_path).unwrap();
    let backup_path = archive_path.with_extension("era.bak");

    repair_archive(
        &archive_path,
        PASSWORD,
        RepairOptions {
            create_backup: true,
            dry_run: true,
            continue_on_error: true,
        },
    )
    .await
    .unwrap();

    assert_eq!(fs::read(&archive_path).unwrap(), damaged);
    assert!(!backup_path.exists());
    assert_backup_recovery(&archive_path, &names).await;
}

async fn assert_matrix_candidate_repair(damaged_sequence: u16) {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("matrix.era");
    let names = vec!["payload.txt".to_string()];
    create_archive(&archive_path, &names, usize::from(MATRIX_VOLUMES)).await;
    let layouts = (0..MATRIX_VOLUMES)
        .map(|sequence| catalog_layout(&volume_path(&archive_path, sequence), 1))
        .collect::<Vec<_>>();
    let damaged_path = volume_path(&archive_path, damaged_sequence);
    damage_blocks(
        &damaged_path,
        &layouts[usize::from(damaged_sequence)].primary,
    );

    // Partial multi-volume primary Catalog damage must be reported as Degraded so repair runs.
    {
        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let stats = reader.verify().await.unwrap();
        assert!(stats.is_ok(), "sibling catalog copies remain readable");
        assert!(
            stats.is_degraded(),
            "damaged primary Catalog on volume {damaged_sequence} must report Degraded, got {:?}",
            stats.archive_health
        );
        assert_eq!(stats.warnings.len(), 1);
        assert!(
            stats.warnings[0].contains(&format!("Volume {damaged_sequence}")),
            "expected warning for Volume {damaged_sequence}, got {:?}",
            stats.warnings
        );
        assert!(stats.errors.is_empty());

        let before_dir = temp_dir.path().join("before");
        let extracted = reader
            .extract_all(&ExtractOptions::new(&before_dir))
            .await
            .unwrap();
        assert_eq!(extracted.extracted, u64::try_from(names.len()).unwrap());
        for name in &names {
            assert_eq!(fs::read(before_dir.join(name)).unwrap(), PAYLOAD);
        }
    }

    repair(&archive_path).await;
    assert_healthy_and_extract(&archive_path, &temp_dir.path().join("repaired"), &names).await;

    for (sequence, layout) in (0..MATRIX_VOLUMES).zip(&layouts) {
        if sequence != damaged_sequence {
            let sibling = volume_path(&archive_path, sequence);
            damage_blocks(&sibling, &layout.primary);
            damage_blocks(&sibling, &layout.backup);
        }
    }

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    assert_eq!(
        reader.load_catalog().await.unwrap().entries.len(),
        names.len(),
        "repaired primary Catalog on volume {damaged_sequence} must work standalone"
    );
    let stats = reader.verify().await.unwrap();
    assert!(stats.is_ok());
    assert!(stats.is_degraded());
    assert_eq!(stats.warnings.len(), usize::from(MATRIX_VOLUMES - 1));
    assert!(stats.errors.is_empty());
    let after_dir = temp_dir.path().join("after");
    let extracted = reader
        .extract_all(&ExtractOptions::new(&after_dir))
        .await
        .unwrap();
    assert_eq!(extracted.extracted, u64::try_from(names.len()).unwrap());
    for name in &names {
        assert_eq!(fs::read(after_dir.join(name)).unwrap(), PAYLOAD);
    }
}

#[tokio::test]
async fn resid_high01_matrix_repairs_first_catalog_candidate_independently() {
    assert_matrix_candidate_repair(0).await;
}

#[tokio::test]
async fn resid_high01_matrix_repairs_second_catalog_candidate_independently() {
    assert_matrix_candidate_repair(1).await;
}
