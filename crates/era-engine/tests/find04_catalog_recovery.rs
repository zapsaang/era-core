//! FIND-04: authenticated EC backup Catalog recovery through the public reader.

use era_common::{ArchiveConfig, BlockHeader, BlockType, CompressionAlgorithm, ErasureCodeConfig};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_volume::{Footer, FOOTER_SIZE};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "find04-catalog-recovery";
const MAX_CATALOG_CHUNK: usize = era_volume::MAX_SHARD_SIZE / 2;

struct CatalogLayout {
    primary_offset: u64,
    backup_offset: u64,
    primary_lengths: Vec<u32>,
    backup_lengths: Vec<u32>,
}

fn test_config() -> ArchiveConfig {
    let mut config = ArchiveConfig::default();
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.erasure = Some(ErasureCodeConfig::new(4, 2));
    config.compression.algorithm = CompressionAlgorithm::None;
    config
}

async fn create_ec_archive(path: &Path, names: &[String], payload: &[u8]) {
    let mut writer = ArchiveWriter::builder(path)
        .password(PASSWORD)
        .config(test_config())
        .enable_erasure(true)
        .erasure_config(ErasureCodeConfig::new(4, 2))
        .volume_count(1)
        .enable_small_file_packing(false)
        .build()
        .await
        .unwrap();
    for name in names {
        writer.add_bytes(name, payload).await.unwrap();
    }
    writer.finalize().await.unwrap();
}

async fn catalog_chunk_count(path: &Path) -> usize {
    let mut reader = ArchiveReader::open(path, PASSWORD).await.unwrap();
    let catalog_len = reader
        .load_catalog()
        .await
        .unwrap()
        .to_bytes()
        .unwrap()
        .len();
    catalog_len.div_ceil(MAX_CATALOG_CHUNK).max(1)
}

fn footer(bytes: &[u8]) -> Footer {
    Footer::from_bytes(&bytes[bytes.len() - FOOTER_SIZE..]).unwrap()
}

fn header_at(bytes: &[u8], offset: u64) -> BlockHeader {
    let start = usize::try_from(offset).unwrap();
    BlockHeader::from_bytes(&bytes[start..start + BlockHeader::SIZE]).unwrap()
}

fn read_copy_headers(bytes: &[u8], start: u64, count: usize) -> (Vec<BlockHeader>, u64) {
    let mut offset = start;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        let header = header_at(bytes, offset);
        assert_eq!(header.block_type, BlockType::Catalog);
        assert!(header.verify(
            &bytes[offset as usize + BlockHeader::SIZE
                ..offset as usize + BlockHeader::SIZE + header.length as usize]
        ));
        headers.push(header);
        offset += BlockHeader::SIZE as u64 + u64::from(header.length);
    }
    (headers, offset)
}

fn catalog_layout(path: &Path, chunk_count: usize) -> CatalogLayout {
    let bytes = fs::read(path).unwrap();
    let footer = footer(&bytes);
    let primary_offset = footer.catalog_offset();
    let (primary, backup_offset) = read_copy_headers(&bytes, primary_offset, chunk_count);
    let (backup, _) = read_copy_headers(&bytes, backup_offset, chunk_count);
    CatalogLayout {
        primary_offset,
        backup_offset,
        primary_lengths: primary.iter().map(|header| header.length).collect(),
        backup_lengths: backup.iter().map(|header| header.length).collect(),
    }
}

fn flip_payload_byte(path: &Path, block_offset: u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let offset = block_offset + BlockHeader::SIZE as u64 + 24;
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
}

#[tokio::test]
async fn find04_single_chunk_ec_backup_restores_catalog_verify_and_extract() {
    // Given: a single-volume EC archive with two independently encrypted Catalog blocks.
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("single.era");
    let names = vec!["payload.txt".to_string()];
    let payload = b"recover the catalog from its authenticated backup";
    create_ec_archive(&archive_path, &names, payload).await;
    assert_eq!(catalog_chunk_count(&archive_path).await, 1);
    let layout = catalog_layout(&archive_path, 1);
    assert_eq!(layout.primary_lengths.len(), 1);
    assert_eq!(layout.backup_lengths.len(), 1);

    // When: the primary payload fails block CRC and AEAD processing.
    flip_payload_byte(&archive_path, layout.primary_offset);

    // Then: the backup loads the real Catalog, verification reports degradation, and extraction works.
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    assert!(reader.manifest().is_some());
    let catalog = reader.load_catalog().await.unwrap();
    assert_eq!(catalog.entries[0].path, Path::new("payload.txt"));
    let stats = reader.verify().await.unwrap();
    assert!(stats.is_ok());
    assert!(stats.is_degraded());
    assert_eq!(stats.warnings.len(), 1);
    assert!(stats.errors.is_empty());

    let output_dir = temp_dir.path().join("output");
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(output_dir.join("payload.txt")).unwrap(), payload);
}

#[tokio::test]
async fn find04_multi_chunk_ec_backup_uses_actual_block_spans() {
    // Given: a Catalog large enough to require multiple blocks with different encoded lengths.
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("multi.era");
    let names: Vec<String> = (0..55_000)
        .map(|index| format!("entry-{index:06}-{}", "x".repeat(180)))
        .collect();
    create_ec_archive(&archive_path, &names, b"x").await;
    let chunk_count = catalog_chunk_count(&archive_path).await;
    assert!(
        chunk_count > 1,
        "fixture must produce a multi-chunk Catalog"
    );
    let layout = catalog_layout(&archive_path, chunk_count);
    assert!(layout
        .primary_lengths
        .iter()
        .any(|length| *length != layout.primary_lengths[0]));
    assert_eq!(layout.primary_lengths.len(), chunk_count);
    assert_eq!(layout.backup_lengths.len(), chunk_count);

    // When: the primary first block is damaged before any chunk count is authenticated.
    flip_payload_byte(&archive_path, layout.primary_offset);

    // Then: the complete backup group is recovered and degradation is observable.
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    assert!(reader.manifest().is_some());
    let catalog = reader.load_catalog().await.unwrap();
    assert_eq!(catalog.entries.len(), names.len());
    assert_eq!(catalog.file_count, names.len() as u64);
    let stats = reader.verify().await.unwrap();
    assert!(stats.is_ok());
    assert!(stats.is_degraded());
    assert_eq!(stats.warnings.len(), 1);
    assert!(stats.errors.is_empty());
}

#[tokio::test]
async fn find04_ec_catalog_fails_closed_when_both_copies_are_damaged() {
    // Given: a single-volume EC archive with independently located Catalog copies.
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("dual-failure.era");
    let names = vec!["payload.txt".to_string()];
    create_ec_archive(&archive_path, &names, b"payload").await;
    let layout = catalog_layout(&archive_path, 1);

    // When: both encrypted copies fail integrity checks.
    flip_payload_byte(&archive_path, layout.primary_offset);
    flip_payload_byte(&archive_path, layout.backup_offset);

    // Then: neither direct loading nor full verification accepts the archive.
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    reader
        .load_catalog()
        .await
        .expect_err("damaged primary and backup Catalog copies must fail closed");
    assert!(reader.catalog().is_none());
    reader
        .verify()
        .await
        .expect_err("verification must not succeed without an authenticated Catalog");
}
