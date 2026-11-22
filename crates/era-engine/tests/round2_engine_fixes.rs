//! Round 2 audit revision: behavioral regression tests for R2-02, R2-05 and R2-08.
//!
//! R2-02: when both canonical footer copies are damaged but a floating reverse-scan
//! recovers the footer, repair used to report success without writing anything, so
//! verification stayed degraded forever. Repair must rewrite both canonical copies from
//! the floating footer (truncating trailing garbage when the recovered footer describes
//! the canonical finalized layout), and must return an error when the layout cannot be
//! safely rebuilt.
//!
//! R2-05: coverage gaps - multi-volume/EC footer repair, repair dry-run not writing,
//! multi-volume authenticated header adoption.
//!
//! R2-08: a parseable tamper of a header field that participates in the manifest AAD
//! (archive_id/epoch_id) makes manifest decryption fail before digest-based adoption is
//! reachable. Opening must retry once with the reserved backup header.

use era_common::{ArchiveConfig, CompressionAlgorithm, EraError, ErasureCodeConfig};
use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, ExtractOptions, RepairOptions};
use era_storage::{LocalStorageBackend, LocalStorageReader};
use era_volume::{
    volume_path, Footer, SuperHeader, VolumeReader, DATA_REGION_START, FOOTER_SIZE, HEADER_SIZE,
};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &str = "round2-engine-fixes";
const BLOCK_SIZE: usize = 512 * 1024;
const MAX_VOLUME_SIZE: u64 = 1024 * 1024;

fn fast_config(
    erasure: Option<ErasureCodeConfig>,
    compression: CompressionAlgorithm,
) -> ArchiveConfig {
    let mut config = ArchiveConfig {
        erasure,
        ..Default::default()
    };
    config.encryption.kdf_memory_cost = 1024;
    config.encryption.kdf_time_cost = 1;
    config.compression.algorithm = compression;
    config
}

fn repair_options() -> RepairOptions {
    RepairOptions {
        create_backup: false,
        dry_run: false,
        continue_on_error: true,
    }
}

fn dry_run_options() -> RepairOptions {
    RepairOptions {
        create_backup: false,
        dry_run: true,
        continue_on_error: true,
    }
}

fn read_range(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let mut file = OpenOptions::new().read(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).unwrap();
    buf
}

fn write_range(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 37) % 251) as u8).collect()
}

async fn create_single_volume_non_ec(dir: &Path, name: &str, payload: &[u8]) -> PathBuf {
    let path = dir.join(name);
    let mut writer = ArchiveWriter::builder(&path)
        .password(PASSWORD)
        .config(fast_config(None, CompressionAlgorithm::None))
        .enable_erasure(false)
        .volume_count(1)
        .build()
        .await
        .unwrap();
    writer.add_bytes("payload.bin", payload).await.unwrap();
    writer.finalize().await.unwrap();
    path
}

/// Returns the end offset of the length-delimited protobuf payload inside a header;
/// bytes after this offset are zero padding that the parser tolerates.
fn length_delimited_end(data: &[u8]) -> usize {
    let mut shift = 0usize;
    let mut len = 0usize;
    let mut idx = 0usize;
    loop {
        let byte = data[idx];
        idx += 1;
        len |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        assert!(shift <= 63, "varint length prefix too long");
    }
    idx + len
}

async fn open_volume(archive_path: &Path, sequence: u16) -> VolumeReader<LocalStorageReader> {
    let path = volume_path(archive_path, sequence);
    let backend = LocalStorageBackend::new(path.parent().unwrap());
    VolumeReader::open(&backend, Path::new(path.file_name().unwrap()))
        .await
        .unwrap()
}

fn header_padding_tamper(header: &[u8]) -> Vec<u8> {
    let mut tampered = header.to_vec();
    let padding_start = length_delimited_end(&tampered);
    assert!(padding_start + 1 < HEADER_SIZE, "header must have padding");
    assert_eq!(
        tampered[padding_start], 0,
        "first padding byte must be zero"
    );
    tampered[padding_start] = 0x01;
    assert!(
        SuperHeader::from_bytes(&tampered).is_ok(),
        "tampered header must still parse; the digest check must be what rejects it"
    );
    tampered
}

/// R2-02: primary footer buried by trailing garbage + reserved backup footer zeroed.
/// A floating reverse scan still finds the intact primary footer, so repair must
/// rewrite both canonical copies, truncate the garbage tail and converge to Healthy.
#[tokio::test]
async fn floating_footer_double_damage_is_repaired_and_converges() {
    let temp = TempDir::new().unwrap();
    let payload = payload(64 * 1024);
    let path = create_single_volume_non_ec(temp.path(), "floating.era", &payload).await;
    let original_size = fs::metadata(&path).unwrap().len();
    let original_primary = read_range(&path, original_size - FOOTER_SIZE as u64, FOOTER_SIZE);
    assert!(
        Footer::from_bytes(&original_primary).is_ok(),
        "baseline primary footer must parse"
    );

    // Damage both canonical copies and bury the primary under appended garbage.
    write_range(&path, HEADER_SIZE as u64, &[0u8; FOOTER_SIZE]);
    append_bytes(&path, &[0x5Au8; 512]);
    let damaged_size = fs::metadata(&path).unwrap().len();
    assert_eq!(damaged_size, original_size + 512);

    // The floating footer keeps the archive readable but degraded.
    {
        let mut reader = ArchiveReader::open(&path, PASSWORD)
            .await
            .expect("floating footer must keep the archive readable");
        let stats = reader.verify().await.unwrap();
        assert!(
            stats.is_degraded(),
            "damaged footer redundancy must be reported as degraded, got {:?}",
            stats.archive_health
        );
        assert!(stats.warnings.iter().any(|w| w.contains("footer")));
    }

    // R2-02 regression: repair must not claim success without repairing.
    repair_archive(&path, PASSWORD, repair_options())
        .await
        .expect("repairable floating footer must be restored");

    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        original_size,
        "repair must truncate the trailing garbage so the canonical layout holds"
    );
    let primary = read_range(&path, original_size - FOOTER_SIZE as u64, FOOTER_SIZE);
    let backup = read_range(&path, HEADER_SIZE as u64, FOOTER_SIZE);
    assert_eq!(
        primary, backup,
        "repaired primary and reserved footer copies must be byte-identical"
    );
    assert!(Footer::from_bytes(&primary).is_ok());
    assert_eq!(
        primary, original_primary,
        "repair must restore the exact floating footer bytes"
    );

    let mut reader = ArchiveReader::open(&path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_healthy(),
        "repaired archive must verify Healthy, got {:?} ({:?})",
        stats.archive_health,
        stats.warnings
    );
    let out_dir = temp.path().join("out");
    reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(out_dir.join("payload.bin")).unwrap(), payload);
}

/// R2-02: when the floating footer does not describe a canonical finalized layout, no
/// footer can be safely rebuilt; repair must fail instead of reporting success.
#[tokio::test]
async fn unrepairable_floating_footer_layout_fails_repair() {
    let temp = TempDir::new().unwrap();
    let payload = payload(64 * 1024);
    let path = create_single_volume_non_ec(temp.path(), "unrepairable.era", &payload).await;
    let original_size = fs::metadata(&path).unwrap().len();
    let original = Footer::from_bytes(&read_range(
        &path,
        original_size - FOOTER_SIZE as u64,
        FOOTER_SIZE,
    ))
    .unwrap();

    // Destroy both canonical copies.
    write_range(&path, HEADER_SIZE as u64, &[0u8; FOOTER_SIZE]);
    write_range(
        &path,
        original_size - FOOTER_SIZE as u64,
        &[0u8; FOOTER_SIZE],
    );

    // Plant a footer with a non-canonical layout (data_end_offset != backup_header_offset)
    // inside trailing garbage so the floating scan finds it. Catalog/manifest locations are
    // preserved so the archive still opens and verification still succeeds with warnings.
    let crafted = Footer::builder(
        original.data_end_offset() + FOOTER_SIZE as u64,
        original.block_count(),
        original.sequence_number(),
    )
    .catalog(
        original.catalog_offset(),
        original.catalog_size(),
        original.catalog_block_id(),
    )
    .checkpoint(
        original.last_checkpoint_offset(),
        original.last_checkpoint_block_id(),
    )
    .manifest(original.manifest_offset(), original.manifest_block_id())
    .index(
        original.index_offset(),
        original.index_size(),
        original.index_block_id(),
    )
    .build();
    append_bytes(&path, &[0u8; FOOTER_SIZE]);
    append_bytes(&path, &crafted.to_bytes().unwrap());
    append_bytes(&path, &[0u8; 256]);

    // The floating footer still lets the archive open (degraded).
    {
        let mut reader = ArchiveReader::open(&path, PASSWORD)
            .await
            .expect("floating footer must keep the archive readable");
        let stats = reader.verify().await.unwrap();
        assert!(stats.is_degraded());
    }

    let err = repair_archive(&path, PASSWORD, repair_options())
        .await
        .expect_err("a non-canonical floating footer layout must not report success");
    assert!(
        matches!(err, EraError::IntegrityError(_)),
        "expected IntegrityError for unrecoverable footer redundancy, got {err:?}"
    );
}

/// R2-05(b): repair dry-run must not write or truncate the volume, including when the
/// plan comes from a floating footer (which involves trailing-garbage truncation).
#[tokio::test]
async fn dry_run_floating_footer_repair_does_not_touch_volume() {
    let temp = TempDir::new().unwrap();
    let payload = payload(64 * 1024);
    let path = create_single_volume_non_ec(temp.path(), "dry_run.era", &payload).await;
    write_range(&path, HEADER_SIZE as u64, &[0u8; FOOTER_SIZE]);
    append_bytes(&path, &[0x33u8; 512]);
    let before = fs::read(&path).unwrap();

    repair_archive(&path, PASSWORD, dry_run_options())
        .await
        .expect("dry-run repair must report the planned floating-footer repair");

    let after = fs::read(&path).unwrap();
    assert_eq!(
        before, after,
        "dry-run footer repair must not write or truncate the volume"
    );
}

/// R2-05(a): fixed-size 12-volume EC archive footer repair through the matrix path.
#[tokio::test]
async fn twelve_volume_ec_footer_repair_restores_health() {
    let temp = TempDir::new().unwrap();
    let archive_path = temp.path().join("twelve.era");
    let files: Vec<(String, Vec<u8>)> = (1..=4u8)
        .map(|i| (format!("payload-{i}.bin"), vec![i; 640 * 1024]))
        .collect();
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(fast_config(
            Some(ErasureCodeConfig {
                data_shards: 4,
                parity_shards: 2,
            }),
            CompressionAlgorithm::None,
        ))
        .enable_erasure(true)
        .volume_count(12)
        .max_volume_size(MAX_VOLUME_SIZE)
        .target_block_size(640 * 1024)
        .enable_cdc(false)
        .build()
        .await
        .unwrap();
    for (name, bytes) in &files {
        writer.add_bytes(name, bytes).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let total = open_volume(&archive_path, 0).await.header().total_volumes();
    assert_eq!(
        total, 12,
        "fixture must produce exactly 12 fixed-size EC volumes (got {total})"
    );

    // Damage the reserved backup footer of a non-first volume.
    let damaged_sequence = 1u16;
    let damaged_path = volume_path(&archive_path, damaged_sequence);
    let damaged_size = fs::metadata(&damaged_path).unwrap().len();
    write_range(&damaged_path, HEADER_SIZE as u64, &[0xEEu8; FOOTER_SIZE]);

    {
        let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
        let stats = reader.verify().await.unwrap();
        assert!(
            stats.is_degraded(),
            "damaged backup footer must degrade the archive, got {:?}",
            stats.archive_health
        );
        assert!(
            stats.warnings.iter().any(|w| w.contains("footer")),
            "warning must mention the damaged footer: {:?}",
            stats.warnings
        );
    }

    repair_archive(&archive_path, PASSWORD, repair_options())
        .await
        .expect("matrix repair must restore the damaged footer");

    let primary = read_range(
        &damaged_path,
        damaged_size - FOOTER_SIZE as u64,
        FOOTER_SIZE,
    );
    let backup = read_range(&damaged_path, HEADER_SIZE as u64, FOOTER_SIZE);
    assert_eq!(
        primary, backup,
        "matrix repair must restore byte-identical footer copies"
    );
    assert!(Footer::from_bytes(&primary).is_ok());

    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_healthy(),
        "twelve-volume EC archive must verify Healthy after footer repair, got {:?} ({:?})",
        stats.archive_health,
        stats.warnings
    );
    let out_dir = temp.path().join("out");
    reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    for (name, expected) in &files {
        assert_eq!(fs::read(out_dir.join(name)).unwrap(), *expected);
    }
}

/// R2-05(c): a parseable (padding-only) primary header tamper in one volume of a
/// multi-volume archive must be adopted from the authenticated backup header, and
/// repair must restore the primary bytes.
#[tokio::test]
async fn multi_volume_header_adoption_and_repair() {
    let temp = TempDir::new().unwrap();
    let files: Vec<(String, Vec<u8>)> = (1..=3u8)
        .map(|i| (format!("payload-{i}.bin"), vec![i; BLOCK_SIZE]))
        .collect();
    let archive_path = temp.path().join("multi_header.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(PASSWORD)
        .config(fast_config(None, CompressionAlgorithm::None))
        .volume_count(1)
        .max_volume_size(MAX_VOLUME_SIZE)
        .target_block_size(BLOCK_SIZE)
        .enable_cdc(false)
        .build()
        .await
        .unwrap();
    for (name, bytes) in &files {
        writer.add_bytes(name, bytes).await.unwrap();
    }
    writer.finalize().await.unwrap();

    let total = open_volume(&archive_path, 0).await.header().total_volumes();
    assert!(total >= 2, "fixture must rotate to multiple volumes");

    let damaged_sequence = total - 1;
    let damaged_path = volume_path(&archive_path, damaged_sequence);
    let original_header = read_range(&damaged_path, 0, HEADER_SIZE);
    let tampered = header_padding_tamper(&original_header);
    write_range(&damaged_path, 0, &tampered);

    {
        let mut reader = ArchiveReader::open(&archive_path, PASSWORD)
            .await
            .expect("parseable header tamper must be adopted from the authenticated backup");
        let stats = reader.verify().await.unwrap();
        assert!(
            stats.is_degraded(),
            "recovered primary header must degrade the archive, got {:?}",
            stats.archive_health
        );
        assert!(
            stats.warnings.iter().any(|w| w.contains("backup header")),
            "warnings must report the backup-header recovery: {:?}",
            stats.warnings
        );
    }

    repair_archive(&archive_path, PASSWORD, repair_options())
        .await
        .expect("repair must rewrite the adopted primary header");

    assert_eq!(
        read_range(&damaged_path, 0, HEADER_SIZE),
        original_header,
        "repair must restore the authenticated primary header bytes"
    );
    let mut reader = ArchiveReader::open(&archive_path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_healthy(),
        "multi-volume archive must verify Healthy after header repair, got {:?} ({:?})",
        stats.archive_health,
        stats.warnings
    );
    let out_dir = temp.path().join("out");
    reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    for (name, expected) in &files {
        assert_eq!(fs::read(out_dir.join(name)).unwrap(), *expected);
    }
}

/// R2-08: the manifest AAD uses header fields (archive_id/epoch_id/volume_sequence) that
/// are only authenticated once the manifest itself is decrypted. A parseable tamper of
/// such a field must be repaired by retrying the decryption with the reserved backup
/// header, instead of failing open irrecoverably.
#[tokio::test]
async fn manifest_aad_field_tamper_recovers_from_backup_header() {
    let temp = TempDir::new().unwrap();
    let payload = payload(32 * 1024);
    let path = create_single_volume_non_ec(temp.path(), "aad_tamper.era", &payload).await;
    let original_header = read_range(&path, 0, HEADER_SIZE);

    let reader = open_volume(&path, 0).await;
    let mut proto = era_common::proto::SuperHeader::from(reader.header().clone());
    drop(reader);
    proto.archive_id[0] ^= 0xFF;
    let tampered = SuperHeader::try_from(proto)
        .expect("tampered proto must convert")
        .to_bytes()
        .unwrap();
    assert!(
        SuperHeader::from_bytes(&tampered).is_ok(),
        "tampered header must still parse"
    );
    assert_ne!(tampered[..HEADER_SIZE], original_header[..]);
    write_range(&path, 0, &tampered);

    {
        let mut reader = ArchiveReader::open(&path, PASSWORD)
            .await
            .expect("manifest AAD tamper must retry with the reserved backup header");
        let stats = reader.verify().await.unwrap();
        assert!(
            stats.is_degraded(),
            "AAD-only header tamper must be reported as degraded, got {:?}",
            stats.archive_health
        );
    }

    repair_archive(&path, PASSWORD, repair_options())
        .await
        .expect("repair must rewrite the primary header from the authenticated backup");
    assert_eq!(
        read_range(&path, 0, HEADER_SIZE),
        original_header,
        "repair must restore the authenticated primary header bytes"
    );

    let mut reader = ArchiveReader::open(&path, PASSWORD).await.unwrap();
    let stats = reader.verify().await.unwrap();
    assert!(
        stats.is_healthy(),
        "archive must verify Healthy after AAD-field header repair, got {:?} ({:?})",
        stats.archive_health,
        stats.warnings
    );
    let out_dir = temp.path().join("out");
    reader
        .extract_all(&ExtractOptions::new(&out_dir))
        .await
        .unwrap();
    assert_eq!(fs::read(out_dir.join("payload.bin")).unwrap(), payload);
}

/// Sanity guard: a volume must be large enough for the reserved footer gap used above.
#[test]
fn data_region_start_is_above_reserved_footer_gap() {
    assert!(DATA_REGION_START >= HEADER_SIZE as u64 + FOOTER_SIZE as u64);
}

/// R2-02: when both canonical footer copies are zeroed and no floating footer can be
/// recovered, the volume cannot even be opened for repair; repair must fail instead of
/// reporting success (the CLI must exit non-zero).
#[tokio::test]
async fn both_canonical_footers_zeroed_fails_repair() {
    let temp = TempDir::new().unwrap();
    let payload = payload(16 * 1024);
    let path = create_single_volume_non_ec(temp.path(), "both_zero.era", &payload).await;
    let size = fs::metadata(&path).unwrap().len();
    write_range(&path, HEADER_SIZE as u64, &[0u8; FOOTER_SIZE]);
    write_range(&path, size - FOOTER_SIZE as u64, &[0u8; FOOTER_SIZE]);

    let err = repair_archive(&path, PASSWORD, repair_options())
        .await
        .expect_err("double footer loss without floating recovery must not report success");
    assert!(
        matches!(
            err,
            EraError::CorruptedHeader(_)
                | EraError::CorruptedFooter(_)
                | EraError::IntegrityError(_)
        ),
        "expected a corruption error, got {err:?}"
    );
}
