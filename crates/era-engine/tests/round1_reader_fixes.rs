//! Round 1 audit revision: behavioral regression tests for ENG-RC-02 and LL-04.
//!
//! ENG-RC-02: footer redundancy must be covered by `verify()` (Degraded, not silently
//! Healthy) and restored by `repair_archive()` (both the primary footer at
//! `size - FOOTER_SIZE` and the reserved copy at offset `HEADER_SIZE` = 4096).
//!
//! LL-04: the *active* (primary) SuperHeader must be authenticated against the
//! manifest header-digest table when an archive is opened; a header that still
//! parses but does not match the authenticated digest must fail closed.
//!
//! ENG-RC-01 coverage lives in the `reader.rs` unit tests (injected block iterator)
//! and in `adversarial_audit_v2.rs` (behavior instead of source-string assertions).

use era_common::ArchiveConfig;
use era_engine::{repair_archive, ArchiveReader, ArchiveWriter, RepairOptions};
use era_volume::{Footer, SuperHeader, FOOTER_SIZE, HEADER_SIZE};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &str = "round1-reader-fixes";

fn no_ec_config() -> ArchiveConfig {
    ArchiveConfig {
        erasure: None,
        ..Default::default()
    }
}

async fn create_archive(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let mut writer = ArchiveWriter::builder(&path)
        .password(PASSWORD)
        .config(no_ec_config())
        .build()
        .await
        .expect("build writer");
    writer
        .add_bytes("payload.txt", &vec![0x41u8; 64 * 1024])
        .await
        .expect("add bytes");
    writer.finalize().await.expect("finalize");
    path
}

fn corrupt_range(path: &Path, offset: u64, len: usize, fill: u8) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open archive for corruption");
    file.seek(SeekFrom::Start(offset)).expect("seek corruption");
    file.write_all(&vec![fill; len])
        .expect("write corruption bytes");
    file.sync_all().expect("sync corruption");
}

fn read_range(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    let mut file = fs::File::open(path).expect("open archive for read");
    file.seek(SeekFrom::Start(offset)).expect("seek read");
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).expect("read range");
    buf
}

fn write_range(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open archive for write");
    file.seek(SeekFrom::Start(offset)).expect("seek write");
    file.write_all(bytes).expect("write range");
    file.sync_all().expect("sync write");
}

fn repair_options() -> RepairOptions {
    RepairOptions {
        create_backup: false,
        dry_run: false,
        continue_on_error: true,
    }
}

/// Returns the end offset of the length-delimited protobuf payload inside a header.
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

#[tokio::test]
async fn primary_footer_corruption_is_degraded_and_repairable() {
    let temp = TempDir::new().expect("temp dir");
    let path = create_archive(temp.path(), "primary_footer.era").await;
    let size = fs::metadata(&path).expect("metadata").len();

    // Baseline: a freshly finalized archive is Healthy with no footer warnings.
    {
        let mut reader = ArchiveReader::open(&path, PASSWORD)
            .await
            .expect("open healthy archive");
        let stats = reader.verify().await.expect("verify healthy archive");
        assert!(
            stats.is_healthy(),
            "fresh archive must be Healthy, got {:?} ({:?})",
            stats.archive_health,
            stats.warnings
        );
        assert!(
            stats.warnings.is_empty(),
            "fresh archive must not emit footer warnings: {:?}",
            stats.warnings
        );
    }

    // Corrupt the primary footer copy (last FOOTER_SIZE bytes).
    corrupt_range(&path, size - FOOTER_SIZE as u64, FOOTER_SIZE, 0xAA);

    // ENG-RC-02: verification must notice the lost footer redundancy.
    {
        let mut reader = ArchiveReader::open(&path, PASSWORD)
            .await
            .expect("open archive via backup footer");
        let stats = reader.verify().await.expect("verify degraded archive");
        assert!(
            stats.is_degraded(),
            "corrupt primary footer must degrade health, got {:?}",
            stats.archive_health
        );
        assert!(
            stats.warnings.iter().any(|w| w.contains("footer")),
            "warnings must mention the damaged footer: {:?}",
            stats.warnings
        );
    }

    // ENG-RC-02: repair must restore byte-identical footer copies.
    repair_archive(&path, PASSWORD, repair_options())
        .await
        .expect("repair must restore the primary footer");

    let repaired_size = fs::metadata(&path).expect("metadata").len();
    assert_eq!(
        repaired_size, size,
        "footer repair must not resize the volume"
    );
    let primary = read_range(&path, repaired_size - FOOTER_SIZE as u64, FOOTER_SIZE);
    let backup = read_range(&path, HEADER_SIZE as u64, FOOTER_SIZE);
    assert_eq!(
        primary, backup,
        "repaired primary and backup footers must be byte-identical"
    );
    assert!(
        Footer::from_bytes(&primary).is_ok(),
        "repaired primary footer must parse"
    );

    let mut reader = ArchiveReader::open(&path, PASSWORD)
        .await
        .expect("open repaired archive");
    let stats = reader.verify().await.expect("verify repaired archive");
    assert!(
        stats.is_healthy(),
        "repaired archive must verify Healthy, got {:?} ({:?})",
        stats.archive_health,
        stats.warnings
    );
}

#[tokio::test]
async fn backup_footer_corruption_is_degraded_and_repairable() {
    let temp = TempDir::new().expect("temp dir");
    let path = create_archive(temp.path(), "backup_footer.era").await;
    let size = fs::metadata(&path).expect("metadata").len();

    // Corrupt the reserved footer copy at offset HEADER_SIZE (4096).
    corrupt_range(&path, HEADER_SIZE as u64, FOOTER_SIZE, 0xBB);

    {
        let mut reader = ArchiveReader::open(&path, PASSWORD)
            .await
            .expect("open archive with corrupt backup footer");
        let stats = reader.verify().await.expect("verify degraded archive");
        assert!(
            stats.is_degraded(),
            "corrupt backup footer must degrade health, got {:?}",
            stats.archive_health
        );
        assert!(
            stats.warnings.iter().any(|w| w.contains("footer")),
            "warnings must mention the damaged backup footer: {:?}",
            stats.warnings
        );
    }

    repair_archive(&path, PASSWORD, repair_options())
        .await
        .expect("repair must restore the backup footer");

    let repaired_size = fs::metadata(&path).expect("metadata").len();
    assert_eq!(
        repaired_size, size,
        "footer repair must not resize the volume"
    );
    let primary = read_range(&path, repaired_size - FOOTER_SIZE as u64, FOOTER_SIZE);
    let backup = read_range(&path, HEADER_SIZE as u64, FOOTER_SIZE);
    assert_eq!(
        primary, backup,
        "repaired backup footer must match the primary footer"
    );

    let mut reader = ArchiveReader::open(&path, PASSWORD)
        .await
        .expect("open repaired archive");
    let stats = reader.verify().await.expect("verify repaired archive");
    assert!(
        stats.is_healthy(),
        "repaired archive must verify Healthy, got {:?} ({:?})",
        stats.archive_health,
        stats.warnings
    );
}

#[tokio::test]
async fn active_primary_header_tamper_recovers_from_authenticated_backup() {
    let temp = TempDir::new().expect("temp dir");
    let path = create_archive(temp.path(), "header_digest.era").await;

    // The archive must carry a manifest (and therefore a header digest table),
    // otherwise this authentication check does not apply (legacy compatibility).
    {
        let reader = ArchiveReader::open(&path, PASSWORD)
            .await
            .expect("open baseline archive");
        assert!(
            reader.manifest().is_some(),
            "test archive must carry a v8.2 manifest"
        );
    }

    let original = read_range(&path, 0, HEADER_SIZE);
    assert!(
        SuperHeader::from_bytes(&original).is_ok(),
        "baseline header must parse"
    );

    // Tamper with a header byte that still deserializes (the protobuf payload ends
    // before the zero padding, and length-delimited decoding ignores the padding).
    let mut tampered = original.clone();
    let padding_start = length_delimited_end(&tampered);
    assert!(
        padding_start + 1 < HEADER_SIZE,
        "header must contain zero padding for this test"
    );
    assert_eq!(
        tampered[padding_start], 0,
        "first padding byte must be zero"
    );
    tampered[padding_start] = 0x01;
    assert!(
        SuperHeader::from_bytes(&tampered).is_ok(),
        "tampered header must still parse so the digest check is what rejects it"
    );
    write_range(&path, 0, &tampered);

    // LL-04 (revised): a primary header that parses but does not match the
    // authenticated manifest digest must not make the archive unopenable when the
    // reserved backup header still authenticates. It is recovered from the
    // authenticated backup and reported as degraded so repair can rewrite it.
    let mut reader = ArchiveReader::open(&path, PASSWORD)
        .await
        .expect("tampered primary header must recover from the authenticated backup header");
    let stats = reader.verify().await.expect("verify degraded archive");
    assert!(
        stats.is_degraded(),
        "recovered primary header must be reported as degraded, got {:?}",
        stats.archive_health
    );
    assert!(
        stats
            .warnings
            .iter()
            .any(|w| w.contains("using backup header")),
        "warnings must report the backup-header recovery: {:?}",
        stats.warnings
    );
    drop(reader);

    repair_archive(&path, PASSWORD, repair_options())
        .await
        .expect("repair must rewrite the authenticated primary header");
    assert_eq!(
        read_range(&path, 0, HEADER_SIZE),
        original,
        "repair must restore the primary header to the authenticated bytes"
    );

    let mut reader = ArchiveReader::open(&path, PASSWORD)
        .await
        .expect("open repaired archive");
    let stats = reader.verify().await.expect("verify repaired archive");
    assert!(
        stats.is_healthy(),
        "repaired archive must verify Healthy, got {:?} ({:?})",
        stats.archive_health,
        stats.warnings
    );
}

#[tokio::test]
async fn active_primary_header_tamper_without_authenticated_backup_fails_closed() {
    let temp = TempDir::new().expect("temp dir");
    let path = create_archive(temp.path(), "header_digest_no_backup.era").await;
    let size = fs::metadata(&path).expect("metadata").len();
    let original = read_range(&path, 0, HEADER_SIZE);

    let mut tampered = original.clone();
    let padding_start = length_delimited_end(&tampered);
    tampered[padding_start] = 0x01;

    // Read the footer to find the reserved backup header location and corrupt the
    // primary header and the backup header simultaneously: no authenticated header
    // provenance remains, so open must fail closed.
    let footer_bytes = read_range(&path, size - FOOTER_SIZE as u64, FOOTER_SIZE);
    let footer = Footer::from_bytes(&footer_bytes).expect("footer must parse");
    let backup_offset = footer.backup_header_offset();
    assert!(backup_offset >= era_volume::DATA_REGION_START);

    write_range(&path, 0, &tampered);
    let mut tampered_backup = read_range(&path, backup_offset, HEADER_SIZE);
    tampered_backup[padding_start] = 0x02;
    write_range(&path, backup_offset, &tampered_backup);

    let err = match ArchiveReader::open(&path, PASSWORD).await {
        Ok(_) => panic!("tampering both header copies must fail closed"),
        Err(err) => err,
    };
    assert!(
        matches!(err, era_common::EraError::IntegrityError(_)),
        "expected IntegrityError, got {err:?}"
    );
    assert!(
        err.to_string().to_ascii_lowercase().contains("digest"),
        "error must mention the header digest, got: {err}"
    );
}
