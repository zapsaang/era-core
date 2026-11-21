mod common;

use common::{corrupt_header_magic, create_test_file, era_cmd};
use era_volume::HEADER_SIZE;
use std::fs;
use tempfile::TempDir;

const PASSWORD: &str = "resid-high02-cli-password";

#[test]
fn resid_high02_cli_repairs_non_ec_primary_header_instead_of_rejecting_archive() {
    let temp = TempDir::new().unwrap();
    let payload = vec![0x5A; 128 * 1024];
    let input = create_test_file(temp.path(), "payload.bin", &payload);
    let archive = temp.path().join("non-ec-header.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            PASSWORD,
            "--erasure",
            "none",
            "--no-compression",
        ])
        .assert()
        .success();

    let original_header = fs::read(&archive).unwrap()[..HEADER_SIZE].to_vec();
    corrupt_header_magic(&archive);
    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .failure();

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            PASSWORD,
            "--force",
        ])
        .assert()
        .success();

    assert_eq!(&fs::read(&archive).unwrap()[..HEADER_SIZE], original_header);
    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .success();

    let output = temp.path().join("output");
    fs::create_dir_all(&output).unwrap();
    era_cmd()
        .args([
            "extract",
            archive.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--password",
            PASSWORD,
        ])
        .assert()
        .success();
    assert_eq!(fs::read(output.join("payload.bin")).unwrap(), payload);
}

#[test]
fn resid_high02_cli_non_ec_header_plus_data_damage_error_does_not_mention_erasure_parity() {
    use common::corrupt_volume_data;

    let temp = TempDir::new().unwrap();
    let payload = vec![0xA5; 128 * 1024];
    let input = create_test_file(temp.path(), "payload.bin", &payload);
    let archive = temp.path().join("non-ec-both.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            PASSWORD,
            "--erasure",
            "none",
            "--no-compression",
        ])
        .assert()
        .success();

    let original_header = fs::read(&archive).unwrap()[..HEADER_SIZE].to_vec();
    corrupt_header_magic(&archive);
    corrupt_volume_data(&archive);

    let repair_assert = era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            PASSWORD,
            "--force",
        ])
        .assert()
        .failure();
    assert_eq!(
        &fs::read(&archive).unwrap()[..HEADER_SIZE],
        original_header,
        "non-EC repair --force must still restore authenticated primary header even when data is damaged"
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&repair_assert.get_output().stdout),
        String::from_utf8_lossy(&repair_assert.get_output().stderr)
    );
    assert!(
        combined.contains("without erasure coding"),
        "expected non-EC explanation, got:\n{combined}"
    );
    assert!(
        !combined.contains("beyond available erasure parity")
            && !combined.contains("valid EC repairs"),
        "non-EC repair failure must not emit misleading erasure-parity message:\n{combined}"
    );
}

#[test]
fn resid_high02_cli_detects_and_repairs_corrupted_backup_header() {
    use era_volume::{Footer, FOOTER_SIZE};
    use std::io::{Seek, SeekFrom, Write};

    let temp = TempDir::new().unwrap();
    let payload = vec![0x3E; 128 * 1024];
    let input = create_test_file(temp.path(), "payload.bin", &payload);
    let archive = temp.path().join("non-ec-backup.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            PASSWORD,
            "--erasure",
            "none",
            "--no-compression",
        ])
        .assert()
        .success();

    let original_bytes = fs::read(&archive).unwrap();
    let footer = Footer::from_bytes(&original_bytes[original_bytes.len() - FOOTER_SIZE..]).unwrap();
    let backup_offset = footer.backup_header_offset();
    {
        let mut f = fs::OpenOptions::new().write(true).open(&archive).unwrap();
        f.seek(SeekFrom::Start(backup_offset)).unwrap();
        f.write_all(&vec![0u8; HEADER_SIZE]).unwrap();
        f.sync_all().unwrap();
    }
    let damaged_bytes = fs::read(&archive).unwrap();

    // 1. `era verify` must fail (Degraded) when backup header is corrupted.
    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .failure();

    // 2. Dry-run `era repair` must report repair is possible without mutating file.
    let dry_run = era_cmd()
        .args(["repair", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .success();
    let dry_out = format!(
        "{}\n{}",
        String::from_utf8_lossy(&dry_run.get_output().stdout),
        String::from_utf8_lossy(&dry_run.get_output().stderr)
    );
    assert!(dry_out.contains("--force"), "got:\n{dry_out}");
    assert_eq!(fs::read(&archive).unwrap(), damaged_bytes);

    // 3. `era repair --force` restores backup header byte-for-byte.
    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            PASSWORD,
            "--force",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&archive).unwrap(), original_bytes);

    // 4. `era verify` passes; subsequent primary header loss is recoverable via repaired backup.
    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .success();
    corrupt_header_magic(&archive);
    let out = temp.path().join("recovered");
    fs::create_dir_all(&out).unwrap();
    era_cmd()
        .args([
            "extract",
            archive.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--password",
            PASSWORD,
        ])
        .assert()
        .success();
    assert_eq!(fs::read(out.join("payload.bin")).unwrap(), payload);
}
