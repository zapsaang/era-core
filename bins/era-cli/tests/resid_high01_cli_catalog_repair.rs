mod common;

use common::{create_test_file, era_cmd};
use era_common::BlockHeader;
use era_volume::{Footer, FOOTER_SIZE};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "resid-high01-cli-catalog-repair";

fn flip_primary_catalog_byte(volume_path: &Path) {
    let bytes = fs::read(volume_path).unwrap();
    let footer = Footer::from_bytes(&bytes[bytes.len() - FOOTER_SIZE..]).unwrap();
    assert!(footer.has_catalog_location());
    let offset = footer.catalog_offset() + BlockHeader::SIZE as u64 + 24;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(volume_path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn resid_high01_cli_repairs_damaged_primary_catalog_on_volume_zero() {
    let temp = TempDir::new().unwrap();
    let payload = vec![0x4C; 64 * 1024];
    let input = create_test_file(temp.path(), "payload.bin", &payload);
    let archive = temp.path().join("matrix_catalog.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            PASSWORD,
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    let original_vol0 = fs::read(&archive).unwrap();
    flip_primary_catalog_byte(&archive);
    let damaged_vol0 = fs::read(&archive).unwrap();
    assert_ne!(damaged_vol0, original_vol0);

    // 1. `era verify` must fail (Degraded) when Volume 0's primary Catalog is corrupted.
    let verify_assert = era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .failure();
    let verify_out = format!(
        "{}\n{}",
        String::from_utf8_lossy(&verify_assert.get_output().stdout),
        String::from_utf8_lossy(&verify_assert.get_output().stderr)
    );
    assert!(
        verify_out.contains("degraded") && verify_out.contains("Volume 0"),
        "verify output must report degraded Volume 0 Catalog damage, got:\n{verify_out}"
    );

    // 2. Dry-run `era repair` must report repair is possible without mutating Volume 0.
    let dry_run_assert = era_cmd()
        .args(["repair", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .success();
    let dry_run_out = format!(
        "{}\n{}",
        String::from_utf8_lossy(&dry_run_assert.get_output().stdout),
        String::from_utf8_lossy(&dry_run_assert.get_output().stderr)
    );
    assert!(
        dry_run_out.contains("--force"),
        "dry-run repair should offer --force instead of skipping healthy archive, got:\n{dry_run_out}"
    );
    assert_eq!(fs::read(&archive).unwrap(), damaged_vol0);

    // 3. `era repair --force` must actually restore Volume 0's primary Catalog bytes.
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
    assert_eq!(
        fs::read(&archive).unwrap(),
        original_vol0,
        "repair --force must restore Volume 0 primary Catalog in place"
    );

    // 4. Re-verify succeeds (Healthy) and extraction matches original bytes.
    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", PASSWORD])
        .assert()
        .success();

    let out_dir = temp.path().join("restored");
    fs::create_dir_all(&out_dir).unwrap();
    era_cmd()
        .args([
            "extract",
            archive.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            PASSWORD,
        ])
        .assert()
        .success();
    assert_eq!(fs::read(out_dir.join("payload.bin")).unwrap(), payload);
}
