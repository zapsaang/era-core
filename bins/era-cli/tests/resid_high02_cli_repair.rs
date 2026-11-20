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
