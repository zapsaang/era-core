mod common;

use common::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[test]
fn t9f_extract_force_overwrites_existing_readonly_files() {
    let temp = TempDir::new().unwrap();
    let src_dir = temp.path().join("src");
    let small = create_test_file(&src_dir, "ro_small.txt", b"readonly small cli payload");
    let large = create_large_test_file(&src_dir, "ro_large.bin", 192 * 1024);

    #[cfg(unix)]
    {
        fs::set_permissions(&small, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&large, fs::Permissions::from_mode(0o444)).unwrap();
    }

    let archive = temp.path().join("t9f.era");
    era_cmd()
        .args([
            "create",
            src_dir.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    let out_dir = temp.path().join("out");
    era_cmd()
        .args([
            "extract",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("src/ro_small.txt")).unwrap(),
        b"readonly small cli payload"
    );
    assert_eq!(
        fs::read(out_dir.join("src/ro_large.bin")).unwrap(),
        generate_deterministic_data(192 * 1024)
    );
}

#[test]
fn t8c_repair_non_ec_corrupted_archive_does_not_mislead_with_extract_force() {
    let temp = TempDir::new().unwrap();
    let input = create_large_test_file(temp.path(), "payload.bin", 128 * 1024);
    let archive = temp.path().join("no_ec.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "none",
            "--no-compression",
        ])
        .assert()
        .success();

    corrupt_archive_shard(&archive, 10000);

    let assert = era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let combined = format!("{}\n{}", stdout, stderr);

    assert!(
        combined.contains("without erasure coding"),
        "expected non-EC explanation, got: {}",
        combined
    );
    assert!(
        combined.contains("cannot be repaired"),
        "expected explicit unrepairable message, got: {}",
        combined
    );
    assert!(
        !combined.contains("Use 'era extract --force' to recover")
            && !combined.contains("try: era extract --force")
            && !combined.contains("use: era extract --force"),
        "repair should not mislead users into thinking `extract --force` bypasses corruption: {}",
        combined
    );
}
