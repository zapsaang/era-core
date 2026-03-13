//! CLI integration tests for the ERA command-line tool.

#![allow(deprecated)] // cargo_bin deprecation doesn't affect our use case

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Get a command for the era binary
fn era_cmd() -> Command {
    Command::cargo_bin("era").unwrap()
}

#[test]
fn test_help_output() {
    era_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted Redundant Archiver"))
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("extract"))
        .stdout(predicate::str::contains("list"));
}

#[test]
fn test_version_output() {
    era_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("era"));
}

#[test]
fn test_create_subcommand_help() {
    era_cmd()
        .args(["create", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Create a new ERA archive"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--password"));
}

#[test]
fn test_extract_subcommand_help() {
    era_cmd()
        .args(["extract", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Extract all files"))
        .stdout(predicate::str::contains("--input"))
        .stdout(predicate::str::contains("--output"));
}

#[test]
fn test_list_subcommand_help() {
    era_cmd()
        .args(["list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("List files stored"))
        .stdout(predicate::str::contains("--password"));
}

#[test]
fn test_create_missing_input() {
    era_cmd()
        .args(["create", "--output", "test.era"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_create_missing_output() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("test.txt");
    fs::write(&input, "test content").unwrap();

    era_cmd()
        .args(["create", input.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--output"));
}

#[test]
fn test_extract_missing_input() {
    era_cmd()
        .args(["extract", "--output", "."])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--input"));
}

#[test]
fn test_create_and_extract_roundtrip() {
    let temp = TempDir::new().unwrap();

    // Create a test file
    let input_file = temp.path().join("input.txt");
    let test_content = "Hello, ERA archive system!";
    fs::write(&input_file, test_content).unwrap();

    // Create archive
    let archive_path = temp.path().join("test.era");
    era_cmd()
        .args([
            "create",
            input_file.to_str().unwrap(),
            "--output",
            archive_path.to_str().unwrap(),
            "--password",
            "test_password",
        ])
        .assert()
        .success();

    // Verify archive was created
    assert!(archive_path.exists(), "Archive file should exist");
    assert!(
        fs::metadata(&archive_path).unwrap().len() > 0,
        "Archive should not be empty"
    );

    // Extract archive
    let output_dir = temp.path().join("output");
    fs::create_dir_all(&output_dir).unwrap();

    era_cmd()
        .args([
            "extract",
            "--input",
            archive_path.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
            "--password",
            "test_password",
        ])
        .assert()
        .success();

    // Verify extracted file
    let extracted_file = output_dir.join("input.txt");
    assert!(extracted_file.exists(), "Extracted file should exist");
    let extracted_content = fs::read_to_string(&extracted_file).unwrap();
    assert_eq!(extracted_content, test_content, "Content should match");
}

#[test]
fn test_wrong_password_fails() {
    let temp = TempDir::new().unwrap();

    // Create a test file
    let input_file = temp.path().join("secret.txt");
    fs::write(&input_file, "secret data").unwrap();

    // Create archive with password
    let archive_path = temp.path().join("encrypted.era");
    era_cmd()
        .args([
            "create",
            input_file.to_str().unwrap(),
            "--output",
            archive_path.to_str().unwrap(),
            "--password",
            "correct_password",
        ])
        .assert()
        .success();

    // Try to extract with wrong password
    let output_dir = temp.path().join("wrong_output");
    fs::create_dir_all(&output_dir).unwrap();

    era_cmd()
        .args([
            "extract",
            "--input",
            archive_path.to_str().unwrap(),
            "--output",
            output_dir.to_str().unwrap(),
            "--password",
            "wrong_password",
        ])
        .assert()
        .failure();
}

#[test]
fn test_list_archive() {
    let temp = TempDir::new().unwrap();

    // Create test files
    let input_file = temp.path().join("document.txt");
    fs::write(&input_file, "document content").unwrap();

    // Create archive
    let archive_path = temp.path().join("list_test.era");
    era_cmd()
        .args([
            "create",
            input_file.to_str().unwrap(),
            "--output",
            archive_path.to_str().unwrap(),
            "--password",
            "list_password",
        ])
        .assert()
        .success();

    // List archive contents
    era_cmd()
        .args([
            "list",
            archive_path.to_str().unwrap(),
            "--password",
            "list_password",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("document.txt"));
}

#[test]
fn test_nonexistent_archive() {
    era_cmd()
        .args(["list", "/nonexistent/archive.era", "--password", "test"])
        .assert()
        .failure();
}

#[test]
fn test_compression_levels() {
    let temp = TempDir::new().unwrap();

    // Create a compressible test file
    let input_file = temp.path().join("compressible.txt");
    let content = "a".repeat(10000); // Highly compressible
    fs::write(&input_file, &content).unwrap();

    // Test low compression (fast)
    let archive_low = temp.path().join("low.era");
    era_cmd()
        .args([
            "create",
            input_file.to_str().unwrap(),
            "--output",
            archive_low.to_str().unwrap(),
            "--password",
            "test",
            "--level",
            "1",
        ])
        .assert()
        .success();

    // Test high compression (slow but smaller)
    let archive_high = temp.path().join("high.era");
    era_cmd()
        .args([
            "create",
            input_file.to_str().unwrap(),
            "--output",
            archive_high.to_str().unwrap(),
            "--password",
            "test",
            "--level",
            "19",
        ])
        .assert()
        .success();

    // Both archives should exist
    assert!(archive_low.exists());
    assert!(archive_high.exists());
}

#[test]
fn test_verify_subcommand_help() {
    era_cmd()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Verify archive integrity"))
        .stdout(predicate::str::contains("--password"))
        .stdout(predicate::str::contains("--verbose"));
}

#[test]
fn test_verify_valid_archive() {
    let temp = TempDir::new().unwrap();

    // Create test files
    let input_file = temp.path().join("test.txt");
    fs::write(&input_file, "test content for verification").unwrap();

    // Create archive
    let archive_path = temp.path().join("verify_test.era");
    era_cmd()
        .args([
            "create",
            input_file.to_str().unwrap(),
            "--output",
            archive_path.to_str().unwrap(),
            "--password",
            "verify_password",
        ])
        .assert()
        .success();

    // Verify the archive
    era_cmd()
        .args([
            "verify",
            archive_path.to_str().unwrap(),
            "--password",
            "verify_password",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verified successfully"));
}

#[test]
fn test_verify_wrong_password() {
    let temp = TempDir::new().unwrap();

    // Create test file
    let input_file = temp.path().join("test.txt");
    fs::write(&input_file, "test content").unwrap();

    // Create archive
    let archive_path = temp.path().join("verify_pwd.era");
    era_cmd()
        .args([
            "create",
            input_file.to_str().unwrap(),
            "--output",
            archive_path.to_str().unwrap(),
            "--password",
            "correct_password",
        ])
        .assert()
        .success();

    // Verify with wrong password should fail
    era_cmd()
        .args([
            "verify",
            archive_path.to_str().unwrap(),
            "--password",
            "wrong_password",
        ])
        .assert()
        .failure();
}
