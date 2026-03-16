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
        .stderr(predicate::str::contains("verified successfully"));
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
