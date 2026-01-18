#![allow(deprecated)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn era_cmd() -> Command {
    Command::cargo_bin("era").unwrap()
}

#[test]
fn test_create_no_compression_flag() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    let output = temp.path().join("archive_store.era");

    fs::write(&input, "some compressible content".repeat(100)).unwrap();

    // Run with --no-compression and --verbose to catch the log message
    era_cmd()
        .arg("--verbose") // To ensure we see logs
        .arg("create")
        .arg("--output")
        .arg(output.to_str().unwrap())
        .arg("--password")
        .arg("testpass")
        .arg("--no-compression")
        .arg(input.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Compression: disabled (Store mode)"));
}

#[test]
fn test_create_level_zero() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("input_zero.txt");
    let output = temp.path().join("archive_zero.era");

    fs::write(&input, "some compressible content".repeat(100)).unwrap();

    // Run with --level 0
    era_cmd()
        .arg("--verbose")
        .arg("create")
        .arg("--output")
        .arg(output.to_str().unwrap())
        .arg("--password")
        .arg("testpass")
        .arg("--level")
        .arg("0")
        .arg(input.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Compression: disabled (Store mode)"));
}
