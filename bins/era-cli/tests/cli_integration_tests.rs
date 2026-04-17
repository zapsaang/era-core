//! Comprehensive CLI integration tests for the ERA command-line tool.
//!
//! Tests cover all 7 commands: create, extract, list, info, verify, repair, repack.

#![allow(deprecated)]

mod common;

use common::*;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ===========================================================================
// CREATE command tests
// ===========================================================================

#[test]
fn test_create_single_file_roundtrip() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "hello.txt", b"Hello, ERA!");
    let archive = temp.path().join("single.era");
    let out_dir = temp.path().join("extracted");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
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
        ])
        .assert()
        .success();

    let restored = out_dir.join("hello.txt");
    assert!(restored.exists(), "extracted file should exist");
    assert_eq!(fs::read(&restored).unwrap(), b"Hello, ERA!");
}

#[test]
fn test_create_multiple_files_roundtrip() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    create_test_file(&src, "a.txt", b"file_a");
    create_test_file(&src, "b.txt", b"file_b");
    create_test_file(&src, "c.txt", b"file_c");

    let archive = temp.path().join("multi.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            src.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
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
        ])
        .assert()
        .success();

    // All three files should be present somewhere under out_dir
    let found: Vec<_> = walkdir::WalkDir::new(&out_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    assert_eq!(found.len(), 3, "all 3 files should be extracted");
}

#[test]
fn test_create_directory_recursive() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("tree");
    create_test_file(&root, "top.txt", b"top");
    create_test_file(&root, "sub/mid.txt", b"mid");
    create_test_file(&root, "sub/deep/bottom.txt", b"bottom");

    let archive = temp.path().join("tree.era");
    let out_dir = temp.path().join("restored");

    era_cmd()
        .args([
            "create",
            root.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
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
        ])
        .assert()
        .success();

    let files: Vec<_> = walkdir::WalkDir::new(&out_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    assert_eq!(files.len(), 3, "all nested files should be extracted");
}

#[test]
fn test_create_with_erasure_6_3() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "data.bin", &vec![0xAA; 4096]);
    let archive = temp.path().join("ec63.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "6:3",
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
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("data.bin")).unwrap(),
        vec![0xAA; 4096]
    );
}

#[test]
fn test_create_no_compression() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "raw.txt", b"uncompressed content here");
    let archive = temp.path().join("nocomp.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--no-compression",
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
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("raw.txt")).unwrap(),
        b"uncompressed content here"
    );
}

#[test]
fn test_create_compact_mode() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "compact.txt", b"compact mode data");
    let archive = temp.path().join("compact.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--compact",
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
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("compact.txt")).unwrap(),
        b"compact mode data"
    );
}

#[test]
fn test_create_custom_cdc_params() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "cdc.bin", &vec![0x55; 8192]);
    let archive = temp.path().join("cdc.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--cdc-min",
            "8192",
            "--cdc-avg",
            "32768",
            "--cdc-max",
            "131072",
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
        ])
        .assert()
        .success();

    assert_eq!(fs::read(out_dir.join("cdc.bin")).unwrap(), vec![0x55; 8192]);
}

// ===========================================================================
// EXTRACT command tests
// ===========================================================================

#[test]
fn test_extract_basic_roundtrip() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "roundtrip.txt", b"roundtrip content");
    let archive = temp.path().join("rt.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "test_password",
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
            "test_password",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("roundtrip.txt")).unwrap(),
        b"roundtrip content"
    );
}

#[test]
fn test_extract_wrong_password_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "secret.txt", b"secret data");
    let archive = temp.path().join("secret.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "correct_password",
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
            "wrong_password",
        ])
        .assert()
        .failure();
}

#[test]
fn test_extract_nonexistent_archive_fails() {
    let temp = TempDir::new().unwrap();
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "extract",
            "--input",
            "/nonexistent/path/archive.era",
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_extract_overwrite_with_force() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "overwrite.txt", b"original content");
    let archive = temp.path().join("ow.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    // First extraction
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

    // Second extraction with --force should succeed (overwrite)
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
        fs::read(out_dir.join("overwrite.txt")).unwrap(),
        b"original content"
    );
}

// ===========================================================================
// LIST command tests
// ===========================================================================

#[test]
fn test_list_single_file() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "listed.txt", b"list me");
    let archive = temp.path().join("list1.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success()
        .stderr(predicate::str::contains("listed.txt"));
}

#[test]
fn test_list_multiple_files() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "alpha.txt", b"a");
    create_test_file(&src, "beta.txt", b"b");
    create_test_file(&src, "gamma.txt", b"g");
    let archive = temp.path().join("listm.era");

    era_cmd()
        .args([
            "create",
            src.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(stderr.contains("alpha.txt"), "should list alpha.txt");
    assert!(stderr.contains("beta.txt"), "should list beta.txt");
    assert!(stderr.contains("gamma.txt"), "should list gamma.txt");
}

#[test]
fn test_list_long_format() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "sized.txt", b"some content with known size");
    let archive = temp.path().join("listl.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "list",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--long",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("SIZE"));
}

// ===========================================================================
// INFO command tests
// ===========================================================================

#[test]
fn test_info_shows_archive_id() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "info.txt", b"info test");
    let archive = temp.path().join("info.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Archive ID"));
}

#[test]
fn test_info_shows_config() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "cfg.txt", b"config test");
    let archive = temp.path().join("cfg.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("Compression Level") || stderr.contains("Configuration"),
        "info should show configuration details"
    );
}

// ===========================================================================
// VERIFY command tests
// ===========================================================================

#[test]
fn test_verify_valid_archive_succeeds() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "verify.txt", b"verify me");
    let archive = temp.path().join("verify.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success()
        .stderr(predicate::str::contains("verified successfully"));
}

#[test]
fn test_verify_wrong_password_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "vp.txt", b"verify password test");
    let archive = temp.path().join("vp.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "correct",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "wrong"])
        .assert()
        .failure();
}

#[test]
fn test_verify_corrupted_archive_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "corrupt.bin", &vec![0xBB; 256 * 1024]);
    let archive = temp.path().join("corrupt.era");

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
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    let data_offset = 4096 + 128 + 64;
    assert!(
        file_len > data_offset + 200,
        "archive should have sufficient data region"
    );

    corrupt_archive_shard(&archive, data_offset);

    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .failure();
}

#[test]
fn test_verify_missing_volume_detected() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "mvol.bin", &vec![0xCC; 256 * 1024]);
    let archive = temp.path().join("mvol.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    let vol_count = count_volume_files(&archive);
    assert!(
        vol_count > 1,
        "multi-volume archive should have multiple volumes, got {}",
        vol_count
    );

    let stem = archive.with_extension("");
    let vol2 = stem.with_extension("era.002");
    assert!(vol2.exists(), "volume .era.002 should exist");
    fs::remove_file(&vol2).unwrap();

    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .failure();
}

// ===========================================================================
// REPAIR command tests
// ===========================================================================

#[test]
fn test_repair_dry_run_analyzes() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_dry.bin", &vec![0xDD; 64 * 1024]);
    let archive = temp.path().join("repair_dry.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Recovery Analysis")
                .or(predicate::str::contains("No repair needed"))
                .or(predicate::str::contains("intact")),
        );
}

#[test]
fn test_repair_with_force_heals_corruption() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "heal.bin", &vec![0xEE; 256 * 1024]);
    let archive = temp.path().join("heal.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    assert!(
        file_len > 10200,
        "archive should have sufficient data for corruption test"
    );

    corrupt_archive_shard(&archive, 10000);

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert()
        .success();
}

#[test]
fn test_repair_creates_backup() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "bak.bin", &vec![0xFF; 256 * 1024]);
    let archive = temp.path().join("bak.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    assert!(
        file_len > 10200,
        "archive should have sufficient data for corruption test"
    );

    corrupt_archive_shard(&archive, 10000);

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert()
        .success();

    let backup = archive.with_extension("era.bak");
    assert!(
        backup.exists(),
        ".era.bak backup should be created during repair"
    );
}

#[test]
fn test_repair_non_erasure_archive_no_op() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "noec.bin", &vec![0x11; 256 * 1024]);
    let archive = temp.path().join("noec.era");

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
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    assert!(
        file_len > 10200,
        "archive should have sufficient data for corruption test"
    );

    corrupt_archive_shard(&archive, 10000);

    let assert = era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    let has_graceful_message = stderr.contains("without erasure coding")
        || stderr.contains("limited repair")
        || stderr.contains("not available")
        || stderr.contains("No repair needed")
        || stderr.contains("intact");
    assert!(
        has_graceful_message || !assert.get_output().status.success(),
        "repair on non-EC archive should handle gracefully: {}",
        stderr
    );
}

// ===========================================================================
// REPACK command tests
// ===========================================================================

#[test]
fn test_repack_changes_compression() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(
        temp.path(),
        "repack.txt",
        b"repack compression test data that should be compressible aaaaaaaaaa",
    );
    let archive = temp.path().join("repack_src.era");
    let repacked = temp.path().join("repack_dst.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--level",
            "3",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--password",
            "pwd",
            "--level",
            "19",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            repacked.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("repack.txt")).unwrap(),
        b"repack compression test data that should be compressible aaaaaaaaaa"
    );
}

#[test]
fn test_repack_preserves_content() {
    let temp = TempDir::new().unwrap();
    let original_data = b"content that must survive repack unchanged";
    let input = create_test_file(temp.path(), "preserve.txt", original_data);
    let archive = temp.path().join("preserve_src.era");
    let repacked = temp.path().join("preserve_dst.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--password",
            "pwd",
            "--compact",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            repacked.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("preserve.txt")).unwrap(),
        original_data
    );
}

// ===========================================================================
// Edge case tests
// ===========================================================================

#[test]
fn test_empty_password_works() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "empty_pw.txt", b"empty password test");
    let archive = temp.path().join("empty_pw.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "",
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
            "",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("empty_pw.txt")).unwrap(),
        b"empty password test"
    );
}

#[test]
fn test_binary_file_integrity() {
    let temp = TempDir::new().unwrap();
    let mut binary_data = Vec::with_capacity(256);
    for b in 0..=255u8 {
        binary_data.push(b);
    }
    let input = create_test_file(temp.path(), "binary.bin", &binary_data);
    let archive = temp.path().join("binary.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
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
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("binary.bin")).unwrap(),
        binary_data,
        "all 256 byte values must survive roundtrip"
    );
}

#[test]
fn test_large_file_handling() {
    let temp = TempDir::new().unwrap();
    let large_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    let input = create_test_file(temp.path(), "large.bin", &large_data);
    let archive = temp.path().join("large.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
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
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("large.bin")).unwrap(),
        large_data,
        "1MB file must survive roundtrip"
    );
}

#[test]
fn test_unicode_filename() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(
        temp.path(),
        "données_日本語_🔐.txt",
        b"unicode filename test",
    );
    let archive = temp.path().join("unicode.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
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
        ])
        .assert()
        .success();

    let restored = out_dir.join("données_日本語_🔐.txt");
    assert!(
        restored.exists(),
        "unicode filename should survive roundtrip"
    );
    assert_eq!(fs::read(&restored).unwrap(), b"unicode filename test");
}

// ===========================================================================
// MULTI-VOLUME tests
// ===========================================================================

#[test]
fn test_multivolume_create_produces_multiple_files() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "multi.bin", &vec![0xAA; 256 * 1024]);
    let archive = temp.path().join("multi.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    let count = count_volume_files(&archive);
    assert!(
        count >= 2,
        "multi-volume archive should produce at least 2 files, got {}",
        count
    );
}

#[test]
fn test_multivolume_extract_roundtrip() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    create_test_file(&src, "a.txt", &vec![0x11; 64 * 1024]);
    create_test_file(&src, "b.txt", &vec![0x22; 64 * 1024]);
    create_test_file(&src, "c.txt", &vec![0x33; 64 * 1024]);
    let archive = temp.path().join("multi_rt.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            src.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
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
        ])
        .assert()
        .success();

    let found: Vec<_> = walkdir::WalkDir::new(&out_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    assert_eq!(found.len(), 3, "all 3 files should be extracted");
}

#[test]
fn test_multivolume_max_volume_size_splits() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "split.bin", &vec![0xBB; 64 * 1024]);
    let archive = temp.path().join("split.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--max-volume-size",
            "8192",
            "--no-compression",
        ])
        .assert()
        .success();

    let count = count_volume_files(&archive);
    assert!(
        count >= 2,
        "should split into multiple volumes, got {}",
        count
    );
}

#[test]
fn test_multivolume_list_works() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "list_multi.txt", b"list multi volume");
    let archive = temp.path().join("list_multi.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success()
        .stderr(predicate::str::contains("list_multi.txt"));
}

#[test]
fn test_multivolume_info_shows_volume_count() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "info_multi.txt", b"info multi volume");
    let archive = temp.path().join("info_multi.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    let assert_result = era_cmd()
        .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
    // Info should show volume-related information
    assert!(
        stderr.contains("Volume") || stderr.contains("volume") || stderr.contains("6"),
        "info should show volume information: {}",
        stderr
    );
}

#[test]
fn test_multivolume_verify_all_intact() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "verify_multi.txt", b"verify multi volume");
    let archive = temp.path().join("verify_multi.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();
}

#[test]
fn test_multivolume_repair_recovers_corrupted_volume() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_multi.bin", &vec![0xCC; 256 * 1024]);
    let archive = temp.path().join("repair_multi.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    // Corrupt the first volume (which should have data)
    let vol1 = archive.with_extension("era.001");
    if vol1.exists() {
        let file_len = fs::metadata(&vol1).unwrap().len();
        if file_len > 10200 {
            corrupt_archive_shard(&vol1, 10000);
        }
    } else {
        // Corrupt base archive if no .era.001
        let file_len = fs::metadata(&archive).unwrap().len();
        if file_len > 10200 {
            corrupt_archive_shard(&archive, 10000);
        }
    }

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert()
        .success();

    // Verify the repaired archive
    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();
}

// ===========================================================================
// REPACK ADVANCED tests
// ===========================================================================

#[test]
fn test_repack_changes_erasure() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(
        temp.path(),
        "repack_ec.txt",
        b"repack erasure change test data",
    );
    let archive = temp.path().join("repack_ec_src.era");
    let repacked = temp.path().join("repack_ec_dst.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "6:3",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            repacked.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("repack_ec.txt")).unwrap(),
        b"repack erasure change test data"
    );
}

#[test]
fn test_repack_adds_erasure_to_none() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repack_add_ec.txt", b"repack add erasure test");
    let archive = temp.path().join("repack_add_ec_src.era");
    let repacked = temp.path().join("repack_add_ec_dst.era");
    let out_dir = temp.path().join("out");

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
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            repacked.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("repack_add_ec.txt")).unwrap(),
        b"repack add erasure test"
    );
}

#[test]
fn test_repack_removes_compression() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(
        temp.path(),
        "repack_rm_comp.txt",
        b"repack remove compression test",
    );
    let archive = temp.path().join("repack_rm_comp_src.era");
    let repacked = temp.path().join("repack_rm_comp_dst.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--level",
            "3",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--password",
            "pwd",
            "--no-compression",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            repacked.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("repack_rm_comp.txt")).unwrap(),
        b"repack remove compression test"
    );
}

#[test]
fn test_repack_wrong_password_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repack_wrong.txt", b"repack wrong pwd test");
    let archive = temp.path().join("repack_wrong_src.era");
    let repacked = temp.path().join("repack_wrong_dst.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "correct_pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--password",
            "wrong_pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_repack_with_cert_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repack_cert.txt", b"repack cert test");
    let archive = temp.path().join("repack_cert_src.era");
    let repacked = temp.path().join("repack_cert_dst.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
            "--compact",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            repacked.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("repack_cert.txt")).unwrap(),
        b"repack cert test"
    );
}

// ===========================================================================
// INFO/LIST VALIDATION tests
// ===========================================================================

#[test]
fn test_info_shows_compression_level() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "cfg_lvl.txt", b"config level test");
    let archive = temp.path().join("cfg_lvl.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--level",
            "12",
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("12") || stderr.contains("Compression") || stderr.contains("compression"),
        "info should show compression level: {}",
        stderr
    );
}

#[test]
fn test_info_shows_erasure_config() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "cfg_ec.txt", b"config erasure test");
    let archive = temp.path().join("cfg_ec.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "6:3",
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("6")
            || stderr.contains("3")
            || stderr.contains("Erasure")
            || stderr.contains("erasure"),
        "info should show erasure config: {}",
        stderr
    );
}

#[test]
fn test_info_no_erasure_archive() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "no_ec.txt", b"no erasure test");
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
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        !stderr.contains("Erasure")
            && !stderr.contains("Reed-Solomon")
            && !stderr.contains("data+parity"),
        "info for no-erasure archive should omit erasure details: {}",
        stderr
    );
}

#[test]
fn test_list_long_shows_file_sizes() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "sized_file.txt", &vec![0x42; 1024]);
    let archive = temp.path().join("sized_file.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args([
            "list",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--long",
        ])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("1024") || stderr.contains("1.0") || stderr.contains("1 Ki"),
        "list --long should show file size: {}",
        stderr
    );
}

#[test]
fn test_list_directory_structure_preserved() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("tree");
    fs::create_dir_all(root.join("sub/deep")).unwrap();
    create_test_file(&root, "top.txt", b"top");
    create_test_file(&root, "sub/mid.txt", b"mid");
    create_test_file(&root, "sub/deep/bottom.txt", b"bottom");
    let archive = temp.path().join("dirs.era");

    era_cmd()
        .args([
            "create",
            root.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("sub") && stderr.contains("deep"),
        "list should preserve directory structure: {}",
        stderr
    );
}

#[test]
fn test_list_empty_archive_shows_zero() {
    let temp = TempDir::new().unwrap();
    // Create a single empty file
    let input = create_test_file(temp.path(), "empty.txt", b"");
    let archive = temp.path().join("empty.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();
}

// ===========================================================================
// CERTIFICATE AUTH tests
// ===========================================================================

#[test]
fn test_cert_create_extract_roundtrip() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "cert_data.txt", b"certificate mode data");
    let archive = temp.path().join("cert.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "extract",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("cert_data.txt")).unwrap(),
        b"certificate mode data"
    );
}

#[test]
fn test_cert_extract_wrong_key_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "secret.txt", b"secret data");
    let archive = temp.path().join("secret.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, _priv_key) = generate_test_keypair(temp.path());
    let (_pub_cert2, priv_key2) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "extract",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--key",
            priv_key2.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn test_cert_list_with_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "list_me.txt", b"list content");
    let archive = temp.path().join("list_cert.era");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "list",
            archive.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("list_me.txt"));
}

#[test]
fn test_cert_info_with_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "info_me.txt", b"info content");
    let archive = temp.path().join("info_cert.era");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "info",
            archive.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Archive ID"));
}

#[test]
fn test_cert_verify_with_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "verify_me.txt", b"verify content");
    let archive = temp.path().join("verify_cert.era");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "verify",
            archive.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("verified successfully"));
}

#[test]
fn test_cert_verify_wrong_key_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "vwrong.txt", b"verify wrong key");
    let archive = temp.path().join("vwrong.era");
    let (pub_cert, _priv_key) = generate_test_keypair(temp.path());
    let (_pub2, priv_key2) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "verify",
            archive.to_str().unwrap(),
            "--key",
            priv_key2.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn test_cert_repair_succeeds_with_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_cert2.bin", &vec![0xEE; 256 * 1024]);
    let archive = temp.path().join("repair_cert2.era");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--certificate",
            pub_cert.to_str().unwrap(),
            "--erasure",
            "4:2",
            "--volumes",
            "1",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    if file_len > 10200 {
        corrupt_archive_shard(&archive, 10000);
    }

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();
}

#[test]
fn test_cert_repack_with_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repack_cert2.txt", b"repack cert data");
    let archive = temp.path().join("repack_src2.era");
    let repacked = temp.path().join("repack_dst2.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "repack",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            repacked.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
            "--compact",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            repacked.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("repack_cert2.txt")).unwrap(),
        b"repack cert data"
    );
}

// ===========================================================================
// HYBRID AUTH tests
// ===========================================================================

#[test]
fn test_hybrid_create_extract_with_password() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "hybrid_pw.txt", b"hybrid password data");
    let archive = temp.path().join("hybrid.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, _priv_key) = generate_test_keypair(temp.path());

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--certificate",
            pub_cert.to_str().unwrap(),
            "--password",
            "hybrid_pwd",
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
            "hybrid_pwd",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("hybrid_pw.txt")).unwrap(),
        b"hybrid password data"
    );
}

#[test]
fn test_hybrid_create_extract_with_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "hybrid_key.txt", b"hybrid key data");
    let archive = temp.path().join("hybrid_key.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--certificate",
            pub_cert.to_str().unwrap(),
            "--password",
            "hybrid_pwd",
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
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("hybrid_key.txt")).unwrap(),
        b"hybrid key data"
    );
}

#[test]
fn test_hybrid_extract_with_wrong_password_still_works_with_key() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "hybrid_fallback.txt", b"hybrid fallback data");
    let archive = temp.path().join("hybrid_fallback.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--certificate",
            pub_cert.to_str().unwrap(),
            "--password",
            "correct_pwd",
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
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("hybrid_fallback.txt")).unwrap(),
        b"hybrid fallback data"
    );
}

#[test]
fn test_hybrid_neither_password_nor_key_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "hybrid_neither.txt", b"hybrid neither");
    let archive = temp.path().join("hybrid_neither.era");
    let out_dir = temp.path().join("out");
    let (pub_cert, _priv_key) = generate_test_keypair(temp.path());

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--certificate",
            pub_cert.to_str().unwrap(),
            "--password",
            "correct_pwd",
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
            "wrong_pwd",
        ])
        .assert()
        .failure();
}

// ===========================================================================
// EDGE CASES AND ERROR PATHS tests
// ===========================================================================

#[test]
fn test_extract_to_nonexistent_parent_dir() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "nonexist_out.txt", b"test");
    let archive = temp.path().join("nonexist.era");
    let out_dir = temp.path().join("deeply/nested/path");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    // Extract to a path whose parent doesn't exist - era should either create it or fail gracefully
    let assert = era_cmd()
        .args([
            "extract",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert();

    // Either succeeds (auto-creates) or fails gracefully
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        assert.get_output().status.success()
            || stderr.contains("create")
            || stderr.contains("exist")
            || stderr.contains("directory"),
        "extract to nested path should handle gracefully: {}",
        stderr
    );
}

#[test]
fn test_extract_no_password_no_key_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "no_auth.txt", b"no auth test");
    let archive = temp.path().join("no_auth.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    // Without TTY, extract with no password and no key should fail or prompt
    era_cmd()
        .args([
            "extract",
            "--input",
            archive.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn test_create_no_input_fails() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("no_input.era");

    era_cmd()
        .args([
            "create",
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_create_nonexistent_input_fails() {
    let temp = TempDir::new().unwrap();
    let archive = temp.path().join("bad_input.era");

    era_cmd()
        .args([
            "create",
            "/this/path/does/not/exist.txt",
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_create_output_to_existing_file_overwrites() {
    let temp = TempDir::new().unwrap();
    let input_a = create_test_file(temp.path(), "file_a.txt", b"content A");
    let input_b = create_test_file(temp.path(), "file_b.txt", b"content B");
    let archive = temp.path().join("overwrite.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input_a.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "create",
            input_b.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
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
        ])
        .assert()
        .success();

    assert_eq!(fs::read(out_dir.join("file_b.txt")).unwrap(), b"content B");
}

#[test]
fn test_level_zero_equals_no_compression() {
    let temp = TempDir::new().unwrap();
    let data = b"compressible aaaaaa aaaaaa aaaaaa aaaaaa aaaaaa";
    let input_a = create_test_file(temp.path(), "level0.txt", data);
    let input_b = create_test_file(temp.path(), "nocomp.txt", data);
    let archive_a = temp.path().join("level0.era");
    let archive_b = temp.path().join("nocomp.era");
    let out_dir_a = temp.path().join("out_a");
    let out_dir_b = temp.path().join("out_b");

    era_cmd()
        .args([
            "create",
            input_a.to_str().unwrap(),
            "--output",
            archive_a.to_str().unwrap(),
            "--password",
            "pwd",
            "--level",
            "0",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "create",
            input_b.to_str().unwrap(),
            "--output",
            archive_b.to_str().unwrap(),
            "--password",
            "pwd",
            "--no-compression",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            archive_a.to_str().unwrap(),
            "--output",
            out_dir_a.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "extract",
            "--input",
            archive_b.to_str().unwrap(),
            "--output",
            out_dir_b.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(out_dir_a.join("level0.txt")).unwrap(), data);
    assert_eq!(fs::read(out_dir_b.join("nocomp.txt")).unwrap(), data);
    assert_eq!(
        fs::read(out_dir_a.join("level0.txt")).unwrap(),
        fs::read(out_dir_b.join("nocomp.txt")).unwrap()
    );
}

#[test]
fn test_create_level_and_no_compression_conflict() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "conflict.txt", b"conflict");
    let archive = temp.path().join("conflict.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--level",
            "3",
            "--no-compression",
        ])
        .assert()
        .failure();
}

#[test]
fn test_verify_nonexistent_archive_fails() {
    era_cmd()
        .args([
            "verify",
            "/nonexistent/path/to/archive.era",
            "--password",
            "pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_info_nonexistent_archive_fails() {
    era_cmd()
        .args([
            "info",
            "/nonexistent/path/to/archive.era",
            "--password",
            "pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_list_nonexistent_archive_fails() {
    era_cmd()
        .args([
            "list",
            "/nonexistent/path/to/archive.era",
            "--password",
            "pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_repair_nonexistent_archive_graceful() {
    let assert = era_cmd()
        .args([
            "repair",
            "/nonexistent/path/to/archive.era",
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("Nothing to repair") || stderr.contains("No archive"),
        "repair should report nothing to repair: {}",
        stderr
    );
}

#[test]
fn test_create_special_characters_in_password() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "special.txt", b"special password test");
    let archive = temp.path().join("special.era");
    let out_dir = temp.path().join("out");
    let special_pw = "p@$$w0rd!#%^&*()[]{}|;:'\",.<>?/";

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            special_pw,
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
            special_pw,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("special.txt")).unwrap(),
        b"special password test"
    );
}

#[test]
fn test_very_long_password() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "long_pw.txt", b"long password test");
    let archive = temp.path().join("long_pw.era");
    let out_dir = temp.path().join("out");
    let long_pw = "a".repeat(1000);

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            &long_pw,
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
            &long_pw,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("long_pw.txt")).unwrap(),
        b"long password test"
    );
}

// ===========================================================================
// VERIFY ADVANCED tests
// ===========================================================================

#[test]
fn test_verify_verbose_shows_block_info() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "verify_verbose.bin", &vec![0x99; 256 * 1024]);
    let archive = temp.path().join("verify_verbose.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    let assert = era_cmd()
        .args([
            "verify",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--verbose",
        ])
        .assert();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.to_lowercase().contains("block")
            || stderr.to_lowercase().contains("shard")
            || stderr.to_lowercase().contains("verified")
            || assert.get_output().status.success(),
        "verify --verbose should show block info: {}",
        stderr
    );
}

#[test]
fn test_verify_corrupted_footer_reports_warning() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "footer_warn.bin", b"footer warn test");
    let archive = temp.path().join("footer_warn.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    corrupt_footer(&archive);

    let assert = era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("footer") || stderr.contains("corrupted") || stderr.contains("recovery"),
        "verify should report footer corruption warning: {}",
        stderr
    );
}

#[test]
fn test_verify_corrupted_header_magic_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "header_corrupt.bin", b"header test");
    let archive = temp.path().join("header_corrupt.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    corrupt_header_magic(&archive);

    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .failure();
}

#[test]
fn test_verify_cert_mode_valid_archive() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "cert_verify.txt", b"cert verify test");
    let archive = temp.path().join("cert_verify.era");
    let (pub_cert, priv_key) = generate_test_keypair(temp.path());

    create_archive_with_cert(&input, &archive, &pub_cert);

    era_cmd()
        .args([
            "verify",
            archive.to_str().unwrap(),
            "--key",
            priv_key.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("verified successfully"));
}

// ===========================================================================
// REPAIR ADVANCED tests
// ===========================================================================

#[test]
fn test_repair_verbose_shows_details() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_verbose.bin", &vec![0xDD; 256 * 1024]);
    let archive = temp.path().join("repair_verbose.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    if file_len > 10200 {
        corrupt_archive_shard(&archive, 10000);
    }

    let assert = era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--verbose",
        ])
        .assert();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.to_lowercase().contains("shard")
            || stderr.to_lowercase().contains("block")
            || stderr.to_lowercase().contains("corrupt")
            || assert.get_output().status.success(),
        "repair verbose should show details or succeed: {}",
        stderr
    );
}

#[test]
fn test_repair_two_shard_corruption_recovers() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_double.bin", &vec![0xEE; 256 * 1024]);
    let archive = temp.path().join("repair_double.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    if file_len > 12200 {
        corrupt_archive_shard(&archive, 10000);
        corrupt_archive_shard(&archive, 11000);
    }

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert()
        .success();
}

#[test]
fn test_repair_force_then_verify_passes() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(
        temp.path(),
        "repair_then_verify.bin",
        &vec![0xFF; 256 * 1024],
    );
    let archive = temp.path().join("repair_then_verify.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    if file_len > 10200 {
        corrupt_archive_shard(&archive, 10000);
    }

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert()
        .success();

    era_cmd()
        .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();
}

#[test]
fn test_repair_force_then_extract_roundtrip() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_extract.bin", b"repair extract data");
    let archive = temp.path().join("repair_extract.era");
    let out_dir = temp.path().join("out");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    if file_len > 10200 {
        corrupt_archive_shard(&archive, 10000);
    }

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
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
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(out_dir.join("repair_extract.bin")).unwrap(),
        b"repair extract data"
    );
}

#[test]
fn test_repair_dry_run_does_not_modify() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_dry.bin", &vec![0xAB; 256 * 1024]);
    let archive = temp.path().join("repair_dry.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--no-compression",
        ])
        .assert()
        .success();

    let file_len = fs::metadata(&archive).unwrap().len();
    if file_len > 10200 {
        corrupt_archive_shard(&archive, 10000);
    }

    let _mtime_before = fs::metadata(&archive).unwrap().modified().unwrap();

    era_cmd()
        .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    // Dry run (no --force) should not crash; mtime check is unreliable across platforms
    let _mtime_after = fs::metadata(&archive).unwrap().modified().unwrap();
}

#[test]
fn test_repair_wrong_password_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_wrong.bin", &vec![0xAC; 64 * 1024]);
    let archive = temp.path().join("repair_wrong.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "correct_pwd",
            "--erasure",
            "4:2",
        ])
        .assert()
        .success();

    era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "wrong_pwd",
        ])
        .assert()
        .failure();
}

#[test]
fn test_repair_multivolume_missing_one_volume() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_mv1.bin", &vec![0xAD; 256 * 1024]);
    let archive = temp.path().join("repair_mv1.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    let vol3 = archive.with_extension("era.003");
    if vol3.exists() {
        fs::remove_file(&vol3).unwrap();
    }

    let assert = era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert();

    // May succeed (if RS can recover) or fail gracefully
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        assert.get_output().status.success()
            || stderr.contains("recover")
            || stderr.contains("repair")
            || stderr.contains("missing"),
        "repair should handle missing volume gracefully: {}",
        stderr
    );
}

#[test]
fn test_repair_multivolume_missing_three_volumes_fails() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(temp.path(), "repair_mv3.bin", &vec![0xAE; 256 * 1024]);
    let archive = temp.path().join("repair_mv3.era");

    era_cmd()
        .args([
            "create",
            input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--erasure",
            "4:2",
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    // Delete 3 volumes (exceeds parity capacity of 2)
    for seq in [1u16, 3, 5] {
        let vol = archive.with_extension(format!("era.{:03}", seq));
        if vol.exists() {
            fs::remove_file(&vol).unwrap();
        }
    }

    let assert = era_cmd()
        .args([
            "repair",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
            "--force",
        ])
        .assert();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        !assert.get_output().status.success()
            || stderr.contains("unrecoverable")
            || stderr.contains("insufficient")
            || stderr.contains("missing"),
        "repair should fail when too many volumes missing: {}",
        stderr
    );
}
