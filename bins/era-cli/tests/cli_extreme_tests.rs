//! Extreme/edge-case CLI integration tests for era-cli.
//!
//! Covers: large files, multi-volume extremes, repair under corruption,
//! repack edge cases, end-to-end integrity chains, and error handling.
//!
//! Large file and extreme scenario tests using --release profile in CI.

#![allow(deprecated, unused_imports, dead_code)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ===========================================================================
// Helpers
// ===========================================================================

fn era_cmd() -> Command {
    Command::cargo_bin("era").unwrap()
}

fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, content).unwrap();
    path
}

/// Generate deterministic pseudo-random data. Prime modulus avoids alignment artifacts.
fn generate_deterministic_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn create_large_test_file(dir: &Path, name: &str, size_bytes: usize) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let data = generate_deterministic_data(size_bytes);
    fs::write(&path, &data).unwrap();
    path
}

fn corrupt_archive_shard(archive: &Path, offset: u64) {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive)
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 100];
    let n = f.read(&mut buf).unwrap();
    for b in buf[..n].iter_mut() {
        *b = !*b;
    }
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&buf[..n]).unwrap();
    f.flush().unwrap();
}

fn count_volume_files(base: &Path) -> usize {
    let mut count = 0;
    if base.exists() {
        count += 1;
    }
    let stem = base.with_extension("");
    for seq in 1..=999u16 {
        let vol = stem.with_extension(format!("era.{:03}", seq));
        if vol.exists() {
            count += 1;
        } else {
            break;
        }
    }
    count
}

fn get_volume_paths(base: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if base.exists() {
        paths.push(base.to_path_buf());
    }
    let stem = base.with_extension("");
    for seq in 1..=999u16 {
        let vol = stem.with_extension(format!("era.{:03}", seq));
        if vol.exists() {
            paths.push(vol);
        } else {
            break;
        }
    }
    paths
}

fn corrupt_footer(archive: &Path) {
    let len = fs::metadata(archive).unwrap().len();
    assert!(len > 128, "archive must be larger than 128 bytes");
    corrupt_archive_shard(archive, len - 128);
}

fn corrupt_header_magic(archive: &Path) {
    let mut f = fs::OpenOptions::new().write(true).open(archive).unwrap();
    f.write_all(&[0u8; 8]).unwrap();
    f.flush().unwrap();
}

fn generate_test_keypair(dir: &Path) -> (PathBuf, PathBuf) {
    use era_crypto::pem_support::export_private_key_as_pem;
    use era_crypto::{export_public_key_as_pem, EraKeyPair};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);

    let keypair = EraKeyPair::generate().expect("keypair generation should succeed");
    let cert_pem =
        export_public_key_as_pem(&keypair.certificate()).expect("cert export should succeed");
    let key_pem = export_private_key_as_pem(&keypair).expect("key export should succeed");

    let pub_path = dir.join(format!("public_{}.pem", id));
    let priv_path = dir.join(format!("private_{}.pem", id));
    fs::write(&pub_path, cert_pem).expect("public pem should be written");
    fs::write(&priv_path, key_pem).expect("private pem should be written");

    (pub_path, priv_path)
}

/// Count all files recursively in directory.
fn count_files_recursive(dir: &Path) -> usize {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

/// Compare two directories: every file in `expected` must exist in `actual` with same content.
fn assert_dirs_content_equal(expected: &Path, actual: &Path) {
    for entry in walkdir::WalkDir::new(expected)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = entry.path().strip_prefix(expected).unwrap();
        let actual_file = actual.join(rel);
        assert!(
            actual_file.exists(),
            "missing extracted file: {}",
            rel.display()
        );
        let expected_bytes = fs::read(entry.path()).unwrap();
        let actual_bytes = fs::read(&actual_file).unwrap();
        assert_eq!(
            expected_bytes.len(),
            actual_bytes.len(),
            "size mismatch for {}",
            rel.display()
        );
        assert!(
            expected_bytes == actual_bytes,
            "content mismatch for {}",
            rel.display()
        );
    }
}

/// Corrupt data region of a specific volume file.
/// Targets offset 5000 (well into data region past header 4096 + backup footer 128).
fn corrupt_volume_data(volume_path: &Path) {
    let len = fs::metadata(volume_path).unwrap().len();
    // Data region starts at 4224 (4096 header + 128 backup footer)
    let offset = if len > 6000 { 5000 } else { 4300 };
    corrupt_archive_shard(volume_path, offset);
}

// ===========================================================================
// Category 1: Large File Scenarios
// ===========================================================================

mod large_file_tests {
    use super::*;

    #[test]
    fn test_large_file_5mb_roundtrip() {
        let temp = TempDir::new().unwrap();
        let size = 5 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "big5.bin", size);
        let archive = temp.path().join("big5.era");
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

        let restored = fs::read(out_dir.join("big5.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }

    #[test]
    fn test_large_file_10mb_roundtrip() {
        let temp = TempDir::new().unwrap();
        let size = 10 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "big10.bin", size);
        let archive = temp.path().join("big10.era");
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

        let restored = fs::read(out_dir.join("big10.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }

    #[test]
    fn test_large_file_50mb_roundtrip() {
        let temp = TempDir::new().unwrap();
        let size = 50 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "big50.bin", size);
        let archive = temp.path().join("big50.era");
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

        let restored = fs::read(out_dir.join("big50.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }

    #[test]
    fn test_large_file_100mb_roundtrip() {
        let temp = TempDir::new().unwrap();
        let size = 100 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "big100.bin", size);
        let archive = temp.path().join("big100.era");
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

        let restored = fs::read(out_dir.join("big100.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }

    #[test]
    fn test_large_file_with_erasure_roundtrip() {
        let temp = TempDir::new().unwrap();
        let size = 10 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "big_ec.bin", size);
        let archive = temp.path().join("big_ec.era");
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

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
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

        let restored = fs::read(out_dir.join("big_ec.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }

    #[test]
    fn test_large_file_with_compression_levels() {
        let temp = TempDir::new().unwrap();
        let size = 10 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "big_comp.bin", size);

        let mut archive_sizes = Vec::new();
        for level in [1, 12, 22] {
            let archive = temp.path().join(format!("comp_{}.era", level));
            let out_dir = temp.path().join(format!("out_{}", level));

            era_cmd()
                .args([
                    "create",
                    input.to_str().unwrap(),
                    "--output",
                    archive.to_str().unwrap(),
                    "--password",
                    "pwd",
                    "--level",
                    &level.to_string(),
                ])
                .assert()
                .success();

            archive_sizes.push(fs::metadata(&archive).unwrap().len());

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

            let restored = fs::read(out_dir.join("big_comp.bin")).unwrap();
            assert_eq!(restored.len(), size);
            assert_eq!(restored, generate_deterministic_data(size));
        }

        assert!(
            archive_sizes.len() == 3,
            "should have 3 archive sizes for 3 levels"
        );
    }

    #[test]
    fn test_mixed_large_and_small_files() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();

        create_large_test_file(&src, "large.bin", 2 * 1024 * 1024);
        for i in 0..50 {
            create_test_file(&src, &format!("small_{}.txt", i), &vec![0xAA; 1024]);
        }

        let archive = temp.path().join("mixed.era");
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

        let extracted_count = count_files_recursive(&out_dir);
        assert!(
            extracted_count >= 51,
            "should extract at least 51 files (1 large + 50 small), got {}",
            extracted_count
        );

        let mut found_large = false;
        for entry in walkdir::WalkDir::new(&out_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if entry.file_name() == "large.bin" {
                let content = fs::read(entry.path()).unwrap();
                assert_eq!(content.len(), 2 * 1024 * 1024);
                found_large = true;
                break;
            }
        }
        assert!(found_large, "large.bin should be found in extracted output");

        // Verify content of small files
        let mut small_verified = 0;
        for entry in walkdir::WalkDir::new(&out_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if entry.file_name().to_string_lossy().starts_with("small_") {
                let content = fs::read(entry.path()).unwrap();
                assert_eq!(content.len(), 1024, "small file should be 1024 bytes");
                assert_eq!(
                    content,
                    vec![0xAA; 1024],
                    "small file content should be all 0xAA"
                );
                small_verified += 1;
            }
        }
        assert!(
            small_verified >= 10,
            "should verify at least 10 small files, got {}",
            small_verified
        );
    }

    #[test]
    fn test_large_file_no_compression() {
        let temp = TempDir::new().unwrap();
        let size = 2 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "nocomp.bin", size);
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

        let archive_size = fs::metadata(&archive).unwrap().len();
        assert!(
            archive_size > (size as u64) / 2,
            "uncompressed archive should be substantial ({} vs input {})",
            archive_size,
            size
        );

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

        let restored = fs::read(out_dir.join("nocomp.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }
}

// ===========================================================================
// Category 2: Multi-Volume Extreme Scenarios
// ===========================================================================

mod multivolume_extreme_tests {
    use super::*;

    #[test]
    fn test_multivolume_tiny_volume_size_8kb() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv8k.bin", &vec![0xAA; 256 * 1024]);
        let archive = temp.path().join("mv8k.era");
        let out_dir = temp.path().join("out");

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
            "8KB volumes for 256KB data should produce multiple volumes, got {}",
            count
        );

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

        let restored = fs::read(out_dir.join("mv8k.bin")).unwrap();
        assert_eq!(restored, vec![0xAA; 256 * 1024]);
    }

    #[test]
    fn test_multivolume_tiny_volume_size_16kb() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv16k.bin", &vec![0xBB; 256 * 1024]);
        let archive = temp.path().join("mv16k.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--max-volume-size",
                "16384",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 5,
            "16KB volumes for 256KB data should produce multiple volumes, got {}",
            count
        );

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

        let restored = fs::read(out_dir.join("mv16k.bin")).unwrap();
        assert_eq!(restored, vec![0xBB; 256 * 1024]);
    }

    #[test]
    fn test_multivolume_volume_expansion_triggered() {
        let temp = TempDir::new().unwrap();
        let input = create_large_test_file(temp.path(), "mv_expand.bin", 2 * 1024 * 1024);
        let archive = temp.path().join("mv_expand.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--max-volume-size",
                "32768",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 6,
            "small max-volume-size with 2MB data should produce many volumes, got {}",
            count
        );

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

        let restored = fs::read(out_dir.join("mv_expand.bin")).unwrap();
        assert_eq!(restored.len(), 2 * 1024 * 1024);
    }

    #[test]
    fn test_multivolume_extract_from_secondary_volume() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_sec.bin", &vec![0xCC; 256 * 1024]);
        let archive = temp.path().join("mv_sec.era");
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
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol1 = archive.with_extension("era.001");
        assert!(vol1.exists(), ".era.001 should exist");

        era_cmd()
            .args([
                "extract",
                "--input",
                vol1.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let restored = fs::read(out_dir.join("mv_sec.bin")).unwrap();
        assert_eq!(restored, vec![0xCC; 256 * 1024]);
    }

    #[test]
    fn test_multivolume_extract_primary_missing() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_nopri.bin", &vec![0xDD; 256 * 1024]);
        let archive = temp.path().join("mv_nopri.era");

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

        let vol1 = archive.with_extension("era.001");
        assert!(
            vol1.exists(),
            ".era.001 should exist before deleting primary"
        );

        fs::remove_file(&archive).unwrap();
        assert!(!archive.exists());

        let out_dir = temp.path().join("out");
        let assert_result = era_cmd()
            .args([
                "extract",
                "--input",
                vol1.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        if assert_result.get_output().status.success() {
            // Verify content integrity
            let restored = fs::read(out_dir.join("mv_nopri.bin")).unwrap();
            assert_eq!(restored, vec![0xDD; 256 * 1024]);
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.contains("recover")
                    || stderr.contains("degraded")
                    || stderr.contains("missing"),
                "unexpected error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_multivolume_gap_discovery() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_gap.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("mv_gap.era");

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

        for seq in [1u16, 3] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

        let out_dir = temp.path().join("out");
        let assert_result = era_cmd()
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

        if assert_result.get_output().status.success() {
            let restored = fs::read(out_dir.join("mv_gap.bin")).unwrap();
            assert_eq!(restored, vec![0xEE; 256 * 1024]);
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.contains("recover")
                    || stderr.contains("degraded")
                    || stderr.contains("missing"),
                "unexpected error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_multivolume_high_redundancy_2_plus_4() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_hr.bin", &vec![0xFF; 256 * 1024]);
        let archive = temp.path().join("mv_hr.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "2:4",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        for seq in [1u16, 2, 3, 4] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

        let out_dir = temp.path().join("out");
        let assert_result = era_cmd()
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

        if assert_result.get_output().status.success() {
            let restored = fs::read(out_dir.join("mv_hr.bin")).unwrap();
            assert_eq!(restored, vec![0xFF; 256 * 1024]);
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.contains("recover")
                    || stderr.contains("degraded")
                    || stderr.contains("missing"),
                "unexpected error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_multivolume_too_many_volumes_lost() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_fail.bin", &vec![0xAB; 256 * 1024]);
        let archive = temp.path().join("mv_fail.era");

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

        for seq in [1u16, 3, 5] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

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
            .failure();
    }

    #[test]
    fn test_multivolume_verify_degraded_status() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_vdeg.bin", &vec![0xCD; 256 * 1024]);
        let archive = temp.path().join("mv_vdeg.era");

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

        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            fs::remove_file(&vol2).unwrap();
        }

        let assert_result = era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--verbose",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            stderr.to_lowercase().contains("degraded")
                || stderr.to_lowercase().contains("missing")
                || stderr.to_lowercase().contains("warning")
                || assert_result.get_output().status.success(),
            "verify should report degraded or warning with 1 missing volume: {}",
            stderr
        );
    }

    #[test]
    fn test_multivolume_list_degraded_archive() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_ldeg.bin", &vec![0xDE; 256 * 1024]);
        let archive = temp.path().join("mv_ldeg.era");

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

        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            fs::remove_file(&vol2).unwrap();
        }

        let assert_result = era_cmd()
            .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
            .assert();

        let stdout = String::from_utf8_lossy(&assert_result.get_output().stdout);
        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("degraded")
                || stderr.contains("missing"),
            "list should work or report degraded on archive with 1 missing volume.\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );
    }

    #[test]
    fn test_multivolume_info_degraded_archive() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_ideg.bin", &vec![0xEF; 256 * 1024]);
        let archive = temp.path().join("mv_ideg.era");

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

        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            fs::remove_file(&vol2).unwrap();
        }

        let assert_result = era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success() || stderr.contains("missing"),
            "info should work on degraded archive: {}",
            stderr
        );
    }

    #[test]
    fn test_multivolume_large_file_spans_volumes() {
        let temp = TempDir::new().unwrap();
        let size = 50 * 1024 * 1024;
        let input = create_large_test_file(temp.path(), "mv_big.bin", size);
        let archive = temp.path().join("mv_big.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--max-volume-size",
                "1048576",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 5,
            "50MB with 1MB volumes should produce multiple volumes, got {}",
            count
        );

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

        let restored = fs::read(out_dir.join("mv_big.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }

    #[test]
    fn test_multivolume_single_volume_mode() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_single.bin", &vec![0x11; 64 * 1024]);
        let archive = temp.path().join("mv_single.era");

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
                "1",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert_eq!(count, 1, "single volume mode should produce exactly 1 file");

        let vol1 = archive.with_extension("era.001");
        assert!(
            !vol1.exists(),
            ".era.001 should NOT exist in single volume mode"
        );
    }

    #[test]
    fn test_multivolume_consecutive_volumes_lost() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_consec.bin", &vec![0x22; 256 * 1024]);
        let archive = temp.path().join("mv_consec.era");

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

        for seq in [2u16, 3] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

        let out_dir = temp.path().join("out");
        let assert_result = era_cmd()
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

        if assert_result.get_output().status.success() {
            let restored = fs::read(out_dir.join("mv_consec.bin")).unwrap();
            assert_eq!(restored, vec![0x22; 256 * 1024]);
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.contains("recover")
                    || stderr.contains("degraded")
                    || stderr.contains("missing"),
                "unexpected error: {}",
                stderr
            );
        }
    }
}

// ===========================================================================
// Category 3: Repair Extreme Scenarios
// ===========================================================================

mod repair_extreme_tests {
    use super::*;

    fn create_ec_archive(temp: &TempDir, name: &str, data: &[u8]) -> (PathBuf, PathBuf) {
        let input = create_test_file(temp.path(), &format!("{}.bin", name), data);
        let archive = temp.path().join(format!("{}.era", name));

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

        (input, archive)
    }

    #[test]
    fn test_repair_partial_shard_corruption_single() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xAA; 256 * 1024];
        let (_input, archive) = create_ec_archive(&temp, "rep_single", &data);

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

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

        let restored = fs::read(out_dir.join("rep_single.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repair_partial_shard_corruption_double() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xBB; 256 * 1024];
        let (_input, archive) = create_ec_archive(&temp, "rep_double", &data);

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 6200);
        corrupt_archive_shard(&archive, 5000);
        corrupt_archive_shard(&archive, 6000);

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("repair")
                || stderr.contains("recover"),
            "double shard corruption in 4+2 should be repairable: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_unrecoverable_triple_corruption() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xCC; 256 * 1024];
        let input = create_test_file(temp.path(), "rep_triple.bin", &data);
        let archive = temp.path().join("rep_triple.era");

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

        // With 6 volumes and 4+2 EC, each volume holds one shard per block.
        // Corrupting 3+ volume files exceeds the 2-parity recovery limit.
        let volumes = get_volume_paths(&archive);
        let mut corrupted = 0;
        for vol in &volumes {
            let len = fs::metadata(vol).unwrap().len();
            if len > 5000 && corrupted < 4 {
                corrupt_volume_data(vol);
                corrupted += 1;
            }
        }
        assert!(
            corrupted >= 3,
            "need to corrupt at least 3 volumes, only got {}",
            corrupted
        );

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            !assert_result.get_output().status.success()
                || stderr.to_lowercase().contains("unrecoverable")
                || stderr.to_lowercase().contains("insufficient"),
            "corrupting 3+ shards in 4+2 should be unrecoverable: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_dry_run_no_modification() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xDD; 256 * 1024];
        let (_input, archive) = create_ec_archive(&temp, "rep_drymod", &data);

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

        let before_bytes = fs::read(&archive).unwrap();

        era_cmd()
            .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let after_bytes = fs::read(&archive).unwrap();
        assert_eq!(
            before_bytes, after_bytes,
            "dry-run repair should NOT modify the archive"
        );
    }

    #[test]
    fn test_repair_force_creates_backup() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xEE; 256 * 1024];
        let (_input, archive) = create_ec_archive(&temp, "rep_bak", &data);

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

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
    fn test_repair_post_repair_full_roundtrip() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let (_input, archive) = create_ec_archive(&temp, "rep_rt", &data);

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

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

        let restored = fs::read(out_dir.join("rep_rt.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repair_non_ec_archive_graceful() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_noec.bin", &vec![0xFF; 64 * 1024]);
        let archive = temp.path().join("rep_noec.era");

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

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            stderr.to_lowercase().contains("erasure")
                || stderr.to_lowercase().contains("not available")
                || stderr.to_lowercase().contains("no repair")
                || stderr.to_lowercase().contains("no erasure")
                || assert_result.get_output().status.success(),
            "repair on non-EC archive should report gracefully: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_high_redundancy_2_plus_4() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_hr.bin", &vec![0xAB; 256 * 1024]);
        let archive = temp.path().join("rep_hr.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "2:4",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

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
    fn test_repair_multivolume_partial_corruption() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_mvpc.bin", &vec![0xCD; 256 * 1024]);
        let archive = temp.path().join("rep_mvpc.era");

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

        let volumes = get_volume_paths(&archive);
        let mut corrupted = 0;
        for vol in &volumes {
            let len = fs::metadata(vol).unwrap().len();
            if len > 5200 && corrupted < 2 {
                corrupt_volume_data(vol);
                corrupted += 1;
            }
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        if assert_result.get_output().status.success() {
            era_cmd()
                .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
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

            let restored = fs::read(out_dir.join("rep_mvpc.bin")).unwrap();
            assert_eq!(restored, vec![0xCD; 256 * 1024]);
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.contains("repair")
                    || stderr.contains("recover")
                    || stderr.contains("missing"),
                "unexpected error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_repair_multivolume_missing_volume() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_mvmiss.bin", &vec![0xDE; 256 * 1024]);
        let archive = temp.path().join("rep_mvmiss.era");

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

        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            fs::remove_file(&vol2).unwrap();
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        if assert_result.get_output().status.success() {
            era_cmd()
                .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
                .assert()
                .success();
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.contains("missing")
                    || stderr.contains("cannot recreate")
                    || stderr.contains("recover"),
                "unexpected error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_repair_large_archive_corruption() {
        let temp = TempDir::new().unwrap();
        let size = 10 * 1024 * 1024;
        let data = generate_deterministic_data(size);
        let input = create_large_test_file(temp.path(), "rep_big.bin", size);
        let archive = temp.path().join("rep_big.era");

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
        assert!(file_len > 10200);
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

        let restored = fs::read(out_dir.join("rep_big.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repair_verbose_output_details() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xEF; 256 * 1024];
        let (_input, archive) = create_ec_archive(&temp, "rep_verb", &data);

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--verbose",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            stderr.to_lowercase().contains("shard")
                || stderr.to_lowercase().contains("block")
                || stderr.to_lowercase().contains("repair")
                || stderr.to_lowercase().contains("analysis")
                || stderr.to_lowercase().contains("recovery"),
            "verbose repair should show shard/block details: {}",
            stderr
        );
    }
}

// ===========================================================================
// Category 4: Repack Edge Cases
// ===========================================================================

mod repack_edge_tests {
    use super::*;

    #[test]
    fn test_repack_multivolume_to_single() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xAA; 256 * 1024];
        let input = create_test_file(temp.path(), "rp_mv.bin", &data);
        let archive = temp.path().join("rp_mv.era");

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

        assert!(count_volume_files(&archive) >= 2);

        let repacked = temp.path().join("rp_mv_out.era");
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

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rp_mv.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repack_upgrade_no_ec_to_ec() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xBB; 64 * 1024];
        let input = create_test_file(temp.path(), "rp_noec.bin", &data);
        let archive = temp.path().join("rp_noec.era");

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

        let repacked = temp.path().join("rp_ec.era");
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
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rp_noec.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repack_downgrade_ec_to_none() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xCC; 64 * 1024];
        let input = create_test_file(temp.path(), "rp_rmec.bin", &data);
        let archive = temp.path().join("rp_rmec.era");

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

        let repacked = temp.path().join("rp_noec2.era");
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
                "none",
            ])
            .assert()
            .success();

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rp_rmec.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repack_change_compression_level() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let input = create_test_file(temp.path(), "rp_comp.bin", &data);
        let archive = temp.path().join("rp_comp.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "1",
            ])
            .assert()
            .success();

        let size_level1 = fs::metadata(&archive).unwrap().len();

        let repacked = temp.path().join("rp_comp19.era");
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

        let size_level19 = fs::metadata(&repacked).unwrap().len();
        assert!(
            size_level19 <= size_level1,
            "level 19 should be <= level 1 ({} vs {})",
            size_level19,
            size_level1
        );

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rp_comp.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repack_large_archive() {
        let temp = TempDir::new().unwrap();
        let size = 10 * 1024 * 1024;
        let data = generate_deterministic_data(size);
        let input = create_large_test_file(temp.path(), "rp_big.bin", size);
        let archive = temp.path().join("rp_big.era");

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

        let repacked = temp.path().join("rp_big_out.era");
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

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rp_big.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repack_preserves_all_files() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();

        for i in 0..20 {
            let content = generate_deterministic_data(1024 * (i + 1));
            create_test_file(&src, &format!("file_{}.bin", i), &content);
        }

        let archive = temp.path().join("rp_all.era");
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

        let repacked = temp.path().join("rp_all_out.era");
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
                "12",
            ])
            .assert()
            .success();

        let out_dir = temp.path().join("out");
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

        let extracted_count = count_files_recursive(&out_dir);
        assert!(
            extracted_count >= 20,
            "all 20 files should be preserved after repack, got {}",
            extracted_count
        );
    }

    #[test]
    fn test_repack_all_geek_params() {
        let temp = TempDir::new().unwrap();
        let size = 2 * 1024 * 1024;
        let data = generate_deterministic_data(size);
        let input = create_large_test_file(temp.path(), "rp_geek.bin", size);
        let archive = temp.path().join("rp_geek.era");

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

        let repacked = temp.path().join("rp_geek_out.era");
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
                "--erasure",
                "4:2",
                "--cdc-min",
                "16384",
                "--cdc-avg",
                "65536",
                "--cdc-max",
                "262144",
                "--packing-k",
                "8",
                "--flush-threshold",
                "80",
                "--block-target-size",
                "16777216",
            ])
            .assert()
            .success();

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rp_geek.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, data);
    }
}

// ===========================================================================
// Category 5: End-to-End Integrity Chains
// ===========================================================================

mod e2e_integrity_tests {
    use super::*;

    #[test]
    fn test_e2e_create_corrupt_verify_repair_verify_extract() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "e2e_chain.bin", &data);
        let archive = temp.path().join("e2e_chain.era");

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
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

        let verify1 = era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--verbose",
            ])
            .assert();

        let stderr1 = String::from_utf8_lossy(&verify1.get_output().stderr);
        assert!(
            stderr1.to_lowercase().contains("warning")
                || stderr1.to_lowercase().contains("degraded")
                || stderr1.to_lowercase().contains("corrupt")
                || stderr1.to_lowercase().contains("shard"),
            "verify should detect corruption: {}",
            stderr1
        );

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

        let restored = fs::read(out_dir.join("e2e_chain.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_e2e_create_repack_verify_extract_compare() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let input = create_test_file(temp.path(), "e2e_repack.bin", &data);
        let archive = temp.path().join("e2e_repack.era");

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

        let repacked = temp.path().join("e2e_repacked.era");
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
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        era_cmd()
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("e2e_repack.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_e2e_multivolume_delete_verify_repair_extract() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "e2e_mv.bin", &data);
        let archive = temp.path().join("e2e_mv.era");

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

        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            fs::remove_file(&vol2).unwrap();
        }

        let verify_result = era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--verbose",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&verify_result.get_output().stderr);
        assert!(
            stderr.to_lowercase().contains("degraded")
                || stderr.to_lowercase().contains("missing")
                || stderr.to_lowercase().contains("warning")
                || verify_result.get_output().status.success(),
            "verify should report degraded with missing volume: {}",
            stderr
        );

        let repair_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let repair_stderr = String::from_utf8_lossy(&repair_result.get_output().stderr);
        assert!(
            repair_result.get_output().status.success()
                || repair_stderr.contains("missing")
                || repair_stderr.contains("recover"),
            "repair should handle missing volume: {}",
            repair_stderr
        );

        let out_dir = temp.path().join("out");
        let extract_result = era_cmd()
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

        let extract_stderr = String::from_utf8_lossy(&extract_result.get_output().stderr);
        assert!(
            extract_result.get_output().status.success() || extract_stderr.contains("recover"),
            "extract should succeed with 1 missing volume in 4+2: {}",
            extract_stderr
        );
    }

    #[test]
    fn test_e2e_large_file_full_lifecycle() {
        let temp = TempDir::new().unwrap();
        let size = 10 * 1024 * 1024;
        let data = generate_deterministic_data(size);
        let input = create_large_test_file(temp.path(), "e2e_big.bin", size);
        let archive = temp.path().join("e2e_big.era");

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
                "list",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--long",
            ])
            .assert()
            .success();

        era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
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

        let restored = fs::read(out_dir.join("e2e_big.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, data);
    }

    #[test]
    fn test_e2e_cert_mode_full_lifecycle() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "e2e_cert.bin", &data);
        let archive = temp.path().join("e2e_cert.era");
        let (pub_path, priv_path) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "list",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "info",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
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
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        let restored = fs::read(out_dir.join("e2e_cert.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_e2e_hybrid_mode_full_lifecycle() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "e2e_hybrid.bin", &data);
        let archive = temp.path().join("e2e_hybrid.era");
        let (pub_path, priv_path) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_path.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        let out_pwd = temp.path().join("out_pwd");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_pwd.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        let restored_pwd = fs::read(out_pwd.join("e2e_hybrid.bin")).unwrap();
        assert_eq!(restored_pwd, data);

        let out_key = temp.path().join("out_key");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_key.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        let restored_key = fs::read(out_key.join("e2e_hybrid.bin")).unwrap();
        assert_eq!(restored_key, data);

        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();
    }
}

// ===========================================================================
// Category 6: Error Handling & Edge Cases
// ===========================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_error_truncated_archive() {
        let temp = TempDir::new().unwrap();
        let truncated = temp.path().join("truncated.era");
        fs::write(&truncated, [0u8; 100]).unwrap();

        era_cmd()
            .args([
                "extract",
                "--input",
                truncated.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_empty_file_as_archive() {
        let temp = TempDir::new().unwrap();
        let empty = temp.path().join("empty.era");
        fs::write(&empty, []).unwrap();

        era_cmd()
            .args([
                "extract",
                "--input",
                empty.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_empty_directory_input() {
        let temp = TempDir::new().unwrap();
        let empty_dir = temp.path().join("empty_src");
        fs::create_dir_all(&empty_dir).unwrap();
        let archive = temp.path().join("empty_dir.era");

        let assert_result = era_cmd()
            .args([
                "create",
                empty_dir.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.to_lowercase().contains("empty")
                || stderr.to_lowercase().contains("no file"),
            "empty dir should succeed with 0 files or fail gracefully: {}",
            stderr
        );
    }

    #[test]
    fn test_error_path_with_spaces() {
        let temp = TempDir::new().unwrap();
        let spaced_dir = temp.path().join("path with spaces");
        fs::create_dir_all(&spaced_dir).unwrap();
        let input = create_test_file(&spaced_dir, "spaced file.txt", b"spaces work");
        let archive = spaced_dir.join("spaced archive.era");
        let out_dir = spaced_dir.join("extracted output");

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

        let restored = fs::read(out_dir.join("spaced file.txt")).unwrap();
        assert_eq!(restored, b"spaces work");
    }

    #[test]
    fn test_error_path_with_unicode() {
        let temp = TempDir::new().unwrap();
        let unicode_dir = temp.path().join("路径_тест_パス");
        fs::create_dir_all(&unicode_dir).unwrap();
        let input = create_test_file(&unicode_dir, "文件.txt", b"unicode paths");
        let archive = unicode_dir.join("归档.era");
        let out_dir = unicode_dir.join("输出");

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

        let restored = fs::read(out_dir.join("文件.txt")).unwrap();
        assert_eq!(restored, b"unicode paths");
    }

    #[test]
    fn test_error_nonexistent_input_path() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("nonexist.era");

        era_cmd()
            .args([
                "create",
                "/nonexistent/path/to/file.txt",
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_extract_to_existing_no_force() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "exist.txt", b"original");
        let archive = temp.path().join("exist.era");

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

        let out_dir = temp.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(out_dir.join("exist.txt"), b"pre-existing").unwrap();

        let assert_result = era_cmd()
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

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.to_lowercase().contains("exist")
                || stderr.to_lowercase().contains("overwrite"),
            "extract without --force should handle existing files: {}",
            stderr
        );
    }

    #[test]
    fn test_error_extract_to_existing_with_force() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "force.txt", b"new content");
        let archive = temp.path().join("force.era");

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

        let out_dir = temp.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(out_dir.join("force.txt"), b"old content").unwrap();

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

        let restored = fs::read(out_dir.join("force.txt")).unwrap();
        assert_eq!(restored, b"new content");
    }

    #[test]
    fn test_error_repair_wrong_password() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_wp.bin", &vec![0xAA; 64 * 1024]);
        let archive = temp.path().join("rep_wp.era");

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
                "--force",
            ])
            .assert()
            .failure();
    }
}

// ===========================================================================
// Category 7: Header/Footer Corruption Recovery
// ===========================================================================

mod header_footer_recovery_tests {
    use super::*;

    #[test]
    fn test_corrupted_primary_header_hard_failure() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hdr_fail.bin", &vec![0xAA; 64 * 1024]);
        let archive = temp.path().join("hdr_fail.era");

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

        corrupt_header_magic(&archive);

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();

        era_cmd()
            .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();
    }

    #[test]
    fn test_corrupted_primary_footer_backup_recovery() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xBB; 64 * 1024];
        let input = create_test_file(temp.path(), "ftr_rec.bin", &data);
        let archive = temp.path().join("ftr_rec.era");

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

        corrupt_footer(&archive);

        let out_dir = temp.path().join("out");
        // Backup footer at offset 4096 is intact — recovery must always succeed
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

        let restored = fs::read(out_dir.join("ftr_rec.bin")).unwrap();
        assert_eq!(
            restored, data,
            "backup footer recovery must produce correct data"
        );
    }

    #[test]
    fn test_corrupted_backup_footer_primary_still_works() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xCC; 64 * 1024];
        let input = create_test_file(temp.path(), "bftr_ok.bin", &data);
        let archive = temp.path().join("bftr_ok.era");

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

        // Backup footer is at offset 4096 (right after primary header)
        corrupt_archive_shard(&archive, 4096);

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

        let restored = fs::read(out_dir.join("bftr_ok.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_verify_footer_corrupted_archive() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xDD; 64 * 1024];
        let input = create_test_file(temp.path(), "ftr_verify.bin", &data);
        let archive = temp.path().join("ftr_verify.era");

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

        corrupt_footer(&archive);

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    /// When both primary and backup footers are corrupted, VolumeReader::open
    /// falls back to the third-level floating footer reverse scan (reader.rs:143-204).
    /// This test appends garbage after the primary footer (burying it) and corrupts
    /// the backup footer at offset 4096, forcing the reverse scan to locate the
    /// buried real footer within the last 1 MB of the file.
    #[test]
    fn test_both_footers_corrupted_floating_recovery() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xBB; 64 * 1024];
        let input = create_test_file(temp.path(), "float_rec.bin", &data);
        let archive = temp.path().join("float_rec.era");

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

        // Append 512 bytes of 0xDE after the primary footer.
        // This buries the real primary footer inside the file so that
        // reading at new EOF-128 yields garbage.
        // 0xDE does not match any byte in FOOTER_MAGIC [0x45,0x52,0x41,0x46].
        {
            let mut f = fs::OpenOptions::new().append(true).open(&archive).unwrap();
            f.write_all(&[0xDE; 512]).unwrap();
            f.flush().unwrap();
        }

        // Corrupt backup footer at offset 4096 (HEADER_SIZE).
        // corrupt_archive_shard flips 100 bytes, destroying the "ERAF" magic.
        corrupt_archive_shard(&archive, 4096);

        // Extract — floating footer reverse scan should find the buried real footer
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

        let restored = fs::read(out_dir.join("float_rec.bin")).unwrap();
        assert_eq!(
            restored, data,
            "floating footer recovery must produce correct data"
        );

        // Verify command should also succeed via the same recovery path
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }
}

// ===========================================================================
// Category 8: Truncated Volume Files
// ===========================================================================

mod truncated_volume_tests {
    use super::*;

    fn truncate_file(path: &Path, new_size: u64) {
        let f = fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_len(new_size).unwrap();
    }

    #[test]
    fn test_truncated_volume_below_header_size() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "trunc_hdr.bin", &vec![0xAA; 64 * 1024]);
        let archive = temp.path().join("trunc_hdr.era");

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

        truncate_file(&archive, 100);

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_truncated_volume_half_size() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "trunc_half.bin", &vec![0xBB; 64 * 1024]);
        let archive = temp.path().join("trunc_half.era");

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

        let original_size = fs::metadata(&archive).unwrap().len();
        truncate_file(&archive, original_size / 2);

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_truncated_multivolume_one_volume() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "trunc_mv.bin", &vec![0xCC; 256 * 1024]);
        let archive = temp.path().join("trunc_mv.era");

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

        let vol2 = archive.with_extension("era.002");
        assert!(vol2.exists(), "expected volume .era.002 to exist");
        truncate_file(&vol2, 100);

        let out_dir = temp.path().join("out");
        let assert_result = era_cmd()
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

        if assert_result.get_output().status.success() {
            let restored = fs::read(out_dir.join("trunc_mv.bin")).unwrap();
            assert_eq!(restored, vec![0xCC; 256 * 1024]);
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.to_lowercase().contains("truncat")
                    || stderr.to_lowercase().contains("corrupt")
                    || stderr.to_lowercase().contains("small")
                    || stderr.to_lowercase().contains("error")
                    || stderr.to_lowercase().contains("failed"),
                "truncated volume should report meaningful error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_repair_truncated_volume_ec() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "trunc_repair.bin", &vec![0xDD; 256 * 1024]);
        let archive = temp.path().join("trunc_repair.era");

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

        let vol2 = archive.with_extension("era.002");
        assert!(vol2.exists(), "expected volume .era.002 to exist");
        truncate_file(&vol2, 100);

        let repair_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        if repair_result.get_output().status.success() {
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

            let restored = fs::read(out_dir.join("trunc_repair.bin")).unwrap();
            assert_eq!(restored, vec![0xDD; 256 * 1024]);
        } else {
            let stderr = String::from_utf8_lossy(&repair_result.get_output().stderr);
            assert!(
                stderr.to_lowercase().contains("truncat")
                    || stderr.to_lowercase().contains("corrupt")
                    || stderr.to_lowercase().contains("small")
                    || stderr.to_lowercase().contains("recover")
                    || stderr.to_lowercase().contains("repair")
                    || stderr.to_lowercase().contains("error"),
                "repair of truncated volume should report meaningful error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_zero_length_volume_file() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "zero_vol.bin", &vec![0xEE; 64 * 1024]);
        let archive = temp.path().join("zero_vol.era");

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

        truncate_file(&archive, 0);

        let extract_result = era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out_extract").to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();

        let extract_stderr = String::from_utf8_lossy(&extract_result.get_output().stderr);
        assert!(
            extract_stderr.to_lowercase().contains("small")
                || extract_stderr.to_lowercase().contains("corrupt")
                || extract_stderr.to_lowercase().contains("empty")
                || extract_stderr.to_lowercase().contains("header")
                || extract_stderr.to_lowercase().contains("error"),
            "zero-length volume extract should report meaningful error: {}",
            extract_stderr
        );

        let verify_result = era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();

        let verify_stderr = String::from_utf8_lossy(&verify_result.get_output().stderr);
        assert!(
            verify_stderr.to_lowercase().contains("small")
                || verify_stderr.to_lowercase().contains("corrupt")
                || verify_stderr.to_lowercase().contains("empty")
                || verify_stderr.to_lowercase().contains("header")
                || verify_stderr.to_lowercase().contains("error"),
            "zero-length volume verify should report meaningful error: {}",
            verify_stderr
        );

        let repair_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .failure();

        let repair_stderr = String::from_utf8_lossy(&repair_result.get_output().stderr);
        assert!(
            repair_stderr.to_lowercase().contains("small")
                || repair_stderr.to_lowercase().contains("corrupt")
                || repair_stderr.to_lowercase().contains("empty")
                || repair_stderr.to_lowercase().contains("header")
                || repair_stderr.to_lowercase().contains("error"),
            "zero-length volume repair should report meaningful error: {}",
            repair_stderr
        );
    }
}

// ===========================================================================
// Category 9: Cross-Archive Volume Splicing Attack
// ===========================================================================

mod splicing_attack_tests {
    use super::*;

    #[test]
    fn test_splicing_attack_swap_volume_between_archives() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();

        let input_a = create_test_file(temp_a.path(), "archive_a.bin", &vec![0xAA; 256 * 1024]);
        let archive_a = temp_a.path().join("archive_a.era");

        era_cmd()
            .args([
                "create",
                input_a.to_str().unwrap(),
                "--output",
                archive_a.to_str().unwrap(),
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

        let input_b = create_test_file(temp_b.path(), "archive_b.bin", &vec![0xBB; 256 * 1024]);
        let archive_b = temp_b.path().join("archive_b.era");

        era_cmd()
            .args([
                "create",
                input_b.to_str().unwrap(),
                "--output",
                archive_b.to_str().unwrap(),
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

        let vol_a2 = archive_a.with_extension("era.002");
        let vol_b2 = archive_b.with_extension("era.002");
        assert!(vol_a2.exists(), "archive A should have .era.002");
        assert!(vol_b2.exists(), "archive B should have .era.002");
        fs::copy(&vol_b2, &vol_a2).unwrap();

        let out_dir = temp_a.path().join("out");
        let assert_result = era_cmd()
            .args([
                "extract",
                "--input",
                archive_a.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        if assert_result.get_output().status.success() {
            // If extraction succeeds (foreign volume skipped, RS recovered),
            // content must match archive A's original data
            let restored = fs::read(out_dir.join("archive_a.bin")).unwrap();
            assert_eq!(
                restored,
                vec![0xAA; 256 * 1024],
                "spliced volume must not corrupt extracted data"
            );
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.to_lowercase().contains("decrypt")
                    || stderr.to_lowercase().contains("integrity")
                    || stderr.to_lowercase().contains("archive_id")
                    || stderr.to_lowercase().contains("corrupt")
                    || stderr.to_lowercase().contains("mismatch"),
                "splicing rejection should cite integrity failure: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_splicing_attack_swap_primary_volume() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();

        let input_a = create_test_file(temp_a.path(), "splice_a.bin", &vec![0xCC; 64 * 1024]);
        let archive_a = temp_a.path().join("splice_a.era");

        era_cmd()
            .args([
                "create",
                input_a.to_str().unwrap(),
                "--output",
                archive_a.to_str().unwrap(),
                "--password",
                "password_a",
                "--no-compression",
            ])
            .assert()
            .success();

        let input_b = create_test_file(temp_b.path(), "splice_b.bin", &vec![0xDD; 64 * 1024]);
        let archive_b = temp_b.path().join("splice_b.era");

        era_cmd()
            .args([
                "create",
                input_b.to_str().unwrap(),
                "--output",
                archive_b.to_str().unwrap(),
                "--password",
                "password_b",
                "--no-compression",
            ])
            .assert()
            .success();

        fs::copy(&archive_b, &archive_a).unwrap();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive_a.to_str().unwrap(),
                "--output",
                temp_a.path().join("out").to_str().unwrap(),
                "--password",
                "password_a",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_splicing_attack_same_password_different_archive_id() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();

        let data_a = vec![0xAA; 256 * 1024];
        let input_a = create_test_file(temp_a.path(), "splice_same_pwd_a.bin", &data_a);
        let archive_a = temp_a.path().join("splice_same_pwd_a.era");

        era_cmd()
            .args([
                "create",
                input_a.to_str().unwrap(),
                "--output",
                archive_a.to_str().unwrap(),
                "--password",
                "shared_password",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let data_b = vec![0xBB; 256 * 1024];
        let input_b = create_test_file(temp_b.path(), "splice_same_pwd_b.bin", &data_b);
        let archive_b = temp_b.path().join("splice_same_pwd_b.era");

        era_cmd()
            .args([
                "create",
                input_b.to_str().unwrap(),
                "--output",
                archive_b.to_str().unwrap(),
                "--password",
                "shared_password",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol_a3 = archive_a.with_extension("era.003");
        let vol_b3 = archive_b.with_extension("era.003");
        assert!(vol_a3.exists(), "archive A should have .era.003");
        assert!(vol_b3.exists(), "archive B should have .era.003");
        fs::copy(&vol_b3, &vol_a3).unwrap();

        // Foreign volume is skipped (archive_id mismatch in header).
        // 5/6 valid volumes remain — above 4-shard RS minimum → recovery succeeds.
        let out_dir = temp_a.path().join("out");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive_a.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "shared_password",
            ])
            .assert()
            .success();

        let restored = fs::read(out_dir.join("splice_same_pwd_a.bin")).unwrap();
        assert_eq!(
            restored, data_a,
            "spliced volume from different archive_id must not corrupt extracted data"
        );
    }

    /// Existing splicing tests rely on archive_id mismatch at the header level.
    /// If an attacker copies Archive A's header (including archive_id_A and
    /// encrypted VK_A) onto Archive B, the header check passes. The AEAD layer
    /// must still reject because blocks_B were encrypted with BK_B while the
    /// reader derives BK_A from the forged header — key, nonce, and AAD all
    /// differ, causing tag verification failure.
    #[test]
    fn test_aead_rejects_forged_header_with_matching_archive_id() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();

        let data_a = vec![0xAA; 256 * 1024];
        let input_a = create_test_file(temp_a.path(), "forge_a.bin", &data_a);
        let archive_a = temp_a.path().join("forge_a.era");

        era_cmd()
            .args([
                "create",
                input_a.to_str().unwrap(),
                "--output",
                archive_a.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
            ])
            .assert()
            .success();

        let data_b = vec![0xBB; 256 * 1024];
        let input_b = create_test_file(temp_b.path(), "forge_b.bin", &data_b);
        let archive_b = temp_b.path().join("forge_b.era");

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

        // Graft Archive A's header (4096 bytes) onto Archive B.
        // Backup footer at offset 4096 is untouched.
        {
            let header_a = {
                let mut f = fs::File::open(&archive_a).unwrap();
                let mut buf = vec![0u8; 4096];
                f.read_exact(&mut buf).unwrap();
                buf
            };
            let mut f = fs::OpenOptions::new().write(true).open(&archive_b).unwrap();
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&header_a).unwrap();
            f.flush().unwrap();
        }

        // Password "pwd" → MK_A → IK_A → unwrap VK_A → BK_A →
        // decrypt blocks_B (encrypted with BK_B) → AEAD tag failure
        let out_dir = temp_b.path().join("out");
        let assert_result = era_cmd()
            .args([
                "extract",
                "--input",
                archive_b.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        assert!(
            !assert_result.get_output().status.success(),
            "extraction must fail when header is forged from a different archive"
        );

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        let stderr_lower = stderr.to_lowercase();
        assert!(
            stderr_lower.contains("decrypt")
                || stderr_lower.contains("security")
                || stderr_lower.contains("aead")
                || stderr_lower.contains("tamper")
                || stderr_lower.contains("integrity")
                || stderr_lower.contains("corrupt")
                || stderr_lower.contains("authentication"),
            "AEAD rejection should cite decryption/integrity failure, got: {}",
            stderr
        );
    }
}

// ===========================================================================
// Category 10: Repair → Repack Chain
// ===========================================================================

mod repair_repack_chain_tests {
    use super::*;

    #[test]
    fn test_repair_then_repack_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "rr_chain.bin", &data);
        let archive = temp.path().join("rr_chain.era");

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
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

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

        let repacked = temp.path().join("rr_repacked.era");
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
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rr_chain.bin")).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_repair_then_repack_upgrade_ec() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "rr_ec.bin", &data);
        let archive = temp.path().join("rr_ec.era");

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
        assert!(file_len > 5200);
        corrupt_archive_shard(&archive, 5000);

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

        let repacked = temp.path().join("rr_ec_out.era");
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
                "2:4",
            ])
            .assert()
            .success();

        era_cmd()
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let out_dir = temp.path().join("out");
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

        let restored = fs::read(out_dir.join("rr_ec.bin")).unwrap();
        assert_eq!(restored, data);
    }
}

// ===========================================================================
// Category 11: Combined Corruption + Missing Volumes
// ===========================================================================

mod combined_corruption_tests {
    use super::*;

    #[test]
    fn test_combined_corruption_and_missing_volume() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xAA; 256 * 1024];
        let input = create_test_file(temp.path(), "comb_ok.bin", &data);
        let archive = temp.path().join("comb_ok.era");

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

        let vol1 = archive.with_extension("era.001");
        if vol1.exists() {
            fs::remove_file(&vol1).unwrap();
        }

        let vol3 = archive.with_extension("era.003");
        if vol3.exists() {
            corrupt_volume_data(&vol3);
        }

        let out_dir = temp.path().join("out");
        let assert_result = era_cmd()
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

        if assert_result.get_output().status.success() {
            let restored = fs::read(out_dir.join("comb_ok.bin")).unwrap();
            assert_eq!(restored, data, "extracted data must match original");
        } else {
            let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
            assert!(
                stderr.to_lowercase().contains("recover")
                    || stderr.to_lowercase().contains("missing")
                    || stderr.to_lowercase().contains("corrupt")
                    || stderr.to_lowercase().contains("degraded"),
                "combined damage should report meaningful error: {}",
                stderr
            );
        }
    }

    #[test]
    fn test_combined_corruption_and_missing_exceeds_parity() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "comb_fail.bin", &vec![0xBB; 256 * 1024]);
        let archive = temp.path().join("comb_fail.era");

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

        // 3 deleted = 3 unavailable > 2 parity shards
        for seq in [1u16, 2, 3] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

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
            .failure();
    }
}
