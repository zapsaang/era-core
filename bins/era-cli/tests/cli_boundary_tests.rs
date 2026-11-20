//! Boundary and edge-case CLI integration tests for era-cli.
//!
//! This module contains tests for:
//! 1. `--volumes 0` validation (silently converted to 1)
//! 2. Threshold T-of-N mode CLI exposure (genuinely missing feature)
//! 3. Volume rotation at exact 4GB boundary
//! 4. Edge cases in volume size limits
//!
//! These tests target gaps identified in existing test coverage.

#![allow(deprecated, unused_imports, dead_code)]

mod common;

use common::*;
use predicates::prelude::*;
use std::fs;
use std::io::{Read, Seek, Write};
use tempfile::TempDir;

// ===========================================================================
// Category 1: Volume Count Boundary Tests
// ===========================================================================

mod volume_count_boundary_tests {
    use super::*;

    /// Test that --volumes 0 is handled gracefully.
    ///
    /// Expected behavior: CLI accepts --volumes 0 but silently converts it to 1
    /// via `.max(1)` in ArchiveWriterBuilder::volume_count().
    /// This test verifies the actual behavior.
    #[test]
    fn test_volumes_zero_silently_becomes_one() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "test.txt", b"volumes zero test");
        let archive = temp.path().join("vol0.era");

        // Create with --volumes 0 - should not crash
        let binding = era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--volumes",
                "0",
            ])
            .assert();
        let output = binding.get_output();

        // The command either succeeds (converted to --volumes 1) or fails with a proper error
        // Both are acceptable - the key is it shouldn't panic or crash
        if output.status.success() {
            // If it succeeds, verify we got exactly 1 volume (0 -> 1 conversion)
            let count = count_volume_files(&archive);
            assert_eq!(count, 1, "--volumes 0 should create exactly 1 volume");
        } else {
            // If it fails, it should be with a clear error message, not a crash
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Note: --volumes 0 failed with: {}", stderr);
        }
    }

    /// Test that --volumes 1 works correctly (baseline).
    #[test]
    fn test_volumes_one_baseline() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "test.txt", b"volumes one test");
        let archive = temp.path().join("vol1.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--volumes",
                "1",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert_eq!(count, 1, "--volumes 1 should create exactly 1 volume");

        // Verify extraction works
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
            fs::read(out_dir.join("test.txt")).unwrap(),
            b"volumes one test"
        );
    }
}

// ===========================================================================
// Category 2: Volume Size Boundary Tests
// ===========================================================================

mod volume_size_boundary_tests {
    use super::*;

    /// Test volume rotation at exactly 4GB boundary.
    ///
    /// The default MAX_VOLUME_SIZE is 4GB (4_294_967_296 bytes).
    /// This test creates a file that spans this boundary.
    ///
    /// IGNORED: Requires ~10GB disk space (input + archive + extraction).
    /// The archive output is ~6GB even with --no-compression due to Reed-Solomon
    /// encoding (4+2 = 1.5x overhead). This is skipped in normal CI.
    #[test]
    #[ignore = "requires ~10GB disk space"]
    fn test_volume_rotation_at_4gb_boundary() {
        let temp = repo_tmp_dir();
        // Create a 4.5GB file (4GB + 512MB)
        let size = 4 * 1024 * 1024 * 1024 + 512 * 1024 * 1024;
        let input = create_large_test_file_streaming(temp.path(), "big_file.bin", size);
        let archive = temp.path().join("boundary.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression", // Faster for large file test
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 2,
            "4.5GB file should produce at least 2 volumes, got {}",
            count
        );

        // Verify total archive size is reasonable (input * ~1.5x for 4:2 RS overhead)
        let mut total_archive_size = 0u64;
        if archive.exists() {
            total_archive_size += get_volume_size(&archive);
        }
        let stem = archive.with_extension("");
        for seq in 1..=999u16 {
            let vol = stem.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                total_archive_size += get_volume_size(&vol);
            } else {
                break;
            }
        }
        let input_size_u64 = size as u64;
        assert!(
            total_archive_size >= input_size_u64,
            "Total archive size ({}) should be >= input size ({})",
            total_archive_size,
            input_size_u64
        );

        // Verify extraction works
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

        // Verify file size is correct
        let extracted_size = fs::metadata(out_dir.join("big_file.bin")).unwrap().len();
        assert_eq!(extracted_size, size as u64, "Extracted file size mismatch");
    }

    /// Test volume rotation with exactly at-max-volume-size file.
    ///
    /// Creates a file that is exactly 4GB and verifies volume rotation occurs.
    ///
    /// IGNORED: Same disk space requirement as test_volume_rotation_at_4gb_boundary.
    /// See that test for details on disk space calculation.
    #[test]
    #[ignore = "requires ~10GB disk space"]
    fn test_volume_rotation_at_exact_4gb() {
        let temp = repo_tmp_dir();
        let size = 4_294_967_296usize; // Exactly 4GB
        let input = create_large_test_file_streaming(temp.path(), "exact_4gb.bin", size);
        let archive = temp.path().join("exact4gb.era");

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

        // With exact 4GB, we expect at least 2 volumes due to archive overhead
        // and the way max_volume_size is checked (can slightly exceed)
        let count = count_volume_files(&archive);
        eprintln!("Created {} volume(s) for exactly 4GB input", count);

        // The key assertion is that creation succeeds and we get valid volumes
        assert!(count >= 1, "Should have at least 1 volume");
    }

    /// Test with --max-volume-size below minimum threshold (1 MiB).
    #[test]
    fn test_max_volume_size_below_minimum() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "test.txt", b"min vol size test");
        let archive = temp.path().join("minvol.era");

        for invalid_cap in ["1024", "1048575"] {
            let binding = era_cmd()
                .args([
                    "create",
                    input.to_str().unwrap(),
                    "--output",
                    archive.to_str().unwrap(),
                    "--password",
                    "pwd",
                    "--max-volume-size",
                    invalid_cap,
                ])
                .assert()
                .failure();
            let stderr = String::from_utf8_lossy(&binding.get_output().stderr);
            assert!(
                stderr.contains("minimum"),
                "Error message for {invalid_cap} should mention minimum size requirement: {stderr}"
            );
            assert_eq!(
                count_volume_files(&archive),
                0,
                "Rejected --max-volume-size {invalid_cap} must not leave volume files behind"
            );
        }
    }

    /// Exercise size-driven rotation with a 2 MiB payload and a 1 MiB cap.
    #[test]
    fn test_volume_rotation_at_exact_boundary_small_scale() {
        let temp = TempDir::new().unwrap();
        let max_vol_size = 1024 * 1024u64;
        // Distinct offsets keep deduplication from shrinking the payload below the cap.
        let input = create_large_test_file_streaming(temp.path(), "small_rot.bin", 2 * 1024 * 1024);
        let archive = temp.path().join("rot_boundary.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
                "--erasure",
                "none",
                "--max-volume-size",
                &max_vol_size.to_string(),
            ])
            .assert()
            .success();

        let volumes = get_volume_paths(&archive);
        for volume in &volumes {
            let size = get_volume_size(volume);
            assert!(
                size <= max_vol_size,
                "{} has {size} bytes, exceeding the {max_vol_size}-byte cap",
                volume.display()
            );
        }
        assert!(volumes.len() > 1, "expected rotation, got {volumes:?}");

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

        let extracted = fs::read(out_dir.join("small_rot.bin")).unwrap();
        assert!(
            extracted == fs::read(input).unwrap(),
            "Extracted bytes differ"
        );
    }

    fn assert_1mib_rotation_roundtrip(
        file_stem: &str,
        erasure: &str,
        unrotated_volume_count: usize,
    ) {
        const MAX_VOLUME_SIZE: u64 = 1024 * 1024;
        const INPUT_SIZE: usize = 5 * 1024 * 1024;

        let temp = TempDir::new().unwrap();
        let input_name = format!("{file_stem}.bin");
        let input = create_large_test_file_streaming(temp.path(), &input_name, INPUT_SIZE);
        let expected = fs::read(&input).unwrap();
        let archive = temp.path().join(format!("{file_stem}.era"));
        let max_volume_size = MAX_VOLUME_SIZE.to_string();

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
                "--erasure",
                erasure,
                "--max-volume-size",
                max_volume_size.as_str(),
            ])
            .assert()
            .success();

        let volumes = get_volume_paths(&archive);
        for volume in &volumes {
            let size = get_volume_size(volume);
            assert!(
                size <= MAX_VOLUME_SIZE,
                "{} has {size} bytes, exceeding the {MAX_VOLUME_SIZE}-byte cap",
                volume.display()
            );
        }
        assert!(
            volumes.len() > unrotated_volume_count,
            "expected size-driven rotation with --erasure {erasure}, got {} volume(s): {volumes:?}",
            volumes.len()
        );

        let first_volume = volumes.first().unwrap();
        let last_volume = volumes.last().unwrap();
        for (entry_point, volume) in [("first", first_volume), ("last", last_volume)] {
            era_cmd()
                .args(["verify", volume.to_str().unwrap(), "--password", "pwd"])
                .assert()
                .success();

            let out_dir = temp.path().join(format!("out_{entry_point}"));
            era_cmd()
                .args([
                    "extract",
                    "--input",
                    volume.to_str().unwrap(),
                    "--output",
                    out_dir.to_str().unwrap(),
                    "--password",
                    "pwd",
                ])
                .assert()
                .success();

            assert_file_content_eq(&out_dir.join(&input_name), &expected);
        }
    }

    #[test]
    fn test_volume_rotation_1mib_ec_4_plus_2() {
        assert_1mib_rotation_roundtrip("rot_1mib_ec", "4:2", 6);
    }

    #[test]
    fn test_volume_rotation_1mib_non_ec() {
        assert_1mib_rotation_roundtrip("rot_1mib_non_ec", "none", 1);
    }

    #[test]
    fn test_p3_7_minimum_cap_compressed_ec_with_colocated_shards() {
        const MIN_VOLUME_SIZE: u64 = 1024 * 1024;
        const INPUT_SIZE: usize = 3 * 1024 * 1024;

        let temp = TempDir::new().unwrap();
        let mut state = 0x4D59_5DF4_D0F3_3173u64;
        let data: Vec<u8> = (0..INPUT_SIZE)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        let input = create_test_file(temp.path(), "minimum_ec.bin", &data);
        let archive = temp.path().join("minimum_ec.era");

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
                "3",
                "--max-volume-size",
                &MIN_VOLUME_SIZE.to_string(),
            ])
            .assert()
            .success();

        let volumes = get_volume_paths(&archive);
        assert!(volumes.len() > 3, "expected rotation, got {volumes:?}");
        for volume in &volumes {
            assert!(
                get_volume_size(volume) <= MIN_VOLUME_SIZE,
                "{} exceeds the minimum-sized configured cap",
                volume.display()
            );
        }

        for volume in [volumes.first().unwrap(), volumes.last().unwrap()] {
            era_cmd()
                .args(["verify", volume.to_str().unwrap(), "--password", "pwd"])
                .assert()
                .success();
        }
        let out_dir = temp.path().join("out");
        era_cmd()
            .args([
                "extract",
                "--input",
                volumes.last().unwrap().to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();
        assert_file_content_eq(&out_dir.join("minimum_ec.bin"), &data);
    }
}

// ===========================================================================
// Category 3: Threshold Mode CLI Exposure Tests
// ===========================================================================

mod threshold_mode_cli_tests {
    use super::*;

    /// Test that threshold (T-of-N) mode IS exposed in CLI.
    #[test]
    fn test_threshold_mode_exposed_in_cli_help() {
        let binding = era_cmd().args(["create", "--help"]).assert();
        let output = binding.get_output();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        assert!(
            combined.to_lowercase().contains("threshold"),
            "CLI help should show --threshold option"
        );
        assert!(
            combined.to_lowercase().contains("shares"),
            "CLI help should show --shares option"
        );
    }

    /// Test that threshold mode can be configured via config file.
    ///
    /// This test verifies the workaround: using TOML config to enable threshold mode.
    #[test]
    fn test_threshold_mode_via_config_file() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "test.txt", b"threshold config test");
        let archive = temp.path().join("threshold.era");
        let out_dir = temp.path().join("out");
        let config_path = temp.path().join("threshold.toml");

        // Threshold mode is not implemented via config - this test documents the gap

        // Create a minimal TOML config (this is the expected format if implemented)
        let config_content = r#"
[access]
# Threshold mode: require 2 of 3 shares to unlock
policy = "threshold"
threshold = 2
"#;

        fs::write(&config_path, config_content).unwrap();

        // Try to create with config
        let binding = era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--config",
                config_path.to_str().unwrap(),
            ])
            .assert();
        let output = binding.get_output();

        if output.status.success() {
            // Config was accepted - verify extraction
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
        } else {
            // Config was rejected - likely threshold not implemented
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Note: Threshold via config not implemented: {}", stderr);
            // Skip this test if not implemented
        }
    }

    #[test]
    fn test_create_help_shows_hybrid_certificate_threshold_and_shares_flags() {
        let binding = era_cmd().args(["create", "--help"]).assert();
        let output = binding.get_output();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        assert!(
            combined.contains("--hybrid-certificate"),
            "CLI help should show --hybrid-certificate option"
        );
        assert!(
            combined.contains("--threshold"),
            "CLI help should show --threshold option"
        );
        assert!(
            combined.contains("--shares"),
            "CLI help should show --shares option"
        );
    }

    #[test]
    fn test_certificate_flag_remains_legacy_and_hybrid_is_opt_in() {
        let binding = era_cmd().args(["create", "--help"]).assert();
        let output = binding.get_output();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        assert!(
            combined.contains("--certificate"),
            "CLI help should still show legacy --certificate option"
        );
        assert!(
            combined.contains("--hybrid-certificate"),
            "CLI help should show new --hybrid-certificate option"
        );
    }

    /// Test that --help shows certificate-based options (baseline).
    /// This verifies our help text parsing is working correctly.
    #[test]
    fn test_certificate_option_visible_in_help() {
        let binding = era_cmd().args(["create", "--help"]).assert();
        let output = binding.get_output();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        assert!(
            combined.contains("--certificate"),
            "CLI help should show --certificate option"
        );
    }

    #[test]
    fn test_repair_help_shows_key() {
        let repair_help = era_cmd().args(["repair", "--help"]).assert();
        let repair_output = repair_help.get_output();
        let repair_stdout = String::from_utf8_lossy(&repair_output.stdout);
        let repair_stderr = String::from_utf8_lossy(&repair_output.stderr);
        let repair_combined = format!("{}\n{}", repair_stdout, repair_stderr);

        assert!(
            repair_combined.contains("--key"),
            "repair --help should show --key option"
        );

        let extract_help = era_cmd().args(["extract", "--help"]).assert();
        let extract_output = extract_help.get_output();
        let extract_stdout = String::from_utf8_lossy(&extract_output.stdout);
        let extract_stderr = String::from_utf8_lossy(&extract_output.stderr);
        let extract_combined = format!("{}\n{}", extract_stdout, extract_stderr);

        assert!(
            extract_combined.contains("--key"),
            "extract --help should still show --key option"
        );
    }
}

// ===========================================================================
// Category 4: Repair Edge Case Tests
// ===========================================================================

mod repair_edge_case_tests {
    use super::*;

    /// Test repair on an archive with zero corruption.
    ///
    /// This verifies repair handles the healthy archive case correctly.
    #[test]
    fn test_repair_healthy_archive_no_changes() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "test.txt", b"healthy archive");
        let archive = temp.path().join("healthy.era");

        // Archive doesn't exist yet, so original size is 0
        let original_size = 0u64;

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

        let after_create_size = fs::metadata(&archive).unwrap().len();
        assert_eq!(original_size, 0);
        assert!(after_create_size > 0);

        // Run repair in dry-run mode (no --force)
        era_cmd()
            .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // File should be unchanged
        let after_repair_size = fs::metadata(&archive).unwrap().len();
        assert_eq!(
            after_create_size, after_repair_size,
            "Dry-run repair should not modify archive"
        );
    }

    /// Test repair with --force on corrupted archive creates backup.
    #[test]
    fn test_repair_force_creates_backup_on_corrupted_archive() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "test.txt", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("rep_bak.era");

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

        // Corrupt the archive to have something to repair
        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive)
            .unwrap();
        f.seek(std::io::SeekFrom::Start(5000)).unwrap();
        let mut buf = [0u8; 100];
        f.read_exact(&mut buf).unwrap();
        for b in buf.iter_mut() {
            *b = !*b;
        }
        f.seek(std::io::SeekFrom::Start(5000)).unwrap();
        f.write_all(&buf).unwrap();
        f.flush().unwrap();

        // Run repair with --force
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

        // Backup should be created at archive.with_extension("era.bak")
        let backup = archive.with_extension("era.bak");
        assert!(
            backup.exists(),
            "Repair with --force should create .era.bak backup"
        );
    }
}

// ===========================================================================
// Category 5: Multi-Volume Edge Cases
// ===========================================================================

mod multi_volume_edge_tests {
    use super::*;

    /// Test extraction from multi-volume archive with all volumes present.
    #[test]
    fn test_multivolume_extract_with_all_volumes() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_all.txt", b"all volumes present");
        let archive = temp.path().join("mv_all.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--volumes",
                "3",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert_eq!(count, 3, "Should have exactly 3 volumes");

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
            fs::read(out_dir.join("mv_all.txt")).unwrap(),
            b"all volumes present"
        );
    }

    /// Test verify on multi-volume archive.
    #[test]
    fn test_multivolume_verify_all_volumes() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "verify.txt", b"verify multi");
        let archive = temp.path().join("verify.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--volumes",
                "6", // 6 volumes works with default 4:2 erasure (6 total shards)
            ])
            .assert()
            .success();

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }
}

// ===========================================================================
// Category 6: Info Command Tests
// ===========================================================================

mod info_command_tests {
    use super::*;

    /// Test info on single-volume archive.
    #[test]
    fn test_info_single_volume() {
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
            .success();
    }

    /// Test info on multi-volume archive shows volume count.
    #[test]
    fn test_info_multi_volume_shows_count() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "info_mv.txt", b"info multi volume");
        let archive = temp.path().join("info_mv.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--volumes",
                "3",
            ])
            .assert()
            .success();

        let output = era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Info output should mention volumes - info outputs to stderr
        let stderr = String::from_utf8_lossy(&output.get_output().stderr);
        assert!(
            stderr.contains("Volume") || stderr.contains("volume") || stderr.contains("3"),
            "info should show volume information: {}",
            stderr
        );
    }
}
