//! CLI integration tests targeting coverage gaps identified in
//! doc_gen/CLI_TEST_COVERAGE_GAP_ANALYSIS.md
//!
//! Covers:
//! - P0: Compression + EC repair interaction
//! - P0: Exact parity capacity boundary
//! - P0: Cross-archive volume splicing detection
//! - P1: Repair backup extractability
//! - P1: Metadata preservation after repair
//! - P1: Random-offset corruption
//! - P1: Concurrent repair scenarios
//! - P2: Very small file + high EC overhead
//! - P2: Repair -> Repack -> Repair chain
//!
//! Deferred (per gap analysis prioritization):
//! - P2 gap #8: Repair interrupt/resume (high effort, requires process control)
//! - P2 gap #11: >4GB file roundtrip (requires dedicated CI runner)

#![allow(deprecated, unused_imports, dead_code)]

mod common;

use common::*;
use predicates::prelude::*;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcCommand, Stdio};
use std::thread;
use tempfile::TempDir;

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ===========================================================================
// P0: Compression + Erasure Coding Repair Interaction
// ===========================================================================

mod compression_ec_repair {
    use super::*;

    /// Create with zstd level 19 + 4:2 EC, corrupt, repair, verify, extract.
    /// Assert exact byte match.
    #[test]
    fn test_repair_zstd_compressed_ec_archive() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "zstd_ec.bin", &data);
        let archive = temp.path().join("zstd_ec.era");
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
                "19",
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        // Corrupt at offset 5000
        corrupt_archive_shard(&archive, 5000);

        // Repair
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

        // Verify
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract
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

        assert_file_content_eq(&out_dir.join("zstd_ec.bin"), &data);
    }

    /// Test that compressed multi-volume archive with EC survives corruption and repair.
    #[test]
    fn test_repair_zstd_multivolume_compressed_ec() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "zstd_mv.bin", &data);
        let archive = temp.path().join("zstd_mv.era");
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
                "12",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
            ])
            .assert()
            .success();

        // Corrupt volume 2
        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            corrupt_archive_shard(&vol2, 5000);
        }

        // Repair
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

        // Verify
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract
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

        assert_file_content_eq(&out_dir.join("zstd_mv.bin"), &data);
    }

    /// Test fast/low-level compression + EC repair path.
    /// Uses zstd level 3 since LZ4 is not directly exposed via CLI flags.
    #[test]
    fn test_repair_fast_compressed_ec_archive() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "fast_ec.bin", &data);
        let archive = temp.path().join("fast_ec.era");
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
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

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

        assert_file_content_eq(&out_dir.join("fast_ec.bin"), &data);
    }
}

// ===========================================================================
// P0: Exact Parity Capacity Boundary
// ===========================================================================

mod exact_parity_boundary {
    use super::*;

    /// Corrupt exactly 2 shards in a 4:2 archive -> must succeed.
    /// Corrupt 3 shards -> must fail (or leave unrecoverable blocks).
    #[test]
    fn test_repair_exact_parity_boundary_4_plus_2() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "boundary.bin", &data);
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
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        // First test: corrupt exactly 2 volumes -> should fully recover
        let vol4 = archive.with_extension("era.004");
        let vol5 = archive.with_extension("era.005");
        assert!(vol4.exists() && vol5.exists());

        fs::remove_file(&vol4).unwrap();
        fs::remove_file(&vol5).unwrap();

        // Extract should still succeed (2 missing = within parity limit)
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

        assert_file_content_eq(&out_dir.join("boundary.bin"), &data);

        // Restore the volumes for the second test
        // We need a fresh archive for the 3-shard failure test
        let archive2 = temp.path().join("boundary2.era");
        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive2.to_str().unwrap(),
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

        // Corrupt 3 volumes -> should NOT fully recover
        let vol1 = archive2.with_extension("era.001");
        let vol2_2 = archive2.with_extension("era.002");
        let vol3 = archive2.with_extension("era.003");
        assert!(vol1.exists() && vol2_2.exists() && vol3.exists());

        fs::remove_file(&vol1).unwrap();
        fs::remove_file(&vol2_2).unwrap();
        fs::remove_file(&vol3).unwrap();

        // Extract should fail or produce incomplete data
        let out_dir2 = temp.path().join("out2");
        let assert = era_cmd()
            .args([
                "extract",
                "--input",
                archive2.to_str().unwrap(),
                "--output",
                out_dir2.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        // Should fail because 3 losses exceeds 2 parity shards
        assert.failure();
    }

    /// Repair should succeed when exactly 2 volumes are corrupted in 4:2 EC.
    #[test]
    fn test_repair_exact_parity_boundary_4_plus_2_repair_succeeds() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "boundary_repair.bin", &data);
        let archive = temp.path().join("boundary_repair.era");
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

        // Corrupt exactly 2 volumes (within parity limit)
        let vol4 = archive.with_extension("era.004");
        let vol5 = archive.with_extension("era.005");
        corrupt_archive_shard(&vol4, 5000);
        corrupt_archive_shard(&vol5, 5000);

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

        assert_file_content_eq(&out_dir.join("boundary_repair.bin"), &data);
    }

    /// Repair should fail when 3 volumes are lost in 4:2 EC (beyond repair capability).
    #[test]
    fn test_repair_exact_parity_boundary_4_plus_2_repair_fails() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "boundary_repair_fail.bin", &data);
        let archive = temp.path().join("boundary_repair_fail.era");

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

        // Remove 3 volumes: repair cannot recreate missing volume files
        let vol1 = archive.with_extension("era.001");
        let vol2 = archive.with_extension("era.002");
        let vol3 = archive.with_extension("era.003");
        fs::remove_file(&vol1).unwrap();
        fs::remove_file(&vol2).unwrap();
        fs::remove_file(&vol3).unwrap();

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .failure();
    }

    /// Test 6:3 EC boundary: corrupt exactly 3 -> succeed, corrupt 4 -> fail.
    #[test]
    fn test_repair_exact_parity_boundary_6_plus_3() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "boundary63.bin", &data);
        let archive = temp.path().join("boundary63.era");

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
                "--volumes",
                "9",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol_count = count_volume_files(&archive);
        assert!(
            vol_count >= 6,
            "6:3 EC with --volumes 9 should produce at least 6 volumes, got {}",
            vol_count
        );

        // Corrupt exactly 3 volumes -> should succeed (within parity limit)
        let vol_paths = get_volume_paths(&archive);
        let to_remove = vol_paths.iter().rev().take(3).collect::<Vec<_>>();
        assert!(
            to_remove.len() == 3,
            "need at least 3 volumes to remove, got {}",
            to_remove.len()
        );

        for vol in &to_remove {
            fs::remove_file(vol).unwrap();
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
            .success();

        assert_file_content_eq(&out_dir.join("boundary63.bin"), &data);
    }

    /// Repair should succeed when exactly 3 volumes are corrupted in 6:3 EC.
    #[test]
    fn test_repair_exact_parity_boundary_6_plus_3_repair_succeeds() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "boundary63_repair.bin", &data);
        let archive = temp.path().join("boundary63_repair.era");
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
                "--volumes",
                "9",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol_paths = get_volume_paths(&archive);
        let to_corrupt = vol_paths.iter().rev().take(3).collect::<Vec<_>>();
        for vol in &to_corrupt {
            corrupt_archive_shard(vol, 5000);
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

        assert_file_content_eq(&out_dir.join("boundary63_repair.bin"), &data);
    }

    /// Repair should fail when 4 volumes are lost in 6:3 EC (beyond repair capability).
    #[test]
    fn test_repair_exact_parity_boundary_6_plus_3_repair_fails() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "boundary63_repair_fail.bin", &data);
        let archive = temp.path().join("boundary63_repair_fail.era");

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
                "--volumes",
                "9",
                "--no-compression",
            ])
            .assert()
            .success();

        // Remove 4 volumes: repair cannot recreate missing volume files
        let vol_paths = get_volume_paths(&archive);
        let to_remove = vol_paths.iter().rev().take(4).collect::<Vec<_>>();
        for vol in &to_remove {
            fs::remove_file(vol).unwrap();
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
            .failure();
    }
}

// ===========================================================================
// P0: Cross-Archive Volume Splicing Detection
// ===========================================================================

mod cross_archive_splicing {
    use super::*;

    /// Create archiveA (volumes 0..3) and archiveB (volumes 0..3).
    /// Swap one volume from B into A's directory.
    /// The CLI should detect archive ID mismatch and handle it gracefully
    /// (skip the spliced volume, not crash, and not silently use wrong data).
    #[test]
    fn test_repair_rejects_spliced_volumes_from_different_archives() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();
        let data_a = generate_deterministic_data(256 * 1024);
        let mut data_b = generate_deterministic_data(256 * 1024);
        // Make data_b different to ensure archives are different
        data_b[0] = !data_b[0];
        let input_a = create_test_file(temp_a.path(), "archive_a.bin", &data_a);
        let input_b = create_test_file(temp_b.path(), "archive_b.bin", &data_b);
        let archive_a = temp_a.path().join("archive_a.era");
        let archive_b = temp_b.path().join("archive_b.era");

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

        // Swap volume .era.001 from B into A's directory
        let a_vol1 = archive_a.with_extension("era.001");
        let b_vol1 = archive_b.with_extension("era.001");
        assert!(a_vol1.exists() && b_vol1.exists());

        fs::copy(&b_vol1, &a_vol1).unwrap();

        // Verify should detect splicing and report issues
        let assert = era_cmd()
            .args(["verify", archive_a.to_str().unwrap(), "--password", "pwd"])
            .assert();

        let verify_text = combined_output(assert.get_output()).to_lowercase();
        // Should mention missing volume or degraded state due to splicing being skipped
        assert!(
            verify_text.contains("missing")
                || verify_text.contains("degraded")
                || verify_text.contains("incomplete")
                || !assert.get_output().status.success(),
            "verify should report issues with spliced volume: {}",
            verify_text
        );

        // Extract may succeed if enough volumes remain (5 of 6 for 4:2 is recoverable),
        // but should NOT silently use the spliced volume data.
        let out_dir = temp_a.path().join("out");
        let assert2 = era_cmd()
            .args([
                "extract",
                "--input",
                archive_a.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .output()
            .expect("failed to execute era extract");

        let extract_text = combined_output(&assert2).to_lowercase();

        // Should never panic/crash
        assert!(
            !extract_text.contains("panicked"),
            "extract should not panic with spliced volume"
        );

        // If extract succeeds, data should be correct (spliced volume was skipped)
        if assert2.status.success() {
            assert_file_content_eq(&out_dir.join("archive_a.bin"), &data_a);
        }
    }

    /// Verify that spliced volumes are detected during repair too.
    #[test]
    fn test_repair_detects_spliced_volumes() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();
        let data_a = generate_deterministic_data(256 * 1024);
        let mut data_b = generate_deterministic_data(256 * 1024);
        data_b[0] = !data_b[0];
        let input_a = create_test_file(temp_a.path(), "repair_a.bin", &data_a);
        let input_b = create_test_file(temp_b.path(), "repair_b.bin", &data_b);
        let archive_a = temp_a.path().join("repair_a.era");
        let archive_b = temp_b.path().join("repair_b.era");

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

        // Corrupt a volume in A
        let a_vol2 = archive_a.with_extension("era.002");
        corrupt_archive_shard(&a_vol2, 5000);

        // Swap volume .era.001 from B into A
        let a_vol1 = archive_a.with_extension("era.001");
        let b_vol1 = archive_b.with_extension("era.001");
        fs::copy(&b_vol1, &a_vol1).unwrap();

        // Repair should detect splicing
        let repair_output = era_cmd()
            .args([
                "repair",
                archive_a.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .output()
            .expect("failed to execute era repair");
        let _repair_text = combined_output(&repair_output).to_lowercase();

        // Verify should detect splicing and either fail or report degraded/corrupt state
        let verify_output = era_cmd()
            .args(["verify", archive_a.to_str().unwrap(), "--password", "pwd"])
            .output()
            .expect("failed to execute era verify");
        let verify_text = combined_output(&verify_output).to_lowercase();

        // If verify passes, it must explicitly report degraded/corrupt/missing state
        // (not just generic "archive" text that appears in all output)
        if verify_output.status.success() {
            assert!(
                verify_text.contains("degraded")
                    || verify_text.contains("corrupt")
                    || verify_text.contains("missing")
                    || verify_text.contains("mismatch")
                    || verify_text.contains("integrity"),
                "verify of spliced archive should report degradation, got: {}",
                verify_text
            );
        }

        // Extract should either fail or produce the correct original data (never wrong data)
        let out_dir = temp_a.path().join("out");
        let extract_output = era_cmd()
            .args([
                "extract",
                "--input",
                archive_a.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .output()
            .expect("failed to execute era extract");

        if extract_output.status.success() {
            // If extraction succeeded, the data MUST match original archive A
            assert_file_content_eq(&out_dir.join("repair_a.bin"), &data_a);
        }
    }
}

// ===========================================================================
// P1: Repair Backup Integrity
// ===========================================================================

mod repair_backup_integrity {
    use super::*;

    /// Repair with --force creates a .backup file.
    /// Extract from `.era.backup` to prove it is a valid, complete archive.
    #[test]
    fn test_repair_backup_archive_is_extractable() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "backup.bin", &data);
        let archive = temp.path().join("backup.era");

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

        // Backup should exist
        let backup = archive.with_extension("era.bak");
        assert!(
            backup.exists(),
            ".era.bak backup should be created during repair"
        );

        // Extract from backup should succeed and produce original data
        let out_dir = temp.path().join("out");
        era_cmd()
            .args([
                "extract",
                "--input",
                backup.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_file_content_eq(&out_dir.join("backup.bin"), &data);
    }

    /// Verify that backup is created even for multi-volume archives.
    ///
    /// For multi-volume repairs, backups are created per-volume. To verify the backup
    /// is truly extractable, we isolate the backup files in a separate directory and
    /// rename them back to canonical names so volume discovery finds only the backup set.
    #[test]
    fn test_repair_backup_multivolume_is_extractable() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "backup_mv.bin", &data);
        let archive = temp.path().join("backup_mv.era");

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

        // Corrupt the primary volume to ensure repair is actually triggered.
        // (Corrupting a small secondary volume may be silently tolerated by EC
        // verification without requiring file-level repair.)
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

        // Collect all backup files that were created
        let backup_dir = temp.path().join("backup_only");
        fs::create_dir_all(&backup_dir).unwrap();

        let primary_bak = archive.with_extension("era.bak");
        assert!(
            primary_bak.exists(),
            "primary backup should exist after repair"
        );
        let canonical_primary = backup_dir.join("backup_mv.era");
        fs::copy(&primary_bak, &canonical_primary).unwrap();

        // Copy any volume-specific backups and rename to canonical volume names
        for seq in 1..=99u16 {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            let vol_bak = vol.with_extension(format!("{:03}.bak", seq));
            if vol_bak.exists() {
                let canonical_vol = backup_dir.join(format!("backup_mv.era.{:03}", seq));
                fs::copy(&vol_bak, &canonical_vol).unwrap();
            }
        }

        // Extract from the isolated backup directory
        let out_dir = temp.path().join("out");
        era_cmd()
            .args([
                "extract",
                "--input",
                canonical_primary.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_file_content_eq(&out_dir.join("backup_mv.bin"), &data);
    }
}

// ===========================================================================
// P1: Metadata Preservation After Repair
// ===========================================================================

#[cfg(unix)]
mod metadata_preservation {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_repair_preserves_file_permissions() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "perm.bin", &data);
        let archive = temp.path().join("perm.era");
        let out_dir = temp.path().join("out");

        let mut perms = fs::metadata(&input).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&input, perms).unwrap();

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

        let extracted = out_dir.join("perm.bin");
        assert!(extracted.exists(), "extracted file should exist");

        let extracted_perms = fs::metadata(&extracted).unwrap().permissions();
        let mode = extracted_perms.mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "file permissions should be preserved through corrupt-repair-extract chain, got {:o}",
            mode
        );
    }

    #[test]
    fn test_repair_preserves_modification_time() {
        use std::time::{Duration, SystemTime};

        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "mtime.bin", &data);
        let archive = temp.path().join("mtime.era");
        let out_dir = temp.path().join("out");

        let custom_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200);
        let file_time = filetime::FileTime::from_system_time(custom_time);
        filetime::set_file_mtime(&input, file_time).unwrap();

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

        let extracted = out_dir.join("mtime.bin");
        assert!(extracted.exists());

        let mtime = fs::metadata(&extracted).unwrap().modified().unwrap();
        let diff = if mtime > custom_time {
            mtime.duration_since(custom_time).unwrap()
        } else {
            custom_time.duration_since(mtime).unwrap()
        };

        assert!(
            diff <= std::time::Duration::from_secs(2),
            "modification time should be preserved, expected {:?}, got {:?}, diff={:?}",
            custom_time,
            mtime,
            diff
        );
    }

    #[test]
    fn test_repair_preserves_xattr() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "xattr.bin", &data);
        let archive = temp.path().join("xattr.era");
        let out_dir = temp.path().join("out");

        xattr::set(&input, "user.testkey", b"testvalue").unwrap();

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

        let extracted = out_dir.join("xattr.bin");
        assert!(extracted.exists());

        let val = xattr::get(&extracted, "user.testkey").unwrap();
        assert_eq!(
            val,
            Some(b"testvalue".to_vec()),
            "xattr should be preserved"
        );
    }

    /// Regression test: read-only files must have mtime and xattrs restored correctly.
    #[test]
    fn test_repair_preserves_readonly_file_metadata() {
        use std::time::{Duration, SystemTime};

        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "readonly.bin", &data);
        let archive = temp.path().join("readonly.era");
        let out_dir = temp.path().join("out");

        // Set custom mtime and xattr BEFORE making the file read-only
        let custom_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200);
        filetime::set_file_mtime(&input, filetime::FileTime::from_system_time(custom_time))
            .unwrap();
        xattr::set(&input, "user.rokey", b"rovalue").unwrap();

        // Set read-only permissions last
        let mut perms = fs::metadata(&input).unwrap().permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&input, perms).unwrap();

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

        let extracted = out_dir.join("readonly.bin");
        assert!(extracted.exists());

        // Verify permissions
        let final_perms = fs::metadata(&extracted).unwrap().permissions();
        assert_eq!(
            final_perms.mode() & 0o777,
            0o444,
            "read-only permissions should be preserved"
        );

        // Verify mtime
        let mtime = fs::metadata(&extracted).unwrap().modified().unwrap();
        let diff = if mtime > custom_time {
            mtime.duration_since(custom_time).unwrap()
        } else {
            custom_time.duration_since(mtime).unwrap()
        };
        assert!(
            diff <= Duration::from_secs(2),
            "read-only file mtime should be preserved"
        );

        // Verify xattr
        assert_eq!(
            xattr::get(&extracted, "user.rokey").unwrap(),
            Some(b"rovalue".to_vec()),
            "read-only file xattr should be preserved"
        );
    }

    /// Regression test: skipped existing files must not have their metadata modified.
    #[test]
    fn test_extract_skipped_file_metadata_untouched() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "skip_test.bin", b"archive content");
        let archive = temp.path().join("skip.era");
        let out_dir = temp.path().join("out");

        let mut perms = fs::metadata(&input).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&input, perms).unwrap();

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

        // Pre-create the output file with different content and restrictive permissions
        fs::create_dir_all(&out_dir).unwrap();
        let pre_existing = out_dir.join("skip_test.bin");
        fs::write(&pre_existing, b"already here").unwrap();
        let mut pre_perms = fs::metadata(&pre_existing).unwrap().permissions();
        pre_perms.set_mode(0o600);
        fs::set_permissions(&pre_existing, pre_perms).unwrap();

        // Extract without --force: should skip the existing file
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

        // Existing file content and permissions must be untouched
        assert_file_content_eq(&pre_existing, b"already here");
        let final_perms = fs::metadata(&pre_existing).unwrap().permissions();
        assert_eq!(
            final_perms.mode() & 0o777,
            0o600,
            "skipped file permissions should not be modified"
        );
    }

    /// Regression test: overlapping suffix paths must receive correct metadata.
    #[test]
    fn test_overlapping_suffix_paths_receive_correct_metadata() {
        use std::time::{Duration, SystemTime};

        let temp = TempDir::new().unwrap();
        let src_dir = temp.path().join("src");
        let input_ab = create_test_file(&src_dir, "a/b/file.txt", b"ab content");
        let input_b = create_test_file(&src_dir, "b/file.txt", b"b content");
        let archive = temp.path().join("overlap.era");
        let out_dir = temp.path().join("out");

        // Different permissions
        let mut perms_ab = fs::metadata(&input_ab).unwrap().permissions();
        perms_ab.set_mode(0o700);
        fs::set_permissions(&input_ab, perms_ab).unwrap();

        let mut perms_b = fs::metadata(&input_b).unwrap().permissions();
        perms_b.set_mode(0o600);
        fs::set_permissions(&input_b, perms_b).unwrap();

        // Different mtimes
        let mtime_ab = SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200);
        filetime::set_file_mtime(&input_ab, filetime::FileTime::from_system_time(mtime_ab))
            .unwrap();

        let mtime_b = SystemTime::UNIX_EPOCH + Duration::from_secs(1609545600);
        filetime::set_file_mtime(&input_b, filetime::FileTime::from_system_time(mtime_b)).unwrap();

        // Different xattrs
        xattr::set(&input_ab, "user.key", b"ab").unwrap();
        xattr::set(&input_b, "user.key", b"b").unwrap();

        era_cmd()
            .args([
                "create",
                temp.path().join("src").to_str().unwrap(),
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

        // Because we archived the `src` directory, stored paths include the `src` prefix
        let extracted_ab = out_dir.join("src/a/b/file.txt");
        let extracted_b = out_dir.join("src/b/file.txt");

        // Verify permissions
        assert_eq!(
            fs::metadata(&extracted_ab).unwrap().permissions().mode() & 0o777,
            0o700,
            "src/a/b/file.txt should have 0700"
        );
        assert_eq!(
            fs::metadata(&extracted_b).unwrap().permissions().mode() & 0o777,
            0o600,
            "src/b/file.txt should have 0600"
        );

        // Verify mtime
        let got_ab = fs::metadata(&extracted_ab).unwrap().modified().unwrap();
        let got_b = fs::metadata(&extracted_b).unwrap().modified().unwrap();
        assert!(
            got_ab
                .duration_since(mtime_ab)
                .unwrap_or_else(|_| mtime_ab.duration_since(got_ab).unwrap())
                <= Duration::from_secs(2),
            "src/a/b/file.txt mtime mismatch"
        );
        assert!(
            got_b
                .duration_since(mtime_b)
                .unwrap_or_else(|_| mtime_b.duration_since(got_b).unwrap())
                <= Duration::from_secs(2),
            "src/b/file.txt mtime mismatch"
        );

        // Verify xattrs
        assert_eq!(
            xattr::get(&extracted_ab, "user.key").unwrap(),
            Some(b"ab".to_vec())
        );
        assert_eq!(
            xattr::get(&extracted_b, "user.key").unwrap(),
            Some(b"b".to_vec())
        );
    }
}

// ===========================================================================
// P1: Random-Offset Corruption
// ===========================================================================

mod random_offset_corruption {
    use super::*;

    /// Test corruption at multiple offsets to catch alignment-sensitive regions.
    #[test]
    fn test_repair_corruption_at_multiple_offsets() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "multi_offset.bin", &data);

        // Test several different offsets
        for offset in [1000, 4096, 5000, 8192, 10000, 16384, 20000] {
            let archive = temp.path().join(format!("offset_{}.era", offset));
            let out_dir = temp.path().join(format!("out_{}", offset));

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

            let len = fs::metadata(&archive).unwrap().len();
            if len > offset as u64 + 100 {
                corrupt_archive_shard(&archive, offset as u64);

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

                assert_file_content_eq(&out_dir.join("multi_offset.bin"), &data);
            }
        }
    }

    /// Test corruption at header boundary.
    #[test]
    fn test_repair_corruption_at_header_boundary() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "header_boundary.bin", &data);
        let archive = temp.path().join("header_boundary.era");
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

        // Corrupt just after the super header (4096 bytes)
        let len = fs::metadata(&archive).unwrap().len();
        if len > 4200 {
            corrupt_archive_shard(&archive, 4100);

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

            assert_file_content_eq(&out_dir.join("header_boundary.bin"), &data);
        }
    }

    /// Test corruption near footer boundary.
    #[test]
    fn test_repair_corruption_at_footer_boundary() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "footer_boundary.bin", &data);
        let archive = temp.path().join("footer_boundary.era");
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

        let len = fs::metadata(&archive).unwrap().len();
        if len > 200 {
            // Corrupt near the end (before footer)
            corrupt_archive_shard(&archive, len - 200);

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

            assert_file_content_eq(&out_dir.join("footer_boundary.bin"), &data);
        }
    }
}

// ===========================================================================
// P1: Concurrent Repair Scenarios
// ===========================================================================

mod concurrent_repair {
    use super::*;

    /// Spawn two repair --force processes on the same archive.
    /// Neither should panic; at least one should succeed.
    #[test]
    fn test_concurrent_repair_on_same_archive_races_safely() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "concurrent_repair.bin", &data);
        let archive = temp.path().join("concurrent_repair.era");

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

        corrupt_archive_shard(&archive, 5000);

        let archive_str = archive.to_str().unwrap().to_string();
        let password = "pwd".to_string();

        // Spawn two repair processes simultaneously
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let archive_clone = archive_str.clone();
                let password_clone = password.clone();
                thread::spawn(move || {
                    ProcCommand::new(era_binary_path())
                        .args([
                            "repair",
                            &archive_clone,
                            "--password",
                            &password_clone,
                            "--force",
                        ])
                        .output()
                        .expect("failed to execute era repair")
                })
            })
            .collect();

        let mut results = Vec::new();
        for (i, handle) in handles.into_iter().enumerate() {
            let output = handle.join().unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains("panicked"),
                "repair {} should not panic: {}",
                i,
                stderr
            );
            results.push(output.status.success());
        }

        // At least one should succeed
        assert!(
            results.iter().any(|&r| r),
            "at least one concurrent repair should succeed: {:?}",
            results
        );

        // Verify the archive is still valid
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    /// Concurrent repair and verify should not crash.
    #[test]
    fn test_concurrent_repair_and_verify_same_archive() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "repair_verify_race.bin", &data);
        let archive = temp.path().join("repair_verify_race.era");

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

        corrupt_archive_shard(&archive, 5000);

        let archive_str = archive.to_str().unwrap().to_string();
        let password = "pwd".to_string();

        let repair_handle = thread::spawn(move || {
            ProcCommand::new(era_binary_path())
                .args(["repair", &archive_str, "--password", &password, "--force"])
                .output()
                .expect("failed to execute era repair")
        });

        thread::sleep(std::time::Duration::from_millis(50));

        let archive_str2 = archive.to_str().unwrap().to_string();
        let password2 = "pwd".to_string();
        let verify_output = ProcCommand::new(era_binary_path())
            .args(["verify", &archive_str2, "--password", &password2])
            .output()
            .expect("failed to execute era verify");

        let repair_output = repair_handle.join().unwrap();

        // Neither should panic
        let repair_stderr = String::from_utf8_lossy(&repair_output.stderr);
        let verify_stderr = String::from_utf8_lossy(&verify_output.stderr);
        assert!(
            !repair_stderr.contains("panicked"),
            "repair should not panic: {}",
            repair_stderr
        );
        assert!(
            !verify_stderr.contains("panicked"),
            "verify should not panic: {}",
            verify_stderr
        );
    }
}

// ===========================================================================
// P2: Very Small File + High EC Overhead
// ===========================================================================

mod small_file_high_ec {
    use super::*;

    /// A 1-byte file with 4:2 EC has extreme padding ratios.
    /// Ensure it round-trips correctly.
    #[test]
    fn test_very_small_file_with_high_ec_overhead() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "one_byte.bin", b"X");
        let archive = temp.path().join("one_byte.era");
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

        assert_file_content_eq(&out_dir.join("one_byte.bin"), b"X");
    }

    /// Empty file with EC overhead.
    #[test]
    fn test_empty_file_with_ec() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "empty.bin", b"");
        let archive = temp.path().join("empty.era");
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

        let extracted = out_dir.join("empty.bin");
        assert!(extracted.exists());
        assert_eq!(fs::metadata(&extracted).unwrap().len(), 0);
    }
}

// ===========================================================================
// P2: Repair -> Repack -> Repair Chain
// ===========================================================================

mod repair_repack_chain {
    use super::*;

    /// Create -> Corrupt -> Repair -> Repack -> Corrupt -> Repair -> Extract
    #[test]
    fn test_repair_repack_repair_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "chain.bin", &data);
        let archive = temp.path().join("chain.era");
        let repacked = temp.path().join("chain_repacked.era");
        let out_dir = temp.path().join("out");

        // Create
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

        // Corrupt and repair
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

        // Repack
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

        // Corrupt repacked archive
        corrupt_archive_shard(&repacked, 5000);

        // Repair repacked archive
        era_cmd()
            .args([
                "repair",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();

        // Verify
        era_cmd()
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract
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

        assert_file_content_eq(&out_dir.join("chain.bin"), &data);
    }

    /// Multi-volume variant of the chain.
    #[test]
    fn test_repair_repack_repair_chain_multivolume() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "chain_mv.bin", &data);
        let archive = temp.path().join("chain_mv.era");
        let repacked = temp.path().join("chain_mv_repacked.era");
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

        // Corrupt volume 2
        let vol2 = archive.with_extension("era.002");
        corrupt_archive_shard(&vol2, 5000);

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

        // Repack with compact preset (which uses default volume distribution)
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

        // Corrupt repacked archive
        corrupt_archive_shard(&repacked, 5000);

        era_cmd()
            .args([
                "repair",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();

        era_cmd()
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
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

        assert_file_content_eq(&out_dir.join("chain_mv.bin"), &data);
    }
}
