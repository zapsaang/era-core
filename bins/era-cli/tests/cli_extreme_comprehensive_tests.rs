//! Comprehensive extreme scenario CLI integration tests for era-cli.
//!
//! Covers: large files (500MB+), multi-volume extremes, various corruption scenarios,
//! certificate-based auth on multi-volume archives, and repair chains.
//!
//! Run with `--release` profile for acceptable performance on large files.

#![allow(deprecated)]

mod common;

use common::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ===========================================================================
// Module 1: Large File Extreme Scenarios
// ===========================================================================

mod large_file_extreme_tests {
    use super::*;

    #[test]
    fn test_large_file_500mb_multivolume_roundtrip() {
        let temp = TempDir::new().unwrap();
        let size = 500 * 1024 * 1024u64;
        let input = temp.path().join("large500mb.bin");
        let archive = temp.path().join("large500mb.era");
        let out_dir = temp.path().join("out");

        create_large_deterministic_file(&input, size);

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--max-volume-size",
                "104857600",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol_count = count_volume_files(&archive);
        assert!(
            vol_count >= 5,
            "500MB with 100MB max should create 5+ volumes, got {}",
            vol_count
        );

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

        verify_large_deterministic_file(&out_dir.join("large500mb.bin"), size);
    }

    #[test]
    fn test_large_file_256mb_multivolume_certificate_auth() {
        let temp = TempDir::new().unwrap();
        let size = 256 * 1024 * 1024u64;
        let input = temp.path().join("large_cert.bin");
        let archive = temp.path().join("large_cert.era");
        let out_dir = temp.path().join("out");

        let (pub_cert, priv_key) = generate_test_keypair(temp.path());
        create_large_deterministic_file(&input, size);

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--max-volume-size",
                "52428800",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol_count = count_volume_files(&archive);
        assert!(
            vol_count >= 4,
            "256MB with 50MB max should create 4+ volumes, got {}",
            vol_count
        );

        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
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

        verify_large_deterministic_file(&out_dir.join("large_cert.bin"), size);
    }

    #[test]
    fn test_large_file_128mb_hybrid_certificate_multivolume() {
        let temp = TempDir::new().unwrap();
        let size = 128 * 1024 * 1024u64;
        let input = temp.path().join("large_hybrid.bin");
        let archive = temp.path().join("large_hybrid.era");
        let out_dir = temp.path().join("out");

        let (pub_cert, priv_key) = generate_test_hybrid_keypair(temp.path());
        create_large_deterministic_file(&input, size);

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
                "--max-volume-size",
                "33554432",
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        let vol_count = count_volume_files(&archive);
        assert!(
            vol_count >= 3,
            "128MB with 32MB max should create 3+ volumes, got {}",
            vol_count
        );

        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
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

        verify_large_deterministic_file(&out_dir.join("large_hybrid.bin"), size);
    }
}

// ===========================================================================
// Module 2: Multi-Volume Extreme Scenarios
// ===========================================================================

mod multivolume_extreme_scenarios {
    use super::*;

    /// Multi-volume with very small volume size (16KB)
    #[test]
    fn test_multivolume_tiny_16kb_with_large_file() {
        let temp = TempDir::new().unwrap();
        let size = 2 * 1024 * 1024; // 2MB file
        let input = create_large_test_file(temp.path(), "tiny_vol.bin", size);
        let archive = temp.path().join("tiny_vol.era");
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
                "16384", // 16KB per volume
                "--no-compression",
            ])
            .assert()
            .success();

        let vol_count = count_volume_files(&archive);
        assert!(
            vol_count >= 4,
            "2MB with 16KB max should create multiple volumes, got {}",
            vol_count
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

        let restored = fs::read(out_dir.join("tiny_vol.bin")).unwrap();
        assert_eq!(restored.len(), size);
        assert_eq!(restored, generate_deterministic_data(size));
    }

    /// Extract from middle volume after primary deleted (catalog fallback strict regression)
    #[test]
    fn test_multivolume_extract_from_middle_with_primary_missing() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(512 * 1024);
        let input = create_test_file(temp.path(), "mid_extract.bin", &data);
        let archive = temp.path().join("mid_extract.era");
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

        fs::remove_file(&archive).unwrap();

        let vol3 = archive.with_extension("era.003");
        assert!(vol3.exists(), "volume 3 should exist");

        era_cmd()
            .args([
                "extract",
                "--input",
                vol3.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_extracted_file(&out_dir, "mid_extract.bin", &data);
    }

    /// List archive info from different volumes
    #[test]
    fn test_multivolume_info_from_different_volumes() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xAA; 256 * 1024];
        let input = create_test_file(temp.path(), "info_test.bin", &data);
        let archive = temp.path().join("info_test.era");

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

        // Get info from primary
        let primary_info = era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Get info from volume 2
        let vol2 = archive.with_extension("era.002");
        let vol2_info = era_cmd()
            .args(["info", vol2.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Both should succeed and show similar info
        let primary_stderr = String::from_utf8_lossy(&primary_info.get_output().stderr);
        let vol2_stderr = String::from_utf8_lossy(&vol2_info.get_output().stderr);
        assert!(
            primary_stderr.contains("Archive ID") && vol2_stderr.contains("Archive ID"),
            "both info calls should show Archive ID"
        );
    }

    /// Multi-volume with high redundancy (2 data + 4 parity)
    #[test]
    fn test_multivolume_high_redundancy_2_plus_4_recovery() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "high_redund.bin", &data);
        let archive = temp.path().join("high_redund.era");
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
                "2:4",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        // Delete 3 volumes (should still recover with 2:4 EC)
        for seq in [1u16, 3, 5] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

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

        assert_extracted_file(&out_dir, "high_redund.bin", &data);
    }
}

// ===========================================================================
// Module 3: Repair Corruption Scenarios
// ===========================================================================

mod repair_corruption_scenarios {
    use super::*;

    fn create_ec_archive(temp: &TempDir, name: &str, data: &[u8]) -> PathBuf {
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

        archive
    }

    /// Repair data region corruption at early offset
    #[test]
    fn test_repair_data_region_early_corruption() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xBB; 256 * 1024];
        let archive = create_ec_archive(&temp, "data_corr", &data);
        let out_dir = temp.path().join("out");

        // Corrupt data region (offset 5000 is well into data region)
        corrupt_archive_shard(&archive, 5000);

        // Verify should detect corruption
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();

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

        // Verify after repair
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract and verify content
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

        assert_extracted_file(&out_dir, "data_corr.bin", &data);
    }

    /// Footer corruption smoke test - verify graceful handling without panic
    #[test]
    fn test_footer_corruption_graceful_handling() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xCC; 256 * 1024];
        let archive = create_ec_archive(&temp, "footer_corr", &data);
        corrupt_footer(&archive);

        let result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .output()
            .expect("repair command should execute without panic");

        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            !stderr.contains("panicked"),
            "repair should not panic on footer corruption"
        );
    }

    /// Repair multi-shard corruption (2 shards in same stripe)
    #[test]
    fn test_repair_multi_shard_corruption_same_stripe() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xDD; 512 * 1024];
        let archive = create_ec_archive(&temp, "multi_shard", &data);
        let out_dir = temp.path().join("out");

        let file_len = fs::metadata(&archive).unwrap().len();

        // Corrupt two different locations (likely different shards)
        if file_len > 5000 {
            corrupt_archive_shard(&archive, 5000);
        }
        if file_len > 10000 {
            corrupt_archive_shard(&archive, 10000);
        }

        // Repair with force
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

        // Verify after repair
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract and verify
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

        assert_extracted_file(&out_dir, "multi_shard.bin", &data);
    }

    /// Repair all parity shards (should succeed with just data shards)
    #[test]
    fn test_repair_all_parity_shards_corrupted() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xEE; 256 * 1024];
        let input = create_test_file(temp.path(), "parity_corr.bin", &data);
        let archive = temp.path().join("parity_corr.era");

        // Create with 6 volumes (4 data + 2 parity = 6 total)
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

        // Corrupt the last 2 volumes (parity shards)
        for seq in [4u16, 5] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                corrupt_volume_data(&vol);
            }
        }

        // Should still be able to repair (4 data shards intact)
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
    }

    /// Repair dry run should not modify archive
    #[test]
    fn test_repair_dry_run_no_modification() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xFF; 256 * 1024];
        let archive = create_ec_archive(&temp, "dry_run", &data);

        // Corrupt
        corrupt_archive_shard(&archive, 5000);

        // Get checksum before repair
        let before_bytes = fs::read(&archive).unwrap();

        // Dry run (no --force)
        era_cmd()
            .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Archive should be unchanged
        let after_bytes = fs::read(&archive).unwrap();
        assert_eq!(
            before_bytes, after_bytes,
            "dry-run repair should NOT modify the archive"
        );
    }

    /// Repair with verbose output shows details
    #[test]
    fn test_repair_verbose_output_shows_details() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x12; 256 * 1024];
        let archive = create_ec_archive(&temp, "verbose", &data);

        // Corrupt
        corrupt_archive_shard(&archive, 5000);

        // Repair with verbose
        let result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
                "--verbose",
            ])
            .assert()
            .success();

        let stderr = String::from_utf8_lossy(&result.get_output().stderr);
        let stderr_lower = stderr.to_lowercase();
        assert!(
            stderr_lower.contains("blocks")
                || stderr_lower.contains("shard")
                || stderr_lower.contains("corrupt")
                || stderr_lower.contains("repair"),
            "verbose repair should show detailed info: {}",
            stderr
        );
    }
}

// ===========================================================================
// Module 4: Certificate Auth Repair Scenarios
// ===========================================================================

mod certificate_repair_scenarios {
    use super::*;

    /// Repair multi-volume archive with certificate authentication
    #[test]
    fn test_repair_multivolume_with_certificate_auth() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x34; 256 * 1024];
        let input = create_test_file(temp.path(), "cert_mv.bin", &data);
        let archive = temp.path().join("cert_mv.era");

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
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        // Corrupt one volume
        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            corrupt_volume_data(&vol2);
        }

        // Repair with certificate
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

        // Verify with certificate
        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success();
    }

    /// Repair hybrid certificate multi-volume archive
    #[test]
    fn test_repair_hybrid_certificate_multivolume() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x56; 256 * 1024];
        let input = create_test_file(temp.path(), "hyb_mv.bin", &data);
        let archive = temp.path().join("hyb_mv.era");

        let (pub_cert, priv_key) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        // Corrupt volume 1
        let vol1 = archive.with_extension("era.001");
        if vol1.exists() {
            corrupt_volume_data(&vol1);
        }

        // Repair with hybrid key
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

        // Verify with hybrid key
        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success();
    }
}

// ===========================================================================
// Module 5: Repair Chain Scenarios
// ===========================================================================

mod repair_chain_scenarios {
    use super::*;

    /// Repair then repack should produce clean archive
    #[test]
    fn test_repair_then_repack_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "repair_repack.bin", &data);
        let archive = temp.path().join("repair_repack.era");
        let repacked = temp.path().join("repair_repack_out.era");
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

        // Corrupt
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

        // Repack repaired archive
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

        // Verify repacked archive
        era_cmd()
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract from repacked
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

        assert_extracted_file(&out_dir, "repair_repack.bin", &data);
    }

    /// Verify failure then repair then verify success chain
    #[test]
    fn test_verify_fail_repair_verify_success_chain() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x78; 256 * 1024];
        let input = create_test_file(temp.path(), "chain.bin", &data);
        let archive = temp.path().join("chain.era");

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

        // Initial verify should pass
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Corrupt
        corrupt_archive_shard(&archive, 5000);

        // Verify should fail
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();

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

        // Verify should pass again
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    /// Multiple repair cycles should be idempotent
    #[test]
    fn test_multiple_repair_cycles_idempotent() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x9A; 256 * 1024];
        let input = create_test_file(temp.path(), "idempotent.bin", &data);
        let archive = temp.path().join("idempotent.era");

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

        // First repair cycle (nothing to repair, should be no-op)
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

        // Corrupt
        corrupt_archive_shard(&archive, 5000);

        // Second repair cycle (actual repair)
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

        // Third repair cycle (nothing left to repair)
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

        // Should still be valid
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }
}

// ===========================================================================
// Module 6: Threshold Mode Scenarios
// ===========================================================================

mod threshold_mode_scenarios {
    use super::*;

    /// Create and extract with 2-of-2 threshold passwords
    #[test]
    fn test_threshold_2_of_2_passwords_roundtrip() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xAB; 128 * 1024];
        let input = create_test_file(temp.path(), "threshold.bin", &data);
        let archive = temp.path().join("threshold.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pw1",
                "--password",
                "pw2",
                "--threshold",
                "2",
                "--shares",
                "2",
                "--no-compression",
            ])
            .assert()
            .success();

        // Extract with both passwords
        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pw1",
                "--password",
                "pw2",
            ])
            .assert()
            .success();

        assert_extracted_file(&out_dir, "threshold.bin", &data);
    }

    /// Extract with only 1 of 2 passwords should fail
    #[test]
    fn test_threshold_1_of_2_passwords_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "threshold_fail.bin", b"secret");
        let archive = temp.path().join("threshold_fail.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pw1",
                "--password",
                "pw2",
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .success();

        // Try extract with only 1 password
        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--password",
                "pw1",
            ])
            .assert()
            .failure();
    }

    /// 2-of-2 threshold with hybrid certificates
    #[test]
    fn test_threshold_2_of_2_hybrid_certificates() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xCD; 128 * 1024];
        let input = create_test_file(temp.path(), "hyb_thresh.bin", &data);
        let archive = temp.path().join("hyb_thresh.era");
        let out_dir = temp.path().join("out");

        let (pub1, priv1) = generate_test_hybrid_keypair(temp.path());
        let (pub2, priv2) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub1.to_str().unwrap(),
                "--hybrid-certificate",
                pub2.to_str().unwrap(),
                "--threshold",
                "2",
                "--shares",
                "2",
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
                "--key",
                priv1.to_str().unwrap(),
                "--key",
                priv2.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_extracted_file(&out_dir, "hyb_thresh.bin", &data);
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

fn assert_extracted_file(root: &Path, file_name: &str, expected: &[u8]) {
    let path = find_file_recursive(root, file_name);
    assert_file_content_eq(&path, expected);
}

fn find_file_recursive(root: &Path, file_name: &str) -> PathBuf {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_type().is_file() && entry.file_name() == file_name)
        .map(|entry| entry.path().to_path_buf())
        .unwrap_or_else(|| panic!("could not find {} under {}", file_name, root.display()))
}
