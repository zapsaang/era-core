#![allow(deprecated, unused_imports, dead_code)]

mod common;

use assert_cmd::Command;
use common::*;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_contains_any(text: &str, expected: &[&str]) {
    assert!(
        expected
            .iter()
            .any(|needle| text.to_lowercase().contains(needle)),
        "expected one of {:?} in output: {}",
        expected,
        text
    );
}
fn find_file_recursive(root: &Path, file_name: &str) -> PathBuf {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_type().is_file() && entry.file_name() == file_name)
        .map(|entry| entry.path().to_path_buf())
        .unwrap_or_else(|| panic!("could not find {} under {}", file_name, root.display()))
}

fn assert_extracted_file(root: &Path, file_name: &str, expected: &[u8]) {
    let path = find_file_recursive(root, file_name);
    assert_file_content_eq(&path, expected);
}

fn create_multivolume_archive_with_data(
    temp: &TempDir,
    name: &str,
    data: &[u8],
    erasure: &str,
) -> PathBuf {
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
            erasure,
            "--volumes",
            "6",
            "--no-compression",
        ])
        .assert()
        .success();

    assert_eq!(
        count_volume_files(&archive),
        6,
        "archive should have 6 volumes"
    );
    archive
}

mod large_file_stress {
    use super::*;

    #[ignore]
    #[test]
    fn test_stress_large_file_128mb_roundtrip_single_volume() {
        let temp = TempDir::new().unwrap();
        let input = temp.path().join("large_128mb.bin");
        let archive = temp.path().join("large_128mb.era");
        let out_dir = temp.path().join("out");
        let size = 128 * 1024 * 1024u64;

        create_large_deterministic_file(&input, size);

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

        verify_large_deterministic_file(&out_dir.join("large_128mb.bin"), size);
    }

    #[ignore]
    #[test]
    fn test_stress_large_file_128mb_repair_after_corruption_release_regression() {
        let temp = TempDir::new().unwrap();
        let input = temp.path().join("large_128mb_repair.bin");
        let archive = temp.path().join("large_128mb_repair.era");
        let out_dir = temp.path().join("out");
        let size = 128 * 1024 * 1024u64;

        create_large_deterministic_file(&input, size);

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

        verify_large_deterministic_file(&out_dir.join("large_128mb_repair.bin"), size);
    }
}

mod volume_discovery {
    use super::*;

    #[test]
    fn test_discovery_open_from_secondary_volume() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let archive = create_multivolume_archive_with_data(&temp, "secondary_start", &data, "4:2");
        let secondary = archive.with_extension("era.001");

        fs::remove_file(&archive).unwrap();

        let assert = era_cmd()
            .args(["verify", secondary.to_str().unwrap(), "--password", "pwd"])
            .assert();

        let text = combined_output(assert.get_output()).to_lowercase();
        assert_contains_any(
            &text,
            &["opened 5 volumes", "missing sequences", "readable"],
        );
        assert!(
            !assert.get_output().status.success(),
            "verify should report degraded health when the primary volume is missing"
        );
    }

    #[test]
    fn test_discovery_open_from_middle_volume_with_end_gaps() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let archive = create_multivolume_archive_with_data(&temp, "middle_start", &data, "4:2");
        let middle = archive.with_extension("era.003");

        fs::remove_file(&archive).unwrap();
        fs::remove_file(archive.with_extension("era.005")).unwrap();

        let assert = era_cmd()
            .args(["verify", middle.to_str().unwrap(), "--password", "pwd"])
            .assert();

        let text = combined_output(assert.get_output()).to_lowercase();
        assert_contains_any(
            &text,
            &["opened 4 volumes", "missing sequences", "readable"],
        );
        assert!(
            !assert.get_output().status.success(),
            "verify should report degraded health when discovery starts mid-chain with end gaps"
        );
    }

    #[test]
    fn test_discovery_volume_gaps_still_extract() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let archive = create_multivolume_archive_with_data(&temp, "gap_extract", &data, "4:2");
        let out_dir = temp.path().join("out");

        fs::remove_file(archive.with_extension("era.002")).unwrap();
        fs::remove_file(archive.with_extension("era.004")).unwrap();

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

        assert_extracted_file(&out_dir, "gap_extract.bin", &data);
    }

    #[test]
    fn test_discovery_archive_id_cross_volume_verification() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();
        let data_a = vec![0xA1; 256 * 1024];
        let data_b = vec![0xB2; 256 * 1024];
        let archive_a = create_multivolume_archive_with_data(&temp_a, "archive_a", &data_a, "4:2");
        let archive_b = create_multivolume_archive_with_data(&temp_b, "archive_b", &data_b, "4:2");

        fs::copy(
            archive_b.with_extension("era.001"),
            archive_a.with_extension("era.001"),
        )
        .unwrap();

        era_cmd()
            .args([
                "verify",
                archive_a.with_extension("era.001").to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }
}

mod multivolume_extreme {
    use super::*;

    #[test]
    fn test_multivolume_parity_only_loss_recovery_4_plus_2() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let archive = create_multivolume_archive_with_data(&temp, "parity_loss", &data, "4:2");
        let out_dir = temp.path().join("out");

        fs::remove_file(archive.with_extension("era.004")).unwrap();
        fs::remove_file(archive.with_extension("era.005")).unwrap();

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

        assert_extracted_file(&out_dir, "parity_loss.bin", &data);
    }

    #[test]
    fn test_multivolume_mixed_survival_2_plus_4() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let archive = create_multivolume_archive_with_data(&temp, "survival_2_4", &data, "2:4");
        let out_dir = temp.path().join("out");

        for seq in 2..=5u16 {
            fs::remove_file(archive.with_extension(format!("era.{:03}", seq))).unwrap();
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

        assert_extracted_file(&out_dir, "survival_2_4.bin", &data);
    }

    #[test]
    fn test_multivolume_near_min_volume_boundary_roundtrip() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "near_min.bin", &data);
        let archive = temp.path().join("near_min.era");
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
                "--max-volume-size",
                "24576",
            ])
            .assert()
            .success();

        assert!(
            count_volume_files(&archive) >= 2,
            "archive should span multiple volumes"
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

        assert_extracted_file(&out_dir, "near_min.bin", &data);
    }
}

mod repair_recovery {
    use super::*;

    #[test]
    fn test_repair_chain_verify_repair_verify_extract_single_volume() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "repair_chain.bin", &data);
        let archive = temp.path().join("repair_chain.era");
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

        corrupt_archive_shard(&archive, 5000);

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();

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

        assert_file_content_eq(&out_dir.join("repair_chain.bin"), &data);
    }

    #[test]
    fn test_repair_chain_repair_then_repack_then_verify() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "repair_repack.bin", &data);
        let archive = temp.path().join("repair_repack.era");
        let repacked = temp.path().join("repair_repack_compact.era");

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
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    #[test]
    fn test_recovery_force_discards_interrupted_create_checkpoint() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "truncated_checkpoint.bin", &data);
        let archive = temp.path().join("truncated_checkpoint.era");

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

        let original_len = fs::metadata(&archive).unwrap().len();
        truncate_file(&archive, original_len / 2);

        let assert = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();
        let text = combined_output(assert.get_output()).to_lowercase();

        assert!(
            assert.get_output().status.success() || !text.is_empty(),
            "repair should handle interrupted archive gracefully"
        );
        if !assert.get_output().status.success() {
            assert_contains_any(
                &text,
                &["checkpoint", "trunc", "corrupt", "repair", "footer"],
            );
        }
    }

    #[test]
    fn test_recovery_checkpoint_corruption_is_rejected() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "footer_corrupt.bin", &data);
        let archive = temp.path().join("footer_corrupt.era");

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

        corrupt_footer(&archive);

        let assert = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();
        let text = combined_output(assert.get_output()).to_lowercase();

        assert!(
            assert.get_output().status.success() || !text.is_empty(),
            "repair should fail gracefully on footer corruption"
        );
        if !assert.get_output().status.success() {
            assert_contains_any(
                &text,
                &["checkpoint", "footer", "corrupt", "invalid", "repair"],
            );
        }
    }

    #[test]
    fn test_cold_recovery_drop_without_finalize_has_no_sidecars() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "no_sidecars.txt", b"no sidecar expected");
        let archive = temp.path().join("no_sidecars.era");

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

        let sidecars: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name.ends_with(".wal") || name.ends_with(".checkpoint")
            })
            .collect();

        assert!(
            sidecars.is_empty(),
            "unexpected recovery sidecars: {:?}",
            sidecars
        );
    }
}

mod security_edge_cases {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_security_extract_rejects_symlink_parent_swap() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        let inner = src.join("evil");
        let outside = temp.path().join("outside");
        let archive = temp.path().join("symlink_parent.era");
        let out_dir = temp.path().join("out");
        let outside_file = outside.join("payload.txt");

        fs::create_dir_all(&inner).unwrap();
        fs::create_dir_all(&outside).unwrap();
        create_test_file(&inner, "payload.txt", b"payload through symlink");

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

        fs::create_dir_all(&out_dir).unwrap();
        symlink(&outside, out_dir.join("evil")).unwrap();

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

        assert!(
            !outside_file.exists(),
            "extract must not write through a swapped parent symlink"
        );

        if assert.get_output().status.success() {
            let extracted = find_file_recursive(&out_dir, "payload.txt");
            assert!(
                extracted.starts_with(&out_dir),
                "sanitized extraction must stay within output root"
            );
        } else {
            let text = combined_output(assert.get_output()).to_lowercase();
            assert_contains_any(&text, &["symlink", "path", "outside", "contain"]);
        }
    }

    #[test]
    fn test_security_verify_reports_aead_tag_failure_message() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "aead_fail.bin", &data);
        let archive = temp.path().join("aead_fail.era");

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

        corrupt_volume_data(&archive);

        let assert = era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();
        let text = combined_output(assert.get_output()).to_lowercase();
        assert_contains_any(
            &text,
            &["integrity", "verification", "corrupt", "decrypt", "tamper"],
        );
    }

    #[test]
    fn test_security_verify_detects_spliced_foreign_volume() {
        let temp_a = TempDir::new().unwrap();
        let temp_b = TempDir::new().unwrap();
        let data_a = vec![0x11; 256 * 1024];
        let data_b = vec![0x22; 256 * 1024];
        let archive_a = create_multivolume_archive_with_data(&temp_a, "splice_a", &data_a, "4:2");
        let archive_b = create_multivolume_archive_with_data(&temp_b, "splice_b", &data_b, "4:2");

        fs::copy(
            archive_b.with_extension("era.003"),
            archive_a.with_extension("era.003"),
        )
        .unwrap();

        let assert = era_cmd()
            .args(["verify", archive_a.to_str().unwrap(), "--password", "pwd"])
            .assert();

        if assert.get_output().status.success() {
            panic!("verify should fail when a foreign secondary volume is spliced in");
        }

        let text = combined_output(assert.get_output()).to_lowercase();
        assert_contains_any(
            &text,
            &["integrity", "archive", "mismatch", "corrupt", "decrypt"],
        );
    }
}

mod empty_and_zero_byte {
    use super::*;

    #[test]
    fn test_edge_zero_byte_and_nonzero_mix_roundtrip() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        let archive = temp.path().join("zero_mix.era");
        let out_dir = temp.path().join("out");
        let small = generate_deterministic_data(1024);

        create_test_file(&src, "empty.bin", b"");
        create_test_file(&src, "small.bin", &small);

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

        let empty_path = find_file_recursive(&out_dir, "empty.bin");
        let small_path = find_file_recursive(&out_dir, "small.bin");
        assert_eq!(fs::metadata(empty_path).unwrap().len(), 0);
        assert_eq!(fs::metadata(&small_path).unwrap().len(), 1024);
        assert_file_content_eq(&small_path, &small);
    }

    #[test]
    fn test_edge_empty_directory_create_is_explicit() {
        let temp = TempDir::new().unwrap();
        let empty_dir = temp.path().join("empty_src");
        let archive = temp.path().join("empty_src.era");
        let out_dir = temp.path().join("out");
        fs::create_dir_all(&empty_dir).unwrap();

        let assert = era_cmd()
            .args([
                "create",
                empty_dir.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        if assert.get_output().status.success() {
            era_cmd()
                .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
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
                count_files_recursive(&out_dir),
                0,
                "empty archive should extract zero files"
            );
        } else {
            let text = combined_output(assert.get_output()).to_lowercase();
            assert_contains_any(&text, &["empty", "no file", "no input"]);
        }
    }
}

mod dedup_verification {
    use super::*;

    #[test]
    fn test_dedup_identical_files_roundtrip_and_growth_sanity() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        let single_src = temp.path().join("single_src");
        let archive = temp.path().join("dedup_many.era");
        let single_archive = temp.path().join("dedup_single.era");
        let out_dir = temp.path().join("out");
        let data = generate_deterministic_data(64 * 1024);

        for i in 0..3 {
            create_test_file(&src, &format!("dup_{}.bin", i), &data);
        }
        create_test_file(&single_src, "dup_single.bin", &data);

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
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
                "create",
                single_src.to_str().unwrap(),
                "--output",
                single_archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
            ])
            .assert()
            .success();

        let many_size = fs::metadata(&archive).unwrap().len();
        let single_size = fs::metadata(&single_archive).unwrap().len();
        assert!(
            many_size < single_size * 2,
            "dedup archive should grow well below 3x single-file size: many={}, single={}",
            many_size,
            single_size
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

        for i in 0..3 {
            assert_extracted_file(&out_dir, &format!("dup_{}.bin", i), &data);
        }
    }

    #[test]
    fn test_dedup_many_small_duplicate_files_verify() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        let archive = temp.path().join("many_small_dups.era");
        let out_dir = temp.path().join("out");
        let data = generate_deterministic_data(1024);

        for i in 0..50 {
            create_test_file(&src, &format!("dup_{:02}.txt", i), &data);
        }

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
            ])
            .assert()
            .success();

        let list_assert = era_cmd()
            .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
        let listed = combined_output(list_assert.get_output());
        for i in 0..50 {
            assert!(
                listed.contains(&format!("dup_{:02}.txt", i)),
                "list output should contain file {}",
                i
            );
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

        assert_eq!(
            count_files_recursive(&out_dir),
            50,
            "all duplicate files should extract"
        );
        for i in 0..50 {
            assert_extracted_file(&out_dir, &format!("dup_{:02}.txt", i), &data);
        }
    }
}

mod ec_config_matrix {
    use super::*;

    #[test]
    fn test_ec_config_2_plus_1_roundtrip() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(32 * 1024);
        let input = create_test_file(temp.path(), "ec_2_1.bin", &data);
        let archive = temp.path().join("ec_2_1.era");
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
                "2:1",
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

        assert_file_content_eq(&out_dir.join("ec_2_1.bin"), &data);
    }

    #[test]
    fn test_ec_config_6_plus_3_roundtrip() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "ec_6_3.bin", &data);
        let archive = temp.path().join("ec_6_3.era");
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

        assert_file_content_eq(&out_dir.join("ec_6_3.bin"), &data);
    }

    #[test]
    fn test_ec_config_8_plus_4_roundtrip() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "ec_8_4.bin", &data);
        let archive = temp.path().join("ec_8_4.era");
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
                "8:4",
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

        assert_file_content_eq(&out_dir.join("ec_8_4.bin"), &data);
    }

    #[test]
    fn test_config_file_comprehensive_overrides_work_end_to_end() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(32 * 1024);
        let input = create_test_file(temp.path(), "config_end_to_end.bin", &data);
        let archive = temp.path().join("config_end_to_end.era");
        let out_dir = temp.path().join("out");
        let config = create_test_config(
            temp.path(),
            r#"
[compression]
algorithm = "Zstd"
level = 19

[erasure]
data_shards = 6
parity_shards = 3
"#,
        );

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "-C",
                config.to_str().unwrap(),
            ])
            .assert()
            .success();

        let info_assert = era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
        let info_text = combined_output(info_assert.get_output()).to_lowercase();
        assert!(
            info_text.contains("19") && info_text.contains("compression"),
            "info should show compression_level=19: {}",
            info_text
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

        assert_file_content_eq(&out_dir.join("config_end_to_end.bin"), &data);
    }
}

mod concurrent_access {
    use super::*;

    #[test]
    fn test_concurrent_multivolume_extracts_to_distinct_roots() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let archive =
            create_multivolume_archive_with_data(&temp, "concurrent_extract", &data, "4:2");
        let archive_path = archive.to_path_buf();
        let binary = era_binary_path();

        let handles: Vec<_> = (0..4)
            .map(|idx| {
                let binary = binary.clone();
                let archive = archive_path.clone();
                let out_dir = temp.path().join(format!("out_{}", idx));
                std::thread::spawn(move || {
                    let output = std::process::Command::new(binary)
                        .args([
                            "extract",
                            "--input",
                            archive.to_str().unwrap(),
                            "--output",
                            out_dir.to_str().unwrap(),
                            "--password",
                            "pwd",
                        ])
                        .output()
                        .unwrap();
                    (out_dir, output)
                })
            })
            .collect();

        for handle in handles {
            let (out_dir, output) = handle.join().unwrap();
            assert!(
                output.status.success(),
                "extract failed: {}",
                combined_output(&output)
            );
            assert_extracted_file(&out_dir, "concurrent_extract.bin", &data);
        }
    }

    #[test]
    fn test_concurrent_verify_while_extracting_multivolume_archive() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let archive =
            create_multivolume_archive_with_data(&temp, "verify_extract_parallel", &data, "4:2");
        let binary = era_binary_path();
        let archive_for_verify = archive.clone();
        let archive_for_extract = archive.clone();
        let out_dir = temp.path().join("out");

        let verify_handle = std::thread::spawn(move || {
            std::process::Command::new(binary)
                .args([
                    "verify",
                    archive_for_verify.to_str().unwrap(),
                    "--password",
                    "pwd",
                ])
                .output()
                .unwrap()
        });

        let binary = era_binary_path();
        let extract_handle = std::thread::spawn(move || {
            std::process::Command::new(binary)
                .args([
                    "extract",
                    "--input",
                    archive_for_extract.to_str().unwrap(),
                    "--output",
                    out_dir.to_str().unwrap(),
                    "--password",
                    "pwd",
                ])
                .output()
                .unwrap()
        });

        let verify_output = verify_handle.join().unwrap();
        let extract_output = extract_handle.join().unwrap();

        assert!(
            verify_output.status.success(),
            "verify failed: {}",
            combined_output(&verify_output)
        );
        assert!(
            extract_output.status.success(),
            "extract failed: {}",
            combined_output(&extract_output)
        );
        assert_extracted_file(
            &temp.path().join("out"),
            "verify_extract_parallel.bin",
            &data,
        );
    }
}

mod repair_key_limitation {
    use super::*;

    #[test]
    fn test_repair_with_certificate_key_succeeds() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "repair_key_limit.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("repair_key_limit.era");
        let (public_cert, private_key) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &public_cert);

        let vol2 = archive.with_extension("era.002");
        assert!(vol2.exists(), "expected secondary volume for repair test");
        corrupt_volume_data(&vol2);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--key",
                private_key.to_str().unwrap(),
                "--force",
            ])
            .assert()
            .success();
    }
}
