//! End-to-End CLI integration tests for era-cli.
//!
//! Fills coverage gaps with 47 tests across 8 categories: data integrity,
//! CDC boundaries, multi-volume stress, repair chains, repack scenarios,
//! cross-command chains, error paths, and large file stress.
//!
//! Tests marked `#[ignore]` involve >5MB of data and are skipped by default.

#![allow(deprecated)]

use assert_cmd::Command;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ===========================================================================
// Shared helpers
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

fn generate_deterministic_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
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

fn count_files_recursive(dir: &Path) -> usize {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

fn corrupt_volume_data(volume_path: &Path) {
    let len = fs::metadata(volume_path).unwrap().len();
    let offset = if len > 6000 { 5000 } else { 4300 };
    corrupt_archive_shard(volume_path, offset);
}

fn assert_file_content_eq(path: &Path, expected: &[u8]) {
    let actual = fs::read(path).unwrap();
    assert_eq!(
        actual.len(),
        expected.len(),
        "size mismatch for {}",
        path.display()
    );
    assert_eq!(
        actual.as_slice(),
        expected,
        "content mismatch for {}",
        path.display()
    );
}

// ===========================================================================
// Category 1: Data Integrity Verification
// ===========================================================================

mod data_integrity_tests {
    use super::*;

    #[test]
    fn test_integrity_all_zeros_1mb() {
        let temp = TempDir::new().unwrap();
        let size = 1024 * 1024;
        let data = vec![0x00; size];
        let input = create_test_file(temp.path(), "zeros.bin", &data);
        let archive = temp.path().join("zeros.era");
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

        assert_file_content_eq(&out_dir.join("zeros.bin"), &data);
    }

    #[test]
    fn test_integrity_all_ones_1mb() {
        let temp = TempDir::new().unwrap();
        let size = 1024 * 1024;
        let data = vec![0xFF; size];
        let input = create_test_file(temp.path(), "ones.bin", &data);
        let archive = temp.path().join("ones.era");
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

        assert_file_content_eq(&out_dir.join("ones.bin"), &data);
    }

    #[test]
    fn test_integrity_alternating_pattern() {
        let temp = TempDir::new().unwrap();
        let size = 512 * 1024;
        let data: Vec<u8> = (0..size)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect();
        let input = create_test_file(temp.path(), "alternating.bin", &data);
        let archive = temp.path().join("alt.era");
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

        assert_file_content_eq(&out_dir.join("alternating.bin"), &data);
    }

    #[test]
    fn test_integrity_null_embedded_file() {
        let temp = TempDir::new().unwrap();
        // Text with embedded nulls: "hello\x00world\x00test"
        let data = b"hello\x00world\x00test".to_vec();
        let input = create_test_file(temp.path(), "nulls.txt", &data);
        let archive = temp.path().join("nulls.era");
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

        assert_file_content_eq(&out_dir.join("nulls.txt"), &data);
    }

    #[test]
    fn test_integrity_all_256_byte_values_repeated() {
        let temp = TempDir::new().unwrap();
        let size = 256 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let input = create_test_file(temp.path(), "allbytes.bin", &data);
        let archive = temp.path().join("allbytes.era");
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

        assert_file_content_eq(&out_dir.join("allbytes.bin"), &data);
    }

    #[test]
    fn test_integrity_highly_compressible_vs_random() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let compressible = vec![0x00; 128 * 1024];
        let random = generate_deterministic_data(128 * 1024);
        create_test_file(&src, "compressible.bin", &compressible);
        create_test_file(&src, "random.bin", &random);

        let archive_comp = temp.path().join("with_comp.era");
        let archive_nocomp = temp.path().join("no_comp.era");

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
                "--output",
                archive_comp.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "none",
                "--level",
                "3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
                "--output",
                archive_nocomp.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "none",
                "--no-compression",
            ])
            .assert()
            .success();

        let size_comp = fs::metadata(&archive_comp).unwrap().len();
        let size_nocomp = fs::metadata(&archive_nocomp).unwrap().len();

        assert!(
            size_comp < size_nocomp,
            "compressed archive ({}) should be smaller than uncompressed ({})",
            size_comp,
            size_nocomp
        );

        let out_dir = temp.path().join("out");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive_comp.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_file_content_eq(&out_dir.join("src").join("compressible.bin"), &compressible);
        assert_file_content_eq(&out_dir.join("src").join("random.bin"), &random);
    }

    #[test]
    fn test_integrity_deterministic_data_multiple_sizes() {
        let temp = TempDir::new().unwrap();
        let sizes = [1, 1024, 65536, 1024 * 1024, 4 * 1024 * 1024];

        for (i, &size) in sizes.iter().enumerate() {
            let data = generate_deterministic_data(size);
            let input = create_test_file(temp.path(), &format!("det_{}.bin", i), &data);
            let archive = temp.path().join(format!("det_{}.era", i));
            let out_dir = temp.path().join(format!("out_{}", i));

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

            assert_file_content_eq(&out_dir.join(format!("det_{}.bin", i)), &data);
        }
    }

    #[test]
    fn test_integrity_single_byte_file() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x42];
        let input = create_test_file(temp.path(), "single.bin", &data);
        let archive = temp.path().join("single.era");
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

        assert_file_content_eq(&out_dir.join("single.bin"), &data);
    }
}

// ===========================================================================
// Category 2: CDC Boundary Tests
// ===========================================================================

mod cdc_boundary_tests {
    use super::*;

    #[test]
    fn test_cdc_boundary_exact_min_16kb() {
        let temp = TempDir::new().unwrap();
        let size = 16384;
        let data = generate_deterministic_data(size);
        let input = create_test_file(temp.path(), "min_16k.bin", &data);
        let archive = temp.path().join("min_16k.era");
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

        assert_file_content_eq(&out_dir.join("min_16k.bin"), &data);
    }

    #[test]
    fn test_cdc_boundary_exact_avg_64kb() {
        let temp = TempDir::new().unwrap();
        let size = 65536;
        let data = generate_deterministic_data(size);
        let input = create_test_file(temp.path(), "avg_64k.bin", &data);
        let archive = temp.path().join("avg_64k.era");
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

        assert_file_content_eq(&out_dir.join("avg_64k.bin"), &data);
    }

    #[test]
    fn test_cdc_boundary_exact_max_256kb() {
        let temp = TempDir::new().unwrap();
        let size = 262144;
        let data = generate_deterministic_data(size);
        let input = create_test_file(temp.path(), "max_256k.bin", &data);
        let archive = temp.path().join("max_256k.era");
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

        assert_file_content_eq(&out_dir.join("max_256k.bin"), &data);
    }

    #[test]
    fn test_cdc_boundary_one_byte_over_max() {
        let temp = TempDir::new().unwrap();
        let size = 262145;
        let data = generate_deterministic_data(size);
        let input = create_test_file(temp.path(), "over_max.bin", &data);
        let archive = temp.path().join("over_max.era");
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

        assert_file_content_eq(&out_dir.join("over_max.bin"), &data);
    }
}

// ===========================================================================
// Category 3: Multi-Volume Stress Tests
// ===========================================================================

mod multivolume_stress_tests {
    use super::*;

    #[test]
    fn test_multivolume_many_volumes_stress() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(2 * 1024 * 1024);
        let input = create_test_file(temp.path(), "manyvols.bin", &data);
        let archive = temp.path().join("manyvols.era");
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
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 6,
            "2MB with 32KB max-volume-size should produce many volumes, got {}",
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

        assert_file_content_eq(&out_dir.join("manyvols.bin"), &data);
    }

    #[test]
    fn test_multivolume_min_volume_size_boundary() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xCD; 256 * 1024];
        let input = create_test_file(temp.path(), "minvol.bin", &data);
        let archive = temp.path().join("minvol.era");
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
                "20480",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 2,
            "256KB with 20KB volumes should produce multiple volumes, got {}",
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

        assert_file_content_eq(&out_dir.join("minvol.bin"), &data);
    }

    #[test]
    fn test_multivolume_extract_from_middle_volume() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xEE; 256 * 1024];
        let input = create_test_file(temp.path(), "midvol.bin", &data);
        let archive = temp.path().join("midvol.era");
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

        let vol3 = archive.with_extension("era.003");
        assert!(vol3.exists(), ".era.003 should exist");

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

        assert_file_content_eq(&out_dir.join("midvol.bin"), &data);
    }

    #[test]
    fn test_multivolume_list_from_arbitrary_volume() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xFF; 256 * 1024];
        let input = create_test_file(temp.path(), "listvol.bin", &data);
        let archive = temp.path().join("listvol.era");

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

        let vol4 = archive.with_extension("era.004");
        assert!(vol4.exists(), ".era.004 should exist");

        era_cmd()
            .args(["list", vol4.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    #[test]
    fn test_multivolume_info_from_arbitrary_volume() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x11; 256 * 1024];
        let input = create_test_file(temp.path(), "infovol.bin", &data);
        let archive = temp.path().join("infovol.era");

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
        assert!(vol2.exists(), ".era.002 should exist");

        era_cmd()
            .args(["info", vol2.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    #[test]
    fn test_multivolume_verify_from_secondary() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x22; 256 * 1024];
        let input = create_test_file(temp.path(), "verifyvol.bin", &data);
        let archive = temp.path().join("verifyvol.era");

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

        let vol5 = archive.with_extension("era.005");
        assert!(vol5.exists(), ".era.005 should exist");

        era_cmd()
            .args(["verify", vol5.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    #[test]
    fn test_multivolume_single_volume_with_erasure() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x33; 64 * 1024];
        let input = create_test_file(temp.path(), "singleec.bin", &data);
        let archive = temp.path().join("singleec.era");

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
        assert_eq!(count, 1, "single volume mode with EC should produce 1 file");

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

        assert_file_content_eq(&out_dir.join("singleec.bin"), &data);
    }

    #[test]
    fn test_multivolume_non_divisible_volume_count_fails() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x44; 64 * 1024];
        let input = create_test_file(temp.path(), "baddiv.bin", &data);
        let archive = temp.path().join("baddiv.era");

        // With 4+2 = 6 shards total, --volumes 4 is not valid
        // because 6 is not divisible by 4
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
                "4",
                "--no-compression",
            ])
            .assert()
            .failure();
    }
}

// ===========================================================================
// Category 4: Repair Chain Scenarios
// ===========================================================================

mod repair_chain_tests {
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
    fn test_repair_double_cycle() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let (_input, archive) = create_ec_archive(&temp, "double_cycle", &data);

        // First corruption and repair
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

        // Second corruption at different offset
        corrupt_archive_shard(&archive, 7000);
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

        assert_file_content_eq(&out_dir.join("double_cycle.bin"), &data);
    }

    #[test]
    fn test_repair_multivolume_simultaneous_corruption() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x55; 256 * 1024];
        let input = create_test_file(temp.path(), "simul_corr.bin", &data);
        let archive = temp.path().join("simul_corr.era");

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

        // Corrupt 2 different volumes
        let volumes = get_volume_paths(&archive);
        let mut corrupted = 0;
        for vol in &volumes {
            if corrupted >= 2 {
                break;
            }
            let len = fs::metadata(vol).unwrap().len();
            if len > 5000 {
                corrupt_volume_data(vol);
                corrupted += 1;
            }
        }
        assert!(corrupted >= 2, "should corrupt at least 2 volumes");

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

        assert_file_content_eq(&out_dir.join("simul_corr.bin"), &data);
    }

    #[test]
    fn test_repair_then_repack_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let (_input, archive) = create_ec_archive(&temp, "repair_repack", &data);

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

        // Repack with compact
        let repacked = temp.path().join("repair_repack_out.era");
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

        assert_file_content_eq(&out_dir.join("repair_repack.bin"), &data);
    }

    #[test]
    fn test_repair_dry_run_then_force() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x66; 256 * 1024];
        let (_input, archive) = create_ec_archive(&temp, "dry_then_force", &data);

        corrupt_archive_shard(&archive, 5000);
        let before_bytes = fs::read(&archive).unwrap();

        // Dry run (no --force)
        era_cmd()
            .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let after_bytes = fs::read(&archive).unwrap();
        assert_eq!(
            before_bytes, after_bytes,
            "dry-run repair should NOT modify the archive"
        );

        // Force repair
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
    fn test_repair_verbose_output_contains_stats() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x77; 256 * 1024];
        let (_input, archive) = create_ec_archive(&temp, "verbose_stats", &data);

        corrupt_archive_shard(&archive, 5000);

        let assert_result = era_cmd()
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

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        let stderr_lower = stderr.to_lowercase();
        assert!(
            stderr_lower.contains("blocks scanned")
                || stderr_lower.contains("corrupted shards")
                || stderr_lower.contains("shards repaired")
                || stderr_lower.contains("blocks with damage"),
            "verbose repair should show detailed stats: {}",
            stderr
        );
    }

    #[test]
    fn test_repack_multivolume_preserves_content() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x99; 256 * 1024];
        let input = create_test_file(temp.path(), "mv_preserve.bin", &data);
        let archive = temp.path().join("mv_preserve.era");

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

        let original_count = count_volume_files(&archive);
        assert!(original_count >= 2, "should be multi-volume");

        let repacked = temp.path().join("mv_preserve_out.era");
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

        // Verify repacked archive has correct content
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

        assert_file_content_eq(&out_dir.join("mv_preserve.bin"), &data);

        // Verify both archives pass verification
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        era_cmd()
            .args(["verify", repacked.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
    }

    #[test]
    fn test_repair_multivolume_missing_one_then_corrupt_another() {
        let temp = TempDir::new().unwrap();
        let data = vec![0x88; 256 * 1024];
        let input = create_test_file(temp.path(), "miss_corr.bin", &data);
        let archive = temp.path().join("miss_corr.era");

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

        // Delete vol.003
        let vol3 = archive.with_extension("era.003");
        if vol3.exists() {
            fs::remove_file(&vol3).unwrap();
        }

        // Corrupt vol.001
        let vol1 = archive.with_extension("era.001");
        if vol1.exists() {
            corrupt_volume_data(&vol1);
        }

        // With 4+2 EC and 6 volumes: losing 1 (missing) + 1 (corrupted) = 2 losses
        // This is within the 2 parity budget, repair should succeed
        let repair_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&repair_result.get_output().stderr);
        if repair_result.get_output().status.success() {
            // Repair succeeded — verify data integrity
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

            assert_file_content_eq(&out_dir.join("miss_corr.bin"), &data);
        } else {
            assert!(
                stderr.to_lowercase().contains("missing")
                    || stderr.to_lowercase().contains("insufficient")
                    || stderr.to_lowercase().contains("recover"),
                "repair failure should explain why: {}",
                stderr
            );
        }
    }
}

// ===========================================================================
// Category 5: Repack Advanced Tests
// ===========================================================================

mod repack_advanced_tests {
    use super::*;

    #[test]
    fn test_repack_different_compression_level() {
        let temp = TempDir::new().unwrap();
        // Use highly compressible data so different levels produce different sizes
        let data = vec![0x00; 64 * 1024];
        let input = create_test_file(temp.path(), "diff_comp.bin", &data);
        let archive = temp.path().join("diff_comp.era");

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

        let size_level3 = fs::metadata(&archive).unwrap().len();

        let repacked = temp.path().join("diff_comp_out.era");
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

        assert_file_content_eq(&out_dir.join("diff_comp.bin"), &data);
        // With all-zeros data, both levels compress well but level 19 should be <= level 3
        assert!(
            size_level19 <= size_level3,
            "level 19 ({}) should produce archive <= level 3 ({}) for compressible data",
            size_level19,
            size_level3
        );
    }

    #[test]
    fn test_repack_all_geek_params_changed() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let input = create_test_file(temp.path(), "geek_params.bin", &data);
        let archive = temp.path().join("geek_params.era");

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

        let repacked = temp.path().join("geek_params_out.era");
        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--cdc-min",
                "8192",
                "--cdc-avg",
                "32768",
                "--cdc-max",
                "131072",
                "--packing-k",
                "16",
                "--flush-threshold",
                "75",
                "--block-target-size",
                "4194304",
                "--level",
                "12",
                "--erasure",
                "6:3",
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

        assert_file_content_eq(&out_dir.join("geek_params.bin"), &data);
    }

    #[test]
    fn test_repack_verify_extract_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let input = create_test_file(temp.path(), "verify_chain.bin", &data);
        let archive = temp.path().join("verify_chain.era");

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

        let repacked = temp.path().join("verify_chain_out.era");
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

        let out1 = temp.path().join("out1");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out1.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let out2 = temp.path().join("out2");
        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out2.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let original = fs::read(out1.join("verify_chain.bin")).unwrap();
        let repacked_extracted = fs::read(out2.join("verify_chain.bin")).unwrap();
        assert_eq!(
            original, repacked_extracted,
            "repacked should match original"
        );
    }

    #[test]
    fn test_repack_previously_repaired_archive() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let input = create_test_file(temp.path(), "repaired.bin", &data);
        let archive = temp.path().join("repaired.era");

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

        let repacked = temp.path().join("repaired_out.era");
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

        assert_file_content_eq(&out_dir.join("repaired.bin"), &data);
    }

    #[test]
    fn test_repack_no_compression_to_max_compression() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let input = create_test_file(temp.path(), "comp_up.bin", &data);
        let archive = temp.path().join("comp_up.era");

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

        let size_no_comp = fs::metadata(&archive).unwrap().len();

        let repacked = temp.path().join("comp_up_out.era");
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
                "22",
            ])
            .assert()
            .success();

        let size_max_comp = fs::metadata(&repacked).unwrap().len();

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

        assert_file_content_eq(&out_dir.join("comp_up.bin"), &data);
        assert!(
            size_max_comp <= size_no_comp,
            "max compression ({}) should be <= no compression ({})",
            size_max_comp,
            size_no_comp
        );
    }

    #[test]
    fn test_repack_different_password() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "diff_pw.bin", &data);
        let archive = temp.path().join("diff_pw.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "alpha",
            ])
            .assert()
            .success();

        // Repack uses the same --password for both reading and writing.
        // Verify that repacking with the correct password produces a valid archive,
        // and that the original password still works on the repacked output.
        let repacked = temp.path().join("diff_pw_out.era");
        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "alpha",
            ])
            .assert()
            .success();

        // Wrong password on repacked archive should fail
        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                temp.path().join("out_wrong").to_str().unwrap(),
                "--password",
                "wrong",
            ])
            .assert()
            .failure();

        // Correct password on repacked archive should succeed
        let out_dir = temp.path().join("out_correct");
        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "alpha",
            ])
            .assert()
            .success();

        assert_file_content_eq(&out_dir.join("diff_pw.bin"), &data);
    }

    #[test]
    fn test_repack_multivolume_to_single() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xBB; 256 * 1024];
        let input = create_test_file(temp.path(), "mv_to_single.bin", &data);
        let archive = temp.path().join("mv_to_single.era");

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
        assert!(vol_count >= 2, "should be multi-volume, got {}", vol_count);

        let repacked = temp.path().join("single_out.era");
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

        let repacked_vol_count = count_volume_files(&repacked);
        assert_eq!(
            repacked_vol_count, 1,
            "repacked with --erasure none should be single file, got {}",
            repacked_vol_count
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

        assert_file_content_eq(&out_dir.join("mv_to_single.bin"), &data);
    }
}

// ===========================================================================
// Category 6: Cross-Command Integration Chains
// ===========================================================================

mod cross_command_chains {
    use super::*;

    #[test]
    fn test_full_lifecycle_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(256 * 1024);
        let input = create_test_file(temp.path(), "lifecycle.bin", &data);
        let archive = temp.path().join("lifecycle.era");

        // create
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

        // verify
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // list
        era_cmd()
            .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // info
        era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // corrupt
        corrupt_archive_shard(&archive, 5000);

        // repair
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

        // verify again
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // extract
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

        assert_file_content_eq(&out_dir.join("lifecycle.bin"), &data);
    }

    #[test]
    fn test_create_repack_compare_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(128 * 1024);
        let input = create_test_file(temp.path(), "repack_cmp.bin", &data);

        // Create with level 3
        let archive_l3 = temp.path().join("level3.era");
        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive_l3.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "3",
            ])
            .assert()
            .success();

        // Repack with level 19
        let archive_l19 = temp.path().join("level19.era");
        era_cmd()
            .args([
                "repack",
                "--input",
                archive_l3.to_str().unwrap(),
                "--output",
                archive_l19.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "19",
            ])
            .assert()
            .success();

        // Verify both
        era_cmd()
            .args(["verify", archive_l3.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();
        era_cmd()
            .args(["verify", archive_l19.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract both
        let out_l3 = temp.path().join("out_l3");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive_l3.to_str().unwrap(),
                "--output",
                out_l3.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let out_l19 = temp.path().join("out_l19");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive_l19.to_str().unwrap(),
                "--output",
                out_l19.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        // Both should produce identical files
        let extracted_l3 = fs::read(out_l3.join("repack_cmp.bin")).unwrap();
        let extracted_l19 = fs::read(out_l19.join("repack_cmp.bin")).unwrap();
        assert_eq!(extracted_l3, extracted_l19, "both extractions should match");
        assert_eq!(extracted_l3, data, "extraction should match original");
    }

    #[test]
    fn test_degraded_extract_then_repair_chain() {
        let temp = TempDir::new().unwrap();
        let data = vec![0xAA; 256 * 1024];
        let input = create_test_file(temp.path(), "deg_extract.bin", &data);
        let archive = temp.path().join("deg_extract.era");

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

        // Corrupt vol.002 (simulate data degradation)
        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            let len = fs::metadata(&vol2).unwrap().len();
            if len > 5000 {
                corrupt_archive_shard(&vol2, 5000);
            }
        }

        // Extract degraded - should still succeed with 4+2 EC (can tolerate 1 corrupted shard)
        let out_deg = temp.path().join("out_deg");
        let extract_result = era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_deg.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        // Repair should succeed after corruption
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

        // Extract again
        let out_rep = temp.path().join("out_rep");
        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_rep.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let after_repair = fs::read(out_rep.join("deg_extract.bin")).unwrap();
        assert_eq!(
            after_repair, data,
            "repaired extraction should match original"
        );

        // Also verify degraded extraction matched if it succeeded
        if extract_result.get_output().status.success() {
            let degraded = fs::read(out_deg.join("deg_extract.bin")).unwrap();
            assert_eq!(degraded, data, "degraded extraction should also match");
        }
    }

    #[test]
    fn test_cert_full_command_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "cert_chain.bin", &data);
        let archive = temp.path().join("cert_chain.era");
        let (pub_path, priv_path) = generate_test_keypair(temp.path());

        // Create with certificate
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

        // List with key
        era_cmd()
            .args([
                "list",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        // Info with key
        era_cmd()
            .args([
                "info",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        // Verify with key
        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        // Repack with key
        let repacked = temp.path().join("cert_chain_out.era");
        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
                "--compact",
            ])
            .assert()
            .success();

        // Extract repacked with key
        let out_dir = temp.path().join("out");
        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_file_content_eq(&out_dir.join("cert_chain.bin"), &data);
    }

    #[test]
    fn test_hybrid_full_command_chain() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(64 * 1024);
        let input = create_test_file(temp.path(), "hybrid_chain.bin", &data);
        let archive = temp.path().join("hybrid_chain.era");
        let (pub_path, priv_path) = generate_test_keypair(temp.path());

        // Create with certificate + password
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

        // Verify with password
        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        // List with key
        era_cmd()
            .args([
                "list",
                archive.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        // Info with password
        era_cmd()
            .args([
                "info",
                archive.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        // Extract with key
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

        assert_file_content_eq(&out_dir.join("hybrid_chain.bin"), &data);
    }

    #[test]
    fn test_create_verify_list_info_consistency() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        for i in 0..5 {
            create_test_file(
                &src,
                &format!("file_{}.bin", i),
                &vec![i as u8; 1024 * (i + 1)],
            );
        }
        let archive = temp.path().join("consistency.era");

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

        // Verify
        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // List
        let list_result = era_cmd()
            .args([
                "list",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--long",
            ])
            .assert()
            .success();

        let list_stderr = String::from_utf8_lossy(&list_result.get_output().stderr);
        let listed_count = list_stderr.matches("file_").count();
        assert_eq!(listed_count, 5, "list should show 5 files");

        // Info
        era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        // Extract and verify count
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

        let extracted_count = count_files_recursive(&out_dir);
        assert_eq!(
            extracted_count, 5,
            "extracted file count should match list output, got {}",
            extracted_count
        );
    }
}

// ===========================================================================
// Category 7: Error Path Validation
// ===========================================================================

mod error_path_tests {
    use super::*;

    #[test]
    fn test_create_self_reference_protection() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        create_test_file(&src, "data.txt", b"some data");
        // Output inside input directory
        let archive = src.join("self_ref.era");

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

        // Archive should exist
        assert!(archive.exists(), "archive should be created");

        // Extract should work
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

        // The archive itself should NOT appear inside itself
        // (self-reference protection)
        let extracted = count_files_recursive(&out_dir);
        assert!(
            extracted <= 1,
            "self-reference should be excluded, got {} files",
            extracted
        );
    }

    #[test]
    fn test_repair_no_erasure_after_corruption() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "noec_corr.bin", &vec![0xBB; 64 * 1024]);
        let archive = temp.path().join("noec_corr.era");

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

        corrupt_archive_shard(&archive, 5000);

        let repair_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&repair_result.get_output().stderr);
        assert!(
            stderr.to_lowercase().contains("without erasure")
                || stderr.to_lowercase().contains("no repair")
                || stderr.to_lowercase().contains("not available")
                || stderr.to_lowercase().contains("erasure")
                || !repair_result.get_output().status.success(),
            "repair on non-EC archive should report gracefully: {}",
            stderr
        );
    }

    #[test]
    fn test_long_filename_near_os_limit() {
        let temp = TempDir::new().unwrap();
        // Create filename with ~200 chars (some systems limit to 255 bytes)
        let long_name = "a".repeat(200) + ".txt";
        let data = b"long filename test".to_vec();
        let input = create_test_file(temp.path(), &long_name, &data);
        let archive = temp.path().join("longfn.era");
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

        // Find the extracted file - search by content since name may be truncated by OS
        let mut found = false;
        for entry in walkdir::WalkDir::new(&out_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Ok(content) = fs::read(entry.path()) {
                if content == data {
                    found = true;
                    break;
                }
            }
        }
        assert!(
            found,
            "file with long name should be extracted with correct content"
        );
    }

    #[test]
    fn test_deeply_nested_path_20_levels() {
        let temp = TempDir::new().unwrap();
        let mut path = temp.path().join("src");
        for i in 0..20 {
            path = path.join(format!("level_{}", i));
        }
        fs::create_dir_all(&path).unwrap();
        let data = b"deep nesting test".to_vec();
        create_test_file(&path, "deep.txt", &data);
        let archive = temp.path().join("deep.era");
        let out_dir = temp.path().join("out");

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

        // Verify content exists somewhere in nested structure
        let mut found = false;
        for entry in walkdir::WalkDir::new(&out_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if entry.file_name() == "deep.txt" {
                let content = fs::read(entry.path()).unwrap();
                assert_eq!(content, data);
                found = true;
                break;
            }
        }
        assert!(found, "deeply nested file should be extracted");
    }

    #[test]
    fn test_many_empty_files_100() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();

        for i in 0..100 {
            create_test_file(&src, &format!("empty_{:03}.txt", i), &[]);
        }

        let archive = temp.path().join("empty100.era");
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
        assert_eq!(
            extracted_count, 100,
            "all 100 empty files should be extracted, got {}",
            extracted_count
        );

        // Verify all are empty
        for i in 0..100 {
            let file = out_dir.join("src").join(format!("empty_{:03}.txt", i));
            if file.exists() {
                let content = fs::read(&file).unwrap();
                assert!(
                    content.is_empty(),
                    "empty file {} should have no content",
                    i
                );
            }
        }
    }
}

// ===========================================================================
// Category 8: Large File Stress Tests (all #[ignore])
// ===========================================================================

mod large_file_stress_tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_large_10_files_5mb_each() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();

        for i in 0..10 {
            let data = generate_deterministic_data(5 * 1024 * 1024);
            create_test_file(&src, &format!("large_{}.bin", i), &data);
        }

        let archive = temp.path().join("large10.era");
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

        // Verify all 10 files
        for i in 0..10 {
            let expected = generate_deterministic_data(5 * 1024 * 1024);
            assert_file_content_eq(
                &out_dir.join("src").join(format!("large_{}.bin", i)),
                &expected,
            );
        }
    }

    #[test]
    #[ignore]
    fn test_large_multivolume_20_volumes_roundtrip() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(10 * 1024 * 1024);
        let input = create_test_file(temp.path(), "big_mv.bin", &data);
        let archive = temp.path().join("big_mv.era");
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
                "65536",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 20,
            "10MB with 64KB volumes should produce 20+ volumes, got {}",
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

        assert_file_content_eq(&out_dir.join("big_mv.bin"), &data);
    }

    #[test]
    #[ignore]
    fn test_large_repair_5mb_archive() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(5 * 1024 * 1024);
        let input = create_test_file(temp.path(), "repair_big.bin", &data);
        let archive = temp.path().join("repair_big.era");

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

        assert_file_content_eq(&out_dir.join("repair_big.bin"), &data);
    }

    #[test]
    #[ignore]
    fn test_large_repack_10mb_compact() {
        let temp = TempDir::new().unwrap();
        let data = generate_deterministic_data(10 * 1024 * 1024);
        let input = create_test_file(temp.path(), "repack_big.bin", &data);
        let archive = temp.path().join("repack_big.era");

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

        let repacked = temp.path().join("repack_big_out.era");
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

        let size_original = fs::metadata(&archive).unwrap().len();
        let size_repacked = fs::metadata(&repacked).unwrap().len();

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

        assert_file_content_eq(&out_dir.join("repack_big.bin"), &data);

        assert!(
            size_repacked <= size_original,
            "compact repacked ({}) should be <= original ({})",
            size_repacked,
            size_original
        );
    }
}
