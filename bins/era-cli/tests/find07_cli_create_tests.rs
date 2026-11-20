mod common;

use common::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn t3a_nonexistent_input_leaves_no_volume_files() {
    let temp = TempDir::new().unwrap();
    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let archive = out_dir.join("t3a.era");
    let missing_input = temp.path().join("no_such_file.txt");

    era_cmd()
        .args([
            "create",
            missing_input.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .failure();

    let remaining: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        remaining.is_empty(),
        "failed create on nonexistent input should leave no volume files, found: {:?}",
        remaining
    );
}

#[test]
fn t3b_duplicate_single_file_basenames_fail_before_creating_volumes() {
    let temp = TempDir::new().unwrap();
    let d1 = temp.path().join("d1");
    let d2 = temp.path().join("d2");
    let f1 = create_test_file(&d1, "dup.txt", b"first content");
    let f2 = create_test_file(&d2, "dup.txt", b"second content");

    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let archive = out_dir.join("t3b.era");

    let assert = era_cmd()
        .args([
            "create",
            f1.to_str().unwrap(),
            f2.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("dup.txt") && (stderr.contains("Duplicate") || stderr.contains("conflict")),
        "expected collision error mentioning dup.txt, got: {}",
        stderr
    );

    let remaining: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        remaining.is_empty(),
        "duplicate collision should fail before creating volumes, found: {:?}",
        remaining
    );
}

#[test]
fn t3c_parent_dir_input_leaves_no_volume_files() {
    let temp = TempDir::new().unwrap();
    let parent = temp.path().join("parent");
    let sub = parent.join("sub");
    fs::create_dir_all(&sub).unwrap();
    create_test_file(&parent, "payload.txt", b"parent content");

    let out_dir = temp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let archive = out_dir.join("t3c.era");

    era_cmd()
        .current_dir(&sub)
        .args([
            "create",
            "..",
            "--output",
            archive.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .failure();

    let remaining: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        remaining.is_empty(),
        "failed create on '..' input should leave no volume files, found: {:?}",
        remaining
    );
}

#[test]
fn t3d_output_without_era_extension_inside_input_dir_excludes_self() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "data.txt", b"real input payload");

    // Pre-create stale volume files to also verify exclusion before build
    let archive_base = src.join("my_archive");
    let first_vol = src.join("my_archive.era");
    fs::write(&first_vol, b"stale primary volume").unwrap();
    fs::write(src.join("my_archive.era.001"), b"stale secondary volume").unwrap();

    era_cmd()
        .args([
            "create",
            src.to_str().unwrap(),
            "--output",
            archive_base.to_str().unwrap(),
            "--password",
            "pwd",
        ])
        .assert()
        .success();

    assert!(first_vol.exists(), "expected my_archive.era to be created");

    let list_assert = era_cmd()
        .args(["list", first_vol.to_str().unwrap(), "--password", "pwd"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&list_assert.get_output().stdout);
    let stderr = String::from_utf8_lossy(&list_assert.get_output().stderr);
    let combined = format!("{}\n{}", stdout, stderr);
    assert!(
        combined.contains("Total: 1 files") && combined.contains("src/data.txt"),
        "expected exactly 1 file (src/data.txt) in list output: {}",
        combined
    );
    let listed_self = combined
        .lines()
        .filter(|line| !line.contains("Opening archive:"))
        .any(|line| line.contains("my_archive.era"));
    assert!(
        !listed_self,
        "archive must not include its own volumes even without .era extension: {}",
        combined
    );
}
