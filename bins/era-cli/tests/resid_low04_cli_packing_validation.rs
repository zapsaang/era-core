mod common;

use common::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn create_invalid_packing_params_fail_without_creating_volumes() {
    let temp = TempDir::new().unwrap();
    let input = create_test_file(
        &temp.path().join("in"),
        "payload.txt",
        b"packing validation",
    );

    for (case_name, flag, value) in [
        ("k0", "--packing-k", "0"),
        ("ft0", "--flush-threshold", "0"),
        ("ft101", "--flush-threshold", "101"),
    ] {
        let out_dir = temp.path().join(format!("out_{case_name}"));
        fs::create_dir_all(&out_dir).unwrap();
        let archive = out_dir.join(format!("{case_name}.era"));

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                flag,
                value,
            ])
            .assert()
            .failure();

        let remaining: Vec<_> = fs::read_dir(&out_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            remaining.is_empty(),
            "failed create with {flag} {value} must leave no residual volume files, found: {remaining:?}"
        );
    }
}
