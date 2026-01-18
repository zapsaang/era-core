use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_directory_recursion() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();
    let source_dir = root.join("source");
    let output_file = root.join("archive.era");

    // Create a directory structure
    // source/
    //   file1.txt
    //   subdir/
    //     file2.txt

    fs::create_dir(&source_dir)?;
    fs::write(source_dir.join("file1.txt"), "content1")?;
    fs::create_dir(source_dir.join("subdir"))?;
    fs::write(source_dir.join("subdir").join("file2.txt"), "content2")?;

    let mut cmd = Command::cargo_bin("era")?;

    // Attempt to archive the directory
    cmd.arg("create")
        .arg("-o")
        .arg(&output_file)
        .arg("--password")
        .arg("testpass")
        .arg(&source_dir);

    // Assert success
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Archive created successfully"));

    // Now extract and verify
    let extract_dir = root.join("restored");
    fs::create_dir(&extract_dir)?;

    let mut extract_cmd = Command::cargo_bin("era")?;
    extract_cmd
        .arg("extract")
        .arg("-o")
        .arg(&extract_dir)
        .arg("--password")
        .arg("testpass")
        .arg("--input") // Add --input if that's what the CLI expects, or just the arg if it's positional but named differently
        .arg(&output_file);

    extract_cmd.assert().success();

    // Verify files exist
    assert!(extract_dir.join("source/file1.txt").exists());
    assert!(extract_dir.join("source/subdir/file2.txt").exists());

    Ok(())
}
