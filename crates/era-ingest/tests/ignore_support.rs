use era_ingest::{DirectoryScanner, ScanOptions};
use std::fs::{self, File};
use std::io::Write;
use tempfile::TempDir;

fn create_file<P: AsRef<std::path::Path>>(path: P, content: &[u8]) {
    let mut f = File::create(path).unwrap();
    f.write_all(content).unwrap();
}

fn find_path(entries: &[era_ingest::FileEntry], partial: &str) -> bool {
    entries
        .iter()
        .any(|e| e.path.to_string_lossy().ends_with(partial))
}

#[test]
fn test_ignore_files_respected() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    fs::create_dir_all(root.join("tmp")).unwrap();

    create_file(root.join("keep.txt"), b"keep");
    create_file(root.join("ignored.log"), b"ignore");
    create_file(root.join("secret.bin"), b"secret");
    create_file(root.join("tmp/skip.txt"), b"skip");

    create_file(root.join(".gitignore"), b"ignored.log\n");
    create_file(root.join(".ignore"), b"tmp/\n");
    create_file(root.join(".eraignore"), b"secret.bin\n");

    let options = ScanOptions {
        root: root.to_path_buf(),
        include_patterns: vec![],
        exclude_patterns: vec![],
        extract_xattrs: false,
        extract_acls: false,
    };

    let scanner = DirectoryScanner::new(options).expect("Failed to initialize scanner");
    let entries: Vec<_> = scanner
        .scan()
        .map(|r| r.expect("Failed to scan entry"))
        .collect();

    assert!(find_path(&entries, "keep.txt"), "Expected keep.txt");
    assert!(
        !find_path(&entries, "ignored.log"),
        "Expected ignored.log to be skipped via .gitignore"
    );
    assert!(
        !find_path(&entries, "secret.bin"),
        "Expected secret.bin to be skipped via .eraignore"
    );
    assert!(
        !find_path(&entries, "tmp/skip.txt"),
        "Expected tmp/skip.txt to be skipped via .ignore"
    );
}
