use era_ingest::{DirectoryScanner, ScanOptions};
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_acl_ingestion_macos() {
    if !cfg!(target_os = "macos") {
        return;
    }

    let temp = TempDir::new().unwrap();
    let root = temp.path();
    let file_path = root.join("secret.txt");
    fs::write(&file_path, "secret").unwrap();

    // Set ACL on macOS: user cleanup works
    // chmod +a "nobody allow read,write" secret.txt
    let status = Command::new("chmod")
        .arg("+a")
        .arg("nobody allow read,write")
        .arg(&file_path)
        .status()
        .expect("Failed to execute chmod");

    if !status.success() {
        eprintln!("Warning: chmod +a failed, maybe FS doesn't support ACLs. Skipping test.");
        return;
    }

    let options = ScanOptions {
        root: root.to_path_buf(),
        extract_acls: true,
        ..Default::default()
    };

    let scanner = DirectoryScanner::new(options).unwrap();
    // Scan recurses, find our file
    let entry = scanner
        .scan()
        .find(|res| {
            res.as_ref()
                .unwrap()
                .path
                .to_str()
                .unwrap()
                .contains("secret.txt")
        })
        .unwrap()
        .unwrap();

    assert!(entry.acl.is_some(), "Expected ACL to be captured on macOS");
    let acl_bytes = entry.acl.unwrap();
    assert!(!acl_bytes.is_empty());
}
