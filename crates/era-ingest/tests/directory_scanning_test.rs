use era_ingest::{DirectoryScanner, FileType, ScanOptions};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[test]
fn test_end_to_end_directory_scanning() {
    // 1. Setup Environment
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    // Create directory structure
    fs::create_dir(root.join("src")).unwrap();
    fs::create_dir_all(root.join("target/debug")).unwrap();
    fs::create_dir(root.join("scripts")).unwrap();

    create_file(root.join("src/main.rs"), b"fn main() {}");
    create_file(root.join("src/lib.rs"), b"pub fn add() {}");
    create_file(root.join("target/debug/build_artifact.bin"), b"binary data");
    create_file(root.join("README.md"), b"# Readme");
    create_file(root.join("ignored_config.json"), b"{}");

    let script_path = root.join("scripts/script.sh");
    create_file(&script_path, b"#!/bin/bash\necho hello");

    // Set permissions (executable)
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();
    }

    // Set xattrs (if supported)
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let has_xattr_support = {
        let xattr_path = root.join("src/main.rs");
        match xattr::set(&xattr_path, "user.era_test", b"test_value") {
            Ok(_) => true,
            Err(_) => false,
        }
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let has_xattr_support = false;

    // 2. Configure Scanner
    let options = ScanOptions {
        root: root.to_path_buf(),
        include_patterns: vec![
            "**/*.rs".to_string(),
            "**/*.md".to_string(),
            "**/*.sh".to_string(),
        ],
        exclude_patterns: vec!["**/target/**".to_string()],
        extract_xattrs: true,
        extract_acls: true,
    };

    let scanner = DirectoryScanner::new(options).expect("Failed to initialize scanner");

    // 3. Execution
    let entries: Vec<_> = scanner
        .scan()
        .map(|r| r.expect("Failed to scan entry"))
        .collect();

    // 4. Verification
    let paths: Vec<_> = entries
        .iter()
        .map(|e| e.path.to_string_lossy().to_string())
        .collect();

    println!("Scanned paths: {:#?}", paths);

    // Verify Files exist
    assert!(find_path(&entries, "src/main.rs"), "Missing src/main.rs");
    assert!(find_path(&entries, "src/lib.rs"), "Missing src/lib.rs");
    assert!(find_path(&entries, "README.md"), "Missing README.md");
    assert!(
        find_path(&entries, "scripts/script.sh"),
        "Missing scripts/script.sh"
    );

    // Verify Exclusions
    assert!(
        !find_path(&entries, "target/debug/build_artifact.bin"),
        "Should exclude target/"
    );
    assert!(
        !find_path(&entries, "ignored_config.json"),
        "Should exclude json (not in include list)"
    );

    // Verify Metadata
    let script_entry = entries
        .iter()
        .find(|e| e.path.to_string_lossy().ends_with("scripts/script.sh"))
        .expect("Script entry not found");

    assert_eq!(script_entry.file_type, FileType::File);

    #[cfg(unix)]
    {
        // 0o111 checks if any execute bit is set. (user, group, or other)
        // 0o755 = rwx r-x r-x. All have execute.
        assert_eq!(
            script_entry.permissions & 0o111,
            0o111,
            "Executable permission missing"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if has_xattr_support {
        let main_rs_entry = entries
            .iter()
            .find(|e| e.path.to_string_lossy().ends_with("src/main.rs"))
            .expect("main.rs not found");
        assert!(
            main_rs_entry.xattrs.contains_key("user.era_test"),
            "XAttr missing"
        );
        assert_eq!(
            main_rs_entry.xattrs.get("user.era_test").unwrap(),
            b"test_value"
        );
    }
}

fn create_file<P: AsRef<std::path::Path>>(path: P, content: &[u8]) {
    let mut f = File::create(path).unwrap();
    f.write_all(content).unwrap();
}

fn find_path(entries: &[era_ingest::FileEntry], partial: &str) -> bool {
    entries
        .iter()
        .any(|e| e.path.to_string_lossy().ends_with(partial))
}
