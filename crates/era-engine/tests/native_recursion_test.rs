use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_native_directory_recursion() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("recursion_test.era");
    let source_dir = temp_dir.path().join("source");

    // Create directory structure:
    // source/
    //   file1.txt
    //   subdir/
    //     file2.txt
    //   empty_subdir/
    fs::create_dir_all(source_dir.join("subdir")).unwrap();
    fs::create_dir_all(source_dir.join("empty_subdir")).unwrap();
    fs::write(source_dir.join("file1.txt"), "File 1 Content").unwrap();
    fs::write(source_dir.join("subdir/file2.txt"), "File 2 Content").unwrap();

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .build()
        .await
        .unwrap();

    // This method needs to be recursive or support directories
    // Currently, based on audit, this might fail or not exist
    let result = writer.add_path(&source_dir, true).await; // true for recursive

    assert!(
        result.is_ok(),
        "Adding directory should succeed: {:?}",
        result
    );

    writer.finalize().await.unwrap();

    // Verify
    let mut reader = ArchiveReader::open(&archive_path, "").await.unwrap();
    let files = reader.list_files().await.unwrap();

    // We expect 2 files (and maybe directory entries if supported)
    // path identifiers should be relative to the added root usually, or absolute?
    // Let's assume relative to the added path if we pass a directory.
    // Or maybe we need to check how they are stored.

    let paths: Vec<&str> = files.iter().map(|f| f.path.to_str().unwrap()).collect();
    println!("Archived paths: {:?}", paths);

    // Naive expectation: partial matching
    let found_file1 = paths.iter().any(|p| p.contains("file1.txt"));
    let found_file2 = paths.iter().any(|p| p.contains("file2.txt"));

    assert!(found_file1, "Should contain file1.txt");
    assert!(found_file2, "Should contain file2.txt");
}
