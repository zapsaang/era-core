use era_engine::{ArchiveReader, ArchiveWriterBuilder};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(content).unwrap();
    path
}

/// GIVEN a source directory containing real files
/// WHEN the archive output (.era) is placed inside that same directory
/// THEN add_path must NOT include the output .era file in the archive
#[tokio::test]
async fn test_add_path_excludes_output_archive_from_input_directory() {
    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("project");
    fs::create_dir_all(&source_dir).unwrap();

    create_test_file(&source_dir, "readme.txt", b"Hello ERA");
    create_test_file(&source_dir, "data/config.toml", b"[settings]\nkey = \"value\"");
    create_test_file(&source_dir, "src/main.rs", b"fn main() {}");

    let archive_path = source_dir.join("output.era");

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .build()
        .await
        .unwrap();

    writer.add_path(&source_dir, true).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    let files = reader.list_files().await.unwrap();
    let paths: Vec<String> = files
        .iter()
        .map(|f| f.path.to_string_lossy().to_string())
        .collect();

    println!("Archived paths: {:?}", paths);

    assert!(paths.iter().any(|p| p.contains("readme.txt")));
    assert!(paths.iter().any(|p| p.contains("config.toml")));
    assert!(paths.iter().any(|p| p.contains("main.rs")));

    let self_included = paths.iter().any(|p| p.contains("output.era"));
    assert!(
        !self_included,
        "Archive must NOT include itself! Found output.era in archive: {:?}",
        paths
    );
}

/// GIVEN a source directory with files
/// WHEN a multi-volume archive (.era + .era.NNN) output is inside that directory
/// THEN neither the primary archive nor its volume files should be archived
#[tokio::test]
async fn test_add_path_excludes_volume_files_from_input_directory() {
    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("multi_vol");
    fs::create_dir_all(&source_dir).unwrap();

    create_test_file(&source_dir, "file_a.bin", &vec![0xAA; 1024]);
    create_test_file(&source_dir, "file_b.bin", &vec![0xBB; 1024]);

    let archive_path = source_dir.join("archive.era");

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .enable_erasure(true)
        .volume_count(3)
        .build()
        .await
        .unwrap();

    writer.add_path(&source_dir, true).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    let files = reader.list_files().await.unwrap();
    let paths: Vec<String> = files
        .iter()
        .map(|f| f.path.to_string_lossy().to_string())
        .collect();

    println!("Archived paths (multi-vol): {:?}", paths);

    assert!(paths.iter().any(|p| p.contains("file_a.bin")));
    assert!(paths.iter().any(|p| p.contains("file_b.bin")));

    let archive_files: Vec<&String> = paths
        .iter()
        .filter(|p| p.contains("archive.era"))
        .collect();
    assert!(
        archive_files.is_empty(),
        "Archive must NOT include itself or its volume files! Found: {:?}",
        archive_files
    );
}

/// GIVEN a source directory containing both real files AND an unrelated .era file
/// WHEN the archive output is placed inside that directory
/// THEN the unrelated .era file MUST still be archived (only our own output is excluded)
#[tokio::test]
async fn test_add_path_preserves_unrelated_era_files() {
    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("mixed");
    fs::create_dir_all(&source_dir).unwrap();

    create_test_file(&source_dir, "data.txt", b"real data");
    create_test_file(&source_dir, "other_backup.era", b"some other archive");

    let archive_path = source_dir.join("my_output.era");

    let mut writer = ArchiveWriterBuilder::new(&archive_path)
        .password("test_password")
        .build()
        .await
        .unwrap();

    writer.add_path(&source_dir, true).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "test_password")
        .await
        .unwrap();
    let files = reader.list_files().await.unwrap();
    let paths: Vec<String> = files
        .iter()
        .map(|f| f.path.to_string_lossy().to_string())
        .collect();

    println!("Archived paths (mixed): {:?}", paths);

    assert!(paths.iter().any(|p| p.contains("data.txt")));
    assert!(
        paths.iter().any(|p| p.contains("other_backup.era")),
        "Unrelated .era files must still be archived! Paths: {:?}",
        paths
    );
    assert!(
        !paths.iter().any(|p| p.contains("my_output.era")),
        "Our own output must NOT be archived! Paths: {:?}",
        paths
    );
}
