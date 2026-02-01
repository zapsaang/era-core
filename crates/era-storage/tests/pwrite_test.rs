use era_storage::{LocalStorageBackend, StorageBackend, StorageReader, StorageWriter};
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Barrier;

/// This test is fundamentally flawed: it opens files with `open_append()` which sets O_APPEND,
/// then attempts to use `write_at()` for positional writes. On POSIX systems, O_APPEND forces
/// ALL writes (including pwrite) to occur at EOF, making positional writes impossible.
///
/// The test assumption that `write_at` can work on append-mode handles is incorrect.
/// Proper concurrent positional writes require opening without O_APPEND (e.g., O_RDWR).
///
/// Ignored until a non-append `open_readwrite()` API is added to StorageBackend trait.
#[tokio::test]
#[ignore = "Invalid test: pwrite with O_APPEND is undefined behavior. Requires non-append open mode."]
async fn test_storage_pwrite_concurrency() {
    let temp_dir = TempDir::new().unwrap();
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("concurrent_write.test");

    // Initialize file
    {
        let mut writer = backend.create(path).await.unwrap();
        writer.append(&vec![0u8; 4096]).await.unwrap(); // 4KB file
        writer.close().await.unwrap();
    }

    // Spawn tasks to write to different regions of the file using separate writers
    // This simulates multi-task writes to the same file (which usually requires separate FDs or locked FD)
    // LocalStorageBackend::open_append opens a new File handle each time.
    // On Unix, pread/pwrite on shared FD or separate FD pointing to same inode are atomic at syscall level regarding position.

    let barrier = Arc::new(Barrier::new(4));
    let mut handles = vec![];

    for i in 0..4 {
        let b_clone = backend.clone();
        let path_buf = path.to_path_buf();
        let bar = barrier.clone();

        handles.push(tokio::spawn(async move {
            let mut writer = b_clone.open_append(&path_buf).await.unwrap();

            // Wait for all to open
            bar.wait().await;

            // Write to a specific quadrant: i * 1024
            let offset = (i * 1024) as u64;
            let data = vec![i as u8 + 1; 1024]; // Fill with 1, 2, 3, 4

            // Use write_at
            writer.write_at(offset, &data).await.unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Verify content
    let reader = backend.open_read(path).await.unwrap();
    let content = reader.read_at(0, 4096).await.unwrap();

    for i in 0..4 {
        let start = i * 1024;
        let expected_val = (i as u8) + 1;
        for j in 0..1024 {
            assert_eq!(
                content[start + j],
                expected_val,
                "Mismatch at quadrant {}",
                i
            );
        }
    }
}
