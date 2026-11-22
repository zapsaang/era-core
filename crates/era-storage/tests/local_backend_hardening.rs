//! Regression tests for LL-06 (symlink-safe local `create`) and LL-07
//! (`read_all_from` past EOF must not underflow).
//!
//! LL-06: `LocalStorageBackend::create` used a truncating `File::create`, which
//! follows symlinks. A symlink planted in the storage directory would redirect
//! the truncating open to an arbitrary file. The backend must refuse symlink
//! final components while keeping the historical overwrite-of-regular-file
//! semantics (volume rotation and crash-retry rely on it).
//!
//! LL-07: `read_all_from(offset)` with `offset > size` underflowed `size - offset`;
//! in release builds it then attempted a huge allocation. It must return an
//! empty buffer instead.

use era_storage::{LocalStorageBackend, StorageBackend, StorageReader, StorageWriter};
use std::path::Path;
use tempfile::TempDir;

#[cfg(unix)]
#[tokio::test]
async fn create_refuses_symlink_target() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("temp dir");
    let backend = LocalStorageBackend::new(temp_dir.path());
    let victim = temp_dir.path().join("victim.txt");
    std::fs::write(&victim, b"do not truncate me").expect("write victim");
    let link = temp_dir.path().join("archive.era");
    symlink(&victim, &link).expect("create symlink");

    let result = backend.create(Path::new("archive.era")).await;
    assert!(
        result.is_err(),
        "create must refuse to follow a symlink, but it succeeded"
    );
    assert_eq!(
        std::fs::read(&victim).expect("read victim"),
        b"do not truncate me",
        "create must not truncate the symlink target"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn create_refuses_dangling_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("temp dir");
    let backend = LocalStorageBackend::new(temp_dir.path());
    let missing_target = temp_dir.path().join("outside-target.bin");
    let link = temp_dir.path().join("archive.era");
    symlink(&missing_target, &link).expect("create symlink");

    let result = backend.create(Path::new("archive.era")).await;
    assert!(
        result.is_err(),
        "create must refuse to follow a dangling symlink, but it succeeded"
    );
    assert!(
        !missing_target.exists(),
        "create must not materialise the symlink target"
    );
}

#[tokio::test]
async fn create_still_truncates_existing_regular_file() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("volume.era");

    let mut writer = backend.create(path).await.expect("first create");
    writer.append(b"stale volume bytes").await.expect("append");
    writer.close().await.expect("close");

    let mut writer = backend.create(path).await.expect("overwrite create");
    assert_eq!(
        writer.current_size(),
        0,
        "create must truncate regular files"
    );
    writer.append(b"fresh").await.expect("append fresh");
    writer.close().await.expect("close");

    let reader = backend.open_read(path).await.expect("open read");
    assert_eq!(reader.size(), 5);
    assert_eq!(
        reader.read_all_from(0).await.expect("read").as_ref(),
        b"fresh"
    );
}

#[tokio::test]
async fn read_all_from_past_end_returns_empty() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("small.dat");

    let mut writer = backend.create(path).await.expect("create");
    writer.append(b"12345").await.expect("append");
    writer.close().await.expect("close");

    let reader = backend.open_read(path).await.expect("open read");
    assert_eq!(reader.size(), 5);
    let bytes = reader
        .read_all_from(reader.size() + 1)
        .await
        .expect("read_all_from past EOF must not underflow");
    assert!(
        bytes.is_empty(),
        "read_all_from past EOF must return an empty buffer, got {} bytes",
        bytes.len()
    );
}

#[tokio::test]
async fn read_all_from_at_end_returns_empty() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend = LocalStorageBackend::new(temp_dir.path());
    let path = Path::new("small.dat");

    let mut writer = backend.create(path).await.expect("create");
    writer.append(b"12345").await.expect("append");
    writer.close().await.expect("close");

    let reader = backend.open_read(path).await.expect("open read");
    let bytes = reader
        .read_all_from(reader.size())
        .await
        .expect("read_all_from at EOF must succeed");
    assert!(bytes.is_empty());
}
