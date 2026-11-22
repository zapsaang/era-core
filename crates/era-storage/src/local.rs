//! Local filesystem storage backend (async).
//!
//! Provides non-blocking I/O operations using tokio::fs.

use async_trait::async_trait;
use bytes::Bytes;
use era_common::{EraError, Result};
use std::path::{Path, PathBuf};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::traits::{StorageBackend, StorageMetadata, StorageReader, StorageWriter};

/// O_NOFOLLOW for unix targets whose value is known here.
///
/// The local backend creates volume files in directories that may be writable by
/// other users (shared directories, removable media, restored backups). A symlink
/// planted at a volume path must not redirect the truncating open to an arbitrary
/// file, so create() refuses to follow a symlink final component.
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
const O_NOFOLLOW: i32 = 0x0100;

/// Build the open options used by StorageBackend::create.
///
/// create() keeps its historical truncate-and-overwrite semantics for regular
/// files (volume rotation and crash-retry rely on it) but never follows a symlink
/// final component on platforms where O_NOFOLLOW is known.
fn create_open_options() -> OpenOptions {
    // custom_flags below is unix-only, so mut is unused on other targets.
    #[allow(unused_mut)]
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(any(
        all(unix, any(target_os = "linux", target_os = "android")),
        all(
            unix,
            any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            )
        )
    ))]
    options.custom_flags(O_NOFOLLOW);
    options
}

/// Directory whose entry must be made durable after creating `path`.
///
/// `Path::parent` is not a usable answer on its own: a bare relative file name
/// such as `backup.era` has `Some("")` as its parent, and `File::open("")` fails
/// with ENOENT, which silently disabled the directory fsync for the most common
/// CLI invocation (`era create -o backup.era ...`). The parent of a bare name is
/// the current directory, and a path without any parent (e.g. `/`) is handled
/// through the same fallback so the helper never returns an unopenable path.
#[cfg(unix)]
fn parent_directory_for_fsync(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Best-effort fsync of the directory that holds a newly created storage object.
///
/// A power loss right after create() would otherwise be allowed to drop the new
/// directory entry even though create() returned success. Failure is logged, not
/// propagated: some platforms and filesystems reject directory fsync, and this is
/// a hardening measure on top of the writer's explicit sync()/close().
#[cfg(unix)]
async fn sync_parent_directory(path: &Path) {
    let parent = parent_directory_for_fsync(path);
    match File::open(parent).await {
        Ok(directory) => {
            if let Err(error) = directory.sync_all().await {
                tracing::warn!(
                    parent = %parent.display(),
                    %error,
                    "failed to fsync storage parent directory after create (best-effort)"
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                parent = %parent.display(),
                %error,
                "failed to open storage parent directory for fsync (best-effort)"
            );
        }
    }
}

/// Directory fsync has no portable non-unix equivalent; do not warn about it.
#[cfg(not(unix))]
async fn sync_parent_directory(_path: &Path) {}

/// Local filesystem storage backend
#[derive(Debug, Clone)]
pub struct LocalStorageBackend {
    /// Base directory for storage
    base_path: PathBuf,
}

impl LocalStorageBackend {
    /// Create a new local storage backend
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    /// Resolve a path relative to the base directory
    fn resolve_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_path.join(path)
        }
    }
}

#[async_trait]
impl StorageBackend for LocalStorageBackend {
    type Writer = LocalStorageWriter;
    type Reader = LocalStorageReader;

    async fn create(&self, path: &Path) -> Result<Self::Writer> {
        let full_path = self.resolve_path(path);

        // Create parent directories if needed
        if let Some(parent) = full_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(EraError::Io)?;
        }

        // Reject an explicit symlink with a typed error; O_NOFOLLOW in
        // create_open_options() is the race-free guard for the check-then-open gap.
        let is_symlink = tokio::fs::symlink_metadata(&full_path)
            .await
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
        if is_symlink {
            return Err(EraError::PermissionDenied { path: full_path });
        }

        let options = create_open_options();
        let file = options.open(&full_path).await.map_err(EraError::Io)?;

        // Make the new directory entry durable before callers treat the volume as
        // created; failures are logged inside the helper (best-effort).
        sync_parent_directory(&full_path).await;

        Ok(LocalStorageWriter { file, size: 0 })
    }

    async fn open_append(&self, path: &Path) -> Result<Self::Writer> {
        let full_path = self.resolve_path(path);

        // O_APPEND would override write_at's seek; append already seeks to the tracked end.
        let file = OpenOptions::new()
            .write(true)
            .open(&full_path)
            .await
            .map_err(EraError::Io)?;

        let metadata = file.metadata().await.map_err(EraError::Io)?;
        let size = metadata.len();

        Ok(LocalStorageWriter { file, size })
    }

    async fn open_read(&self, path: &Path) -> Result<Self::Reader> {
        let full_path = self.resolve_path(path);

        let file = File::open(&full_path).await.map_err(EraError::Io)?;
        let metadata = file.metadata().await.map_err(EraError::Io)?;
        let size = metadata.len();

        Ok(LocalStorageReader { file, size })
    }

    async fn exists(&self, path: &Path) -> bool {
        let full_path = self.resolve_path(path);
        tokio::fs::try_exists(&full_path).await.unwrap_or(false)
    }

    async fn delete(&self, path: &Path) -> Result<()> {
        let full_path = self.resolve_path(path);
        tokio::fs::remove_file(&full_path)
            .await
            .map_err(EraError::Io)
    }

    async fn stat(&self, path: &Path) -> Result<StorageMetadata> {
        let full_path = self.resolve_path(path);
        let metadata = tokio::fs::metadata(&full_path)
            .await
            .map_err(EraError::Io)?;

        Ok(StorageMetadata {
            size: metadata.len(),
            created: metadata
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
            modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
        })
    }
}

/// Writer for local filesystem storage
pub struct LocalStorageWriter {
    file: File,
    size: u64,
}

#[async_trait]
impl StorageWriter for LocalStorageWriter {
    async fn append(&mut self, data: &[u8]) -> Result<u64> {
        let offset = self.size;
        // Seek to end before writing to ensure correctness after write_at
        self.file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(EraError::Io)?;
        self.file.write_all(data).await.map_err(EraError::Io)?;
        self.size += data.len() as u64;
        Ok(offset)
    }

    async fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(EraError::Io)?;
        self.file.write_all(data).await.map_err(EraError::Io)?;

        // Update size if we wrote past the end
        let new_pos = offset + data.len() as u64;
        if new_pos > self.size {
            self.size = new_pos;
        }

        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        self.file.sync_all().await.map_err(EraError::Io)
    }

    fn current_size(&self) -> u64 {
        self.size
    }

    async fn truncate(&mut self, size: u64) -> Result<()> {
        self.file.set_len(size).await.map_err(EraError::Io)?;
        self.size = size;
        Ok(())
    }

    async fn close(mut self) -> Result<()> {
        self.file.sync_all().await.map_err(EraError::Io)?;
        // File is automatically closed when dropped
        Ok(())
    }
}

/// Reader for local filesystem storage
pub struct LocalStorageReader {
    file: File,
    size: u64,
}

#[async_trait]
impl StorageReader for LocalStorageReader {
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        // Clone the file handle for thread-safe reading
        let mut file = self.file.try_clone().await.map_err(EraError::Io)?;

        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(EraError::Io)?;

        let mut buffer = vec![0u8; len];
        file.read_exact(&mut buffer).await.map_err(EraError::Io)?;

        Ok(Bytes::from(buffer))
    }

    async fn read_all_from(&self, offset: u64) -> Result<Bytes> {
        // At or past EOF there is nothing left to read; return an empty buffer
        // instead of underflowing size - offset (debug panic / release capacity
        // overflow in the old code).
        if offset >= self.size {
            return Ok(Bytes::new());
        }
        let len = (self.size - offset) as usize;
        self.read_at(offset, len).await
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_local_storage_create_and_write() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = backend.create(Path::new("test.dat")).await.unwrap();

        let data = b"Hello, async world!";
        let offset = writer.append(data).await.unwrap();

        assert_eq!(offset, 0);
        assert_eq!(writer.current_size(), data.len() as u64);

        writer.sync().await.unwrap();
        writer.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_local_storage_read() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write data
        let mut writer = backend.create(Path::new("test.dat")).await.unwrap();
        let data = b"Hello, async world!";
        writer.append(data).await.unwrap();
        writer.close().await.unwrap();

        // Read data
        let reader = backend.open_read(Path::new("test.dat")).await.unwrap();
        let read_data = reader.read_all_from(0).await.unwrap();

        assert_eq!(read_data.as_ref(), data);
    }

    #[tokio::test]
    async fn test_local_storage_write_at() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = backend.create(Path::new("test.dat")).await.unwrap();

        writer.append(b"0000000000").await.unwrap();
        writer.write_at(5, b"HELLO").await.unwrap();
        writer.close().await.unwrap();

        let reader = backend.open_read(Path::new("test.dat")).await.unwrap();
        let data = reader.read_all_from(0).await.unwrap();

        assert_eq!(data.as_ref(), b"00000HELLO");
    }

    #[tokio::test]
    async fn test_local_storage_open_append_write_at_then_append() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());
        let path = Path::new("test.dat");

        let mut writer = backend.create(path).await.unwrap();
        writer.append(b"0123456789").await.unwrap();
        writer.close().await.unwrap();

        let mut writer = backend.open_append(path).await.unwrap();
        writer.write_at(2, b"abc").await.unwrap();
        let offset = writer.append(b"XYZ").await.unwrap();
        assert_eq!(offset, 10);
        assert_eq!(writer.current_size(), 13);
        writer.close().await.unwrap();

        let reader = backend.open_read(path).await.unwrap();
        assert_eq!(reader.size(), 13);
        assert_eq!(
            reader.read_all_from(0).await.unwrap().as_ref(),
            b"01abc56789XYZ"
        );
    }

    #[tokio::test]
    async fn test_local_storage_truncate() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = backend.create(Path::new("test.dat")).await.unwrap();
        writer.append(b"0123456789").await.unwrap();
        writer.truncate(5).await.unwrap();
        writer.close().await.unwrap();

        let reader = backend.open_read(Path::new("test.dat")).await.unwrap();
        assert_eq!(reader.size(), 5);
    }

    #[tokio::test]
    async fn test_local_storage_exists() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        assert!(!backend.exists(Path::new("nonexistent.dat")).await);

        let writer = backend.create(Path::new("test.dat")).await.unwrap();
        writer.close().await.unwrap();

        assert!(backend.exists(Path::new("test.dat")).await);
    }

    #[cfg(unix)]
    #[test]
    fn parent_directory_for_fsync_normalizes_empty_and_missing_parents() {
        // R2-STOR-01: the parent of a bare relative file name is the current
        // directory, not the empty path (File::open("") is ENOENT).
        assert_eq!(
            parent_directory_for_fsync(Path::new("backup.era")),
            Path::new(".")
        );
        assert_eq!(
            parent_directory_for_fsync(Path::new("./backup.era")),
            Path::new(".")
        );
        assert_eq!(
            parent_directory_for_fsync(Path::new("out/backup.era")),
            Path::new("out")
        );
        assert_eq!(
            parent_directory_for_fsync(Path::new("/tmp/backup.era")),
            Path::new("/tmp")
        );
        // A path with no parent at all still maps to an openable directory.
        assert_eq!(parent_directory_for_fsync(Path::new("/")), Path::new("."));
    }

    #[tokio::test]
    async fn test_local_storage_delete() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let writer = backend.create(Path::new("test.dat")).await.unwrap();
        writer.close().await.unwrap();

        assert!(backend.exists(Path::new("test.dat")).await);

        backend.delete(Path::new("test.dat")).await.unwrap();

        assert!(!backend.exists(Path::new("test.dat")).await);
    }
}
