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

        let file = File::create(&full_path).await.map_err(EraError::Io)?;

        Ok(LocalStorageWriter { file, size: 0 })
    }

    async fn open_append(&self, path: &Path) -> Result<Self::Writer> {
        let full_path = self.resolve_path(path);

        let file = OpenOptions::new()
            .write(true)
            .append(true)
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
