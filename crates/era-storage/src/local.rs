//! Local filesystem storage backend.

use bytes::Bytes;
use era_common::{EraError, Result};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{StorageBackend, StorageMetadata, StorageReader, StorageWriter};

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

    /// Get the full path for a storage object
    fn full_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_path.join(path)
        }
    }
}

impl StorageBackend for LocalStorageBackend {
    type Writer = LocalStorageWriter;
    type Reader = LocalStorageReader;

    fn create(&self, path: &Path) -> Result<Self::Writer> {
        let full_path = self.full_path(path);

        // Ensure parent directory exists
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&full_path)?;

        Ok(LocalStorageWriter { file, size: 0 })
    }

    fn open_append(&self, path: &Path) -> Result<Self::Writer> {
        let full_path = self.full_path(path);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&full_path)?;

        let size = file.seek(SeekFrom::End(0))?;

        Ok(LocalStorageWriter { file, size })
    }

    fn open_read(&self, path: &Path) -> Result<Self::Reader> {
        let full_path = self.full_path(path);

        let file = File::open(&full_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                EraError::FileNotFound {
                    path: full_path.clone(),
                }
            } else {
                EraError::Io(e)
            }
        })?;

        let size = file.metadata()?.len();

        Ok(LocalStorageReader { file, size })
    }

    fn exists(&self, path: &Path) -> bool {
        self.full_path(path).exists()
    }

    fn delete(&self, path: &Path) -> Result<()> {
        let full_path = self.full_path(path);
        std::fs::remove_file(&full_path)?;
        Ok(())
    }

    fn stat(&self, path: &Path) -> Result<StorageMetadata> {
        let full_path = self.full_path(path);
        let metadata = std::fs::metadata(&full_path)?;

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

/// Local filesystem storage writer
pub struct LocalStorageWriter {
    file: File,
    size: u64,
}

impl StorageWriter for LocalStorageWriter {
    fn append(&mut self, data: &[u8]) -> Result<u64> {
        let offset = self.size;
        self.file.write_all(data)?;
        self.size += data.len() as u64;
        Ok(offset)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        // Use pwrite (FileExt) on Unix systems for atomic-like positional writes
        // without disturbing the file pointer or requiring seek/write/seek dance.
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.write_all_at(data, offset)?;
        }

        #[cfg(not(unix))]
        {
            // Save current position
            let current_pos = self.file.stream_position()?;

            // Write at offset
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(data)?;

            // Restore position
            self.file.seek(SeekFrom::Start(current_pos))?;
        }

        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    fn sync_data(&mut self) -> Result<()> {
        // Use fdatasync (sync_data) which only syncs file data, not metadata.
        // This is more efficient when we don't need to persist metadata changes.
        self.file.sync_data()?;
        Ok(())
    }

    fn current_size(&self) -> u64 {
        self.size
    }

    fn truncate(&mut self, size: u64) -> Result<()> {
        self.file.set_len(size)?;
        self.size = size;
        Ok(())
    }

    fn close(self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

/// Local filesystem storage reader
pub struct LocalStorageReader {
    file: File,
    size: u64,
}

impl StorageReader for LocalStorageReader {
    fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        use std::os::unix::fs::FileExt;

        let mut buffer = vec![0u8; len];
        let bytes_read = self.file.read_at(&mut buffer, offset)?;
        buffer.truncate(bytes_read);

        Ok(Bytes::from(buffer))
    }

    fn read_all_from(&self, offset: u64) -> Result<Bytes> {
        let len = self.size.saturating_sub(offset) as usize;
        self.read_at(offset, len)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_write() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = backend.create(Path::new("test.era")).unwrap();
        let offset1 = writer.append(b"Hello, ").unwrap();
        let offset2 = writer.append(b"ERA!").unwrap();
        writer.close().unwrap();

        assert_eq!(offset1, 0);
        assert_eq!(offset2, 7);
        assert!(backend.exists(Path::new("test.era")));
    }

    #[test]
    fn test_read() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Write some data
        let mut writer = backend.create(Path::new("test.era")).unwrap();
        writer.append(b"Hello, ERA!").unwrap();
        writer.close().unwrap();

        // Read it back
        let reader = backend.open_read(Path::new("test.era")).unwrap();
        let data = reader.read_at(0, 11).unwrap();
        assert_eq!(data.as_ref(), b"Hello, ERA!");

        // Read partial
        let partial = reader.read_at(7, 4).unwrap();
        assert_eq!(partial.as_ref(), b"ERA!");
    }

    #[test]
    fn test_append() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        // Create and write
        let mut writer = backend.create(Path::new("test.era")).unwrap();
        writer.append(b"Hello").unwrap();
        writer.close().unwrap();

        // Append more
        let mut writer = backend.open_append(Path::new("test.era")).unwrap();
        assert_eq!(writer.current_size(), 5);
        writer.append(b", ERA!").unwrap();
        writer.close().unwrap();

        // Verify
        let reader = backend.open_read(Path::new("test.era")).unwrap();
        let data = reader.read_all_from(0).unwrap();
        assert_eq!(data.as_ref(), b"Hello, ERA!");
    }

    #[test]
    fn test_stat() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalStorageBackend::new(temp_dir.path());

        let mut writer = backend.create(Path::new("test.era")).unwrap();
        writer.append(b"Hello, ERA!").unwrap();
        writer.close().unwrap();

        let metadata = backend.stat(Path::new("test.era")).unwrap();
        assert_eq!(metadata.size, 11);
    }
}
