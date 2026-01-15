//! In-memory storage backend for testing.

use bytes::Bytes;
use era_common::{EraError, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{StorageBackend, StorageMetadata, StorageReader, StorageWriter};

/// Shared storage state
type StorageState = Arc<RwLock<HashMap<PathBuf, Vec<u8>>>>;

/// In-memory storage backend for testing
#[derive(Debug, Clone)]
pub struct MemoryStorageBackend {
    storage: StorageState,
}

impl Default for MemoryStorageBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorageBackend {
    /// Create a new in-memory storage backend
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get all stored data (for testing)
    pub fn get_data(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        Ok(self.storage.read().get(path).cloned())
    }

    /// List all stored paths (for testing)
    pub fn list_paths(&self) -> Result<Vec<PathBuf>> {
        Ok(self.storage.read().keys().cloned().collect())
    }
}

impl StorageBackend for MemoryStorageBackend {
    type Writer = MemoryStorageWriter;
    type Reader = MemoryStorageReader;

    fn create(&self, path: &Path) -> Result<Self::Writer> {
        // Initialize with empty data
        self.storage.write().insert(path.to_path_buf(), Vec::new());

        Ok(MemoryStorageWriter {
            storage: self.storage.clone(),
            path: path.to_path_buf(),
            buffer: Vec::new(),
        })
    }

    fn open_append(&self, path: &Path) -> Result<Self::Writer> {
        let buffer = self.storage.read().get(path).cloned().unwrap_or_default();

        Ok(MemoryStorageWriter {
            storage: self.storage.clone(),
            path: path.to_path_buf(),
            buffer,
        })
    }

    fn open_read(&self, path: &Path) -> Result<Self::Reader> {
        let data =
            self.storage
                .read()
                .get(path)
                .cloned()
                .ok_or_else(|| EraError::FileNotFound {
                    path: path.to_path_buf(),
                })?;

        Ok(MemoryStorageReader {
            data: Bytes::from(data),
        })
    }

    fn exists(&self, path: &Path) -> bool {
        self.storage.read().contains_key(path)
    }

    fn delete(&self, path: &Path) -> Result<()> {
        self.storage
            .write()
            .remove(path)
            .ok_or_else(|| EraError::FileNotFound {
                path: path.to_path_buf(),
            })?;
        Ok(())
    }

    fn stat(&self, path: &Path) -> Result<StorageMetadata> {
        let data =
            self.storage
                .read()
                .get(path)
                .cloned()
                .ok_or_else(|| EraError::FileNotFound {
                    path: path.to_path_buf(),
                })?;

        Ok(StorageMetadata {
            size: data.len() as u64,
            created: None,
            modified: None,
        })
    }
}

/// In-memory storage writer
pub struct MemoryStorageWriter {
    storage: StorageState,
    path: PathBuf,
    buffer: Vec<u8>,
}

impl StorageWriter for MemoryStorageWriter {
    fn append(&mut self, data: &[u8]) -> Result<u64> {
        let offset = self.buffer.len() as u64;
        self.buffer.extend_from_slice(data);
        // Immediately sync to shared storage
        self.storage
            .write()
            .insert(self.path.clone(), self.buffer.clone());
        Ok(offset)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let start = offset as usize;
        let end = start + data.len();

        if start > self.buffer.len() {
            self.buffer.resize(start, 0);
        }

        if end > self.buffer.len() {
            self.buffer.resize(end, 0);
        }

        self.buffer[start..end].copy_from_slice(data);

        // Sync to shared storage
        self.storage
            .write()
            .insert(self.path.clone(), self.buffer.clone());
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        // Already synced on each write
        Ok(())
    }

    fn current_size(&self) -> u64 {
        self.buffer.len() as u64
    }

    fn close(self) -> Result<()> {
        // Final sync
        self.storage.write().insert(self.path.clone(), self.buffer);
        Ok(())
    }
}

/// In-memory storage reader
pub struct MemoryStorageReader {
    data: Bytes,
}

impl StorageReader for MemoryStorageReader {
    fn read_at(&self, offset: u64, len: usize) -> Result<Bytes> {
        let start = offset as usize;
        let end = std::cmp::min(start + len, self.data.len());

        if start >= self.data.len() {
            return Ok(Bytes::new());
        }

        Ok(self.data.slice(start..end))
    }

    fn read_all_from(&self, offset: u64) -> Result<Bytes> {
        let start = offset as usize;
        if start >= self.data.len() {
            return Ok(Bytes::new());
        }
        Ok(self.data.slice(start..))
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_backend_create_and_read() {
        let backend = MemoryStorageBackend::new();
        let path = Path::new("test.dat");

        // Create and write
        let mut writer = backend.create(path).unwrap();
        writer.append(b"Hello, ").unwrap();
        writer.append(b"World!").unwrap();
        assert_eq!(writer.current_size(), 13);
        writer.close().unwrap();

        // Read back
        let reader = backend.open_read(path).unwrap();
        assert_eq!(reader.size(), 13);

        let data = reader.read_at(0, 7).unwrap();
        assert_eq!(&data[..], b"Hello, ");

        let data = reader.read_at(7, 6).unwrap();
        assert_eq!(&data[..], b"World!");

        let all = reader.read_all_from(0).unwrap();
        assert_eq!(&all[..], b"Hello, World!");
    }

    #[test]
    fn test_memory_backend_exists_and_delete() {
        let backend = MemoryStorageBackend::new();
        let path = Path::new("test.dat");

        assert!(!backend.exists(path));

        let writer = backend.create(path).unwrap();
        writer.close().unwrap();

        assert!(backend.exists(path));

        backend.delete(path).unwrap();
        assert!(!backend.exists(path));
    }

    #[test]
    fn test_memory_backend_open_append() {
        let backend = MemoryStorageBackend::new();
        let path = Path::new("test.dat");

        // Create initial content
        let mut writer = backend.create(path).unwrap();
        writer.append(b"First").unwrap();
        writer.close().unwrap();

        // Append more
        let mut writer = backend.open_append(path).unwrap();
        assert_eq!(writer.current_size(), 5);
        writer.append(b"Second").unwrap();
        writer.close().unwrap();

        // Verify
        let reader = backend.open_read(path).unwrap();
        let all = reader.read_all_from(0).unwrap();
        assert_eq!(&all[..], b"FirstSecond");
    }

    #[test]
    fn test_memory_backend_stat() {
        let backend = MemoryStorageBackend::new();
        let path = Path::new("test.dat");

        let mut writer = backend.create(path).unwrap();
        writer.append(b"12345").unwrap();
        writer.close().unwrap();

        let stat = backend.stat(path).unwrap();
        assert_eq!(stat.size, 5);
    }

    #[test]
    fn test_memory_backend_file_not_found() {
        let backend = MemoryStorageBackend::new();
        let path = Path::new("nonexistent.dat");

        let result = backend.open_read(path);
        assert!(result.is_err());
    }
}
