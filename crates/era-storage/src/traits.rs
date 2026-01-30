//! Storage backend traits (async-only).

use async_trait::async_trait;
use bytes::Bytes;
use era_common::Result;
use std::path::Path;

/// Metadata about a storage object
#[derive(Debug, Clone)]
pub struct StorageMetadata {
    /// Size in bytes
    pub size: u64,
    /// Creation time (Unix timestamp)
    pub created: Option<u64>,
    /// Modification time (Unix timestamp)
    pub modified: Option<u64>,
}

/// Writer for storage objects (async, non-blocking I/O)
#[async_trait]
pub trait StorageWriter: Send {
    /// Append data to the end of the storage object
    /// Returns the offset where the data was written
    async fn append(&mut self, data: &[u8]) -> Result<u64>;

    /// Write data at a specific offset
    async fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;

    /// Force data to be written to persistent storage (sync_all)
    async fn sync(&mut self) -> Result<()>;

    /// Force data to be written to persistent storage without metadata (fdatasync)
    /// More efficient than sync() when metadata changes are not critical.
    /// Default implementation falls back to sync().
    async fn sync_data(&mut self) -> Result<()> {
        self.sync().await
    }

    /// Get the current size of the storage object
    fn current_size(&self) -> u64;

    /// Truncate storage to a specific size
    async fn truncate(&mut self, size: u64) -> Result<()>;

    /// Close the writer
    async fn close(self) -> Result<()>;
}

/// Reader for storage objects (async, non-blocking I/O)
#[async_trait]
pub trait StorageReader: Send {
    /// Read data at the specified offset
    async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes>;

    /// Read all remaining data from the specified offset
    async fn read_all_from(&self, offset: u64) -> Result<Bytes>;

    /// Get the total size of the storage object
    fn size(&self) -> u64;
}

/// Storage backend abstraction (async, non-blocking I/O)
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// The writer type for this backend
    type Writer: StorageWriter;
    /// The reader type for this backend
    type Reader: StorageReader;

    /// Create a new storage object
    async fn create(&self, path: &Path) -> Result<Self::Writer>;

    /// Open an existing storage object for appending
    async fn open_append(&self, path: &Path) -> Result<Self::Writer>;

    /// Open a storage object for reading
    async fn open_read(&self, path: &Path) -> Result<Self::Reader>;

    /// Check if a storage object exists
    async fn exists(&self, path: &Path) -> bool;

    /// Delete a storage object
    async fn delete(&self, path: &Path) -> Result<()>;

    /// Get metadata for a storage object
    async fn stat(&self, path: &Path) -> Result<StorageMetadata>;
}
