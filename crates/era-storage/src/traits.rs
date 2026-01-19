//! Storage backend traits.

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

/// Storage backend abstraction
pub trait StorageBackend: Send + Sync {
    /// The writer type for this backend
    type Writer: StorageWriter;
    /// The reader type for this backend
    type Reader: StorageReader;

    /// Create a new storage object
    fn create(&self, path: &Path) -> Result<Self::Writer>;

    /// Open an existing storage object for appending
    fn open_append(&self, path: &Path) -> Result<Self::Writer>;

    /// Open a storage object for reading
    fn open_read(&self, path: &Path) -> Result<Self::Reader>;

    /// Check if a storage object exists
    fn exists(&self, path: &Path) -> bool;

    /// Delete a storage object
    fn delete(&self, path: &Path) -> Result<()>;

    /// Get metadata for a storage object
    fn stat(&self, path: &Path) -> Result<StorageMetadata>;
}

/// Writer for storage objects
pub trait StorageWriter: Send {
    /// Append data to the end of the storage object
    /// Returns the offset where the data was written
    fn append(&mut self, data: &[u8]) -> Result<u64>;

    /// Write data at a specific offset
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;

    /// Force data to be written to persistent storage
    fn sync(&mut self) -> Result<()>;

    /// Get the current size of the storage object
    fn current_size(&self) -> u64;

    /// Truncate storage to a specific size
    fn truncate(&mut self, size: u64) -> Result<()>;

    /// Close the writer
    fn close(self) -> Result<()>;
}

/// Reader for storage objects
pub trait StorageReader: Send {
    /// Read data at the specified offset
    fn read_at(&self, offset: u64, len: usize) -> Result<Bytes>;

    /// Read all remaining data from the specified offset
    fn read_all_from(&self, offset: u64) -> Result<Bytes>;

    /// Get the total size of the storage object
    fn size(&self) -> u64;
}
