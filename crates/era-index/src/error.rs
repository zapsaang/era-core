//! Index error types.

use thiserror::Error;

/// Errors that can occur during index operations
#[derive(Error, Debug)]
pub enum IndexError {
    /// RocksDB error
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Index not found
    #[error("Index not found at path: {0}")]
    NotFound(String),

    /// Index already exists
    #[error("Index already exists at path: {0}")]
    AlreadyExists(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Index is read-only
    #[error("Index is open in read-only mode")]
    ReadOnly,

    /// Corruption detected
    #[error("Index corruption detected: {0}")]
    Corruption(String),
}

impl From<IndexError> for era_common::EraError {
    fn from(err: IndexError) -> Self {
        era_common::EraError::IndexError(err.to_string())
    }
}
