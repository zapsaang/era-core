//! Error types for ERA archive system.

use std::path::PathBuf;

use thiserror::Error;

/// Result type for ERA operations
pub type Result<T> = std::result::Result<T, EraError>;

/// Main error type for ERA archive system
#[derive(Error, Debug)]
pub enum EraError {
    // I/O Errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File not found: {path}")]
    FileNotFound { path: PathBuf },

    #[error("Permission denied: {path}")]
    PermissionDenied { path: PathBuf },

    // Serialization Errors
    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    // Crypto Errors
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    // Compression Errors
    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    // Erasure Coding Errors
    #[error("Erasure coding error: {0}")]
    ErasureError(String),

    // Checkpoint Errors
    #[error("Checkpoint error: {0}")]
    CheckpointError(String),

    // Data Integrity Errors
    #[error("Integrity error: {0}")]
    IntegrityError(String),

    // Archive Format Errors
    #[error("Invalid magic number")]
    InvalidMagic,

    #[error("Empty archive")]
    EmptyArchive,

    #[error("Empty catalog block")]
    EmptyCatalog,

    #[error("Unsupported version: {version}")]
    UnsupportedVersion { version: u32 },

    #[error("Corrupted header: {0}")]
    CorruptedHeader(String),

    #[error("Corrupted footer: {0}")]
    CorruptedFooter(String),

    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    // Volume Errors
    #[error("Volume full: {volume_id}")]
    VolumeFull { volume_id: String },

    #[error("Volume not found: {volume_id}")]
    VolumeNotFound { volume_id: String },

    // Block Errors
    #[error("Block not found: {block_id}")]
    BlockNotFound { block_id: String },

    #[error("Block too large: {size} bytes (max: {max_size})")]
    BlockTooLarge { size: usize, max_size: usize },

    // Chunk Errors
    #[error("Chunk not found: {hash}")]
    ChunkNotFound { hash: String },

    // Configuration Errors
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    // Concurrency Errors
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    // Generic Errors
    #[error("{0}")]
    Other(String),
}

impl EraError {
    /// Create a new serialization error
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::Serialization(msg.into())
    }

    /// Create a new deserialization error
    pub fn deserialization(msg: impl Into<String>) -> Self {
        Self::Deserialization(msg.into())
    }

    /// Create a new encryption error
    pub fn encryption(msg: impl Into<String>) -> Self {
        Self::Encryption(msg.into())
    }

    /// Create a new decryption error
    pub fn decryption(msg: impl Into<String>) -> Self {
        Self::Decryption(msg.into())
    }

    /// Create a new compression error
    pub fn compression(msg: impl Into<String>) -> Self {
        Self::Compression(msg.into())
    }

    /// Create a new decompression error
    pub fn decompression(msg: impl Into<String>) -> Self {
        Self::Decompression(msg.into())
    }

    /// Create a new other error
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

impl From<bincode::error::EncodeError> for EraError {
    fn from(err: bincode::error::EncodeError) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<bincode::error::DecodeError> for EraError {
    fn from(err: bincode::error::DecodeError) -> Self {
        Self::Deserialization(err.to_string())
    }
}
