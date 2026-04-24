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

    // Index Errors
    #[error("Index error: {0}")]
    IndexError(String),

    #[error("Index not found: {0}")]
    IndexNotFound(String),

    #[error("Index corruption: {0}")]
    IndexCorruption(String),

    // Concurrency Errors
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("Channel closed: {0}")]
    ChannelClosed(String),

    // Async operation error
    #[error("Async operation error: {0}")]
    AsyncError(String),

    // Post-Quantum Cryptography error
    #[error("PQC operation error: {0}")]
    PostQuantumError(String),

    // Write-Ahead Log error
    #[error("WAL error: {0}")]
    WalError(String),

    // Security Errors
    #[error("Security violation: {0}")]
    Security(String),

    #[error("Threshold not met: need {required} shares, got {provided}")]
    ThresholdNotMet { required: u32, provided: u32 },

    // v8.2 Errors
    #[error("Read beyond commit horizon: offset={offset}, horizon={horizon}")]
    BeyondCommitHorizon { offset: u64, horizon: u64 },

    #[error("Catalog commitment mismatch: computed commitment does not match manifest")]
    CatalogCommitmentMismatch,

    #[error("Index commitment mismatch: computed commitment does not match manifest")]
    IndexCommitmentMismatch,

    #[error(
        "Volume {volume} space exhausted: required={required}, available={available}: {message}"
    )]
    VolumeSpaceExhausted {
        volume: usize,
        required: u64,
        available: u64,
        message: String,
    },

    #[error("Manifest load error: {0}")]
    ManifestLoadError(String),

    #[error("Footer inconsistency: field={field}, expected={expected}, actual={actual}")]
    FooterInconsistency {
        field: String,
        expected: String,
        actual: String,
    },

    #[error("All {kind} copies corrupted across {volume_count} volumes")]
    AllTypedBlockCopiesCorrupted {
        kind: String,
        volume_count: usize,
        warnings: Vec<String>,
    },

    #[error("Typed block not found: {0}")]
    TypedBlockNotFound(String),

    #[error("Repair verification failed for {kind} on volume {volume_idx}: expected_crc={expected_crc}, actual_crc={actual_crc}")]
    RepairVerificationFailed {
        kind: String,
        volume_idx: usize,
        expected_crc: u32,
        actual_crc: u32,
    },

    #[error("Unsupported archive format: {0}")]
    UnsupportedFormat(String),

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

    /// Create a new async error
    pub fn async_error(msg: impl Into<String>) -> Self {
        Self::AsyncError(msg.into())
    }

    /// Create a new PQC error
    pub fn pqc_error(msg: impl Into<String>) -> Self {
        Self::PostQuantumError(msg.into())
    }

    /// Create a new WAL error
    pub fn wal_error(msg: impl Into<String>) -> Self {
        Self::WalError(msg.into())
    }

    /// Create a new security violation error
    pub fn security(msg: impl Into<String>) -> Self {
        Self::Security(msg.into())
    }

    pub fn beyond_commit_horizon(offset: u64, horizon: u64) -> Self {
        Self::BeyondCommitHorizon { offset, horizon }
    }

    pub fn catalog_commitment_mismatch() -> Self {
        Self::CatalogCommitmentMismatch
    }

    pub fn index_commitment_mismatch() -> Self {
        Self::IndexCommitmentMismatch
    }

    pub fn volume_space_exhausted(
        volume: usize,
        required: u64,
        available: u64,
        message: impl Into<String>,
    ) -> Self {
        Self::VolumeSpaceExhausted {
            volume,
            required,
            available,
            message: message.into(),
        }
    }

    pub fn manifest_load_error(msg: impl Into<String>) -> Self {
        Self::ManifestLoadError(msg.into())
    }

    pub fn footer_inconsistency(
        field: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::FooterInconsistency {
            field: field.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    pub fn all_typed_block_copies_corrupted(
        kind: impl Into<String>,
        volume_count: usize,
        warnings: Vec<String>,
    ) -> Self {
        Self::AllTypedBlockCopiesCorrupted {
            kind: kind.into(),
            volume_count,
            warnings,
        }
    }

    pub fn typed_block_not_found(msg: impl Into<String>) -> Self {
        Self::TypedBlockNotFound(msg.into())
    }

    pub fn repair_verification_failed(
        kind: impl Into<String>,
        volume_idx: usize,
        expected_crc: u32,
        actual_crc: u32,
    ) -> Self {
        Self::RepairVerificationFailed {
            kind: kind.into(),
            volume_idx,
            expected_crc,
            actual_crc,
        }
    }

    pub fn unsupported_format(msg: impl Into<String>) -> Self {
        Self::UnsupportedFormat(msg.into())
    }
}
