//! Configuration types for ERA archive system.

use serde::{Deserialize, Serialize};

/// Main archive configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Compression configuration
    pub compression: CompressionConfig,
    /// Encryption configuration  
    pub encryption: EncryptionConfig,
    /// Volume configuration
    pub volume: VolumeConfig,
    /// Block configuration
    pub block: BlockConfig,
}

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// Zstandard compression (default)
    #[default]
    Zstd,
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Algorithm to use
    pub algorithm: CompressionAlgorithm,
    /// Compression level (1-22 for Zstd)
    pub level: i32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Zstd,
            level: 3, // Good balance of speed and ratio
        }
    }
}

/// Encryption algorithm selection
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// No encryption
    None,
    /// XChaCha20-Poly1305 AEAD (default)
    #[default]
    XChaCha20Poly1305,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Algorithm to use
    pub algorithm: EncryptionAlgorithm,
    /// Key derivation memory cost (KB) for Argon2id
    pub kdf_memory_cost: u32,
    /// Key derivation time cost (iterations) for Argon2id
    pub kdf_time_cost: u32,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::XChaCha20Poly1305,
            kdf_memory_cost: 65536, // 64 MB
            kdf_time_cost: 3,
        }
    }
}

/// Volume configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeConfig {
    /// Maximum volume size in bytes (default: 1GB)
    pub max_size: u64,
    /// Enable random padding for side-channel protection
    pub enable_padding: bool,
    /// Volume naming template
    pub naming_template: String,
}

impl Default for VolumeConfig {
    fn default() -> Self {
        Self {
            max_size: 1024 * 1024 * 1024, // 1GB
            enable_padding: true,
            naming_template: "{archive_id}.vol{seq:03}.era".to_string(),
        }
    }
}

/// Block configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockConfig {
    /// Target block size in bytes (default: 4MB)
    pub target_size: usize,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            target_size: 4 * 1024 * 1024, // 4MB
        }
    }
}
