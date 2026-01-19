//! Configuration types for ERA archive system.

use serde::{Deserialize, Serialize};

use crate::{ErasureCodeConfig, MatrixDistributionConfig};

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
    /// Chunking configuration (CDC)
    #[serde(default)]
    pub chunking: ChunkingConfig,
    /// Packing configuration (k-Bounded Best-Fit)
    #[serde(default)]
    pub packing: PackingConfig,
    /// Erasure coding configuration (None = disabled)
    pub erasure: Option<ErasureCodeConfig>,
    /// Matrix distribution configuration
    #[serde(default)]
    pub distribution: MatrixDistributionConfig,
}

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// Zstandard compression (default, good compression ratio)
    #[default]
    Zstd,
    /// LZ4 compression (fastest, lower compression ratio but still effective)
    LZ4,
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

/// Chunking configuration for FastCDC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkingConfig {
    /// Minimum chunk size in bytes
    pub min_size: usize,
    /// Average chunk size in bytes
    pub avg_size: usize,
    /// Maximum chunk size in bytes
    pub max_size: usize,
    /// FastCDC normalization level (v2020)
    #[serde(default)]
    pub normalization_level: NormalizationLevel,
    /// Rolling hash seed for FastCDC (v2020)
    #[serde(default)]
    pub rolling_hash_seed: u64,
}

/// Normalization level for FastCDC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalizationLevel {
    Level0,
    Level1,
    Level2,
    Level3,
}

impl Default for NormalizationLevel {
    fn default() -> Self {
        NormalizationLevel::Level1
    }
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            min_size: 4 * 1024,   // 4 KB
            avg_size: 64 * 1024,  // 64 KB
            max_size: 256 * 1024, // 256 KB
            normalization_level: NormalizationLevel::default(),
            rolling_hash_seed: 0,
        }
    }
}

/// Packing configuration for k-Bounded Best-Fit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackingConfig {
    /// Number of active bins (k-factor)
    /// Higher k = better packing efficiency, higher memory usage
    pub k_factor: usize,
    /// Flush threshold percentage (0-100)
    /// When a bin reaches this fill level, it's flushed to disk
    pub flush_threshold: usize,
}

impl Default for PackingConfig {
    fn default() -> Self {
        Self {
            k_factor: 8,         // Balanced default
            flush_threshold: 95, // Flush at 95% full
        }
    }
}
