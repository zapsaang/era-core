//! Index configuration.

use std::path::PathBuf;

/// Configuration for the Redb-backed chunk index
#[derive(Debug, Clone)]
pub struct IndexConfig {
    /// Path to the index directory
    pub path: PathBuf,

    /// Memory limit for bloom filter sizing (default: 128MB)
    pub memtable_size: usize,

    /// Bloom filter bits per key (default: 10, ~1% false positive rate)
    pub bloom_filter_bits: i32,

    /// Enable compression (default: true)
    pub enable_compression: bool,

    /// Block cache size in bytes (default: 64MB)
    pub block_cache_size: usize,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(".era-index"),
            memtable_size: 128 * 1024 * 1024, // 128MB
            bloom_filter_bits: 10,            // ~1% false positive
            enable_compression: true,
            block_cache_size: 64 * 1024 * 1024, // 64MB
        }
    }
}

impl IndexConfig {
    /// Create a new configuration with the given path
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ..Default::default()
        }
    }

    /// Create a builder for custom configuration
    pub fn builder(path: impl Into<PathBuf>) -> IndexConfigBuilder {
        IndexConfigBuilder::new(path)
    }

    /// Configuration optimized for low memory systems (< 4GB RAM)
    pub fn low_memory(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            memtable_size: 32 * 1024 * 1024, // 32MB
            bloom_filter_bits: 10,
            enable_compression: true,
            block_cache_size: 16 * 1024 * 1024, // 16MB
        }
    }

    /// Configuration optimized for high throughput (16GB+ RAM)
    pub fn high_throughput(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            memtable_size: 256 * 1024 * 1024, // 256MB
            bloom_filter_bits: 10,
            enable_compression: true,
            block_cache_size: 256 * 1024 * 1024, // 256MB
        }
    }

    /// Configuration for in-memory only (for testing)
    pub fn in_memory(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            memtable_size: 64 * 1024 * 1024,
            bloom_filter_bits: 10,
            enable_compression: false,
            block_cache_size: 32 * 1024 * 1024,
        }
    }
}

/// Builder for IndexConfig with fluent API
#[derive(Debug, Clone)]
pub struct IndexConfigBuilder {
    config: IndexConfig,
}

impl IndexConfigBuilder {
    /// Create a new builder with the given path
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            config: IndexConfig::new(path),
        }
    }

    /// Create a builder with low-memory preset
    pub fn low_memory(path: impl Into<PathBuf>) -> Self {
        Self {
            config: IndexConfig::low_memory(path),
        }
    }

    /// Create a builder with high-throughput preset
    pub fn high_throughput(path: impl Into<PathBuf>) -> Self {
        Self {
            config: IndexConfig::high_throughput(path),
        }
    }

    /// Set memory limit in bytes
    pub fn memtable_size(mut self, size: usize) -> Self {
        self.config.memtable_size = size;
        self
    }

    /// Set bloom filter bits per key
    pub fn bloom_filter_bits(mut self, bits: i32) -> Self {
        self.config.bloom_filter_bits = bits;
        self
    }

    /// Enable or disable compression
    pub fn compression(mut self, enable: bool) -> Self {
        self.config.enable_compression = enable;
        self
    }

    /// Set block cache size
    pub fn block_cache_size(mut self, size: usize) -> Self {
        self.config.block_cache_size = size;
        self
    }

    /// Build the configuration
    pub fn build(self) -> IndexConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IndexConfig::default();
        assert_eq!(config.memtable_size, 128 * 1024 * 1024);
        assert_eq!(config.bloom_filter_bits, 10);
    }

    #[test]
    fn test_builder() {
        let config = IndexConfig::builder("/tmp/test")
            .memtable_size(64 * 1024 * 1024)
            .bloom_filter_bits(8)
            .compression(false)
            .build();

        assert_eq!(config.memtable_size, 64 * 1024 * 1024);
        assert_eq!(config.bloom_filter_bits, 8);
        assert!(!config.enable_compression);
    }
}
