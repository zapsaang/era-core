//! Index configuration.

use std::path::PathBuf;

/// Configuration for the LSM-Tree chunk index
#[derive(Debug, Clone)]
pub struct IndexConfig {
    /// Path to the index directory
    pub path: PathBuf,

    /// MemTable size in bytes (default: 128MB)
    /// Larger values reduce write amplification but increase memory usage
    pub memtable_size: usize,

    /// Maximum number of MemTables before stalling (default: 3)
    pub max_memtables: i32,

    /// Target SSTable file size (default: 64MB)
    pub sstable_size: u64,

    /// Bloom filter bits per key (default: 10, ~1% false positive rate)
    pub bloom_filter_bits: i32,

    /// Enable compression for SSTables (default: true)
    pub enable_compression: bool,

    /// Maximum number of open files (default: 1000)
    pub max_open_files: i32,

    /// Block cache size in bytes (default: 64MB)
    /// Caches frequently accessed data blocks
    pub block_cache_size: usize,

    /// Enable WAL (Write-Ahead Log) for crash recovery (default: true)
    pub enable_wal: bool,

    /// Sync WAL on every write (default: false)
    /// Setting to true improves durability but reduces performance
    pub sync_wal: bool,

    /// Enable direct I/O for reads (default: false)
    /// Bypasses OS page cache, useful for large datasets
    pub use_direct_io: bool,

    /// Number of background compaction threads (default: 4)
    pub compaction_threads: i32,

    /// Number of background flush threads (default: 2)
    pub flush_threads: i32,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(".era-index"),
            memtable_size: 128 * 1024 * 1024, // 128MB
            max_memtables: 3,
            sstable_size: 64 * 1024 * 1024, // 64MB
            bloom_filter_bits: 10,          // ~1% false positive
            enable_compression: true,
            max_open_files: 1000,
            block_cache_size: 64 * 1024 * 1024, // 64MB
            enable_wal: true,
            sync_wal: false,
            use_direct_io: false,
            compaction_threads: 4,
            flush_threads: 2,
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
            max_memtables: 2,
            sstable_size: 32 * 1024 * 1024, // 32MB
            bloom_filter_bits: 10,
            enable_compression: true,
            max_open_files: 256,
            block_cache_size: 16 * 1024 * 1024, // 16MB
            enable_wal: true,
            sync_wal: false,
            use_direct_io: false,
            compaction_threads: 2,
            flush_threads: 1,
        }
    }

    /// Configuration optimized for high throughput (16GB+ RAM)
    pub fn high_throughput(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            memtable_size: 256 * 1024 * 1024, // 256MB
            max_memtables: 4,
            sstable_size: 128 * 1024 * 1024, // 128MB
            bloom_filter_bits: 10,
            enable_compression: true,
            max_open_files: 4096,
            block_cache_size: 256 * 1024 * 1024, // 256MB
            enable_wal: true,
            sync_wal: false,
            use_direct_io: true,
            compaction_threads: 8,
            flush_threads: 4,
        }
    }

    /// Configuration for in-memory only (for testing)
    pub fn in_memory(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            memtable_size: 64 * 1024 * 1024,
            max_memtables: 2,
            sstable_size: 32 * 1024 * 1024,
            bloom_filter_bits: 10,
            enable_compression: false,
            max_open_files: 100,
            block_cache_size: 32 * 1024 * 1024,
            enable_wal: false,
            sync_wal: false,
            use_direct_io: false,
            compaction_threads: 2,
            flush_threads: 1,
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

    /// Create a builder with low-memory preset.
    ///
    /// Suitable for resource-constrained environments:
    /// - 16MB MemTable
    /// - 16MB block cache  
    /// - 8-bit bloom filter
    pub fn low_memory(path: impl Into<PathBuf>) -> Self {
        Self {
            config: IndexConfig::low_memory(path),
        }
    }

    /// Create a builder with high-throughput preset.
    ///
    /// Suitable for high-performance environments:
    /// - 256MB MemTable
    /// - 256MB block cache
    /// - 12-bit bloom filter
    pub fn high_throughput(path: impl Into<PathBuf>) -> Self {
        Self {
            config: IndexConfig::high_throughput(path),
        }
    }

    /// Set MemTable size in bytes
    pub fn memtable_size(mut self, size: usize) -> Self {
        self.config.memtable_size = size;
        self
    }

    /// Set maximum number of MemTables
    pub fn max_memtables(mut self, count: i32) -> Self {
        self.config.max_memtables = count;
        self
    }

    /// Set SSTable file size
    pub fn sstable_size(mut self, size: u64) -> Self {
        self.config.sstable_size = size;
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

    /// Set maximum open files
    pub fn max_open_files(mut self, count: i32) -> Self {
        self.config.max_open_files = count;
        self
    }

    /// Set block cache size
    pub fn block_cache_size(mut self, size: usize) -> Self {
        self.config.block_cache_size = size;
        self
    }

    /// Enable or disable WAL
    pub fn wal(mut self, enable: bool) -> Self {
        self.config.enable_wal = enable;
        self
    }

    /// Enable or disable sync on WAL writes
    pub fn sync_wal(mut self, sync: bool) -> Self {
        self.config.sync_wal = sync;
        self
    }

    /// Enable or disable direct I/O
    pub fn direct_io(mut self, enable: bool) -> Self {
        self.config.use_direct_io = enable;
        self
    }

    /// Set number of compaction threads
    pub fn compaction_threads(mut self, threads: i32) -> Self {
        self.config.compaction_threads = threads;
        self
    }

    /// Set number of flush threads
    pub fn flush_threads(mut self, threads: i32) -> Self {
        self.config.flush_threads = threads;
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
