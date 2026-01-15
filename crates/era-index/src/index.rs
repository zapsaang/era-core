//! LSM-Tree based chunk index implementation.
//!
//! This module provides the core `LsmChunkIndex` type which wraps RocksDB
//! to provide persistent, high-performance chunk deduplication.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rocksdb::{
    BlockBasedOptions, Cache, DBCompactionStyle, DBCompressionType, Options, ReadOptions, 
    WriteBatch, WriteOptions, DB,
};
use tracing::{debug, info, warn};

use era_common::{BlockLocation, ChunkHash};

use crate::config::IndexConfig;
use crate::error::IndexError;
use crate::metrics::IndexMetrics;

/// LSM-Tree based chunk deduplication index.
///
/// This index maps ChunkHash → BlockLocation, enabling efficient deduplication
/// of chunks across multiple archive sessions.
///
/// ## Thread Safety
///
/// LsmChunkIndex is designed for concurrent access:
/// - Multiple readers can access the index simultaneously
/// - Single writer with automatic serialization
/// - All operations are atomic
///
/// ## Memory Management
///
/// The index uses RocksDB's block cache and bloom filters to minimize
/// memory usage while maintaining high performance:
/// - Block cache: Configurable, default 64MB
/// - Bloom filters: ~10 bits per key, ~1% false positive rate
/// - MemTable: Configurable, default 128MB (flushed to disk when full)
pub struct LsmChunkIndex {
    /// RocksDB instance
    db: DB,
    
    /// Configuration
    config: IndexConfig,
    
    /// Performance metrics
    metrics: Arc<IndexMetrics>,
    
    /// Write options for normal writes
    write_opts: WriteOptions,
    
    /// Read options
    read_opts: ReadOptions,
    
    /// Whether the index is in read-only mode
    read_only: bool,
    
    /// Batch write buffer for high-throughput scenarios
    batch_buffer: Mutex<Option<WriteBatch>>,
}

impl LsmChunkIndex {
    /// Open an existing index or create a new one at the given path.
    ///
    /// This is the recommended way to open an index for read-write access.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IndexError> {
        let config = IndexConfig::new(path.as_ref());
        Self::open_with_config(config)
    }
    
    /// Open an index with custom configuration.
    pub fn open_with_config(config: IndexConfig) -> Result<Self, IndexError> {
        info!("Opening LSM chunk index at {:?}", config.path);
        
        let opts = Self::build_options(&config)?;
        
        // Ensure directory exists
        std::fs::create_dir_all(&config.path)?;
        
        let db = DB::open(&opts, &config.path)?;
        
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(config.sync_wal);
        write_opts.disable_wal(!config.enable_wal);
        
        let read_opts = ReadOptions::default();
        
        info!(
            "LSM index opened: memtable={}MB, bloom={}bits, cache={}MB",
            config.memtable_size / (1024 * 1024),
            config.bloom_filter_bits,
            config.block_cache_size / (1024 * 1024)
        );
        
        Ok(Self {
            db,
            config,
            metrics: Arc::new(IndexMetrics::new()),
            write_opts,
            read_opts,
            read_only: false,
            batch_buffer: Mutex::new(None),
        })
    }
    
    /// Open an index in read-only mode.
    ///
    /// This allows multiple processes to read the index simultaneously
    /// without holding exclusive locks.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, IndexError> {
        let config = IndexConfig::new(path.as_ref());
        Self::open_read_only_with_config(config)
    }
    
    /// Open an index in read-only mode with custom configuration.
    pub fn open_read_only_with_config(config: IndexConfig) -> Result<Self, IndexError> {
        info!("Opening LSM chunk index (read-only) at {:?}", config.path);
        
        let opts = Self::build_options(&config)?;
        let db = DB::open_for_read_only(&opts, &config.path, false)?;
        
        let write_opts = WriteOptions::default();
        let read_opts = ReadOptions::default();
        
        Ok(Self {
            db,
            config,
            metrics: Arc::new(IndexMetrics::new()),
            write_opts,
            read_opts,
            read_only: true,
            batch_buffer: Mutex::new(None),
        })
    }
    
    /// Build RocksDB options from our configuration.
    fn build_options(config: &IndexConfig) -> Result<Options, IndexError> {
        let mut opts = Options::default();
        
        // Basic settings
        opts.create_if_missing(true);
        opts.set_error_if_exists(false);
        
        // MemTable configuration
        opts.set_write_buffer_size(config.memtable_size);
        opts.set_max_write_buffer_number(config.max_memtables);
        opts.set_min_write_buffer_number_to_merge(1);
        
        // SSTable configuration
        opts.set_target_file_size_base(config.sstable_size);
        opts.set_max_open_files(config.max_open_files);
        
        // Compaction
        opts.set_compaction_style(DBCompactionStyle::Level);
        opts.set_level_zero_file_num_compaction_trigger(4);
        opts.set_level_zero_slowdown_writes_trigger(20);
        opts.set_level_zero_stop_writes_trigger(36);
        opts.increase_parallelism(config.compaction_threads);
        opts.set_max_background_jobs(config.compaction_threads + config.flush_threads);
        
        // Compression
        if config.enable_compression {
            opts.set_compression_type(DBCompressionType::Lz4);
            opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        }
        
        // Block-based table options with bloom filter
        let mut block_opts = BlockBasedOptions::default();
        
        // Bloom filter for fast negative lookups
        block_opts.set_bloom_filter(config.bloom_filter_bits as f64, true);
        
        // Block cache
        let cache = Cache::new_lru_cache(config.block_cache_size);
        block_opts.set_block_cache(&cache);
        block_opts.set_cache_index_and_filter_blocks(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        
        // Block size
        block_opts.set_block_size(16 * 1024); // 16KB blocks
        
        opts.set_block_based_table_factory(&block_opts);
        
        // Direct I/O (if enabled)
        if config.use_direct_io {
            opts.set_use_direct_reads(true);
            opts.set_use_direct_io_for_flush_and_compaction(true);
        }
        
        // Statistics for debugging
        opts.enable_statistics();
        
        Ok(opts)
    }
    
    /// Get the location of a chunk by its hash.
    ///
    /// Returns `Ok(Some(location))` if found, `Ok(None)` if not found.
    pub fn get(&self, hash: &ChunkHash) -> Result<Option<BlockLocation>, IndexError> {
        let key = hash.as_bytes();
        
        match self.db.get_opt(key, &self.read_opts)? {
            Some(value) => {
                self.metrics.record_get(true);
                let location = Self::deserialize_location(&value)?;
                Ok(Some(location))
            }
            None => {
                self.metrics.record_get(false);
                Ok(None)
            }
        }
    }
    
    /// Check if a chunk exists in the index.
    ///
    /// This is slightly faster than `get` if you only need to check existence.
    pub fn contains(&self, hash: &ChunkHash) -> Result<bool, IndexError> {
        let key = hash.as_bytes();
        
        // Use key_may_exist for bloom filter optimization
        if !self.db.key_may_exist(key) {
            self.metrics.record_bloom(false, false);
            return Ok(false);
        }
        
        self.metrics.record_bloom(true, true); // May be false positive
        
        // Verify with actual lookup
        let exists = self.db.get_opt(key, &self.read_opts)?.is_some();
        Ok(exists)
    }
    
    /// Store a chunk location in the index.
    ///
    /// If the chunk already exists, its location will be updated.
    pub fn put(&self, hash: ChunkHash, location: BlockLocation) -> Result<(), IndexError> {
        if self.read_only {
            return Err(IndexError::ReadOnly);
        }
        
        let key = hash.as_bytes();
        let value = Self::serialize_location(&location)?;
        
        // Check if we're in batch mode - use lock() for Mutex
        let mut batch_guard = self.batch_buffer.lock();
        if let Some(ref mut batch) = *batch_guard {
            batch.put(key, &value);
            self.metrics.record_put(value.len());
            return Ok(());
        }
        drop(batch_guard);
        
        // Normal write
        self.db.put_opt(key, &value, &self.write_opts)?;
        self.metrics.record_put(value.len());
        
        Ok(())
    }
    
    /// Delete a chunk from the index.
    pub fn delete(&self, hash: &ChunkHash) -> Result<(), IndexError> {
        if self.read_only {
            return Err(IndexError::ReadOnly);
        }
        
        let key = hash.as_bytes();
        self.db.delete_opt(key, &self.write_opts)?;
        self.metrics.record_delete();
        
        Ok(())
    }
    
    /// Start a batch write operation.
    ///
    /// All subsequent `put` calls will be buffered until `commit_batch` is called.
    /// This significantly improves write throughput for bulk operations.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// # use era_index::LsmChunkIndex;
    /// # use era_common::{ChunkHash, BlockLocation, VolumeId};
    /// # fn example() -> Result<(), era_index::IndexError> {
    /// let index = LsmChunkIndex::open("/tmp/index")?;
    ///
    /// index.start_batch();
    /// for i in 0..10000 {
    ///     let hash = ChunkHash::from_bytes([i as u8; 32]);
    ///     let location = BlockLocation {
    ///         volume_id: VolumeId::new(),
    ///         slot_index: i,
    ///         physical_offset: i as u64 * 4096,
    ///         encrypted_size: 4096,
    ///         erasure_info: None,
    ///         shard_offsets: None,
    ///         shard_volumes: None,
    ///     };
    ///     index.put(hash, location)?;
    /// }
    /// index.commit_batch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn start_batch(&self) {
        if self.read_only {
            warn!("Ignoring start_batch on read-only index");
            return;
        }
        
        let mut batch_guard = self.batch_buffer.lock();
        *batch_guard = Some(WriteBatch::default());
        debug!("Started batch write mode");
    }
    
    /// Commit the current batch write operation.
    ///
    /// All buffered writes will be applied atomically.
    pub fn commit_batch(&self) -> Result<(), IndexError> {
        if self.read_only {
            return Err(IndexError::ReadOnly);
        }
        
        let batch: Option<WriteBatch> = {
            let mut batch_guard = self.batch_buffer.lock();
            batch_guard.take()
        };
        
        if let Some(batch) = batch {
            let count = batch.len();
            self.db.write_opt(batch, &self.write_opts)?;
            debug!("Committed batch with {} operations", count);
        }
        
        Ok(())
    }
    
    /// Abort the current batch write operation.
    ///
    /// All buffered writes will be discarded.
    pub fn abort_batch(&self) {
        let mut batch_guard = self.batch_buffer.lock();
        if batch_guard.take().is_some() {
            debug!("Aborted batch write");
        }
    }
    
    /// Get the number of entries in the index.
    ///
    /// Note: This is an estimate and may not be exact.
    pub fn len(&self) -> u64 {
        self.db
            .property_int_value("rocksdb.estimate-num-keys")
            .ok()
            .flatten()
            .unwrap_or(0)
    }
    
    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// Flush all in-memory data to disk.
    pub fn flush(&self) -> Result<(), IndexError> {
        if self.read_only {
            return Ok(());
        }
        
        self.db.flush()?;
        info!("Flushed LSM index to disk");
        Ok(())
    }
    
    /// Compact the entire database.
    ///
    /// This may take a long time for large databases.
    pub fn compact(&self) -> Result<(), IndexError> {
        if self.read_only {
            return Ok(());
        }
        
        info!("Starting full compaction...");
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        info!("Compaction complete");
        Ok(())
    }
    
    /// Get index metrics.
    pub fn metrics(&self) -> Arc<IndexMetrics> {
        Arc::clone(&self.metrics)
    }
    
    /// Get RocksDB statistics as a string.
    pub fn stats(&self) -> Option<String> {
        self.db.property_value("rocksdb.stats").ok().flatten()
    }
    
    /// Get the size of all SST files on disk (bytes).
    pub fn disk_size(&self) -> u64 {
        self.db
            .property_int_value("rocksdb.total-sst-files-size")
            .ok()
            .flatten()
            .unwrap_or(0)
    }
    
    /// Get the path to the index.
    pub fn path(&self) -> &Path {
        &self.config.path
    }
    
    /// Check if the index is in read-only mode.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
    
    /// Iterate over all entries in the index.
    ///
    /// The iterator yields (ChunkHash, BlockLocation) pairs in key order.
    pub fn iter(&self) -> impl Iterator<Item = Result<(ChunkHash, BlockLocation), IndexError>> + '_ {
        self.db.iterator(rocksdb::IteratorMode::Start).map(|result| {
            let (key, value) = result.map_err(IndexError::from)?;
            
            if key.len() != 32 {
                return Err(IndexError::Corruption(format!(
                    "Invalid key length: expected 32, got {}",
                    key.len()
                )));
            }
            
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&key);
            let hash = ChunkHash::from_bytes(hash_bytes);
            
            let location = Self::deserialize_location(&value)?;
            
            Ok((hash, location))
        })
    }
    
    /// Serialize a BlockLocation to bytes.
    fn serialize_location(location: &BlockLocation) -> Result<Vec<u8>, IndexError> {
        bincode::serde::encode_to_vec(location, bincode::config::standard())
            .map_err(|e| IndexError::Serialization(e.to_string()))
    }
    
    /// Deserialize a BlockLocation from bytes.
    fn deserialize_location(bytes: &[u8]) -> Result<BlockLocation, IndexError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(location, _)| location)
            .map_err(|e| IndexError::Deserialization(e.to_string()))
    }
    
    /// Destroy the index at the given path.
    ///
    /// This permanently deletes all data.
    pub fn destroy(path: impl AsRef<Path>) -> Result<(), IndexError> {
        let opts = Options::default();
        DB::destroy(&opts, path.as_ref())?;
        info!("Destroyed LSM index at {:?}", path.as_ref());
        Ok(())
    }
}

impl Drop for LsmChunkIndex {
    fn drop(&mut self) {
        // Commit any pending batch
        if self.batch_buffer.lock().is_some() {
            if let Err(e) = self.commit_batch() {
                warn!("Failed to commit batch on drop: {}", e);
            }
        }
        
        // Flush before closing
        if !self.read_only {
            if let Err(e) = self.flush() {
                warn!("Failed to flush on drop: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use era_common::VolumeId;
    use tempfile::TempDir;
    
    fn create_test_location(slot: u32) -> BlockLocation {
        BlockLocation {
            volume_id: VolumeId::new(),
            slot_index: slot,
            physical_offset: slot as u64 * 4096,
            encrypted_size: 4096,
            erasure_info: None,
            shard_offsets: None,
            shard_volumes: None,
        }
    }
    
    #[test]
    fn test_basic_operations() {
        let tmp = TempDir::new().unwrap();
        let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();
        
        let hash = ChunkHash::from_bytes([1u8; 32]);
        let location = create_test_location(0);
        
        // Initially empty
        assert!(index.get(&hash).unwrap().is_none());
        assert!(!index.contains(&hash).unwrap());
        
        // Put and get
        index.put(hash, location.clone()).unwrap();
        let retrieved = index.get(&hash).unwrap().unwrap();
        assert_eq!(retrieved.slot_index, location.slot_index);
        assert!(index.contains(&hash).unwrap());
        
        // Delete
        index.delete(&hash).unwrap();
        assert!(index.get(&hash).unwrap().is_none());
    }
    
    #[test]
    fn test_batch_operations() {
        let tmp = TempDir::new().unwrap();
        let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();
        
        // Start batch
        index.start_batch();
        
        // Add many entries
        for i in 0..1000 {
            let hash = ChunkHash::from_bytes([i as u8; 32]);
            let location = create_test_location(i);
            index.put(hash, location).unwrap();
        }
        
        // Entries should not be visible yet (implementation detail, may vary)
        
        // Commit batch
        index.commit_batch().unwrap();
        
        // Now entries should be visible
        for i in 0..1000 {
            let hash = ChunkHash::from_bytes([i as u8; 32]);
            assert!(index.get(&hash).unwrap().is_some());
        }
    }
    
    #[test]
    fn test_persistence() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("index");
        
        let hash = ChunkHash::from_bytes([42u8; 32]);
        let location = create_test_location(99);
        
        // Write and close
        {
            let index = LsmChunkIndex::open(&path).unwrap();
            index.put(hash, location.clone()).unwrap();
            index.flush().unwrap();
        }
        
        // Reopen and verify
        {
            let index = LsmChunkIndex::open(&path).unwrap();
            let retrieved = index.get(&hash).unwrap().unwrap();
            assert_eq!(retrieved.slot_index, 99);
        }
    }
    
    #[test]
    fn test_read_only_mode() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("index");
        
        let hash = ChunkHash::from_bytes([1u8; 32]);
        let location = create_test_location(0);
        
        // Create and populate
        {
            let index = LsmChunkIndex::open(&path).unwrap();
            index.put(hash, location.clone()).unwrap();
            index.flush().unwrap();
        }
        
        // Open read-only
        {
            let index = LsmChunkIndex::open_read_only(&path).unwrap();
            assert!(index.is_read_only());
            
            // Reading should work
            let retrieved = index.get(&hash).unwrap().unwrap();
            assert_eq!(retrieved.slot_index, location.slot_index);
            
            // Writing should fail
            let result = index.put(hash, location);
            assert!(matches!(result, Err(IndexError::ReadOnly)));
        }
    }
    
    #[test]
    fn test_iteration() {
        let tmp = TempDir::new().unwrap();
        let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();
        
        // Add entries
        for i in 0..10 {
            let hash = ChunkHash::from_bytes([i as u8; 32]);
            let location = create_test_location(i);
            index.put(hash, location).unwrap();
        }
        
        index.flush().unwrap();
        
        // Count entries via iteration
        let count = index.iter().count();
        assert_eq!(count, 10);
    }
    
    #[test]
    fn test_metrics() {
        let tmp = TempDir::new().unwrap();
        let index = LsmChunkIndex::open(tmp.path().join("index")).unwrap();
        
        let hash = ChunkHash::from_bytes([1u8; 32]);
        let location = create_test_location(0);
        
        // Do some operations
        index.put(hash, location).unwrap();
        index.get(&hash).unwrap();
        index.get(&ChunkHash::from_bytes([99u8; 32])).unwrap(); // Miss
        
        let metrics = index.metrics();
        let snapshot = metrics.snapshot();
        
        assert_eq!(snapshot.puts, 1);
        assert_eq!(snapshot.gets, 2);
        assert_eq!(snapshot.get_hits, 1);
        assert_eq!(snapshot.get_misses, 1);
    }
}
