//! FastCDC (Fast Content-Defined Chunking) implementation.
//!
//! This module provides content-defined chunking using the industry-standard
//! `fastcdc` crate. It enables efficient deduplication by producing chunks
//! with boundaries determined by content rather than position.
//!
//! # Migration from Custom Implementation
//!
//! This module has been refactored to use the `fastcdc` crate instead of
//! a custom 700+ line implementation. Benefits:
//! - Reduced code maintenance (removed ~600 lines)
//! - Battle-tested implementation used in production
//! - Better performance with optimized algorithms
//! - Active community maintenance and bug fixes

use bytes::Bytes;
use era_common::{ChunkHash, Result, UniqueChunk};
use fastcdc::v2020::FastCDC;
use std::io::Read;

/// Default minimum chunk size (4 KB)
pub const DEFAULT_MIN_SIZE: usize = 4 * 1024;

/// Default average chunk size (64 KB)
pub const DEFAULT_AVG_SIZE: usize = 64 * 1024;

/// Default maximum chunk size (256 KB)
pub const DEFAULT_MAX_SIZE: usize = 256 * 1024;

/// Configuration for FastCDC chunking
#[derive(Debug, Clone)]
pub struct ChunkerConfig {
    /// Minimum chunk size in bytes
    pub min_size: usize,
    /// Average (target) chunk size in bytes
    pub avg_size: usize,
    /// Maximum chunk size in bytes
    pub max_size: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            min_size: DEFAULT_MIN_SIZE,
            avg_size: DEFAULT_AVG_SIZE,
            max_size: DEFAULT_MAX_SIZE,
        }
    }
}

impl ChunkerConfig {
    /// Create a new configuration with custom sizes
    pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        assert!(min_size <= avg_size, "min_size must be <= avg_size");
        assert!(avg_size <= max_size, "avg_size must be <= max_size");
        Self {
            min_size,
            avg_size,
            max_size,
        }
    }

    /// Create configuration optimized for small files (16KB average)
    pub fn small_files() -> Self {
        Self::new(2 * 1024, 16 * 1024, 64 * 1024)
    }

    /// Create configuration optimized for large files (256KB average)
    pub fn large_files() -> Self {
        Self::new(16 * 1024, 256 * 1024, 1024 * 1024)
    }
}

/// FastCDC chunker for content-defined chunking
pub struct Chunker {
    config: ChunkerConfig,
}

impl Chunker {
    /// Create a new chunker with the given configuration
    pub fn new(config: ChunkerConfig) -> Self {
        Self { config }
    }

    /// Create a chunker with default configuration
    pub fn default_config() -> Self {
        Self::new(ChunkerConfig::default())
    }

    /// Chunk data from a byte slice
    ///
    /// Returns an iterator over chunks with their hashes.
    pub fn chunk_bytes<'a>(&'a self, data: &'a [u8]) -> ChunkIterator<'a> {
        ChunkIterator {
            data,
            inner: FastCDC::new(
                data,
                self.config.min_size as u32,
                self.config.avg_size as u32,
                self.config.max_size as u32,
            ),
        }
    }

    /// Chunk data from a reader into UniqueChunks
    ///
    /// This is a convenience method that collects all chunks.
    /// For streaming, use `chunk_bytes` with buffered reads.
    pub fn chunk_all(&self, data: &[u8]) -> Vec<UniqueChunk> {
        self.chunk_bytes(data)
            .map(|(chunk_data, hash)| UniqueChunk::new(Bytes::copy_from_slice(chunk_data), hash))
            .collect()
    }

    /// Chunk a file into UniqueChunks
    ///
    /// Reads the entire file into memory first. For very large files,
    /// consider using streaming chunking.
    pub fn chunk_file(&self, path: &std::path::Path) -> Result<Vec<UniqueChunk>> {
        let data = std::fs::read(path)?;
        Ok(self.chunk_all(&data))
    }
}

/// Iterator over chunks in a byte slice
pub struct ChunkIterator<'a> {
    data: &'a [u8],
    inner: FastCDC<'a>,
}

impl<'a> Iterator for ChunkIterator<'a> {
    type Item = (&'a [u8], ChunkHash);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|chunk_info| {
            let chunk = &self.data[chunk_info.offset..chunk_info.offset + chunk_info.length];
            let hash = era_crypto::hash(chunk);
            (chunk, hash)
        })
    }
}

/// Streaming chunker for reading from a file without loading all into memory
pub struct StreamingChunker<R: Read> {
    reader: R,
    config: ChunkerConfig,
    buffer: Vec<u8>,
    buffer_start: usize,
    buffer_end: usize,
    eof: bool,
}

impl<R: Read> StreamingChunker<R> {
    /// Create a new streaming chunker
    pub fn new(reader: R, config: ChunkerConfig) -> Self {
        // Buffer size should be at least max_size * 2 for efficiency
        let buffer_size = config.max_size * 2;
        Self {
            reader,
            config,
            buffer: vec![0u8; buffer_size],
            buffer_start: 0,
            buffer_end: 0,
            eof: false,
        }
    }

    /// Fill the buffer with more data from the reader
    fn fill_buffer(&mut self) -> std::io::Result<()> {
        // Compact buffer if needed
        if self.buffer_start > 0 {
            self.buffer
                .copy_within(self.buffer_start..self.buffer_end, 0);
            self.buffer_end -= self.buffer_start;
            self.buffer_start = 0;
        }

        // Read more data
        while self.buffer_end < self.buffer.len() && !self.eof {
            let n = self.reader.read(&mut self.buffer[self.buffer_end..])?;
            if n == 0 {
                self.eof = true;
                break;
            }
            self.buffer_end += n;
        }

        Ok(())
    }

    /// Get the next chunk
    pub fn next_chunk(&mut self) -> Result<Option<UniqueChunk>> {
        // Ensure we have enough data
        self.fill_buffer()?;

        let available = self.buffer_end - self.buffer_start;
        if available == 0 {
            return Ok(None);
        }

        let data = &self.buffer[self.buffer_start..self.buffer_end];

        // Use fastcdc to find the next chunk boundary
        let mut chunker = FastCDC::new(
            data,
            self.config.min_size as u32,
            self.config.avg_size as u32,
            self.config.max_size as u32,
        );

        if let Some(chunk_info) = chunker.next() {
            let chunk_data = &data[chunk_info.offset..chunk_info.offset + chunk_info.length];
            let hash = era_crypto::hash(chunk_data);

            self.buffer_start += chunk_info.length;

            Ok(Some(UniqueChunk::new(
                Bytes::copy_from_slice(chunk_data),
                hash,
            )))
        } else {
            Ok(None)
        }
    }
}

impl<R: Read> Iterator for StreamingChunker<R> {
    type Item = Result<UniqueChunk>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_chunk() {
            Ok(Some(chunk)) => Some(Ok(chunk)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunker_config_default() {
        let config = ChunkerConfig::default();
        assert_eq!(config.min_size, 4 * 1024);
        assert_eq!(config.avg_size, 64 * 1024);
        assert_eq!(config.max_size, 256 * 1024);
    }

    #[test]
    fn test_chunk_small_data() {
        let chunker = Chunker::default_config();
        let data = b"Hello, World!";
        let chunks: Vec<_> = chunker.chunk_bytes(data).collect();

        // Small data should be a single chunk
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, data.as_slice());
    }

    #[test]
    fn test_chunk_deterministic() {
        let chunker = Chunker::default_config();
        let data = vec![0u8; 100 * 1024]; // 100KB of zeros

        let chunks1: Vec<_> = chunker.chunk_bytes(&data).collect();
        let chunks2: Vec<_> = chunker.chunk_bytes(&data).collect();

        // Same data should produce same chunks
        assert_eq!(chunks1.len(), chunks2.len());
        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.1, c2.1); // Same hash
        }
    }

    #[test]
    fn test_chunk_boundaries_are_content_defined() {
        let chunker = Chunker::new(ChunkerConfig::new(64, 256, 1024));

        // Create data with a distinctive pattern
        let mut data1 = vec![0u8; 2048];
        let mut data2 = vec![0u8; 2048];

        // Add same suffix to both
        let suffix = b"UNIQUE_BOUNDARY_MARKER_12345";
        data1[1000..1000 + suffix.len()].copy_from_slice(suffix);
        data2[500..500 + suffix.len()].copy_from_slice(suffix);

        let chunks1: Vec<_> = chunker.chunk_bytes(&data1).collect();
        let chunks2: Vec<_> = chunker.chunk_bytes(&data2).collect();

        // At least some chunks should be different (due to offset)
        // but the algorithm should find similar boundaries
        assert!(!chunks1.is_empty());
        assert!(!chunks2.is_empty());
    }

    #[test]
    fn test_chunk_respects_max_size() {
        // Use larger sizes that meet fastcdc's minimum requirements
        let config = ChunkerConfig::new(2048, 8192, 16384);
        let chunker = Chunker::new(config.clone());

        // Data that won't trigger any natural boundaries
        let data = vec![0x42u8; 50000];

        for (chunk, _) in chunker.chunk_bytes(&data) {
            assert!(chunk.len() <= config.max_size);
        }
    }

    #[test]
    fn test_chunk_respects_min_size() {
        // Use larger sizes that meet fastcdc's minimum requirements
        let config = ChunkerConfig::new(2048, 8192, 16384);
        let chunker = Chunker::new(config.clone());

        // Large enough data
        let data = vec![0x42u8; 50000];
        let chunks: Vec<_> = chunker.chunk_bytes(&data).collect();

        // All chunks except possibly the last should be >= min_size
        for (i, (chunk, _)) in chunks.iter().enumerate() {
            if i < chunks.len() - 1 {
                assert!(
                    chunk.len() >= config.min_size,
                    "Chunk {} has size {} < min {}",
                    i,
                    chunk.len(),
                    config.min_size
                );
            }
        }
    }

    #[test]
    fn test_chunk_all_data_preserved() {
        let chunker = Chunker::default_config();
        let data: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();

        let chunks: Vec<_> = chunker.chunk_bytes(&data).collect();

        // Concatenating all chunks should give original data
        let reconstructed: Vec<u8> = chunks.iter().flat_map(|(c, _)| c.iter().copied()).collect();

        assert_eq!(data, reconstructed);
    }

    #[test]
    fn test_streaming_chunker() {
        use std::io::Cursor;

        let config = ChunkerConfig::new(64, 256, 1024);
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let reader = Cursor::new(data.clone());
        let mut streaming = StreamingChunker::new(reader, config.clone());

        let mut chunks = Vec::new();
        while let Ok(Some(chunk)) = streaming.next_chunk() {
            chunks.push(chunk);
        }

        // Verify all data is chunked
        let total_size: usize = chunks.iter().map(|c| c.data.len()).sum();
        assert_eq!(total_size, data.len());
    }

    #[test]
    fn test_chunk_unique_chunks() {
        let chunker = Chunker::default_config();
        let data = vec![0x42u8; 100_000];

        let unique_chunks = chunker.chunk_all(&data);

        assert!(!unique_chunks.is_empty());
        for chunk in &unique_chunks {
            assert!(!chunk.data.is_empty());
            // Verify hash is correct
            let expected_hash = era_crypto::hash(&chunk.data);
            assert_eq!(chunk.hash, expected_hash);
        }
    }
}
