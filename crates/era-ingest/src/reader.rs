//! File reading utilities.

use crate::chunker::{Chunker, ChunkerConfig, StreamingChunker};
use bytes::Bytes;
use era_common::{ChunkHash, Result, UniqueChunk};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Threshold for using CDC chunking (files larger than this use chunking)
const CDC_THRESHOLD: u64 = 256 * 1024; // 256KB

/// Reader for ingesting files
pub struct FileReader {
    /// Buffer size for reading
    buffer_size: usize,
    /// Whether to use CDC for large files
    use_cdc: bool,
    /// CDC configuration
    chunker_config: ChunkerConfig,
}

impl FileReader {
    /// Create a new file reader
    pub fn new() -> Self {
        Self {
            buffer_size: 64 * 1024, // 64KB default
            use_cdc: false,         // MVP compatibility: disabled by default
            chunker_config: ChunkerConfig::default(),
        }
    }

    /// Create a file reader with CDC enabled
    pub fn with_cdc() -> Self {
        Self {
            buffer_size: 64 * 1024,
            use_cdc: true,
            chunker_config: ChunkerConfig::default(),
        }
    }

    /// Set the buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Enable or disable CDC chunking
    pub fn enable_cdc(mut self, enable: bool) -> Self {
        self.use_cdc = enable;
        self
    }

    /// Set custom CDC configuration
    pub fn with_chunker_config(mut self, config: ChunkerConfig) -> Self {
        self.chunker_config = config;
        self
    }

    /// Read an entire file as a single chunk
    ///
    /// This is the original MVP behavior, kept for backward compatibility.
    /// For large files, consider using `read_file_chunked` instead.
    pub fn read_file(&self, path: &Path) -> Result<UniqueChunk> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        let mut reader = BufReader::with_capacity(self.buffer_size, file);
        let mut data = Vec::with_capacity(size);
        reader.read_to_end(&mut data)?;

        let hash = era_crypto::hash(&data);

        Ok(UniqueChunk::new(Bytes::from(data), hash))
    }

    /// Read a file with automatic chunking for large files
    ///
    /// Files smaller than `CDC_THRESHOLD` are returned as a single chunk.
    /// Larger files are split using FastCDC content-defined chunking.
    pub fn read_file_chunked(&self, path: &Path) -> Result<Vec<UniqueChunk>> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();

        if !self.use_cdc || size <= CDC_THRESHOLD {
            // Small file: read as single chunk
            let chunk = self.read_file(path)?;
            return Ok(vec![chunk]);
        }

        // Large file: use streaming CDC
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(self.buffer_size, file);
        let streaming = StreamingChunker::new(reader, self.chunker_config.clone());

        streaming.collect()
    }

    /// Read a file and split into chunks using FastCDC
    ///
    /// Always uses CDC chunking regardless of file size.
    pub fn read_file_cdc(&self, path: &Path) -> Result<Vec<UniqueChunk>> {
        let chunker = Chunker::new(self.chunker_config.clone());
        chunker.chunk_file(path)
    }

    /// Read a file and compute its hash without loading all data at once
    pub fn hash_file(&self, path: &Path) -> Result<ChunkHash> {
        let file = File::open(path)?;
        era_crypto::hash_reader(file).map_err(Into::into)
    }

    /// Read file contents into memory
    pub fn read_bytes(&self, path: &Path) -> Result<Bytes> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        let mut reader = BufReader::with_capacity(self.buffer_size, file);
        let mut data = Vec::with_capacity(size);
        reader.read_to_end(&mut data)?;

        Ok(Bytes::from(data))
    }
}

impl Default for FileReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_file() {
        let mut temp = NamedTempFile::new().unwrap();
        let data = b"Hello, ERA file reader!";
        temp.write_all(data).unwrap();
        temp.flush().unwrap();

        let reader = FileReader::new();
        let chunk = reader.read_file(temp.path()).unwrap();

        assert_eq!(chunk.data.as_ref(), data);
        assert!(!chunk.hash.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_hash_file() {
        let mut temp = NamedTempFile::new().unwrap();
        let data = b"Test data for hashing";
        temp.write_all(data).unwrap();
        temp.flush().unwrap();

        let reader = FileReader::new();
        let hash1 = reader.hash_file(temp.path()).unwrap();
        let hash2 = era_crypto::hash(data);

        assert_eq!(hash1, hash2);
    }
}
