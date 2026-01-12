//! Compression utilities using Zstandard.

use bytes::Bytes;
use era_common::{CompressionAlgorithm, EraError, Result};

/// Trait for compression implementations
pub trait Compressor: Send + Sync {
    /// Compress data
    fn compress(&self, data: &[u8]) -> Result<Bytes>;

    /// Decompress data
    fn decompress(&self, data: &[u8]) -> Result<Bytes>;

    /// Get the algorithm type
    fn algorithm(&self) -> CompressionAlgorithm;
}

/// Zstandard compressor
pub struct ZstdCompressor {
    level: i32,
}

impl ZstdCompressor {
    /// Create a new Zstd compressor with the given level (1-22)
    pub fn new(level: i32) -> Self {
        Self {
            level: level.clamp(1, 22),
        }
    }

    /// Create with default level (3)
    pub fn default_level() -> Self {
        Self::new(3)
    }
}

impl Default for ZstdCompressor {
    fn default() -> Self {
        Self::default_level()
    }
}

impl Compressor for ZstdCompressor {
    fn compress(&self, data: &[u8]) -> Result<Bytes> {
        let compressed =
            zstd::encode_all(data, self.level).map_err(|e| EraError::compression(e.to_string()))?;
        Ok(Bytes::from(compressed))
    }

    fn decompress(&self, data: &[u8]) -> Result<Bytes> {
        let decompressed =
            zstd::decode_all(data).map_err(|e| EraError::decompression(e.to_string()))?;
        Ok(Bytes::from(decompressed))
    }

    fn algorithm(&self) -> CompressionAlgorithm {
        CompressionAlgorithm::Zstd
    }
}

/// No-op compressor (passthrough)
#[allow(dead_code)]
pub struct NoCompressor;

impl Compressor for NoCompressor {
    fn compress(&self, data: &[u8]) -> Result<Bytes> {
        Ok(Bytes::copy_from_slice(data))
    }

    fn decompress(&self, data: &[u8]) -> Result<Bytes> {
        Ok(Bytes::copy_from_slice(data))
    }

    fn algorithm(&self) -> CompressionAlgorithm {
        CompressionAlgorithm::None
    }
}

/// Convenience function to compress data with default settings
pub fn compress(data: &[u8]) -> Result<Bytes> {
    ZstdCompressor::default().compress(data)
}

/// Convenience function to decompress data
pub fn decompress(data: &[u8]) -> Result<Bytes> {
    ZstdCompressor::default().decompress(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let compressor = ZstdCompressor::default();
        let data = b"Hello, ERA! This is a test of compression. ".repeat(100);

        let compressed = compressor.compress(&data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_ref());
        assert!(compressed.len() < data.len()); // Should actually compress
    }

    #[test]
    fn test_no_compressor() {
        let compressor = NoCompressor;
        let data = b"Hello, ERA!";

        let compressed = compressor.compress(data).unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert_eq!(data.as_slice(), compressed.as_ref());
        assert_eq!(data.as_slice(), decompressed.as_ref());
    }

    #[test]
    fn test_empty_data() {
        let compressor = ZstdCompressor::default();

        let compressed = compressor.compress(b"").unwrap();
        let decompressed = compressor.decompress(&compressed).unwrap();

        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_convenience_functions() {
        let data = b"Test data for compression";

        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(data.as_slice(), decompressed.as_ref());
    }
}
