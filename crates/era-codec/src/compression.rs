//! Compression utilities using Zstandard.

use bytes::Bytes;
use era_common::{CompressionAlgorithm, EraError, Result};
use std::io::Read;

/// Maximum decompressed output size (256 MB) to prevent decompression bombs.
const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

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
        let mut decoder =
            zstd::Decoder::new(data).map_err(|e| EraError::decompression(e.to_string()))?;
        let mut output = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = decoder
                .read(&mut buf)
                .map_err(|e| EraError::decompression(e.to_string()))?;
            if n == 0 {
                break;
            }
            if output.len() + n > MAX_DECOMPRESSED_SIZE {
                return Err(EraError::decompression(format!(
                    "Decompressed output exceeds maximum allowed size of {} bytes",
                    MAX_DECOMPRESSED_SIZE
                )));
            }
            output.extend_from_slice(&buf[..n]);
        }
        Ok(Bytes::from(output))
    }

    fn algorithm(&self) -> CompressionAlgorithm {
        CompressionAlgorithm::Zstd
    }
}

/// No-op compressor (passthrough)
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

/// LZ4 compressor (fast compression, lower ratio than Zstd)
pub struct LZ4Compressor {
    level: i32, // 1-12 for lz4_flex
}

impl LZ4Compressor {
    /// Create a new LZ4 compressor with the given level (1-12)
    pub fn new(level: i32) -> Self {
        Self {
            level: level.clamp(1, 12),
        }
    }

    /// Create with default level (4, balanced speed/ratio)
    pub fn default_level() -> Self {
        Self::new(4)
    }
}

impl Default for LZ4Compressor {
    fn default() -> Self {
        Self::default_level()
    }
}

impl Compressor for LZ4Compressor {
    fn compress(&self, data: &[u8]) -> Result<Bytes> {
        // LZ4 compression - very fast, lower compression ratio than Zstd
        // We use the default acceleration factor based on compression level
        let _level = self.level;
        let compressed = lz4_flex::compress_prepend_size(data);
        Ok(Bytes::from(compressed))
    }

    fn decompress(&self, data: &[u8]) -> Result<Bytes> {
        // Validate the 4-byte LE size prefix before decompression
        if data.len() < 4 {
            return Err(EraError::decompression(
                "LZ4 data too short: missing size prefix".to_string(),
            ));
        }
        let declared_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if declared_size > MAX_DECOMPRESSED_SIZE {
            return Err(EraError::decompression(format!(
                "LZ4 declared size {} exceeds maximum allowed size of {} bytes",
                declared_size, MAX_DECOMPRESSED_SIZE
            )));
        }
        match lz4_flex::decompress_size_prepended(data) {
            Ok(decompressed) => Ok(Bytes::from(decompressed)),
            Err(e) => Err(EraError::decompression(format!(
                "LZ4 decompression failed: {}",
                e
            ))),
        }
    }

    fn algorithm(&self) -> CompressionAlgorithm {
        CompressionAlgorithm::LZ4
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
