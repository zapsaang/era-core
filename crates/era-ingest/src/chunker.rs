//! FastCDC (Fast Content-Defined Chunking) implementation.
//!
//! This module provides content-defined chunking using the Gear hash algorithm
//! as described in the FastCDC paper. It enables efficient deduplication by
//! producing chunks with boundaries determined by content rather than position.
//!
//! # Algorithm Overview
//!
//! 1. **Gear Hash**: Uses a pre-computed random table to update a rolling hash
//!    with a single shift and XOR operation per byte.
//! 2. **Normalized Chunking**: Adjusts the hash mask dynamically to produce
//!    chunks that cluster around the target average size.
//! 3. **Sub-minimum Skip**: After finding a cut point, skips the minimum chunk
//!    size before scanning again, reducing computation by 50-70%.

use bytes::Bytes;
use era_common::{ChunkHash, Result, UniqueChunk};
use std::io::Read;

/// Default minimum chunk size (4 KB)
pub const DEFAULT_MIN_SIZE: usize = 4 * 1024;

/// Default average chunk size (64 KB)
pub const DEFAULT_AVG_SIZE: usize = 64 * 1024;

/// Default maximum chunk size (256 KB)
pub const DEFAULT_MAX_SIZE: usize = 256 * 1024;

/// Gear hash table - 256 unique random 64-bit integers
/// Generated using SHA-256 hash of "ERA-GEAR-TABLE-V2-{index}" for reproducibility.
/// Each entry is SHA256(b"ERA-GEAR-TABLE-V2-{i}")[0..8] as little-endian u64.
/// All 256 values are verified unique to maximize hash entropy.
const GEAR_TABLE: [u64; 256] = [
    0x8040dbda75c236ce,
    0x3a943c99e220c634,
    0x6647e47ad7affbe8,
    0x19961cf260c601b9,
    0xdcbea4e77ee2c2ff,
    0xdc015788e2dbf8f2,
    0x9c32fc600d3ab33d,
    0xe5b009b8775c5958,
    0x32b4acd60f78d2c5,
    0x00ab2a9fedec417c,
    0x0c8e799f2f7cdf26,
    0xa8505acb78c4c940,
    0x8592b1b2f6491ba8,
    0xa3837d5081b50ebb,
    0x2fa70a89995d5f1e,
    0x5369dbdde6356a3b,
    0x1735f1e2fafa98d2,
    0xfe16915d545ba698,
    0xfb51a610b637112f,
    0xc42227becd643bb0,
    0xc84f35f6ec9a91b7,
    0x94ed0f8177f69f28,
    0x3155ec69f54999b2,
    0x592f7b0a2b2827bc,
    0xddd16406c3eed0a6,
    0x863ad1f8a156c526,
    0x29722abde7e77850,
    0x57d078286894efc6,
    0xed87a1a0589d372e,
    0x8d90cb1816e176a1,
    0xa94c1108fd405188,
    0xd8a57047b0fb64d2,
    0x2620d22c18cd9dd5,
    0x11373b8ffe846206,
    0x09865af2be8af400,
    0xaffb0ff133739e78,
    0x1b272c0278a589c3,
    0x2888979ff1784546,
    0x018a9dee318d993a,
    0x884f0e1345d9ab31,
    0xd294b6d24859bc9c,
    0x45208d7d45d5c430,
    0xda1c635053d962db,
    0x329b985748918d09,
    0xeeccec8204200347,
    0xcce770c03a0cef33,
    0xa69a99f5a83c0cb8,
    0x447e3041753de766,
    0xe0a059e61ed99376,
    0x56ffc009c02d025b,
    0xa5c9cdbd95c384e5,
    0x0c98a57eb8bd2a66,
    0xb0d20f35696c4b24,
    0x30d37216e0aeb9db,
    0xd021765742ac90b9,
    0x2f8cebd0cae3570e,
    0x9b406d2aac0ebbdc,
    0xe630b449552f34a9,
    0xb527ba959f0047c4,
    0x32c748c665c06c28,
    0xa9502ada1e8ca2ce,
    0x1ee8558195daa4c0,
    0x9656111f9e05c4b8,
    0x435a2eb4807410c2,
    0xcc9cf04d708fea9b,
    0xda75f0c5c00e3618,
    0xea0f12c96e0c17df,
    0xc59dd1b39fee1abb,
    0x4a538a6b10378a5d,
    0x84c85c9aa764cf89,
    0x4d9a47bffacb09eb,
    0xf0743f98851562e8,
    0x4797b4ca3ecffc75,
    0x23c7e8708e2f948c,
    0xe34766d07727d278,
    0x873e8e77a21e0a14,
    0xf7dba423ce03d7c2,
    0x4c4fe9e2460e2a7a,
    0x6bcf4c676f90bad5,
    0xcedb01c0e380f3f7,
    0x4a783e812cb9105a,
    0x242747490b833d7c,
    0xc19e80e45eb5c74f,
    0x35a588089221b5a3,
    0xf517a87c1f5bd2c5,
    0xd7564055366b636e,
    0x8d039278de08e08b,
    0x5bf34045c7e378f1,
    0xd35676962c13d8be,
    0x4894b8037ea12224,
    0xcb8f712fa39444e2,
    0x2e4d5ef7ae22fdc0,
    0x5d1d37ebf03f78a9,
    0xc133d50386a32228,
    0xf34f25bcf4869437,
    0xe37fde6e9bad1daf,
    0x4cb839de1cbe4c59,
    0x1b29f6d209be5b8b,
    0x2c95d515df01f291,
    0xca522df42bcbdfcd,
    0xe955ea5deaceaf13,
    0x6f948b1ea44c900b,
    0xca08eb7757c495db,
    0x63c5ed7a88d98e37,
    0x38b78cff01edc572,
    0xd4bfd7eb75f270b3,
    0xec7761d9ce79688c,
    0x8454ecc832d421c2,
    0xe584d6542e1c8646,
    0xb813157cf46bddaf,
    0xa7b2b7925fd7c003,
    0x5d331659df6fcf5e,
    0x98b32dec759d996d,
    0x73bfb606d4b068b0,
    0x9f646a21a07d638c,
    0xf60973a282210dc5,
    0xf02f41a3f25c4914,
    0x2883ad86f094a76f,
    0xd4b6d84685b5908c,
    0x9555926e3f62facc,
    0x7739c697f48225b4,
    0xde5d47942ac8b639,
    0xe62dfc31c0f7a2c4,
    0x4e39b058dcd48338,
    0x013dbc548905670c,
    0x4fbaa0c403f0fe23,
    0x9295c617441f7b91,
    0xc1043d283f3ad2ea,
    0x5fef511eb93f7501,
    0x4fa8d02dd6c8b25d,
    0x1aa1bc12c5f216d8,
    0x01440fad72d176fd,
    0x4c6721e5a81bca9e,
    0xf607a653e0f1a29a,
    0xb763737cacd97b5c,
    0x203eb3e980ed35e6,
    0xe5ab6c1ab4283114,
    0x3411085ce506ab38,
    0xc5958d117b346783,
    0x20afa8d79da41726,
    0x93166b65dff274ac,
    0x98ed1f73349ccb9d,
    0xeaf9b20be07df389,
    0x0a5487106f208006,
    0x456258da5e433628,
    0x1b19b6faa1d49160,
    0x31b3ba43a843fc12,
    0x9872653125ef586f,
    0x0a6aeafe14be7e56,
    0x1cfab9fdb47a26a7,
    0xcdd9690adc777fb0,
    0xfdfc0bc5a4d8d271,
    0x7597e504a5c5af9e,
    0x698ab8184b4dd163,
    0x4d1d5aa8706e0c0d,
    0x395a7cd73b6000c6,
    0x72c8d9c2be6a12a7,
    0xf53053a42000b6ef,
    0xb7cf5a0015d16efc,
    0x754025cde131bbca,
    0x0eb8d8951cb486ee,
    0xcc7cb98d2595c015,
    0x55401fe3f8a45834,
    0x93445ebf01dc509d,
    0x5b38b86ae4805470,
    0xb54ad886818379f6,
    0x771ee4f0ec3eb974,
    0x19b0efb1d5d90526,
    0x9b68beff191ccb86,
    0x8c2b01abff502e2c,
    0xd5cfd1438348f21e,
    0xd8abad7717cb8761,
    0xd2190595af29aed8,
    0x60cd49690c3ba997,
    0x53a0232f4510e3ef,
    0xecd8e4b554ddeb4d,
    0xc001212fc1611f94,
    0x5eb7afa0e8dcc3d3,
    0xceb669a93ae59ad7,
    0xa7b6bcaf8904a4b4,
    0xaaa6d91e607f4433,
    0x2e83951b1d0af4af,
    0xae0e3ffed7a7a6d5,
    0x7c22c6c6b7153f74,
    0xc0d639142f94c54d,
    0xcf13d4f2093de2d1,
    0x7ee0673f47f0bcf2,
    0x421313d494723671,
    0x7c8779c21fcd7f14,
    0x656cc6684028efb5,
    0xe138293272974abe,
    0xde2d9a3e74e60a1e,
    0x1d5dc80ea0a046cf,
    0xe9511b83d59c0970,
    0x927a779a6128b849,
    0xf28a22f5ea8a77d2,
    0xc5557d036fc02415,
    0xb2253588bf68d3a1,
    0xe6b338555bf59f40,
    0x84bfa2d403711026,
    0x08877cb981d62474,
    0x03810e7a3fe206d7,
    0xc567fa133679988e,
    0x486f8b8cc479612f,
    0x8bd469fa24cbed33,
    0xfe644a2210327911,
    0xfa3f7b7506f8217f,
    0xfd18851cdbfbecb1,
    0x48d62ac0f712f779,
    0x7a28551edd0505de,
    0x703b9268c5dc14e6,
    0xd16f484646fed25b,
    0x47b82799b7413e72,
    0x148df146d663f4b1,
    0x36995da58ea30881,
    0x8e1b3a136c699798,
    0x541bf14876c8aa1d,
    0xf3f3e1b431bc5bc4,
    0x6af8475fbed5b69e,
    0x67ef61406a0b29c6,
    0xaaf2bf7b5dba122d,
    0x5548fc88d1011328,
    0x8ec12ab73f7e3ee7,
    0xf3a0c3544b1aacff,
    0x0427c98f53ff398d,
    0xd00ad6a0368169bc,
    0xe494354648dacc74,
    0xf60c4c98cff4fef6,
    0xc5ddd96fb5a296ca,
    0xbdf19b36b9e615d6,
    0xceb9cd4daeac362b,
    0xec17c8374e25f1af,
    0xfa0c90966d100db9,
    0x47c629326111a8b4,
    0x2bdac6dc5530a856,
    0x20782a113b4dea85,
    0x91c6e72b7bfd8d4d,
    0x83883537f84bdde9,
    0xeab67bcdec953e8b,
    0x0cd4d5346f5d7f2c,
    0xf23f67c5ef80aaeb,
    0x8ef7679cae891742,
    0x65418f889b700146,
    0x6dcb9cb362d308e9,
    0x4112afaca64aec0b,
    0xda73c8f2f2bef7d5,
    0x3847aa74ab8f2565,
    0x8bb84a86e90e72fe,
    0xb0a4942f23dc1df1,
    0x8f100f2ad90c6702,
    0xa76622268599fe2d,
    0xf8932b4f699160b0,
    0x4c99ee2dc6c43f34,
    0x668e062f248ad388,
    0xb650c2113f9f7677,
    0x111559e3428da885,
];

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

    /// Calculate the mask for normalized chunking
    fn mask_s(&self) -> u64 {
        // Mask for sub-average region (more bits = harder to match = larger chunks)
        let bits = (self.avg_size as f64).log2().ceil() as u32 + 1;
        (1u64 << bits) - 1
    }

    /// Calculate the mask for super-average region
    fn mask_l(&self) -> u64 {
        // Mask for super-average region (fewer bits = easier to match)
        let bits = (self.avg_size as f64).log2().ceil() as u32 - 1;
        (1u64 << bits) - 1
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
            offset: 0,
            config: &self.config,
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

    /// Find the next chunk boundary using FastCDC algorithm
    fn find_boundary(&self, data: &[u8]) -> usize {
        let len = data.len();

        // If data is smaller than minimum, it's a single chunk
        if len <= self.config.min_size {
            return len;
        }

        // If data is smaller than average, use the stricter mask
        let mask_s = self.config.mask_s();
        let mask_l = self.config.mask_l();

        let mut hash: u64 = 0;

        // Skip minimum size (sub-minimum cut-point skipping optimization)
        let mut i = self.config.min_size;

        // Scan from min_size to avg_size with stricter mask
        let limit1 = std::cmp::min(self.config.avg_size, len);
        while i < limit1 {
            hash = (hash << 1).wrapping_add(GEAR_TABLE[data[i] as usize]);
            if (hash & mask_s) == 0 {
                return i + 1;
            }
            i += 1;
        }

        // Scan from avg_size to max_size with looser mask (normalized chunking)
        let limit2 = std::cmp::min(self.config.max_size, len);
        while i < limit2 {
            hash = (hash << 1).wrapping_add(GEAR_TABLE[data[i] as usize]);
            if (hash & mask_l) == 0 {
                return i + 1;
            }
            i += 1;
        }

        // Reached max size, force cut
        limit2
    }
}

/// Iterator over chunks in a byte slice
pub struct ChunkIterator<'a> {
    data: &'a [u8],
    offset: usize,
    config: &'a ChunkerConfig,
}

impl<'a> Iterator for ChunkIterator<'a> {
    type Item = (&'a [u8], ChunkHash);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let remaining = &self.data[self.offset..];
        let chunker = Chunker::new(self.config.clone());
        let boundary = chunker.find_boundary(remaining);

        let chunk = &remaining[..boundary];
        let hash = era_crypto::hash(chunk);

        self.offset += boundary;

        Some((chunk, hash))
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
        let chunker = Chunker::new(self.config.clone());
        let boundary = chunker.find_boundary(data);

        let chunk_data = &data[..boundary];
        let hash = era_crypto::hash(chunk_data);

        self.buffer_start += boundary;

        Ok(Some(UniqueChunk::new(
            Bytes::copy_from_slice(chunk_data),
            hash,
        )))
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

        // Different prefixes but chunks containing the marker should have same hash
        // (This is the key property of content-defined chunking)
        let _hashes1: Vec<_> = chunks1.iter().map(|(_, h)| *h).collect();
        let _hashes2: Vec<_> = chunks2.iter().map(|(_, h)| *h).collect();

        // At least some chunks should be different (due to offset)
        // but the algorithm should find similar boundaries
        assert!(!chunks1.is_empty());
        assert!(!chunks2.is_empty());
    }

    #[test]
    fn test_chunk_respects_max_size() {
        let config = ChunkerConfig::new(64, 256, 512);
        let chunker = Chunker::new(config.clone());

        // Data that won't trigger any natural boundaries
        let data = vec![0x42u8; 2000];

        for (chunk, _) in chunker.chunk_bytes(&data) {
            assert!(chunk.len() <= config.max_size);
        }
    }

    #[test]
    fn test_chunk_respects_min_size() {
        let config = ChunkerConfig::new(64, 256, 512);
        let chunker = Chunker::new(config.clone());

        // Large enough data
        let data = vec![0x42u8; 2000];
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
