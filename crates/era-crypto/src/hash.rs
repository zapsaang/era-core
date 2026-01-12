//! Blake3 hashing utilities.

use era_common::ChunkHash;
use std::io::Read;

/// Hash data using Blake3
pub fn hash(data: &[u8]) -> ChunkHash {
    let hash = blake3::hash(data);
    ChunkHash::from_bytes(*hash.as_bytes())
}

/// Hash data from a reader using Blake3
pub fn hash_reader<R: Read>(mut reader: R) -> std::io::Result<ChunkHash> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let hash = hasher.finalize();
    Ok(ChunkHash::from_bytes(*hash.as_bytes()))
}

/// Streaming hasher for incremental hashing
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    /// Create a new hasher
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Update the hasher with more data
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> ChunkHash {
        let hash = self.inner.finalize();
        ChunkHash::from_bytes(*hash.as_bytes())
    }

    /// Finalize and reset, allowing reuse
    pub fn finalize_reset(&mut self) -> ChunkHash {
        let hash = self.inner.finalize();
        self.inner.reset();
        ChunkHash::from_bytes(*hash.as_bytes())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_empty() {
        let h = hash(b"");
        // Blake3 hash of empty string
        assert!(!h.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_hash_deterministic() {
        let data = b"Hello, ERA!";
        let h1 = hash(data);
        let h2 = hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hasher_streaming() {
        let data = b"Hello, ERA!";
        let direct = hash(data);

        let mut hasher = Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"ERA!");
        let streamed = hasher.finalize();

        assert_eq!(direct, streamed);
    }
}
