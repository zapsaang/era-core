//! Bloom filter serialization using rkyv
//!
//! The `bloomfilter` crate v3 uses a self-describing binary format (header
//! embeds k_num + seed), so we store the opaque bytes from `Bloom::to_bytes()`
//! inside an rkyv-serializable wrapper.

use bloomfilter::Bloom;
use era_common::{ChunkHash, EraError, Result};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use std::hash::Hash;

/// V25-F2 fix: consolidate MAX_BLOOM_BITMAP_SIZE to single module-level definition.
/// Maximum allowed bloom data size in bytes (128 MiB). Used by both
/// `from_bytes()` and `validate_archived()` to reject oversized bitmaps.
const MAX_BLOOM_DATA_SIZE: usize = 128 * 1024 * 1024;

/// Serializable representation of a Bloom filter
///
/// This struct captures the opaque bytes from `Bloom::to_bytes()` (bloomfilter v3)
/// in a format that can be serialized with rkyv.
///
/// V23-F1 fix: Fields are `pub(crate)` to prevent external consumers from
/// bypassing the validated `new()` constructor via struct literal construction.
/// Use `new()` or `from_bytes()` to create instances.
#[derive(Archive, RkyvDeserialize, RkyvSerialize, Debug, Clone, bytecheck::CheckBytes)]
pub struct BloomFilterData {
    /// Schema version for future evolution (2 = bloomfilter v3 format)
    pub(crate) version: u8,
    /// Opaque bloom filter bytes from `Bloom::to_bytes()` (self-describing format
    /// with embedded header containing k_num and seed)
    pub(crate) data: Vec<u8>,
}

impl BloomFilterData {
    /// Validate bloom filter data integrity.
    ///
    /// Checks that data is not empty and within size limits.
    fn validate(&self) -> Result<()> {
        if self.data.is_empty() {
            return Err(EraError::IndexError(
                "BloomFilterData: data is empty".into(),
            ));
        }
        if self.data.len() > MAX_BLOOM_DATA_SIZE {
            return Err(EraError::IndexError(format!(
                "BloomFilterData: data too large: {} bytes (max {})",
                self.data.len(),
                MAX_BLOOM_DATA_SIZE
            )));
        }
        Ok(())
    }

    /// Create a validated BloomFilterData from raw bloom bytes.
    ///
    /// The `data` parameter should be the output of `Bloom::to_bytes()`.
    /// Returns an error if data is empty or exceeds size limits.
    pub fn new(data: Vec<u8>) -> Result<Self> {
        let bfd = Self { version: 2, data };
        bfd.validate()?;
        Ok(bfd)
    }

    /// Accessor for the schema version.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Accessor for the raw bloom data bytes.
    #[must_use]
    pub fn data_ref(&self) -> &[u8] {
        &self.data
    }

    /// Create from a Bloom filter.
    ///
    /// Extracts the self-describing bytes via `Bloom::to_bytes()`.
    pub(crate) fn from_bloom<T: Hash>(bloom: &Bloom<T>) -> Result<Self> {
        let data = bloom.to_bytes();
        Self::new(data)
    }

    /// Convert back to a Bloom filter.
    ///
    /// Reconstructs the bloom filter from the stored opaque bytes.
    pub fn to_bloom<T: Hash>(&self) -> Result<Bloom<T>> {
        self.validate()?;
        Bloom::from_bytes(self.data.clone())
            .map_err(|e| EraError::IndexError(format!("BloomFilterData: to_bloom failed: {}", e)))
    }

    /// Serialize to bytes using rkyv.
    ///
    /// V23-F4 fix: `.to_vec()` copies the `rkyv::AlignedVec` into a standard
    /// `Vec<u8>`. This copy is necessary because `AlignedVec` uses a different
    /// allocator alignment and does not implement `Into<Vec<u8>>`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|bytes| bytes.to_vec())
            .map_err(|e| EraError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes using rkyv (check_archived_root + deserialize).
    ///
    /// Validates the schema version on the archived (zero-copy) view
    /// BEFORE performing the full deserialization.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let archived = rkyv::access::<rkyv::Archived<Self>, rkyv::rancor::Error>(bytes)
            .map_err(|e| EraError::Deserialization(e.to_string()))?;
        // Version check: accept version 2 (bloomfilter v3 format)
        if archived.version != 2 {
            return Err(EraError::IndexError(format!(
                "unsupported bloom filter version: {}",
                archived.version
            )));
        }
        // Pre-deser size check
        Self::validate_archived(archived)?;
        let result = rkyv::deserialize::<Self, rkyv::rancor::Error>(archived)
            .map_err(|e| EraError::Deserialization(e.to_string()))?;
        result.validate()?;
        Ok(result)
    }

    /// Pre-deserialize size validation on archived (zero-copy) view.
    fn validate_archived(archived: &ArchivedBloomFilterData) -> Result<()> {
        if archived.data.len() > MAX_BLOOM_DATA_SIZE {
            return Err(EraError::IndexError(format!(
                "bloom data too large (pre-deser): {} B (max {})",
                archived.data.len(),
                MAX_BLOOM_DATA_SIZE
            )));
        }
        if archived.data.is_empty() {
            return Err(EraError::IndexError("bloom data empty (pre-deser)".into()));
        }
        Ok(())
    }
}

/// Serialize a Bloom<ChunkHash> to bytes
pub fn serialize_bloom(bloom: &Bloom<ChunkHash>) -> Result<Vec<u8>> {
    BloomFilterData::from_bloom(bloom)?.to_bytes()
}

/// Deserialize a Bloom<ChunkHash> from bytes
pub fn deserialize_bloom(bytes: &[u8]) -> Result<Bloom<ChunkHash>> {
    BloomFilterData::from_bytes(bytes)?.to_bloom()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_bloom_roundtrip() {
        let mut bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(1000, 0.01).unwrap();

        // Insert some hashes
        for i in 0..100 {
            bloom.set(&test_hash(i));
        }

        // Serialize
        let bytes = serialize_bloom(&bloom).unwrap();

        // Deserialize
        let restored = deserialize_bloom(&bytes).unwrap();

        // Verify all inserted hashes are found
        for i in 0..100 {
            assert!(restored.check(&test_hash(i)), "Hash {} not found", i);
        }

        // Verify non-inserted hashes are mostly not found (allowing for FP rate)
        let mut false_positives = 0;
        for i in 100..200 {
            if restored.check(&test_hash(i)) {
                false_positives += 1;
            }
        }
        // Should be < 5% false positives (we set 1% FP rate)
        assert!(
            false_positives < 5,
            "Too many false positives: {}",
            false_positives
        );
    }

    #[test]
    fn test_bloom_data_serialization() {
        let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(100, 0.01).unwrap();
        let data = BloomFilterData::from_bloom(&bloom).unwrap();

        let bytes = data.to_bytes().unwrap();
        let restored = BloomFilterData::from_bytes(&bytes).unwrap();

        assert_eq!(data.version, restored.version);
        assert_eq!(data.data, restored.data);
    }

    #[test]
    fn test_bloom_version_validation() {
        // Create a valid BloomFilterData
        let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(100, 0.01).unwrap();
        let mut data = BloomFilterData::from_bloom(&bloom).unwrap();

        // Serialize with version 2
        let bytes = data.to_bytes().unwrap();

        // Verify it deserializes successfully
        let result = BloomFilterData::from_bytes(&bytes);
        assert!(result.is_ok());

        // Now create invalid data with version 3
        data.version = 3;
        let bytes = data.to_bytes().unwrap();

        // Verify deserialization rejects version 3
        let result = BloomFilterData::from_bytes(&bytes);
        assert!(result.is_err());
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                err_msg.contains("unsupported bloom filter version"),
                "Expected version error, got: {}",
                err_msg
            );
        }
    }
}
