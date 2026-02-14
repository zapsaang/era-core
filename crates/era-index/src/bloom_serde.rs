//! Bloom filter serialization using rkyv
//!
//! The `bloomfilter` crate only supports serde, so we create a custom
//! rkyv-serializable wrapper that can convert to/from `Bloom<T>`.

use bloomfilter::Bloom;
use era_common::{ChunkHash, EraError, Result};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use std::hash::Hash;

/// Serializable representation of a Bloom filter
///
/// This struct captures the essential state of a `Bloom<T>` filter
/// in a format that can be serialized with rkyv.
#[derive(Archive, RkyvDeserialize, RkyvSerialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct BloomFilterData {
    /// The bit vector as raw bytes
    pub bitmap: Vec<u8>,
    /// Number of bits in the filter
    pub bitmap_bits: u64,
    /// Number of hash functions (k)
    pub k_num: u32,
    /// SipHasher keys for reproducible hashing
    pub sip_keys: [(u64, u64); 2],
}

impl BloomFilterData {
    /// Create from a Bloom filter
    pub fn from_bloom<T: Hash>(bloom: &Bloom<T>) -> Self {
        // Get the internal bitmap as bytes
        let bitmap = bloom.bitmap();
        let bitmap_bits = bloom.number_of_bits();
        let k_num = bloom.number_of_hash_functions();
        let sip_keys = bloom.sip_keys();

        Self {
            bitmap,
            bitmap_bits,
            k_num,
            sip_keys,
        }
    }

    /// Convert back to a Bloom filter
    pub fn to_bloom<T: Hash>(&self) -> Bloom<T> {
        Bloom::from_existing(&self.bitmap, self.bitmap_bits, self.k_num, self.sip_keys)
    }

    /// Serialize to bytes using rkyv
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        rkyv::to_bytes::<_, 4096>(self)
            .map(|bytes| bytes.to_vec())
            .map_err(|e| EraError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes using rkyv (check_archived_root + deserialize)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let archived = rkyv::check_archived_root::<Self>(bytes)
            .map_err(|e| EraError::Deserialization(e.to_string()))?;
        Ok(match archived.deserialize(&mut rkyv::Infallible) {
            Ok(val) => val,
            Err(never) => match never {},
        })
    }
}

/// Serialize a Bloom<ChunkHash> to bytes
pub fn serialize_bloom(bloom: &Bloom<ChunkHash>) -> Result<Vec<u8>> {
    BloomFilterData::from_bloom(bloom).to_bytes()
}

/// Deserialize a Bloom<ChunkHash> from bytes
pub fn deserialize_bloom(bytes: &[u8]) -> Result<Bloom<ChunkHash>> {
    Ok(BloomFilterData::from_bytes(bytes)?.to_bloom())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(value: u64) -> ChunkHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        ChunkHash::from_bytes(bytes)
    }

    #[test]
    fn test_bloom_roundtrip() {
        let mut bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(1000, 0.01);

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
        let bloom: Bloom<ChunkHash> = Bloom::new_for_fp_rate(100, 0.01);
        let data = BloomFilterData::from_bloom(&bloom);

        let bytes = data.to_bytes().unwrap();
        let restored = BloomFilterData::from_bytes(&bytes).unwrap();

        assert_eq!(data.bitmap_bits, restored.bitmap_bits);
        assert_eq!(data.k_num, restored.k_num);
        assert_eq!(data.sip_keys, restored.sip_keys);
        assert_eq!(data.bitmap, restored.bitmap);
    }
}
