//! Volume footer structure.

use era_common::{EraError, Result};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Magic bytes for footer: "ERAF"
pub const FOOTER_MAGIC: [u8; 4] = [0x45, 0x52, 0x41, 0x46];

/// Footer size (128 bytes for atomic write)
pub const FOOTER_SIZE: usize = 128;

/// Current footer version
pub const FOOTER_VERSION: u16 = 3;

/// Volume footer - stored at the end of each volume
///
/// The footer is designed to be exactly 128 bytes to fit within a single
/// disk sector, ensuring atomic writes on most storage devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Footer {
    /// Magic bytes: "ERAF"
    pub magic: [u8; 4],
    /// Footer version
    pub version: u16,
    /// Status flags
    pub flags: u16,
    /// Offset of the data region end
    pub data_end_offset: u64,
    /// Number of blocks in this volume
    pub block_count: u32,
    /// Sequence number (monotonically increasing)
    pub sequence_number: u64,
    /// Offset of the catalog block (for fast lookup)
    pub catalog_offset: u64,
    /// Size of the catalog block (encrypted size)
    pub catalog_size: u32,
    /// Block ID of the catalog (for correct decryption)
    pub catalog_block_id: u32,
    /// Blake3 checksum of the footer (excluding this field)
    pub checksum: [u8; 32],
    /// Reserved for future use (reduced from 48 to 44 bytes)
    #[serde(with = "BigArray")]
    pub _reserved: [u8; 44],
}

impl Footer {
    /// Create a new footer
    pub fn new(data_end_offset: u64, block_count: u32, sequence_number: u64) -> Self {
        Self::with_catalog(data_end_offset, block_count, sequence_number, 0, 0, 0)
    }

    /// Create a new footer with catalog location
    pub fn with_catalog(
        data_end_offset: u64,
        block_count: u32,
        sequence_number: u64,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
    ) -> Self {
        let mut footer = Self {
            magic: FOOTER_MAGIC,
            version: FOOTER_VERSION,
            flags: 0,
            data_end_offset,
            block_count,
            sequence_number,
            catalog_offset,
            catalog_size,
            catalog_block_id,
            checksum: [0u8; 32],
            _reserved: [0u8; 44],
        };

        footer.update_checksum();
        footer
    }

    /// Check if catalog location is available
    pub fn has_catalog_location(&self) -> bool {
        self.catalog_offset > 0 && self.catalog_size > 0
    }

    /// Update the checksum field
    fn update_checksum(&mut self) {
        // Zero out checksum before calculating
        self.checksum = [0u8; 32];

        // Serialize without checksum
        // Note: This serialization should never fail for a valid Footer struct
        let data = era_common::serialize(self).expect("Footer serialization should never fail");

        // Calculate Blake3 hash
        let hash = blake3::hash(&data);
        self.checksum = *hash.as_bytes();
    }

    /// Verify the checksum
    pub fn verify_checksum(&self) -> bool {
        let mut copy = self.clone();
        let expected = copy.checksum;
        copy.checksum = [0u8; 32];

        // Note: This serialization should never fail for a valid Footer struct
        let Ok(data) = era_common::serialize(&copy) else {
            return false; // If we can't serialize, checksum is invalid
        };
        let hash = blake3::hash(&data);

        hash.as_bytes() == &expected
    }

    /// Serialize the footer to bytes
    pub fn to_bytes(&self) -> Result<[u8; FOOTER_SIZE]> {
        let data = era_common::serialize(self)?;

        if data.len() > FOOTER_SIZE {
            return Err(EraError::other("Footer serialization too large"));
        }

        let mut result = [0u8; FOOTER_SIZE];
        result[..data.len()].copy_from_slice(&data);

        Ok(result)
    }

    /// Deserialize a footer from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < FOOTER_SIZE {
            return Err(EraError::CorruptedFooter("Footer too small".to_string()));
        }

        let footer: Self = era_common::deserialize(&data[..FOOTER_SIZE])?;

        // Validate magic
        if footer.magic != FOOTER_MAGIC {
            return Err(EraError::CorruptedFooter("Invalid magic".to_string()));
        }

        // Validate checksum
        if !footer.verify_checksum() {
            return Err(EraError::CorruptedFooter("Checksum mismatch".to_string()));
        }

        Ok(footer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_roundtrip() {
        let footer = Footer::new(1024 * 1024, 10, 1);

        let bytes = footer.to_bytes().unwrap();
        assert_eq!(bytes.len(), FOOTER_SIZE);

        let restored = Footer::from_bytes(&bytes).unwrap();
        assert_eq!(restored.magic, FOOTER_MAGIC);
        assert_eq!(restored.data_end_offset, 1024 * 1024);
        assert_eq!(restored.block_count, 10);
    }

    #[test]
    fn test_checksum_verification() {
        let footer = Footer::new(1024, 5, 1);
        assert!(footer.verify_checksum());

        // Tamper with the footer
        let mut tampered = footer.clone();
        tampered.block_count = 100;
        assert!(!tampered.verify_checksum());
    }

    #[test]
    fn test_corrupted_magic() {
        let mut footer = Footer::new(1024, 5, 1);
        footer.magic = [0, 0, 0, 0];
        footer.update_checksum();

        let bytes = footer.to_bytes().unwrap();
        let result = Footer::from_bytes(&bytes);

        assert!(result.is_err());
    }
}
