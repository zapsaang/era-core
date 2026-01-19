//! Volume footer structure.

use era_common::proto::Footer as ProtoFooter;
use era_common::{EraError, Result};
use prost::Message;

/// Magic bytes for footer: "ERAF"
pub const FOOTER_MAGIC: [u8; 4] = [0x45, 0x52, 0x41, 0x46];

/// Footer size (128 bytes for atomic write)
pub const FOOTER_SIZE: usize = 128;

/// Current footer version
pub const FOOTER_VERSION: u16 = 4;

/// Volume footer - stored at the end of each volume
///
/// The footer is designed to be exactly 128 bytes to fit within a single
/// disk sector, ensuring atomic writes on most storage devices.
#[derive(Debug, Clone, PartialEq)]
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
    /// Offset of the last checkpoint (for atomic updates)
    pub last_checkpoint_offset: u64,
    /// Offset of embedded LSM manifest block
    pub lsm_manifest_offset: u64,
    /// Size of embedded LSM manifest block
    pub lsm_manifest_size: u32,
    /// Block ID of embedded LSM manifest
    pub lsm_manifest_block_id: u32,
    /// Blake3 checksum of the footer (excluding this field)
    pub checksum: [u8; 32],
}

impl Footer {
    /// Create a new footer
    pub fn new(data_end_offset: u64, block_count: u32, sequence_number: u64) -> Self {
        Self::with_catalog(
            data_end_offset,
            block_count,
            sequence_number,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    }

    /// Create a new footer with catalog location
    #[allow(clippy::too_many_arguments)]
    pub fn with_catalog(
        data_end_offset: u64,
        block_count: u32,
        sequence_number: u64,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u32,
        last_checkpoint_offset: u64,
        lsm_manifest_offset: u64,
        lsm_manifest_size: u32,
        lsm_manifest_block_id: u32,
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
            last_checkpoint_offset,
            lsm_manifest_offset,
            lsm_manifest_size,
            lsm_manifest_block_id,
            checksum: [0u8; 32],
        };

        footer.update_checksum();
        footer
    }

    /// Check if catalog location is available
    pub fn has_catalog_location(&self) -> bool {
        self.catalog_offset > 0 && self.catalog_size > 0
    }

    /// Check if embedded LSM manifest location is available
    pub fn has_lsm_manifest(&self) -> bool {
        self.lsm_manifest_offset > 0 && self.lsm_manifest_size > 0
    }

    fn to_proto(&self) -> ProtoFooter {
        ProtoFooter {
            magic: self.magic.to_vec(),
            version: self.version as u32,
            flags: self.flags as u32,
            data_end_offset: self.data_end_offset,
            block_count: self.block_count,
            sequence_number: self.sequence_number,
            catalog_offset: self.catalog_offset,
            catalog_size: self.catalog_size,
            catalog_block_id: self.catalog_block_id,
            last_checkpoint_offset: self.last_checkpoint_offset,
            lsm_manifest_offset: self.lsm_manifest_offset,
            lsm_manifest_size: self.lsm_manifest_size,
            lsm_manifest_block_id: self.lsm_manifest_block_id,
            checksum: self.checksum.to_vec(),
        }
    }

    fn from_proto(proto: ProtoFooter) -> Result<Self> {
        let magic: [u8; 4] = proto.magic.try_into().unwrap_or(FOOTER_MAGIC);
        let checksum: [u8; 32] = proto.checksum.try_into().unwrap_or([0u8; 32]);

        Ok(Self {
            magic,
            version: proto.version as u16,
            flags: proto.flags as u16,
            data_end_offset: proto.data_end_offset,
            block_count: proto.block_count,
            sequence_number: proto.sequence_number,
            catalog_offset: proto.catalog_offset,
            catalog_size: proto.catalog_size,
            catalog_block_id: proto.catalog_block_id,
            last_checkpoint_offset: proto.last_checkpoint_offset,
            lsm_manifest_offset: proto.lsm_manifest_offset,
            lsm_manifest_size: proto.lsm_manifest_size,
            lsm_manifest_block_id: proto.lsm_manifest_block_id,
            checksum,
        })
    }

    /// Update the checksum field
    fn update_checksum(&mut self) {
        // Zero out checksum for calculation
        self.checksum = [0u8; 32];
        let mut proto = self.to_proto();
        // Ensure proto checksum is empty for calculation
        proto.checksum = Vec::new();

        let data = proto.encode_to_vec();

        // Calculate Blake3 hash
        let hash = blake3::hash(&data);
        self.checksum = *hash.as_bytes();
    }

    /// Verify the checksum
    pub fn verify_checksum(&self) -> bool {
        let mut proto = self.to_proto();
        let expected = proto.checksum.clone();

        // Zero out checksum for recalculation
        proto.checksum = Vec::new();

        let data = proto.encode_to_vec();
        let hash = blake3::hash(&data);

        hash.as_bytes().as_slice() == expected.as_slice()
    }

    /// Serialize the footer to bytes
    pub fn to_bytes(&self) -> Result<[u8; FOOTER_SIZE]> {
        let proto = self.to_proto();
        // Since update_checksum uses empty checksum, we must ensure self.checksum is set before calling to_proto
        // But to_bytes is supposedly called on a valid valid Footer.
        // Wait, update_checksum sets self.checksum. to_proto reads it.
        // So proto.checksum will be set.

        let data = proto.encode_to_vec();

        // Format: [u32 len] [protobuf bytes] [padding]
        // Length of length prefix = 4 bytes.
        let payload_len = data.len();
        if payload_len + 4 > FOOTER_SIZE {
            return Err(EraError::Serialization(format!(
                "Footer serialization too large: {} bytes > {}",
                payload_len + 4,
                FOOTER_SIZE
            )));
        }

        let mut result = [0u8; FOOTER_SIZE];
        // Write length
        result[0..4].copy_from_slice(&(payload_len as u32).to_le_bytes());
        // Write data
        result[4..4 + payload_len].copy_from_slice(&data);

        Ok(result)
    }

    /// Deserialize a footer from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < FOOTER_SIZE {
            return Err(EraError::CorruptedFooter("Footer too small".to_string()));
        }

        // Read length
        let len_bytes: [u8; 4] = data[0..4].try_into().unwrap();
        let payload_len = u32::from_le_bytes(len_bytes) as usize;

        if payload_len + 4 > FOOTER_SIZE {
            return Err(EraError::CorruptedFooter(format!(
                "Invalid footer length: {}",
                payload_len
            )));
        }

        let proto_data = &data[4..4 + payload_len];
        let proto = ProtoFooter::decode(proto_data).map_err(|e| {
            EraError::Deserialization(format!("Failed to decode footer proto: {}", e))
        })?;

        let footer = Self::from_proto(proto)?;

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
