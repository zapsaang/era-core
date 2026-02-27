//! Volume footer structure.
//!
//! The footer uses a fixed-length binary format to guarantee atomic writes
//! within a single 128-byte disk sector. This is critical for crash consistency.

use era_common::{EraError, Result};

/// Magic bytes for footer: "ERAF"
pub const FOOTER_MAGIC: [u8; 4] = [0x45, 0x52, 0x41, 0x46];

/// Domain separation prefix for footer checksum.
/// Prevents cross-protocol hash collisions.
const FOOTER_DOMAIN: &[u8] = b"ERAFv1-footer\0";

/// Footer size (128 bytes for atomic write within a single disk sector)
pub const FOOTER_SIZE: usize = 128;

/// Backup footer gap size (reserved after header for backup footer)
/// Layout: [Header 4096] [Backup Footer Gap 128] [Data...] [Backup Header 4096] [Primary Footer 128]
pub const BACKUP_FOOTER_GAP: usize = FOOTER_SIZE;

/// Footer format version
pub const FOOTER_VERSION: u8 = 1;

/// Volume footer - stored at the end of each volume
///
/// The footer is designed to be exactly 128 bytes to fit within a single
/// disk sector, ensuring atomic writes on most storage devices.
///
/// ## Binary Layout (128 bytes, fixed-length)
///
/// | Offset | Size | Field                    |
/// |--------|------|--------------------------|
/// | 0      | 4    | magic ("ERAF")           |
/// | 4      | 1    | version                  |
/// | 5      | 1    | reserved1                |
/// | 6      | 2    | flags                    |
/// | 8      | 8    | data_end_offset          |
/// | 16     | 4    | block_count              |
/// | 20     | 4    | reserved2                |
/// | 24     | 8    | sequence_number          |
/// | 32     | 8    | catalog_offset           |
/// | 40     | 4    | catalog_size             |
/// | 44     | 4    | catalog_block_id         |
/// | 48     | 8    | last_checkpoint_offset   |
/// | 56     | 4    | last_checkpoint_block_id |
/// | 60     | 4    | reserved3                |
/// | 64     | 8    | index_offset             |
/// | 72     | 4    | index_size               |
/// | 76     | 4    | index_block_id           |
/// | 80     | 8    | backup_header_offset     |
/// | 88     | 8    | reserved4                |
/// | 96     | 32   | checksum (Blake3)        |
/// | **128**|      | **Total**                |
///
#[derive(Debug, Clone, PartialEq)]
pub struct Footer {
    /// Magic bytes: "ERAF"
    pub magic: [u8; 4],
    /// Format version
    pub version: u8,
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
    /// Block ID of the last checkpoint (for direct decryption)
    pub last_checkpoint_block_id: u32,
    /// Offset of the index block
    pub index_offset: u64,
    /// Size of the index block
    pub index_size: u32,
    /// Block ID of the index
    pub index_block_id: u32,
    /// Offset of the backup header (for redundancy layout)
    pub backup_header_offset: u64,
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
            0,
            0, // backup_header_offset
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
        last_checkpoint_block_id: u32,
        index_offset: u64,
        index_size: u32,
        index_block_id: u32,
        backup_header_offset: u64,
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
            last_checkpoint_block_id,
            index_offset,
            index_size,
            index_block_id,
            backup_header_offset,
            checksum: [0u8; 32],
        };

        footer.update_checksum();
        footer
    }

    /// Create a builder for constructing a Footer with named fields.
    ///
    /// Preferred over `with_catalog` for readability.
    pub fn builder(data_end_offset: u64, block_count: u32, sequence_number: u64) -> FooterBuilder {
        FooterBuilder {
            data_end_offset,
            block_count,
            sequence_number,
            catalog_offset: 0,
            catalog_size: 0,
            catalog_block_id: 0,
            last_checkpoint_offset: 0,
            last_checkpoint_block_id: 0,
            index_offset: 0,
            index_size: 0,
            index_block_id: 0,
            backup_header_offset: 0,
        }
    }

    /// Check if catalog location is available
    pub fn has_catalog_location(&self) -> bool {
        self.catalog_offset > 0 && self.catalog_size > 0
    }

    /// Check if index location is available
    pub fn has_index(&self) -> bool {
        self.index_offset > 0 && self.index_size > 0
    }

    /// Update the checksum field (domain-separated Blake3)
    fn update_checksum(&mut self) {
        // Zero out checksum for calculation
        self.checksum = [0u8; 32];

        // Serialize without checksum (first 96 bytes)
        let mut data = [0u8; FOOTER_SIZE - 32];
        self.write_fields_to(&mut data);

        // Calculate Blake3 hash with domain separation prefix
        let mut hasher = blake3::Hasher::new();
        hasher.update(FOOTER_DOMAIN);
        hasher.update(&data);
        self.checksum = *hasher.finalize().as_bytes();
    }

    /// Verify the checksum (domain-separated Blake3)
    pub fn verify_checksum(&self) -> bool {
        // Serialize without checksum (first 96 bytes)
        let mut data = [0u8; FOOTER_SIZE - 32];
        self.write_fields_to(&mut data);

        let mut hasher = blake3::Hasher::new();
        hasher.update(FOOTER_DOMAIN);
        hasher.update(&data);
        hasher.finalize().as_bytes() == &self.checksum
    }

    /// Write all fields except checksum to a buffer
    fn write_fields_to(&self, buf: &mut [u8; FOOTER_SIZE - 32]) {
        // Offset 0: magic (4 bytes)
        buf[0..4].copy_from_slice(&self.magic);
        // Offset 4: version (1 byte)
        buf[4] = self.version;
        // Offset 5: reserved1 (1 byte)
        buf[5] = 0;
        // Offset 6: flags (2 bytes)
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        // Offset 8: data_end_offset (8 bytes)
        buf[8..16].copy_from_slice(&self.data_end_offset.to_le_bytes());
        // Offset 16: block_count (4 bytes)
        buf[16..20].copy_from_slice(&self.block_count.to_le_bytes());
        // Offset 20: reserved2 (4 bytes)
        buf[20..24].copy_from_slice(&0u32.to_le_bytes());
        // Offset 24: sequence_number (8 bytes)
        buf[24..32].copy_from_slice(&self.sequence_number.to_le_bytes());
        // Offset 32: catalog_offset (8 bytes)
        buf[32..40].copy_from_slice(&self.catalog_offset.to_le_bytes());
        // Offset 40: catalog_size (4 bytes)
        buf[40..44].copy_from_slice(&self.catalog_size.to_le_bytes());
        // Offset 44: catalog_block_id (4 bytes)
        buf[44..48].copy_from_slice(&self.catalog_block_id.to_le_bytes());
        // Offset 48: last_checkpoint_offset (8 bytes)
        buf[48..56].copy_from_slice(&self.last_checkpoint_offset.to_le_bytes());
        // Offset 56: last_checkpoint_block_id (4 bytes)
        buf[56..60].copy_from_slice(&self.last_checkpoint_block_id.to_le_bytes());
        // Offset 60: reserved3 (4 bytes)
        buf[60..64].copy_from_slice(&0u32.to_le_bytes());
        // Offset 64: index_offset (8 bytes)
        buf[64..72].copy_from_slice(&self.index_offset.to_le_bytes());
        // Offset 72: index_size (4 bytes)
        buf[72..76].copy_from_slice(&self.index_size.to_le_bytes());
        // Offset 76: index_block_id (4 bytes)
        buf[76..80].copy_from_slice(&self.index_block_id.to_le_bytes());
        // Offset 80: backup_header_offset (8 bytes)
        buf[80..88].copy_from_slice(&self.backup_header_offset.to_le_bytes());
        // Offset 88: reserved4 (8 bytes)
        buf[88..96].copy_from_slice(&0u64.to_le_bytes());
    }

    /// Read fields from a buffer (excluding checksum)
    fn read_fields_from(buf: &[u8; FOOTER_SIZE - 32]) -> Result<Self> {
        Ok(Self {
            magic: buf[0..4].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer magic slice".into()))?,
            version: buf[4],
            flags: u16::from_le_bytes(buf[6..8].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer flags slice".into()))?),
            data_end_offset: u64::from_le_bytes(buf[8..16].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer data_end_offset slice".into()))?),
            block_count: u32::from_le_bytes(buf[16..20].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer block_count slice".into()))?),
            sequence_number: u64::from_le_bytes(buf[24..32].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer sequence_number slice".into()))?),
            catalog_offset: u64::from_le_bytes(buf[32..40].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer catalog_offset slice".into()))?),
            catalog_size: u32::from_le_bytes(buf[40..44].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer catalog_size slice".into()))?),
            catalog_block_id: u32::from_le_bytes(buf[44..48].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer catalog_block_id slice".into()))?),
            last_checkpoint_offset: u64::from_le_bytes(buf[48..56].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer last_checkpoint_offset slice".into()))?),
            last_checkpoint_block_id: u32::from_le_bytes(buf[56..60].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer last_checkpoint_block_id slice".into()))?),
            index_offset: u64::from_le_bytes(buf[64..72].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer index_offset slice".into()))?),
            index_size: u32::from_le_bytes(buf[72..76].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer index_size slice".into()))?),
            index_block_id: u32::from_le_bytes(buf[76..80].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer index_block_id slice".into()))?),
            backup_header_offset: u64::from_le_bytes(buf[80..88].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer backup_header_offset slice".into()))?),
            checksum: [0u8; 32], // Will be filled separately
        })
    }

    /// Serialize the footer to bytes (always exactly 128 bytes)
    pub fn to_bytes(&self) -> Result<[u8; FOOTER_SIZE]> {
        let mut result = [0u8; FOOTER_SIZE];

        // Write fields (first 96 bytes)
        let mut fields_buf = [0u8; FOOTER_SIZE - 32];
        self.write_fields_to(&mut fields_buf);
        result[0..96].copy_from_slice(&fields_buf);

        // Write checksum (last 32 bytes)
        result[96..128].copy_from_slice(&self.checksum);

        Ok(result)
    }

    /// Deserialize a footer from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < FOOTER_SIZE {
            return Err(EraError::CorruptedFooter("Footer too small".to_string()));
        }

        // Read fields
        let fields_buf: [u8; FOOTER_SIZE - 32] = data[0..96].try_into().map_err(|_| EraError::CorruptedFooter("invalid footer data length".into()))?;
        let mut footer = Self::read_fields_from(&fields_buf)?;

        // Read checksum
        footer.checksum = data[96..128].try_into().map_err(|_| EraError::CorruptedFooter("invalid checksum length".into()))?;

        // Validate magic
        if footer.magic != FOOTER_MAGIC {
            return Err(EraError::CorruptedFooter("Invalid magic".to_string()));
        }

        // Validate version
        if footer.version > FOOTER_VERSION {
            return Err(EraError::CorruptedFooter(format!(
                "Unsupported footer version: {} (max supported: {})",
                footer.version, FOOTER_VERSION
            )));
        }

        // Validate checksum
        if !footer.verify_checksum() {
            return Err(EraError::CorruptedFooter("Checksum mismatch".to_string()));
        }

        // Validate field ranges (Defect #6):
        // data_end_offset must be 0 or at least HEADER_SIZE + FOOTER_SIZE (minimum structural size)
        let min_data_end = (crate::header::HEADER_SIZE + FOOTER_SIZE) as u64;
        if footer.data_end_offset != 0 && footer.data_end_offset < min_data_end {
            return Err(EraError::CorruptedFooter(format!(
                "data_end_offset {} is below minimum structural size {}",
                footer.data_end_offset, min_data_end
            )));
        }
        // catalog_offset must be 0 or at least HEADER_SIZE
        if footer.catalog_offset != 0 && footer.catalog_offset < crate::header::HEADER_SIZE as u64 {
            return Err(EraError::CorruptedFooter(format!(
                "catalog_offset {} is below HEADER_SIZE {}",
                footer.catalog_offset,
                crate::header::HEADER_SIZE
            )));
        }
        // index_offset must be 0 or at least HEADER_SIZE
        if footer.index_offset != 0 && footer.index_offset < crate::header::HEADER_SIZE as u64 {
            return Err(EraError::CorruptedFooter(format!(
                "index_offset {} is below HEADER_SIZE {}",
                footer.index_offset,
                crate::header::HEADER_SIZE
            )));
        }

        Ok(footer)
    }
}

/// Builder for constructing a Footer with named fields.
///
/// Replaces the 12-argument `Footer::with_catalog` for better readability.
pub struct FooterBuilder {
    data_end_offset: u64,
    block_count: u32,
    sequence_number: u64,
    catalog_offset: u64,
    catalog_size: u32,
    catalog_block_id: u32,
    last_checkpoint_offset: u64,
    last_checkpoint_block_id: u32,
    index_offset: u64,
    index_size: u32,
    index_block_id: u32,
    backup_header_offset: u64,
}

impl FooterBuilder {
    pub fn catalog(mut self, offset: u64, size: u32, block_id: u32) -> Self {
        self.catalog_offset = offset;
        self.catalog_size = size;
        self.catalog_block_id = block_id;
        self
    }

    pub fn checkpoint(mut self, offset: u64, block_id: u32) -> Self {
        self.last_checkpoint_offset = offset;
        self.last_checkpoint_block_id = block_id;
        self
    }

    pub fn index(mut self, offset: u64, size: u32, block_id: u32) -> Self {
        self.index_offset = offset;
        self.index_size = size;
        self.index_block_id = block_id;
        self
    }

    pub fn backup_header(mut self, offset: u64) -> Self {
        self.backup_header_offset = offset;
        self
    }

    pub fn build(self) -> Footer {
        Footer::with_catalog(
            self.data_end_offset,
            self.block_count,
            self.sequence_number,
            self.catalog_offset,
            self.catalog_size,
            self.catalog_block_id,
            self.last_checkpoint_offset,
            self.last_checkpoint_block_id,
            self.index_offset,
            self.index_size,
            self.index_block_id,
            self.backup_header_offset,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_size_is_exactly_128_bytes() {
        let footer = Footer::new(1024 * 1024, 10, 1);
        let bytes = footer.to_bytes().unwrap();
        assert_eq!(bytes.len(), 128, "Footer must be exactly 128 bytes");
    }

    #[test]
    fn test_footer_roundtrip() {
        let footer = Footer::new(1024 * 1024, 10, 1);

        let bytes = footer.to_bytes().unwrap();
        assert_eq!(bytes.len(), FOOTER_SIZE);

        let restored = Footer::from_bytes(&bytes).unwrap();
        assert_eq!(restored.magic, FOOTER_MAGIC);
        assert_eq!(restored.version, FOOTER_VERSION);
        assert_eq!(restored.data_end_offset, 1024 * 1024);
        assert_eq!(restored.block_count, 10);
        assert_eq!(restored.sequence_number, 1);
    }

    #[test]
    fn test_footer_with_all_fields() {
        let footer = Footer::with_catalog(
            0xFFFF_FFFF_FFFF_FFFF, // max u64
            0xFFFF_FFFF,           // max u32
            0xFFFF_FFFF_FFFF_FFFF, // max u64
            0xFFFF_FFFF_FFFF_FFFF, // catalog_offset
            0xFFFF_FFFF,           // catalog_size
            0xFFFF_FFFF,           // catalog_block_id
            0xFFFF_FFFF_FFFF_FFFF, // last_checkpoint_offset
            0xFFFF_FFFF,           // last_checkpoint_block_id
            0xFFFF_FFFF_FFFF_FFFF, // index_offset
            0xFFFF_FFFF,           // index_size
            0xFFFF_FFFF,           // index_block_id
            0xFFFF_FFFF_FFFF_FFFF, // backup_header_offset
        );

        // Must still serialize to exactly 128 bytes even with max values
        let bytes = footer.to_bytes().unwrap();
        assert_eq!(
            bytes.len(),
            128,
            "Footer must be exactly 128 bytes even with max values"
        );

        let restored = Footer::from_bytes(&bytes).unwrap();
        assert_eq!(restored.data_end_offset, 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(restored.block_count, 0xFFFF_FFFF);
        assert_eq!(restored.catalog_offset, 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(restored.index_offset, 0xFFFF_FFFF_FFFF_FFFF);
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
        assert!(matches!(result, Err(EraError::CorruptedFooter(_))));
    }

    #[test]
    fn test_corrupted_checksum() {
        let footer = Footer::new(1024, 5, 1);
        let mut bytes = footer.to_bytes().unwrap();

        // Corrupt the checksum
        bytes[96] ^= 0xFF;

        let result = Footer::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_catalog_location() {
        let footer = Footer::new(1024, 5, 1);
        assert!(!footer.has_catalog_location());

        let footer_with_catalog = Footer::with_catalog(1024, 5, 1, 2048, 512, 1, 0, 0, 0, 0, 0, 0);
        assert!(footer_with_catalog.has_catalog_location());
    }

    #[test]
    fn test_has_index() {
        let footer = Footer::new(1024, 5, 1);
        assert!(!footer.has_index());

        let footer_with_index = Footer::with_catalog(1024, 5, 1, 0, 0, 0, 0, 0, 4096, 1024, 2, 0);
        assert!(footer_with_index.has_index());
    }
}
