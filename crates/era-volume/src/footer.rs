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

/// MN34-02: Blake3 checksum size in the footer (32 bytes).
/// The checksum occupies the final 32 bytes of the footer.
const FOOTER_CHECKSUM_SIZE: usize = 32;

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
/// | 60     | 4    | manifest_block_id        |
/// | 64     | 8    | index_offset             |
/// | 72     | 4    | index_size               |
/// | 76     | 4    | index_block_id           |
/// | 80     | 8    | backup_header_offset     |
/// | 88     | 8    | manifest_offset          |
/// | 96     | 32   | checksum (Blake3)        |
/// | **128**|      | **Total**                |
///
#[must_use]
#[derive(Debug, Clone, PartialEq)]
pub struct Footer {
    /// Magic bytes: "ERAF"
    magic: [u8; 4],
    /// Format version
    version: u8,
    /// Status flags
    flags: u16,
    /// Offset of the data region end
    data_end_offset: u64,
    /// Number of blocks in this volume
    block_count: u32,
    /// Sequence number (monotonically increasing)
    sequence_number: u64,
    /// Offset of the catalog block (for fast lookup)
    catalog_offset: u64,
    /// Size of the catalog block (encrypted size)
    catalog_size: u32,
    /// Block ID of the catalog (for correct decryption)
    catalog_block_id: u32,
    /// Offset of the last checkpoint (for atomic updates)
    last_checkpoint_offset: u64,
    /// Block ID of the last checkpoint (for direct decryption)
    last_checkpoint_block_id: u32,
    /// Block ID of the manifest typed block (for AEAD decryption).
    /// v8.2: Reuses reserved3 (binary offset 60, 4 bytes).
    /// Zero when no manifest exists (v8.1 footer).
    manifest_block_id: u32,
    /// Offset of the index block
    index_offset: u64,
    /// Size of the index block
    index_size: u32,
    /// Block ID of the index
    index_block_id: u32,
    /// Offset of the backup header (for redundancy layout)
    backup_header_offset: u64,
    /// Absolute byte offset of the manifest typed block.
    /// v8.2: Reuses reserved4 (binary offset 88, 8 bytes).
    /// Zero when no manifest exists (v8.1 footer).
    manifest_offset: u64,
    /// Blake3 checksum of the footer (excluding this field)
    checksum: [u8; 32],
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
            0,
            0, // backup_header_offset
            0,
        )
    }

    /// Create a new footer with catalog location
    ///
    /// Note: This method takes many arguments due to the fixed footer format. For simpler usage,
    /// consider using [`FooterBuilder`] which provides a more ergonomic API.
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
        manifest_block_id: u32,
        index_offset: u64,
        index_size: u32,
        index_block_id: u32,
        backup_header_offset: u64,
        manifest_offset: u64,
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
            manifest_block_id,
            index_offset,
            index_size,
            index_block_id,
            backup_header_offset,
            manifest_offset,
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
            manifest_block_id: 0,
            index_offset: 0,
            index_size: 0,
            index_block_id: 0,
            backup_header_offset: 0,
            manifest_offset: 0,
        }
    }

    /// Check if catalog location is available
    #[must_use]
    pub fn has_catalog_location(&self) -> bool {
        self.catalog_offset > 0 && self.catalog_size > 0
    }

    /// Check if index location is available
    #[must_use]
    pub fn has_index(&self) -> bool {
        self.index_offset > 0 && self.index_size > 0
    }

    /// Check if manifest location is available (v8.2 indicator).
    ///
    /// Uses `manifest_offset != 0` rather than `manifest_block_id > 0`
    /// because `BlockId::new(0)` is valid — block_id can be 0.
    #[must_use]
    pub fn has_manifest(&self) -> bool {
        self.manifest_offset != 0
    }

    /// Update the checksum field (domain-separated Blake3)
    fn update_checksum(&mut self) {
        // Zero out checksum for calculation
        self.checksum = [0u8; 32];

        // Serialize without checksum (first 96 bytes)
        let mut data = [0u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE];
        self.write_fields_to(&mut data);

        // Calculate Blake3 hash with domain separation prefix
        let mut hasher = blake3::Hasher::new();
        hasher.update(FOOTER_DOMAIN);
        hasher.update(&data);
        self.checksum = *hasher.finalize().as_bytes();
    }

    /// Verify the checksum (domain-separated Blake3)
    #[must_use = "security: ignoring checksum verification may accept corrupted data"]
    pub fn verify_checksum(&self) -> bool {
        // Serialize without checksum (first 96 bytes)
        let mut data = [0u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE];
        self.write_fields_to(&mut data);

        let mut hasher = blake3::Hasher::new();
        hasher.update(FOOTER_DOMAIN);
        hasher.update(&data);
        hasher.finalize().as_bytes() == &self.checksum
    }

    /// Write all fields except checksum to a buffer
    fn write_fields_to(&self, buf: &mut [u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE]) {
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
        // Offset 60: manifest_block_id (4 bytes)
        buf[60..64].copy_from_slice(&self.manifest_block_id.to_le_bytes());
        // Offset 64: index_offset (8 bytes)
        buf[64..72].copy_from_slice(&self.index_offset.to_le_bytes());
        // Offset 72: index_size (4 bytes)
        buf[72..76].copy_from_slice(&self.index_size.to_le_bytes());
        // Offset 76: index_block_id (4 bytes)
        buf[76..80].copy_from_slice(&self.index_block_id.to_le_bytes());
        // Offset 80: backup_header_offset (8 bytes)
        buf[80..88].copy_from_slice(&self.backup_header_offset.to_le_bytes());
        // Offset 88: manifest_offset (8 bytes)
        buf[88..96].copy_from_slice(&self.manifest_offset.to_le_bytes());
    }

    /// Read fields from a buffer (excluding checksum)
    fn read_fields_from(buf: &[u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE]) -> Result<Self> {
        Ok(Self {
            magic: buf[0..4]
                .try_into()
                .map_err(|_| EraError::CorruptedFooter("invalid footer magic slice".into()))?,
            version: buf[4],
            flags: u16::from_le_bytes(
                buf[6..8]
                    .try_into()
                    .map_err(|_| EraError::CorruptedFooter("invalid footer flags slice".into()))?,
            ),
            data_end_offset: u64::from_le_bytes(buf[8..16].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer data_end_offset slice".into())
            })?),
            block_count: u32::from_le_bytes(buf[16..20].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer block_count slice".into())
            })?),
            sequence_number: u64::from_le_bytes(buf[24..32].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer sequence_number slice".into())
            })?),
            catalog_offset: u64::from_le_bytes(buf[32..40].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer catalog_offset slice".into())
            })?),
            catalog_size: u32::from_le_bytes(buf[40..44].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer catalog_size slice".into())
            })?),
            catalog_block_id: u32::from_le_bytes(buf[44..48].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer catalog_block_id slice".into())
            })?),
            last_checkpoint_offset: u64::from_le_bytes(buf[48..56].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer last_checkpoint_offset slice".into())
            })?),
            last_checkpoint_block_id: u32::from_le_bytes(buf[56..60].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer last_checkpoint_block_id slice".into())
            })?),
            manifest_block_id: u32::from_le_bytes(buf[60..64].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer manifest_block_id slice".into())
            })?),
            index_offset: u64::from_le_bytes(buf[64..72].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer index_offset slice".into())
            })?),
            index_size: u32::from_le_bytes(buf[72..76].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer index_size slice".into())
            })?),
            index_block_id: u32::from_le_bytes(buf[76..80].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer index_block_id slice".into())
            })?),
            backup_header_offset: u64::from_le_bytes(buf[80..88].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer backup_header_offset slice".into())
            })?),
            manifest_offset: u64::from_le_bytes(buf[88..96].try_into().map_err(|_| {
                EraError::CorruptedFooter("invalid footer manifest_offset slice".into())
            })?),
            checksum: [0u8; 32], // Will be filled separately
        })
    }

    /// Serialize the footer to bytes (always exactly [`FOOTER_SIZE`] bytes).
    ///
    /// # Errors
    /// Returns `CorruptedFooter` if internal field slicing fails (should not happen for valid footers).
    pub fn to_bytes(&self) -> Result<[u8; FOOTER_SIZE]> {
        let mut result = [0u8; FOOTER_SIZE];

        // Write fields (first 96 bytes)
        let mut fields_buf = [0u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE];
        self.write_fields_to(&mut fields_buf);
        result[0..96].copy_from_slice(&fields_buf);

        // Write checksum (last 32 bytes)
        result[96..128].copy_from_slice(&self.checksum);

        Ok(result)
    }

    /// Deserialize a footer from bytes.
    ///
    /// # Errors
    /// Returns `CorruptedFooter` if the data is too small, has invalid magic/version,
    /// fails checksum verification, or has inconsistent cross-field offsets.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < FOOTER_SIZE {
            return Err(EraError::CorruptedFooter(format!(
                "Footer too small: {} bytes, need {}",
                data.len(),
                FOOTER_SIZE
            )));
        }

        // Read fields
        let fields_buf: [u8; FOOTER_SIZE - FOOTER_CHECKSUM_SIZE] = data[0..96]
            .try_into()
            .map_err(|_| EraError::CorruptedFooter("invalid footer data length".into()))?;
        let mut footer = Self::read_fields_from(&fields_buf)?;

        // Read checksum
        footer.checksum = data[96..128]
            .try_into()
            .map_err(|_| EraError::CorruptedFooter("invalid checksum length".into()))?;

        // Validate magic
        if footer.magic != FOOTER_MAGIC {
            return Err(EraError::CorruptedFooter(format!(
                "Invalid magic: expected {:?}, got {:?}",
                FOOTER_MAGIC, footer.magic
            )));
        }

        // Validate version
        if footer.version == 0 || footer.version > FOOTER_VERSION {
            return Err(EraError::CorruptedFooter(format!(
                "Unsupported footer version: {} (max supported: {})",
                footer.version, FOOTER_VERSION
            )));
        }

        // FC39-02: Reject unknown footer flags. No flags are currently defined,
        // so any non-zero value indicates a newer format this reader cannot handle.
        if footer.flags != 0 {
            return Err(EraError::CorruptedFooter(format!(
                "Unknown footer flags: 0x{:04X} (this reader supports none)",
                footer.flags
            )));
        }

        // Validate checksum against the raw input bytes (not re-serialized),
        // so mutations in reserved fields are also detected.
        let mut hasher = blake3::Hasher::new();
        hasher.update(FOOTER_DOMAIN);
        hasher.update(&data[0..96]);
        let computed = hasher.finalize();
        if computed.as_bytes() != &footer.checksum {
            return Err(EraError::CorruptedFooter(format!(
                "Checksum mismatch: expected {:02x}{:02x}{:02x}{:02x}..., got {:02x}{:02x}{:02x}{:02x}...",
                footer.checksum[0], footer.checksum[1], footer.checksum[2], footer.checksum[3],
                computed.as_bytes()[0], computed.as_bytes()[1], computed.as_bytes()[2], computed.as_bytes()[3],
            )));
        }

        // Validate field ranges (Defect #6):
        // data_end_offset must be 0 or at least HEADER_SIZE + FOOTER_SIZE (minimum structural size)
        let min_data_end = crate::header::DATA_REGION_START;
        if footer.data_end_offset != 0 && footer.data_end_offset < min_data_end {
            return Err(EraError::CorruptedFooter(format!(
                "data_end_offset {} is below minimum structural size {}",
                footer.data_end_offset, min_data_end
            )));
        }
        Self::validate_offset_above_header("catalog_offset", footer.catalog_offset)?;
        Self::validate_offset_above_header("index_offset", footer.index_offset)?;
        Self::validate_offset_above_header(
            "last_checkpoint_offset",
            footer.last_checkpoint_offset,
        )?;
        Self::validate_offset_above_header("backup_header_offset", footer.backup_header_offset)?;
        Self::validate_offset_above_header("manifest_offset", footer.manifest_offset)?;

        // D10-01: Cross-field validation — catalog region must not overflow
        // and must be contained within the data region when present.
        Self::validate_region_bounds(
            "catalog",
            footer.catalog_offset,
            footer.catalog_size,
            footer.data_end_offset,
        )?;
        // D10-01: Cross-field validation — index region must not overflow
        // and must be contained within the data region when present.
        Self::validate_region_bounds(
            "index",
            footer.index_offset,
            footer.index_size,
            footer.data_end_offset,
        )?;

        Ok(footer)
    }

    /// Validate that a region (offset+size) does not overflow u64 and fits within `data_end_offset`.
    fn validate_region_bounds(
        name: &str,
        offset: u64,
        size: u32,
        data_end_offset: u64,
    ) -> Result<()> {
        if offset != 0 && size != 0 {
            let region_end = offset.checked_add(size as u64).ok_or_else(|| {
                EraError::CorruptedFooter(format!("{}_offset + {}_size overflows u64", name, name))
            })?;
            if data_end_offset != 0 && region_end > data_end_offset {
                return Err(EraError::CorruptedFooter(format!(
                    "{} region [{}, {}) exceeds data_end_offset {}",
                    name, offset, region_end, data_end_offset
                )));
            }
        }
        Ok(())
    }

    /// Validate that a non-zero offset is at least `HEADER_SIZE`.
    fn validate_offset_above_header(name: &str, offset: u64) -> Result<()> {
        if offset != 0 && offset < crate::header::HEADER_SIZE as u64 {
            return Err(EraError::CorruptedFooter(format!(
                "{} {} is below HEADER_SIZE {}",
                name,
                offset,
                crate::header::HEADER_SIZE
            )));
        }
        Ok(())
    }

    // ── Accessor methods ──────────────────────────────────────────────

    /// Magic bytes ("ERAF")
    #[must_use]
    pub fn magic(&self) -> &[u8; 4] {
        &self.magic
    }

    /// Format version
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Status flags
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Offset of the data region end
    #[must_use]
    pub fn data_end_offset(&self) -> u64 {
        self.data_end_offset
    }

    /// Number of blocks in this volume
    #[must_use]
    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    /// Sequence number (monotonically increasing)
    #[must_use]
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Offset of the catalog block
    #[must_use]
    pub fn catalog_offset(&self) -> u64 {
        self.catalog_offset
    }

    /// Size of the catalog block (encrypted size)
    #[must_use]
    pub fn catalog_size(&self) -> u32 {
        self.catalog_size
    }

    /// Block ID of the catalog
    #[must_use]
    pub fn catalog_block_id(&self) -> u32 {
        self.catalog_block_id
    }

    /// Offset of the last checkpoint
    #[must_use]
    pub fn last_checkpoint_offset(&self) -> u64 {
        self.last_checkpoint_offset
    }

    /// Block ID of the last checkpoint
    #[must_use]
    pub fn last_checkpoint_block_id(&self) -> u32 {
        self.last_checkpoint_block_id
    }

    /// Offset of the manifest typed block.
    /// Returns 0 if no manifest exists (v8.1 footer).
    #[must_use]
    pub fn manifest_offset(&self) -> u64 {
        self.manifest_offset
    }

    /// Block ID of the manifest typed block.
    /// Returns 0 if no manifest exists (v8.1 footer).
    #[must_use]
    pub fn manifest_block_id(&self) -> u32 {
        self.manifest_block_id
    }

    /// Returns the manifest location as a tuple (offset, block_id).
    /// Returns None if no manifest exists.
    #[must_use]
    pub fn manifest_location(&self) -> Option<(u64, u32)> {
        if self.has_manifest() {
            Some((self.manifest_offset, self.manifest_block_id))
        } else {
            None
        }
    }

    /// Offset of the index block
    #[must_use]
    pub fn index_offset(&self) -> u64 {
        self.index_offset
    }

    /// Size of the index block
    #[must_use]
    pub fn index_size(&self) -> u32 {
        self.index_size
    }

    /// Block ID of the index
    #[must_use]
    pub fn index_block_id(&self) -> u32 {
        self.index_block_id
    }

    /// Offset of the backup header
    #[must_use]
    pub fn backup_header_offset(&self) -> u64 {
        self.backup_header_offset
    }

    /// Blake3 checksum of the footer
    #[must_use]
    pub fn checksum(&self) -> &[u8; 32] {
        &self.checksum
    }
}

#[cfg(test)]
impl Footer {
    /// Test-only setter for magic bytes.
    pub(crate) fn set_magic(&mut self, m: [u8; 4]) {
        self.magic = m;
    }

    /// Test-only setter for block_count.
    pub(crate) fn set_block_count(&mut self, c: u32) {
        self.block_count = c;
    }

    /// Test-only: recompute and update the checksum.
    pub(crate) fn recompute_checksum(&mut self) {
        self.update_checksum();
    }
}

/// Builder for constructing a Footer with named fields.
///
/// Replaces the 14-argument `Footer::with_catalog` for better readability.
#[must_use]
pub struct FooterBuilder {
    data_end_offset: u64,
    block_count: u32,
    sequence_number: u64,
    catalog_offset: u64,
    catalog_size: u32,
    catalog_block_id: u32,
    last_checkpoint_offset: u64,
    last_checkpoint_block_id: u32,
    manifest_block_id: u32,
    index_offset: u64,
    index_size: u32,
    index_block_id: u32,
    backup_header_offset: u64,
    manifest_offset: u64,
}

impl FooterBuilder {
    /// Sets the catalog location (offset, size, and block ID).
    pub fn catalog(mut self, offset: u64, size: u32, block_id: u32) -> Self {
        self.catalog_offset = offset;
        self.catalog_size = size;
        self.catalog_block_id = block_id;
        self
    }

    /// Sets the last checkpoint location (offset and block ID).
    pub fn checkpoint(mut self, offset: u64, block_id: u32) -> Self {
        self.last_checkpoint_offset = offset;
        self.last_checkpoint_block_id = block_id;
        self
    }

    /// Sets the manifest location (offset and block ID).
    pub fn manifest(mut self, offset: u64, block_id: u32) -> Self {
        self.manifest_offset = offset;
        self.manifest_block_id = block_id;
        self
    }

    /// Sets the dedup index location (offset, size, and block ID).
    pub fn index(mut self, offset: u64, size: u32, block_id: u32) -> Self {
        self.index_offset = offset;
        self.index_size = size;
        self.index_block_id = block_id;
        self
    }

    /// Sets the backup header offset within the volume.
    pub fn backup_header(mut self, offset: u64) -> Self {
        self.backup_header_offset = offset;
        self
    }

    /// Consumes the builder and produces a [`Footer`] with all configured fields.
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
            self.manifest_block_id,
            self.index_offset,
            self.index_size,
            self.index_block_id,
            self.backup_header_offset,
            self.manifest_offset,
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
        assert_eq!(restored.magic(), &FOOTER_MAGIC);
        assert_eq!(restored.version(), FOOTER_VERSION);
        assert_eq!(restored.data_end_offset(), 1024 * 1024);
        assert_eq!(restored.block_count(), 10);
        assert_eq!(restored.sequence_number(), 1);
    }

    #[test]
    fn test_footer_with_all_fields() {
        // Use large but logically valid values: offset + size must not overflow u64,
        // and catalog/index regions must be within data_end_offset when non-zero.
        let data_end: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        let catalog_offset: u64 = 0xFFFF_FFFF_0000_0000;
        let catalog_size: u32 = 0x0FFF_FFFF; // fits within data_end
        let index_offset: u64 = 0xFFFF_FFFE_0000_0000;
        let index_size: u32 = 0x0FFF_FFFF; // fits within data_end
        let footer = Footer::with_catalog(
            data_end,
            0xFFFF_FFFF,           // block_count
            0xFFFF_FFFF_FFFF_FFFF, // sequence_number
            catalog_offset,
            catalog_size,
            0xFFFF_FFFF,           // catalog_block_id
            0xFFFF_FFFF_FFFF_FFFF, // last_checkpoint_offset
            0xFFFF_FFFF,           // last_checkpoint_block_id
            0xFFFF_FFFF,           // manifest_block_id
            index_offset,
            index_size,
            0xFFFF_FFFF,           // index_block_id
            0xFFFF_FFFF_FFFF_FFFF, // backup_header_offset
            0xFFFF_FFFF_FFFF_FFFF, // manifest_offset
        );

        // Must still serialize to exactly 128 bytes even with max values
        let bytes = footer.to_bytes().unwrap();
        assert_eq!(
            bytes.len(),
            128,
            "Footer must be exactly 128 bytes even with max values"
        );

        let restored = Footer::from_bytes(&bytes).unwrap();
        assert_eq!(restored.data_end_offset(), data_end);
        assert_eq!(restored.block_count(), 0xFFFF_FFFF);
        assert_eq!(restored.catalog_offset(), catalog_offset);
        assert_eq!(restored.catalog_size(), catalog_size);
        assert_eq!(restored.manifest_block_id(), 0xFFFF_FFFF);
        assert_eq!(restored.manifest_offset(), 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(restored.index_offset(), index_offset);
        assert_eq!(restored.index_size(), index_size);
    }

    #[test]
    fn test_footer_rejects_catalog_overflow() {
        // catalog_offset + catalog_size overflows u64
        let footer = Footer::with_catalog(
            0xFFFF_FFFF_FFFF_FFFF,
            1,
            1,
            0xFFFF_FFFF_FFFF_FFFF, // catalog_offset = max
            1,                     // catalog_size = 1 → overflows
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let bytes = footer.to_bytes().unwrap();
        let err = Footer::from_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("overflows"),
            "Expected overflow error, got: {}",
            err
        );
    }

    #[test]
    fn test_footer_rejects_catalog_past_data_end() {
        // catalog region extends past data_end_offset
        let footer = Footer::with_catalog(
            10_000, // data_end_offset
            1, 1, 9_000, // catalog_offset
            2_000, // catalog_size → end = 11_000 > data_end_offset
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let bytes = footer.to_bytes().unwrap();
        let err = Footer::from_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("exceeds data_end_offset"),
            "Expected region-exceeds-data error, got: {}",
            err
        );
    }

    #[test]
    fn test_footer_rejects_index_past_data_end() {
        // index region extends past data_end_offset
        let footer = Footer::with_catalog(
            10_000, // data_end_offset
            1, 1, 0, 0, 0, 0, 0, 0, 9_000, // index_offset
            2_000, // index_size → end = 11_000 > data_end_offset
            0, 0, 0,
        );
        let bytes = footer.to_bytes().unwrap();
        let err = Footer::from_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("exceeds data_end_offset"),
            "Expected region-exceeds-data error, got: {}",
            err
        );
    }

    #[test]
    fn test_checksum_verification() {
        let footer = Footer::new(1024, 5, 1);
        assert!(footer.verify_checksum());

        // Tamper with the footer
        let mut tampered = footer.clone();
        tampered.set_block_count(100);
        assert!(!tampered.verify_checksum());
    }

    #[test]
    fn test_corrupted_magic() {
        let mut footer = Footer::new(1024, 5, 1);
        footer.set_magic([0, 0, 0, 0]);
        footer.recompute_checksum();

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
        // TQ37-01: Verify specific error variant, matching test_corrupted_magic's pattern
        assert!(matches!(result, Err(EraError::CorruptedFooter(_))));
    }

    #[test]
    fn test_has_catalog_location() {
        let footer = Footer::new(1024, 5, 1);
        assert!(!footer.has_catalog_location());

        let footer_with_catalog =
            Footer::with_catalog(1024, 5, 1, 2048, 512, 1, 0, 0, 0, 0, 0, 0, 0, 0);
        assert!(footer_with_catalog.has_catalog_location());
    }

    #[test]
    fn test_has_index() {
        let footer = Footer::new(1024, 5, 1);
        assert!(!footer.has_index());

        let footer_with_index =
            Footer::with_catalog(1024, 5, 1, 0, 0, 0, 0, 0, 0, 4096, 1024, 2, 0, 0);
        assert!(footer_with_index.has_index());
    }

    #[test]
    fn footer_manifest_fields_default_zero() {
        let footer = Footer::builder(4096, 0, 0)
            .catalog(0, 0, 0)
            .backup_header(0)
            .build();
        assert_eq!(footer.manifest_block_id(), 0);
        assert_eq!(footer.manifest_offset(), 0);
        assert!(!footer.has_manifest());
    }

    #[test]
    fn footer_with_manifest_roundtrip() {
        let footer = Footer::builder(10000, 5, 1)
            .catalog(5000, 200, 3)
            .manifest(8000, 7)
            .index(6000, 300, 4)
            .backup_header(9000)
            .build();
        assert_eq!(footer.manifest_offset(), 8000);
        assert_eq!(footer.manifest_block_id(), 7);
        assert!(footer.has_manifest());

        let bytes = footer.to_bytes().unwrap();
        let footer2 = Footer::from_bytes(&bytes).unwrap();
        assert_eq!(footer2.manifest_offset(), 8000);
        assert_eq!(footer2.manifest_block_id(), 7);
        assert!(footer2.has_manifest());
    }

    #[test]
    fn footer_has_manifest_uses_offset_not_block_id() {
        // BlockId 0 is valid, so has_manifest checks offset != 0
        let footer = Footer::builder(10000, 5, 1)
            .catalog(5000, 200, 3)
            .manifest(4096, 0)
            .backup_header(9000)
            .build();
        assert!(footer.has_manifest());
    }

    #[test]
    fn footer_no_manifest_when_offset_zero() {
        let footer = Footer::builder(10000, 5, 1)
            .catalog(5000, 200, 3)
            .manifest(0, 5)
            .backup_header(9000)
            .build();
        assert!(!footer.has_manifest());
    }

    #[test]
    fn footer_manifest_location() {
        let footer = Footer::builder(10000, 5, 1)
            .catalog(5000, 200, 3)
            .manifest(8000, 7)
            .backup_header(9000)
            .build();
        let loc = footer.manifest_location();
        assert_eq!(loc, Some((8000, 7)));

        let footer_no_manifest = Footer::builder(10000, 5, 1)
            .catalog(5000, 200, 3)
            .backup_header(9000)
            .build();
        assert_eq!(footer_no_manifest.manifest_location(), None);
    }
}
