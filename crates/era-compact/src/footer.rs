use era_common::{EraError, Result};
use serde::{Deserialize, Serialize};

pub const COMPACT_FOOTER_MAGIC: [u8; 8] = *b"ERACFTR1";
pub const COMPACT_FOOTER_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactVolumeFooter {
    magic: [u8; 8],
    version: u16,
    data_region_end: u64,
    meta_region_offset: u64,
    directory_offset: u64,
    directory_size: u32,
    directory_count: u32,
    catalog_offset: u64,
    catalog_size: u32,
    catalog_block_id: u64,
    index_offset: u64,
    index_size: u32,
    index_block_id: u64,
    header_hash: [u8; 32],
    directory_hash: [u8; 32],
    checksum: u32,
}

impl CompactVolumeFooter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data_region_end: u64,
        meta_region_offset: u64,
        directory_offset: u64,
        directory_size: u32,
        directory_count: u32,
        catalog_offset: u64,
        catalog_size: u32,
        catalog_block_id: u64,
        index_offset: u64,
        index_size: u32,
        index_block_id: u64,
        header_hash: [u8; 32],
        directory_hash: [u8; 32],
    ) -> Result<Self> {
        if !(data_region_end <= meta_region_offset && meta_region_offset <= directory_offset) {
            return Err(EraError::InvalidFormat(
                "compact footer offsets must be monotonic".into(),
            ));
        }
        let mut f = Self {
            magic: COMPACT_FOOTER_MAGIC,
            version: COMPACT_FOOTER_VERSION,
            data_region_end,
            meta_region_offset,
            directory_offset,
            directory_size,
            directory_count,
            catalog_offset,
            catalog_size,
            catalog_block_id,
            index_offset,
            index_size,
            index_block_id,
            header_hash,
            directory_hash,
            checksum: 0,
        };
        f.checksum = f.compute_checksum()?;
        Ok(f)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode_serialize(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() as u64 > crate::MAX_COMPACT_FOOTER_SIZE {
            return Err(EraError::InvalidFormat(format!(
                "compact footer input {} exceeds limit {}",
                data.len(),
                crate::MAX_COMPACT_FOOTER_SIZE
            )));
        }
        let decoded: Self = bincode_deserialize(data)?;
        if decoded.magic != COMPACT_FOOTER_MAGIC {
            return Err(EraError::InvalidMagic);
        }
        if decoded.version != COMPACT_FOOTER_VERSION {
            return Err(EraError::UnsupportedVersion {
                version: decoded.version as u32,
            });
        }
        let mut expected = decoded.clone();
        expected.checksum = 0;
        if decoded.checksum != expected.compute_checksum()? {
            return Err(EraError::CorruptedFooter(
                "compact footer checksum mismatch".into(),
            ));
        }
        Self::new(
            decoded.data_region_end,
            decoded.meta_region_offset,
            decoded.directory_offset,
            decoded.directory_size,
            decoded.directory_count,
            decoded.catalog_offset,
            decoded.catalog_size,
            decoded.catalog_block_id,
            decoded.index_offset,
            decoded.index_size,
            decoded.index_block_id,
            decoded.header_hash,
            decoded.directory_hash,
        )
    }

    pub fn directory_offset(&self) -> u64 {
        self.directory_offset
    }

    pub fn directory_size(&self) -> u32 {
        self.directory_size
    }

    pub fn directory_count(&self) -> u32 {
        self.directory_count
    }

    pub fn catalog_offset(&self) -> u64 {
        self.catalog_offset
    }

    pub fn catalog_size(&self) -> u32 {
        self.catalog_size
    }

    pub fn catalog_block_id(&self) -> u64 {
        self.catalog_block_id
    }

    pub fn index_offset(&self) -> u64 {
        self.index_offset
    }

    pub fn index_size(&self) -> u32 {
        self.index_size
    }

    pub fn index_block_id(&self) -> u64 {
        self.index_block_id
    }

    pub fn header_hash(&self) -> &[u8; 32] {
        &self.header_hash
    }

    pub fn directory_hash(&self) -> &[u8; 32] {
        &self.directory_hash
    }

    pub fn data_region_end(&self) -> u64 {
        self.data_region_end
    }

    pub fn meta_region_offset(&self) -> u64 {
        self.meta_region_offset
    }

    fn compute_checksum(&self) -> Result<u32> {
        let mut tmp = self.clone();
        tmp.checksum = 0;
        let data = bincode_serialize(&tmp)?;
        Ok(crc32fast::hash(&data))
    }
}

fn bincode_serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .map_err(|e| EraError::Serialization(format!("compact encode failed: {e}")))
}

fn bincode_deserialize<T: for<'de> serde::Deserialize<'de>>(data: &[u8]) -> Result<T> {
    let (value, _): (T, usize) =
        bincode::serde::decode_from_slice(data, bincode::config::standard())
            .map_err(|e| EraError::Deserialization(format!("compact decode failed: {e}")))?;
    Ok(value)
}
