use era_common::{BlockId, EraError, Result};
use serde::{Deserialize, Serialize};

/// Input for writing a data block's shard to a compact volume.
/// Defined in era-compact to avoid circular dependency with era-engine.
/// era-engine maps SourceDataBlockSnapshot → CompactShardInput at the boundary.
#[derive(Debug, Clone)]
pub struct CompactShardInput {
    pub block_id: BlockId,
    pub encrypted_bytes: Vec<u8>,
    pub stripe_ordinal: u64,
    pub member_position_in_stripe: u16,
    pub stripe_lengths: Vec<u32>,
    pub data_shards: u8,
    pub parity_shards: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactShardRecordHeader {
    pub version: u16,
    pub block_id: BlockId,
    pub stripe_ordinal: u32,
    pub shard_index: u16,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub encrypted_len: u32,
    pub shard_len: u32,
    pub shard_crc: u32,
}

impl CompactShardRecordHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_id: BlockId,
        stripe_ordinal: u32,
        shard_index: u16,
        data_shards: u16,
        parity_shards: u16,
        encrypted_len: u32,
        shard_len: u32,
        payload: &[u8],
    ) -> Result<Self> {
        if payload.len() != shard_len as usize {
            return Err(EraError::InvalidFormat(format!(
                "payload length {} must equal shard_len {}",
                payload.len(),
                shard_len
            )));
        }
        let header = Self {
            version: 1,
            block_id,
            stripe_ordinal,
            shard_index,
            data_shards,
            parity_shards,
            encrypted_len,
            shard_len,
            shard_crc: crc32fast::hash(payload),
        };
        header.validate()?;
        Ok(header)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| EraError::Serialization(format!("compact shard encode failed: {e}")))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (header, _): (Self, usize) =
            bincode::serde::decode_from_slice(data, bincode::config::standard()).map_err(|e| {
                EraError::Deserialization(format!("compact shard decode failed: {e}"))
            })?;
        header.validate()?;
        Ok(header)
    }

    pub fn validate_payload_crc(&self, payload: &[u8]) -> Result<()> {
        if payload.len() != self.shard_len as usize {
            return Err(EraError::InvalidFormat(format!(
                "payload length {} must equal shard_len {}",
                payload.len(),
                self.shard_len
            )));
        }
        let actual = crc32fast::hash(payload);
        if actual != self.shard_crc {
            return Err(EraError::IntegrityError(format!(
                "Compact shard CRC mismatch: expected {:08x}, got {:08x}",
                self.shard_crc, actual
            )));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        let total = self.data_shards as u32 + self.parity_shards as u32;
        if total == 0 {
            return Err(EraError::InvalidFormat(
                "total shard count must be > 0".into(),
            ));
        }
        if u32::from(self.shard_index) >= total {
            return Err(EraError::InvalidFormat(format!(
                "shard_index {} out of range for total shards {}",
                self.shard_index, total
            )));
        }
        if self.shard_len == 0 {
            return Err(EraError::InvalidFormat("shard_len must be > 0".into()));
        }
        Ok(())
    }
}
