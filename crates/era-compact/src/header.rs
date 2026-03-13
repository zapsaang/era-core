use era_common::{ArchiveConfig, ArchiveId, EraError, Result, VolumeId};
use era_volume::{AccessPolicy, EncryptedVolumeKey, RecipientSlot};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const COMPACT_HEADER_MAGIC: [u8; 8] = *b"ERACMP01";
pub const COMPACT_HEADER_VERSION: u16 = 1;
pub const SOURCE_FORMAT_ERA: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompactDistributionStrategy {
    RotatingOffset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactSuperHeader {
    magic: [u8; 8],
    version: u16,
    compact_set_id: Uuid,
    archive_id: ArchiveId,
    volume_id: VolumeId,
    volume_sequence: u16,
    total_compact_volumes: u16,
    source_format: u16,
    source_version: u16,
    source_volume_count: u16,
    config: ArchiveConfig,
    recipients: Vec<RecipientSlot>,
    access_policy: AccessPolicy,
    threshold: u32,
    salt: [u8; 16],
    epoch_id: u32,
    encrypted_volume_key: EncryptedVolumeKey,
    distribution_strategy: CompactDistributionStrategy,
    reserved_flags: u64,
}

impl CompactSuperHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        compact_set_id: Uuid,
        archive_id: ArchiveId,
        volume_id: VolumeId,
        volume_sequence: u16,
        total_compact_volumes: u16,
        source_version: u16,
        source_volume_count: u16,
        config: ArchiveConfig,
        recipients: Vec<RecipientSlot>,
        access_policy: AccessPolicy,
        threshold: u32,
        salt: [u8; 16],
        epoch_id: u32,
        encrypted_volume_key: EncryptedVolumeKey,
    ) -> Result<Self> {
        if recipients.is_empty() {
            return Err(EraError::InvalidConfig(
                "compact header requires at least one recipient".into(),
            ));
        }
        if total_compact_volumes == 0 {
            return Err(EraError::InvalidConfig(
                "total_compact_volumes must be > 0".into(),
            ));
        }
        if volume_sequence >= total_compact_volumes {
            return Err(EraError::InvalidConfig(format!(
                "volume_sequence {} must be < total_compact_volumes {}",
                volume_sequence, total_compact_volumes
            )));
        }
        match access_policy {
            AccessPolicy::AnyOfN => {
                if threshold != 0 {
                    return Err(EraError::InvalidConfig(
                        "non-threshold policy requires threshold=0".into(),
                    ));
                }
            }
            AccessPolicy::Threshold(t) => {
                if threshold != t {
                    return Err(EraError::InvalidConfig(format!(
                        "threshold field {} must match AccessPolicy::Threshold({})",
                        threshold, t
                    )));
                }
                if !(2..=recipients.len() as u32).contains(&threshold) {
                    return Err(EraError::InvalidConfig(format!(
                        "threshold {} must satisfy 2 <= threshold <= recipients({})",
                        threshold,
                        recipients.len()
                    )));
                }
            }
            _ => {
                return Err(EraError::InvalidConfig(
                    "unsupported access policy variant for compact header".into(),
                ));
            }
        }

        Ok(Self {
            magic: COMPACT_HEADER_MAGIC,
            version: COMPACT_HEADER_VERSION,
            compact_set_id,
            archive_id,
            volume_id,
            volume_sequence,
            total_compact_volumes,
            source_format: SOURCE_FORMAT_ERA,
            source_version,
            source_volume_count,
            config,
            recipients,
            access_policy,
            threshold,
            salt,
            epoch_id,
            encrypted_volume_key,
            distribution_strategy: CompactDistributionStrategy::RotatingOffset,
            reserved_flags: 0,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode_serialize(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() > crate::MAX_COMPACT_HEADER_SIZE {
            return Err(EraError::InvalidFormat(format!(
                "compact header input {} exceeds limit {}",
                data.len(),
                crate::MAX_COMPACT_HEADER_SIZE
            )));
        }
        if data.starts_with(&era_volume::MAGIC) || era_volume::SuperHeader::from_bytes(data).is_ok()
        {
            return Err(EraError::InvalidMagic);
        }
        let decoded: Self = bincode_deserialize(data)?;
        if decoded.magic != COMPACT_HEADER_MAGIC {
            return Err(EraError::InvalidMagic);
        }
        if decoded.version != COMPACT_HEADER_VERSION {
            return Err(EraError::UnsupportedVersion {
                version: decoded.version as u32,
            });
        }
        if decoded.source_format != SOURCE_FORMAT_ERA {
            return Err(EraError::InvalidFormat(format!(
                "unsupported compact source format: {}",
                decoded.source_format
            )));
        }
        if decoded.recipients.len() > crate::MAX_COMPACT_RECIPIENTS {
            return Err(EraError::InvalidFormat(format!(
                "compact header has {} recipients, limit is {}",
                decoded.recipients.len(),
                crate::MAX_COMPACT_RECIPIENTS
            )));
        }
        Self::new(
            decoded.compact_set_id,
            decoded.archive_id,
            decoded.volume_id,
            decoded.volume_sequence,
            decoded.total_compact_volumes,
            decoded.source_version,
            decoded.source_volume_count,
            decoded.config,
            decoded.recipients,
            decoded.access_policy,
            decoded.threshold,
            decoded.salt,
            decoded.epoch_id,
            decoded.encrypted_volume_key,
        )
    }

    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    pub fn epoch_id(&self) -> u32 {
        self.epoch_id
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn access_policy(&self) -> AccessPolicy {
        self.access_policy
    }

    pub fn total_compact_volumes(&self) -> u16 {
        self.total_compact_volumes
    }

    pub fn compact_set_id(&self) -> Uuid {
        self.compact_set_id
    }

    pub fn volume_id(&self) -> VolumeId {
        self.volume_id
    }

    pub fn volume_sequence(&self) -> u16 {
        self.volume_sequence
    }

    pub fn source_version(&self) -> u16 {
        self.source_version
    }

    pub fn source_volume_count(&self) -> u16 {
        self.source_volume_count
    }

    pub fn config(&self) -> &ArchiveConfig {
        &self.config
    }

    pub fn recipients(&self) -> &[RecipientSlot] {
        &self.recipients
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    pub fn encrypted_volume_key(&self) -> &EncryptedVolumeKey {
        &self.encrypted_volume_key
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
