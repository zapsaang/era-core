//! Volume header structures.

use era_common::{ArchiveConfig, ArchiveId, VolumeId};
use serde::{Deserialize, Serialize};

/// Magic bytes for ERA v8.1: "ERA\x08\x01\x00\x00\x00"
pub const MAGIC: [u8; 8] = [0x45, 0x52, 0x41, 0x08, 0x01, 0x00, 0x00, 0x00];

/// Current header version (incremented for certificate support)
pub const HEADER_VERSION: u16 = 2;

/// Size of the header region (4KB aligned)
pub const HEADER_SIZE: usize = 4096;

/// Data region start offset (after header + backup footer gap)
/// V8.1 layout: [Header 4096] [Backup Footer Gap 128] [Data Region...]
pub const DATA_REGION_START: u64 = (HEADER_SIZE + crate::footer::BACKUP_FOOTER_GAP) as u64; // 4224

/// Recipient type for the multi-recipient envelope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientType {
    ScryptPassword,
    X25519PubKey,
    Fido2Hmac,
}

/// A recipient slot containing an encrypted master key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientSlot {
    pub r_type: RecipientType,
    /// Optional Key ID (e.g., fingerprint) for fast matching
    pub key_id: Option<[u8; 8]>,
    /// Dynamic parameters (Salt, Nonce, Scrypt params, etc.)
    pub params: Vec<u8>,
    /// The Master Key wrapped by this recipient's specific credential
    pub encrypted_master_key: Vec<u8>,
}

impl RecipientSlot {
    pub fn new(
        r_type: RecipientType,
        key_id: Option<[u8; 8]>,
        params: Vec<u8>,
        encrypted_master_key: Vec<u8>,
    ) -> Self {
        Self {
            r_type,
            key_id,
            params,
            encrypted_master_key,
        }
    }
}

/// Super header - stored at the beginning of each volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperHeader {
    /// Magic bytes to identify ERA format
    pub magic: [u8; 8],
    /// Header version
    pub version: u16,
    /// Volume UUID
    pub volume_id: VolumeId,
    /// Archive UUID (same across all volumes in an archive set)
    pub archive_id: ArchiveId,
    /// Volume sequence number (0-based)
    pub volume_sequence: u16,
    /// Total number of volumes in this archive set
    /// Set to 0 if unknown at creation time (will be updated on finalize)
    pub total_volumes: u16,
    /// Creation timestamp (Unix seconds)
    pub creation_time: i64,
    /// Feature flags
    pub feature_flags: u64,
    /// Recipient slots (Dynamic Multi-Recipient Envelope)
    pub recipients: Vec<RecipientSlot>,
    /// Archive configuration
    pub config: ArchiveConfig,
    /// Archive-wide salt (16 bytes) for key context/nonce generation
    pub salt: [u8; 16],
}

impl SuperHeader {
    /// Create a new super header for a new archive
    ///
    /// # Arguments
    /// * `archive_id` - Unique archive identifier
    /// * `recipients` - List of recipient slots
    /// * `config` - Archive configuration
    /// * `salt` - Random salt for the archive context
    pub fn new(
        archive_id: ArchiveId,
        recipients: Vec<RecipientSlot>,
        config: ArchiveConfig,
        salt: [u8; 16],
    ) -> Self {
        Self {
            magic: MAGIC,
            version: HEADER_VERSION,
            volume_id: VolumeId::new(),
            archive_id,
            volume_sequence: 0,
            total_volumes: 0, // Unknown at creation, set by writer
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            feature_flags: 0,
            recipients,
            config,
            salt,
        }
    }

    /// Create a header for a subsequent volume in the same archive
    pub fn next_volume(&self) -> Self {
        Self {
            magic: self.magic,
            version: self.version,
            volume_id: VolumeId::new(),
            archive_id: self.archive_id,
            volume_sequence: self.volume_sequence + 1,
            total_volumes: self.total_volumes, // Inherit from parent
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            feature_flags: self.feature_flags,
            recipients: self.recipients.clone(),
            config: self.config.clone(),
            salt: self.salt,
        }
    }

    /// Serialize the header to bytes (padded to HEADER_SIZE)
    pub fn to_bytes(&self) -> era_common::Result<Vec<u8>> {
        use prost::Message;
        let proto: proto::SuperHeader = self.clone().into();
        let mut data = Vec::new();
        proto
            .encode_length_delimited(&mut data)
            .map_err(|e| era_common::EraError::Serialization(e.to_string()))?;

        // Pad to HEADER_SIZE
        if data.len() < HEADER_SIZE {
            data.resize(HEADER_SIZE, 0);
        } else if data.len() > HEADER_SIZE {
            return Err(era_common::EraError::Serialization(format!(
                "Header too large: {} > {}",
                data.len(),
                HEADER_SIZE
            )));
        }

        Ok(data)
    }

    /// Deserialize a header from bytes
    pub fn from_bytes(data: &[u8]) -> era_common::Result<Self> {
        use prost::Message;

        let proto = proto::SuperHeader::decode_length_delimited(data)
            .map_err(|e| era_common::EraError::Deserialization(e.to_string()))?;

        // Validate magic before conversion
        if proto.magic != MAGIC.as_slice() {
            return Err(era_common::EraError::InvalidMagic);
        }

        let header: Self = proto.into();

        Ok(header)
    }
}

use era_common::proto;

impl From<RecipientSlot> for proto::RecipientSlot {
    fn from(slot: RecipientSlot) -> Self {
        Self {
            r#type: match slot.r_type {
                RecipientType::ScryptPassword => {
                    proto::recipient_slot::RecipientType::ScryptPassword.into()
                }
                RecipientType::X25519PubKey => {
                    proto::recipient_slot::RecipientType::X25519Pubkey.into()
                }
                RecipientType::Fido2Hmac => proto::recipient_slot::RecipientType::Fido2Hmac.into(),
            },
            key_id: slot.key_id.map(|k| k.to_vec()).unwrap_or_default(),
            params: slot.params,
            encrypted_master_key: slot.encrypted_master_key,
        }
    }
}

impl From<proto::RecipientSlot> for RecipientSlot {
    fn from(proto: proto::RecipientSlot) -> Self {
        let r_type = proto.r#type();
        Self {
            r_type: match r_type {
                proto::recipient_slot::RecipientType::ScryptPassword => {
                    RecipientType::ScryptPassword
                }
                proto::recipient_slot::RecipientType::X25519Pubkey => RecipientType::X25519PubKey,
                proto::recipient_slot::RecipientType::Fido2Hmac => RecipientType::Fido2Hmac,
            },
            key_id: if proto.key_id.is_empty() {
                None
            } else {
                Some(proto.key_id.try_into().unwrap_or([0u8; 8]))
            },
            params: proto.params,
            encrypted_master_key: proto.encrypted_master_key,
        }
    }
}

impl From<SuperHeader> for proto::SuperHeader {
    fn from(header: SuperHeader) -> Self {
        Self {
            magic: header.magic.to_vec(),
            version: header.version as u32,
            volume_id: header.volume_id.0.as_bytes().to_vec(),
            archive_id: header.archive_id.0.as_bytes().to_vec(),
            volume_sequence: header.volume_sequence as u32,
            total_volumes: header.total_volumes as u32,
            creation_time: header.creation_time,
            feature_flags: header.feature_flags,
            recipients: header.recipients.into_iter().map(Into::into).collect(),
            config: Some(header.config.into()),
            salt: header.salt.to_vec(),
        }
    }
}

impl From<proto::SuperHeader> for SuperHeader {
    fn from(proto: proto::SuperHeader) -> Self {
        Self {
            magic: proto.magic.try_into().unwrap_or(MAGIC),
            version: proto.version as u16,
            volume_id: VolumeId(
                uuid::Uuid::from_slice(&proto.volume_id).unwrap_or(uuid::Uuid::nil()),
            ),
            archive_id: ArchiveId(
                uuid::Uuid::from_slice(&proto.archive_id).unwrap_or(uuid::Uuid::nil()),
            ),
            volume_sequence: proto.volume_sequence as u16,
            total_volumes: proto.total_volumes as u16,
            creation_time: proto.creation_time,
            feature_flags: proto.feature_flags,
            recipients: proto.recipients.into_iter().map(Into::into).collect(),
            config: proto.config.map(Into::into).unwrap_or_default(),
            salt: proto.salt.try_into().unwrap_or([0u8; 16]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARAMS: [u8; 16] = [0xABu8; 16];

    fn mock_recipient() -> RecipientSlot {
        RecipientSlot::new(
            RecipientType::ScryptPassword,
            Some([0x12; 8]),
            TEST_PARAMS.to_vec(),
            vec![1, 2, 3, 4],
        )
    }

    #[test]
    fn test_header_roundtrip() {
        let recipients = vec![mock_recipient()];
        let header = SuperHeader::new(
            ArchiveId::new(),
            recipients.clone(),
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE, "Header must be 4KB padded");

        let restored = SuperHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.magic, MAGIC);
        assert_eq!(restored.version, HEADER_VERSION);
        assert_eq!(restored.archive_id.0, header.archive_id.0);
        assert_eq!(restored.recipients.len(), 1);
        assert_eq!(restored.recipients[0].params, TEST_PARAMS.to_vec());
    }

    #[test]
    fn test_next_volume() {
        let recipients = vec![mock_recipient()];
        let header1 = SuperHeader::new(
            ArchiveId::new(),
            recipients,
            ArchiveConfig::default(),
            [0u8; 16],
        );

        let header2 = header1.next_volume();

        assert_eq!(header2.archive_id.0, header1.archive_id.0);
        assert_ne!(header2.volume_id.0, header1.volume_id.0);
        assert_eq!(header2.volume_sequence, 1);
        assert_eq!(header2.recipients.len(), 1);
    }
}
