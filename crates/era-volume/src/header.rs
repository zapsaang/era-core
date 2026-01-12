//! Volume header structures.

use era_common::{ArchiveConfig, ArchiveId, VolumeId};
use serde::{Deserialize, Serialize};

/// Magic bytes for ERA v8.1: "ERA\x08\x01\x00\x00\x00"
pub const MAGIC: [u8; 8] = [0x45, 0x52, 0x41, 0x08, 0x01, 0x00, 0x00, 0x00];

/// Current header version
pub const HEADER_VERSION: u16 = 1;

/// Size of the header region (4KB aligned)
pub const HEADER_SIZE: usize = 4096;

/// Cryptographic anchor containing key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAnchor {
    /// Salt for key derivation (16 bytes)
    pub salt: [u8; 16],
    /// Memory cost for Argon2id (KB)
    pub kdf_memory_cost: u32,
    /// Time cost for Argon2id (iterations)
    pub kdf_time_cost: u32,
    /// Parallelism for Argon2id
    pub kdf_parallelism: u32,
    /// Password verification tag (16 bytes) - allows early detection of wrong password
    /// This is HMAC(key, "ERA-PASSWORD-VERIFY") truncated to 16 bytes
    pub password_verification_tag: [u8; 16],
}

impl CryptoAnchor {
    /// Create a new crypto anchor with the given salt and verification tag
    pub fn new(salt: [u8; 16], password_verification_tag: [u8; 16]) -> Self {
        Self {
            salt,
            kdf_memory_cost: 65536, // 64 MB
            kdf_time_cost: 3,
            kdf_parallelism: 4,
            password_verification_tag,
        }
    }

    /// Create a new crypto anchor with default KDF parameters
    pub fn with_params(
        salt: [u8; 16],
        password_verification_tag: [u8; 16],
        kdf_memory_cost: u32,
        kdf_time_cost: u32,
        kdf_parallelism: u32,
    ) -> Self {
        Self {
            salt,
            kdf_memory_cost,
            kdf_time_cost,
            kdf_parallelism,
            password_verification_tag,
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
    /// Creation timestamp (Unix seconds)
    pub creation_time: i64,
    /// Feature flags
    pub feature_flags: u64,
    /// Cryptographic parameters
    pub crypto_anchor: CryptoAnchor,
    /// Archive configuration
    pub config: ArchiveConfig,
}

impl SuperHeader {
    /// Create a new super header for a new archive
    ///
    /// # Arguments
    /// * `archive_id` - Unique archive identifier
    /// * `salt` - 16-byte salt for key derivation
    /// * `password_verification_tag` - 16-byte tag for password verification
    /// * `config` - Archive configuration
    pub fn new(
        archive_id: ArchiveId,
        salt: [u8; 16],
        password_verification_tag: [u8; 16],
        config: ArchiveConfig,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: HEADER_VERSION,
            volume_id: VolumeId::new(),
            archive_id,
            volume_sequence: 0,
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            feature_flags: 0,
            crypto_anchor: CryptoAnchor::new(salt, password_verification_tag),
            config,
        }
    }

    /// Create a new super header with custom KDF parameters
    pub fn with_kdf_params(
        archive_id: ArchiveId,
        salt: [u8; 16],
        password_verification_tag: [u8; 16],
        kdf_memory_cost: u32,
        kdf_time_cost: u32,
        config: ArchiveConfig,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: HEADER_VERSION,
            volume_id: VolumeId::new(),
            archive_id,
            volume_sequence: 0,
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            feature_flags: 0,
            crypto_anchor: CryptoAnchor::with_params(
                salt,
                password_verification_tag,
                kdf_memory_cost,
                kdf_time_cost,
                4, // parallelism
            ),
            config,
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
            creation_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            feature_flags: self.feature_flags,
            crypto_anchor: self.crypto_anchor.clone(),
            config: self.config.clone(),
        }
    }

    /// Serialize the header to bytes (padded to HEADER_SIZE)
    pub fn to_bytes(&self) -> era_common::Result<Vec<u8>> {
        let mut data = era_common::serialize(self)?;

        // Pad to HEADER_SIZE
        if data.len() < HEADER_SIZE {
            data.resize(HEADER_SIZE, 0);
        }

        Ok(data)
    }

    /// Deserialize a header from bytes
    pub fn from_bytes(data: &[u8]) -> era_common::Result<Self> {
        let header: Self = era_common::deserialize(data)?;

        // Validate magic
        if header.magic != MAGIC {
            return Err(era_common::EraError::InvalidMagic);
        }

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test verification tag for unit tests
    const TEST_VERIFICATION_TAG: [u8; 16] = [0xABu8; 16];

    #[test]
    fn test_header_roundtrip() {
        let header = SuperHeader::new(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
        );

        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let restored = SuperHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.magic, MAGIC);
        assert_eq!(restored.version, HEADER_VERSION);
        assert_eq!(restored.archive_id.0, header.archive_id.0);
        assert_eq!(
            restored.crypto_anchor.password_verification_tag,
            TEST_VERIFICATION_TAG
        );
    }

    #[test]
    fn test_next_volume() {
        let header1 = SuperHeader::new(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
        );

        let header2 = header1.next_volume();

        assert_eq!(header2.archive_id.0, header1.archive_id.0);
        assert_ne!(header2.volume_id.0, header1.volume_id.0);
        assert_eq!(header2.volume_sequence, 1);
        // Verification tag should be preserved across volumes
        assert_eq!(
            header2.crypto_anchor.password_verification_tag,
            TEST_VERIFICATION_TAG
        );
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let header = SuperHeader::new(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
        );

        let mut bytes = header.to_bytes().unwrap();
        // Corrupt the magic bytes
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;

        let result = SuperHeader::from_bytes(&bytes);
        assert!(result.is_err());
        match result {
            Err(era_common::EraError::InvalidMagic) => {}
            Err(e) => panic!("Expected InvalidMagic error, got: {:?}", e),
            Ok(_) => panic!("Expected error, but got Ok"),
        }
    }

    #[test]
    fn test_crypto_anchor_with_params() {
        let anchor = CryptoAnchor::with_params(
            [1u8; 16], [2u8; 16], 131072, // 128 MB
            5, 8,
        );
        assert_eq!(anchor.salt, [1u8; 16]);
        assert_eq!(anchor.password_verification_tag, [2u8; 16]);
        assert_eq!(anchor.kdf_memory_cost, 131072);
        assert_eq!(anchor.kdf_time_cost, 5);
        assert_eq!(anchor.kdf_parallelism, 8);
    }

    #[test]
    fn test_header_with_kdf_params() {
        let header = SuperHeader::with_kdf_params(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            131072, // 128 MB
            5,
            ArchiveConfig::default(),
        );

        assert_eq!(header.crypto_anchor.kdf_memory_cost, 131072);
        assert_eq!(header.crypto_anchor.kdf_time_cost, 5);

        // Round-trip should preserve KDF params
        let bytes = header.to_bytes().unwrap();
        let restored = SuperHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.crypto_anchor.kdf_memory_cost, 131072);
        assert_eq!(restored.crypto_anchor.kdf_time_cost, 5);
    }

    #[test]
    fn test_header_size_is_4kb() {
        // Ensure our header serialization always produces 4KB
        let header = SuperHeader::new(
            ArchiveId::new(),
            [0u8; 16],
            TEST_VERIFICATION_TAG,
            ArchiveConfig::default(),
        );

        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), 4096);
    }

    #[test]
    fn test_different_salts_produce_different_anchors() {
        let anchor1 = CryptoAnchor::new([0u8; 16], [0u8; 16]);
        let anchor2 = CryptoAnchor::new([1u8; 16], [0u8; 16]);

        assert_ne!(anchor1.salt, anchor2.salt);
    }
}
