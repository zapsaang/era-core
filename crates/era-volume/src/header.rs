//! Volume header structures.

use era_common::{ArchiveConfig, ArchiveId, VolumeId};
use serde::{Deserialize, Serialize};

/// Return the current Unix timestamp as `i64`, or `InvalidConfig` on overflow.
///
/// Centralises the `SystemTime → i64` boilerplate used by both
/// [`SuperHeader::new()`] and [`SuperHeader::next_volume()`].
fn unix_timestamp_now() -> era_common::Result<i64> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs(),
    )
    .map_err(|_| era_common::EraError::InvalidConfig("creation_time exceeds i64::MAX".into()))
}

/// Magic bytes for ERA format: "ERA\x08\x01\x00\x00\x00"
pub const MAGIC: [u8; 8] = [0x45, 0x52, 0x41, 0x08, 0x01, 0x00, 0x00, 0x00];

/// Current header version
pub const HEADER_VERSION: u16 = 3;

/// Size of the header region (4KB aligned)
pub const HEADER_SIZE: usize = 4096;

/// Maximum number of recipients allowed in a single archive
pub const MAX_RECIPIENTS: usize = 256;

/// Data region start offset (after header + backup footer gap)
/// V8.1 layout: [Header 4096] [Backup Footer Gap 128] [Data Region...]
pub const DATA_REGION_START: u64 = (HEADER_SIZE + crate::footer::BACKUP_FOOTER_GAP) as u64; // 4224

/// Maximum allowed size for any single recipient field (params, encrypted_master_key).
/// Kyber-768 ciphertext is ~1088 bytes; Argon2id params ~32 bytes.
/// 4 KiB is generous headroom for any current or near-future KEM.
const MAX_RECIPIENT_FIELD_SIZE: usize = 4096;

/// Maximum allowed size for the EncryptedVolumeKey ciphertext.
/// VK is 32 bytes; XChaCha20-Poly1305 adds 16-byte tag = 48 bytes.
/// 4 KiB is generous headroom.
const MAX_EVK_CIPHERTEXT_SIZE: usize = 4096;

/// The encryption algorithm used for Key Wrapping (IK -> VK)
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyWrapAlgorithm {
    /// XChaCha20-Poly1305 AEAD (256-bit key, 192-bit nonce).
    XChaCha20Poly1305 = 0,
}

/// Access policy for multi-party decryption
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AccessPolicy {
    /// Any single recipient can unlock (OR logic)
    #[default]
    AnyOfN,
    /// T-of-N threshold required (AND logic via Shamir's Secret Sharing)
    Threshold(u32),
}

/// The encrypted Volume Key container
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedVolumeKey {
    /// The AEAD algorithm used for wrapping the Volume Key.
    algorithm: KeyWrapAlgorithm,
    /// Random nonce for the wrapping operation (24 bytes for XChaCha20)
    nonce: [u8; 24],
    /// The random VK encrypted by the IK (ciphertext + Poly1305 tag)
    ciphertext: Vec<u8>,
}

impl std::fmt::Debug for EncryptedVolumeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedVolumeKey")
            .field("algorithm", &self.algorithm)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

impl EncryptedVolumeKey {
    /// Creates a new encrypted volume key container.
    pub fn new(algorithm: KeyWrapAlgorithm, nonce: [u8; 24], ciphertext: Vec<u8>) -> Self {
        Self {
            algorithm,
            nonce,
            ciphertext,
        }
    }

    /// Returns the AEAD algorithm used for wrapping.
    pub fn algorithm(&self) -> KeyWrapAlgorithm {
        self.algorithm
    }

    /// Returns a reference to the random nonce (24 bytes).
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Returns a slice of the ciphertext (encrypted VK + Poly1305 tag).
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Test-only setter for ciphertext (adversarial mutation scenarios).
    #[doc(hidden)]
    pub fn set_ciphertext(&mut self, ct: Vec<u8>) {
        self.ciphertext = ct;
    }
}

/// Recipient type for the multi-recipient envelope
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecipientType {
    /// Password-based: Argon2id KDF derives the Master Key.
    Argon2idPassword,
    /// Public-key: X25519 (+ Kyber-768 hybrid KEM) encapsulates the Master Key.
    X25519PubKey,
    /// Hardware token: FIDO2 HMAC-secret extension derives the Master Key.
    Fido2Hmac,
}

/// A recipient slot containing an encrypted master key
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipientSlot {
    /// The type of credential used to protect this slot's master key.
    r_type: RecipientType,
    /// Optional Key ID (e.g., fingerprint) for fast matching
    key_id: Option<[u8; 8]>,
    /// Dynamic parameters (Salt, Nonce, Scrypt params, etc.)
    params: Vec<u8>,
    /// The Master Key wrapped by this recipient's specific credential
    encrypted_master_key: Vec<u8>,
}

impl RecipientSlot {
    /// Creates a new recipient slot with the given credential type and encrypted key material.
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
    /// Validates that this recipient slot's fields are within acceptable bounds.
    ///
    /// This mirrors the validation performed by `TryFrom<proto::RecipientSlot>` on
    /// the deserialization path, ensuring that programmatically-constructed slots
    /// are also checked before being accepted into a [`SuperHeader`].
    ///
    /// **Note:** [`SuperHeader::new()`] calls this method automatically for each slot,
    /// so callers do not need to invoke `validate()` before passing slots to the constructor.
    /// Direct use is appropriate when validating slots independently of header construction.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if:
    /// - `params` exceeds `MAX_RECIPIENT_FIELD_SIZE` (4096 bytes)
    /// - `encrypted_master_key` exceeds `MAX_RECIPIENT_FIELD_SIZE` (4096 bytes)
    /// - `encrypted_master_key` is shorter than 24 bytes (minimum for any AEAD output)
    pub fn validate(&self) -> era_common::Result<()> {
        if self.params.len() > MAX_RECIPIENT_FIELD_SIZE {
            return Err(era_common::EraError::InvalidConfig(format!(
                "recipient params too large: {} bytes (max {})",
                self.params.len(),
                MAX_RECIPIENT_FIELD_SIZE
            )));
        }
        if self.encrypted_master_key.len() > MAX_RECIPIENT_FIELD_SIZE {
            return Err(era_common::EraError::InvalidConfig(format!(
                "encrypted_master_key too large: {} bytes (max {})",
                self.encrypted_master_key.len(),
                MAX_RECIPIENT_FIELD_SIZE
            )));
        }
        if self.encrypted_master_key.len() < 24 {
            return Err(era_common::EraError::InvalidConfig(format!(
                "encrypted_master_key too short: {} bytes (minimum 24)",
                self.encrypted_master_key.len()
            )));
        }
        Ok(())
    }

    /// Returns the type of credential used to protect this slot.
    pub fn r_type(&self) -> RecipientType {
        self.r_type
    }

    /// Returns the optional key ID (8-byte fingerprint).
    pub fn key_id(&self) -> Option<&[u8; 8]> {
        self.key_id.as_ref()
    }

    /// Returns a slice of the dynamic parameters.
    pub fn params(&self) -> &[u8] {
        &self.params
    }

    /// Returns a slice of the encrypted master key.
    pub fn encrypted_master_key(&self) -> &[u8] {
        &self.encrypted_master_key
    }

    /// Test-only setter for params (adversarial mutation scenarios).
    #[doc(hidden)]
    pub fn set_params(&mut self, p: Vec<u8>) {
        self.params = p;
    }

    /// Test-only setter for encrypted_master_key (adversarial mutation scenarios).
    #[doc(hidden)]
    pub fn set_encrypted_master_key(&mut self, emk: Vec<u8>) {
        self.encrypted_master_key = emk;
    }
}
impl std::fmt::Debug for RecipientSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientSlot")
            .field("r_type", &self.r_type)
            .field("key_id", &self.key_id)
            .field("params", &"[REDACTED]")
            .field("encrypted_master_key", &"[REDACTED]")
            .finish()
    }
}

/// Super header - stored at the beginning of each volume
#[derive(Clone, Serialize, Deserialize)]
pub struct SuperHeader {
    /// Magic bytes to identify ERA format
    magic: [u8; 8],
    /// Header version
    version: u16,
    /// Volume UUID
    volume_id: VolumeId,
    /// Archive UUID (same across all volumes in an archive set)
    archive_id: ArchiveId,
    /// Volume sequence number (0-based)
    volume_sequence: u16,
    /// Total number of volumes in this archive set
    /// Set to 0 if unknown at creation time (will be updated on finalize)
    total_volumes: u16,
    /// Creation timestamp (Unix seconds)
    creation_time: i64,
    /// Feature flags
    feature_flags: u64,
    /// Recipient slots (Dynamic Multi-Recipient Envelope)
    recipients: Vec<RecipientSlot>,
    /// Archive configuration
    config: ArchiveConfig,
    /// Archive-wide salt (16 bytes) for key context/nonce generation
    salt: [u8; 16],
    /// Key Epoch ID. Increments when MK is rotated.
    epoch_id: u32,
    /// The Encrypted Volume Key (VK wrapped by IK derived from MK)
    encrypted_volume_key: EncryptedVolumeKey,
    /// Access control policy
    access_policy: AccessPolicy,
}

impl std::fmt::Debug for SuperHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuperHeader")
            .field("magic", &self.magic)
            .field("version", &self.version)
            .field("volume_id", &self.volume_id)
            .field("archive_id", &self.archive_id)
            .field("volume_sequence", &self.volume_sequence)
            .field("total_volumes", &self.total_volumes)
            .field("creation_time", &self.creation_time)
            .field("feature_flags", &self.feature_flags)
            .field("recipients", &self.recipients)
            .field("config", &self.config)
            .field("salt", &"[REDACTED]")
            .field("epoch_id", &self.epoch_id)
            .field("encrypted_volume_key", &self.encrypted_volume_key)
            .field("access_policy", &self.access_policy)
            .finish()
    }
}

impl SuperHeader {
    /// Create a new super header for a new archive.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if:
    /// - `recipients` is empty or exceeds [`MAX_RECIPIENTS`]
    /// - `access_policy` is `Threshold(t)` with `t < 2` or `t > recipients.len()`
    /// - any recipient slot fails [`RecipientSlot::validate()`] (params/key size bounds)
    /// - the system clock returns a timestamp exceeding `i64::MAX`
    pub fn new(
        archive_id: ArchiveId,
        recipients: Vec<RecipientSlot>,
        config: ArchiveConfig,
        salt: [u8; 16],
        encrypted_volume_key: EncryptedVolumeKey,
        access_policy: AccessPolicy,
    ) -> era_common::Result<Self> {
        if recipients.is_empty() {
            return Err(era_common::EraError::InvalidConfig(
                "Archive must have at least one recipient".into(),
            ));
        }
        if recipients.len() > MAX_RECIPIENTS {
            return Err(era_common::EraError::InvalidConfig(format!(
                "too many recipients: {} exceeds maximum {}",
                recipients.len(),
                MAX_RECIPIENTS
            )));
        }
        // CB25-01: Validate AccessPolicy at construction time, not just on deserialization
        if let AccessPolicy::Threshold(t) = access_policy {
            if t < 2 {
                return Err(era_common::EraError::InvalidConfig(format!(
                    "Invalid threshold: {} (minimum 2)",
                    t
                )));
            }
            // IS31-01: Threshold must not exceed recipient count (T-of-N requires T <= N)
            let t_usize = usize::try_from(t).map_err(|_| {
                era_common::EraError::InvalidConfig(format!("Threshold {} overflows usize", t))
            })?;
            if t_usize > recipients.len() {
                return Err(era_common::EraError::InvalidConfig(format!(
                    "Threshold {} exceeds recipient count {} (T-of-N requires T <= N)",
                    t,
                    recipients.len()
                )));
            }
        }
        // CB25-02: Validate each recipient slot's field bounds at construction time
        for (i, slot) in recipients.iter().enumerate() {
            slot.validate().map_err(|e| {
                era_common::EraError::InvalidConfig(format!("recipient slot {}: {}", i, e))
            })?;
        }
        let creation_time = unix_timestamp_now()?;
        Ok(Self {
            magic: MAGIC,
            version: HEADER_VERSION,
            volume_id: VolumeId::new(),
            archive_id,
            volume_sequence: 0,
            total_volumes: 0,
            creation_time,
            feature_flags: 0,
            recipients,
            config,
            salt,
            epoch_id: 0,
            encrypted_volume_key,
            access_policy,
        })
    }

    /// Create a header for a subsequent volume in the same archive.
    ///
    /// # Errors
    /// Returns `InvalidConfig` if `volume_sequence` would overflow `u16::MAX`,
    /// if `total_volumes > 0` and the next sequence would equal or exceed it,
    /// or if the system clock returns a timestamp exceeding `i64::MAX`.
    pub fn next_volume(&self) -> era_common::Result<Self> {
        Ok(Self {
            magic: self.magic,
            version: self.version,
            volume_id: VolumeId::new(),
            archive_id: self.archive_id,
            volume_sequence: {
                let next_seq = self.volume_sequence.checked_add(1).ok_or_else(|| {
                    era_common::EraError::InvalidConfig(
                        "volume sequence overflow at u16::MAX".into(),
                    )
                })?;
                // CV32-02: Prevent creating a volume whose sequence violates the IS31-02 invariant
                if self.total_volumes > 0 && next_seq >= self.total_volumes {
                    return Err(era_common::EraError::InvalidConfig(format!(
                        "next volume_sequence {} would equal or exceed total_volumes {}",
                        next_seq, self.total_volumes
                    )));
                }
                next_seq
            },
            total_volumes: self.total_volumes,
            creation_time: unix_timestamp_now()?,
            feature_flags: self.feature_flags,
            recipients: self.recipients.clone(),
            config: self.config.clone(),
            salt: self.salt,
            epoch_id: self.epoch_id,
            encrypted_volume_key: self.encrypted_volume_key.clone(),
            access_policy: self.access_policy,
        })
    }

    /// Convert to protobuf representation by borrowing, avoiding a full struct clone.
    /// Only heap-allocated fields (`recipients`, `config`, `encrypted_volume_key`) are
    /// cloned individually; fixed-size fields are copied.
    fn to_proto(&self) -> proto::SuperHeader {
        let (access_policy, threshold) = match self.access_policy {
            AccessPolicy::AnyOfN => (proto::AccessPolicy::AnyOfN.into(), 0u32),
            AccessPolicy::Threshold(t) => (proto::AccessPolicy::Threshold.into(), t),
        };
        proto::SuperHeader {
            magic: self.magic.to_vec(),
            version: self.version as u32,
            volume_id: self.volume_id.0.as_bytes().to_vec(),
            archive_id: self.archive_id.0.as_bytes().to_vec(),
            volume_sequence: self.volume_sequence as u32,
            total_volumes: self.total_volumes as u32,
            creation_time: self.creation_time,
            feature_flags: self.feature_flags,
            recipients: self
                .recipients
                .iter()
                .map(|s| proto::RecipientSlot {
                    r#type: match s.r_type {
                        RecipientType::Argon2idPassword => {
                            proto::recipient_slot::RecipientType::Argon2idPassword.into()
                        }
                        RecipientType::X25519PubKey => {
                            proto::recipient_slot::RecipientType::X25519Pubkey.into()
                        }
                        RecipientType::Fido2Hmac => {
                            proto::recipient_slot::RecipientType::Fido2Hmac.into()
                        }
                    },
                    key_id: s.key_id.map(|k| k.to_vec()).unwrap_or_default(),
                    params: s.params.clone(),
                    encrypted_master_key: s.encrypted_master_key.clone(),
                })
                .collect(),
            config: Some(self.config.clone().into()),
            salt: self.salt.to_vec(),
            epoch_id: self.epoch_id,
            encrypted_volume_key: Some(proto::EncryptedVolumeKey {
                algorithm: match self.encrypted_volume_key.algorithm {
                    KeyWrapAlgorithm::XChaCha20Poly1305 => {
                        proto::KeyWrapAlgorithm::Xchacha20Poly1305.into()
                    }
                },
                nonce: self.encrypted_volume_key.nonce.to_vec(),
                ciphertext: self.encrypted_volume_key.ciphertext.clone(),
            }),
            access_policy,
            threshold,
        }
    }

    /// Serialize the header to bytes (padded to [`HEADER_SIZE`]).
    ///
    /// # Errors
    /// Returns `Serialization` if protobuf encoding fails or the encoded header exceeds [`HEADER_SIZE`].
    pub fn to_bytes(&self) -> era_common::Result<Vec<u8>> {
        use prost::Message;
        let proto = self.to_proto();
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

    /// Deserialize a header from bytes.
    ///
    /// # Errors
    /// Returns `CorruptedHeader` if the data exceeds [`HEADER_SIZE`], has invalid magic/version,
    /// or contains malformed protobuf fields.
    pub fn from_bytes(data: &[u8]) -> era_common::Result<Self> {
        use prost::Message;

        // D10-03: Pre-decode size limit to prevent prost from allocating
        // unbounded memory during protobuf decoding. The header region is
        // HEADER_SIZE (4096) bytes, so legitimate protobuf data cannot exceed this.
        if data.len() > HEADER_SIZE {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "header data too large: {} bytes (max {})",
                data.len(),
                HEADER_SIZE
            )));
        }

        let proto = proto::SuperHeader::decode_length_delimited(data)
            .map_err(|e| era_common::EraError::Deserialization(e.to_string()))?;

        // Validate magic before conversion
        if proto.magic != MAGIC.as_slice() {
            return Err(era_common::EraError::InvalidMagic);
        }

        let header: Self = proto.try_into()?;

        Ok(header)
    }

    // ── Accessors ──

    /// Returns the magic bytes.
    pub fn magic(&self) -> &[u8; 8] {
        &self.magic
    }

    /// Returns the header version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Returns the volume UUID.
    pub fn volume_id(&self) -> VolumeId {
        self.volume_id
    }

    /// Returns the archive UUID.
    pub fn archive_id(&self) -> ArchiveId {
        self.archive_id
    }

    /// Returns the volume sequence number (0-based).
    pub fn volume_sequence(&self) -> u16 {
        self.volume_sequence
    }

    /// Returns the total number of volumes (0 if unknown).
    pub fn total_volumes(&self) -> u16 {
        self.total_volumes
    }

    /// Returns the creation timestamp (Unix seconds).
    pub fn creation_time(&self) -> i64 {
        self.creation_time
    }

    /// Returns the feature flags.
    pub fn feature_flags(&self) -> u64 {
        self.feature_flags
    }

    /// Returns a slice of recipient slots.
    pub fn recipients(&self) -> &[RecipientSlot] {
        &self.recipients
    }

    /// Returns a reference to the archive configuration.
    pub fn config(&self) -> &ArchiveConfig {
        &self.config
    }

    /// Returns a reference to the archive-wide salt (16 bytes).
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Returns the key epoch ID.
    pub fn epoch_id(&self) -> u32 {
        self.epoch_id
    }

    /// Returns a reference to the encrypted volume key container.
    pub fn encrypted_volume_key(&self) -> &EncryptedVolumeKey {
        &self.encrypted_volume_key
    }

    /// Returns the access control policy.
    pub fn access_policy(&self) -> AccessPolicy {
        self.access_policy
    }

    // ── Setters (internal use + adversarial tests) ──

    /// Sets the volume UUID (used by volume pool during rotation).
    #[doc(hidden)]
    pub fn set_volume_id(&mut self, id: VolumeId) {
        self.volume_id = id;
    }

    /// Sets the volume sequence number.
    #[doc(hidden)]
    pub fn set_volume_sequence(&mut self, seq: u16) {
        self.volume_sequence = seq;
    }

    /// Sets the total number of volumes.
    #[doc(hidden)]
    pub fn set_total_volumes(&mut self, total: u16) {
        self.total_volumes = total;
    }

    // ── Test-only setters (adversarial mutation scenarios) ──

    /// Test-only setter for epoch_id.
    #[doc(hidden)]
    pub fn set_epoch_id(&mut self, id: u32) {
        self.epoch_id = id;
    }

    /// Test-only setter for access_policy.
    #[doc(hidden)]
    pub fn set_access_policy(&mut self, policy: AccessPolicy) {
        self.access_policy = policy;
    }

    /// Test-only setter for version.
    #[doc(hidden)]
    pub fn set_version(&mut self, v: u16) {
        self.version = v;
    }
    /// Test-only constructor with full field control (property tests).
    /// Does NOT validate fields — callers are responsible for providing valid data.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_testing(
        archive_id: ArchiveId,
        volume_id: VolumeId,
        volume_sequence: u16,
        total_volumes: u16,
        creation_time: i64,
        feature_flags: u64,
        recipients: Vec<RecipientSlot>,
        salt: [u8; 16],
        epoch_id: u32,
        encrypted_volume_key: EncryptedVolumeKey,
        access_policy: AccessPolicy,
    ) -> Self {
        Self {
            magic: MAGIC,
            version: HEADER_VERSION,
            volume_id,
            archive_id,
            volume_sequence,
            total_volumes,
            creation_time,
            feature_flags,
            recipients,
            config: ArchiveConfig::default(),
            salt,
            epoch_id,
            encrypted_volume_key,
            access_policy,
        }
    }
}

use era_common::proto;

impl From<RecipientSlot> for proto::RecipientSlot {
    fn from(slot: RecipientSlot) -> Self {
        Self {
            r#type: match slot.r_type {
                RecipientType::Argon2idPassword => {
                    proto::recipient_slot::RecipientType::Argon2idPassword.into()
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

impl TryFrom<proto::RecipientSlot> for RecipientSlot {
    type Error = era_common::EraError;

    fn try_from(proto: proto::RecipientSlot) -> std::result::Result<Self, Self::Error> {
        // EV36-01: Use raw i32 field instead of generated accessor which silently
        // maps unknown enum values to the default variant (Argon2idPassword/0).
        let r_type =
            proto::recipient_slot::RecipientType::try_from(proto.r#type).map_err(|_| {
                era_common::EraError::CorruptedHeader(format!(
                    "Unknown RecipientType value: {}",
                    proto.r#type
                ))
            })?;

        let key_id = if proto.key_id.is_empty() {
            None
        } else {
            Some(proto.key_id.as_slice().try_into().map_err(|_| {
                era_common::EraError::CorruptedHeader("Invalid key_id length".into())
            })?)
        };

        // D10-02: Upper bound on params to prevent allocation bomb
        if proto.params.len() > MAX_RECIPIENT_FIELD_SIZE {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "recipient params too large: {} bytes (max {})",
                proto.params.len(),
                MAX_RECIPIENT_FIELD_SIZE
            )));
        }
        // D10-02: Upper bound on encrypted_master_key
        if proto.encrypted_master_key.len() > MAX_RECIPIENT_FIELD_SIZE {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "encrypted_master_key too large: {} bytes (max {})",
                proto.encrypted_master_key.len(),
                MAX_RECIPIENT_FIELD_SIZE
            )));
        }

        if proto.encrypted_master_key.len() < 24 {
            return Err(era_common::EraError::CorruptedHeader(
                "encrypted_master_key too short (min 24 bytes)".into(),
            ));
        }

        Ok(Self {
            r_type: match r_type {
                proto::recipient_slot::RecipientType::Argon2idPassword => {
                    RecipientType::Argon2idPassword
                }
                proto::recipient_slot::RecipientType::X25519Pubkey => RecipientType::X25519PubKey,
                proto::recipient_slot::RecipientType::Fido2Hmac => RecipientType::Fido2Hmac,
            },
            key_id,
            params: proto.params,
            encrypted_master_key: proto.encrypted_master_key,
        })
    }
}

impl From<EncryptedVolumeKey> for proto::EncryptedVolumeKey {
    fn from(evk: EncryptedVolumeKey) -> Self {
        Self {
            algorithm: match evk.algorithm {
                KeyWrapAlgorithm::XChaCha20Poly1305 => {
                    proto::KeyWrapAlgorithm::Xchacha20Poly1305.into()
                }
            },
            nonce: evk.nonce.to_vec(),
            ciphertext: evk.ciphertext,
        }
    }
}

impl TryFrom<proto::EncryptedVolumeKey> for EncryptedVolumeKey {
    type Error = era_common::EraError;

    fn try_from(proto: proto::EncryptedVolumeKey) -> std::result::Result<Self, Self::Error> {
        let nonce: [u8; 24] = proto
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| era_common::EraError::CorruptedHeader("Invalid nonce".into()))?;
        if proto.ciphertext.is_empty() {
            return Err(era_common::EraError::CorruptedHeader(
                "Missing ciphertext".into(),
            ));
        }
        // C12-02: Minimum ciphertext length — Poly1305 tag alone is 16 bytes
        const MIN_EVK_CIPHERTEXT_SIZE: usize = 16;
        if proto.ciphertext.len() < MIN_EVK_CIPHERTEXT_SIZE {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "EVK ciphertext too short: {} bytes (minimum {})",
                proto.ciphertext.len(),
                MIN_EVK_CIPHERTEXT_SIZE
            )));
        }
        // D10-02: Upper bound on ciphertext to prevent allocation bomb
        if proto.ciphertext.len() > MAX_EVK_CIPHERTEXT_SIZE {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "EVK ciphertext too large: {} bytes (max {})",
                proto.ciphertext.len(),
                MAX_EVK_CIPHERTEXT_SIZE
            )));
        }
        // EV36-03: Validate algorithm field instead of hardcoding.
        let algorithm = match proto::KeyWrapAlgorithm::try_from(proto.algorithm) {
            Ok(proto::KeyWrapAlgorithm::Xchacha20Poly1305) => KeyWrapAlgorithm::XChaCha20Poly1305,
            Err(_) => {
                return Err(era_common::EraError::CorruptedHeader(format!(
                    "Unknown KeyWrapAlgorithm value: {}",
                    proto.algorithm
                )));
            }
        };
        Ok(Self {
            algorithm,
            nonce,
            ciphertext: proto.ciphertext,
        })
    }
}

impl From<SuperHeader> for proto::SuperHeader {
    fn from(header: SuperHeader) -> Self {
        let (access_policy, threshold) = match header.access_policy {
            AccessPolicy::AnyOfN => (proto::AccessPolicy::AnyOfN.into(), 0u32),
            AccessPolicy::Threshold(t) => (proto::AccessPolicy::Threshold.into(), t),
        };
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
            epoch_id: header.epoch_id,
            encrypted_volume_key: Some(header.encrypted_volume_key.into()),
            access_policy,
            threshold,
        }
    }
}

impl TryFrom<proto::SuperHeader> for SuperHeader {
    type Error = era_common::EraError;

    fn try_from(proto: proto::SuperHeader) -> std::result::Result<Self, Self::Error> {
        let magic: [u8; 8] = proto
            .magic
            .as_slice()
            .try_into()
            .map_err(|_| era_common::EraError::InvalidMagic)?;
        if magic != MAGIC {
            return Err(era_common::EraError::InvalidMagic);
        }
        let version = u16::try_from(proto.version).map_err(|_| {
            era_common::EraError::CorruptedHeader("version field out of u16 range".into())
        })?;
        if version != HEADER_VERSION {
            return Err(era_common::EraError::UnsupportedVersion {
                version: proto.version,
            });
        }
        // EV36-02: Use raw i32 field instead of generated accessor which silently
        // maps unknown enum values to the default variant (AnyOfN/0).
        let proto_access_policy =
            proto::AccessPolicy::try_from(proto.access_policy).map_err(|_| {
                era_common::EraError::CorruptedHeader(format!(
                    "Unknown AccessPolicy value: {}",
                    proto.access_policy
                ))
            })?;
        let access_policy = match proto_access_policy {
            proto::AccessPolicy::AnyOfN => AccessPolicy::AnyOfN,
            proto::AccessPolicy::Threshold => {
                if proto.threshold < 2 {
                    return Err(era_common::EraError::CorruptedHeader(format!(
                        "Invalid threshold: {} (minimum 2)",
                        proto.threshold
                    )));
                }
                AccessPolicy::Threshold(proto.threshold)
            }
        };
        let encrypted_volume_key = proto
            .encrypted_volume_key
            .ok_or_else(|| era_common::EraError::CorruptedHeader("Missing EVK".into()))?
            .try_into()?;
        let recipients: Vec<RecipientSlot> = proto
            .recipients
            .into_iter()
            .map(|r| r.try_into())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if recipients.is_empty() {
            return Err(era_common::EraError::CorruptedHeader(
                "Archive must have at least one recipient".into(),
            ));
        }
        if recipients.len() > MAX_RECIPIENTS {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "too many recipients: {} exceeds maximum {}",
                recipients.len(),
                MAX_RECIPIENTS
            )));
        }
        // IS31-01: Cross-validate threshold against recipient count on deserialization
        if let AccessPolicy::Threshold(t) = access_policy {
            let t_usize = usize::try_from(t).map_err(|_| {
                era_common::EraError::CorruptedHeader(format!("Threshold {} overflows usize", t))
            })?;
            if t_usize > recipients.len() {
                return Err(era_common::EraError::CorruptedHeader(format!(
                    "Threshold {} exceeds recipient count {} (T-of-N requires T <= N)",
                    t,
                    recipients.len()
                )));
            }
        }
        // IS31-02: Cross-validate volume_sequence against total_volumes on deserialization
        let volume_sequence = u16::try_from(proto.volume_sequence).map_err(|_| {
            era_common::EraError::CorruptedHeader("volume_sequence exceeds u16".into())
        })?;
        let total_volumes = u16::try_from(proto.total_volumes).map_err(|_| {
            era_common::EraError::CorruptedHeader("total_volumes exceeds u16".into())
        })?;
        if total_volumes > 0 && volume_sequence >= total_volumes {
            return Err(era_common::EraError::CorruptedHeader(format!(
                "volume_sequence {} >= total_volumes {} (0-based sequence must be < total)",
                volume_sequence, total_volumes
            )));
        }
        Ok(Self {
            magic,
            version,
            volume_id: VolumeId(
                uuid::Uuid::from_slice(&proto.volume_id)
                    .map_err(|_| era_common::EraError::CorruptedHeader("Invalid UUID".into()))?,
            ),
            archive_id: ArchiveId(
                uuid::Uuid::from_slice(&proto.archive_id)
                    .map_err(|_| era_common::EraError::CorruptedHeader("Invalid UUID".into()))?,
            ),
            volume_sequence,
            total_volumes,
            creation_time: proto.creation_time,
            // FC39-01: Reject unknown feature flags. No flags are currently defined,
            // so any non-zero value indicates a newer format that this reader cannot handle.
            feature_flags: {
                if proto.feature_flags != 0 {
                    return Err(era_common::EraError::CorruptedHeader(format!(
                        "Unknown feature flags: 0x{:016X} (this reader supports none)",
                        proto.feature_flags
                    )));
                }
                proto.feature_flags
            },
            recipients,
            config: proto
                .config
                .ok_or_else(|| era_common::EraError::CorruptedHeader("Missing config".into()))?
                .try_into()?,
            salt: proto
                .salt
                .as_slice()
                .try_into()
                .map_err(|_| era_common::EraError::CorruptedHeader("Corrupted salt".into()))?,
            epoch_id: proto.epoch_id,
            encrypted_volume_key,
            access_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PARAMS: [u8; 16] = [0xABu8; 16];

    fn mock_recipient() -> RecipientSlot {
        RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            TEST_PARAMS.to_vec(),
            vec![0xCD; 48],
        )
    }

    fn mock_encrypted_vk() -> EncryptedVolumeKey {
        EncryptedVolumeKey::new(
            KeyWrapAlgorithm::XChaCha20Poly1305,
            [0xAA; 24],
            vec![0xBB; 48], // 32 bytes VK + 16 bytes tag
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
            mock_encrypted_vk(),
            AccessPolicy::AnyOfN,
        )
        .unwrap();

        let bytes = header.to_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE, "Header must be 4KB padded");

        let restored = SuperHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.magic(), &MAGIC);
        assert_eq!(restored.version(), HEADER_VERSION);
        assert_eq!(restored.archive_id().0, header.archive_id().0);
        assert_eq!(restored.recipients().len(), 1);
        assert_eq!(restored.recipients()[0].params(), TEST_PARAMS.as_slice());
        assert_eq!(restored.epoch_id(), 0);
        assert_eq!(restored.encrypted_volume_key().nonce(), &[0xAA; 24]);
        assert_eq!(
            restored.encrypted_volume_key().ciphertext(),
            &vec![0xBB; 48]
        );
        assert_eq!(restored.access_policy(), AccessPolicy::AnyOfN);
    }

    #[test]
    fn test_next_volume() {
        let recipients = vec![mock_recipient()];
        let header = SuperHeader::new(
            ArchiveId::new(),
            recipients,
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::AnyOfN,
        )
        .unwrap();

        let header2 = header.next_volume().unwrap();

        assert_eq!(header2.archive_id().0, header.archive_id().0);
        assert_ne!(header2.volume_id().0, header.volume_id().0);
        assert_eq!(header2.volume_sequence(), 1);
        assert_eq!(header2.recipients().len(), 1);
        assert_eq!(header2.epoch_id(), header.epoch_id());
        assert_eq!(
            header2.encrypted_volume_key().nonce(),
            header.encrypted_volume_key().nonce()
        );
    }

    #[test]
    fn test_threshold_policy_roundtrip() {
        let header = SuperHeader::new(
            ArchiveId::new(),
            vec![mock_recipient(), mock_recipient(), mock_recipient()],
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::Threshold(3),
        )
        .unwrap();
        // No need to manually set access_policy — it's passed to new()

        let bytes = header.to_bytes().unwrap();
        let restored = SuperHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.access_policy(), AccessPolicy::Threshold(3));
    }

    // ===== CB25: Configuration Boundary Audit Tests =====

    #[test]
    fn cb25_01_threshold_zero_rejected_at_construction() {
        let result = SuperHeader::new(
            ArchiveId::new(),
            vec![mock_recipient()],
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::Threshold(0),
        );
        assert!(
            result.is_err(),
            "Threshold(0) must be rejected by SuperHeader::new()"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid threshold") || err.contains("minimum 2"),
            "Error should mention threshold: {err}"
        );
    }

    #[test]
    fn cb25_01_threshold_one_rejected_at_construction() {
        let result = SuperHeader::new(
            ArchiveId::new(),
            vec![mock_recipient()],
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::Threshold(1),
        );
        assert!(
            result.is_err(),
            "Threshold(1) must be rejected by SuperHeader::new()"
        );
    }

    #[test]
    fn cb25_01_threshold_two_accepted() {
        let result = SuperHeader::new(
            ArchiveId::new(),
            vec![mock_recipient(), mock_recipient()],
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::Threshold(2),
        );
        assert!(result.is_ok(), "Threshold(2) is the minimum valid value");
    }

    #[test]
    fn cb25_02_recipient_params_too_large_rejected() {
        let oversized_slot = RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; MAX_RECIPIENT_FIELD_SIZE + 1], // 4097 bytes
            vec![0xCD; 48],
        );
        let result = SuperHeader::new(
            ArchiveId::new(),
            vec![oversized_slot],
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::AnyOfN,
        );
        assert!(result.is_err(), "Oversized params must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("params too large"),
            "Error should mention params: {err}"
        );
    }

    #[test]
    fn cb25_02_recipient_key_too_large_rejected() {
        let oversized_slot = RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            TEST_PARAMS.to_vec(),
            vec![0xCD; MAX_RECIPIENT_FIELD_SIZE + 1], // 4097 bytes
        );
        let result = SuperHeader::new(
            ArchiveId::new(),
            vec![oversized_slot],
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::AnyOfN,
        );
        assert!(
            result.is_err(),
            "Oversized encrypted_master_key must be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("encrypted_master_key too large"),
            "Error should mention key size: {err}"
        );
    }

    #[test]
    fn cb25_02_recipient_key_too_short_rejected() {
        let short_key_slot = RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            TEST_PARAMS.to_vec(),
            vec![0xCD; 23], // 23 bytes, below minimum 24
        );
        let result = SuperHeader::new(
            ArchiveId::new(),
            vec![short_key_slot],
            ArchiveConfig::default(),
            [0u8; 16],
            mock_encrypted_vk(),
            AccessPolicy::AnyOfN,
        );
        assert!(
            result.is_err(),
            "Short encrypted_master_key must be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too short"),
            "Error should mention minimum length: {err}"
        );
    }

    #[test]
    fn cb25_02_recipient_validate_direct() {
        // Valid slot passes validation
        let valid = mock_recipient();
        assert!(valid.validate().is_ok());

        // Params at exactly MAX size — should pass
        let at_limit = RecipientSlot::new(
            RecipientType::Argon2idPassword,
            None,
            vec![0u8; MAX_RECIPIENT_FIELD_SIZE],
            vec![0xCD; 48],
        );
        assert!(
            at_limit.validate().is_ok(),
            "Exactly MAX_RECIPIENT_FIELD_SIZE should pass"
        );

        // Key at exactly 24 bytes — should pass
        let min_key = RecipientSlot::new(
            RecipientType::Argon2idPassword,
            None,
            vec![0u8; 16],
            vec![0xCD; 24],
        );
        assert!(min_key.validate().is_ok(), "Exactly 24 bytes should pass");
    }
}
