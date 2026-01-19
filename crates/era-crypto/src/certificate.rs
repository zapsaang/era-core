//! # ERA Certificate Key Module
//!
//! Provides an X25519-based key exchange flow as a high-performance alternative
//! to Argon2 password-derived keys.
//!
//! ## Performance Comparison
//!
//! | Scheme | Key Derivation Time |
//! |--------|---------------------|
//! | Argon2 (64MB) | ~80ms |
//! | Argon2 (256MB) | ~343ms |
//! | X25519 | ~0.05ms |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use era_crypto::certificate::{EraKeyPair, EraCertificate};
//!
//! // Generate a keypair
//! let keypair = EraKeyPair::generate()?;
//!
//! // Export the public certificate (safe to distribute)
//! let cert = keypair.certificate();
//!
//! // Save the keypair (encrypted at rest)
//! keypair.save_encrypted("my_key.era-key", "key_password")?;
//!
//! // Load the keypair
//! let keypair = EraKeyPair::load_encrypted("my_key.era-key", "key_password")?;
//! ```

use crate::aead::{AeadCipher, AeadKey, Nonce};
use crate::kdf::{derive_key, KdfParams};
use crate::timestamp::{OptionalTimestamp, Timestamp};
use crate::Salt;
use era_common::proto::KeyEncapsulation as ProtoKeyEncapsulation;
use era_common::{EraError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use time::OffsetDateTime;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key ID length (16 bytes = 128 bits)
pub const KEY_ID_LEN: usize = 16;

/// X25519 key length
pub const KEY_LEN: usize = 32;

/// Key file magic bytes
const KEY_FILE_MAGIC: &[u8; 4] = b"ERAK";

/// Certificate file magic bytes
const CERT_FILE_MAGIC: &[u8; 4] = b"ERAC";

/// Key file version
const KEY_FILE_VERSION: u8 = 1;

/// ERA keypair
///
/// Holds the private and public key used to create and decrypt archives.
/// The private key is protected in secure memory and zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct EraKeyPair {
    /// Private key (32 bytes)
    #[zeroize(skip)] // StaticSecret has its own zeroize
    pub(crate) secret_key: StaticSecret,
    /// Public key (32 bytes)
    public_key: PublicKey,
    /// Key ID (identifier)
    key_id: [u8; KEY_ID_LEN],
    /// Creation time (Unix timestamp)
    created_at: u64,
}

impl Clone for EraKeyPair {
    fn clone(&self) -> Self {
        let secret_bytes = self.secret_key.to_bytes();
        Self {
            secret_key: StaticSecret::from(secret_bytes),
            public_key: self.public_key,
            key_id: self.key_id,
            created_at: self.created_at,
        }
    }
}

/// ERA public certificate (v0.2.0+)
///
/// Contains only public key data and is safe to distribute. Used to create
/// archives that only the corresponding private key holder can decrypt.
///
/// Timestamps are stored in ISO 8601 format (OffsetDateTime).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraCertificate {
    /// Public key (32 bytes)
    public_key: [u8; KEY_LEN],
    /// Key ID
    key_id: [u8; KEY_ID_LEN],
    /// Creation time (ISO 8601 UTC)
    created_at: Timestamp,
    /// Optional expiration time (ISO 8601 UTC)
    expires_at: OptionalTimestamp,
    /// Optional label
    label: Option<String>,
}

/// Ephemeral keypair (for ECDH)
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeyPair {
    #[zeroize(skip)]
    secret: StaticSecret,
    public: PublicKey,
}

/// Key encapsulation result
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyEncapsulation {
    /// Ephemeral public key (stored in the archive)
    pub ephemeral_public: [u8; KEY_LEN],
    /// Encrypted master key
    pub encrypted_master_key: Vec<u8>,
}

impl KeyEncapsulation {
    pub fn to_proto(&self) -> ProtoKeyEncapsulation {
        ProtoKeyEncapsulation {
            ephemeral_public: self.ephemeral_public.to_vec(),
            encrypted_master_key: self.encrypted_master_key.clone(),
        }
    }

    pub fn from_proto(proto: ProtoKeyEncapsulation) -> Result<Self> {
        let ephemeral_public = proto
            .ephemeral_public
            .try_into()
            .map_err(|_| EraError::InvalidKey("Invalid ephemeral public key length".into()))?;

        Ok(Self {
            ephemeral_public,
            encrypted_master_key: proto.encrypted_master_key,
        })
    }
}

/// Decapsulated master key
pub struct DecapsulatedKey {
    /// Master key (32 bytes), zeroized on drop
    master_key: Vec<u8>,
}

impl DecapsulatedKey {
    /// Get master key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.master_key
    }

    /// Get a 32-byte array copy
    pub fn to_array(&self) -> [u8; KEY_LEN] {
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&self.master_key);
        arr
    }
}

impl Drop for DecapsulatedKey {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

impl EraKeyPair {
    /// Generate a new keypair
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();

        // Generate X25519 keypair
        let secret_key = StaticSecret::random_from_rng(&mut rng);
        let public_key = PublicKey::from(&secret_key);

        // Generate key ID (first 16 bytes of the public key hash)
        let key_id = Self::compute_key_id(&public_key);

        // Capture current timestamp
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            secret_key,
            public_key,
            key_id,
            created_at,
        })
    }

    /// Create a keypair from raw bytes
    pub fn from_bytes(secret_bytes: &[u8; KEY_LEN]) -> Result<Self> {
        let secret_key = StaticSecret::from(*secret_bytes);
        let public_key = PublicKey::from(&secret_key);
        let key_id = Self::compute_key_id(&public_key);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            secret_key,
            public_key,
            key_id,
            created_at,
        })
    }

    /// Compute key ID (first 16 bytes of the public key BLAKE3 hash)
    fn compute_key_id(public_key: &PublicKey) -> [u8; KEY_ID_LEN] {
        let hash = crate::hash(public_key.as_bytes());
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&hash.0[..KEY_ID_LEN]);
        key_id
    }

    /// Get key ID
    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }

    /// Get public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; KEY_LEN] {
        *self.public_key.as_bytes()
    }

    /// Get creation time
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Export public certificate
    pub fn certificate(&self) -> EraCertificate {
        EraCertificate {
            public_key: *self.public_key.as_bytes(),
            key_id: self.key_id,
            created_at: Timestamp::from_unix_timestamp(self.created_at)
                .unwrap_or_else(|_| Timestamp::now()),
            expires_at: OptionalTimestamp(None),
            label: None,
        }
    }

    /// Encapsulate the master key with the recipient's public key.
    ///
    /// Generates an ephemeral keypair, performs ECDH with the recipient key,
    /// then encrypts the master key.
    pub fn encapsulate_for(
        recipient: &EraCertificate,
        master_key: &[u8],
    ) -> Result<KeyEncapsulation> {
        if master_key.len() != KEY_LEN {
            return Err(EraError::InvalidKey("Master key must be 32 bytes".into()));
        }

        // Generate ephemeral keypair
        let ephemeral = EphemeralKeyPair::generate();

        // Perform ECDH with recipient public key
        let recipient_public = PublicKey::from(recipient.public_key);
        let shared_secret = ephemeral.secret.diffie_hellman(&recipient_public);

        // Derive wrapping key via HKDF
        let wrap_key = Self::derive_wrap_key(shared_secret.as_bytes())?;

        // Encrypt master key
        let aead = AeadCipher::new();
        let nonce = Nonce::zero(); // One-time wrap key allows a zero nonce
        let encrypted = aead.encrypt(&wrap_key, &nonce, master_key)?;

        Ok(KeyEncapsulation {
            ephemeral_public: *ephemeral.public.as_bytes(),
            encrypted_master_key: encrypted,
        })
    }

    /// Decapsulate the master key.
    ///
    /// Uses the private key and the ephemeral public key for ECDH, then
    /// decrypts the master key.
    pub fn decapsulate(&self, encapsulation: &KeyEncapsulation) -> Result<DecapsulatedKey> {
        // Restore ephemeral public key
        let ephemeral_public = PublicKey::from(encapsulation.ephemeral_public);

        // Perform ECDH
        let shared_secret = self.secret_key.diffie_hellman(&ephemeral_public);

        // Derive unwrapping key via HKDF
        let wrap_key = Self::derive_wrap_key(shared_secret.as_bytes())?;

        // Decrypt master key
        let aead = AeadCipher::new();
        let nonce = Nonce::zero();
        let mut decrypted = aead.decrypt(&wrap_key, &nonce, &encapsulation.encrypted_master_key)?;

        if decrypted.len() != KEY_LEN {
            decrypted.zeroize();
            return Err(EraError::InvalidKey(
                "Decrypted key has wrong length".into(),
            ));
        }

        Ok(DecapsulatedKey {
            master_key: decrypted,
        })
    }

    /// Derive the key wrapping key via HKDF
    fn derive_wrap_key(shared_secret: &[u8]) -> Result<AeadKey> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut okm = [0u8; 32];
        hkdf.expand(b"ERA-KEY-WRAP-V1", &mut okm)
            .map_err(|_| EraError::KeyDerivation("HKDF expand failed".into()))?;

        Ok(AeadKey(okm))
    }

    /// Save the keypair to a file (encrypted at rest).
    ///
    /// Uses Argon2 to derive an encryption key to protect the private key.
    /// The Argon2 cost is acceptable because the key file is loaded rarely.
    pub fn save_encrypted<P: AsRef<Path>>(&self, path: P, password: &str) -> Result<()> {
        // Derive encryption key via Argon2 (lighter params since the private key is high entropy)
        let salt = Salt::generate();
        let params = KdfParams::fast(); // 1MB memory, fast
        let encryption_key = derive_key(password.as_bytes(), &salt, &params)?;

        // Encrypt private key
        let aead = AeadCipher::new();
        let nonce = Nonce::generate();
        let secret_bytes = self.secret_key.as_bytes();
        let encrypted_secret =
            aead.encrypt(&AeadKey(*encryption_key.as_bytes()), &nonce, secret_bytes)?;

        // Build file payload
        // Format: MAGIC(4) + VERSION(1) + SALT(16) + NONCE(24) + KEY_ID(16) + CREATED_AT(8) + ENCRYPTED_SECRET(32+16)
        let mut file_data = Vec::with_capacity(128);
        file_data.extend_from_slice(KEY_FILE_MAGIC);
        file_data.push(KEY_FILE_VERSION);
        file_data.extend_from_slice(salt.as_bytes());
        file_data.extend_from_slice(nonce.as_bytes());
        file_data.extend_from_slice(&self.key_id);
        file_data.extend_from_slice(&self.created_at.to_le_bytes());
        file_data.extend_from_slice(&encrypted_secret);

        // Write file
        let mut file = fs::File::create(path)?;
        file.write_all(&file_data)?;

        Ok(())
    }

    /// Load a keypair from an encrypted file
    pub fn load_encrypted<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)?;

        // Validate magic and version
        // Format: MAGIC(4) + VERSION(1) + SALT(16) + NONCE(24) + KEY_ID(16) + CREATED_AT(8) + ENCRYPTED_SECRET
        // Minimum: 4+1+16+24+16+8+48 = 117 bytes
        if file_data.len() < 117 {
            return Err(EraError::InvalidFormat("Key file too short".into()));
        }

        if &file_data[0..4] != KEY_FILE_MAGIC {
            return Err(EraError::InvalidFormat("Invalid key file magic".into()));
        }

        if file_data[4] != KEY_FILE_VERSION {
            return Err(EraError::InvalidFormat(
                "Unsupported key file version".into(),
            ));
        }

        // Parse file payload
        let salt_bytes: [u8; 16] = file_data[5..21]
            .try_into()
            .map_err(|_| EraError::InvalidFormat("Invalid salt length".into()))?;
        let salt = Salt::from_bytes(salt_bytes);
        let nonce = Nonce::from_bytes(&file_data[21..45])?;
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&file_data[45..61]);
        let created_at = u64::from_le_bytes(file_data[61..69].try_into().unwrap());
        let encrypted_secret = &file_data[69..];

        // Derive decryption key via Argon2
        let params = KdfParams::fast();
        let encryption_key = derive_key(password.as_bytes(), &salt, &params)?;

        // Decrypt private key
        let aead = AeadCipher::new();
        let secret_bytes = aead.decrypt(
            &AeadKey(*encryption_key.as_bytes()),
            &nonce,
            encrypted_secret,
        )?;

        if secret_bytes.len() != KEY_LEN {
            return Err(EraError::InvalidKey("Invalid secret key length".into()));
        }

        let mut secret_array = [0u8; KEY_LEN];
        secret_array.copy_from_slice(&secret_bytes);
        let secret_key = StaticSecret::from(secret_array);
        secret_array.zeroize();

        let public_key = PublicKey::from(&secret_key);

        // Validate key_id match
        let computed_key_id = Self::compute_key_id(&public_key);
        if computed_key_id != key_id {
            return Err(EraError::InvalidKey("Key ID mismatch".into()));
        }

        Ok(Self {
            secret_key,
            public_key,
            key_id,
            created_at,
        })
    }

    /// Get creation time as OffsetDateTime.
    ///
    /// Converts the stored Unix timestamp to OffsetDateTime.
    ///
    /// # Errors
    /// Returns `EraError` if the Unix timestamp is invalid.
    pub fn created_at_datetime(&self) -> Result<OffsetDateTime> {
        OffsetDateTime::from_unix_timestamp(self.created_at as i64)
            .map_err(|e| EraError::InvalidKey(format!("Invalid timestamp: {}", e)))
    }

    /// Get key age in seconds (creation to now)
    pub fn age_seconds(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.created_at)
    }
}

impl EraCertificate {
    /// Create a new certificate
    pub fn new(public_key: [u8; KEY_LEN], key_id: [u8; KEY_ID_LEN], created_at: u64) -> Self {
        Self {
            public_key,
            key_id,
            created_at: Timestamp::from_unix_timestamp(created_at)
                .unwrap_or_else(|_| Timestamp::now()),
            expires_at: OptionalTimestamp(None),
            label: None,
        }
    }

    /// Create from public key bytes
    pub fn from_public_key(public_key: &[u8; KEY_LEN]) -> Self {
        let hash = crate::hash(public_key);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&hash.0[..KEY_ID_LEN]);

        Self {
            public_key: *public_key,
            key_id,
            created_at: Timestamp::now(),
            expires_at: OptionalTimestamp(None),
            label: None,
        }
    }

    /// Set expiration time
    pub fn with_expiry(mut self, expires_at: u64) -> Self {
        if expires_at == 0 {
            // 0 means already expired
            if let Ok(ts) = Timestamp::from_unix_timestamp(0) {
                self.expires_at = OptionalTimestamp(Some(ts));
            }
        } else if expires_at == u64::MAX {
            // u64::MAX is way in the future, treat it as never expiring
            // Set it to a far future date (year 2100)
            if let Ok(ts) = Timestamp::from_unix_timestamp(4102444800) {
                self.expires_at = OptionalTimestamp(Some(ts));
            }
        } else if let Ok(ts) = Timestamp::from_unix_timestamp(expires_at) {
            self.expires_at = OptionalTimestamp(Some(ts));
        }
        self
    }

    /// Set label
    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// Get public key
    pub fn public_key(&self) -> &[u8; KEY_LEN] {
        &self.public_key
    }

    /// Get key ID
    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }

    /// Get creation time
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Check whether expired
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_expired()
    }

    /// Save certificate to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file_data = Vec::with_capacity(128);
        file_data.extend_from_slice(CERT_FILE_MAGIC);
        file_data.push(KEY_FILE_VERSION);

        // Serialize with Protobuf
        let proto = self.to_proto();
        let cert_data = era_common::serialize_proto(&proto)?;

        file_data.extend_from_slice(&(cert_data.len() as u32).to_le_bytes());
        file_data.extend_from_slice(&cert_data);

        let mut file = fs::File::create(path)?;
        file.write_all(&file_data)?;

        Ok(())
    }

    /// Load certificate from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = fs::File::open(path)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)?;

        if file_data.len() < 9 {
            return Err(EraError::InvalidFormat("Certificate file too short".into()));
        }

        if &file_data[0..4] != CERT_FILE_MAGIC {
            return Err(EraError::InvalidFormat(
                "Invalid certificate file magic".into(),
            ));
        }

        if file_data[4] != KEY_FILE_VERSION {
            return Err(EraError::InvalidFormat(
                "Unsupported certificate file version".into(),
            ));
        }

        let cert_len = u32::from_le_bytes(file_data[5..9].try_into().unwrap()) as usize;
        if file_data.len() < 9 + cert_len {
            return Err(EraError::InvalidFormat("Certificate file truncated".into()));
        }

        let proto: era_common::proto::EraCertificate =
            era_common::deserialize_proto(&file_data[9..9 + cert_len])?;
        Self::from_proto(proto)
    }

    pub fn to_proto(&self) -> era_common::proto::EraCertificate {
        era_common::proto::EraCertificate {
            public_key: self.public_key.to_vec(),
            key_id: self.key_id.to_vec(),
            created_at: self.created_at.to_unix_timestamp() as i64,
            expires_at: self.expires_at.0.map(|t| t.to_unix_timestamp() as i64),
            label: self.label.clone(),
        }
    }

    pub fn from_proto(proto: era_common::proto::EraCertificate) -> Result<Self> {
        let created_at = Timestamp::from_unix_timestamp(proto.created_at as u64)?;
        let expires_at = match proto.expires_at {
            Some(ts) => OptionalTimestamp(Some(Timestamp::from_unix_timestamp(ts as u64)?)),
            None => OptionalTimestamp(None),
        };
        let public_key: [u8; KEY_LEN] = proto
            .public_key
            .try_into()
            .map_err(|_| EraError::Deserialization("Invalid public key length".into()))?;
        let key_id: [u8; KEY_ID_LEN] = proto
            .key_id
            .try_into()
            .map_err(|_| EraError::Deserialization("Invalid key ID length".into()))?;

        Ok(Self {
            public_key,
            key_id,
            created_at,
            expires_at,
            label: proto.label,
        })
    }

    /// Get creation time as OffsetDateTime.
    ///
    /// Returns the OffsetDateTime stored in the Timestamp struct.
    pub fn created_at_datetime(&self) -> OffsetDateTime {
        self.created_at.to_datetime()
    }

    /// Get expiration time as OffsetDateTime (if set).
    ///
    /// Returns the OffsetDateTime stored in OptionalTimestamp (if set).
    pub fn expires_at_datetime(&self) -> Option<OffsetDateTime> {
        self.expires_at.0.as_ref().map(|ts| ts.to_datetime())
    }
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral keypair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl std::fmt::Debug for EraKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EraKeyPair")
            .field("key_id", &hex::encode(self.key_id))
            .field("public_key", &hex::encode(self.public_key.as_bytes()))
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tempfile::TempDir;

    #[test]
    fn test_keypair_generation() {
        let keypair = EraKeyPair::generate().unwrap();
        assert_eq!(keypair.key_id().len(), KEY_ID_LEN);
        assert_eq!(keypair.public_key_bytes().len(), KEY_LEN);
    }

    #[test]
    fn test_certificate_export() {
        let keypair = EraKeyPair::generate().unwrap();
        let cert = keypair.certificate();

        assert_eq!(cert.key_id(), keypair.key_id());
        assert_eq!(cert.public_key(), &keypair.public_key_bytes());
    }

    #[test]
    fn test_key_encapsulation_roundtrip() {
        let recipient = EraKeyPair::generate().unwrap();
        let cert = recipient.certificate();

        // Master key to encapsulate
        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);

        // Encapsulate
        let encapsulation = EraKeyPair::encapsulate_for(&cert, &master_key).unwrap();

        // Decapsulate
        let decapsulated = recipient.decapsulate(&encapsulation).unwrap();

        assert_eq!(decapsulated.master_key.as_slice(), &master_key);
    }

    #[test]
    fn test_keypair_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.era-key");

        let original = EraKeyPair::generate().unwrap();
        original.save_encrypted(&key_path, "test_password").unwrap();

        let loaded = EraKeyPair::load_encrypted(&key_path, "test_password").unwrap();

        assert_eq!(loaded.key_id(), original.key_id());
        assert_eq!(loaded.public_key_bytes(), original.public_key_bytes());
    }

    #[test]
    fn test_keypair_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test.era-key");

        let original = EraKeyPair::generate().unwrap();
        original
            .save_encrypted(&key_path, "correct_password")
            .unwrap();

        let result = EraKeyPair::load_encrypted(&key_path, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("test.era-cert");

        let keypair = EraKeyPair::generate().unwrap();
        let original = keypair.certificate().with_label("Test Key".to_string());
        original.save(&cert_path).unwrap();

        let loaded = EraCertificate::load(&cert_path).unwrap();

        assert_eq!(loaded.key_id(), original.key_id());
        assert_eq!(loaded.public_key(), original.public_key());
        assert_eq!(loaded.label, Some("Test Key".to_string()));
    }

    #[test]
    fn test_certificate_expiry() {
        let keypair = EraKeyPair::generate().unwrap();

        // Not expired
        let cert = keypair.certificate().with_expiry(u64::MAX);
        assert!(!cert.is_expired());

        // Expired
        let cert = keypair.certificate().with_expiry(0);
        assert!(cert.is_expired());
    }

    #[test]
    fn test_certificate_created_at_datetime() {
        let keypair = EraKeyPair::generate().unwrap();
        let cert = keypair.certificate();

        let datetime = cert.created_at_datetime();
        // Validate the datetime is recent
        let now = time::OffsetDateTime::now_utc();
        let diff = (now - datetime).whole_seconds().abs();
        assert!(diff < 5); // Should be within 5 seconds
    }

    #[test]
    fn test_keypair_created_at_datetime() {
        let keypair = EraKeyPair::generate().unwrap();

        let datetime = keypair.created_at_datetime().unwrap();
        let now = time::OffsetDateTime::now_utc();
        let diff = (now - datetime).whole_seconds().abs();
        assert!(diff < 5);
    }

    #[test]
    fn test_keypair_age_seconds() {
        let keypair = EraKeyPair::generate().unwrap();
        let initial_age = keypair.age_seconds();

        // Wait 1 second
        std::thread::sleep(std::time::Duration::from_secs(1));

        let later_age = keypair.age_seconds();
        assert!(later_age >= initial_age);
        assert!(later_age - initial_age >= 1);
    }

    #[test]
    fn test_certificate_expires_at_datetime() {
        let keypair = EraKeyPair::generate().unwrap();

        // No expiration
        let cert = keypair.certificate();
        assert!(cert.expires_at_datetime().is_none());

        // With expiration
        let future_ts =
            (time::OffsetDateTime::now_utc() + time::Duration::days(30)).unix_timestamp() as u64;
        let cert_with_expiry = keypair.certificate().with_expiry(future_ts);
        let expires = cert_with_expiry.expires_at_datetime();
        assert!(expires.is_some());
    }
}
