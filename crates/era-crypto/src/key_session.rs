//! Key Session Management for ERA v8.1
//!
//! This module implements the HKDF-based multi-level key derivation system
//! (the "Onion Model") as described in the security optimization document.
//!
//! ## Architecture
//!
//! The key hierarchy is:
//! - **Master Key (MK)**: Derived from password via Argon2id (expensive, done once)
//! - **Volume Key (VK)**: Derived from MK via HKDF (fast, per-volume)
//! - **Block Key (BK)**: Derived from VK via HKDF (fast, per-block)
//!
//! ## Security Features
//!
//! - Keys implement `Zeroize` and `ZeroizeOnDrop` for secure memory cleanup
//! - Debug output is redacted to prevent accidental logging
//! - HKDF provides cryptographic key isolation between volumes and blocks

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{derive_key, DerivedKey, KdfParams, Salt};
use era_common::Result;

/// Domain separator for volume key derivation
const VOLUME_KEY_DOMAIN: &[u8] = b"ERA_VOL_KEY_v8.1";

/// Domain separator for block key derivation
const BLOCK_KEY_DOMAIN: &[u8] = b"ERA_BLOCK_KEY_v8.1";

/// A Volume Key derived from the Master Key using HKDF.
///
/// Volume keys are cached for the lifetime of the archive session
/// and used to derive per-block keys efficiently.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VolumeKey {
    bytes: [u8; 32],
}

impl VolumeKey {
    /// Create a volume key from raw bytes
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the key bytes for cryptographic operations
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for VolumeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A Block Key derived from a Volume Key using HKDF.
///
/// Block keys are unique per macro-block and provide cryptographic
/// isolation between blocks. They are short-lived and should be
/// zeroized immediately after use.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlockKey {
    bytes: [u8; 32],
}

impl BlockKey {
    /// Create a block key from raw bytes
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the key bytes for cryptographic operations
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert to DerivedKey for compatibility with existing encryption APIs
    pub fn to_derived_key(&self) -> DerivedKey {
        DerivedKey::from_bytes(self.bytes)
    }
}

impl std::fmt::Debug for BlockKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A Key Session that caches the Master Key and provides fast sub-key derivation.
///
/// The KeySession eliminates the need to call expensive Argon2id for each block.
/// Instead, Argon2id is called once during session creation, and all subsequent
/// key derivations use the efficient HKDF algorithm.
///
/// # Security Considerations
///
/// - The master key is cached in memory for the session lifetime
/// - Use `drop()` or let the session go out of scope to clear keys
/// - All keys implement `ZeroizeOnDrop` for secure cleanup
/// - Consider calling `zeroize()` explicitly for critical sections
///
/// # Example
///
/// ```ignore
/// let session = KeySession::new(b"password", &salt, &kdf_params)?;
///
/// // Derive volume key (fast HKDF)
/// let volume_key = session.derive_volume_key(volume_id);
///
/// // Derive block key (fast HKDF)
/// let block_key = session.derive_block_key(&volume_key, block_index, &nonce_context);
///
/// // Use block_key for encryption...
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeySession {
    /// The master key derived via Argon2id
    master_key: [u8; 32],
}

impl KeySession {
    /// Create a new key session by deriving the master key from a password.
    ///
    /// This is the only expensive operation. All subsequent key derivations
    /// will use fast HKDF.
    ///
    /// # Arguments
    ///
    /// * `password` - The user's password
    /// * `salt` - The archive salt (stored in the super header)
    /// * `params` - KDF parameters (memory cost, time cost, parallelism)
    ///
    /// # Returns
    ///
    /// A new `KeySession` with the master key cached in memory.
    pub fn new(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<Self> {
        let derived_key = derive_key(password, salt, params)?;
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(derived_key.as_bytes());
        Ok(Self { master_key })
    }

    /// Create a key session from an existing DerivedKey.
    ///
    /// This allows reusing an already-derived key without calling Argon2id again.
    /// Useful for scenarios where the key was derived externally.
    pub fn from_derived_key(key: &DerivedKey) -> Self {
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(key.as_bytes());
        Self { master_key }
    }

    /// Derive a Volume Key for a specific volume.
    ///
    /// Uses HKDF-Expand with the volume ID as context, providing
    /// cryptographic isolation between volumes.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - The volume sequence number (0, 1, 2, ...)
    ///
    /// # Returns
    ///
    /// A unique `VolumeKey` for this volume.
    pub fn derive_volume_key(&self, volume_id: u16) -> VolumeKey {
        let hk = Hkdf::<Sha256>::new(None, &self.master_key);

        // Build info: DOMAIN || volume_id (big-endian)
        let mut info = Vec::with_capacity(VOLUME_KEY_DOMAIN.len() + 2);
        info.extend_from_slice(VOLUME_KEY_DOMAIN);
        info.extend_from_slice(&volume_id.to_be_bytes());

        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .expect("HKDF expand should not fail with valid parameters");

        VolumeKey::from_bytes(okm)
    }

    /// Derive a Block Key for a specific block within a volume.
    ///
    /// Uses HKDF-Expand with the block index and nonce context as info,
    /// providing cryptographic isolation between blocks.
    ///
    /// # Arguments
    ///
    /// * `volume_key` - The volume key for the current volume
    /// * `block_index` - The block index within the volume
    /// * `nonce_context` - Additional context (typically the archive salt)
    ///
    /// # Returns
    ///
    /// A unique `BlockKey` for this block.
    pub fn derive_block_key(
        &self,
        volume_key: &VolumeKey,
        block_index: u64,
        nonce_context: &[u8; 16],
    ) -> BlockKey {
        let hk = Hkdf::<Sha256>::new(None, volume_key.as_bytes());

        // Build info: DOMAIN || block_index (big-endian) || nonce_context
        let mut info = Vec::with_capacity(BLOCK_KEY_DOMAIN.len() + 8 + 16);
        info.extend_from_slice(BLOCK_KEY_DOMAIN);
        info.extend_from_slice(&block_index.to_be_bytes());
        info.extend_from_slice(nonce_context);

        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .expect("HKDF expand should not fail with valid parameters");

        BlockKey::from_bytes(okm)
    }

    /// Get the master key as a DerivedKey for backward compatibility.
    ///
    /// This allows gradual migration: existing code can continue using
    /// DerivedKey while new code uses the session-based approach.
    pub fn master_key(&self) -> DerivedKey {
        DerivedKey::from_bytes(self.master_key)
    }

    /// Get the password verification tag for this session.
    ///
    /// This tag can be stored in the archive header for early password validation.
    pub fn password_verification_tag(&self) -> [u8; 16] {
        crate::generate_password_verification_tag(&self.master_key())
    }
}

impl std::fmt::Debug for KeySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySession")
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_kdf_params() -> KdfParams {
        KdfParams {
            memory_cost: 1024, // 1 MB for fast tests
            time_cost: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn test_key_session_creation() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();

        // Session should be created successfully
        // Master key should match direct derivation
        let direct_key = derive_key(password, &salt, &params).unwrap();
        assert_eq!(session.master_key().as_bytes(), direct_key.as_bytes());
    }

    #[test]
    fn test_key_session_from_derived_key() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let derived_key = derive_key(password, &salt, &params).unwrap();
        let session = KeySession::from_derived_key(&derived_key);

        assert_eq!(session.master_key().as_bytes(), derived_key.as_bytes());
    }

    #[test]
    fn test_volume_key_derivation_deterministic() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();

        // Same volume ID should produce same key
        let vk1 = session.derive_volume_key(0);
        let vk2 = session.derive_volume_key(0);
        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
    }

    #[test]
    fn test_volume_keys_different_for_different_volumes() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();

        // Different volume IDs should produce different keys
        let vk0 = session.derive_volume_key(0);
        let vk1 = session.derive_volume_key(1);
        let vk2 = session.derive_volume_key(2);

        assert_ne!(vk0.as_bytes(), vk1.as_bytes());
        assert_ne!(vk1.as_bytes(), vk2.as_bytes());
        assert_ne!(vk0.as_bytes(), vk2.as_bytes());
    }

    #[test]
    fn test_block_key_derivation_deterministic() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = session.derive_volume_key(0);
        let nonce_context = [1u8; 16];

        // Same parameters should produce same key
        let bk1 = session.derive_block_key(&vk, 0, &nonce_context);
        let bk2 = session.derive_block_key(&vk, 0, &nonce_context);
        assert_eq!(bk1.as_bytes(), bk2.as_bytes());
    }

    #[test]
    fn test_block_keys_different_for_different_blocks() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = session.derive_volume_key(0);
        let nonce_context = [1u8; 16];

        // Different block indices should produce different keys
        let bk0 = session.derive_block_key(&vk, 0, &nonce_context);
        let bk1 = session.derive_block_key(&vk, 1, &nonce_context);
        let bk2 = session.derive_block_key(&vk, 1000, &nonce_context);

        assert_ne!(bk0.as_bytes(), bk1.as_bytes());
        assert_ne!(bk1.as_bytes(), bk2.as_bytes());
        assert_ne!(bk0.as_bytes(), bk2.as_bytes());
    }

    #[test]
    fn test_block_keys_different_for_different_nonce_contexts() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = session.derive_volume_key(0);

        let nonce1 = [1u8; 16];
        let nonce2 = [2u8; 16];

        let bk1 = session.derive_block_key(&vk, 0, &nonce1);
        let bk2 = session.derive_block_key(&vk, 0, &nonce2);

        assert_ne!(bk1.as_bytes(), bk2.as_bytes());
    }

    #[test]
    fn test_block_key_to_derived_key_conversion() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = session.derive_volume_key(0);
        let nonce_context = [1u8; 16];

        let bk = session.derive_block_key(&vk, 0, &nonce_context);
        let derived = bk.to_derived_key();

        assert_eq!(bk.as_bytes(), derived.as_bytes());
    }

    #[test]
    fn test_password_verification_tag_matches() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let tag = session.password_verification_tag();

        // Should match the tag generated directly from the key
        let direct_key = derive_key(password, &salt, &params).unwrap();
        let direct_tag = crate::generate_password_verification_tag(&direct_key);

        assert_eq!(tag, direct_tag);
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = session.derive_volume_key(0);
        let bk = session.derive_block_key(&vk, 0, &[0u8; 16]);

        // Debug output should not contain actual key bytes
        let session_debug = format!("{:?}", session);
        let vk_debug = format!("{:?}", vk);
        let bk_debug = format!("{:?}", bk);

        assert!(session_debug.contains("REDACTED"));
        assert!(vk_debug.contains("REDACTED"));
        assert!(bk_debug.contains("REDACTED"));

        // Should not contain any actual byte values
        assert!(!session_debug.contains("[0x"));
    }

    #[test]
    fn test_different_passwords_different_sessions() {
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session1 = KeySession::new(b"password1", &salt, &params).unwrap();
        let session2 = KeySession::new(b"password2", &salt, &params).unwrap();

        let vk1 = session1.derive_volume_key(0);
        let vk2 = session2.derive_volume_key(0);

        assert_ne!(vk1.as_bytes(), vk2.as_bytes());
    }

    #[test]
    fn test_different_salts_different_sessions() {
        let salt1 = Salt::generate();
        let salt2 = Salt::generate();
        let params = fast_kdf_params();

        let session1 = KeySession::new(b"password", &salt1, &params).unwrap();
        let session2 = KeySession::new(b"password", &salt2, &params).unwrap();

        let vk1 = session1.derive_volume_key(0);
        let vk2 = session2.derive_volume_key(0);

        assert_ne!(vk1.as_bytes(), vk2.as_bytes());
    }

    #[test]
    fn test_hkdf_performance() {
        // This test verifies that HKDF derivation is fast
        // In a real benchmark, we'd measure actual times
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = session.derive_volume_key(0);
        let nonce_context = [1u8; 16];

        // Derive 1000 block keys - should be nearly instant
        for i in 0..1000 {
            let _bk = session.derive_block_key(&vk, i, &nonce_context);
        }
    }

    #[test]
    fn test_key_isolation() {
        // Test that knowing one key doesn't help derive others
        // This is a property test, not a cryptographic proof
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();

        // Volume keys for different volumes
        let vk0 = session.derive_volume_key(0);
        let vk1 = session.derive_volume_key(1);

        // Block keys from different volume keys
        let bk0_0 = session.derive_block_key(&vk0, 0, &[0u8; 16]);
        let bk1_0 = session.derive_block_key(&vk1, 0, &[0u8; 16]);

        // Same block index but different volume -> different block keys
        assert_ne!(bk0_0.as_bytes(), bk1_0.as_bytes());

        // Verify no obvious relationship between consecutive keys
        let bk0_1 = session.derive_block_key(&vk0, 1, &[0u8; 16]);
        let xor_diff: u32 = bk0_0
            .as_bytes()
            .iter()
            .zip(bk0_1.as_bytes())
            .map(|(a, b)| (*a ^ *b).count_ones())
            .sum();

        // Expect roughly half the bits to differ (avalanche effect)
        // 256 bits total, expect ~128 bits different
        assert!(xor_diff > 64, "Insufficient avalanche effect");
    }
}
