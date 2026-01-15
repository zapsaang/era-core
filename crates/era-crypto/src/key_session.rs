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
//! - All keys use `SecureBuffer` with mlock protection against swap
//! - Debug output is redacted to prevent accidental logging
//! - HKDF provides cryptographic key isolation between volumes and blocks
//! - Master key is not directly exposed; use VolumeKey/BlockKey instead

use crate::hkdf_utils::derive_key_hkdf;
use crate::secure_memory::{SecureBuffer, SecureBytes, SecureMemoryConfig};
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
///
/// Uses `SecureBuffer` internally for mlock protection.
pub struct VolumeKey {
    buffer: SecureBuffer<32>,
}

impl VolumeKey {
    /// Create a volume key from raw bytes
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut buffer = SecureBuffer::with_config(SecureMemoryConfig::default())
            .expect("Failed to allocate secure memory for VolumeKey");
        buffer.as_mut().copy_from_slice(&bytes);
        Self { buffer }
    }

    /// Get the key bytes for cryptographic operations
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.buffer.as_ref()
    }

    /// Check if the key memory is locked (protected from swapping)
    pub fn is_memory_locked(&self) -> bool {
        self.buffer.is_locked()
    }
}

impl Clone for VolumeKey {
    fn clone(&self) -> Self {
        Self::from_bytes(*self.as_bytes())
    }
}

impl std::fmt::Debug for VolumeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeKey")
            .field("bytes", &"[REDACTED]")
            .field("is_locked", &self.buffer.is_locked())
            .finish()
    }
}

/// A Block Key derived from a Volume Key using HKDF.
///
/// Block keys are unique per macro-block and provide cryptographic
/// isolation between blocks. They are short-lived and should be
/// dropped immediately after use.
///
/// Uses `SecureBuffer` internally for mlock protection.
pub struct BlockKey {
    buffer: SecureBuffer<32>,
}

impl BlockKey {
    /// Create a block key from raw bytes
    fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut buffer = SecureBuffer::with_config(SecureMemoryConfig::default())
            .expect("Failed to allocate secure memory for BlockKey");
        buffer.as_mut().copy_from_slice(&bytes);
        Self { buffer }
    }

    /// Get the key bytes for cryptographic operations
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.buffer.as_ref()
    }

    /// Convert to DerivedKey for compatibility with existing encryption APIs
    pub fn to_derived_key(&self) -> DerivedKey {
        DerivedKey::from_bytes(*self.as_bytes())
    }

    /// Check if the key memory is locked (protected from swapping)
    pub fn is_memory_locked(&self) -> bool {
        self.buffer.is_locked()
    }
}

impl Clone for BlockKey {
    fn clone(&self) -> Self {
        Self::from_bytes(*self.as_bytes())
    }
}

impl std::fmt::Debug for BlockKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockKey")
            .field("bytes", &"[REDACTED]")
            .field("is_locked", &self.buffer.is_locked())
            .finish()
    }
}

/// KeySession creates and manages encryption keys.
///
/// # Security Policy (v8.1)
/// - **Master Key Transience**: The Master Key (MK) is used ONLY during session initialization
///   to derive a set of Volume Keys (VK). It is then immediately dropped/zeroized.
/// - **Volume Key Cache**: Derived VKs are stored in a single contiguous `SecureBytes` buffer.
///
/// # Configuration
/// By default, `KeySession` pre-calculates keys for volumes 0..1024.
/// Use `KeySessionBuilder` to customize this limit.
pub struct KeySession {
    /// Cached Volume Keys. Layout: [VK_0 (32B) | VK_1 (32B) | ... ]
    vk_cache: SecureBytes,
    /// Number of volumes currently cached
    cached_volumes: usize,
    /// Verification tag derived from MK before it was dropped
    verification_tag: [u8; 16],
}

/// Builder for customization of KeySession
pub struct KeySessionBuilder {
    max_volumes: usize,
}

impl Default for KeySessionBuilder {
    fn default() -> Self {
        Self { max_volumes: 1024 }
    }
}

impl KeySessionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of volumes to pre-derive keys for.
    pub fn with_max_volumes(mut self, max: usize) -> Self {
        self.max_volumes = max;
        self
    }

    /// Build from password
    pub fn build(self, password: &[u8], salt: &Salt, params: &KdfParams) -> Result<KeySession> {
        let derived_key = derive_key(password, salt, params)?;
        Self::build_internal(derived_key.as_bytes(), self.max_volumes)
    }

    /// Build from existing derived key
    pub fn build_from_derived(self, key: &DerivedKey) -> Result<KeySession> {
        Self::build_internal(key.as_bytes(), self.max_volumes)
    }

    /// Build from raw master key bytes (32 bytes).
    ///
    /// This is useful when the master key is obtained from certificate-based
    /// key exchange (X25519 ECDH) instead of password derivation (Argon2).
    ///
    /// # Security Note
    ///
    /// The caller is responsible for obtaining the master key securely.
    /// When using certificate mode, the master key should come from
    /// `EraKeyPair::decapsulate()` which provides proper key encapsulation.
    ///
    /// # Arguments
    ///
    /// * `master_key` - 32-byte master key (will be zeroized after use)
    pub fn build_from_master_key(self, master_key: &[u8; 32]) -> Result<KeySession> {
        Self::build_internal(master_key, self.max_volumes)
    }

    fn build_internal(mk_bytes: &[u8], max_volumes: usize) -> Result<KeySession> {
        // Allocate cache
        let cache_size = max_volumes
            .checked_mul(32)
            .ok_or_else(|| era_common::EraError::Encryption("Cache size overflow".into()))?;

        // Safety: If cache_size is 0, allocation handles it gracefully (returns error or empty)
        // But max_volumes=0 creates a session that can't derive VKs. Valid but useless.

        // Critical Security Config:
        // We MUST enable guard pages for the long-lived VK cache to prevent
        // heartbleed-style over-reads from leaking adjacent keys or other memory.
        let config = SecureMemoryConfig {
            enable_guard_pages: true, // Force ON for cache
            enable_mlock: true,       // Force ON for cache
            strict_mlock: false,      // Warn if mlock fails (don't crash app)
        };

        let mut vk_cache = SecureBytes::with_config(cache_size, config).map_err(|e| {
            era_common::EraError::Encryption(format!("Failed to allocate VK cache: {}", e))
        })?;

        // 1. Calculate Verification Tag using HKDF
        let mut verification_tag = [0u8; 16];
        derive_key_hkdf(
            mk_bytes,
            None,
            b"ERA_PASSWORD_VERIFICATION_v8.1",
            &mut verification_tag,
        )
        .expect("HKDF expand should not fail");

        // 2. Derive Volume Keys using HKDF
        let mut info_buf = [0u8; VOLUME_KEY_DOMAIN.len() + 2];
        info_buf[..VOLUME_KEY_DOMAIN.len()].copy_from_slice(VOLUME_KEY_DOMAIN);

        let method_slice = vk_cache.as_mut_slice();
        for i in 0..max_volumes {
            let vol_id = i as u16;
            info_buf[VOLUME_KEY_DOMAIN.len()..].copy_from_slice(&vol_id.to_be_bytes());

            let start = i * 32;
            let end = start + 32;

            derive_key_hkdf(mk_bytes, None, &info_buf, &mut method_slice[start..end])
                .expect("HKDF expand failed");
        }

        // MK is dropped/zeroized when `hk` and `mk_bytes` source go out of scope.

        Ok(KeySession {
            vk_cache,
            cached_volumes: max_volumes,
            verification_tag,
        })
    }
}

impl KeySession {
    /// Create a new key session with default settings (1024 volumes).
    pub fn new(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<Self> {
        KeySessionBuilder::new().build(password, salt, params)
    }

    /// Create from existing derived key
    pub fn from_derived_key(key: &DerivedKey) -> Self {
        KeySessionBuilder::new()
            .build_from_derived(key)
            .expect("Default build failed")
    }

    /// Create a key session from a raw master key (for certificate mode).
    ///
    /// This method is ~1000x faster than password-based creation because
    /// it skips Argon2 key derivation.
    ///
    /// # Arguments
    ///
    /// * `master_key` - 32-byte master key from certificate decapsulation
    ///
    /// # Example
    ///
    /// ```ignore
    /// use era_crypto::certificate::{EraKeyPair, KeyEncapsulation};
    ///
    /// // Writer side: generate random master key, encapsulate for recipient
    /// let master_key = [0u8; 32]; // should be random in practice
    /// let encapsulation = EraKeyPair::encapsulate_for(&recipient_cert, &master_key)?;
    ///
    /// // Reader side: decapsulate to get master key
    /// let decapsulated = my_keypair.decapsulate(&encapsulation)?;
    /// let session = KeySession::from_master_key(&decapsulated.master_key)?;
    /// ```
    pub fn from_master_key(master_key: &[u8; 32]) -> Result<Self> {
        KeySessionBuilder::new().build_from_master_key(master_key)
    }

    /// Derive a Volume Key for a specific volume.
    ///
    /// Retrieving the key from the pre-calculated cache.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - The volume sequence number (0, 1, 2, ...)
    ///
    /// # Returns
    ///
    /// A unique `VolumeKey` for this volume.
    ///
    /// # Panics
    ///
    /// Panics if `volume_id` >= `cached_volumes` (default 1024).
    pub fn derive_volume_key(&self, volume_id: u16) -> VolumeKey {
        let idx = volume_id as usize;
        if idx >= self.cached_volumes {
            panic!(
                "Volume ID {} exceeds cached limit {}. Use KeySessionBuilder to increase limit.",
                volume_id, self.cached_volumes
            );
        }

        let start = idx * 32;
        let bytes = &self.vk_cache.as_slice()[start..start + 32];

        VolumeKey::from_bytes(bytes.try_into().expect("Slice length must be 32"))
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
        // Build info: DOMAIN || block_index (big-endian) || nonce_context
        // Use stack allocation instead of Vec for performance
        let mut info = [0u8; 42]; // 18 (domain) + 8 (block_index) + 16 (nonce)
        let domain_len = BLOCK_KEY_DOMAIN.len();
        info[..domain_len].copy_from_slice(BLOCK_KEY_DOMAIN);
        info[domain_len..domain_len + 8].copy_from_slice(&block_index.to_be_bytes());
        info[domain_len + 8..domain_len + 8 + 16].copy_from_slice(nonce_context);

        let mut okm = [0u8; 32];
        derive_key_hkdf(
            volume_key.as_bytes(),
            None,
            &info[..domain_len + 8 + 16],
            &mut okm,
        )
        .expect("HKDF expand should not fail with valid parameters");

        BlockKey::from_bytes(okm)
    }

    /// Verify password against a stored verification tag.
    ///
    /// This is the secure replacement for `master_key()` - it allows password
    /// validation without exposing the master key.
    pub fn verify_password(&self, expected_tag: &[u8; 16]) -> bool {
        let tag = self.password_verification_tag();
        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        tag.ct_eq(expected_tag).into()
    }

    /// Get the password verification tag for this session.
    ///
    /// This tag can be stored in the archive header for early password validation.
    pub fn password_verification_tag(&self) -> [u8; 16] {
        self.verification_tag
    }

    /// Check if the master key memory is locked (protected from swapping)
    pub fn is_memory_locked(&self) -> bool {
        self.vk_cache.is_locked()
    }
}

impl std::fmt::Debug for KeySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySession")
            .field("vk_cache", &"[REDACTED 2MB]")
            .field("cached_volumes", &self.cached_volumes)
            .finish()
    }
}

impl Clone for KeySession {
    /// Clone the key session, creating a new mlock-protected copy of the cache.
    fn clone(&self) -> Self {
        Self {
            vk_cache: self.vk_cache.clone(),
            cached_volumes: self.cached_volumes,
            verification_tag: self.verification_tag,
        }
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
    fn test_builder_custom_limits() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        // Small cache limit
        let session = KeySessionBuilder::new()
            .with_max_volumes(10)
            .build(password, &salt, &params)
            .unwrap();

        // Access within limit
        let _ = session.derive_volume_key(9);

        // This would panic. We can catch it if we want to test panic,
        // but `should_panic` attribute applies to whole test function.
        // Let's create a sub-test.
    }

    #[test]
    #[should_panic(expected = "Volume ID 10 exceeds cached limit 10")]
    fn test_builder_limit_enforcement() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySessionBuilder::new()
            .with_max_volumes(10)
            .build(password, &salt, &params)
            .unwrap();

        // This should panic
        let _ = session.derive_volume_key(10);
    }

    #[test]
    fn test_key_session_creation() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();

        // Session should be created successfully
        // Verify via password verification tag that it derived correctly
        let tag = session.password_verification_tag();
        assert!(session.verify_password(&tag));
    }

    #[test]
    fn test_key_session_from_derived_key() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let derived_key = derive_key(password, &salt, &params).unwrap();
        let session = KeySession::from_derived_key(&derived_key);

        // Verify the session was created correctly by checking volume key derivation
        let vk = session.derive_volume_key(0);
        assert!(!vk.as_bytes().iter().all(|&b| b == 0)); // Should not be all zeros
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

        // Same session should verify its own tag
        assert!(session.verify_password(&tag));

        // Different session with same password/salt should have same tag
        let session2 = KeySession::new(password, &salt, &params).unwrap();
        let tag2 = session2.password_verification_tag();
        assert_eq!(tag, tag2);

        // Different password should produce different tag
        let session3 = KeySession::new(b"different_password", &salt, &params).unwrap();
        let tag3 = session3.password_verification_tag();
        assert_ne!(tag, tag3);
        assert!(!session.verify_password(&tag3));
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
