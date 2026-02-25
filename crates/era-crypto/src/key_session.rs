//! Key Session Management - v8.1 Randomized Envelope Model
//!
//! ## Architecture (3-Layer Envelope Encryption)
//!
//! - **Layer 1: Master Key (MK)** - Root of trust, from CSPRNG, stored encrypted in RecipientSlots
//! - **Layer 2: Intermediate Key (IK)** - Derived from MK via HKDF, NEVER stored on disk
//! - **Layer 3: Volume Key (VK)** - Randomly generated per-volume, wrapped by IK
//!
//! This model enables instantaneous key rotation: re-wrap VK with new IK
//! without rewriting data blocks.

use crate::aead::{AeadCipher, AeadKey, Nonce};
use crate::hkdf_utils::derive_key_hkdf;
use crate::secure_memory::{SecureBuffer, SecureMemoryConfig};
use era_common::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// Domain separator for Intermediate Key derivation (MK -> IK)
const IK_DOMAIN: &[u8] = b"ERA_KeyWrap_v1";

/// Domain separator for block key derivation (VK -> BK)
const BLOCK_KEY_DOMAIN: &[u8] = b"ERA_BLOCK_KEY_v8.1";

/// Domain separator for password verification tag
const VERIFICATION_DOMAIN: &[u8] = b"ERA_PASSWORD_VERIFICATION_v8.1";

/// The Intermediate Key (Layer 2).
///
/// Derived from MK at runtime only. NEVER stored on disk.
/// Used solely to wrap/unwrap the Volume Key.
pub struct IntermediateKey {
    buffer: SecureBuffer<32>,
}

impl IntermediateKey {
    /// Derive IK from a Master Key using HKDF-SHA256.
    ///
    /// `IK = HKDF-Expand(PRK=MK, Info="ERA_KeyWrap_v1", Salt=None)`
    pub fn derive_from_master_key(mk: &[u8; 32]) -> Result<Self> {
        let mut buffer = SecureBuffer::with_config(SecureMemoryConfig::default()).map_err(|e| {
            era_common::EraError::Encryption(format!(
                "Failed to allocate secure memory for IntermediateKey: {}",
                e
            ))
        })?;
        derive_key_hkdf(mk, None, IK_DOMAIN, buffer.as_mut()).map_err(|e| {
            era_common::EraError::KeyDerivation(format!("HKDF expand failed: {}", e))
        })?;
        Ok(Self { buffer })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.buffer.as_ref()
    }
}

impl std::fmt::Debug for IntermediateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntermediateKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A Volume Key (Layer 3) - the actual Data Encryption Key.
///
/// MUST be randomly generated (32 bytes) for every new volume.
/// Encrypted by IK and stored in `SuperHeader.encrypted_volume_key`.
pub struct VolumeKey {
    buffer: SecureBuffer<32>,
}

impl VolumeKey {
    /// Generate a new random Volume Key using OsRng (CSPRNG).
    pub fn generate() -> Result<Self> {
        let mut buffer = SecureBuffer::with_config(SecureMemoryConfig::default()).map_err(|e| {
            era_common::EraError::Encryption(format!(
                "Failed to allocate secure memory for VolumeKey: {}",
                e
            ))
        })?;
        OsRng.fill_bytes(buffer.as_mut());
        Ok(Self { buffer })
    }

    /// Create a volume key from raw bytes (used when unwrapping)
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let mut buffer = SecureBuffer::with_config(SecureMemoryConfig::default()).map_err(|e| {
            era_common::EraError::Encryption(format!(
                "Failed to allocate secure memory for VolumeKey: {}",
                e
            ))
        })?;
        buffer.as_mut().copy_from_slice(&bytes);
        Ok(Self { buffer })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.buffer.as_ref()
    }

    pub fn is_memory_locked(&self) -> bool {
        self.buffer.is_locked()
    }
}

impl VolumeKey {
    /// Clone the volume key, returning Result since secure memory allocation can fail.
    pub fn try_clone(&self) -> Result<Self> {
        let mut buffer = SecureBuffer::with_config(SecureMemoryConfig::default()).map_err(|e| {
            era_common::EraError::Encryption(format!(
                "Failed to allocate secure memory for VolumeKey clone: {}",
                e
            ))
        })?;
        buffer.as_mut().copy_from_slice(self.buffer.as_ref());
        Ok(Self { buffer })
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
pub struct BlockKey {
    buffer: SecureBuffer<32>,
}

impl BlockKey {
    fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let mut buffer = SecureBuffer::with_config(SecureMemoryConfig::default()).map_err(|e| {
            era_common::EraError::Encryption(format!(
                "Failed to allocate secure memory for BlockKey: {}",
                e
            ))
        })?;
        buffer.as_mut().copy_from_slice(&bytes);
        Ok(Self { buffer })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.buffer.as_ref()
    }

    /// Convert to DerivedKey for compatibility with existing encryption APIs
    pub fn to_derived_key(&self) -> Result<crate::DerivedKey> {
        crate::DerivedKey::from_bytes(*self.as_bytes())
    }

    pub fn is_memory_locked(&self) -> bool {
        self.buffer.is_locked()
    }
}

impl BlockKey {
    /// Clone the block key, returning Result since secure memory allocation can fail.
    pub fn try_clone(&self) -> Result<Self> {
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

/// Result of wrapping a Volume Key with an Intermediate Key.
///
/// Contains the nonce and ciphertext needed to reconstruct the VK.
pub struct WrappedVolumeKey {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Wrap (encrypt) a Volume Key using the Intermediate Key.
///
/// Uses XChaCha20-Poly1305 with a fresh random nonce from OsRng.
/// Domain separator for VK wrap AAD context binding
const VK_WRAP_AAD_DOMAIN: &[u8] = b"ERA_VK_WRAP_v8.1";

pub fn wrap_volume_key(ik: &IntermediateKey, vk: &VolumeKey) -> Result<WrappedVolumeKey> {
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);

    let aead_key = AeadKey::from_bytes(ik.as_bytes())?;
    let nonce = Nonce::from_bytes(&nonce_bytes)?;
    let ciphertext = AeadCipher.encrypt(&aead_key, &nonce, VK_WRAP_AAD_DOMAIN, vk.as_bytes())?;

    Ok(WrappedVolumeKey {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Unwrap (decrypt) a Volume Key using the Intermediate Key.
///
/// Returns `EraError::Security("Key Tampering Detected")` if the
/// Poly1305 tag verification fails.
pub fn unwrap_volume_key(
    ik: &IntermediateKey,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<VolumeKey> {
    let aead_key = AeadKey::from_bytes(ik.as_bytes())?;
    let nonce = Nonce::from_bytes(nonce)?;
    let plaintext = AeadCipher
        .decrypt(&aead_key, &nonce, VK_WRAP_AAD_DOMAIN, ciphertext)
        .map_err(|_| era_common::EraError::Security("Key Tampering Detected".into()))?;

    let mut vk_bytes = [0u8; 32];
    if plaintext.len() != 32 {
        return Err(era_common::EraError::Security(
            "Invalid volume key length after unwrap".into(),
        ));
    }
    vk_bytes.copy_from_slice(&plaintext);
    let vk = VolumeKey::from_bytes(vk_bytes)?;
    vk_bytes.zeroize();
    Ok(vk)
}

/// KeySession holds the master key context for an archive session.
///
/// In the v8.1 envelope model, the session holds the MK (in secure memory)
/// and derives the IK on demand. Volume keys are no longer pre-cached;
/// they are unwrapped from the header's `EncryptedVolumeKey`.
pub struct KeySession {
    /// Master key in secure memory
    mk: SecureBuffer<32>,
    /// Verification tag derived from MK
    verification_tag: [u8; 16],
}

/// Builder for customization of KeySession
pub struct KeySessionBuilder {
    _max_volumes: usize,
}

impl Default for KeySessionBuilder {
    fn default() -> Self {
        Self { _max_volumes: 1024 }
    }
}

impl KeySessionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_volumes(mut self, max: usize) -> Self {
        self._max_volumes = max;
        self
    }

    pub fn build(
        self,
        password: &[u8],
        salt: &crate::Salt,
        params: &crate::KdfParams,
    ) -> Result<KeySession> {
        let derived_key = crate::derive_key(password, salt, params)?;
        KeySession::from_mk_bytes(derived_key.as_bytes())
    }

    pub fn build_from_derived(self, key: &crate::DerivedKey) -> Result<KeySession> {
        KeySession::from_mk_bytes(key.as_bytes())
    }

    pub fn build_from_master_key(self, master_key: &[u8; 32]) -> Result<KeySession> {
        KeySession::from_mk_bytes(master_key)
    }
}

impl KeySession {
    fn from_mk_bytes(mk_bytes: &[u8]) -> Result<Self> {
        if mk_bytes.len() != 32 {
            return Err(era_common::EraError::InvalidKey(
                "Master key must be 32 bytes".into(),
            ));
        }

        let mut mk = SecureBuffer::with_config(SecureMemoryConfig::default()).map_err(|e| {
            era_common::EraError::Encryption(format!("Failed to allocate MK: {}", e))
        })?;
        mk.as_mut().copy_from_slice(mk_bytes);

        let mut verification_tag = [0u8; 16];
        derive_key_hkdf(mk_bytes, None, VERIFICATION_DOMAIN, &mut verification_tag).map_err(
            |e| era_common::EraError::KeyDerivation(format!("HKDF expand failed: {}", e)),
        )?;

        Ok(Self {
            mk,
            verification_tag,
        })
    }

    /// Create a new key session from password
    pub fn new(password: &[u8], salt: &crate::Salt, params: &crate::KdfParams) -> Result<Self> {
        KeySessionBuilder::new().build(password, salt, params)
    }

    /// Create from existing derived key
    pub fn from_derived_key(key: &crate::DerivedKey) -> Result<Self> {
        KeySessionBuilder::new().build_from_derived(key)
    }

    /// Create a key session from a raw master key (for certificate mode).
    pub fn from_master_key(master_key: &[u8; 32]) -> Result<Self> {
        KeySessionBuilder::new().build_from_master_key(master_key)
    }

    /// Derive the Intermediate Key from the stored Master Key.
    pub fn derive_intermediate_key(&self) -> Result<IntermediateKey> {
        IntermediateKey::derive_from_master_key(self.mk.as_ref())
    }

    /// Generate a new random Volume Key and wrap it with the IK.
    ///
    /// Returns both the plaintext VK (for encrypting data) and the
    /// wrapped form (for storing in the header).
    pub fn generate_and_wrap_volume_key(&self) -> Result<(VolumeKey, WrappedVolumeKey)> {
        let vk = VolumeKey::generate()?;
        let ik = self.derive_intermediate_key()?;
        let wrapped = wrap_volume_key(&ik, &vk)?;
        Ok((vk, wrapped))
    }

    /// Unwrap a Volume Key from the header's encrypted form.
    pub fn unwrap_volume_key(&self, nonce: &[u8; 24], ciphertext: &[u8]) -> Result<VolumeKey> {
        let ik = self.derive_intermediate_key()?;
        unwrap_volume_key(&ik, nonce, ciphertext)
    }

    /// Derive a Block Key for a specific block within a volume.
    ///
    /// Uses HKDF-Expand with the block index and nonce context as info.
    pub fn derive_block_key(
        &self,
        volume_key: &VolumeKey,
        block_index: u64,
        nonce_context: &[u8; 16],
    ) -> Result<BlockKey> {
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
        .map_err(|e| era_common::EraError::KeyDerivation(format!("HKDF expand failed: {}", e)))?;

        let key = BlockKey::from_bytes(okm);
        okm.zeroize();
        key
    }

    /// Verify password against a stored verification tag.
    pub fn verify_password(&self, expected_tag: &[u8; 16]) -> bool {
        let tag = self.password_verification_tag();
        use subtle::ConstantTimeEq;
        tag.ct_eq(expected_tag).into()
    }

    /// Get the password verification tag for this session.
    pub fn password_verification_tag(&self) -> [u8; 16] {
        self.verification_tag
    }

    /// Check if the master key memory is locked
    pub fn is_memory_locked(&self) -> bool {
        self.mk.is_locked()
    }

    /// Derive a deterministic key for checkpoint HMAC integrity.
    ///
    /// This uses HKDF with a dedicated domain string, separate from volume keys.
    /// Volume keys MUST be randomly generated (§1.1), but checkpoint keys need
    /// to be reproducible from the same MK for integrity verification.
    pub fn derive_checkpoint_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let mut okm = [0u8; 32];
        derive_key_hkdf(
            self.mk.as_ref(),
            None,
            b"ERA_CHECKPOINT_HMAC_v8.1",
            &mut okm,
        )
        .map_err(|e| era_common::EraError::KeyDerivation(format!("HKDF expand failed: {}", e)))?;
        Ok(zeroize::Zeroizing::new(okm))
    }
}

impl std::fmt::Debug for KeySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySession")
            .field("mk", &"[REDACTED]")
            .finish()
    }
}

impl KeySession {
    /// Clone the session, returning Result since secure memory allocation can fail.
    pub fn try_clone(&self) -> Result<Self> {
        let mut mk = SecureBuffer::with_config(SecureMemoryConfig::default()).map_err(|e| {
            era_common::EraError::Encryption(format!(
                "Failed to allocate secure memory for KeySession clone: {}",
                e
            ))
        })?;
        mk.as_mut().copy_from_slice(self.mk.as_ref());
        Ok(Self {
            mk,
            verification_tag: self.verification_tag,
        })
    }
}

/// Split a master key into N shares with threshold T using Shamir's Secret Sharing.
pub fn split_master_key(
    mk: &[u8; 32],
    threshold: u8,
    total_shares: u8,
) -> era_common::Result<Vec<Vec<u8>>> {
    if threshold < 2 {
        return Err(era_common::EraError::InvalidConfig(
            "Threshold must be >= 2".into(),
        ));
    }
    if total_shares < threshold {
        return Err(era_common::EraError::InvalidConfig(
            "Total shares must be >= threshold".into(),
        ));
    }
    let sharks = sharks::Sharks(threshold);
    let dealer = sharks.dealer(mk);
    Ok(dealer
        .take(total_shares as usize)
        .map(|s| Vec::from(&s))
        .collect())
}

/// Reconstruct a master key from T shares using Shamir's Secret Sharing.
pub fn reconstruct_master_key(shares: &[Vec<u8>], threshold: u8) -> era_common::Result<[u8; 32]> {
    let sharks = sharks::Sharks(threshold);
    let shark_shares: Vec<sharks::Share> = shares
        .iter()
        .map(|s| sharks::Share::try_from(s.as_slice()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| era_common::EraError::Security("Invalid share format".into()))?;
    let secret = sharks
        .recover(&shark_shares)
        .map_err(|_| era_common::EraError::Security("Share reconstruction failed".into()))?;
    secret
        .try_into()
        .map_err(|_| era_common::EraError::Security("Reconstructed key is not 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KdfParams, Salt};

    fn fast_kdf_params() -> KdfParams {
        KdfParams {
            memory_cost: 1024,
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
        let tag = session.password_verification_tag();
        assert!(session.verify_password(&tag));
    }

    #[test]
    fn test_intermediate_key_derivation_deterministic() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let ik1 = session.derive_intermediate_key().unwrap();
        let ik2 = session.derive_intermediate_key().unwrap();
        assert_eq!(ik1.as_bytes(), ik2.as_bytes());
    }

    #[test]
    fn test_volume_key_is_random() {
        let vk1 = VolumeKey::generate().unwrap();
        let vk2 = VolumeKey::generate().unwrap();
        assert_ne!(vk1.as_bytes(), vk2.as_bytes());
    }

    #[test]
    fn test_wrap_unwrap_volume_key() {
        let mk = [0x42u8; 32];
        let session = KeySession::from_master_key(&mk).unwrap();

        let (vk, wrapped) = session.generate_and_wrap_volume_key().unwrap();

        let unwrapped = session
            .unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext)
            .unwrap();

        assert_eq!(vk.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn test_tampered_wrapped_key_fails() {
        let mk = [0x42u8; 32];
        let session = KeySession::from_master_key(&mk).unwrap();

        let (_vk, mut wrapped) = session.generate_and_wrap_volume_key().unwrap();

        // Tamper with ciphertext
        if let Some(byte) = wrapped.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = session.unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Key Tampering Detected"));
    }

    #[test]
    fn test_wrong_mk_cannot_unwrap() {
        let mk1 = [0x42u8; 32];
        let mk2 = [0x43u8; 32];
        let session1 = KeySession::from_master_key(&mk1).unwrap();
        let session2 = KeySession::from_master_key(&mk2).unwrap();

        let (_vk, wrapped) = session1.generate_and_wrap_volume_key().unwrap();

        let result = session2.unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_key_derivation_deterministic() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = VolumeKey::generate().unwrap();
        let nonce_context = [1u8; 16];

        let bk1 = session.derive_block_key(&vk, 0, &nonce_context).unwrap();
        let bk2 = session.derive_block_key(&vk, 0, &nonce_context).unwrap();
        assert_eq!(bk1.as_bytes(), bk2.as_bytes());
    }

    #[test]
    fn test_block_keys_different_for_different_blocks() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = VolumeKey::generate().unwrap();
        let nonce_context = [1u8; 16];

        let bk0 = session.derive_block_key(&vk, 0, &nonce_context).unwrap();
        let bk1 = session.derive_block_key(&vk, 1, &nonce_context).unwrap();
        assert_ne!(bk0.as_bytes(), bk1.as_bytes());
    }

    #[test]
    fn test_password_verification_tag_matches() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let tag = session.password_verification_tag();
        assert!(session.verify_password(&tag));

        let session2 = KeySession::new(password, &salt, &params).unwrap();
        assert_eq!(tag, session2.password_verification_tag());

        let session3 = KeySession::new(b"different_password", &salt, &params).unwrap();
        assert!(!session.verify_password(&session3.password_verification_tag()));
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_kdf_params();

        let session = KeySession::new(password, &salt, &params).unwrap();
        let vk = VolumeKey::generate().unwrap();
        let bk = session.derive_block_key(&vk, 0, &[0u8; 16]).unwrap();
        let ik = session.derive_intermediate_key().unwrap();

        assert!(format!("{:?}", session).contains("REDACTED"));
        assert!(format!("{:?}", vk).contains("REDACTED"));
        assert!(format!("{:?}", bk).contains("REDACTED"));
        assert!(format!("{:?}", ik).contains("REDACTED"));
    }

    #[test]
    fn test_key_rotation_rewrap() {
        // Simulate key rotation: old MK -> new MK, same VK
        let old_mk = [0x01u8; 32];
        let new_mk = [0x02u8; 32];

        let old_session = KeySession::from_master_key(&old_mk).unwrap();
        let new_session = KeySession::from_master_key(&new_mk).unwrap();

        // Create and wrap VK with old MK
        let (original_vk, wrapped) = old_session.generate_and_wrap_volume_key().unwrap();

        // Unwrap with old IK
        let vk = old_session
            .unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext)
            .unwrap();
        assert_eq!(original_vk.as_bytes(), vk.as_bytes());

        // Re-wrap with new IK
        let new_ik = new_session.derive_intermediate_key().unwrap();
        let new_wrapped = wrap_volume_key(&new_ik, &vk).unwrap();

        // Unwrap with new session
        let rewrapped_vk = new_session
            .unwrap_volume_key(&new_wrapped.nonce, &new_wrapped.ciphertext)
            .unwrap();

        // VK must be identical - data doesn't need re-encryption
        assert_eq!(original_vk.as_bytes(), rewrapped_vk.as_bytes());
    }
}
