//! XChaCha20-Poly1305 AEAD encryption.

use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead as AeadTrait, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use era_common::{BlockId, EraError, Result};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::DerivedKey;

/// Size of the nonce in bytes (24 bytes for XChaCha20)
pub const NONCE_SIZE: usize = 24;

/// Size of the authentication tag in bytes
pub const TAG_SIZE: usize = 16;

/// AEAD key wrapper (32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(pub(crate) [u8; 32]);

impl AeadKey {
    /// Create a new AEAD key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(EraError::InvalidKey("AEAD key must be 32 bytes".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Get the key as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nonce wrapper (24 bytes for XChaCha20)
#[derive(Clone)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Create a zero nonce
    pub fn zero() -> Self {
        Self([0u8; NONCE_SIZE])
    }

    /// Generate a random nonce
    pub fn generate() -> Self {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self(nonce)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != NONCE_SIZE {
            return Err(EraError::InvalidFormat(format!(
                "Nonce must be {} bytes",
                NONCE_SIZE
            )));
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(bytes);
        Ok(Self(nonce))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }
}

/// Simple AEAD wrapper for direct encryption/decryption
pub struct AeadCipher;

impl AeadCipher {
    /// Create a new AEAD cipher
    pub fn new() -> Self {
        Self
    }

    /// Encrypt with key and nonce
    pub fn encrypt(&self, key: &AeadKey, nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new((&key.0).into());
        let xnonce = XNonce::from(nonce.0);

        cipher
            .encrypt(&xnonce, plaintext)
            .map_err(|e| EraError::encryption(e.to_string()))
    }

    /// Decrypt with key and nonce
    pub fn decrypt(&self, key: &AeadKey, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new((&key.0).into());
        let xnonce = XNonce::from(nonce.0);

        cipher
            .decrypt(&xnonce, ciphertext)
            .map_err(|e| EraError::decryption(e.to_string()))
    }
}

impl Default for AeadCipher {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt data using XChaCha20-Poly1305
///
/// The nonce is derived from the nonce_context and block ID for deterministic encryption.
/// The nonce_context MUST be unique per archive (e.g., salt or archive_id) to prevent
/// nonce reuse across different archives with the same password.
///
/// # Security
///
/// CRITICAL: The nonce_context must be unique per archive. Using the same
/// nonce_context with the same key across different archives will result in
/// nonce reuse, completely breaking the security of XChaCha20-Poly1305.
pub fn encrypt_with_context(
    key: &DerivedKey,
    nonce_context: &[u8; 16],
    block_id: BlockId,
    plaintext: &[u8],
) -> Result<Bytes> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = derive_nonce_with_context(nonce_context, block_id);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| EraError::encryption(e.to_string()))?;

    Ok(Bytes::from(ciphertext))
}

/// Decrypt data using XChaCha20-Poly1305
pub fn decrypt_with_context(
    key: &DerivedKey,
    nonce_context: &[u8; 16],
    block_id: BlockId,
    ciphertext: &[u8],
) -> Result<Bytes> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = derive_nonce_with_context(nonce_context, block_id);

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| EraError::decryption(e.to_string()))?;

    Ok(Bytes::from(plaintext))
}

/// Legacy encrypt function - DEPRECATED
///
/// This function is kept for backward compatibility but should not be used
/// for new code. Use `encrypt_with_context` instead.
#[deprecated(
    since = "0.2.0",
    note = "Use encrypt_with_context instead for nonce safety"
)]
pub fn encrypt(key: &DerivedKey, block_id: BlockId, plaintext: &[u8]) -> Result<Bytes> {
    // Use zero context for backward compatibility
    // This is NOT secure for production use across multiple archives!
    encrypt_with_context(key, &[0u8; 16], block_id, plaintext)
}

/// Legacy decrypt function - DEPRECATED
#[deprecated(
    since = "0.2.0",
    note = "Use decrypt_with_context instead for nonce safety"
)]
pub fn decrypt(key: &DerivedKey, block_id: BlockId, ciphertext: &[u8]) -> Result<Bytes> {
    decrypt_with_context(key, &[0u8; 16], block_id, ciphertext)
}

/// Derive a nonce from context and block ID
///
/// Uses Blake3 to derive a 24-byte nonce from the context and block ID.
/// This ensures each block has a unique nonce while being deterministic.
fn derive_nonce_with_context(context: &[u8; 16], block_id: BlockId) -> XNonce {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ERA-NONCE-V2"); // Updated version tag
    hasher.update(context); // Unique per-archive context (e.g., salt)
    hasher.update(&block_id.sequence().to_le_bytes());

    let hash = hasher.finalize();
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&hash.as_bytes()[..NONCE_SIZE]);

    XNonce::from(nonce)
}

/// Generate a random nonce (for cases where determinism is not needed)
#[allow(dead_code)]
fn generate_random_nonce() -> XNonce {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    XNonce::from(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_key, KdfParams, Salt};

    /// Test nonce context for consistent testing
    const TEST_NONCE_CONTEXT: [u8; 16] = [42u8; 16];

    fn test_key() -> DerivedKey {
        let salt = Salt::from_bytes([0u8; 16]);
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        derive_key(b"test_password", &salt, &params).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = b"Hello, ERA encryption!";

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();
        let decrypted =
            decrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_ref());
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = test_key();
        let block_id = BlockId::new(42);
        let plaintext = b"Deterministic test";

        let ciphertext1 =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();
        let ciphertext2 =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();

        // Same key, context, block_id, and plaintext should produce same ciphertext
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_different_block_id_different_ciphertext() {
        let key = test_key();
        let plaintext = b"Same plaintext";

        let ciphertext1 =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, BlockId::new(1), plaintext).unwrap();
        let ciphertext2 =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, BlockId::new(2), plaintext).unwrap();

        // Different block IDs should produce different ciphertext
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_different_context_different_ciphertext() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = b"Same plaintext";

        let context1 = [1u8; 16];
        let context2 = [2u8; 16];

        let ciphertext1 = encrypt_with_context(&key, &context1, block_id, plaintext).unwrap();
        let ciphertext2 = encrypt_with_context(&key, &context2, block_id, plaintext).unwrap();

        // Different contexts should produce different ciphertext (prevents nonce reuse across archives)
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let key2 = {
            let salt = Salt::from_bytes([1u8; 16]);
            let params = KdfParams {
                memory_cost: 1024,
                time_cost: 1,
                parallelism: 1,
            };
            derive_key(b"different_password", &salt, &params).unwrap()
        };

        let block_id = BlockId::new(1);
        let plaintext = b"Secret data";

        let ciphertext =
            encrypt_with_context(&key1, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();
        let result = decrypt_with_context(&key2, &TEST_NONCE_CONTEXT, block_id, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_context_fails() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = b"Secret data";

        let context1 = [1u8; 16];
        let context2 = [2u8; 16];

        let ciphertext = encrypt_with_context(&key, &context1, block_id, plaintext).unwrap();
        let result = decrypt_with_context(&key, &context2, block_id, &ciphertext);

        // Decryption with wrong context should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = b"Secret data";

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();

        // Tamper with the ciphertext by converting to Vec and back
        let mut tampered = ciphertext.to_vec();
        if let Some(byte) = tampered.get_mut(10) {
            *byte ^= 0xFF;
        }

        let result = decrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, &tampered);

        // Tampered data should fail AEAD verification
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = b"";

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();
        let decrypted =
            decrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, &ciphertext).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = vec![42u8; 1024 * 1024]; // 1MB

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, &plaintext).unwrap();
        let decrypted =
            decrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_ref());
    }

    #[test]
    fn test_ciphertext_size_includes_tag() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = b"Test data";

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();

        // Ciphertext should be larger than plaintext (includes 16-byte Poly1305 tag)
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_wrong_block_id_fails() {
        let key = test_key();
        let plaintext = b"Secret data";

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, BlockId::new(1), plaintext).unwrap();
        let result = decrypt_with_context(&key, &TEST_NONCE_CONTEXT, BlockId::new(2), &ciphertext);

        // Decryption with wrong block_id should fail (nonce mismatch)
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = test_key();
        let block_id = BlockId::new(1);
        let plaintext = b"Secret data that is long enough";

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();

        // Truncate the ciphertext
        let truncated: Vec<u8> = ciphertext.iter().take(10).copied().collect();

        let result = decrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, &truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_block_id() {
        let key = test_key();
        let block_id = BlockId::new(u64::MAX);
        let plaintext = b"Max block ID test";

        let ciphertext =
            encrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, plaintext).unwrap();
        let decrypted =
            decrypt_with_context(&key, &TEST_NONCE_CONTEXT, block_id, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_ref());
    }
}
