//! AEAD Context abstraction for ERA Crypto
//!
//! This module provides a trait-based abstraction for AEAD ciphers,
//! eliminating code duplication and enabling support for multiple algorithms.

use crate::DerivedKey;
use era_common::{BlockId, EraError, Result};

/// Size of the nonce in bytes (24 bytes for XChaCha20)
pub const NONCE_SIZE: usize = 24;

/// A unified interface for AEAD cipher operations
pub trait AeadContext {
    /// Encrypt plaintext with optional authenticated data
    fn encrypt(&self, nonce: &[u8; NONCE_SIZE], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with optional authenticated data
    fn decrypt(&self, nonce: &[u8; NONCE_SIZE], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Check if this algorithm is available on the current platform
    fn is_available() -> bool;

    /// Get the algorithm name for logging/reporting
    fn algorithm_name() -> &'static str;

    /// Encrypt with implicit nonce derivation (for backward compatibility)
    fn encrypt_with_context(
        &self,
        nonce_context: &[u8; 16],
        block_id: BlockId,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = Self::derive_nonce_with_context(nonce_context, block_id);
        self.encrypt(&nonce, &[], plaintext)
    }

    /// Decrypt with implicit nonce derivation (for backward compatibility)
    fn decrypt_with_context(
        &self,
        nonce_context: &[u8; 16],
        block_id: BlockId,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = Self::derive_nonce_with_context(nonce_context, block_id);
        self.decrypt(&nonce, &[], ciphertext)
    }

    /// Derive a nonce from context and block ID
    fn derive_nonce_with_context(context: &[u8; 16], block_id: BlockId) -> [u8; NONCE_SIZE] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ERA-NONCE-V2");
        hasher.update(context);
        hasher.update(&block_id.sequence().to_le_bytes());

        let hash = hasher.finalize();
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&hash.as_bytes()[..NONCE_SIZE]);
        nonce
    }
}

/// XChaCha20-Poly1305 context implementation
pub struct XChaCha20Poly1305Context {
    cipher: chacha20poly1305::XChaCha20Poly1305,
}

impl XChaCha20Poly1305Context {
    /// Create a new XChaCha20-Poly1305 context from a key
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        use chacha20poly1305::KeyInit;
        Ok(Self {
            cipher: chacha20poly1305::XChaCha20Poly1305::new(key.into()),
        })
    }

    /// Create from DerivedKey
    pub fn from_derived_key(key: &DerivedKey) -> Result<Self> {
        Self::new(key.as_bytes())
    }
}

impl AeadContext for XChaCha20Poly1305Context {
    fn encrypt(&self, nonce: &[u8; NONCE_SIZE], _aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::XNonce;

        let xnonce = XNonce::from(*nonce);
        self.cipher
            .encrypt(&xnonce, plaintext)
            .map_err(|e| EraError::encryption(e.to_string()))
    }

    fn decrypt(&self, nonce: &[u8; NONCE_SIZE], _aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::XNonce;

        let xnonce = XNonce::from(*nonce);
        self.cipher
            .decrypt(&xnonce, ciphertext)
            .map_err(|e| EraError::decryption(e.to_string()))
    }

    fn is_available() -> bool {
        true
    }

    fn algorithm_name() -> &'static str {
        "XChaCha20-Poly1305"
    }
}

/// Ciphertext packet wrapper for better metadata management
#[derive(Clone)]
pub struct CiphertextPacket {
    /// 24-byte nonce
    nonce: [u8; NONCE_SIZE],
    /// Encrypted data
    ciphertext: Vec<u8>,
}

impl CiphertextPacket {
    /// Create from components
    pub fn new(nonce: [u8; NONCE_SIZE], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Get nonce
    pub fn nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.nonce
    }

    /// Get ciphertext
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Serialize to bytes (nonce || ciphertext)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(NONCE_SIZE + self.ciphertext.len());
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserialize from bytes (nonce || ciphertext)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < NONCE_SIZE {
            return Err(EraError::InvalidFormat(
                "Ciphertext packet too short".into(),
            ));
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[..NONCE_SIZE]);

        Ok(Self {
            nonce,
            ciphertext: data[NONCE_SIZE..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20_context() {
        let key = [0x42u8; 32];
        let _context = XChaCha20Poly1305Context::new(&key).unwrap();

        assert_eq!(
            XChaCha20Poly1305Context::algorithm_name(),
            "XChaCha20-Poly1305"
        );
        assert!(XChaCha20Poly1305Context::is_available());
    }

    #[test]
    fn test_ciphertext_packet_roundtrip() {
        let nonce = [0x42u8; NONCE_SIZE];
        let ciphertext = vec![1, 2, 3, 4, 5];

        let packet = CiphertextPacket::new(nonce, ciphertext.clone());
        let bytes = packet.to_bytes();
        let packet2 = CiphertextPacket::from_bytes(&bytes).unwrap();

        assert_eq!(packet2.nonce(), &nonce);
        assert_eq!(packet2.ciphertext(), ciphertext.as_slice());
    }
}
