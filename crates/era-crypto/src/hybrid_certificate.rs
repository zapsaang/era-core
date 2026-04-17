//! Hybrid certificate and keypair adapter for post-quantum archive auth.
//!
//! Bridges the low-level `hybrid_kem` module with the engine's slot-based
//! auth contract: `params` holds the KEM ciphertext, `encrypted_master_key`
//! holds the AEAD-wrapped plaintext.

use crate::aead::{AeadCipher, Nonce};
use crate::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use era_common::{EraError, Result};

/// Domain separator for hybrid certificate MK encapsulation AAD
const HYBRID_ENCAPS_AAD: &[u8] = b"ERA_HYBRID_CERT_ENCAPS_v8.1";

/// Post-quantum public certificate containing a hybrid KEM public key.
#[derive(Clone, Debug)]
pub struct HybridCertificate {
    public_key: HybridPublicKey,
}

impl HybridCertificate {
    /// Create a certificate from a raw hybrid public key.
    pub fn new(public_key: HybridPublicKey) -> Self {
        Self { public_key }
    }

    /// Serialize the public key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    /// Deserialize a certificate from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let public_key = HybridPublicKey::from_bytes(bytes)?;
        Ok(Self { public_key })
    }

    /// Return a reference to the underlying hybrid public key.
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public_key
    }
}

/// Hybrid keypair with automatic zeroization on drop.
pub struct HybridKeyPair {
    secret_key: HybridSecretKey,
    public_key: HybridPublicKey,
}

impl Clone for HybridKeyPair {
    fn clone(&self) -> Self {
        Self {
            secret_key: HybridSecretKey::from_bytes(&self.secret_key.to_bytes())
                .expect(" cloning own bytes must succeed"),
            public_key: self.public_key.clone(),
        }
    }
}

impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKeyPair")
            .field("public_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl HybridKeyPair {
    /// Generate a new hybrid keypair.
    pub fn generate() -> Self {
        let (public_key, secret_key) = hybrid_kem::generate_keypair();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create a keypair from raw secret key bytes.
    ///
    /// The public key is re-derived from the X25519 component.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = HybridSecretKey::from_bytes(bytes)?;
        // Re-derive X25519 public key from the secret
        use x25519_dalek::PublicKey as X25519PublicKey;
        let _x25519_public = X25519PublicKey::from(&secret_key.x25519);
        // Re-derive Kyber public key is not directly supported, so we require
        // the caller to provide both. For PEM loading we store the public key
        // alongside the secret key.
        Err(EraError::InvalidKey(
            "Use from_secret_and_public_bytes for hybrid keys".into(),
        ))
    }

    /// Create a keypair from separate secret and public key byte slices.
    pub fn from_secret_and_public_bytes(secret_bytes: &[u8], public_bytes: &[u8]) -> Result<Self> {
        let secret_key = HybridSecretKey::from_bytes(secret_bytes)?;
        let public_key = HybridPublicKey::from_bytes(public_bytes)?;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Export the public certificate.
    pub fn certificate(&self) -> HybridCertificate {
        HybridCertificate {
            public_key: self.public_key.clone(),
        }
    }

    /// Encapsulate the master key for a hybrid certificate recipient.
    ///
    /// Returns `(params, encrypted_master_key)` where:
    /// - `params` is the 1120-byte hybrid KEM ciphertext
    /// - `encrypted_master_key` is the AEAD-wrapped master key
    pub fn encapsulate_for(
        recipient: &HybridCertificate,
        master_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ciphertext, aead_key) = hybrid_kem::encapsulate(recipient.public_key())?;

        let aead = AeadCipher::new();
        let nonce = Nonce::zero();
        let aad = HYBRID_ENCAPS_AAD;
        let encrypted_master_key = aead.encrypt(&aead_key, &nonce, aad, master_key)?;

        Ok((ciphertext, encrypted_master_key))
    }

    /// Decapsulate the master key from a hybrid recipient slot.
    ///
    /// Takes the 1120-byte `params` (hybrid KEM ciphertext) and the
    /// AEAD-wrapped `encrypted_master_key`.
    pub fn decapsulate(&self, params: &[u8], encrypted_master_key: &[u8]) -> Result<Vec<u8>> {
        let aead_key = hybrid_kem::decapsulate(&self.secret_key, &self.public_key, params)?;

        let aead = AeadCipher::new();
        let nonce = Nonce::zero();
        let aad = HYBRID_ENCAPS_AAD;
        aead.decrypt(&aead_key, &nonce, aad, encrypted_master_key)
    }

    /// Serialize the secret key to bytes.
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes()
    }

    /// Serialize the public key to bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        // HybridSecretKey already zeroizes its x25519 component on drop.
        // No extra work needed here.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_certificate_wraps_and_unwraps_master_key_roundtrip() {
        let keypair = HybridKeyPair::generate();
        let cert = keypair.certificate();
        let master_key = [0xABu8; 32];

        let (params, encrypted_master_key) =
            HybridKeyPair::encapsulate_for(&cert, &master_key).unwrap();

        assert_eq!(params.len(), 1120);
        assert!(!encrypted_master_key.is_empty());

        let decrypted = keypair.decapsulate(&params, &encrypted_master_key).unwrap();
        assert_eq!(decrypted, master_key);
    }

    #[test]
    fn test_hybrid_wrong_key_fails_decapsulation() {
        let keypair1 = HybridKeyPair::generate();
        let cert1 = keypair1.certificate();
        let keypair2 = HybridKeyPair::generate();
        let master_key = [0xABu8; 32];

        let (params, encrypted_master_key) =
            HybridKeyPair::encapsulate_for(&cert1, &master_key).unwrap();

        // Wrong key should produce garbage or fail authentication
        let result = keypair2.decapsulate(&params, &encrypted_master_key);
        assert!(result.is_err() || result.unwrap() != master_key);
    }
}
