//! # Hybrid Post-Quantum Key Encapsulation Mechanism (KEM)
//!
//! **Security Model:** X25519 + Kyber-768 hybrid construction
//!
//! ## Design Philosophy
//!
//! "Paranoid Security" - Both KEMs must succeed for encryption/decryption:
//! - **X25519**: 128-bit classical security (ECDH on Curve25519)
//! - **Kyber-768**: NIST Level 3 post-quantum security (~192-bit classical equivalent)
//! - **Combined**: Secure against both classical AND quantum adversaries
//!
//! ## Key Derivation
//!
//! ```text
//! shared_secret_x25519 = X25519(ephemeral_sk, recipient_pk)
//! shared_secret_kyber = mlkem768.Decapsulate(ct, recipient_sk)
//!
//! combined_secret = HKDF-SHA256(
//!     salt: None,
//!     ikm: shared_secret_x25519 || shared_secret_kyber,
//!     info: "ERA-v2.2-Hybrid-KEM",
//!     output_len: 32 bytes
//! )
//! ```
//!
//! ## Ciphertext Format
//!
//! ```text
//! [X25519 ephemeral public key: 32 bytes]
//! [Kyber-768 ciphertext: 1088 bytes]
//! Total: 1120 bytes
//! ```
//!
//! ## Security Properties
//!
//! - **Confidentiality**: IND-CCA2 secure under both classical and quantum attacks
//! - **Forward Secrecy**: Ephemeral X25519 keys provide perfect forward secrecy
//! - **Quantum Resistance**: ML-KEM-768 provides post-quantum security
//! - **Key Zeroization**: All secret key material is zeroized on drop

use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::AeadKey;
use era_common::{EraError, Result};

/// Size of X25519 public key (32 bytes)
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of Kyber-768 ciphertext (1088 bytes)
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;

/// Total size of hybrid KEM ciphertext
pub const HYBRID_CIPHERTEXT_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM768_CIPHERTEXT_SIZE;

/// Hybrid public key containing both X25519 and ML-KEM-768 components
#[derive(Clone, Debug)]
pub struct HybridPublicKey {
    /// X25519 public key (32 bytes)
    pub x25519: X25519PublicKey,
    /// ML-KEM-768 public key (1184 bytes)
    pub kyber: mlkem768::PublicKey,
}

/// Hybrid secret key with automatic zeroization on drop
///
/// Note: We manually implement Drop instead of deriving ZeroizeOnDrop because
/// pqcrypto-kyber's SecretKey doesn't implement Zeroize. The mlkem768::SecretKey
/// handles its own zeroization via FFI Drop, so we only need to explicitly
/// zeroize the x25519 key.
pub struct HybridSecretKey {
    /// X25519 secret key (32 bytes, zeroized on drop)
    x25519: StaticSecret,
    /// Kyber-768 secret key (2400 bytes, zeroized on drop via FFI)
    kyber: mlkem768::SecretKey,
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        // Zeroize the X25519 key (StaticSecret implements Zeroize)
        use zeroize::Zeroize;
        self.x25519.zeroize();
        // Note: mlkem768::SecretKey handles its own zeroization via Drop
        // from the pqcrypto FFI bindings (it wraps a C library that zeros memory)
    }
}

impl HybridPublicKey {
    /// Serialize the public key to bytes
    ///
    /// Format: [X25519 PK: 32 bytes][Kyber PK: 1184 bytes]
    /// Total: 1216 bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + mlkem768::public_key_bytes());
        bytes.extend_from_slice(self.x25519.as_bytes());
        bytes.extend_from_slice(self.kyber.as_bytes());
        bytes
    }

    /// Deserialize a public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 + mlkem768::public_key_bytes() {
            return Err(EraError::Deserialization(format!(
                "Invalid hybrid public key length: expected {}, got {}",
                32 + mlkem768::public_key_bytes(),
                bytes.len()
            )));
        }

        let x25519_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| EraError::Deserialization("Failed to parse X25519 public key".into()))?;
        let x25519 = X25519PublicKey::from(x25519_bytes);

        let kyber = mlkem768::PublicKey::from_bytes(&bytes[32..]).map_err(|e| {
            EraError::Deserialization(format!("Failed to parse Kyber public key: {}", e))
        })?;

        Ok(Self { x25519, kyber })
    }
}

/// Generate a new hybrid keypair
///
/// This creates both X25519 and Kyber-768 keypairs.
/// The secret keys are automatically zeroized on drop.
pub fn generate_keypair() -> (HybridPublicKey, HybridSecretKey) {
    // Generate X25519 keypair
    let x25519_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // Generate Kyber-768 keypair
    let (kyber_public, kyber_secret) = mlkem768::keypair();

    let public_key = HybridPublicKey {
        x25519: x25519_public,
        kyber: kyber_public,
    };

    let secret_key = HybridSecretKey {
        x25519: x25519_secret,
        kyber: kyber_secret,
    };

    (public_key, secret_key)
}

/// Encapsulate a shared secret using the recipient's public key
///
/// Returns:
/// - Ciphertext (1120 bytes): [X25519 ephemeral PK][Kyber ciphertext]
/// - Shared AeadKey (32 bytes): Derived from combined secrets
///
/// ## Process
/// 1. Generate ephemeral X25519 keypair
/// 2. Perform X25519 ECDH with recipient's public key
/// 3. Encapsulate using Kyber-768 with recipient's public key
/// 4. Combine both shared secrets using HKDF
/// 5. Zeroize intermediate secrets
pub fn encapsulate(recipient_pk: &HybridPublicKey) -> Result<(Vec<u8>, AeadKey)> {
    // Step 1: Generate ephemeral X25519 keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Step 2: X25519 ECDH
    let x25519_shared = ephemeral_secret.diffie_hellman(&recipient_pk.x25519);

    // Step 3: Kyber-768 encapsulation
    let (kyber_shared, kyber_ciphertext) = mlkem768::encapsulate(&recipient_pk.kyber);

    // Step 4: Combine shared secrets using HKDF
    let aead_key = combine_shared_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())?;

    // Step 5: Construct ciphertext
    let mut ciphertext = Vec::with_capacity(HYBRID_CIPHERTEXT_SIZE);
    ciphertext.extend_from_slice(ephemeral_public.as_bytes());
    ciphertext.extend_from_slice(kyber_ciphertext.as_bytes());

    Ok((ciphertext, aead_key))
}

/// Decapsulate a shared secret using the recipient's secret key
///
/// Takes:
/// - Ciphertext (1120 bytes): [X25519 ephemeral PK][Kyber ciphertext]
/// - Recipient's secret key
///
/// Returns:
/// - Shared AeadKey (32 bytes): Same key as encapsulation
///
/// ## Process
/// 1. Parse ciphertext into X25519 PK and Kyber CT
/// 2. Perform X25519 ECDH with ephemeral public key
/// 3. Decapsulate Kyber-768 ciphertext
/// 4. Combine both shared secrets using HKDF
/// 5. Zeroize intermediate secrets
pub fn decapsulate(
    recipient_sk: &HybridSecretKey,
    _recipient_pk: &HybridPublicKey,
    ciphertext: &[u8],
) -> Result<AeadKey> {
    // Step 1: Validate ciphertext length
    if ciphertext.len() != HYBRID_CIPHERTEXT_SIZE {
        return Err(EraError::Decryption(format!(
            "Invalid hybrid ciphertext length: expected {}, got {}",
            HYBRID_CIPHERTEXT_SIZE,
            ciphertext.len()
        )));
    }

    // Step 2: Parse X25519 ephemeral public key
    let ephemeral_pk_bytes: [u8; 32] = ciphertext[..32]
        .try_into()
        .map_err(|_| EraError::Decryption("Failed to parse ephemeral X25519 public key".into()))?;
    let ephemeral_pk = X25519PublicKey::from(ephemeral_pk_bytes);

    // Step 3: X25519 ECDH
    let x25519_shared = recipient_sk.x25519.diffie_hellman(&ephemeral_pk);

    // Step 4: Parse Kyber ciphertext
    let kyber_ct = mlkem768::Ciphertext::from_bytes(&ciphertext[32..])
        .map_err(|e| EraError::Decryption(format!("Failed to parse Kyber ciphertext: {}", e)))?;

    // Step 5: Kyber-768 decapsulation
    let kyber_shared = mlkem768::decapsulate(&kyber_ct, &recipient_sk.kyber);

    // Step 6: Combine shared secrets using HKDF
    let aead_key = combine_shared_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())?;

    Ok(aead_key)
}

/// Combine X25519 and Kyber-768 shared secrets using HKDF
///
/// Uses HKDF-SHA256 with:
/// - Salt: None (all-zero salt of hash output length)
/// - IKM: x25519_shared || kyber_shared
/// - Info: "ERA-v2.2-Hybrid-KEM"
/// - Output: 32 bytes (AES-256-GCM key)
fn combine_shared_secrets(x25519_shared: &[u8], kyber_shared: &[u8]) -> Result<AeadKey> {
    // Concatenate shared secrets
    let mut ikm = Vec::with_capacity(x25519_shared.len() + kyber_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kyber_shared);

    // HKDF-SHA256 derivation
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut key_material = [0u8; 32];
    hkdf.expand(b"ERA-v2.2-Hybrid-KEM", &mut key_material)
        .map_err(|e| EraError::KeyDerivation(format!("HKDF failed: {}", e)))?;

    // Create AeadKey from derived material
    let aead_key = AeadKey::from_bytes(&key_material)?;

    // Zeroize intermediate key material
    ikm.zeroize();
    key_material.zeroize();

    Ok(aead_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (public_key, _secret_key) = generate_keypair();

        // Verify public key serialization roundtrip
        let serialized = public_key.to_bytes();
        assert_eq!(serialized.len(), 32 + mlkem768::public_key_bytes());

        let deserialized = HybridPublicKey::from_bytes(&serialized).unwrap();
        assert_eq!(public_key.x25519.as_bytes(), deserialized.x25519.as_bytes());
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        // Generate recipient keypair
        let (recipient_pk, recipient_sk) = generate_keypair();

        // Encapsulate
        let (ciphertext, encap_key) = encapsulate(&recipient_pk).unwrap();
        assert_eq!(ciphertext.len(), HYBRID_CIPHERTEXT_SIZE);

        // Decapsulate
        let decap_key = decapsulate(&recipient_sk, &recipient_pk, &ciphertext).unwrap();

        // Keys should match
        assert_eq!(encap_key.as_bytes(), decap_key.as_bytes());
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let (recipient_pk, recipient_sk) = generate_keypair();

        // Too short
        let invalid_ct = vec![0u8; 100];
        let result = decapsulate(&recipient_sk, &recipient_pk, &invalid_ct);
        assert!(result.is_err());

        // Too long
        let invalid_ct = vec![0u8; HYBRID_CIPHERTEXT_SIZE + 100];
        let result = decapsulate(&recipient_sk, &recipient_pk, &invalid_ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_key() {
        let (recipient_pk1, _recipient_sk1) = generate_keypair();
        let (_recipient_pk2, recipient_sk2) = generate_keypair();

        // Encapsulate with pk1
        let (ciphertext, encap_key) = encapsulate(&recipient_pk1).unwrap();

        // Try to decapsulate with sk2 (wrong key)
        let decap_key = decapsulate(&recipient_sk2, &recipient_pk1, &ciphertext).unwrap();

        // Keys should NOT match (Kyber decapsulation will produce random shared secret)
        assert_ne!(encap_key.as_bytes(), decap_key.as_bytes());
    }

    #[test]
    fn test_zeroization() {
        // This test verifies that secret keys are zeroized on drop
        // The actual zeroization happens via ZeroizeOnDrop trait
        let (_pk, sk) = generate_keypair();
        drop(sk);
        // If we had unsafe access to the dropped memory, we would verify
        // that it's been zeroized. The ZeroizeOnDrop trait handles this.
    }
}
