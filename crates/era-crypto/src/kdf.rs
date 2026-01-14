//! Argon2id key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use era_common::{EraError, Result};
use subtle::ConstantTimeEq;

use crate::{DerivedKey, Salt};

/// Domain separator for password verification tag
const PASSWORD_VERIFY_DOMAIN: &[u8] = b"ERA-PASSWORD-VERIFY";

/// Parameters for key derivation
#[derive(Debug, Clone)]
pub struct KdfParams {
    /// Memory cost in KB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    /// Fast parameters for encrypting high-entropy secrets (like private keys)
    /// Uses minimal memory since the secret is already high-entropy
    pub fn fast() -> Self {
        Self {
            memory_cost: 1024, // 1 MB
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// Default parameters for user passwords
    pub fn standard() -> Self {
        Self::default()
    }

    /// Production parameters with maximum security
    pub fn production() -> Self {
        Self {
            memory_cost: 262144, // 256 MB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Derive a key from a password using Argon2id
pub fn derive_key(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<DerivedKey> {
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32), // Output length
    )
    .map_err(|e| EraError::InvalidKey(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password, salt.as_bytes(), &mut key_bytes)
        .map_err(|e| EraError::InvalidKey(e.to_string()))?;

    Ok(DerivedKey::from_bytes(key_bytes))
}

/// Generate a password verification tag from the derived key
///
/// This tag is stored in the archive header and allows early detection
/// of incorrect passwords before attempting to decrypt any data.
///
/// The tag is: Blake3(key || "ERA-PASSWORD-VERIFY") truncated to 16 bytes
pub fn generate_password_verification_tag(key: &DerivedKey) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key.as_bytes());
    hasher.update(PASSWORD_VERIFY_DOMAIN);
    let hash = hasher.finalize();

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&hash.as_bytes()[..16]);
    tag
}

/// Verify a password verification tag against a derived key
///
/// Returns true if the password is correct, false otherwise
pub fn verify_password_tag(key: &DerivedKey, expected_tag: &[u8; 16]) -> bool {
    let computed_tag = generate_password_verification_tag(key);
    // Use subtle crate for constant-time comparison to prevent timing attacks
    computed_tag.ct_eq(expected_tag).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn test_derive_key() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_params();

        let key1 = derive_key(password, &salt, &params).unwrap();
        let key2 = derive_key(password, &salt, &params).unwrap();

        // Same password and salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salt_different_key() {
        let password = b"test_password";
        let salt1 = Salt::generate();
        let salt2 = Salt::generate();
        let params = fast_params();

        let key1 = derive_key(password, &salt1, &params).unwrap();
        let key2 = derive_key(password, &salt2, &params).unwrap();

        // Different salt should produce different key
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_password_different_key() {
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = Salt::generate();
        let params = fast_params();

        let key1 = derive_key(password1, &salt, &params).unwrap();
        let key2 = derive_key(password2, &salt, &params).unwrap();

        // Different password should produce different key
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_empty_password() {
        let password = b"";
        let salt = Salt::generate();
        let params = fast_params();

        // Empty password should still work
        let key = derive_key(password, &salt, &params);
        assert!(key.is_ok());
    }

    #[test]
    fn test_password_verification_tag() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_params();

        let key = derive_key(password, &salt, &params).unwrap();
        let tag = generate_password_verification_tag(&key);

        // Tag should be deterministic
        let tag2 = generate_password_verification_tag(&key);
        assert_eq!(tag, tag2);

        // Verification should succeed
        assert!(verify_password_tag(&key, &tag));
    }

    #[test]
    fn test_password_verification_fails_with_wrong_key() {
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = Salt::generate();
        let params = fast_params();

        let key1 = derive_key(password1, &salt, &params).unwrap();
        let key2 = derive_key(password2, &salt, &params).unwrap();

        let tag1 = generate_password_verification_tag(&key1);

        // Verification with wrong key should fail
        assert!(!verify_password_tag(&key2, &tag1));
    }

    #[test]
    fn test_password_verification_fails_with_tampered_tag() {
        let password = b"test_password";
        let salt = Salt::generate();
        let params = fast_params();

        let key = derive_key(password, &salt, &params).unwrap();
        let mut tag = generate_password_verification_tag(&key);

        // Tamper with the tag
        tag[0] ^= 0xFF;

        // Verification should fail
        assert!(!verify_password_tag(&key, &tag));
    }

    #[test]
    fn test_constant_time_comparison() {
        // Test that subtle's ct_eq is correct
        use subtle::ConstantTimeEq;
        let a = [1u8; 16];
        let b = [1u8; 16];
        let c = [2u8; 16];

        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));

        // Test with single bit difference
        let mut d = a;
        d[15] = 0;
        assert!(!bool::from(a.ct_eq(&d)));
    }
}
