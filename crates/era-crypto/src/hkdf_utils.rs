//! Unified HKDF-based key derivation for ERA Crypto
//!
//! This module standardizes all key derivation operations using
//! HKDF with SHA256, eliminating duplicated code across the codebase.

use hkdf::Hkdf;
use sha2::Sha256;
use era_common::Result;

/// Derive a key using HKDF-SHA256
///
/// # Parameters
/// - `ikm`: Input Keying Material (typically a master key)
/// - `salt`: Optional salt (can be None)
/// - `info`: Context/domain string for this derivation
/// - `output`: Output buffer (typically 32 bytes)
///
/// # Security
/// The `info` parameter must be unique for each key type to prevent
/// different keys from being derived for the same material.
pub fn derive_key_hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);

    hk.expand(info, output)
        .map_err(|_| era_common::EraError::InvalidKey("HKDF expand failed".into()))
}

/// Derive a 32-byte key using HKDF-SHA256 (common case)
pub fn derive_key_hkdf_32(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    derive_key_hkdf(ikm, salt, info, &mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_hkdf() {
        let ikm = b"master_key_material";
        let salt = Some(b"salt".as_slice());
        let info = b"volume_key";

        let mut output = [0u8; 32];
        derive_key_hkdf(ikm, salt, info, &mut output).unwrap();

        // Verify deterministic
        let mut output2 = [0u8; 32];
        derive_key_hkdf(ikm, salt, info, &mut output2).unwrap();

        assert_eq!(output, output2);
    }

    #[test]
    fn test_derive_key_hkdf_32() {
        let ikm = b"master_key_material";
        let salt = Some(b"salt".as_slice());
        let info = b"block_key";

        let key = derive_key_hkdf_32(ikm, salt, info).unwrap();
        assert_eq!(key.len(), 32);

        // Verify deterministic
        let key2 = derive_key_hkdf_32(ikm, salt, info).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_different_info_different_keys() {
        let ikm = b"master_key";
        let salt = Some(b"salt".as_slice());

        let key1 = derive_key_hkdf_32(ikm, salt, b"volume").unwrap();
        let key2 = derive_key_hkdf_32(ikm, salt, b"block").unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_salt_different_keys() {
        let ikm = b"master_key";
        let info = b"derived_key";

        let key1 = derive_key_hkdf_32(ikm, Some(b"salt1"), info).unwrap();
        let key2 = derive_key_hkdf_32(ikm, Some(b"salt2"), info).unwrap();

        assert_ne!(key1, key2);
    }
}
