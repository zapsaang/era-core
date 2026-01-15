//! Test utilities for encryption and block processing tests.
//!
//! Consolidates common test setup patterns to reduce code duplication across
//! era-packing and era-crypto test modules.

#[cfg(test)]
pub mod helpers {
    use era_crypto::{derive_key, KdfParams, Salt};

    /// Standard nonce context for tests (all test modules use the same value)
    pub const TEST_NONCE_CONTEXT: [u8; 16] = [42u8; 16];

    /// Create a test key with customizable salt byte
    ///
    /// Used by both era-crypto and era-packing tests
    pub fn test_key_with_salt(salt_byte: u8) -> era_crypto::DerivedKey {
        let salt_bytes = [salt_byte; 16];
        let salt = Salt::from_bytes(salt_bytes);
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        derive_key(b"test_password", &salt, &params).unwrap()
    }

    /// Create a default test key with salt byte 0
    pub fn test_key() -> era_crypto::DerivedKey {
        test_key_with_salt(0)
    }

    /// Create a test session with a default salt
    pub fn test_session() -> (era_crypto::KeySession, Salt) {
        let salt = Salt::from_bytes([0u8; 16]);
        let params = KdfParams {
            memory_cost: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let session = era_crypto::KeySession::new(b"test_password", &salt, &params).unwrap();
        (session, salt)
    }
}
