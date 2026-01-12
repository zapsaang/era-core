//! Key types for encryption.

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A derived encryption key (32 bytes for XChaCha20)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    bytes: [u8; 32],
}

impl DerivedKey {
    /// Create a new derived key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Salt for key derivation (16 bytes)
#[derive(Clone, Debug)]
pub struct Salt {
    bytes: [u8; 16],
}

impl Salt {
    /// Generate a new random salt
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create from existing bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// Get the salt bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }
}
