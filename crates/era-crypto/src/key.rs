//! Key types for encryption.

use rand::RngCore;

use crate::secure_memory::{SecureBuffer, SecureMemoryConfig, SecureMemoryError};

/// A derived encryption key (32 bytes for XChaCha20)
///
/// This key uses `SecureBuffer` internally to provide:
/// - mlock protection to prevent swapping to disk
/// - Automatic zeroization on drop
/// - Debug output redaction
///
/// # Security
///
/// Keys are protected from:
/// - Swap partition leakage (via mlock)
/// - Memory reuse attacks (via zeroize on drop)
/// - Accidental logging (via redacted Debug impl)
pub struct DerivedKey {
    buffer: SecureBuffer<32>,
}

impl DerivedKey {
    /// Create a new derived key from bytes.
    ///
    /// Uses default secure memory configuration (mlock enabled, non-strict).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_bytes_with_config(bytes, SecureMemoryConfig::default())
            .expect("Failed to allocate secure memory for DerivedKey")
    }

    /// Create a new derived key from bytes with custom memory configuration.
    pub fn from_bytes_with_config(
        bytes: [u8; 32],
        config: SecureMemoryConfig,
    ) -> Result<Self, SecureMemoryError> {
        let mut buffer = SecureBuffer::with_config(config)?;
        buffer.as_mut().copy_from_slice(&bytes);
        Ok(Self { buffer })
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.buffer.as_ref()
    }

    /// Check if the key memory is locked (protected from swapping)
    pub fn is_memory_locked(&self) -> bool {
        self.buffer.is_locked()
    }
}

impl Clone for DerivedKey {
    fn clone(&self) -> Self {
        Self::from_bytes(*self.as_bytes())
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("bytes", &"[REDACTED]")
            .field("is_locked", &self.buffer.is_locked())
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
