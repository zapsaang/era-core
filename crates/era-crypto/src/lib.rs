//! # ERA Crypto
//!
//! Cryptographic primitives for the ERA archive system.
//!
//! This crate provides:
//! - Blake3 hashing for content addressing
//! - Argon2id key derivation
//! - XChaCha20-Poly1305 AEAD encryption
//! - HKDF-based key session management for efficient sub-key derivation
//! - X25519-based certificate key exchange (high-performance alternative to Argon2)

mod aead;
pub mod certificate;
mod hash;
mod kdf;
mod key;
mod key_session;
mod secure_memory;
mod security_check;

// Re-exports for common types used in error handling
pub use era_common::{EraError, Result};

#[allow(deprecated)]
pub use aead::{decrypt, encrypt, NONCE_SIZE, TAG_SIZE};
pub use aead::{decrypt_with_context, encrypt_with_context, AeadCipher, AeadKey, Nonce};
pub use certificate::{EraCertificate, EraKeyPair, KeyEncapsulation};
pub use hash::{hash, hash_reader, Hasher};
pub use kdf::{derive_key, generate_password_verification_tag, verify_password_tag, KdfParams};
pub use key::{DerivedKey, Salt};
pub use key_session::{BlockKey, KeySession, KeySessionBuilder, VolumeKey};
pub use secure_memory::{
    check_security_features, disable_core_dumps, SecureBuffer, SecureKey32, SecureKey64,
    SecureMemoryConfig, SecurityReport,
};
pub use security_check::{print_security_report, verify_guard_pages_or_warn, verify_mlock_or_warn};
