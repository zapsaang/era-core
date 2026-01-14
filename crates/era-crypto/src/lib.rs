//! # ERA Crypto
//!
//! Cryptographic primitives for the ERA archive system.
//!
//! This crate provides:
//! - Blake3 hashing for content addressing
//! - Argon2id key derivation
//! - XChaCha20-Poly1305 AEAD encryption
//! - HKDF-based key session management for efficient sub-key derivation

mod aead;
mod hash;
mod kdf;
mod key;
mod key_session;
mod secure_memory;

#[allow(deprecated)]
pub use aead::{decrypt, encrypt, NONCE_SIZE, TAG_SIZE};
pub use aead::{decrypt_with_context, encrypt_with_context};
pub use hash::{hash, hash_reader, Hasher};
pub use kdf::{derive_key, generate_password_verification_tag, verify_password_tag, KdfParams};
pub use key::{DerivedKey, Salt};
pub use key_session::{BlockKey, KeySession, VolumeKey};
pub use secure_memory::{
    disable_core_dumps, SecureBuffer, SecureKey32, SecureKey64, SecureMemoryConfig,
};
