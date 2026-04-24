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
//! - Hybrid Post-Quantum KEM (X25519 + Kyber-768)

mod aead;
mod aead_context;
pub mod certificate;
pub mod commitment;
mod hash;
mod hkdf_utils;
pub mod hybrid_certificate;
pub mod hybrid_kem;
mod kdf;
mod key;
mod key_session;
pub mod pem_support;
pub mod timestamp;
// pub mod migration; // Removed legacy migration
mod secure_memory;
mod security_check;

// Re-exports for common types used in error handling
pub use era_common::{EraError, Result};

pub use commitment::{
    compute_catalog_commitment, compute_index_commitment, verify_catalog_commitment,
    verify_index_commitment,
};

pub use aead::TAG_SIZE;
pub use aead::{decrypt_with_context, encrypt_with_context, AeadCipher, AeadKey, Nonce};
pub use aead_context::{AeadContext, CiphertextPacket, XChaCha20Poly1305Context, NONCE_SIZE};
pub use certificate::{EraCertificate, EraKeyPair, KeyEncapsulation};
pub use hash::{hash, hash_reader, Hasher};
pub use hkdf_utils::{derive_key_hkdf, derive_key_hkdf_32};
pub use hybrid_certificate::{HybridCertificate, HybridKeyPair};
pub use kdf::{derive_key, generate_password_verification_tag, verify_password_tag, KdfParams};
pub use key::{DerivedKey, Salt};
pub use key_session::{
    reconstruct_master_key, split_master_key, unwrap_volume_key, wrap_volume_key, BlockKey,
    IntermediateKey, KeySession, KeySessionBuilder, VolumeKey, WrappedVolumeKey,
};
pub use pem_support::{
    export_hybrid_private_key_as_pem, export_hybrid_public_key_as_pem, export_public_key_as_pem,
    load_any_private_key_from_pem, load_hybrid_private_key_from_pem,
    load_hybrid_public_key_from_pem, load_private_key_from_pem, load_private_key_from_pem_string,
    load_public_key_from_pem, load_public_key_from_pem_string, EitherKeyPair, PemFormat,
};
pub use secure_memory::{
    check_security_features, disable_core_dumps, SecureBuffer, SecureKey32, SecureKey64,
    SecureMemoryConfig, SecurityReport,
};
pub use security_check::{print_security_report, verify_mlock_or_warn, verify_security_or_warn};
