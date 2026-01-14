//! Security-focused tests for key isolation and memory protection
//!
//! These tests verify the security properties described in the
//! "密码缓存安全与性能优化" design document.

use bytes::Bytes;
use era_codec::ZstdCompressor;
use era_common::{ChunkHash, UniqueChunk};
use era_crypto::{
    disable_core_dumps, KdfParams, KeySession, Salt, SecureBuffer, SecureKey32, SecureMemoryConfig,
};
use era_packing::{SessionBlockBuilder, SessionBlockUnpacker};

const TEST_NONCE_CONTEXT: [u8; 16] = [0xAB; 16];

fn fast_kdf_params() -> KdfParams {
    KdfParams {
        memory_cost: 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

/// Test that the HKDF key hierarchy provides cryptographic isolation
#[test]
fn test_key_hierarchy_isolation() {
    let salt = Salt::generate();
    let params = fast_kdf_params();
    let session = KeySession::new(b"test_password", &salt, &params).unwrap();

    // Derive volume keys for different volumes
    let vk0 = session.derive_volume_key(0);
    let vk1 = session.derive_volume_key(1);
    let vk2 = session.derive_volume_key(2);

    // Volume keys should all be different
    assert_ne!(vk0.as_bytes(), vk1.as_bytes());
    assert_ne!(vk1.as_bytes(), vk2.as_bytes());
    assert_ne!(vk0.as_bytes(), vk2.as_bytes());

    // Block keys derived from same volume key should differ
    let bk0 = session.derive_block_key(&vk0, 0, &TEST_NONCE_CONTEXT);
    let bk1 = session.derive_block_key(&vk0, 1, &TEST_NONCE_CONTEXT);
    assert_ne!(bk0.as_bytes(), bk1.as_bytes());

    // Same block index but different volumes should produce different keys
    let bk_v0_b0 = session.derive_block_key(&vk0, 0, &TEST_NONCE_CONTEXT);
    let bk_v1_b0 = session.derive_block_key(&vk1, 0, &TEST_NONCE_CONTEXT);
    assert_ne!(bk_v0_b0.as_bytes(), bk_v1_b0.as_bytes());
}

/// Test avalanche effect in key derivation
#[test]
fn test_key_derivation_avalanche_effect() {
    let salt = Salt::generate();
    let params = fast_kdf_params();
    let session = KeySession::new(b"test_password", &salt, &params).unwrap();
    let vk = session.derive_volume_key(0);

    let bk0 = session.derive_block_key(&vk, 0, &TEST_NONCE_CONTEXT);
    let bk1 = session.derive_block_key(&vk, 1, &TEST_NONCE_CONTEXT);

    // Count bit differences (Hamming distance)
    let bit_diff: u32 = bk0
        .as_bytes()
        .iter()
        .zip(bk1.as_bytes())
        .map(|(a, b)| (*a ^ *b).count_ones())
        .sum();

    // Expect roughly half the bits to differ (128 out of 256)
    // Allow 25% tolerance: between 64 and 192 bits different
    assert!(
        bit_diff > 64 && bit_diff < 192,
        "Avalanche effect failed: {} bits differ (expected ~128)",
        bit_diff
    );
}

/// Test that different passwords produce completely different key hierarchies
#[test]
fn test_password_independence() {
    let salt = Salt::generate();
    let params = fast_kdf_params();

    let session1 = KeySession::new(b"password1", &salt, &params).unwrap();
    let session2 = KeySession::new(b"password2", &salt, &params).unwrap();

    let vk1 = session1.derive_volume_key(0);
    let vk2 = session2.derive_volume_key(0);
    assert_ne!(vk1.as_bytes(), vk2.as_bytes());

    let bk1 = session1.derive_block_key(&vk1, 0, &TEST_NONCE_CONTEXT);
    let bk2 = session2.derive_block_key(&vk2, 0, &TEST_NONCE_CONTEXT);
    assert_ne!(bk1.as_bytes(), bk2.as_bytes());
}

/// Test that different salts produce completely different key hierarchies
#[test]
fn test_salt_independence() {
    let salt1 = Salt::generate();
    let salt2 = Salt::generate();
    let params = fast_kdf_params();

    let session1 = KeySession::new(b"password", &salt1, &params).unwrap();
    let session2 = KeySession::new(b"password", &salt2, &params).unwrap();

    let vk1 = session1.derive_volume_key(0);
    let vk2 = session2.derive_volume_key(0);
    assert_ne!(vk1.as_bytes(), vk2.as_bytes());
}

/// Test per-block key derivation in SessionBlockBuilder
#[test]
fn test_session_builder_per_block_keys() {
    let salt = Salt::generate();
    let params = fast_kdf_params();
    let session = KeySession::new(b"test_password", &salt, &params).unwrap();
    let vk = session.derive_volume_key(0);

    let builder = SessionBlockBuilder::new(
        &session,
        &vk,
        TEST_NONCE_CONTEXT,
        Box::new(ZstdCompressor::default()),
    );

    // Create two blocks with identical data
    let data = vec![0x42u8; 256];
    let chunk1 = UniqueChunk::new(Bytes::from(data.clone()), ChunkHash::from_bytes([1u8; 32]));
    let chunk2 = UniqueChunk::new(Bytes::from(data.clone()), ChunkHash::from_bytes([2u8; 32]));

    let block1 = builder.pack_single(chunk1).unwrap();
    let block2 = builder.pack_single(chunk2).unwrap();

    // Ciphertext should be different even for identical plaintext
    // (different block IDs → different keys → different nonces)
    assert_ne!(block1.data, block2.data);

    // Both should decrypt correctly
    let unpacker = SessionBlockUnpacker::new(
        &session,
        &vk,
        TEST_NONCE_CONTEXT,
        Box::new(ZstdCompressor::default()),
    );

    let unpacked1 = unpacker.unpack(&block1).unwrap();
    let unpacked2 = unpacker.unpack(&block2).unwrap();

    assert_eq!(unpacked1.get_chunk(0).unwrap().as_ref(), &data);
    assert_eq!(unpacked2.get_chunk(0).unwrap().as_ref(), &data);
}

/// Test that wrong volume key fails decryption (key isolation)
#[test]
fn test_volume_key_isolation_prevents_cross_decryption() {
    let salt = Salt::generate();
    let params = fast_kdf_params();
    let session = KeySession::new(b"test_password", &salt, &params).unwrap();

    let vk0 = session.derive_volume_key(0);
    let vk1 = session.derive_volume_key(1);

    // Encrypt with volume 0
    let builder = SessionBlockBuilder::new(
        &session,
        &vk0,
        TEST_NONCE_CONTEXT,
        Box::new(ZstdCompressor::default()),
    );

    let data = vec![0x42u8; 128];
    let chunk = UniqueChunk::new(Bytes::from(data), ChunkHash::from_bytes([1u8; 32]));
    let block = builder.pack_single(chunk).unwrap();

    // Try to decrypt with volume 1 - should fail
    let wrong_unpacker = SessionBlockUnpacker::new(
        &session,
        &vk1,
        TEST_NONCE_CONTEXT,
        Box::new(ZstdCompressor::default()),
    );

    let result = wrong_unpacker.unpack(&block);
    assert!(
        result.is_err(),
        "Decryption with wrong volume key should fail"
    );
}

/// Test SecureBuffer memory protection
#[test]
fn test_secure_buffer_basic_ops() {
    let mut buffer = SecureKey32::new().unwrap();

    // Should be zeroed initially
    assert!(buffer.as_ref().iter().all(|&b| b == 0));

    // Write some data
    let key_data = [0x42u8; 32];
    buffer.as_mut().copy_from_slice(&key_data);
    assert_eq!(buffer.as_ref(), &key_data);
}

/// Test SecureBuffer debug output is redacted
#[test]
fn test_secure_buffer_debug_redaction() {
    let mut buffer = SecureKey32::new().unwrap();
    buffer.as_mut().copy_from_slice(&[0x42u8; 32]);

    let debug_str = format!("{:?}", buffer);
    assert!(
        debug_str.contains("REDACTED"),
        "Debug output should be redacted"
    );
    assert!(
        !debug_str.contains("42"),
        "Debug output should not contain key data"
    );
    assert!(
        !debug_str.contains("0x42"),
        "Debug output should not contain key data"
    );
}

/// Test SecureBuffer with mlock configuration
#[test]
fn test_secure_buffer_mlock_config() {
    let config = SecureMemoryConfig {
        enable_mlock: true,
        enable_guard_pages: false,
        strict_mlock: false, // Don't fail if mlock unavailable
    };

    let buffer = SecureBuffer::<32>::with_config(config).unwrap();
    // Buffer should be created successfully regardless of mlock support
    assert_eq!(buffer.as_ref().len(), 32);
}

/// Test that disable_core_dumps doesn't crash
#[test]
fn test_disable_core_dumps() {
    // This should succeed or gracefully fail on all platforms
    let result = disable_core_dumps();
    // We don't assert success because it depends on system configuration
    // Just ensure it doesn't panic
    let _ = result;
}

/// Test HKDF derivation is deterministic
#[test]
fn test_key_derivation_determinism() {
    let salt = Salt::from_bytes([0x11; 16]);
    let params = fast_kdf_params();

    let session1 = KeySession::new(b"password", &salt, &params).unwrap();
    let session2 = KeySession::new(b"password", &salt, &params).unwrap();

    // Same inputs should produce same keys
    let vk1 = session1.derive_volume_key(0);
    let vk2 = session2.derive_volume_key(0);
    assert_eq!(vk1.as_bytes(), vk2.as_bytes());

    let bk1 = session1.derive_block_key(&vk1, 42, &TEST_NONCE_CONTEXT);
    let bk2 = session2.derive_block_key(&vk2, 42, &TEST_NONCE_CONTEXT);
    assert_eq!(bk1.as_bytes(), bk2.as_bytes());
}

/// Test password verification tag consistency
#[test]
fn test_password_verification_tag() {
    let salt = Salt::generate();
    let params = fast_kdf_params();

    let session1 = KeySession::new(b"password", &salt, &params).unwrap();
    let session2 = KeySession::new(b"password", &salt, &params).unwrap();
    let session3 = KeySession::new(b"different", &salt, &params).unwrap();

    // Same password should produce same tag
    assert_eq!(
        session1.password_verification_tag(),
        session2.password_verification_tag()
    );

    // Different password should produce different tag
    assert_ne!(
        session1.password_verification_tag(),
        session3.password_verification_tag()
    );
}

/// Test block key conversion to DerivedKey
#[test]
fn test_block_key_to_derived_key_roundtrip() {
    let salt = Salt::generate();
    let params = fast_kdf_params();
    let session = KeySession::new(b"password", &salt, &params).unwrap();
    let vk = session.derive_volume_key(0);
    let bk = session.derive_block_key(&vk, 0, &TEST_NONCE_CONTEXT);

    let derived = bk.to_derived_key();
    assert_eq!(bk.as_bytes(), derived.as_bytes());
}
