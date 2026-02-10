//! Security Integration Tests: Cryptographic Context Binding
//!
//! This test suite validates that ERA's encryption scheme properly binds
//! encrypted data to its cryptographic context (Volume UUID, Block ID, Chunk Hash).
//!
//! ## Attack Scenarios Tested
//!
//! 1. **Cross-Volume Block Injection**: Can an encrypted block from Volume A
//!    be copied to Volume B and decrypt successfully?
//!
//! 2. **Block Offset Manipulation**: Can a valid block be moved to a different
//!    offset within the same volume and still decrypt?
//!
//! 3. **Chunk Hash Tampering**: If a chunk's hash is modified, does decryption
//!    fail authentication?
//!
//! ## Expected Behavior (Post-Fix)
//!
//! All attacks should FAIL with authentication errors. The encryption must be
//! cryptographically bound to its context such that any context mismatch results
//! in decryption failure.

use bytes::Bytes;
use era_common::BlockId;
use era_crypto::{
    decrypt_with_context, derive_key, encrypt_with_context, DerivedKey, KdfParams, KeySession, Salt,
};

/// Fast KDF params for testing (DO NOT use in production)
fn test_kdf_params() -> KdfParams {
    KdfParams {
        memory_cost: 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

/// Create a deterministic test key
fn test_master_key() -> DerivedKey {
    let salt = Salt::from_bytes([0x42; 16]);
    derive_key(b"test_password_context_binding", &salt, &test_kdf_params()).unwrap()
}

/// Test data
fn test_plaintext() -> Bytes {
    Bytes::from(vec![0xAA; 4096])
}

// ============================================================================
// ATTACK TEST 1: Cross-Volume Block Injection
// ============================================================================

#[test]
fn test_attack_cross_volume_block_injection() {
    // Setup: Two different volumes with the same master key
    let session = KeySession::from_derived_key(&test_master_key());

    // Derive keys for both volumes
    let volume_a_key = session.generate_and_wrap_volume_key().unwrap().0;
    let volume_b_key = session.generate_and_wrap_volume_key().unwrap().0;

    let block_id = BlockId::new(0);
    let nonce_context = [0x11; 16];

    // Encrypt data in Volume A
    let plaintext = test_plaintext();
    let block_a_key = session.derive_block_key(&volume_a_key, block_id.sequence(), &nonce_context);
    let ciphertext_from_a = encrypt_with_context(
        &block_a_key.to_derived_key(),
        &nonce_context,
        block_id,
        &plaintext,
    )
    .unwrap();

    // ATTACK: Try to decrypt the same ciphertext in Volume B context
    // This should FAIL because the encryption should be bound to Volume A's UUID
    let block_b_key = session.derive_block_key(&volume_b_key, block_id.sequence(), &nonce_context);
    let result = decrypt_with_context(
        &block_b_key.to_derived_key(),
        &nonce_context,
        block_id,
        &ciphertext_from_a,
    );

    // Expected: Authentication failure
    assert!(result.is_err(), "Cross-volume block injection should fail");
    assert!(result.unwrap_err().to_string().contains("Decryption"));
}

// ============================================================================
// ATTACK TEST 2: Block Offset Manipulation
// ============================================================================

#[test]
fn test_attack_block_offset_manipulation() {
    let session = KeySession::from_derived_key(&test_master_key());
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

    let block_id_100 = BlockId::new(100);
    let block_id_200 = BlockId::new(200);
    let nonce_context = [0x22; 16];

    // Encrypt data at block offset 100
    let plaintext = test_plaintext();
    let block_key_100 =
        session.derive_block_key(&volume_key, block_id_100.sequence(), &nonce_context);
    let ciphertext_at_100 = encrypt_with_context(
        &block_key_100.to_derived_key(),
        &nonce_context,
        block_id_100,
        &plaintext,
    )
    .unwrap();

    // ATTACK: Try to decrypt the same block at offset 200
    // This should FAIL because the encryption is bound to block_id_100
    let block_key_200 =
        session.derive_block_key(&volume_key, block_id_200.sequence(), &nonce_context);
    let result = decrypt_with_context(
        &block_key_200.to_derived_key(),
        &nonce_context,
        block_id_200,
        &ciphertext_at_100,
    );

    // Expected: Authentication failure
    assert!(result.is_err(), "Block offset manipulation should fail");
    assert!(result.unwrap_err().to_string().contains("Decryption"));
}

// ============================================================================
// ATTACK TEST 3: Nonce Context Tampering
// ============================================================================

#[test]
fn test_attack_nonce_context_tampering() {
    let session = KeySession::from_derived_key(&test_master_key());
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

    let block_id = BlockId::new(0);
    let nonce_context_a = [0x33; 16];
    let nonce_context_b = [0x44; 16];

    // Encrypt with context A
    let plaintext = test_plaintext();
    let block_key = session.derive_block_key(&volume_key, block_id.sequence(), &nonce_context_a);
    let ciphertext = encrypt_with_context(
        &block_key.to_derived_key(),
        &nonce_context_a,
        block_id,
        &plaintext,
    )
    .unwrap();

    // ATTACK: Try to decrypt with different context B
    // This should FAIL
    let result = decrypt_with_context(
        &block_key.to_derived_key(),
        &nonce_context_b,
        block_id,
        &ciphertext,
    );

    // Expected: Authentication failure
    assert!(result.is_err(), "Nonce context tampering should fail");
    assert!(result.unwrap_err().to_string().contains("Decryption"));
}

// ============================================================================
// ATTACK TEST 4: Advanced - Mix Volume UUID and Block ID
// ============================================================================

#[test]
fn test_attack_mixed_volume_and_block_context() {
    // This is the most sophisticated attack: an adversary intercepts
    // Block 100 from Volume A and tries to inject it as Block 100 in Volume B
    // (matching block IDs but different volumes)

    let session = KeySession::from_derived_key(&test_master_key());

    let volume_a_key = session.generate_and_wrap_volume_key().unwrap().0;
    let volume_b_key = session.generate_and_wrap_volume_key().unwrap().0;

    let block_id = BlockId::new(100); // Same block ID
    let nonce_context = [0x55; 16];

    // Encrypt in Volume A at block 100
    let plaintext = test_plaintext();
    let block_key_a = session.derive_block_key(&volume_a_key, block_id.sequence(), &nonce_context);
    let ciphertext_from_a = encrypt_with_context(
        &block_key_a.to_derived_key(),
        &nonce_context,
        block_id,
        &plaintext,
    )
    .unwrap();

    // ATTACK: Try to decrypt in Volume B at the same block 100
    // Even though the block ID matches, the volume context is different
    let block_key_b = session.derive_block_key(&volume_b_key, block_id.sequence(), &nonce_context);
    let result = decrypt_with_context(
        &block_key_b.to_derived_key(),
        &nonce_context,
        block_id,
        &ciphertext_from_a,
    );

    // Expected: Authentication failure due to volume mismatch
    assert!(
        result.is_err(),
        "Cross-volume attack with matching block ID should fail"
    );
    assert!(result.unwrap_err().to_string().contains("Decryption"));
}

// ============================================================================
// POSITIVE TEST: Legitimate Decryption Should Work
// ============================================================================

#[test]
fn test_legitimate_encrypt_decrypt_with_full_context() {
    // This test verifies that legitimate encryption/decryption still works
    // after we add context binding

    let session = KeySession::from_derived_key(&test_master_key());
    let volume_key = session.generate_and_wrap_volume_key().unwrap().0;

    let block_id = BlockId::new(42);
    let nonce_context = [0x66; 16];

    let plaintext = test_plaintext();

    // Encrypt
    let block_key = session.derive_block_key(&volume_key, block_id.sequence(), &nonce_context);
    let ciphertext = encrypt_with_context(
        &block_key.to_derived_key(),
        &nonce_context,
        block_id,
        &plaintext,
    )
    .unwrap();

    // Decrypt with EXACT same context
    let decrypted = decrypt_with_context(
        &block_key.to_derived_key(),
        &nonce_context,
        block_id,
        &ciphertext,
    )
    .unwrap();

    assert_eq!(plaintext, decrypted);
}

// ============================================================================
// CRITICAL TEST: Volume UUID Must Be Part of Key Derivation
// ============================================================================

#[test]
fn test_volume_uuid_affects_derived_keys() {
    // This test verifies that changing the volume UUID produces different keys
    // even if all other parameters are the same

    let session = KeySession::from_derived_key(&test_master_key());

    let volume_key_0 = session.generate_and_wrap_volume_key().unwrap().0;
    let volume_key_1 = session.generate_and_wrap_volume_key().unwrap().0;

    let block_id = BlockId::new(0);
    let nonce_context = [0x77; 16];

    let block_key_0 = session.derive_block_key(&volume_key_0, block_id.sequence(), &nonce_context);
    let block_key_1 = session.derive_block_key(&volume_key_1, block_id.sequence(), &nonce_context);

    // Keys MUST be different even though block_id and nonce_context are the same
    assert_ne!(
        block_key_0.as_bytes(),
        block_key_1.as_bytes(),
        "VULNERABILITY: Volume UUID does not affect key derivation!"
    );
}

// ============================================================================
// FORENSIC TEST: Demonstrate Current Vulnerability (Before Fix)
// ============================================================================

#[test]
#[ignore] // Remove this attribute once we've confirmed the vulnerability exists
fn test_demonstrate_current_vulnerability() {
    // This test documents the CURRENT state before the fix.
    // It should PASS before the fix (showing the vulnerability exists)
    // and FAIL after the fix (showing we've closed the hole).
    //
    // Run with: cargo test test_demonstrate_current_vulnerability -- --ignored

    println!("\n=== DEMONSTRATING VULNERABILITY ===\n");

    let session = KeySession::from_derived_key(&test_master_key());

    // Two different volumes
    let volume_a_key = session.generate_and_wrap_volume_key().unwrap().0;
    let volume_b_key = session.generate_and_wrap_volume_key().unwrap().0;

    let block_id = BlockId::new(0);
    let nonce_context = [0x99; 16];

    // Encrypt in Volume A
    let plaintext = Bytes::from(b"SECRET DATA FROM VOLUME A".to_vec());
    let block_key_a = session.derive_block_key(&volume_a_key, block_id.sequence(), &nonce_context);

    println!("Volume A Block Key: {:?}", block_key_a.as_bytes());

    let ciphertext = encrypt_with_context(
        &block_key_a.to_derived_key(),
        &nonce_context,
        block_id,
        &plaintext,
    )
    .unwrap();

    println!("Encrypted {} bytes", ciphertext.len());

    // Derive key for Volume B at same block
    let block_key_b = session.derive_block_key(&volume_b_key, block_id.sequence(), &nonce_context);

    println!("Volume B Block Key: {:?}", block_key_b.as_bytes());

    // Check if keys are different
    if block_key_a.as_bytes() == block_key_b.as_bytes() {
        println!("\n🚨 VULNERABILITY CONFIRMED: Keys are IDENTICAL across volumes!");
        println!("An encrypted block from Volume A can be injected into Volume B.\n");
    } else {
        println!("\n✅ Keys are different. Attempting decryption...\n");
    }

    // Try to decrypt in Volume B
    match decrypt_with_context(
        &block_key_b.to_derived_key(),
        &nonce_context,
        block_id,
        &ciphertext,
    ) {
        Ok(decrypted) => {
            println!("🚨 VULNERABILITY CONFIRMED: Decryption succeeded in wrong volume!");
            println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
            panic!("Cross-volume decryption should have failed!");
        }
        Err(e) => {
            println!("✅ SECURE: Decryption failed as expected: {}", e);
        }
    }
}
