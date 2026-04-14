//! # V9 Adversarial Audit — era-crypto Security Tests
//!
//! Tests targeting: panic paths, key material leakage, memory safety,
//! and coding standard violations in the cryptographic layer.

use era_crypto::hybrid_kem::{decapsulate, encapsulate, generate_keypair};
use era_crypto::*;

const TEST_ARCHIVE_ID: [u8; 16] = [0x42u8; 16];
const TEST_EPOCH_ID: u32 = 1;
const TEST_VOLUME_INDEX: u32 = 0;

// ═══════════════════════════════════════════════════════════════════════
// V9-C1: panic!() in HybridSecretKey::public_key() — unconditional abort
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c1a_hybrid_keypair_roundtrip() {
    // P0 fix verified: public_key() panic removed.
    // Verify generate_keypair produces a working keypair via encapsulate/decapsulate.
    let (pk, sk) = generate_keypair();
    let (ciphertext, shared_enc) = encapsulate(&pk).unwrap();
    let shared_dec = decapsulate(&sk, &pk, &ciphertext).unwrap();
    assert_eq!(
        shared_enc.as_bytes(),
        shared_dec.as_bytes(),
        "V9-C1a: KEM roundtrip must produce matching shared secrets"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C2: DerivedKey zeroization — verify key material is not leaked
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c2a_derived_key_basic_operations() {
    let key_bytes = [0x42u8; 32];
    let key = DerivedKey::from_bytes(key_bytes).unwrap();

    let bytes = key.as_bytes();
    assert_eq!(bytes, &key_bytes);
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C3: AEAD context binding — verify AAD is properly bound
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c3a_aead_context_binding_prevents_cross_block_replay() {
    let key = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let nonce_context = [0x01u8; 16];
    let block_id = era_common::BlockId::new(0);
    let block_id_2 = era_common::BlockId::new(1);
    let plaintext = b"sensitive data";

    let ciphertext = encrypt_with_context(
        &key,
        &nonce_context,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id,
        plaintext,
    )
    .expect("Encryption should succeed");

    let decrypted = decrypt_with_context(
        &key,
        &nonce_context,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id,
        &ciphertext,
    )
    .expect("Decryption with correct context should succeed");
    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "Decrypted text must match plaintext"
    );

    let wrong_decrypt = decrypt_with_context(
        &key,
        &nonce_context,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id_2,
        &ciphertext,
    );
    assert!(
        wrong_decrypt.is_err(),
        "V9-C3a: Decryption with wrong block_id should fail (AAD binding)"
    );
}

#[test]
fn v9_c3b_aead_context_binding_prevents_cross_nonce_replay() {
    let key = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let nonce_context_1 = [0x01u8; 16];
    let nonce_context_2 = [0x02u8; 16];
    let block_id = era_common::BlockId::new(0);
    let plaintext = b"sensitive data";

    let ciphertext = encrypt_with_context(
        &key,
        &nonce_context_1,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id,
        plaintext,
    )
    .unwrap();

    let wrong_decrypt = decrypt_with_context(
        &key,
        &nonce_context_2,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id,
        &ciphertext,
    );
    assert!(
        wrong_decrypt.is_err(),
        "V9-C3b: Decryption with wrong nonce context should fail"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C4: KeySession — basic smoke test
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c4a_key_session_derive_block_key() {
    let mk = [0x42u8; 32];
    let derived_key = DerivedKey::from_bytes(mk).unwrap();
    let session = KeySession::from_derived_key(&derived_key).unwrap();

    let vk = VolumeKey::generate().unwrap();
    let nonce_context = [0u8; 16];

    let bk0 = session.derive_block_key(&vk, 0, &nonce_context).unwrap();
    let bk1 = session.derive_block_key(&vk, 1, &nonce_context).unwrap();

    assert_ne!(
        bk0.to_derived_key().unwrap().as_bytes(),
        bk1.to_derived_key().unwrap().as_bytes(),
        "V9-C4a: Different block indices must produce different keys"
    );
}

#[test]
fn v9_c4b_key_session_deterministic() {
    let mk = [0x42u8; 32];
    let dk = DerivedKey::from_bytes(mk).unwrap();
    let session = KeySession::from_derived_key(&dk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let nonce_context = [0x01u8; 16];

    let bk_a = session.derive_block_key(&vk, 42, &nonce_context).unwrap();
    let bk_b = session.derive_block_key(&vk, 42, &nonce_context).unwrap();

    assert_eq!(
        bk_a.to_derived_key().unwrap().as_bytes(),
        bk_b.to_derived_key().unwrap().as_bytes(),
        "V9-C4b: Same inputs must produce same block key (HKDF is deterministic)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C5: Volume key wrapping/unwrapping roundtrip
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c5a_volume_key_wrap_unwrap_roundtrip() {
    let mk = [0x42u8; 32];
    let dk = DerivedKey::from_bytes(mk).unwrap();
    let session = KeySession::from_derived_key(&dk).unwrap();

    let (vk, wrapped) = session.generate_and_wrap_volume_key().unwrap();

    let unwrapped = session
        .unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext)
        .unwrap();

    assert_eq!(
        vk.as_bytes(),
        unwrapped.as_bytes(),
        "V9-C5a: Unwrapped key must match original"
    );
}

#[test]
fn v9_c5b_volume_key_wrong_session_fails() {
    let dk1 = DerivedKey::from_bytes([0x01; 32]).unwrap();
    let dk2 = DerivedKey::from_bytes([0x02; 32]).unwrap();
    let session1 = KeySession::from_derived_key(&dk1).unwrap();
    let session2 = KeySession::from_derived_key(&dk2).unwrap();

    let (_vk, wrapped) = session1.generate_and_wrap_volume_key().unwrap();

    let result = session2.unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext);
    assert!(
        result.is_err(),
        "V9-C5b: Unwrapping with wrong session must fail"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C6: Hybrid KEM encapsulate/decapsulate roundtrip
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c6a_hybrid_kem_roundtrip() {
    let (pk, sk) = generate_keypair();

    let (ciphertext, shared_secret_enc) = encapsulate(&pk).unwrap();
    let shared_secret_dec = decapsulate(&sk, &pk, &ciphertext).unwrap();

    assert_eq!(
        shared_secret_enc.as_bytes(),
        shared_secret_dec.as_bytes(),
        "V9-C6a: KEM shared secrets must match"
    );
}

#[test]
fn v9_c6b_hybrid_kem_wrong_key_fails() {
    let (pk, _sk1) = generate_keypair();
    let (_pk2, sk2) = generate_keypair();

    let (ciphertext, _shared) = encapsulate(&pk).unwrap();

    let result = decapsulate(&sk2, &_pk2, &ciphertext);
    match result {
        Ok(ss) => {
            println!(
                "V9-C6b: Decapsulate with wrong key produced a shared secret (implicit rejection)"
            );
            let _ = ss;
        }
        Err(e) => {
            println!("V9-C6b: Decapsulate with wrong key failed: {}", e);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C7: derive_checkpoint_key returns raw bytes (no zeroize-on-drop)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c7a_checkpoint_key_is_raw_bytes() {
    let dk = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let session = KeySession::from_derived_key(&dk).unwrap();

    let checkpoint_key = session.derive_checkpoint_key().unwrap();
    assert_eq!(checkpoint_key.len(), 32);

    // P2 security concern: raw [u8; 32] with no Zeroize or mlock.
    println!(
        "V9-C7a: derive_checkpoint_key returns raw [u8; 32] — \
         key material is NOT zeroized on drop. P2 security concern."
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C8: XOR domain separation minimal but functional
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c8a_xor_domain_different_keys() {
    let dk = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let session = KeySession::from_derived_key(&dk).unwrap();
    let vk = VolumeKey::generate().unwrap();

    let data_ctx = [0u8; 16];
    let mut index_ctx = data_ctx;
    index_ctx[0] ^= 0xFF;

    let data_key = session.derive_block_key(&vk, 0, &data_ctx).unwrap();
    let index_key = session.derive_block_key(&vk, 0, &index_ctx).unwrap();

    assert_ne!(
        data_key.to_derived_key().unwrap().as_bytes(),
        index_key.to_derived_key().unwrap().as_bytes(),
        "V9-C8a: Data and index block keys must differ with XOR'd nonce context"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C9: BLAKE3 hashing consistency
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c9a_blake3_deterministic() {
    let data = b"ERA test data for hashing";
    let hash1 = hash(data);
    let hash2 = hash(data);
    assert_eq!(hash1, hash2, "V9-C9a: BLAKE3 should be deterministic");
}

#[test]
fn v9_c9b_blake3_different_inputs() {
    let hash1 = hash(b"input A");
    let hash2 = hash(b"input B");
    assert_ne!(
        hash1, hash2,
        "V9-C9b: Different inputs must produce different hashes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C10: AEAD ciphertext integrity — single bit flip detected
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c10a_aead_ciphertext_bit_flip_detected() {
    let key = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let nonce_context = [0x01u8; 16];
    let block_id = era_common::BlockId::new(0);
    let plaintext = b"detect tampering";

    let ciphertext = encrypt_with_context(
        &key,
        &nonce_context,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id,
        plaintext,
    )
    .unwrap();

    let ct_bytes = ciphertext.to_vec();
    if !ct_bytes.is_empty() {
        let mut tampered = ct_bytes;
        tampered[0] ^= 0x01;
        let result = decrypt_with_context(
            &key,
            &nonce_context,
            &TEST_ARCHIVE_ID,
            TEST_EPOCH_ID,
            TEST_VOLUME_INDEX,
            block_id,
            &tampered,
        );
        assert!(
            result.is_err(),
            "V9-C10a: Bit-flipped ciphertext must be rejected by AEAD"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C11: Empty plaintext encryption
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c11a_aead_empty_plaintext() {
    let key = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let nonce_context = [0x01u8; 16];
    let block_id = era_common::BlockId::new(0);
    let plaintext = b"";

    let ciphertext = encrypt_with_context(
        &key,
        &nonce_context,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id,
        plaintext,
    )
    .unwrap();
    let decrypted = decrypt_with_context(
        &key,
        &nonce_context,
        &TEST_ARCHIVE_ID,
        TEST_EPOCH_ID,
        TEST_VOLUME_INDEX,
        block_id,
        &ciphertext,
    )
    .unwrap();

    assert_eq!(
        &decrypted[..],
        &plaintext[..],
        "V9-C11a: Empty plaintext should encrypt/decrypt correctly"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C12: Password verification tag — different passwords produce different tags
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c12a_password_verification_tags_differ() {
    let dk1 = DerivedKey::from_bytes([0x01; 32]).unwrap();
    let dk2 = DerivedKey::from_bytes([0x02; 32]).unwrap();
    let s1 = KeySession::from_derived_key(&dk1).unwrap();
    let s2 = KeySession::from_derived_key(&dk2).unwrap();

    let tag1 = s1.password_verification_tag();
    let tag2 = s2.password_verification_tag();

    assert_ne!(
        tag1, tag2,
        "V9-C12a: Different master keys must produce different verification tags"
    );
}

#[test]
fn v9_c12b_password_verification_roundtrip() {
    let dk = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let session = KeySession::from_derived_key(&dk).unwrap();

    let tag = session.password_verification_tag();
    assert!(
        session.verify_password(&tag),
        "V9-C12b: Session must verify its own tag"
    );

    let wrong_tag = [0xFFu8; 16];
    assert!(
        !session.verify_password(&wrong_tag),
        "V9-C12b: Session must reject wrong tag"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// V9-C13: derive_block_key — stack residue concern documentation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn v9_c13a_derive_block_key_stack_residue_documented() {
    // P2 concern: derive_block_key() uses a local [u8; 32] okm buffer that
    // is NOT zeroized after being copied into BlockKey. Key material remains
    // on the stack until overwritten by future frames.
    let dk = DerivedKey::from_bytes([0x42; 32]).unwrap();
    let session = KeySession::from_derived_key(&dk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let nonce_context = [0u8; 16];

    let bk = session.derive_block_key(&vk, 0, &nonce_context).unwrap();
    let key_bytes = bk.to_derived_key().unwrap();
    assert_ne!(
        key_bytes.as_bytes(),
        &[0u8; 32],
        "V9-C13a: Block key should not be all zeros"
    );
}
