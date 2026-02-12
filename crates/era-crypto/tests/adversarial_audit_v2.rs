//! Adversarial Audit V2 — era-crypto
//!
//! Targets:
//! - FINDING-CRYPTO-1: Deterministic nonce derivation — same (key, context, block_id) = same nonce
//!   This is BY DESIGN for convergent encryption, but means nonce reuse if same block_id
//!   is ever encrypted twice with different plaintext under the same key+context.
//! - FINDING-CRYPTO-2: AeadKey::from_bytes accepts any 32 bytes — no key validation
//! - FINDING-CRYPTO-3: Nonce::zero() exists — encrypting with zero nonce is dangerous

use era_common::BlockId;
use era_crypto::{AeadCipher, AeadKey, Nonce};

/// FINDING-CRYPTO-1: Deterministic encryption — same inputs = same ciphertext.
/// This is the convergent encryption property. Verify it holds AND that
/// different block_ids produce different ciphertext (nonce diversity).
#[test]
fn test_deterministic_nonce_same_block_id_same_ciphertext() {
    let key = AeadKey::from_bytes(&[0x42; 32]).unwrap();
    let nonce = Nonce::from_bytes(&[0x01; 24]).unwrap();
    let cipher = AeadCipher::new();
    let plaintext = b"test data";
    let aad = b"context";

    let ct1 = cipher.encrypt(&key, &nonce, aad, plaintext).unwrap();
    let ct2 = cipher.encrypt(&key, &nonce, aad, plaintext).unwrap();
    assert_eq!(ct1, ct2, "Same inputs must produce same ciphertext");
}

/// FINDING-CRYPTO-1b: Different plaintext with same nonce+key = catastrophic.
/// XChaCha20-Poly1305 with nonce reuse leaks XOR of plaintexts.
/// This test documents the risk — it's not a bug per se, but the system
/// MUST guarantee block_id uniqueness per volume.
#[test]
fn test_nonce_reuse_different_plaintext_produces_different_ciphertext() {
    let key = AeadKey::from_bytes(&[0x42; 32]).unwrap();
    let nonce = Nonce::from_bytes(&[0x01; 24]).unwrap();
    let cipher = AeadCipher::new();

    let ct1 = cipher.encrypt(&key, &nonce, b"aad", b"plaintext A").unwrap();
    let ct2 = cipher.encrypt(&key, &nonce, b"aad", b"plaintext B").unwrap();

    // Both encrypt successfully — the cipher doesn't prevent nonce reuse.
    // The ciphertexts differ, but XOR(ct1, ct2) = XOR(pt1, pt2) — information leak.
    assert_ne!(ct1, ct2);
    // This is a documentation test: the system relies on block_id monotonicity
    // to prevent this scenario. If block_id is ever reused, security is broken.
}

/// FINDING-CRYPTO-3: Nonce::zero() — verify encryption with zero nonce works
/// but is distinguishable (no randomness).
#[test]
fn test_zero_nonce_encryption_works_but_is_deterministic() {
    let key = AeadKey::from_bytes(&[0x42; 32]).unwrap();
    let zero_nonce = Nonce::zero();
    let cipher = AeadCipher::new();

    let ct1 = cipher.encrypt(&key, &zero_nonce, b"", b"data").unwrap();
    let ct2 = cipher.encrypt(&key, &zero_nonce, b"", b"data").unwrap();
    assert_eq!(ct1, ct2, "Zero nonce is deterministic — no randomness");

    // Verify decryption works
    let pt = cipher.decrypt(&key, &zero_nonce, b"", &ct1).unwrap();
    assert_eq!(pt, b"data");
}

/// FINDING-CRYPTO-4: Cross-key decryption must fail with AEAD error.
#[test]
fn test_cross_key_decryption_fails() {
    let key1 = AeadKey::from_bytes(&[0x01; 32]).unwrap();
    let key2 = AeadKey::from_bytes(&[0x02; 32]).unwrap();
    let nonce = Nonce::generate();
    let cipher = AeadCipher::new();

    let ct = cipher.encrypt(&key1, &nonce, b"", b"secret").unwrap();
    let result = cipher.decrypt(&key2, &nonce, b"", &ct);
    assert!(result.is_err(), "Cross-key decryption must fail");
}

/// FINDING-CRYPTO-5: AAD mismatch must fail decryption.
#[test]
fn test_aad_mismatch_fails() {
    let key = AeadKey::from_bytes(&[0x42; 32]).unwrap();
    let nonce = Nonce::generate();
    let cipher = AeadCipher::new();

    let ct = cipher.encrypt(&key, &nonce, b"correct_aad", b"data").unwrap();
    let result = cipher.decrypt(&key, &nonce, b"wrong_aad", &ct);
    assert!(result.is_err(), "AAD mismatch must fail AEAD verification");
}

/// FINDING-CRYPTO-6: Empty ciphertext decryption must fail (no tag).
#[test]
fn test_empty_ciphertext_decryption_fails() {
    let key = AeadKey::from_bytes(&[0x42; 32]).unwrap();
    let nonce = Nonce::generate();
    let cipher = AeadCipher::new();

    let result = cipher.decrypt(&key, &nonce, b"", &[]);
    assert!(result.is_err(), "Empty ciphertext (no Poly1305 tag) must fail");
}

/// FINDING-CRYPTO-7: Bit-flip in ciphertext must fail authentication.
#[test]
fn test_single_bit_flip_detected() {
    let key = AeadKey::from_bytes(&[0x42; 32]).unwrap();
    let nonce = Nonce::generate();
    let cipher = AeadCipher::new();

    let ct = cipher.encrypt(&key, &nonce, b"", b"important data here").unwrap();

    // Flip every single bit position in the ciphertext
    for byte_idx in 0..ct.len() {
        for bit in 0..8 {
            let mut tampered = ct.clone();
            tampered[byte_idx] ^= 1 << bit;
            let result = cipher.decrypt(&key, &nonce, b"", &tampered);
            assert!(
                result.is_err(),
                "Bit flip at byte {} bit {} must be detected",
                byte_idx,
                bit
            );
        }
    }
}

/// FINDING-CRYPTO-8: context-based nonce derivation produces unique nonces
/// for different block IDs. Verified indirectly: same key+context but different
/// block_ids must produce different ciphertext (proving nonce diversity).
#[test]
fn test_context_nonce_derivation_uniqueness() {
    use era_crypto::{encrypt_with_context, derive_key, KdfParams, Salt};

    let key = derive_key(
        b"test",
        &Salt::from_bytes([0x42; 16]),
        &KdfParams { memory_cost: 1024, time_cost: 1, parallelism: 1 },
    ).unwrap();
    let context = [0x42u8; 16];
    let plaintext = b"fixed plaintext";

    let mut seen = std::collections::HashSet::new();
    for i in 0..1_000u64 {
        let ct = encrypt_with_context(&key, &context, BlockId::new(i), plaintext).unwrap();
        assert!(
            seen.insert(ct.to_vec()),
            "Ciphertext collision at block_id {} implies nonce reuse",
            i
        );
    }
}
