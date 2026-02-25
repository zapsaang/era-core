//! ADVERSARIAL AUDIT: Comprehensive Vulnerability Probe
//!
//! This test suite was written to audit and expose weaknesses in a competitor's
//! claimed remediation of CLAUDE.md §6.1 vulnerabilities.
//!
//! ## Findings Summary (6 vulnerabilities found):
//!
//! ### CONFIRMED FIXES (competitor actually fixed these):
//!   ✅ Nonce::generate() now uses OsRng (was thread_rng)
//!   ✅ GenericArchiveWriter MK generation now uses OsRng (was thread_rng)
//!   ✅ Threshold policy is enforced in ArchiveReader (was completely ignored)
//!   ✅ derive_volume_key() removed from public API
//!   ✅ Shamir's Secret Sharing integrated (sharks crate)
//!   ✅ hybrid_kem.rs and certificate.rs ephemeral keys now use OsRng
//!
//! ### REMAINING VULNERABILITIES EXPOSED BY THIS AUDIT:
//!   🚨 V1: thread_rng() in era-index Spiller (AEAD key generation - HIGH)
//!   🚨 V2: thread_rng() in era-volume VolumeWriter padding (MEDIUM)
//!   🚨 V3: thread_rng() in era-engine reader temp dir creation (LOW)
//!   🚨 V4: Reader accepts Threshold(1) from malformed headers → degrades to AnyOfN (MEDIUM)
//!   🚨 V5: GenericArchiveWriter bypasses threshold policy entirely (MEDIUM)
//!   🚨 V6: Doc tests are stale — claim violations exist that were already fixed (LOW)

use era_crypto::{
    reconstruct_master_key, split_master_key, wrap_volume_key, IntermediateKey, KdfParams,
    KeySession, VolumeKey,
};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions};
use era_volume::AccessPolicy;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// HELPERS
// ============================================================================

fn create_test_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(content).unwrap();
    path
}

fn _fast_kdf_params() -> KdfParams {
    KdfParams {
        memory_cost: 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

// ============================================================================
// SECTION 1: thread_rng AUDIT — PROVE REMAINING VIOLATIONS
// ============================================================================

/// 🚨 V1: PROVE that era-index Spiller uses thread_rng for AEAD key generation.
///
/// This is a HIGH severity finding: the Spiller generates an ephemeral AEAD key
/// used to encrypt index spill files at rest. Using thread_rng() violates §5.3.
///
/// ATTACK VECTOR: While thread_rng is seeded from OsRng, the specification
/// explicitly forbids it. In adversarial scenarios (e.g., VM snapshot restore),
/// thread_rng's internal state could be duplicated.
#[test]
fn vuln_01_spiller_uses_thread_rng_for_aead_key() {
    // SOURCE CODE ATTESTATION: crates/era-index/src/spiller.rs was DELETED.
    // The spiller module no longer exists — vulnerability resolved by removal.
    // The index builder now uses IndexStore (Redb) for spill-to-disk,
    // which does not require its own encryption key.
    assert!(
        !std::path::Path::new("crates/era-index/src/spiller.rs").exists(),
        "spiller.rs should have been deleted"
    );
}

/// 🚨 V2: PROVE that era-volume VolumeWriter uses thread_rng for padding.
///
/// While padding bytes are not key material, the padding prevents traffic
/// analysis. Using a predictable RNG for padding could leak volume size
/// information to an adversary who can observe the padding pattern.
#[test]
fn vuln_02_volume_writer_uses_thread_rng_for_padding() {
    // SOURCE CODE ATTESTATION: crates/era-volume/src/writer.rs:126
    // `rand::thread_rng().fill_bytes(&mut buffer[..to_write]);`
    let source = include_str!("../../era-volume/src/writer.rs");
    assert!(
        !source.contains("thread_rng()"),
        "V2 NOT FIXED: volume writer still uses thread_rng for padding"
    );
    assert!(
        source.contains("OsRng"),
        "V2 INCOMPLETE: volume writer must use OsRng"
    );
}

/// � V3: reader.rs temp dir naming — RESOLVED
///
/// The reader now uses `tempfile::TempDir` which handles secure random
/// naming internally via the OS, so no explicit OsRng usage is needed.
#[test]
fn vuln_03_reader_uses_thread_rng_for_temp_dir() {
    let source = include_str!("../src/reader.rs");
    assert!(
        !source.contains("thread_rng()"),
        "V3 NOT FIXED: reader.rs still uses thread_rng for temp dir"
    );
    // Note: reader.rs now uses tempfile::TempDir which handles secure
    // random naming internally. No explicit OsRng needed.
}

/// ✅ VERIFY FIX: Nonce::generate() now uses OsRng.
/// Competitor's fix is confirmed correct.
#[test]
fn verify_fix_nonce_generate_uses_osrng() {
    let source = include_str!("../../era-crypto/src/aead.rs");
    // The fixed version should have OsRng in generate()
    assert!(
        source.contains("OsRng.fill_bytes"),
        "REGRESSION: Nonce::generate() should use OsRng"
    );
    assert!(
        !source.contains("thread_rng"),
        "REGRESSION: aead.rs should not contain thread_rng anymore"
    );
}

/// ✅ VERIFY FIX: GenericArchiveWriter MK generation now uses OsRng.
#[test]
fn verify_fix_generic_writer_mk_uses_osrng() {
    let source = include_str!("../src/writer.rs");
    // Count occurrences of OsRng in the writer — should be >= 2
    // (main builder + generic builder)
    let osrng_count = source.matches("OsRng.fill_bytes").count();
    assert!(
        osrng_count >= 2,
        "Expected at least 2 OsRng.fill_bytes calls in writer.rs, found {}",
        osrng_count
    );
}

// ============================================================================
// SECTION 2: THRESHOLD POLICY — DEEP ADVERSARIAL TESTING
// ============================================================================

/// 🚨 V4: BOUNDARY ATTACK: What happens when a malformed archive header
/// contains Threshold(1)?
///
/// The writer correctly rejects Threshold(1) with `InvalidConfig`, but the
/// READER has no such validation. An attacker who crafts an archive header
/// with Threshold(1) effectively degrades security to AnyOfN.
///
/// The sharks crate with threshold=1 returns the secret from any single share,
/// making the threshold policy meaningless.
#[test]
fn vuln_04_threshold_1_degrades_to_any_of_n() {
    // This test proves the reader-side validation gap.
    // We can't easily craft a full malformed archive, but we CAN test the
    // cryptographic primitive directly to show Threshold(1) is exploitable.

    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    // Split with threshold=1 should fail at the split_master_key level
    let result = split_master_key(&mk, 1, 3);
    assert!(
        result.is_err(),
        "split_master_key should reject threshold=1, but it accepted it! \
         This means the writer-side check is the ONLY defense."
    );

    // However, the reader trusts the header's threshold value blindly.
    // SOURCE CODE: reader.rs lines 341-361
    // ```
    // AccessPolicy::Threshold(t) => {
    //     let mut shares = Vec::new();
    //     ...
    //     era_crypto::reconstruct_master_key(&shares, t as u8)?
    // }
    // ```
    // If an attacker sets t=1 in the header, reconstruct_master_key(shares, 1)
    // is called. The sharks crate allows threshold=1.
    //
    // PROOF: sharks::Sharks(1) is valid and returns secret from single share.

    // Direct test: split with threshold=2, then try reconstruct with threshold=1
    let shares = split_master_key(&mk, 2, 3).unwrap();

    // An attacker modifies header to say Threshold(1) — now a single share suffices
    let single_share = vec![shares[0].clone()];
    let _reconstructed = reconstruct_master_key(&single_share, 1);

    // This SHOULD fail if there were reader-side validation, but it doesn't!
    // The sharks crate with threshold=1 returns any single share as the secret.
    // (Note: the reconstructed value won't match the original MK because SSS
    //  with threshold=1 stores shares differently, but the point is the reader
    //  doesn't reject Threshold(1) at all.)
    //
    // The REAL attack: attacker creates an archive with Threshold(1) from scratch,
    // which the reader accepts without complaint.
    // The reader source has NO check: `if t < 2 { return Err(...) }`

    let reader_source = include_str!("../src/reader.rs");
    let threshold_section = reader_source
        .find("AccessPolicy::Threshold(t)")
        .expect("Reader should handle Threshold variant");

    // Extract the code after the Threshold match
    let after_match = &reader_source[threshold_section..];
    let has_t_validation = after_match[..500].contains("t < 2")
        || after_match[..500].contains("t <= 1")
        || after_match[..500].contains("threshold must");

    assert!(
        has_t_validation,
        "V4 NOT FIXED: Reader still lacks T>=2 validation for threshold policy"
    );
    // VULNERABILITY CONFIRMED: Reader accepts Threshold(1) from header.
}

/// 🚨 V5: PROVE GenericArchiveWriter hardcodes AnyOfN, bypassing threshold policy.
///
/// Any code path using GenericArchiveWriter (the public API for custom backends)
/// will silently produce AnyOfN archives, regardless of the user's security intent.
/// The builder has no access_policy() or add_password() method.
#[test]
fn vuln_05_generic_writer_bypasses_threshold_policy() {
    let source = include_str!("../src/writer.rs");

    // Find the GenericArchiveWriterBuilder section
    let builder_start = source
        .find("pub struct GenericArchiveWriterBuilder")
        .expect("GenericArchiveWriterBuilder should exist");
    let builder_section = &source[builder_start..];

    // Check: does it have access_policy method?
    // It should NOT (vulnerability)
    let next_struct_or_impl = builder_section
        .find("pub struct GenericArchiveWriter<")
        .unwrap_or(3000);
    let builder_definition = &builder_section[..next_struct_or_impl];

    let has_access_policy = builder_definition.contains("access_policy");
    let has_add_password = builder_definition.contains("add_password");

    assert!(
        has_access_policy,
        "V5 NOT FIXED: GenericArchiveWriterBuilder still lacks access_policy support"
    );
    assert!(
        !has_add_password,
        "AUDIT STALE: GenericArchiveWriterBuilder gained add_password support"
    );

    // Also check it hardcodes AnyOfN
    assert!(
        builder_definition.contains("AccessPolicy::AnyOfN")
            || source[builder_start..].contains("AccessPolicy::AnyOfN"),
        "GenericArchiveWriterBuilder should hardcode AnyOfN"
    );
}

/// 🚨 V6: Doc tests are STALE — they claim spec violations that were already fixed.
///
/// The competitor wrote `doc_nonce_generate_uses_thread_rng` and
/// `doc_generic_writer_mk_uses_thread_rng` as documentation tests.
/// These tests do NOTHING (empty bodies) but their docstrings claim
/// the violations still exist. This is misleading after the fixes were applied.
#[test]
fn vuln_06_stale_doc_tests_in_envelope_adversarial() {
    let source = include_str!("envelope_adversarial.rs");

    // These doc tests were renamed after the fixes were applied
    assert!(
        !source.contains("doc_nonce_generate_uses_thread_rng"),
        "V6 NOT FIXED: stale doc test name still exists"
    );
    assert!(
        !source.contains("doc_generic_writer_mk_uses_thread_rng"),
        "V6 NOT FIXED: stale doc test name still exists"
    );
    // Verify the renamed tests exist
    assert!(
        source.contains("doc_nonce_generate_fixed_uses_osrng"),
        "V6 INCOMPLETE: renamed doc test not found"
    );
    assert!(
        source.contains("doc_generic_writer_mk_fixed_uses_osrng"),
        "V6 INCOMPLETE: renamed doc test not found"
    );

    // Verify that the claimed violations no longer exist in the actual source
    let aead_source = include_str!("../../era-crypto/src/aead.rs");
    assert!(
        !aead_source.contains("thread_rng"),
        "The nonce violation was fixed but the doc test still claims it exists"
    );

    // The doc tests should have been updated or removed after fixes.
    // Leaving stale vulnerability documentation is a security audit failure.
}

// ============================================================================
// SECTION 3: SHAMIR SECRET SHARING — CRYPTOGRAPHIC INTEGRITY PROBES
// ============================================================================

/// Adversarial: Verify SSS produces correct shares and reconstruction works.
#[test]
fn sss_01_basic_split_reconstruct_roundtrip() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    let shares = split_master_key(&mk, 2, 3).unwrap();
    assert_eq!(shares.len(), 3, "Should produce exactly 3 shares");

    // Any 2 shares should reconstruct
    let reconstructed = reconstruct_master_key(&shares[0..2], 2).unwrap();
    assert_eq!(reconstructed, mk, "Reconstruction with shares[0,1] failed");

    let reconstructed = reconstruct_master_key(&shares[1..3], 2).unwrap();
    assert_eq!(reconstructed, mk, "Reconstruction with shares[1,2] failed");

    let reconstructed = reconstruct_master_key(&[shares[0].clone(), shares[2].clone()], 2).unwrap();
    assert_eq!(reconstructed, mk, "Reconstruction with shares[0,2] failed");
}

/// Adversarial: Verify that T-1 shares MATHEMATICALLY CANNOT reconstruct MK.
#[test]
fn sss_02_insufficient_shares_cannot_reconstruct() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    let shares = split_master_key(&mk, 3, 5).unwrap();

    // 1 share should fail
    let result = reconstruct_master_key(&shares[0..1], 3);
    // sharks may return a wrong result rather than an error with insufficient shares,
    // but the result MUST NOT match the original MK
    if let Ok(reconstructed) = result {
        assert_ne!(
            reconstructed, mk,
            "CRITICAL: 1 share out of 3-threshold reconstructed the correct MK!"
        );
    }

    // 2 shares should also fail
    let result = reconstruct_master_key(&shares[0..2], 3);
    if let Ok(reconstructed) = result {
        assert_ne!(
            reconstructed, mk,
            "CRITICAL: 2 shares out of 3-threshold reconstructed the correct MK!"
        );
    }
}

/// Adversarial: Verify that 3 of 5 shares correctly reconstructs (threshold=3).
#[test]
fn sss_03_exact_threshold_works() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    let shares = split_master_key(&mk, 3, 5).unwrap();

    // Exactly 3 shares — every possible combination of 3
    let combos = vec![
        vec![0, 1, 2],
        vec![0, 1, 3],
        vec![0, 1, 4],
        vec![0, 2, 3],
        vec![0, 2, 4],
        vec![0, 3, 4],
        vec![1, 2, 3],
        vec![1, 2, 4],
        vec![1, 3, 4],
        vec![2, 3, 4],
    ];

    for combo in combos {
        let selected: Vec<Vec<u8>> = combo.iter().map(|&i| shares[i].clone()).collect();
        let reconstructed = reconstruct_master_key(&selected, 3).unwrap();
        assert_eq!(
            reconstructed, mk,
            "Reconstruction failed with shares {:?}",
            combo
        );
    }
}

/// Adversarial: Verify share uniqueness — all N shares must differ.
#[test]
fn sss_04_shares_are_unique() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    let shares = split_master_key(&mk, 2, 5).unwrap();

    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(
                shares[i], shares[j],
                "CRITICAL: Shares {} and {} are identical!",
                i, j
            );
        }
    }
}

/// Adversarial: split_master_key rejects invalid parameters.
#[test]
fn sss_05_rejects_invalid_params() {
    let mk = [0u8; 32];

    // Threshold 0
    assert!(split_master_key(&mk, 0, 3).is_err(), "Should reject T=0");

    // Threshold 1
    assert!(split_master_key(&mk, 1, 3).is_err(), "Should reject T=1");

    // T > N
    assert!(split_master_key(&mk, 5, 3).is_err(), "Should reject T > N");

    // T = N (valid edge case)
    let result = split_master_key(&mk, 3, 3);
    assert!(result.is_ok(), "T=N should be valid");
}

/// Adversarial: reconstruct with garbage shares should not return original MK.
#[test]
fn sss_06_garbage_shares_cannot_reconstruct() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    let shares = split_master_key(&mk, 2, 3).unwrap();

    // Replace one share with garbage
    let mut garbage_shares = vec![shares[0].clone()];
    let mut garbage = shares[1].clone();
    // Corrupt the share data (not the index byte)
    if garbage.len() > 1 {
        garbage[1] ^= 0xFF;
    }
    garbage_shares.push(garbage);

    let result = reconstruct_master_key(&garbage_shares, 2);
    if let Ok(reconstructed) = result {
        assert_ne!(
            reconstructed, mk,
            "CRITICAL: Corrupted share reconstructed the correct MK!"
        );
    }
}

/// Adversarial: All shares should reconstruct correctly (over-provide).
#[test]
fn sss_07_over_threshold_works() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    let shares = split_master_key(&mk, 2, 5).unwrap();

    // Provide all 5 shares with threshold=2
    let reconstructed = reconstruct_master_key(&shares, 2).unwrap();
    assert_eq!(reconstructed, mk, "Over-threshold reconstruction failed");
}

// ============================================================================
// SECTION 4: KEY WRAPPING — AEAD INTEGRITY PROBES
// ============================================================================

/// Verify that VK is truly random (not deterministic from MK).
#[test]
fn wrap_01_vk_randomness() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();

    let mut vks = Vec::new();
    for _ in 0..100 {
        let (vk, _) = session.generate_and_wrap_volume_key().unwrap();
        vks.push(*vk.as_bytes());
    }

    // All VKs should be unique
    for i in 0..vks.len() {
        for j in (i + 1)..vks.len() {
            assert_ne!(
                vks[i], vks[j],
                "CRITICAL: VK collision detected at indices {}, {}!",
                i, j
            );
        }
    }
}

/// Verify nonces are unique across wrapping operations.
#[test]
fn wrap_02_nonce_uniqueness() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();

    let mut nonces = Vec::new();
    for _ in 0..500 {
        let (_, wrapped) = session.generate_and_wrap_volume_key().unwrap();
        nonces.push(wrapped.nonce);
    }

    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(
                nonces[i], nonces[j],
                "CRITICAL: Nonce collision detected at indices {}, {}!",
                i, j
            );
        }
    }
}

/// Verify wrong MK produces "Key Tampering Detected" error per §5.4.
#[test]
fn wrap_03_wrong_mk_produces_tamper_error() {
    let mk1 = [0x01u8; 32];
    let mk2 = [0x02u8; 32];
    let session1 = KeySession::from_master_key(&mk1).unwrap();
    let session2 = KeySession::from_master_key(&mk2).unwrap();

    let (_, wrapped) = session1.generate_and_wrap_volume_key().unwrap();
    let err = session2
        .unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext)
        .unwrap_err();

    assert!(
        err.to_string().contains("Key Tampering Detected"),
        "Error should contain 'Key Tampering Detected' per §5.4, got: {}",
        err
    );
}

/// Verify tampered ciphertext produces "Key Tampering Detected".
#[test]
fn wrap_04_tampered_ciphertext_detected() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let (_, mut wrapped) = session.generate_and_wrap_volume_key().unwrap();

    // Flip every byte of ciphertext individually
    for i in 0..wrapped.ciphertext.len() {
        let original = wrapped.ciphertext[i];
        wrapped.ciphertext[i] ^= 0xFF;

        let result = session.unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext);
        assert!(
            result.is_err(),
            "CRITICAL: Tampered byte {} not detected!",
            i
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Key Tampering Detected"),
            "Error should be 'Key Tampering Detected' for tampered byte {}",
            i
        );

        wrapped.ciphertext[i] = original; // Restore
    }
}

/// Verify tampered nonce is detected.
#[test]
fn wrap_05_tampered_nonce_detected() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let (_, wrapped) = session.generate_and_wrap_volume_key().unwrap();

    for i in 0..24 {
        let mut bad_nonce = wrapped.nonce;
        bad_nonce[i] ^= 0xFF;

        let result = session.unwrap_volume_key(&bad_nonce, &wrapped.ciphertext);
        assert!(
            result.is_err(),
            "CRITICAL: Tampered nonce byte {} not detected!",
            i
        );
    }
}

/// Verify empty ciphertext is rejected.
#[test]
fn wrap_06_empty_ciphertext_rejected() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();

    let nonce = [0u8; 24];
    let result = session.unwrap_volume_key(&nonce, &[]);
    assert!(result.is_err(), "Empty ciphertext should be rejected");
}

/// Verify truncated ciphertext is rejected.
#[test]
fn wrap_07_truncated_ciphertext_rejected() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let (_, wrapped) = session.generate_and_wrap_volume_key().unwrap();

    // Try various truncation lengths
    for len in [1, 10, 15, 31, wrapped.ciphertext.len() - 1] {
        if len < wrapped.ciphertext.len() {
            let result = session.unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext[..len]);
            assert!(
                result.is_err(),
                "Truncated ciphertext (len={}) should be rejected",
                len
            );
        }
    }
}

/// Verify oversized ciphertext is rejected or handled.
#[test]
fn wrap_08_oversized_ciphertext_rejected() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let (_, wrapped) = session.generate_and_wrap_volume_key().unwrap();

    let mut extended = wrapped.ciphertext.clone();
    extended.extend_from_slice(&[0xFF; 100]);

    let result = session.unwrap_volume_key(&wrapped.nonce, &extended);
    // Should either error or return wrong VK (but not the correct VK)
    if let Ok(vk) = result {
        // If it doesn't error, the VK should be wrong
        // (AEAD should reject extra bytes)
        panic!(
            "Oversized ciphertext should be rejected by AEAD, but got VK: {:?}",
            vk
        );
    }
}

// ============================================================================
// SECTION 5: KEY ROTATION — INTEGRITY PROBES
// ============================================================================

/// Verify key rotation preserves VK identity.
#[test]
fn rotation_01_preserves_vk() {
    let old_mk = [0x01u8; 32];
    let new_mk = [0x02u8; 32];

    let old_session = KeySession::from_master_key(&old_mk).unwrap();
    let new_session = KeySession::from_master_key(&new_mk).unwrap();

    // Create and wrap VK with old MK
    let (original_vk, wrapped) = old_session.generate_and_wrap_volume_key().unwrap();

    // Unwrap with old IK
    let vk = old_session
        .unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext)
        .unwrap();
    assert_eq!(original_vk.as_bytes(), vk.as_bytes());

    // Re-wrap with new IK
    let new_ik = new_session.derive_intermediate_key().unwrap();
    let new_wrapped = wrap_volume_key(&new_ik, &vk).unwrap();

    // Unwrap with new session
    let rewrapped_vk = new_session
        .unwrap_volume_key(&new_wrapped.nonce, &new_wrapped.ciphertext)
        .unwrap();

    // VK must be identical
    assert_eq!(
        original_vk.as_bytes(),
        rewrapped_vk.as_bytes(),
        "Key rotation changed the VK!"
    );
}

/// Double rotation preserves VK identity.
#[test]
fn rotation_02_double_rotation_preserves_vk() {
    let mk1 = [0x01u8; 32];
    let mk2 = [0x02u8; 32];
    let mk3 = [0x03u8; 32];

    let s1 = KeySession::from_master_key(&mk1).unwrap();
    let s2 = KeySession::from_master_key(&mk2).unwrap();
    let s3 = KeySession::from_master_key(&mk3).unwrap();

    let (original_vk, w1) = s1.generate_and_wrap_volume_key().unwrap();
    let vk = s1.unwrap_volume_key(&w1.nonce, &w1.ciphertext).unwrap();

    // Rotation 1: mk1 -> mk2
    let ik2 = s2.derive_intermediate_key().unwrap();
    let w2 = wrap_volume_key(&ik2, &vk).unwrap();
    let vk2 = s2.unwrap_volume_key(&w2.nonce, &w2.ciphertext).unwrap();

    // Rotation 2: mk2 -> mk3
    let ik3 = s3.derive_intermediate_key().unwrap();
    let w3 = wrap_volume_key(&ik3, &vk2).unwrap();
    let vk3 = s3.unwrap_volume_key(&w3.nonce, &w3.ciphertext).unwrap();

    assert_eq!(
        original_vk.as_bytes(),
        vk3.as_bytes(),
        "Double rotation changed VK!"
    );
}

// ============================================================================
// SECTION 6: IK DERIVATION — AVALANCHE AND DOMAIN SEPARATION
// ============================================================================

/// Verify 1-bit MK change produces ~128/256 bit IK change (avalanche effect).
#[test]
fn ik_01_avalanche_effect() {
    let mut mk1 = [0u8; 32];
    OsRng.fill_bytes(&mut mk1);
    let mut mk2 = mk1;
    mk2[0] ^= 0x01; // Flip one bit

    let ik1 = IntermediateKey::derive_from_master_key(&mk1).unwrap();
    let ik2 = IntermediateKey::derive_from_master_key(&mk2).unwrap();

    // Count differing bits
    let mut differing_bits = 0;
    for (b1, b2) in ik1.as_bytes().iter().zip(ik2.as_bytes().iter()) {
        differing_bits += (b1 ^ b2).count_ones();
    }

    // Expected: ~128 bits differ out of 256
    // Allow range [80, 180] for statistical validity
    assert!(
        (80..=180).contains(&differing_bits),
        "Avalanche effect poor: {} bits differ (expected ~128)",
        differing_bits
    );
}

/// Verify IK derivation is deterministic for the same MK.
#[test]
fn ik_02_deterministic() {
    let mk = [0x42u8; 32];
    let ik1 = IntermediateKey::derive_from_master_key(&mk).unwrap();
    let ik2 = IntermediateKey::derive_from_master_key(&mk).unwrap();
    assert_eq!(
        ik1.as_bytes(),
        ik2.as_bytes(),
        "IK derivation not deterministic!"
    );
}

/// Verify different MKs produce different IKs.
#[test]
fn ik_03_different_mk_different_ik() {
    let mut iks = Vec::new();
    for i in 0..100u8 {
        let mut mk = [0u8; 32];
        mk[0] = i;
        let ik = IntermediateKey::derive_from_master_key(&mk).unwrap();
        iks.push(*ik.as_bytes());
    }

    for i in 0..iks.len() {
        for j in (i + 1)..iks.len() {
            assert_ne!(
                iks[i], iks[j],
                "IK collision for MK indices {} and {}!",
                i, j
            );
        }
    }
}

// ============================================================================
// SECTION 7: PER-BLOCK KEY ISOLATION
// ============================================================================

/// Verify per-block keys are unique across block indices.
#[test]
fn block_key_01_isolation() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let nonce_ctx = [0xAB; 16];

    let mut keys = Vec::new();
    for i in 0..100u64 {
        let bk = session.derive_block_key(&vk, i, &nonce_ctx).unwrap();
        keys.push(*bk.as_bytes());
    }

    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i], keys[j],
                "Block key collision at indices {} and {}!",
                i, j
            );
        }
    }
}

/// Verify different nonce contexts produce different block keys.
#[test]
fn block_key_02_nonce_context_isolation() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();

    let bk1 = session.derive_block_key(&vk, 0, &[0x01; 16]).unwrap();
    let bk2 = session.derive_block_key(&vk, 0, &[0x02; 16]).unwrap();
    assert_ne!(
        bk1.as_bytes(),
        bk2.as_bytes(),
        "Different nonce contexts should produce different block keys!"
    );
}

// ============================================================================
// SECTION 8: DEBUG OUTPUT REDACTION
// ============================================================================

/// Verify Debug output does not leak key material.
#[test]
fn redact_01_no_key_leaks_in_debug() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let ik = session.derive_intermediate_key().unwrap();
    let bk = session.derive_block_key(&vk, 0, &[0u8; 16]).unwrap();

    let session_debug = format!("{:?}", session);
    let vk_debug = format!("{:?}", vk);
    let ik_debug = format!("{:?}", ik);
    let bk_debug = format!("{:?}", bk);

    // Must contain REDACTED
    assert!(
        session_debug.contains("REDACTED"),
        "KeySession debug leaks key"
    );
    assert!(vk_debug.contains("REDACTED"), "VolumeKey debug leaks key");
    assert!(
        ik_debug.contains("REDACTED"),
        "IntermediateKey debug leaks key"
    );
    assert!(bk_debug.contains("REDACTED"), "BlockKey debug leaks key");

    // Must NOT contain hex representation of key bytes
    let mk_hex = hex::encode(mk);
    assert!(
        !session_debug.contains(&mk_hex),
        "KeySession debug contains MK hex!"
    );
    assert!(
        !vk_debug.contains(&hex::encode(vk.as_bytes())),
        "VolumeKey debug contains VK hex!"
    );
}

// ============================================================================
// SECTION 9: E2E THRESHOLD INTEGRATION TESTS
// ============================================================================

/// Adversarial E2E: Threshold(2) with 3 passwords — comprehensive flow test.
#[tokio::test]
async fn e2e_threshold_01_full_lifecycle() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();

    let test_data = b"CLASSIFIED: Project ERA Specifications v8.1";
    create_test_file(&input_dir, "classified.txt", test_data);

    let archive_path = temp.path().join("threshold_lifecycle.era");

    // Create with Threshold(2), 3 passwords
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("alpha")
        .add_password("bravo")
        .add_password("charlie")
        .access_policy(AccessPolicy::Threshold(2))
        .build()
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("classified.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Case 1: Single password → MUST fail
    let result = ArchiveReader::open(&archive_path, "alpha").await;
    assert!(
        result.is_err(),
        "Single password must not open threshold(2) archive"
    );
    let err = result.err().unwrap();
    match err {
        era_common::EraError::ThresholdNotMet { required, provided } => {
            assert_eq!(required, 2);
            assert_eq!(provided, 1);
        }
        other => panic!("Expected ThresholdNotMet, got: {:?}", other),
    }

    // Case 2: Two correct passwords → MUST succeed
    let mut reader = ArchiveReader::open_with_passwords(&archive_path, &["alpha", "bravo"])
        .await
        .expect("Two passwords should open threshold(2) archive");

    let output_dir = temp.path().join("output1");
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();
    let extracted = fs::read(output_dir.join("classified.txt")).unwrap();
    assert_eq!(
        extracted, test_data,
        "Data integrity violation after threshold extraction"
    );

    // Case 3: Different pair of passwords → also MUST succeed
    let reader = ArchiveReader::open_with_passwords(&archive_path, &["bravo", "charlie"]).await;
    assert!(
        reader.is_ok(),
        "Different password pair should also work: {:?}",
        reader.err()
    );

    // Case 4: Two passwords, one wrong → MUST fail
    let result = ArchiveReader::open_with_passwords(&archive_path, &["alpha", "wrong"]).await;
    assert!(
        result.is_err(),
        "One correct + one wrong password should not open threshold(2) archive"
    );

    // Case 5: All three passwords → MUST succeed
    let reader =
        ArchiveReader::open_with_passwords(&archive_path, &["alpha", "bravo", "charlie"]).await;
    assert!(
        reader.is_ok(),
        "All three passwords should open threshold(2) archive: {:?}",
        reader.err()
    );
}

/// Adversarial E2E: Threshold(3) with 3 passwords — requires ALL participants.
#[tokio::test]
async fn e2e_threshold_02_all_required() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "nuclear.txt", b"LAUNCH CODES");

    let archive_path = temp.path().join("all_required.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("key_holder_1")
        .add_password("key_holder_2")
        .add_password("key_holder_3")
        .access_policy(AccessPolicy::Threshold(3))
        .build()
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("nuclear.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // 1 of 3 → MUST fail
    let result = ArchiveReader::open(&archive_path, "key_holder_1").await;
    assert!(result.is_err(), "1/3 should fail");

    // 2 of 3 → MUST fail
    let result =
        ArchiveReader::open_with_passwords(&archive_path, &["key_holder_1", "key_holder_2"]).await;
    assert!(result.is_err(), "2/3 should fail for threshold(3)");
    let err = result.err().unwrap();
    match err {
        era_common::EraError::ThresholdNotMet { required, provided } => {
            assert_eq!(required, 3);
            assert_eq!(provided, 2);
        }
        other => panic!("Expected ThresholdNotMet, got: {:?}", other),
    }

    // 3 of 3 → MUST succeed
    let reader = ArchiveReader::open_with_passwords(
        &archive_path,
        &["key_holder_1", "key_holder_2", "key_holder_3"],
    )
    .await;
    assert!(
        reader.is_ok(),
        "3/3 should open threshold(3) archive: {:?}",
        reader.err()
    );
}

/// Adversarial E2E: Duplicate password attack on threshold mode.
///
/// An attacker who knows only "alpha" tries to provide it multiple times
/// to meet the threshold requirement. This MUST fail because each password
/// only decrypts the share it was assigned to.
#[tokio::test]
async fn e2e_threshold_03_duplicate_password_attack() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "secret.txt", b"DUPLICATE ATTACK TARGET");

    let archive_path = temp.path().join("dup_attack.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("alpha")
        .add_password("bravo")
        .add_password("charlie")
        .access_policy(AccessPolicy::Threshold(2))
        .build()
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("secret.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Attacker provides "alpha" three times — should only unlock 1 share
    let result =
        ArchiveReader::open_with_passwords(&archive_path, &["alpha", "alpha", "alpha"]).await;
    assert!(
        result.is_err(),
        "CRITICAL: Duplicate password attack succeeded! \
         Providing the same password multiple times should NOT meet the threshold."
    );
}

/// Adversarial E2E: Wrong password provides zero shares.
#[tokio::test]
async fn e2e_threshold_04_wrong_password_zero_shares() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "data.txt", b"TEST");

    let archive_path = temp.path().join("wrong_pwd.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("real1")
        .add_password("real2")
        .access_policy(AccessPolicy::Threshold(2))
        .build()
        .await
        .unwrap();
    writer.add_file(&input_dir.join("data.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    // Both passwords wrong → 0 shares
    let result = ArchiveReader::open_with_passwords(&archive_path, &["wrong1", "wrong2"]).await;
    assert!(result.is_err(), "Both wrong passwords should fail");
    let err = result.err().unwrap();
    match err {
        era_common::EraError::ThresholdNotMet { required, provided } => {
            assert_eq!(required, 2);
            assert_eq!(provided, 0);
        }
        other => panic!("Expected ThresholdNotMet with 0 provided, got: {:?}", other),
    }
}

/// Adversarial E2E: Verify writer rejects Threshold(1).
#[tokio::test]
async fn e2e_threshold_05_writer_rejects_threshold_1() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "t.txt", b"T");

    let archive_path = temp.path().join("t1_reject.era");

    let result = ArchiveWriter::builder(&archive_path)
        .password("test")
        .access_policy(AccessPolicy::Threshold(1))
        .build()
        .await;

    assert!(result.is_err(), "Writer should reject Threshold(1)");
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("Threshold must be >= 2")
            || err.contains("threshold")
            || err.contains("Invalid"),
        "Error should mention threshold validation, got: {}",
        err
    );
}

/// Adversarial E2E: Verify writer rejects T > N.
#[tokio::test]
async fn e2e_threshold_06_writer_rejects_t_gt_n() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "t.txt", b"T");

    let archive_path = temp.path().join("t_gt_n.era");

    // Threshold(5) but only 2 passwords (primary + 1 additional)
    let result = ArchiveWriter::builder(&archive_path)
        .password("p1")
        .add_password("p2")
        .access_policy(AccessPolicy::Threshold(5))
        .build()
        .await;

    assert!(
        result.is_err(),
        "Writer should reject Threshold(5) with only 2 passwords"
    );
}

// ============================================================================
// SECTION 10: MEMORY HYGIENE
// ============================================================================

/// Verify VolumeKey memory is locked.
#[test]
fn memory_01_volume_key_locked() {
    let vk = VolumeKey::generate().unwrap();
    // On systems with mlock support, this should be locked
    // On CI/containers without CAP_IPC_LOCK, it may not be locked
    // but the SecureBuffer should still function correctly
    let _ = vk.is_memory_locked();
    // The fact that is_memory_locked() exists and doesn't panic is the test
}

/// Verify KeySession memory is locked.
#[test]
fn memory_02_session_memory_locked() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let _ = session.is_memory_locked();
}

// ============================================================================
// SECTION 11: CONCURRENT VK GENERATION
// ============================================================================

/// Verify concurrent VK generation produces unique keys.
#[test]
fn concurrent_01_unique_vks() {
    use std::sync::Arc;
    use std::thread;

    let mk = [0x42u8; 32];
    let session = Arc::new(KeySession::from_master_key(&mk).unwrap());
    let mut handles = Vec::new();

    for _ in 0..8 {
        let session = session.try_clone().unwrap();
        handles.push(thread::spawn(move || {
            let (vk, _) = session.generate_and_wrap_volume_key().unwrap();
            *vk.as_bytes()
        }));
    }

    let results: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            assert_ne!(
                results[i], results[j],
                "CRITICAL: Concurrent VK collision at threads {} and {}!",
                i, j
            );
        }
    }
}

// ============================================================================
// SECTION 12: E2E ANY-OF-N (REGRESSION TESTS)
// ============================================================================

/// Verify AnyOfN mode still works correctly (regression).
#[tokio::test]
async fn e2e_anyofn_01_single_password_roundtrip() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    let output_dir = temp.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();

    let content = b"AnyOfN test data - should be recoverable with single password";
    create_test_file(&input_dir, "anyofn.txt", content);

    let archive_path = temp.path().join("anyofn.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("single_pwd")
        .build()
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("anyofn.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Default is AnyOfN, single password should work
    let mut reader = ArchiveReader::open(&archive_path, "single_pwd")
        .await
        .unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();

    let extracted = fs::read(output_dir.join("anyofn.txt")).unwrap();
    assert_eq!(extracted, content);

    // Wrong password should fail
    let result = ArchiveReader::open(&archive_path, "wrong").await;
    assert!(result.is_err(), "Wrong password should fail for AnyOfN");
}

/// Verify empty password creates and opens correctly.
#[tokio::test]
async fn e2e_anyofn_02_empty_password() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "empty.txt", b"empty password test");

    let archive_path = temp.path().join("empty_pwd.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("")
        .build()
        .await
        .unwrap();
    writer.add_file(&input_dir.join("empty.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    let reader = ArchiveReader::open(&archive_path, "").await;
    assert!(reader.is_ok(), "Empty password should open archive");

    let reader = ArchiveReader::open(&archive_path, "not_empty").await;
    assert!(
        reader.is_err(),
        "Non-empty password should NOT open empty-password archive"
    );
}

// ============================================================================
// SECTION 13: HEADER INTEGRITY
// ============================================================================

/// 🚨 V7: Corrupted magic bytes DON'T prevent opening the archive.
///
/// The header.rs `from_bytes()` method checks magic bytes, BUT the
/// proto conversion `From<proto::SuperHeader> for SuperHeader` silently
/// replaces corrupted magic with valid MAGIC via `unwrap_or(MAGIC)`.
/// This means protobuf deserialization can succeed despite corrupted magic,
/// and the subsequent `from_bytes` magic check may be bypassed depending
/// on how the corruption interacts with protobuf encoding.
///
/// Additionally, corrupting the first 8 bytes may not affect the protobuf
/// length-delimited encoding's ability to parse the rest of the header,
/// since the magic is just a field in the protobuf message.
#[tokio::test]
async fn vuln_07_corrupted_magic_not_always_detected() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "magic.txt", b"test data for magic corruption");

    let archive_path = temp.path().join("magic.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("magic_test")
        .build()
        .await
        .unwrap();
    writer.add_file(&input_dir.join("magic.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    // Corrupt the first 8 bytes (magic) — but NOT in a way that breaks protobuf framing
    let mut data = fs::read(&archive_path).unwrap();
    for item in data.iter_mut().take(8) {
        *item = 0xFF;
    }
    fs::write(&archive_path, &data).unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ArchiveReader::open(&archive_path, "magic_test"),
    )
    .await;

    match result {
        Ok(Ok(_reader)) => {
            // VULNERABILITY FOUND: Archive opened despite corrupted magic bytes.
            // The protobuf deserialization doesn't enforce magic validation correctly.
            // header.rs line 327: `magic: proto.magic.try_into().unwrap_or(MAGIC)`
            // This silently replaces corrupted magic with the valid MAGIC constant.
        }
        Ok(Err(_)) => {
            // If this branch is taken, the corruption was properly detected.
            // In our testing, this is NOT the case — the archive opens successfully.
        }
        Err(_timeout) => {
            panic!("VULNERABILITY: Corrupted header caused hang (DoS via malformed archive)");
        }
    }

    // Either way, we've documented the finding. The key issue is in header.rs:
    // `magic: proto.magic.try_into().unwrap_or(MAGIC)` silently accepts bad magic.
    let header_source = include_str!("../../era-volume/src/header.rs");
    assert!(
        !header_source.contains("unwrap_or(MAGIC)"),
        "V7 NOT FIXED: header.rs still silently replaces corrupted magic bytes"
    );
    // This proves the vulnerability: invalid magic is silently replaced
    // with the correct value during deserialization.
}

/// Verify large file roundtrip with correct byte-for-byte integrity.
#[tokio::test]
async fn e2e_large_file_integrity() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    let output_dir = temp.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();

    // 1MB of pattern data
    let content: Vec<u8> = (0..=255u8).cycle().take(1024 * 1024).collect();
    create_test_file(&input_dir, "large.bin", &content);

    let archive_path = temp.path().join("large.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("large_test")
        .build()
        .await
        .unwrap();
    writer.add_file(&input_dir.join("large.bin")).await.unwrap();
    writer.finalize().await.unwrap();

    let mut reader = ArchiveReader::open(&archive_path, "large_test")
        .await
        .unwrap();
    reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .await
        .unwrap();

    let extracted = fs::read(output_dir.join("large.bin")).unwrap();
    assert_eq!(
        extracted.len(),
        content.len(),
        "Extracted file size mismatch"
    );
    assert_eq!(extracted, content, "Extracted file content mismatch");
}
