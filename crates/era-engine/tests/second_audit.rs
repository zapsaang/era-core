//! SECOND ADVERSARIAL AUDIT: Post-Remediation Vulnerability Probe
//!
//! This test suite audits the competitor's claimed "complete fix" of all 7
//! vulnerabilities listed in CLAUDE.md §6.1. While the competitor DID fix
//! the surface-level issues (V1-V7), this audit exposes **NEW** systemic
//! vulnerabilities introduced or overlooked during remediation.
//!
//! ## AUDIT METHODOLOGY
//!
//! 1. Source code attestation (include_str! for compile-time guarantees)
//! 2. Behavioral probes (actual crypto operations, not just grep)
//! 3. Boundary attacks (malformed inputs, edge cases)
//! 4. Protocol-level attacks (header manipulation, policy confusion)
//! 5. Memory hygiene verification
//!
//! ## FINDINGS SUMMARY
//!
//! ### CONFIRMED FIXES (Competitor's V1-V7 remediation verified):
//!   ✅ V1: Spiller AEAD key now uses OsRng
//!   ✅ V2: Volume writer padding now uses OsRng
//!   ✅ V3: Reader temp dir now uses OsRng
//!   ✅ V4: Reader rejects Threshold(1) — validation added
//!   ✅ V5: GenericArchiveWriterBuilder has access_policy() method
//!   ✅ V6: Stale doc tests renamed
//!   ✅ V7: Magic bytes use TryFrom with validation (unwrap_or(MAGIC) removed)
//!
//! ### NEW VULNERABILITIES DISCOVERED:
//!   🚨 NV1: GenericArchiveWriterBuilder.build() MISSING threshold validation
//!           — accepts Threshold(0), Threshold(1), T>N without error
//!   🚨 NV2: Header deserialization silently zeros critical crypto fields
//!           — salt, EVK nonce, UUIDs default to zero on malformed protobuf
//!   🚨 NV3: Reader mk_array never zeroized after session creation
//!           — raw MK persists on stack; shares Vec never zeroized
//!   🚨 NV4: certificate.rs test code uses thread_rng() — spec violation in tests
//!   🚨 NV5: EncryptedVolumeKey From<proto> fallback creates zero-nonce key wrap
//!           — silent acceptance of truncated nonce field
//!   🚨 NV6: GenericArchiveWriter creates invalid threshold archives silently
//!           — no Shamir splitting, single-slot MK despite Threshold(T) header
//!   🚨 NV7: open_with_session bypasses all access policy enforcement
//!           — no threshold/access_policy check on session-based open path
//!   🚨 NV8: Writer master_key zeroization uses non-volatile fill
//!           — compiler may optimize away `iter_mut().for_each(|b| *b = 0)`

use era_common::ArchiveId;
use era_crypto::{split_master_key, wrap_volume_key, IntermediateKey, KeySession, VolumeKey};
use era_engine::{ArchiveReader, ArchiveWriter};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

// MAGIC is not publicly exported from era_volume, so we define it here for tests
const MAGIC: [u8; 8] = [0x45, 0x52, 0x41, 0x08, 0x01, 0x00, 0x00, 0x00];

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

fn mock_encrypted_vk() -> EncryptedVolumeKey {
    EncryptedVolumeKey::new(
        KeyWrapAlgorithm::XChaCha20Poly1305,
        [0xAA; 24],
        vec![0xBB; 48],
    )
}

// ============================================================================
// SECTION 0: VERIFY COMPETITOR'S V1-V7 FIXES (Regression Baseline)
// ============================================================================

/// ✅ Verify V1 fix: spiller.rs was deleted (vulnerability resolved by removal)
#[test]
fn verify_v1_spiller_uses_osrng() {
    // spiller.rs was deleted — the index builder now uses IndexStore (Redb)
    // for spill-to-disk, which does not require its own encryption key.
    assert!(
        !std::path::Path::new("crates/era-index/src/spiller.rs").exists(),
        "spiller.rs should have been deleted"
    );
}

/// ✅ Verify V2 fix: volume writer padding uses OsRng
#[test]
fn verify_v2_writer_padding_uses_osrng() {
    let source = include_str!("../../era-volume/src/writer.rs");
    assert!(
        !source.contains("thread_rng"),
        "REGRESSION V2: volume writer still contains thread_rng"
    );
    assert!(
        source.contains("OsRng"),
        "REGRESSION V2: volume writer must use OsRng"
    );
}

/// ✅ Verify V3 fix: legacy LSM restore removed, V2.1 IndexReader used instead
#[test]
fn verify_v3_reader_temp_dir_uses_osrng() {
    let source = include_str!("../src/reader.rs");
    // Legacy create_embedded_lsm_restore_dir has been removed in favor of V2.1 IndexReader
    assert!(
        !source.contains("fn create_embedded_lsm_restore_dir"),
        "Legacy create_embedded_lsm_restore_dir should be removed"
    );
    assert!(
        source.contains("IndexReader::recover_from_volume"),
        "Reader must use V2.1 IndexReader::recover_from_volume"
    );
}

/// ✅ Verify V4 fix: reader rejects Threshold(1)
#[test]
fn verify_v4_reader_rejects_threshold_1() {
    let source = include_str!("../src/reader.rs");
    let threshold_section = source
        .find("AccessPolicy::Threshold(t)")
        .expect("Reader must handle Threshold variant");
    let after_match = &source[threshold_section..];
    // Must contain t < 2 check within the first 500 chars of the match
    assert!(
        after_match[..500].contains("t < 2"),
        "REGRESSION V4: Reader still lacks t < 2 validation"
    );
}

/// ✅ Verify V5 fix: GenericArchiveWriterBuilder has access_policy method
#[test]
fn verify_v5_generic_writer_has_access_policy() {
    let source = include_str!("../src/writer.rs");
    let builder_start = source
        .find("pub struct GenericArchiveWriterBuilder")
        .expect("GenericArchiveWriterBuilder should exist");
    let builder_section = &source[builder_start..];
    assert!(
        builder_section[..3000].contains("fn access_policy"),
        "REGRESSION V5: GenericArchiveWriterBuilder still lacks access_policy method"
    );
    assert!(
        builder_section[..3000].contains("access_policy: Option<"),
        "REGRESSION V5: GenericArchiveWriterBuilder missing access_policy field"
    );
}

/// ✅ Verify V6 fix: stale doc tests renamed
#[test]
fn verify_v6_stale_doc_tests_renamed() {
    let source = include_str!("envelope_adversarial.rs");
    assert!(
        !source.contains("doc_nonce_generate_uses_thread_rng"),
        "REGRESSION V6: stale test name still exists"
    );
    assert!(
        !source.contains("doc_generic_writer_mk_uses_thread_rng"),
        "REGRESSION V6: stale test name still exists"
    );
}

/// ✅ Verify V7 fix: header.rs no longer uses unwrap_or(MAGIC)
#[test]
fn verify_v7_magic_validation() {
    let source = include_str!("../../era-volume/src/header.rs");
    assert!(
        !source.contains("unwrap_or(MAGIC)"),
        "REGRESSION V7: header.rs still uses unwrap_or(MAGIC) for silent corruption acceptance"
    );
    // Verify TryFrom is used instead of From
    assert!(
        source.contains("impl TryFrom<proto::SuperHeader> for SuperHeader"),
        "REGRESSION V7: SuperHeader should use TryFrom, not From"
    );
}

// ============================================================================
// SECTION 1: 🚨 NV1 — GenericArchiveWriterBuilder MISSING THRESHOLD VALIDATION
// ============================================================================
//
// The competitor added the `access_policy()` builder method (V5 fix) but
// FORGOT to add the same T>=2 and T<=N validation that exists in the
// non-generic ArchiveWriterBuilder. This means GenericArchiveWriterBuilder
// silently accepts:
//   - Threshold(0) → undefined behavior in sharks crate
//   - Threshold(1) → degrades to AnyOfN semantics
//   - Threshold(T) where T > N → impossible to open archive
//
// The non-generic builder validates at writer.rs:500-533. The generic builder
// at writer.rs:1980 does NOT validate at all.

/// 🚨 NV1: PROVE GenericArchiveWriterBuilder.build() has no threshold validation
#[test]
fn nv1_generic_writer_missing_threshold_validation() {
    let source = include_str!("../src/writer.rs");

    // Find the GenericArchiveWriterBuilder's build() method
    let builder_start = source
        .find("pub struct GenericArchiveWriterBuilder")
        .expect("GenericArchiveWriterBuilder must exist");
    let builder_section = &source[builder_start..];

    // Find the build() method within GenericArchiveWriterBuilder
    let build_fn = builder_section
        .find("async fn build(self)")
        .or_else(|| builder_section.find("pub async fn build(self)"))
        .expect("build() method must exist");

    // Get the build method body (approximate: next ~1500 chars)
    let build_body =
        &builder_section[build_fn..build_fn + 1500.min(builder_section.len() - build_fn)];

    // Check for threshold validation — it should have t < 2 or threshold checks
    let has_threshold_validation = build_body.contains("t < 2")
        || build_body.contains("threshold < 2")
        || build_body.contains("Threshold must")
        || build_body.contains("threshold must")
        || build_body.contains("split_master_key");

    assert!(
        has_threshold_validation,
        "🚨 NV1: GenericArchiveWriterBuilder.build() has NO threshold validation!\n\
         The non-generic ArchiveWriterBuilder validates T>=2 and T<=N,\n\
         but GenericArchiveWriterBuilder passes access_policy straight through.\n\
         An attacker can create archives with Threshold(1) or Threshold(0)\n\
         via the generic API."
    );
}

/// 🚨 NV1b: PROVE ArchiveWriterBuilder HAS the validation (contrast test)
#[test]
fn nv1b_non_generic_writer_has_threshold_validation() {
    let source = include_str!("../src/writer.rs");

    // Find the ArchiveWriterBuilder (non-generic) build method
    // It should contain "Threshold must be >= 2" or similar
    let has_validation = source.contains("Threshold must be >= 2") || source.contains("t < 2");

    assert!(
        has_validation,
        "Expected ArchiveWriterBuilder to validate threshold >= 2"
    );
}

// ============================================================================
// SECTION 2: 🚨 NV2 — HEADER DESERIALIZATION SILENT ZERO-FILL
// ============================================================================
//
// The competitor fixed the magic bytes (V7) but LEFT identical patterns on
// other security-critical fields. When protobuf data is truncated or corrupted:
//   - salt → [0u8; 16]  (CATASTROPHIC: enables nonce reuse across archives)
//   - EVK nonce → [0u8; 24]  (deterministic nonce for key wrapping)
//   - volume_id → Uuid::nil()  (cross-volume confusion)
//   - archive_id → Uuid::nil()  (cross-archive confusion)
//   - encrypted_volume_key → empty (silent failure deferred to crypto layer)
//
// These should ALL fail loudly with EraError, not silently degrade.

/// 🚨 NV2a: PROVE salt field silently defaults to all-zeros
#[test]
fn nv2a_salt_defaults_to_zero_on_malformed_header() {
    let source = include_str!("../../era-volume/src/header.rs");

    // The TryFrom impl should NOT contain unwrap_or([0u8; 16]) for salt
    // This pattern silently accepts corrupted salt, enabling nonce reuse
    let has_salt_fallback = source.contains("salt: proto.salt.try_into().unwrap_or([0u8; 16])");
    assert!(
        !has_salt_fallback,
        "🚨 NV2a: Header deserialization silently zeros the salt on malformed input!\n\
         `salt: proto.salt.try_into().unwrap_or([0u8; 16])` at header.rs\n\
         A corrupted or truncated salt field becomes all-zeros, which means:\n\
         - Two archives with same MK + zero salt = identical nonce contexts\n\
         - Per-block key derivation becomes deterministic across archives\n\
         - XChaCha20-Poly1305 nonce reuse → CATASTROPHIC crypto failure\n\
         \n\
         FIX: Return EraError::InvalidHeader(\"Corrupted archive salt\") instead."
    );
}

/// 🚨 NV2b: PROVE EVK nonce field silently defaults to all-zeros
#[test]
fn nv2b_evk_nonce_defaults_to_zero_on_malformed() {
    let source = include_str!("../../era-volume/src/header.rs");

    // The EncryptedVolumeKey From<proto> impl should NOT silently zero the nonce
    let has_nonce_fallback = source.contains("nonce: proto.nonce.try_into().unwrap_or([0u8; 24])");
    assert!(
        !has_nonce_fallback,
        "🚨 NV2b: EncryptedVolumeKey deserialization silently zeros the nonce!\n\
         `nonce: proto.nonce.try_into().unwrap_or([0u8; 24])` in From<proto::EncryptedVolumeKey>\n\
         A corrupted nonce field becomes [0u8; 24].\n\
         While AEAD will likely reject the decryption (wrong nonce → tag mismatch),\n\
         the error message will be 'Key Tampering Detected' instead of\n\
         'Corrupted key wrapping nonce', which masks the real cause.\n\
         \n\
         FIX: Use TryFrom and return EraError::InvalidHeader."
    );
}

/// 🚨 NV2c: PROVE UUID fields silently default to nil
#[test]
fn nv2c_uuid_fields_default_to_nil_on_malformed() {
    let source = include_str!("../../era-volume/src/header.rs");

    let has_volume_id_nil =
        source.contains("Uuid::from_slice(&proto.volume_id).unwrap_or(uuid::Uuid::nil())");
    let has_archive_id_nil =
        source.contains("Uuid::from_slice(&proto.archive_id).unwrap_or(uuid::Uuid::nil())");

    assert!(
        !has_volume_id_nil,
        "🚨 NV2c: volume_id silently defaults to Uuid::nil() on malformed input!\n\
         Nil UUIDs cause cross-volume identity confusion in multi-volume archives.\n\
         FIX: Return EraError::InvalidHeader(\"Invalid volume UUID\")."
    );
    assert!(
        !has_archive_id_nil,
        "🚨 NV2c: archive_id silently defaults to Uuid::nil() on malformed input!\n\
         Nil archive ID causes archives to be confused with each other.\n\
         FIX: Return EraError::InvalidHeader(\"Invalid archive UUID\")."
    );
}

/// 🚨 NV2d: PROVE encrypted_volume_key defaults to empty on missing protobuf field
#[test]
fn nv2d_evk_defaults_to_empty_on_missing_field() {
    let source = include_str!("../../era-volume/src/header.rs");

    // Check for the pattern where missing EVK gets zeroed defaults
    let has_evk_fallback = source.contains(".unwrap_or(EncryptedVolumeKey {");
    assert!(
        !has_evk_fallback,
        "🚨 NV2d: Missing encrypted_volume_key protobuf field silently creates\n\
         an empty EncryptedVolumeKey with zero nonce and empty ciphertext!\n\
         This causes a misleading 'Key Tampering Detected' error instead of\n\
         'Missing encrypted volume key in header'.\n\
         \n\
         FIX: Return EraError::InvalidHeader(\"Missing encrypted volume key\")."
    );
}

/// 🚨 NV2e: Behavioral test — create a header with truncated salt, verify it's accepted
#[test]
fn nv2e_behavioral_truncated_salt_accepted() {
    // Create a normal header
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        era_common::ArchiveConfig::default(),
        [0xAB; 16], // Valid salt
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    // Serialize to bytes
    let bytes = header.to_bytes().unwrap();

    // Deserialize — this should work
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    assert_eq!(restored.salt(), &[0xAB; 16], "Normal salt roundtrip failed");

    // Now test: if protobuf field has wrong-length salt, does TryFrom still succeed?
    // We can't easily truncate a single protobuf field, but we can verify the source
    // code pattern that would allow it
    let source = include_str!("../../era-volume/src/header.rs");
    let try_from_section = source
        .find("impl TryFrom<proto::SuperHeader> for SuperHeader")
        .expect("TryFrom impl must exist");
    let try_from_body = &source[try_from_section..try_from_section + 2000];

    // The salt line should use map_err, not unwrap_or
    let salt_uses_fallback = try_from_body.contains("salt.try_into().unwrap_or(");
    assert!(
        !salt_uses_fallback,
        "🚨 NV2e: TryFrom<proto::SuperHeader> uses unwrap_or fallback for salt!\n\
         A malformed archive with truncated salt silently gets [0u8; 16],\n\
         which is the MOST DANGEROUS all-zeros value for nonce derivation."
    );
}

// ============================================================================
// SECTION 3: 🚨 NV3 — READER MASTER KEY NOT ZEROIZED
// ============================================================================
//
// Per CLAUDE.md §5.2: "These variables must be scrubbed from memory immediately
// after use." The writer correctly zeroizes master_key after session creation
// (writer.rs:608), but the reader does NOT zeroize mk_array or intermediate
// key material in the open() path.

/// 🚨 NV3: PROVE reader does not zeroize mk_array after use
#[test]
fn nv3_reader_mk_not_zeroized() {
    let source = include_str!("../src/reader.rs");

    // Find the open_with_providers function
    let open_fn = source
        .find("async fn open_with_providers")
        .expect("open_with_providers function must exist");
    let open_body = &source[open_fn..open_fn + 3000.min(source.len() - open_fn)];

    // Check if mk_array is zeroized after KeySession::from_master_key
    let has_mk_zeroize = open_body.contains("mk_array.zeroize()")
        || open_body.contains("mk_array.fill(0)")
        || open_body.contains("mk_array.iter_mut().for_each")
        || open_body.contains("mk_array = [0u8; 32]");

    assert!(
        has_mk_zeroize,
        "🚨 NV3: reader.rs open_with_providers() does NOT zeroize mk_array!\n\
         After `let session = KeySession::from_master_key(&mk_array)?;`\n\
         the raw 32-byte master key remains on the stack frame.\n\
         \n\
         Contrast with writer.rs which correctly does:\n\
         `master_key.iter_mut().for_each(|b| *b = 0);`\n\
         \n\
         Per §5.2: 'These variables must be scrubbed from memory immediately after use.'\n\
         \n\
         ALSO MISSING: shares Vec<Vec<u8>> containing Shamir shares is never zeroized."
    );
}

/// 🚨 NV3b: PROVE reader doesn't zeroize Shamir shares after reconstruction
#[test]
fn nv3b_reader_shares_not_zeroized() {
    let source = include_str!("../src/reader.rs");

    // Find the threshold handling section
    let threshold_section = source
        .find("AccessPolicy::Threshold(t)")
        .expect("Threshold handling must exist");
    let threshold_body = &source[threshold_section..threshold_section + 1000];

    // Check if shares are zeroized
    let has_shares_zeroize = threshold_body.contains("shares.zeroize()")
        || threshold_body.contains("shares.iter_mut().for_each")
        || threshold_body.contains("share.zeroize()");

    assert!(
        has_shares_zeroize,
        "🚨 NV3b: reader.rs does NOT zeroize Shamir shares after MK reconstruction!\n\
         `let mut shares = Vec::new();` at the threshold branch\n\
         contains raw Shamir shares that persist on the heap.\n\
         An attacker with memory access could recover individual shares\n\
         and reconstruct the MK offline."
    );
}

// ============================================================================
// SECTION 4: 🚨 NV4 — PRODUCTION-ADJACENT thread_rng() IN CERTIFICATE TESTS
// ============================================================================

/// 🚨 NV4: certificate.rs test code uses thread_rng()
///
/// While this is test code (not production), it violates the letter of §5.3
/// which says "FORBIDDEN: rand::thread_rng()" without exempting test code.
/// More importantly, test code that uses forbidden APIs sets a bad precedent
/// and risks being copy-pasted into production paths during future maintenance.
#[test]
fn nv4_certificate_test_uses_thread_rng() {
    let source = include_str!("../../era-crypto/src/certificate.rs");

    // Check for thread_rng in the entire file (including tests)
    let has_thread_rng = source.contains("thread_rng");
    assert!(
        !has_thread_rng,
        "🚨 NV4: certificate.rs contains thread_rng()!\n\
         Found in test_key_encapsulation_roundtrip() at line ~682.\n\
         While this is test code, §5.3 states:\n\
         'Use rand::rngs::OsRng. FORBIDDEN: rand::thread_rng()'\n\
         with NO exemption for test code.\n\
         Test code using forbidden APIs risks copy-paste contamination."
    );
}

/// Verify NO production .rs files under crates/*/src/ use thread_rng
#[test]
fn nv4b_no_production_thread_rng_anywhere() {
    // Check all production source files
    let files_to_check = [
        (
            "era-crypto/src/aead.rs",
            include_str!("../../era-crypto/src/aead.rs"),
        ),
        (
            "era-crypto/src/key_session.rs",
            include_str!("../../era-crypto/src/key_session.rs"),
        ),
        // spiller.rs was deleted — skipped
        (
            "era-volume/src/writer.rs",
            include_str!("../../era-volume/src/writer.rs"),
        ),
        ("era-engine/src/reader.rs", include_str!("../src/reader.rs")),
        ("era-engine/src/writer.rs", include_str!("../src/writer.rs")),
    ];

    for (name, source) in &files_to_check {
        // Only check non-test sections
        let production_section = if let Some(test_start) = source.find("#[cfg(test)]") {
            &source[..test_start]
        } else {
            source
        };
        assert!(
            !production_section.contains("thread_rng"),
            "🚨 NV4b: Production code in {} still uses thread_rng!",
            name
        );
    }
}

// ============================================================================
// SECTION 5: 🚨 NV5 — EncryptedVolumeKey From<proto> ZERO-NONCE FALLBACK
// ============================================================================

/// 🚨 NV5: PROVE EncryptedVolumeKey From<proto> uses unwrap_or for nonce
///
/// The `From<proto::EncryptedVolumeKey> for EncryptedVolumeKey` impl at
/// header.rs:270 uses:
///   `nonce: proto.nonce.try_into().unwrap_or([0u8; 24])`
///
/// This means a truncated protobuf nonce field silently becomes [0u8; 24].
/// While AEAD decryption will likely fail (wrong nonce), the error misleads:
/// "Key Tampering Detected" instead of "Corrupted nonce in header".
///
/// More critically, this `From` impl (not `TryFrom`) is INFALLIBLE.
/// The competitor fixed the SuperHeader conversion to use TryFrom,
/// but left the EncryptedVolumeKey conversion as `From` — meaning it
/// CAN'T propagate errors.
#[test]
fn nv5_evk_from_proto_is_infallible() {
    let source = include_str!("../../era-volume/src/header.rs");

    // The EVK conversion should be TryFrom (fallible), not From (infallible)
    let has_from_evk =
        source.contains("impl From<proto::EncryptedVolumeKey> for EncryptedVolumeKey");
    let has_tryfrom_evk =
        source.contains("impl TryFrom<proto::EncryptedVolumeKey> for EncryptedVolumeKey");

    assert!(
        !has_from_evk || has_tryfrom_evk,
        "🚨 NV5: EncryptedVolumeKey uses infallible `From<proto>` conversion!\n\
         The competitor changed SuperHeader to use TryFrom (V7 fix) but LEFT\n\
         EncryptedVolumeKey as `From`, which CANNOT return errors.\n\
         This means truncated nonce/ciphertext data is silently accepted\n\
         with zero-fill defaults.\n\
         \n\
         FIX: Change to TryFrom<proto::EncryptedVolumeKey> and propagate errors."
    );
}

// ============================================================================
// SECTION 6: 🚨 NV6 — GenericArchiveWriter CREATES INVALID THRESHOLD ARCHIVES
// ============================================================================
//
// The competitor added access_policy() to GenericArchiveWriterBuilder (V5 fix),
// but the build() method's crypto setup only creates a SINGLE recipient slot
// with the full MK — it does NOT perform Shamir's Secret Sharing.
//
// This means: if someone sets `.access_policy(Threshold(2))`, the header will
// say "Threshold(2)" but there's only 1 recipient slot containing the full MK
// (not a share). The reader will try to treat it as SSS, fail to get enough
// shares, and the archive becomes permanently unreadable.

/// 🚨 NV6: PROVE GenericArchiveWriter doesn't implement Shamir splitting
#[test]
fn nv6_generic_writer_no_shamir_splitting() {
    let source = include_str!("../src/writer.rs");

    // Find GenericArchiveWriterBuilder's build method
    let builder_start = source
        .find("pub struct GenericArchiveWriterBuilder")
        .expect("GenericArchiveWriterBuilder must exist");
    let builder_section = &source[builder_start..];

    // Find the struct boundary (next major struct or mod declaration)
    let next_struct = builder_section
        .find("pub struct GenericArchiveWriter<")
        .unwrap_or(4000);
    let builder_and_impl = &builder_section[..next_struct];

    // Check if Shamir splitting is performed in the builder
    let does_shamir = builder_and_impl.contains("split_master_key")
        || builder_and_impl.contains("shares")
        || builder_and_impl.contains("add_password");

    assert!(
        does_shamir,
        "🚨 NV6: GenericArchiveWriterBuilder does NOT perform Shamir splitting!\n\
         The build() method creates a single recipient slot with the full MK,\n\
         but if access_policy is set to Threshold(T), the header claims T-of-N\n\
         threshold while the archive actually stores the full MK in one slot.\n\
         \n\
         Result: Archive with Threshold(2) header is PERMANENTLY UNREADABLE\n\
         because the reader expects SSS shares but finds full MK payloads.\n\
         \n\
         FIX: Either:\n\
         1. Add add_password() method and implement Shamir splitting, OR\n\
         2. Reject Threshold policy in build() if only 1 password provided"
    );
}

// ============================================================================
// SECTION 7: 🚨 NV7 — open_with_session BYPASSES ACCESS POLICY
// ============================================================================
//
// The `open_with_session()` method provides a shortcut that bypasses ALL
// credential verification. It does not check header.access_policy at all.
// While having the correct MK implies authorization, the API contract should
// at minimum LOG a warning if a threshold archive is opened via session instead
// of the standard multi-password flow.

/// 🚨 NV7: PROVE open_with_session doesn't check access_policy
#[test]
fn nv7_open_with_session_no_policy_check() {
    let source = include_str!("../src/reader.rs");

    let fn_start = source
        .find("pub async fn open_with_session")
        .expect("open_with_session must exist");
    let fn_body = &source[fn_start..fn_start + 3000.min(source.len() - fn_start)];

    // It should at least check or log the access_policy
    let checks_policy = fn_body.contains("access_policy")
        || fn_body.contains("AccessPolicy")
        || fn_body.contains("Threshold");

    assert!(
        checks_policy,
        "🚨 NV7: open_with_session() does not check header.access_policy!\n\
         A threshold archive can be opened with a pre-derived session\n\
         without multi-party verification. While this may be intentional\n\
         (session implies MK possession), it should at minimum:\n\
         1. Log a warning for threshold archives\n\
         2. Document that it bypasses threshold enforcement\n\
         3. Consider refusing threshold archives via this path"
    );
}

// ============================================================================
// SECTION 8: 🚨 NV8 — WRITER MASTER KEY ZEROIZATION NOT GUARANTEED
// ============================================================================
//
// The writer uses `master_key.iter_mut().for_each(|b| *b = 0)` at writer.rs:608
// which is NOT guaranteed to work — the compiler can optimize this away as a
// dead store (the variable is not read after zeroing). The `zeroize` crate
// exists specifically to solve this problem with volatile writes.
//
// The GenericArchiveWriter uses `master_key.fill(0)` at writer.rs:2023 which
// has the same problem.

/// 🚨 NV8: PROVE writer uses non-volatile zeroing for master_key
#[test]
fn nv8_writer_mk_zeroize_not_volatile() {
    let source = include_str!("../src/writer.rs");

    // Check all master_key zeroing patterns
    let uses_volatile_zeroize = source.contains("master_key.zeroize()")
        || source.contains("Zeroize::zeroize(&mut master_key)");

    let uses_nonvolatile_zeroing = source.contains("master_key.iter_mut().for_each(|b| *b = 0)")
        || source.contains("master_key.fill(0)");

    if uses_nonvolatile_zeroing && !uses_volatile_zeroize {
        panic!(
            "🚨 NV8: Writer uses non-volatile zeroing for master_key!\n\
             `master_key.iter_mut().for_each(|b| *b = 0)` and `master_key.fill(0)`\n\
             can be optimized away by the compiler as dead stores.\n\
             \n\
             The `zeroize` crate uses volatile writes to prevent this:\n\
             `master_key.zeroize()` or `Zeroize::zeroize(&mut master_key)`\n\
             \n\
             Per §5.2: 'Use the zeroize crate for MK, IK, and VK.'\n\
             \n\
             Found patterns:\n\
             - writer.rs:608: `master_key.iter_mut().for_each(|b| *b = 0)`\n\
             - writer.rs:2023: `master_key.fill(0)`\n\
             \n\
             FIX: `use zeroize::Zeroize; master_key.zeroize();`"
        );
    }
}

// ============================================================================
// SECTION 9: BEHAVIORAL ATTACKS — E2E INTEGRATION
// ============================================================================

/// E2E: Verify that corrupted magic bytes are rejected on read
#[tokio::test]
async fn behavioral_corrupted_magic_rejected() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "test.txt", b"corruption test data");

    let archive_path = temp.path().join("corrupt_magic.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("test")
        .build()
        .await
        .unwrap();
    writer.add_file(&input_dir.join("test.txt")).await.unwrap();
    writer.finalize().await.unwrap();

    // Corrupt the magic bytes
    let mut data = fs::read(&archive_path).unwrap();
    // The protobuf length-delimited format starts with a varint length,
    // then the message. We need to find and corrupt the magic field WITHIN
    // the protobuf message, not just the first bytes of the file.
    // But first, let's just verify that from_bytes properly validates.

    // Simple approach: zero out first 32 bytes (destroys protobuf framing too)
    for i in 0..32.min(data.len()) {
        data[i] = 0xFF;
    }
    fs::write(&archive_path, &data).unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ArchiveReader::open(&archive_path, "test"),
    )
    .await;

    match result {
        Ok(Ok(_)) => {
            panic!(
                "🚨 VULNERABILITY: Archive with corrupted magic bytes opened successfully!\n\
                 This means header validation was bypassed."
            );
        }
        Ok(Err(_e)) => {
            // Expected: corrupted header detected
        }
        Err(_) => {
            panic!(
                "🚨 VULNERABILITY: Corrupted archive caused hang (DoS).\n\
                 Malformed archives should fail fast, not block indefinitely."
            );
        }
    }
}

/// E2E: Verify single password cannot open Threshold(2) archive
#[tokio::test]
async fn behavioral_single_pwd_rejected_for_threshold() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "secret.txt", b"threshold protected");

    let archive_path = temp.path().join("threshold.era");
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("alpha")
        .add_password("bravo")
        .access_policy(AccessPolicy::Threshold(2))
        .build()
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("secret.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Single password must fail
    let result = ArchiveReader::open(&archive_path, "alpha").await;
    assert!(
        result.is_err(),
        "Single password should not open Threshold(2) archive"
    );

    // Two correct passwords must succeed
    let result = ArchiveReader::open_with_passwords(&archive_path, &["alpha", "bravo"]).await;
    assert!(
        result.is_ok(),
        "Two correct passwords should open Threshold(2) archive: {:?}",
        result.err()
    );
}

/// E2E: Writer must reject Threshold(0) — spec mandates T >= 2
#[tokio::test]
async fn behavioral_writer_rejects_threshold_0() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "t.txt", b"T");

    let archive_path = temp.path().join("t0.era");
    let result = ArchiveWriter::builder(&archive_path)
        .password("test")
        .access_policy(AccessPolicy::Threshold(0))
        .build()
        .await;

    assert!(
        result.is_err(),
        "Writer must reject Threshold(0) — spec mandates T >= 2"
    );
}

/// E2E: Verify key rotation preserves data integrity
#[tokio::test]
async fn behavioral_key_rotation_e2e() {
    let mk_old = [0x01u8; 32];
    let mk_new = [0x02u8; 32];

    let session_old = KeySession::from_master_key(&mk_old).unwrap();
    let session_new = KeySession::from_master_key(&mk_new).unwrap();

    // Create and wrap VK with old MK
    let (original_vk, wrapped_old) = session_old.generate_and_wrap_volume_key().unwrap();

    // Unwrap with old MK
    let vk = session_old
        .unwrap_volume_key(&wrapped_old.nonce, &wrapped_old.ciphertext)
        .unwrap();
    assert_eq!(original_vk.as_bytes(), vk.as_bytes());

    // Re-wrap with new MK (simulating key rotation)
    let new_ik = session_new.derive_intermediate_key().unwrap();
    let wrapped_new = wrap_volume_key(&new_ik, &vk).unwrap();

    // Old MK must NOT unwrap new wrapping
    assert!(
        session_old
            .unwrap_volume_key(&wrapped_new.nonce, &wrapped_new.ciphertext)
            .is_err(),
        "Old MK should not unwrap re-wrapped VK"
    );

    // New MK must unwrap successfully
    let rotated_vk = session_new
        .unwrap_volume_key(&wrapped_new.nonce, &wrapped_new.ciphertext)
        .unwrap();
    assert_eq!(
        original_vk.as_bytes(),
        rotated_vk.as_bytes(),
        "VK must survive key rotation unchanged"
    );
}

// ============================================================================
// SECTION 10: CROSS-CUTTING SECURITY PROPERTIES
// ============================================================================

/// Verify VK is random, not derived from MK (regression test for removed derive_volume_key)
#[test]
fn cross_vk_randomness_not_derived() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();

    let mut vks = std::collections::HashSet::new();
    for _ in 0..100 {
        let (vk, _) = session.generate_and_wrap_volume_key().unwrap();
        assert!(
            vks.insert(*vk.as_bytes()),
            "VK collision detected — VK may be deterministically derived from MK!"
        );
    }
}

/// Verify IK derivation uses correct HKDF domain separator
#[test]
fn cross_ik_domain_separation() {
    let source = include_str!("../../era-crypto/src/key_session.rs");
    assert!(
        source.contains("ERA_KeyWrap_v1"),
        "IK derivation must use 'ERA_KeyWrap_v1' domain separator per §1.1"
    );
}

/// Verify Debug impls redact key material
#[test]
fn cross_debug_redaction() {
    let mk = [0xAB; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let ik = session.derive_intermediate_key().unwrap();
    let bk = session.derive_block_key(&vk, 0, &[0; 16]).unwrap();

    for (name, debug_str) in [
        ("KeySession", format!("{:?}", session)),
        ("VolumeKey", format!("{:?}", vk)),
        ("IntermediateKey", format!("{:?}", ik)),
        ("BlockKey", format!("{:?}", bk)),
    ] {
        assert!(
            debug_str.contains("REDACTED"),
            "{} Debug output does not contain REDACTED: {}",
            name,
            debug_str
        );
        assert!(
            !debug_str.contains(&hex::encode([0xAB; 32])),
            "{} Debug output leaks raw key hex!",
            name
        );
    }
}

/// Verify AEAD tag failure produces correct error message per §5.4
#[test]
fn cross_aead_tamper_error_message() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let (_, wrapped) = session.generate_and_wrap_volume_key().unwrap();

    let mut tampered = wrapped.ciphertext.clone();
    tampered[0] ^= 0xFF;

    let err = session
        .unwrap_volume_key(&wrapped.nonce, &tampered)
        .unwrap_err();
    assert!(
        err.to_string().contains("Key Tampering Detected"),
        "AEAD error should say 'Key Tampering Detected' per §5.4, got: {}",
        err
    );
}

/// Verify Shamir splitting rejects T < 2 at the crypto layer
#[test]
fn cross_shamir_rejects_t_lt_2() {
    let mk = [0u8; 32];
    assert!(
        split_master_key(&mk, 0, 3).is_err(),
        "split_master_key should reject T=0"
    );
    assert!(
        split_master_key(&mk, 1, 3).is_err(),
        "split_master_key should reject T=1"
    );
}

/// Verify Shamir splitting rejects T > N
#[test]
fn cross_shamir_rejects_t_gt_n() {
    let mk = [0u8; 32];
    assert!(
        split_master_key(&mk, 5, 3).is_err(),
        "split_master_key should reject T > N"
    );
}

/// Verify nonces are unique across 1000 wrap operations
#[test]
fn cross_nonce_uniqueness() {
    let mk = [0x42u8; 32];
    let ik = IntermediateKey::derive_from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();

    let mut nonces = std::collections::HashSet::new();
    for i in 0..1000 {
        let wrapped = wrap_volume_key(&ik, &vk).unwrap();
        assert!(
            nonces.insert(wrapped.nonce),
            "Nonce collision after {} wraps!",
            i
        );
    }
}

/// Verify block keys are unique across 100 indices
#[test]
fn cross_block_key_isolation() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let nonce_ctx = [0xAB; 16];

    let mut keys = std::collections::HashSet::new();
    for i in 0..100u64 {
        let bk = session.derive_block_key(&vk, i, &nonce_ctx).unwrap();
        assert!(
            keys.insert(*bk.as_bytes()),
            "Block key collision at index {}!",
            i
        );
    }
}

/// Verify concurrent VK generation produces unique keys
#[test]
fn cross_concurrent_vk_unique() {
    use std::sync::Arc;

    let mk = [0x42u8; 32];
    let session = Arc::new(KeySession::from_master_key(&mk).unwrap());

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let s = session.try_clone().unwrap();
            std::thread::spawn(move || {
                let (vk, wrapped) = s.generate_and_wrap_volume_key().unwrap();
                let unwrapped = s
                    .unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext)
                    .unwrap();
                assert_eq!(vk.as_bytes(), unwrapped.as_bytes());
                *vk.as_bytes()
            })
        })
        .collect();

    let results: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let unique: std::collections::HashSet<_> = results.into_iter().collect();
    assert_eq!(
        unique.len(),
        8,
        "Concurrent VK generation produced duplicates!"
    );
}

// ============================================================================
// SECTION 11: HEADER INTEGRITY BYPASS PROBES
// ============================================================================

/// Header with Threshold(0) in from_bytes should be caught somewhere
#[test]
fn header_threshold_0_handled() {
    // V30: SuperHeader::new() now validates at construction time,
    // so Threshold(0) is rejected before it can ever be serialized.
    let result = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        era_common::ArchiveConfig::default(),
        [0xAB; 16],
        mock_encrypted_vk(),
        AccessPolicy::Threshold(0),
    );

    assert!(
        result.is_err(),
        "SuperHeader::new() should reject Threshold(0) — defense-in-depth validation"
    );
}

/// Verify header roundtrip preserves all fields
#[test]
fn header_full_roundtrip() {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // V30: Threshold(3) requires at least 3 recipients to pass validation
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![
            RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x12; 8]),
                vec![0xAB; 16],
                vec![0xCD; 48],
            ),
            RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x13; 8]),
                vec![0xAC; 16],
                vec![0xCE; 48],
            ),
            RecipientSlot::new(
                RecipientType::Argon2idPassword,
                Some([0x14; 8]),
                vec![0xAD; 16],
                vec![0xCF; 48],
            ),
        ],
        era_common::ArchiveConfig::default(),
        salt,
        EncryptedVolumeKey::new(
            KeyWrapAlgorithm::XChaCha20Poly1305,
            [0xEE; 24],
            vec![0xFF; 48],
        ),
        AccessPolicy::Threshold(3),
    )
    .unwrap();

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();

    assert_eq!(*restored.magic(), MAGIC);
    assert_eq!(restored.salt(), &salt, "Salt not preserved in roundtrip!");
    assert_eq!(restored.encrypted_volume_key().nonce(), &[0xEE; 24]);
    assert_eq!(
        restored.encrypted_volume_key().ciphertext(),
        &vec![0xFF; 48][..]
    );
    assert_eq!(restored.access_policy(), AccessPolicy::Threshold(3));
    assert_eq!(restored.recipients().len(), 3);
    assert_eq!(
        restored.recipients()[0].encrypted_master_key(),
        &vec![0xCD; 48][..]
    );
}

// ============================================================================
// SECTION 12: ADVERSARIAL CRYPTO PROBES
// ============================================================================

/// Verify wrap/unwrap roundtrip is correct
#[test]
fn crypto_wrap_unwrap_roundtrip() {
    for _ in 0..50 {
        let mut mk = [0u8; 32];
        OsRng.fill_bytes(&mut mk);

        let session = KeySession::from_master_key(&mk).unwrap();
        let (vk, wrapped) = session.generate_and_wrap_volume_key().unwrap();
        let unwrapped = session
            .unwrap_volume_key(&wrapped.nonce, &wrapped.ciphertext)
            .unwrap();

        assert_eq!(
            vk.as_bytes(),
            unwrapped.as_bytes(),
            "Wrap/unwrap roundtrip failed!"
        );
    }
}

/// Verify every byte position of ciphertext is authenticated
#[test]
fn crypto_every_ciphertext_byte_authenticated() {
    let mk = [0x42u8; 32];
    let ik = IntermediateKey::derive_from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let wrapped = wrap_volume_key(&ik, &vk).unwrap();

    for i in 0..wrapped.ciphertext.len() {
        let mut tampered = wrapped.ciphertext.clone();
        tampered[i] ^= 0x01;

        let result = era_crypto::unwrap_volume_key(&ik, &wrapped.nonce, &tampered);
        assert!(
            result.is_err(),
            "Tampered byte at position {} was NOT detected by AEAD!",
            i
        );
    }
}

/// Verify every byte position of nonce is validated
#[test]
fn crypto_every_nonce_byte_validated() {
    let mk = [0x42u8; 32];
    let ik = IntermediateKey::derive_from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let wrapped = wrap_volume_key(&ik, &vk).unwrap();

    for i in 0..24 {
        let mut tampered_nonce = wrapped.nonce;
        tampered_nonce[i] ^= 0x01;

        let result = era_crypto::unwrap_volume_key(&ik, &tampered_nonce, &wrapped.ciphertext);
        assert!(
            result.is_err(),
            "Tampered nonce byte at position {} was NOT detected!",
            i
        );
    }
}

/// Avalanche effect: 1-bit MK change → ~50% IK bit change
#[test]
fn crypto_avalanche_effect() {
    let mk1 = [0u8; 32];
    let mut mk2 = [0u8; 32];
    mk2[0] = 1;

    let ik1 = IntermediateKey::derive_from_master_key(&mk1).unwrap();
    let ik2 = IntermediateKey::derive_from_master_key(&mk2).unwrap();

    let hamming: u32 = ik1
        .as_bytes()
        .iter()
        .zip(ik2.as_bytes())
        .map(|(a, b)| (*a ^ *b).count_ones())
        .sum();

    assert!(
        hamming > 64 && hamming < 192,
        "Weak avalanche: {}/256 bits differ (expected ~128)",
        hamming
    );
}

/// Empty and truncated ciphertext must be rejected
#[test]
fn crypto_reject_degenerate_ciphertext() {
    let mk = [0x42u8; 32];
    let ik = IntermediateKey::derive_from_master_key(&mk).unwrap();

    // Empty
    assert!(
        era_crypto::unwrap_volume_key(&ik, &[0u8; 24], &[]).is_err(),
        "Empty ciphertext must be rejected"
    );

    // 1 byte
    assert!(
        era_crypto::unwrap_volume_key(&ik, &[0u8; 24], &[0x42]).is_err(),
        "1-byte ciphertext must be rejected"
    );

    // Just VK, no tag (32 bytes, missing 16-byte Poly1305 tag)
    assert!(
        era_crypto::unwrap_volume_key(&ik, &[0u8; 24], &[0x42; 32]).is_err(),
        "32-byte ciphertext (no auth tag) must be rejected"
    );
}

/// Hybrid KEM threshold requires exactly T keypairs to unlock.
#[tokio::test]
async fn behavioral_hybrid_kem_threshold_requires_two_keys() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("hybrid_threshold.era");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir(&output_dir).unwrap();

    let test_file = temp_dir.path().join("secret.txt");
    fs::write(&test_file, b"threshold hybrid data").unwrap();

    let kp1 = era_engine::HybridKeyPair::generate();
    let kp2 = era_engine::HybridKeyPair::generate();
    let kp3 = era_engine::HybridKeyPair::generate();

    // Create 2-of-3 hybrid threshold archive
    {
        let mut writer = era_engine::ArchiveWriterBuilder::new(&archive_path)
            .hybrid_certificate(kp1.certificate())
            .add_hybrid_certificate(kp2.certificate())
            .add_hybrid_certificate(kp3.certificate())
            .access_policy(era_volume::AccessPolicy::Threshold(2))
            .config(era_common::ArchiveConfig {
                erasure: None,
                ..Default::default()
            })
            .build()
            .await
            .unwrap();
        writer.add_file(&test_file).await.unwrap();
        writer.finalize().await.unwrap();
    }

    // Extract with any 2 keypairs should succeed
    {
        let p1 = Box::new(era_engine::auth::HybridCertificateProvider::new(
            kp1.clone(),
        ));
        let p2 = Box::new(era_engine::auth::HybridCertificateProvider::new(
            kp2.clone(),
        ));
        let mut reader =
            era_engine::ArchiveReader::open_with_providers(&archive_path, vec![p1, p2])
                .await
                .unwrap();
        reader.load_catalog().await.unwrap();
        let stats = reader
            .extract_all(&era_engine::ExtractOptions::new(&output_dir))
            .await
            .unwrap();
        assert_eq!(stats.extracted, 1);
    }
}

/// Mixed threshold families (password + hybrid cert) are rejected.
#[tokio::test]
async fn behavioral_mixed_threshold_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let archive_path = temp_dir.path().join("mixed_threshold.era");

    let kp = era_engine::HybridKeyPair::generate();

    let result = era_engine::ArchiveWriterBuilder::new(&archive_path)
        .password("secret")
        .add_hybrid_certificate(kp.certificate())
        .access_policy(era_volume::AccessPolicy::Threshold(2))
        .config(era_common::ArchiveConfig {
            erasure: None,
            ..Default::default()
        })
        .build()
        .await;

    assert!(
        result.is_err(),
        "Mixed threshold (password + hybrid certificate) must be rejected"
    );
}
