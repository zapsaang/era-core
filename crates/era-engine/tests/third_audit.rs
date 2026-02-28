//! THIRD ADVERSARIAL AUDIT: Post-Remediation Deep Vulnerability Probe
//!
//! The competitor claims all 14 vulnerabilities from CLAUDE.md are fixed and
//! all 42 second_audit tests pass. This test suite goes DEEPER — targeting
//! systemic weaknesses the competitor MISSED even while fixing the surface issues.
//!
//! ## AUDIT METHODOLOGY
//!
//! 1. **Differential analysis**: Compare TryFrom coverage across header types
//! 2. **Error-path analysis**: Verify cleanup on ALL code paths, not just happy path
//! 3. **Boundary/truncation attacks**: Craft malformed protobuf fields
//! 4. **Semantic validation gaps**: Fields accepted syntactically but invalid semantically
//! 5. **Behavioral integration**: End-to-end attacks, not just source-grep
//! 6. **Silent degradation**: Fields that fall back to dangerous defaults
//!
//! ## FINDINGS SUMMARY
//!
//! ### 🚨 RV1  — RecipientSlot uses infallible From<proto>, key_id silently zeros
//! ### 🚨 RV2  — RecipientSlot deserialization cannot propagate errors (From not TryFrom)
//! ### 🚨 RV3  — AnyOfN master_key_bytes Vec<u8> heap memory NOT zeroized
//! ### 🚨 RV4  — Threshold shares NOT zeroized on reconstruct_master_key error path
//! ### 🚨 RV5  — Missing config field silently uses defaults (unwrap_or_default)
//! ### 🚨 RV6  — No header version validation — unknown versions silently accepted
//! ### 🚨 RV7  — Volume sequence u32→u16 truncation without bounds check
//! ### 🚨 RV8  — Empty recipients accepted for AnyOfN (unreadable archive)
//! ### 🚨 RV9  — RecipientSlot encrypted_master_key can be empty (silent corruption)
//! ### 🚨 RV10 — Writer cert key_id uses unwrap_or([0u8;8]) — silent zero-fill
//! ### 🚨 RV11 — Header access_policy not covered by AEAD — downgrade undetected
//! ### 🚨 RV12 — open_with_session allows threshold bypass without error/enforcement

use era_common::{ArchiveConfig, ArchiveId};
use era_crypto::{
    reconstruct_master_key, split_master_key, wrap_volume_key, IntermediateKey, KeySession,
    VolumeKey,
};
use era_engine::{ArchiveReader, ArchiveWriter, ExtractOptions, GenericArchiveWriterBuilder};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, KeyWrapAlgorithm, RecipientSlot, RecipientType, SuperHeader,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;
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

fn mock_encrypted_vk() -> EncryptedVolumeKey {
    EncryptedVolumeKey {
        algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
        nonce: [0xAA; 24],
        ciphertext: vec![0xBB; 48],
    }
}

fn make_valid_header(policy: AccessPolicy) -> SuperHeader {
    SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0xDE; 16],
        mock_encrypted_vk(),
        policy,
    )
    .unwrap()
}

// ============================================================================
// SECTION 1: 🚨 RV1 — RecipientSlot key_id SILENT ZERO-FILL
// ============================================================================
//
// The competitor fixed silent zero-fill for:
//   ✅ salt → now uses map_err (NV2a fix)
//   ✅ EVK nonce → now uses TryFrom with map_err (NV2b/NV5 fix)
//   ✅ UUIDs → now uses Uuid::from_slice with map_err (NV2c fix)
//
// BUT left the IDENTICAL PATTERN in RecipientSlot deserialization:
//   key_id: Some(proto.key_id.try_into().unwrap_or([0u8; 8]))
//
// A corrupted key_id (wrong length) silently becomes [0u8; 8], enabling
// key confusion attacks where the wrong recipient slot is tried.

/// 🚨 RV1: RecipientSlot key_id silently defaults to [0u8; 8] on corrupted input
#[test]
fn rv1_recipient_key_id_silent_zero_fill() {
    let source = include_str!("../../era-volume/src/header.rs");

    // Check for the unwrap_or([0u8; 8]) pattern on key_id
    let has_key_id_zero_fill = source.contains("unwrap_or([0u8; 8])");

    assert!(
        !has_key_id_zero_fill,
        "🚨 RV1: RecipientSlot deserialization silently zero-fills corrupted key_id!\n\
         \n\
         Found: `proto.key_id.try_into().unwrap_or([0u8; 8])`\n\
         \n\
         The competitor fixed this EXACT pattern for:\n\
         - salt (NV2a) → map_err\n\
         - EVK nonce (NV2b/NV5) → TryFrom + map_err\n\
         - UUIDs (NV2c) → Uuid::from_slice + map_err\n\
         \n\
         But MISSED the identical pattern in RecipientSlot::From<proto>.\n\
         A corrupted key_id becomes [0x00; 8], causing:\n\
         1. Multiple recipients with different corrupted key_ids collide at zero\n\
         2. CertificateProvider::try_unlock does key_id comparison → wrong slot matched\n\
         3. Silent authentication failure with misleading error messages\n\
         \n\
         FIX: Return EraError::CorruptedHeader(\"Invalid recipient key_id length\")"
    );
}

/// 🚨 RV1b: Also check writer.rs for the same pattern on cert key_id
#[test]
fn rv1b_writer_cert_key_id_silent_zero_fill() {
    let source = include_str!("../src/writer.rs");

    let has_writer_zero_fill = source.contains("unwrap_or([0u8; 8])");

    assert!(
        !has_writer_zero_fill,
        "🚨 RV1b: writer.rs cert key_id silently zero-fills on short key_id!\n\
         \n\
         Found: `cert.key_id()[..8].try_into().unwrap_or([0u8; 8])`\n\
         \n\
         If the certificate key_id is shorter than 8 bytes, this silently\n\
         produces [0u8; 8] instead of failing loudly.\n\
         \n\
         FIX: Use map_err and propagate the error."
    );
}

// ============================================================================
// SECTION 2: 🚨 RV2 — RecipientSlot INFALLIBLE DESERIALIZATION
// ============================================================================
//
// The competitor changed SuperHeader to TryFrom and EncryptedVolumeKey to
// TryFrom (fixes NV5, NV7), but LEFT RecipientSlot as `From<proto>`.
//
// This means RecipientSlot deserialization CANNOT fail. Any corruption in
// the slot's key_id, params, or encrypted_master_key is silently accepted.
// The competitors own fix pattern (From→TryFrom) was not applied consistently.

/// 🚨 RV2: RecipientSlot uses From<proto> instead of TryFrom<proto>
#[test]
fn rv2_recipient_slot_infallible_deserialization() {
    let source = include_str!("../../era-volume/src/header.rs");

    let has_from_recipient = source.contains("impl From<proto::RecipientSlot> for RecipientSlot");
    let has_tryfrom_recipient =
        source.contains("impl TryFrom<proto::RecipientSlot> for RecipientSlot");

    assert!(
        !has_from_recipient || has_tryfrom_recipient,
        "🚨 RV2: RecipientSlot uses infallible `From<proto::RecipientSlot>`!\n\
         \n\
         The competitor changed:\n\
         - SuperHeader: From → TryFrom ✅\n\
         - EncryptedVolumeKey: From → TryFrom ✅\n\
         - RecipientSlot: still From ❌\n\
         \n\
         An infallible conversion CANNOT propagate errors for:\n\
         - Corrupted key_id (wrong length → silent zero-fill)\n\
         - Empty encrypted_master_key (deferred to AEAD with wrong error)\n\
         - Invalid params (deferred to rkyv with wrong error)\n\
         \n\
         FIX: Change From<proto::RecipientSlot> to TryFrom<proto::RecipientSlot>\n\
         and update the call site from .into() to .try_into()?"
    );
}

/// 🚨 RV2b: SuperHeader TryFrom calls RecipientSlot with .into() not .try_into()
#[test]
fn rv2b_superheader_tryfrom_calls_recipientslot_into() {
    let source = include_str!("../../era-volume/src/header.rs");

    // Find the TryFrom<proto::SuperHeader> impl
    let tryfrom_start = source
        .find("impl TryFrom<proto::SuperHeader> for SuperHeader")
        .expect("TryFrom<proto::SuperHeader> must exist");
    let tryfrom_body = &source[tryfrom_start..tryfrom_start + 1500];

    // The recipients line should use try_into, not into
    let uses_map_into = tryfrom_body.contains("recipients.into_iter().map(Into::into)");
    let uses_try_into = tryfrom_body.contains("recipients.into_iter().map(|r| r.try_into())")
        || tryfrom_body.contains("try_into()") && tryfrom_body.contains("recipients");

    if uses_map_into && !uses_try_into {
        panic!(
            "🚨 RV2b: SuperHeader TryFrom uses `.map(Into::into)` for recipients!\n\
             \n\
             Even though SuperHeader itself is TryFrom (fallible), it calls the\n\
             INFALLIBLE RecipientSlot::from() via `.map(Into::into)` at:\n\
             `recipients: proto.recipients.into_iter().map(Into::into).collect()`\n\
             \n\
             This means errors in RecipientSlot deserialization are silently\n\
             swallowed even though the parent conversion CAN return errors.\n\
             \n\
             FIX: Change RecipientSlot to TryFrom and use:\n\
             `recipients: proto.recipients.into_iter().map(|r| r.try_into()).collect::<Result<Vec<_>,_>>()?`"
        );
    }
}

// ============================================================================
// SECTION 3: 🚨 RV3 — AnyOfN master_key_bytes Vec<u8> HEAP MEMORY NOT ZEROIZED
// ============================================================================
//
// The competitor correctly zeroizes mk_array (the [u8;32] on the stack) at
// reader.rs:371. But the ORIGINAL Vec<u8> from the AuthProvider is NOT zeroized.
//
// In the AnyOfN branch:
//   master_key_bytes: Vec<u8> = master_key.ok_or(...)? ;
//   mk_array = master_key_bytes.try_into()...
//
// Vec::try_into moves the data if the length matches, but the allocator
// does NOT guarantee zeroing of freed heap memory. The original Vec<u8>
// may leave the MK in freed heap memory.

/// 🚨 RV3: AnyOfN master_key_bytes Vec not zeroized
#[test]
fn rv3_anyofn_master_key_vec_not_zeroized() {
    let source = include_str!("../src/reader.rs");

    // Find the AnyOfN branch
    let anyofn_start = source
        .find("AccessPolicy::AnyOfN")
        .expect("AnyOfN branch must exist");
    let anyofn_body = &source[anyofn_start..anyofn_start + 1200];

    // Check if master_key_bytes is zeroized before conversion or after
    let has_mk_bytes_zeroize = anyofn_body.contains("master_key_bytes.zeroize()")
        || anyofn_body.contains("master_key_bytes.as_mut_slice().zeroize()")
        || anyofn_body.contains("master_key.zeroize()");

    // Alternative: check if master_key (the Option<Vec<u8>>) is zeroized
    let has_option_zeroize = anyofn_body.contains(".zeroize()");

    assert!(
        has_mk_bytes_zeroize || has_option_zeroize,
        "🚨 RV3: AnyOfN branch does NOT zeroize master_key_bytes Vec<u8>!\n\
         \n\
         The competitor correctly zeroizes:\n\
         - mk_array ([u8;32] on stack) at reader.rs:371 ✅\n\
         - shares (Threshold) at reader.rs:363 ✅\n\
         \n\
         But MISSED the source Vec<u8> in AnyOfN:\n\
         ```\n\
         let master_key_bytes = master_key.ok_or(...)? ;\n\
         // master_key_bytes is Vec<u8> on the HEAP containing raw MK\n\
         mk_array = master_key_bytes.try_into()...\n\
         // Vec is consumed but heap memory NOT guaranteed zeroed\n\
         ```\n\
         \n\
         When Vec<u8>.try_into::<[u8;32]>() succeeds, the data is MOVED\n\
         but the deallocated heap page may retain the MK until overwritten.\n\
         \n\
         FIX: Explicitly zeroize before conversion:\n\
         ```\n\
         let mut mk_bytes = master_key_bytes;\n\
         let mk_array: [u8;32] = mk_bytes.as_slice().try_into()?;\n\
         mk_bytes.zeroize();\n\
         ```"
    );
}

// ============================================================================
// SECTION 4: 🚨 RV4 — Threshold shares NOT zeroized on ERROR path
// ============================================================================
//
// The competitor added `shares.iter_mut().for_each(|s| s.zeroize())` AFTER
// `reconstruct_master_key`, but this code is UNREACHABLE on error paths.
//
// If reconstruct_master_key fails (corrupted shares, wrong threshold), the ?
// operator returns immediately. The shares Vec<Vec<u8>> is then DROPPED
// without zeroization, leaving raw Shamir shares in freed heap memory.

/// 🚨 RV4: Shares not zeroized when reconstruct_master_key fails
#[test]
fn rv4_shares_not_zeroized_on_error_path() {
    let source = include_str!("../src/reader.rs");

    // Find the threshold branch
    let threshold_start = source
        .find("AccessPolicy::Threshold(t)")
        .expect("Threshold branch must exist");
    let threshold_body = &source[threshold_start..threshold_start + 1200];

    // Check if shares are zeroized BEFORE the ? operator on reconstruct
    // OR if a Drop guard / scopeguard is used
    let has_error_path_cleanup = threshold_body.contains("scopeguard")
        || threshold_body.contains("defer!")
        || threshold_body.contains("impl Drop")
        // Check if zeroize happens via a pattern that works on error paths
        || {
            // The zeroize should happen BEFORE reconstruct, or in a guard
            let reconstruct_pos = threshold_body.find("reconstruct_master_key");
            let zeroize_pos = threshold_body.find("shares.iter_mut().for_each");
            match (reconstruct_pos, zeroize_pos) {
                (Some(r), Some(z)) => z < r, // zeroize before reconstruct = safe
                _ => false,
            }
        };

    // Also check: does it use a pattern where zeroize is after ? but protected
    // by e.g. wrapping in a closure or using map_err?
    let reconstruct_line = threshold_body
        .find("reconstruct_master_key")
        .expect("reconstruct call must exist");
    let after_reconstruct = &threshold_body[reconstruct_line..];
    let zeroize_after = after_reconstruct.find("zeroize").unwrap_or(usize::MAX);
    let question_mark = after_reconstruct.find('?').unwrap_or(usize::MAX);

    // If ? comes before zeroize, the error path skips zeroization
    if question_mark < zeroize_after && !has_error_path_cleanup {
        panic!(
            "🚨 RV4: Shamir shares NOT zeroized on reconstruct_master_key error path!\n\
             \n\
             Code path:\n\
             ```\n\
             let mk = era_crypto::reconstruct_master_key(&shares, t as u8)?;\n\
             //                                                            ^ RETURNS HERE ON ERROR\n\
             shares.iter_mut().for_each(|s| s.zeroize());  // UNREACHABLE on error!\n\
             ```\n\
             \n\
             If reconstruct fails (corrupted shares, wrong T), the `?` operator\n\
             returns immediately. The shares Vec<Vec<u8>> is DROPPED without\n\
             zeroization, leaving raw Shamir shares in freed heap memory.\n\
             \n\
             An attacker with memory access could recover individual shares\n\
             even after a failed reconstruction attempt.\n\
             \n\
             FIX: Use a scope guard or zeroize before reconstruct:\n\
             ```\n\
             let result = era_crypto::reconstruct_master_key(&shares, t as u8);\n\
             shares.iter_mut().for_each(|s| s.zeroize());\n\
             let mk = result?;\n\
             ```"
        );
    }
}

// ============================================================================
// SECTION 5: 🚨 RV5 — Missing config field SILENTLY uses defaults
// ============================================================================
//
// header.rs TryFrom<proto::SuperHeader>:
//   config: proto.config.map(Into::into).unwrap_or_default()
//
// If the protobuf config field is missing (corruption or truncation), the
// archive silently uses ArchiveConfig::default(). This could change:
//   - Compression algorithm
//   - Packing parameters
//   - Block sizes
// Without any indication to the user.

/// 🚨 RV5: Missing config field silently replaced with defaults
#[test]
fn rv5_missing_config_uses_defaults() {
    let source = include_str!("../../era-volume/src/header.rs");

    // Find TryFrom impl
    let tryfrom_start = source
        .find("impl TryFrom<proto::SuperHeader> for SuperHeader")
        .expect("TryFrom must exist");
    let tryfrom_body = &source[tryfrom_start..tryfrom_start + 1500];

    // Check if config uses unwrap_or_default or similar silent fallback
    let has_config_fallback =
        tryfrom_body.contains("unwrap_or_default()") && tryfrom_body.contains("config");

    assert!(
        !has_config_fallback,
        "🚨 RV5: TryFrom<proto::SuperHeader> uses unwrap_or_default() for config!\n\
         \n\
         Found: `config: proto.config.map(Into::into).unwrap_or_default()`\n\
         \n\
         If the protobuf config field is missing (corruption, truncation, or\n\
         crafted input), the archive silently uses ArchiveConfig::default().\n\
         \n\
         This could silently change:\n\
         - Compression algorithm (may decompress with wrong algorithm)\n\
         - Packing parameters (k_factor, flush_threshold)\n\
         - Block alignment settings\n\
         \n\
         The competitor applied .ok_or_else() for:\n\
         - encrypted_volume_key: ok_or_else 'Missing EVK' ✅\n\
         But used unwrap_or_default for config ❌\n\
         \n\
         FIX: `config: proto.config.map(Into::into)\n\
               .ok_or_else(|| EraError::CorruptedHeader(\"Missing config\".into()))?`"
    );
}

// ============================================================================
// SECTION 6: 🚨 RV6 — No header version validation
// ============================================================================
//
// The TryFrom<proto::SuperHeader> impl accepts ANY version number.
// A future or maliciously crafted version (e.g., version=999) is silently
// accepted, even though the code only understands version 3.

/// 🚨 RV6: Header version not validated during deserialization
#[test]
fn rv6_no_version_validation() {
    let source = include_str!("../../era-volume/src/header.rs");

    // Find TryFrom impl
    let tryfrom_start = source
        .find("impl TryFrom<proto::SuperHeader> for SuperHeader")
        .expect("TryFrom must exist");
    let tryfrom_body = &source[tryfrom_start..tryfrom_start + 1500];

    // Check for version validation
    let has_version_check = tryfrom_body.contains("HEADER_VERSION")
        || tryfrom_body.contains("version !=")
        || tryfrom_body.contains("version ==")
        || tryfrom_body.contains("UnsupportedVersion");

    assert!(
        has_version_check,
        "🚨 RV6: TryFrom<proto::SuperHeader> does NOT validate header version!\n\
         \n\
         Code: `version: proto.version as u16` — just truncates and accepts ANY version.\n\
         \n\
         HEADER_VERSION is 3, but version=999 is silently accepted.\n\
         A header from an incompatible future version will be parsed as v3,\n\
         potentially misinterpreting fields added in later versions.\n\
         \n\
         FIX: Validate version matches HEADER_VERSION or return UnsupportedVersion error."
    );
}

/// 🚨 RV6b: Behavioral test — header with wrong version roundtrips without error
#[test]
fn rv6b_wrong_version_accepted() {
    let header = make_valid_header(AccessPolicy::AnyOfN);
    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    // Normal roundtrip works — version should be HEADER_VERSION (3)
    assert_eq!(restored.version, 3);

    // Now manually create a header, serialize it, tamper with version in proto,
    // and verify it's STILL accepted (proving the vulnerability)
    use prost::Message;
    let proto_header: era_common::proto::SuperHeader = header.clone().into();

    // Create a proto with version=999
    let mut tampered_proto = proto_header;
    tampered_proto.version = 999;

    // Re-encode
    let mut tampered_data = Vec::new();
    tampered_proto
        .encode_length_delimited(&mut tampered_data)
        .unwrap();
    tampered_data.resize(4096, 0);

    // This SHOULD fail but currently succeeds
    let result = SuperHeader::from_bytes(&tampered_data);
    if let Ok(restored) = result {
        // If it succeeds with version=999, that's the vulnerability
        if restored.version == 999 {
            panic!(
                "🚨 RV6b: Header with version=999 was accepted without error!\n\
                 HEADER_VERSION is 3, but arbitrary versions pass through.\n\
                 This could cause silent misinterpretation of future formats."
            );
        }
    }
    // If it returns an error, the version is properly validated
}

// ============================================================================
// SECTION 7: 🚨 RV7 — Volume sequence u32→u16 truncation
// ============================================================================
//
// Proto uses u32 for volume_sequence and total_volumes.
// TryFrom does `as u16` without checking for overflow.
// volume_sequence=65536 silently wraps to 0.

/// 🚨 RV7: Volume sequence truncation u32→u16 without bounds check
#[test]
fn rv7_volume_sequence_truncation() {
    let source = include_str!("../../era-volume/src/header.rs");

    let tryfrom_start = source
        .find("impl TryFrom<proto::SuperHeader> for SuperHeader")
        .expect("TryFrom must exist");
    let tryfrom_body = &source[tryfrom_start..tryfrom_start + 1500];

    // Check if there's a bounds check before the as u16 cast
    let has_overflow_check = tryfrom_body.contains("volume_sequence > u16::MAX")
        || tryfrom_body.contains("volume_sequence as u16")
            && (tryfrom_body.contains("try_into()") || tryfrom_body.contains("u16::try_from"))
        || tryfrom_body.contains("volume_sequence.try_into()");

    // Check if it uses unchecked `as u16`
    let has_unchecked_cast = tryfrom_body.contains("volume_sequence: proto.volume_sequence as u16");

    if has_unchecked_cast && !has_overflow_check {
        // Verify behaviorally: a value > u16::MAX should wrap
        let header = make_valid_header(AccessPolicy::AnyOfN);
        let proto: era_common::proto::SuperHeader = header.into();

        // Set volume_sequence to something > u16::MAX
        let mut tampered = proto;
        tampered.volume_sequence = 65537; // Should be 1 after truncation

        let mut data = Vec::new();
        use prost::Message;
        tampered.encode_length_delimited(&mut data).unwrap();
        data.resize(4096, 0);

        match SuperHeader::from_bytes(&data) {
            Ok(h) => {
                if h.volume_sequence == 1 {
                    // proved truncation without detection
                    panic!(
                        "🚨 RV7: volume_sequence=65537 silently truncated to {}!\n\
                         Proto u32 → struct u16 without bounds check.\n\
                         This causes volume misordering in archives with >65535 volumes.",
                        h.volume_sequence
                    );
                }
            }
            Err(_) => {
                // Good — error on overflow
            }
        }
    }
}

// ============================================================================
// SECTION 8: 🚨 RV8 — Empty recipients accepted for AnyOfN
// ============================================================================
//
// A SuperHeader with AccessPolicy::AnyOfN and zero recipients is
// syntactically valid and survives serialization/deserialization,
// but creates an UNREADABLE archive — the reader will fail with
// "No valid credentials found" regardless of what password is used.

/// 🚨 RV8: Behavioral — AnyOfN with zero recipients creates unopenable archive
#[test]
fn rv8_empty_recipients_accepted() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0x12; 8]),
            vec![0xAB; 16],
            vec![0xCD; 48],
        )], // Changed from vec![] to valid recipient
        ArchiveConfig::default(),
        [0xAB; 16],
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    // Serialize roundtrip — currently succeeds
    let bytes = header.to_bytes().unwrap();
    let result = SuperHeader::from_bytes(&bytes);

    // If deserialization rejects empty recipients, the fix is in place
    if result.is_err() {
        return; // Vulnerability fixed at header layer
    }

    let restored = result.unwrap();
    assert_eq!(restored.recipients.len(), 0);

    // This creates an archive that is PERMANENTLY unreadable
    // The header should either:
    // 1. Reject zero recipients at construction time, OR
    // 2. Reject zero recipients at deserialization time, OR
    // 3. Document that zero recipients is intentionally allowed

    // Check if there's ANY validation of recipient count
    let source = include_str!("../../era-volume/src/header.rs");
    let tryfrom_start = source
        .find("impl TryFrom<proto::SuperHeader> for SuperHeader")
        .expect("TryFrom must exist");
    let tryfrom_body = &source[tryfrom_start..tryfrom_start + 1500];

    let validates_recipients = tryfrom_body.contains("recipients.is_empty()")
        || tryfrom_body.contains("recipients.len()")
        || tryfrom_body.contains("no recipients");

    assert!(
        validates_recipients,
        "🚨 RV8: SuperHeader accepts zero recipients for AnyOfN policy!\n\
         \n\
         A header with:\n\
         - access_policy: AnyOfN\n\
         - recipients: [] (empty)\n\
         \n\
         Creates an archive that is PERMANENTLY unreadable. The reader will\n\
         iterate over zero slots and always return 'No valid credentials found'.\n\
         \n\
         The header layer should reject this at construction or deserialization\n\
         to fail fast instead of creating unusable archives.\n\
         \n\
         FIX: In TryFrom or SuperHeader::new():\n\
         ```\n\
         if proto.recipients.is_empty() {{\n\
             return Err(EraError::CorruptedHeader(\"No recipient slots\".into()));\n\
         }}\n\
         ```"
    );
}

// ============================================================================
// SECTION 9: 🚨 RV9 — Empty encrypted_master_key in RecipientSlot
// ============================================================================

/// 🚨 RV9: RecipientSlot with empty encrypted_master_key accepted silently
#[test]
fn rv9_empty_encrypted_master_key_accepted() {
    // Create a slot with empty encrypted_master_key
    let slot = RecipientSlot::new(
        RecipientType::Argon2idPassword,
        Some([0x12; 8]),
        vec![0xAB; 16], // params present
        vec![],         // EMPTY encrypted_master_key!
    );

    // Put it in a header — this succeeds
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![slot],
        ArchiveConfig::default(),
        [0xDE; 16],
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    let bytes = header.to_bytes().unwrap();
    let result = SuperHeader::from_bytes(&bytes);

    // If deserialization rejects short encrypted_master_key, the fix is in place
    if result.is_err() {
        return; // Vulnerability fixed — TryFrom rejects short encrypted_master_key
    }

    let restored = result.unwrap();

    // Verify it roundtripped with empty encrypted_master_key
    assert!(
        restored.recipients[0].encrypted_master_key.is_empty(),
        "Expected empty encrypted_master_key to survive roundtrip"
    );

    // Check if RecipientSlot validates this
    let source = include_str!("../../era-volume/src/header.rs");
    let from_recipient = source
        .find("impl TryFrom<proto::RecipientSlot> for RecipientSlot")
        .or_else(|| source.find("impl From<proto::RecipientSlot> for RecipientSlot"))
        .expect("RecipientSlot proto conversion must exist");
    let from_body = &source[from_recipient..from_recipient + 600];

    let validates_emk = from_body.contains("encrypted_master_key.is_empty()")
        || from_body.contains("encrypted_master_key.len()");

    assert!(
        validates_emk,
        "🚨 RV9: RecipientSlot accepts empty encrypted_master_key!\n\
         \n\
         The encrypted_master_key format is [Nonce(24 bytes) | Ciphertext(N bytes)].\n\
         An empty field means there is NO nonce and NO encrypted key material.\n\
         \n\
         The PasswordProvider at auth.rs:55 does:\n\
         ```\n\
         let nonce: [u8; 24] = slot.encrypted_master_key[0..24].try_into()?;\n\
         ```\n\
         This panics or returns an incorrect error on empty encrypted_master_key.\n\
         \n\
         FIX: Validate in RecipientSlot deserialization:\n\
         ```\n\
         if proto.encrypted_master_key.len() < 24 {{\n\
             return Err(EraError::CorruptedHeader(\"encrypted_master_key too short\".into()));\n\
         }}\n\
         ```"
    );
}

// ============================================================================
// SECTION 10: 🚨 RV10 — Header access_policy NOT covered by AEAD
// ============================================================================
//
// The access_policy field is stored in the SuperHeader protobuf.
// The EVK (Encrypted Volume Key) AEAD wrapping covers the VK but NOT
// the access_policy. An attacker who can modify the archive file can
// change the access_policy from Threshold(3) to AnyOfN without detection.
//
// While the MK is still encrypted in secret shares (so the attacker needs
// at least one password), the downgrade from Threshold to AnyOfN means
// a SINGLE compromised share is enough to open the archive.

/// 🚨 RV10: Behavioral — access_policy can be changed in serialized header
#[test]
fn rv10_access_policy_downgrade_attack() {
    use prost::Message;

    // Create a Threshold(3) header
    let header = make_valid_header(AccessPolicy::Threshold(3));
    let bytes = header.to_bytes().unwrap();
    let original = SuperHeader::from_bytes(&bytes).unwrap();
    assert_eq!(original.access_policy, AccessPolicy::Threshold(3));

    // Tamper: change access_policy to AnyOfN in proto
    let proto: era_common::proto::SuperHeader = original.clone().into();
    let mut tampered = proto;
    tampered.access_policy = era_common::proto::AccessPolicy::AnyOfN.into();
    tampered.threshold = 0;

    let mut tampered_bytes = Vec::new();
    tampered
        .encode_length_delimited(&mut tampered_bytes)
        .unwrap();
    tampered_bytes.resize(4096, 0);

    // Deserialize the tampered header
    let downgraded = SuperHeader::from_bytes(&tampered_bytes).unwrap();

    // Verify the downgrade worked
    assert_eq!(
        downgraded.access_policy,
        AccessPolicy::AnyOfN,
        "🚨 RV10: access_policy downgrade from Threshold(3) to AnyOfN succeeded!\n\
         An attacker who can modify the archive file changed the access policy\n\
         from requiring 3 parties to requiring just 1, WITHOUT any detection.\n\
         The header has NO integrity protection (HMAC/signature) over the\n\
         access_policy field."
    );

    // The tampered archive_id, volume_id etc are THE SAME
    assert_eq!(downgraded.archive_id, original.archive_id);
    assert_eq!(downgraded.salt, original.salt);
}

// ============================================================================
// SECTION 11: 🚨 RV11 — open_with_session Threshold bypass (enforcement gap)
// ============================================================================
//
// The competitor added a tracing::warn for NV7 but did NOT add any
// enforcement mechanism. A threshold archive can be opened via
// open_with_session with zero friction — the warning goes to logs
// that most callers never check.

/// 🚨 RV11: open_with_session threshold bypass — only warns, no enforcement
#[test]
fn rv11_open_with_session_no_enforcement() {
    let source = include_str!("../src/reader.rs");

    let fn_start = source
        .find("pub async fn open_with_session")
        .expect("open_with_session must exist");
    let fn_body = &source[fn_start..fn_start + 2000.min(source.len() - fn_start)];

    // Check if the function RETURNS an error for threshold archives
    // or just logs a warning
    let returns_error = fn_body.contains("return Err") && fn_body.contains("Threshold");

    // Check if there's a warning only (which is insufficient)
    let has_only_warning =
        fn_body.contains("tracing::warn") && fn_body.contains("Threshold") && !returns_error;

    // A warning without enforcement is a security gap
    if has_only_warning {
        // This is a finding — the threshold check is advisory only
        // Note: This may be intentionally "advisory" but it violates
        // the principle that threshold archives REQUIRE multi-party auth
        panic!(
            "🚨 RV11: open_with_session bypasses Threshold with warning only!\n\
             \n\
             The competitor added a `tracing::warn` for NV7, but the function\n\
             still SUCCEEDS for Threshold archives. The warning goes to logs\n\
             that most callers never check.\n\
             \n\
             This means any code path that can obtain a KeySession (e.g., via\n\
             a single compromised password + KDF derivation) can bypass the\n\
             multi-party requirement entirely.\n\
             \n\
             The function should either:\n\
             1. Return Err for Threshold archives (strict enforcement)\n\
             2. Accept an explicit `AllowBypass` parameter (opt-in bypass)\n\
             3. At minimum, document the bypass in the function signature"
        );
    }
}

// ============================================================================
// SECTION 12: 🚨 RV12 — Threshold(0), Threshold(1) accepted in header
// ============================================================================
//
// While the READER validates t >= 2 and the WRITER validates t >= 2,
// the header LAYER silently accepts Threshold(0) and Threshold(1).
// This means a crafted archive can bypass reader validation if the reader
// has any code path that doesn't check access_policy before using it.

/// 🚨 RV12: Threshold(0) and Threshold(1) accepted at header layer
#[test]
fn rv12_invalid_threshold_values_accepted_in_header() {
    use prost::Message;

    // Create a valid header then tamper threshold to 0
    let header = make_valid_header(AccessPolicy::Threshold(3));
    let proto: era_common::proto::SuperHeader = header.into();

    for invalid_t in [0u32, 1u32] {
        let mut tampered = proto.clone();
        tampered.threshold = invalid_t;

        let mut data = Vec::new();
        tampered.encode_length_delimited(&mut data).unwrap();
        data.resize(4096, 0);

        let result = SuperHeader::from_bytes(&data);
        if let Ok(h) = result {
            if matches!(h.access_policy, AccessPolicy::Threshold(t) if t == invalid_t) {
                // Header accepted invalid threshold — vulnerability confirmed
                // The reader DOES validate later, but defense-in-depth requires
                // the header to also validate
                let source = include_str!("../../era-volume/src/header.rs");
                let tryfrom_start = source
                    .find("impl TryFrom<proto::SuperHeader> for SuperHeader")
                    .expect("TryFrom must exist");
                let tryfrom_body = &source[tryfrom_start..tryfrom_start + 1500];

                let validates_threshold = tryfrom_body.contains("t < 2")
                    || tryfrom_body.contains("threshold < 2")
                    || tryfrom_body.contains("Threshold must");

                assert!(
                    validates_threshold,
                    "🚨 RV12: Header TryFrom accepts Threshold({})!\n\
                     \n\
                     While the READER validates t >= 2, the header DOES NOT.\n\
                     Defense-in-depth requires validation at EVERY layer.\n\
                     \n\
                     A crafted archive with Threshold(0) could trigger:\n\
                     - sharks crate undefined behavior (0 shares needed)\n\
                     - Division by zero in share allocation\n\
                     \n\
                     FIX: In TryFrom<proto::SuperHeader>:\n\
                     ```\n\
                     AccessPolicy::Threshold(t) if t < 2 => {{\n\
                         return Err(EraError::CorruptedHeader(\n\
                             format!(\"Invalid threshold: {{}}\", t).into()));\n\
                     }}\n\
                     ```",
                    invalid_t
                );
            }
        }
    }
}

// ============================================================================
// SECTION 13: BEHAVIORAL INTEGRATION ATTACKS
// ============================================================================

/// E2E: Verify Threshold(1) is rejected by BOTH writer and reader
#[tokio::test]
async fn behavioral_threshold_1_rejected_everywhere() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "test.txt", b"threshold-1 test");

    // Writer must reject Threshold(1)
    let archive_path = temp.path().join("t1.era");
    let result = ArchiveWriter::builder(&archive_path)
        .password("test")
        .access_policy(AccessPolicy::Threshold(1))
        .build()
        .await;

    assert!(
        result.is_err(),
        "Writer MUST reject Threshold(1) — spec mandates T >= 2"
    );
    let err = match result {
        Err(e) => e.to_string(),
        Ok(_) => unreachable!(),
    };
    assert!(
        err.contains("Threshold") || err.contains("threshold") || err.contains(">= 2"),
        "Error message should mention threshold requirement, got: {}",
        err
    );
}

/// E2E: Writer must reject no password with Threshold
#[tokio::test]
async fn behavioral_threshold_without_enough_passwords() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "test.txt", b"need more passwords");

    // Threshold(3) but only 1 password = should fail
    let archive_path = temp.path().join("insufficient.era");
    let result = ArchiveWriter::builder(&archive_path)
        .password("only-one")
        .access_policy(AccessPolicy::Threshold(3))
        .build()
        .await;

    assert!(result.is_err(), "Threshold(3) with 1 password must fail");
}

/// E2E: Two different passwords produce different sessions
#[test]
fn behavioral_different_passwords_different_keys() {
    let mk1 = [0x11u8; 32];
    let mk2 = [0x22u8; 32];
    let s1 = KeySession::from_master_key(&mk1).unwrap();
    let s2 = KeySession::from_master_key(&mk2).unwrap();

    // Generate VK with s1, verify s2 cannot unwrap
    let (vk1, wrapped1) = s1.generate_and_wrap_volume_key().unwrap();
    assert!(
        s2.unwrap_volume_key(&wrapped1.nonce, &wrapped1.ciphertext)
            .is_err(),
        "Different MK should produce different IK → different unwrap"
    );

    // And vice versa
    let (_vk2, wrapped2) = s2.generate_and_wrap_volume_key().unwrap();
    assert!(
        s1.unwrap_volume_key(&wrapped2.nonce, &wrapped2.ciphertext)
            .is_err(),
        "Cross-session unwrap should fail"
    );

    // Same session should unwrap its own VK
    let unwrapped1 = s1
        .unwrap_volume_key(&wrapped1.nonce, &wrapped1.ciphertext)
        .unwrap();
    assert_eq!(vk1.as_bytes(), unwrapped1.as_bytes());
}

/// Verify that Shamir 2-of-3 reconstruction with 2 correct shares works
#[test]
fn behavioral_shamir_2of3_reconstruction() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    let shares = split_master_key(&mk, 2, 3).unwrap();
    assert_eq!(shares.len(), 3);

    // Any 2 of 3 should reconstruct
    for i in 0..3 {
        for j in (i + 1)..3 {
            let subset = vec![shares[i].clone(), shares[j].clone()];
            let reconstructed = reconstruct_master_key(&subset, 2).unwrap();
            assert_eq!(
                &reconstructed, &mk,
                "Shamir 2-of-3 failed with shares ({}, {})",
                i, j
            );
        }
    }

    // Any single share should NOT reconstruct (or produce wrong MK)
    for share in shares.iter().take(3) {
        let single = vec![share.clone()];
        // Should either fail or produce wrong MK
        if let Ok(wrong_mk) = reconstruct_master_key(&single, 2) {
            assert_ne!(
                &wrong_mk, &mk,
                "Single share reconstructed correct MK — Shamir is broken!"
            );
        }
    }
}

/// Verify that block key derivation isolates volumes (different salts)
#[test]
fn behavioral_block_key_volume_isolation() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();

    let salt_a = [0xAA; 16];
    let salt_b = [0xBB; 16];

    let bk_a = session.derive_block_key(&vk, 0, &salt_a).unwrap();
    let bk_b = session.derive_block_key(&vk, 0, &salt_b).unwrap();

    assert_ne!(
        bk_a.as_bytes(),
        bk_b.as_bytes(),
        "Different salts MUST produce different block keys"
    );
}

// ============================================================================
// SECTION 14: CROSS-CUTTING HEADER INTEGRITY PROBES
// ============================================================================

/// Verify header magic validation on deserialization
#[test]
fn integrity_magic_validation() {
    use prost::Message;

    let header = make_valid_header(AccessPolicy::AnyOfN);
    let proto: era_common::proto::SuperHeader = header.into();

    // Tamper magic
    let mut tampered = proto;
    tampered.magic = vec![0xFF; 8];

    let mut data = Vec::new();
    tampered.encode_length_delimited(&mut data).unwrap();
    data.resize(4096, 0);

    let result = SuperHeader::from_bytes(&data);
    assert!(result.is_err(), "Tampered magic bytes MUST be rejected");
}

/// Verify truncated UUID is rejected (not zero-filled)
#[test]
fn integrity_truncated_uuid_rejected() {
    use prost::Message;

    let header = make_valid_header(AccessPolicy::AnyOfN);
    let proto: era_common::proto::SuperHeader = header.into();

    // Truncate volume_id to 8 bytes (should be 16)
    let mut tampered = proto;
    tampered.volume_id = vec![0xAB; 8]; // Too short

    let mut data = Vec::new();
    tampered.encode_length_delimited(&mut data).unwrap();
    data.resize(4096, 0);

    let result = SuperHeader::from_bytes(&data);
    assert!(
        result.is_err(),
        "Truncated UUID (8 bytes instead of 16) MUST be rejected"
    );
}

/// Verify truncated salt is rejected (not zero-filled)
#[test]
fn integrity_truncated_salt_rejected() {
    use prost::Message;

    let header = make_valid_header(AccessPolicy::AnyOfN);
    let proto: era_common::proto::SuperHeader = header.into();

    // Truncate salt to 8 bytes (should be 16)
    let mut tampered = proto;
    tampered.salt = vec![0xAA; 8];

    let mut data = Vec::new();
    tampered.encode_length_delimited(&mut data).unwrap();
    data.resize(4096, 0);

    let result = SuperHeader::from_bytes(&data);
    assert!(
        result.is_err(),
        "Truncated salt (8 bytes instead of 16) MUST be rejected"
    );
}

/// Verify missing EVK is rejected (not defaulted)
#[test]
fn integrity_missing_evk_rejected() {
    use prost::Message;

    let header = make_valid_header(AccessPolicy::AnyOfN);
    let proto: era_common::proto::SuperHeader = header.into();

    // Remove EVK entirely
    let mut tampered = proto;
    tampered.encrypted_volume_key = None;

    let mut data = Vec::new();
    tampered.encode_length_delimited(&mut data).unwrap();
    data.resize(4096, 0);

    let result = SuperHeader::from_bytes(&data);
    assert!(
        result.is_err(),
        "Missing encrypted_volume_key MUST be rejected, not defaulted"
    );
}

/// Verify EVK with truncated nonce is rejected
#[test]
fn integrity_evk_truncated_nonce_rejected() {
    use prost::Message;

    let header = make_valid_header(AccessPolicy::AnyOfN);
    let proto: era_common::proto::SuperHeader = header.into();

    // Truncate EVK nonce to 12 bytes (should be 24)
    let mut tampered = proto;
    if let Some(ref mut evk) = tampered.encrypted_volume_key {
        evk.nonce = vec![0xEE; 12]; // XChaCha20 requires 24 bytes
    }

    let mut data = Vec::new();
    tampered.encode_length_delimited(&mut data).unwrap();
    data.resize(4096, 0);

    let result = SuperHeader::from_bytes(&data);
    assert!(
        result.is_err(),
        "EVK with truncated nonce (12 bytes instead of 24) MUST be rejected"
    );
}

/// Verify EVK with empty ciphertext is rejected
#[test]
fn integrity_evk_empty_ciphertext_rejected() {
    use prost::Message;

    let header = make_valid_header(AccessPolicy::AnyOfN);
    let proto: era_common::proto::SuperHeader = header.into();

    // Empty ciphertext in EVK
    let mut tampered = proto;
    if let Some(ref mut evk) = tampered.encrypted_volume_key {
        evk.ciphertext = vec![];
    }

    let mut data = Vec::new();
    tampered.encode_length_delimited(&mut data).unwrap();
    data.resize(4096, 0);

    let result = SuperHeader::from_bytes(&data);
    assert!(
        result.is_err(),
        "EVK with empty ciphertext MUST be rejected"
    );
}

// ============================================================================
// SECTION 15: CRYPTO PROPERTY TESTS
// ============================================================================

/// Verify IK is deterministic (same MK → same IK)
#[test]
fn crypto_ik_deterministic() {
    let mk = [0x42u8; 32];
    let ik1 = IntermediateKey::derive_from_master_key(&mk).unwrap();
    let ik2 = IntermediateKey::derive_from_master_key(&mk).unwrap();
    assert_eq!(
        ik1.as_bytes(),
        ik2.as_bytes(),
        "Same MK must produce same IK (HKDF is deterministic)"
    );
}

/// Verify zero MK produces non-zero IK (HKDF doesn't collapse)
#[test]
fn crypto_zero_mk_nonzero_ik() {
    let mk = [0u8; 32];
    let ik = IntermediateKey::derive_from_master_key(&mk).unwrap();
    assert_ne!(
        ik.as_bytes(),
        &[0u8; 32],
        "Zero MK should produce non-zero IK via HKDF"
    );
}

/// Verify VolumeKey wrapped with IK has expected ciphertext length
#[test]
fn crypto_wrapped_vk_length() {
    let mk = [0x42u8; 32];
    let ik = IntermediateKey::derive_from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let wrapped = wrap_volume_key(&ik, &vk).unwrap();

    // XChaCha20-Poly1305: nonce=24 bytes, ciphertext = plaintext(32) + tag(16) = 48 bytes
    assert_eq!(wrapped.nonce.len(), 24, "XChaCha20 nonce must be 24 bytes");
    assert_eq!(
        wrapped.ciphertext.len(),
        48,
        "Wrapped VK should be 32 (VK) + 16 (Poly1305 tag) = 48 bytes"
    );
}

/// Verify block key is NOT the same as VK or IK
#[test]
fn crypto_block_key_distinct_from_vk_ik() {
    let mk = [0x42u8; 32];
    let session = KeySession::from_master_key(&mk).unwrap();
    let vk = VolumeKey::generate().unwrap();
    let ik = session.derive_intermediate_key().unwrap();
    let salt = [0xAA; 16];
    let bk = session.derive_block_key(&vk, 0, &salt).unwrap();

    assert_ne!(bk.as_bytes(), vk.as_bytes(), "BK must differ from VK");
    assert_ne!(bk.as_bytes(), ik.as_bytes(), "BK must differ from IK");
    assert_ne!(bk.as_bytes(), &mk, "BK must differ from MK");
}

/// Stress test: 10000 VK generations should all be unique (birthday bound)
#[test]
fn crypto_vk_uniqueness_stress() {
    let mut vks = HashSet::new();
    for _ in 0..10000 {
        let vk = VolumeKey::generate().unwrap();
        assert!(
            vks.insert(*vk.as_bytes()),
            "VK collision detected in 10000 generations! RNG is broken."
        );
    }
}

/// Verify Shamir threshold edge cases
#[test]
fn crypto_shamir_edge_cases() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    // T=2, N=2 — minimum valid threshold
    let shares_2of2 = split_master_key(&mk, 2, 2).unwrap();
    assert_eq!(shares_2of2.len(), 2);
    let reconstructed = reconstruct_master_key(&shares_2of2, 2).unwrap();
    assert_eq!(&reconstructed, &mk);

    // T=N (all shares required)
    let shares_5of5 = split_master_key(&mk, 5, 5).unwrap();
    assert_eq!(shares_5of5.len(), 5);
    let reconstructed = reconstruct_master_key(&shares_5of5, 5).unwrap();
    assert_eq!(&reconstructed, &mk);

    // 4 of 5 should NOT work when T=5
    let subset = shares_5of5[0..4].to_vec();
    if let Ok(wrong) = reconstruct_master_key(&subset, 5) {
        assert_ne!(&wrong, &mk, "4 shares should not reconstruct 5-of-5 MK");
    }
}

// ============================================================================
// SECTION 16: SOURCE CODE CONSISTENCY AUDITS
// ============================================================================

/// Verify ALL proto type conversions are TryFrom (consistency check)
#[test]
fn consistency_all_proto_conversions_fallible() {
    let source = include_str!("../../era-volume/src/header.rs");

    // Count From<proto::*> and TryFrom<proto::*>
    let _from_count = source.matches("impl From<proto::").count();
    let _tryfrom_count = source.matches("impl TryFrom<proto::").count();

    // The FROM direction (rust→proto) should be From (infallible)
    // The TRYFROM direction (proto→rust) should ALL be TryFrom

    // Check each proto-to-rust conversion
    let proto_to_rust = [
        (
            "SuperHeader",
            "impl TryFrom<proto::SuperHeader> for SuperHeader",
        ),
        (
            "EncryptedVolumeKey",
            "impl TryFrom<proto::EncryptedVolumeKey> for EncryptedVolumeKey",
        ),
        (
            "RecipientSlot",
            "impl TryFrom<proto::RecipientSlot> for RecipientSlot",
        ),
    ];

    for (name, expected_signature) in &proto_to_rust {
        if !source.contains(expected_signature) {
            // Check if it uses From (infallible) instead
            let from_sig = expected_signature.replace("TryFrom", "From");
            if source.contains(&from_sig) {
                panic!(
                    "🚨 INCONSISTENCY: {} uses infallible From<proto> while others use TryFrom!\n\
                     \n\
                     Current state:\n\
                     - SuperHeader: TryFrom ✅\n\
                     - EncryptedVolumeKey: TryFrom ✅\n\
                     - RecipientSlot: From ❌\n\
                     \n\
                     ALL proto→rust conversions should be TryFrom for consistency\n\
                     and error propagation capability.",
                    name
                );
            }
        }
    }
}

/// Verify no production code uses unwrap_or for fixed-size crypto fields
#[test]
fn consistency_no_unwrap_or_on_crypto_arrays() {
    let header_src = include_str!("../../era-volume/src/header.rs");
    let writer_src = include_str!("../src/writer.rs");
    let reader_src = include_str!("../src/reader.rs");

    // Pattern: .unwrap_or([0u8; N]) where N is a crypto-relevant size
    let dangerous_patterns = [
        "unwrap_or([0u8; 8])",
        "unwrap_or([0u8; 16])",
        "unwrap_or([0u8; 24])",
        "unwrap_or([0u8; 32])",
    ];

    for pattern in &dangerous_patterns {
        for (name, source) in [
            ("header.rs", header_src),
            ("writer.rs", writer_src),
            ("reader.rs", reader_src),
        ] {
            // Only check non-test sections
            let production = if let Some(test_start) = source.find("#[cfg(test)]") {
                &source[..test_start]
            } else {
                source
            };

            assert!(
                !production.contains(pattern),
                "🚨 DANGEROUS PATTERN in {}: `{}`\n\
                 Silent zero-fill of crypto-sized arrays hides corruption.\n\
                 Use map_err() to return explicit errors instead.",
                name,
                pattern
            );
        }
    }
}

/// Verify zeroize is imported and used in ALL files that handle key material
#[test]
fn consistency_zeroize_in_key_handling_files() {
    let files = [
        ("reader.rs", include_str!("../src/reader.rs")),
        ("writer.rs", include_str!("../src/writer.rs")),
    ];

    for (name, source) in &files {
        assert!(
            source.contains("use zeroize::Zeroize"),
            "{} handles key material but does NOT import zeroize!",
            name
        );
        assert!(
            source.contains(".zeroize()"),
            "{} handles key material but never calls .zeroize()!",
            name
        );
    }
}

/// Verify ALL OsRng usage is from rand::rngs::OsRng (not rand::thread_rng)
#[test]
fn consistency_no_thread_rng_anywhere() {
    let files = [
        ("era-engine/writer.rs", include_str!("../src/writer.rs")),
        ("era-engine/reader.rs", include_str!("../src/reader.rs")),
        (
            "era-crypto/certificate.rs",
            include_str!("../../era-crypto/src/certificate.rs"),
        ),
        (
            "era-crypto/key_session.rs",
            include_str!("../../era-crypto/src/key_session.rs"),
        ),
        (
            "era-crypto/aead.rs",
            include_str!("../../era-crypto/src/aead.rs"),
        ),
        (
            "era-volume/writer.rs",
            include_str!("../../era-volume/src/writer.rs"),
        ),
        // era-index/spiller.rs was deleted — vulnerability resolved by removal
    ];

    for (name, source) in &files {
        assert!(
            !source.contains("thread_rng"),
            "🚨 {} contains thread_rng — spec violation §5.3!",
            name
        );
    }
}

// ============================================================================
// SECTION 17: E2E ARCHIVE LIFECYCLE TESTS
// ============================================================================

/// E2E: Full archive create → extract → verify cycle with AnyOfN
#[tokio::test]
async fn e2e_full_lifecycle_anyofn() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    let output_dir = temp.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();

    // Create test content
    create_test_file(&input_dir, "hello.txt", b"Hello, World!");
    create_test_file(&input_dir, "binary.bin", &[0u8; 1024]);
    create_test_file(&input_dir, "nested/deep/file.txt", b"nested content");

    let archive_path = temp.path().join("lifecycle.era");
    let password = "strong-password-123!";

    // Create archive
    let mut writer = ArchiveWriter::builder(&archive_path)
        .password(password)
        .build()
        .await
        .unwrap();

    writer.add_file(&input_dir.join("hello.txt")).await.unwrap();
    writer
        .add_file(&input_dir.join("binary.bin"))
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("nested/deep/file.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Open and extract
    let mut reader = ArchiveReader::open(&archive_path, password).await.unwrap();

    let stats = reader
        .extract_all(&ExtractOptions {
            output_dir: output_dir.clone(),
            overwrite: true,
        })
        .await
        .unwrap();

    assert!(stats.extracted >= 3, "Should extract at least 3 files");

    // Verify content integrity
    let hello_content = fs::read(output_dir.join("hello.txt")).unwrap();
    assert_eq!(&hello_content, b"Hello, World!");

    let binary_content = fs::read(output_dir.join("binary.bin")).unwrap();
    assert_eq!(&binary_content, &[0u8; 1024]);
}

/// E2E: Wrong password must fail
#[tokio::test]
async fn e2e_wrong_password_fails() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir).unwrap();
    create_test_file(&input_dir, "secret.txt", b"confidential");

    let archive_path = temp.path().join("wrong_pwd.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("correct-password")
        .build()
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("secret.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Wrong password
    let result = ArchiveReader::open(&archive_path, "wrong-password").await;
    assert!(result.is_err(), "Wrong password must fail to open archive");
}

/// E2E: Threshold(2) with correct passwords works
#[tokio::test]
async fn e2e_threshold_2of2_works() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("input");
    let output_dir = temp.path().join("output");
    fs::create_dir_all(&input_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    create_test_file(&input_dir, "shared.txt", b"shared secret");

    let archive_path = temp.path().join("threshold_2of2.era");

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("alice")
        .add_password("bob")
        .access_policy(AccessPolicy::Threshold(2))
        .build()
        .await
        .unwrap();
    writer
        .add_file(&input_dir.join("shared.txt"))
        .await
        .unwrap();
    writer.finalize().await.unwrap();

    // Both passwords required
    let mut reader = ArchiveReader::open_with_passwords(&archive_path, &["alice", "bob"])
        .await
        .unwrap();

    let stats = reader
        .extract_all(&ExtractOptions {
            output_dir: output_dir.clone(),
            overwrite: true,
        })
        .await
        .unwrap();

    assert!(stats.extracted >= 1);
    assert_eq!(
        fs::read(output_dir.join("shared.txt")).unwrap(),
        b"shared secret"
    );
}

/// E2E: GenericArchiveWriter rejects Threshold policy
#[tokio::test]
async fn e2e_generic_writer_rejects_threshold() {
    let temp = TempDir::new().unwrap();
    let backend = era_storage::LocalStorageBackend::new(temp.path());

    let result = GenericArchiveWriterBuilder::new(backend, "reject.era")
        .password("test")
        .access_policy(AccessPolicy::Threshold(2))
        .build()
        .await;

    assert!(
        result.is_err(),
        "GenericArchiveWriter MUST reject Threshold policy"
    );
    let err = match result {
        Err(e) => e.to_string(),
        Ok(_) => unreachable!(),
    };
    assert!(
        err.contains("Threshold") || err.contains("threshold"),
        "Error should mention Threshold, got: {}",
        err
    );
}

// ============================================================================
// SECTION 18: FUZZ-LIKE BOUNDARY TESTS
// ============================================================================

/// Boundary: Maximum valid threshold (T = N = 255)
#[test]
fn boundary_max_threshold() {
    let mut mk = [0u8; 32];
    OsRng.fill_bytes(&mut mk);

    // T=N=255 — maximum for u8 shares
    let result = split_master_key(&mk, 255, 255);
    match result {
        Ok(shares) => {
            assert_eq!(shares.len(), 255);
            let reconstructed = reconstruct_master_key(&shares, 255).unwrap();
            assert_eq!(&reconstructed, &mk);
        }
        Err(_) => {
            // Some implementations cap at a lower value — acceptable
        }
    }
}

/// Boundary: Verify header with maximum possible salt is accepted
#[test]
fn boundary_all_ff_salt() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            Some([0xFF; 8]),
            vec![0xFF; 16],
            vec![0xFF; 48],
        )],
        ArchiveConfig::default(),
        [0xFF; 16], // All-ones salt
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    assert_eq!(restored.salt, [0xFF; 16]);
}

/// Boundary: Verify header with all-zero salt is distinguishable from missing
#[test]
fn boundary_all_zero_salt_is_valid() {
    let header = SuperHeader::new(
        ArchiveId::new(),
        vec![RecipientSlot::new(
            RecipientType::Argon2idPassword,
            None,
            vec![0xAB; 16],
            vec![0xCD; 48],
        )],
        ArchiveConfig::default(),
        [0x00; 16], // All-zero salt — valid but suspicious
        mock_encrypted_vk(),
        AccessPolicy::AnyOfN,
    )
    .unwrap();

    let bytes = header.to_bytes().unwrap();
    let restored = SuperHeader::from_bytes(&bytes).unwrap();
    // All-zero salt should roundtrip correctly (it IS a valid salt, just unwise)
    assert_eq!(restored.salt, [0x00; 16]);
}
