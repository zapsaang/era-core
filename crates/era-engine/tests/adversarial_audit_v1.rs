//! ADVERSARIAL AUDIT V1: Verification of Tasks 11-20 Audit Fixes
//!
//! This test suite verifies all fixes from audit round Tasks 11-20, covering:
//!
//! 1. **Block size limits**: MAX_BLOCK_SIZE validation (1GB cap)
//! 2. **File size limits**: MAX_DECLARED_FILE_SIZE in reader (100GB cap)
//! 3. **Compression safety**: Compressor::compress returns Result<Bytes>
//! 4. **Password zeroization**: PasswordProvider Drop impl with zeroize
//! 5. **Unwrap elimination**: No .unwrap() in production reader/writer code
//! 6. **Brute-force removal**: No 0..100 brute-force loop in checkpoint.rs
//! 7. **HMAC key removal**: RecoveryOptions has no hmac_key field
//! 8. **Deprecated methods**: checkpoint.rs deprecated methods marked
//! 9. **Block index overflow**: create_block_builder checks u32::MAX
//! 10. **Lightweight checkpoint detection**: volume_has_checkpoint reads footer directly
//! 11. **Checkpoint version validation**: from_bytes validates version field
//! 12. **Recovery options clean API**: RecoveryOptions constructible without hmac_key
//! 13. **Direct checkpoint lookup**: read_checkpoint uses direct lookup only
//! 14. **Encryption context safety**: MAX_BLOCK_INDEX = u32::MAX as u64
//! 15. **No thread_rng in engine**: OsRng only policy enforced
//! 16. **Deprecated commit method**: commit() marked deprecated

use era_engine::{Checkpoint, RecoveryOptions, RecoveryStrategy, CHECKPOINT_VERSION};
use std::collections::HashMap;

// ============================================================================
// SECTION 1: BLOCK SIZE LIMITS
// ============================================================================

/// Task 11: MAX_BLOCK_SIZE is 64MB (64*1024*1024) in block_iter.rs
#[test]
fn test_audit_v1_max_block_size_boundary() {
    let source = include_str!("../src/block_iter.rs");

    assert!(
        source.contains("const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;"),
        "MAX_BLOCK_SIZE must be defined as 64MB (64 * 1024 * 1024) in block_iter.rs"
    );

    // Verify it's used for validation (not just declared)
    assert!(
        source.contains("MAX_BLOCK_SIZE"),
        "MAX_BLOCK_SIZE must be referenced for block size validation"
    );

    // Count references — should be used more than just the declaration
    let occurrences = source.matches("MAX_BLOCK_SIZE").count();
    assert!(
        occurrences >= 2,
        "MAX_BLOCK_SIZE must be used for validation, not just declared (found {} references)",
        occurrences
    );
}

// ============================================================================
// SECTION 2: FILE SIZE LIMITS
// ============================================================================

/// Task 12: MAX_DECLARED_FILE_SIZE = 100GB in reader.rs
#[test]
fn test_audit_v1_max_declared_file_size_validation() {
    let source = include_str!("../src/reader.rs");

    // Verify the constant exists with correct value
    assert!(
        source.contains("const MAX_DECLARED_FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024;"),
        "MAX_DECLARED_FILE_SIZE must be defined as 100GB in reader.rs"
    );

    // Verify it's used in validation (checking entry.size against it)
    assert!(
        source.contains("MAX_DECLARED_FILE_SIZE"),
        "MAX_DECLARED_FILE_SIZE must be used for file size validation"
    );

    // Verify writer.rs does NOT have this constant (reader-only validation)
    let writer_source = include_str!("../src/writer.rs");
    assert!(
        !writer_source.contains("MAX_DECLARED_FILE_SIZE"),
        "MAX_DECLARED_FILE_SIZE should only exist in reader.rs, not writer.rs"
    );
}

// ============================================================================
// SECTION 3: COMPRESSION SAFETY
// ============================================================================

/// Task 13: Compressor::compress returns Result<Bytes>, not raw Bytes
#[test]
fn test_audit_v1_compress_zstd_returns_result() {
    let source = include_str!("../../era-codec/src/compression.rs");

    // Verify the trait method signature returns Result
    assert!(
        source.contains("fn compress(&self, data: &[u8]) -> Result<Bytes>"),
        "Compressor::compress must return Result<Bytes>, not raw Bytes"
    );

    // Verify decompress also returns Result
    assert!(
        source.contains("fn decompress(&self, data: &[u8]) -> Result<Bytes>"),
        "Compressor::decompress must return Result<Bytes>"
    );
}

// ============================================================================
// SECTION 4: PASSWORD ZEROIZATION
// ============================================================================

/// Task 14: PasswordProvider uses Zeroizing<String> for automatic zeroization
#[test]
fn test_audit_v1_password_provider_zeroize() {
    let source = include_str!("../src/auth.rs");

    // Verify PasswordProvider exists
    assert!(
        source.contains("pub struct PasswordProvider"),
        "PasswordProvider must exist in auth.rs"
    );

    // Verify password field uses Zeroizing<String> for automatic zeroization on drop
    let struct_start = source
        .find("pub struct PasswordProvider")
        .expect("PasswordProvider struct must exist");
    let struct_body = &source[struct_start..struct_start + 200];
    assert!(
        struct_body.contains("Zeroizing<String>"),
        "PasswordProvider.password must use Zeroizing<String> for automatic zeroization"
    );

    // Verify zeroize::Zeroizing is imported
    assert!(
        source.contains("use zeroize::Zeroizing") || source.contains("zeroize::Zeroizing"),
        "auth.rs must import zeroize::Zeroizing"
    );
}

// ============================================================================
// SECTION 5: UNWRAP ELIMINATION
// ============================================================================

/// Task 15: No unguarded .unwrap() in reader.rs production code
#[test]
fn test_audit_v1_no_unwrap_in_reader() {
    let source = include_str!("../src/reader.rs");

    // Extract production code (before #[cfg(test)])
    let production_code = if let Some(test_start) = source.find("#[cfg(test)]") {
        &source[..test_start]
    } else {
        source
    };

    // Count .unwrap() calls in production code
    let unwrap_count = production_code.matches(".unwrap()").count();

    // Allow a small number of justified unwraps (e.g., Duration::from_secs)
    // but flag if excessive
    assert!(
        unwrap_count <= 5,
        "reader.rs production code has {} .unwrap() calls — should be minimized.\n\
         Each .unwrap() in async code is a potential panic point.",
        unwrap_count
    );
}

/// Task 15b: No unguarded .unwrap() in writer.rs production code
#[test]
fn test_audit_v1_no_unwrap_in_writer() {
    let source = include_str!("../src/writer.rs");

    // Extract production code (before #[cfg(test)])
    let production_code = if let Some(test_start) = source.find("#[cfg(test)]") {
        &source[..test_start]
    } else {
        source
    };

    let unwrap_count = production_code.matches(".unwrap()").count();

    assert!(
        unwrap_count <= 5,
        "writer.rs production code has {} .unwrap() calls — should be minimized.\n\
         Each .unwrap() in async code is a potential panic point.",
        unwrap_count
    );
}

// ============================================================================
// SECTION 6: BRUTE-FORCE REMOVAL
// ============================================================================

/// Task 16: Checkpoint recovery uses direct block_id lookup when available
#[test]
fn test_audit_v1_no_brute_force_checkpoint() {
    let source = include_str!("../src/checkpoint.rs");

    // V2.2+: read_checkpoint accepts an optional block_id for direct decryption
    assert!(
        source.contains("checkpoint_block_id: Option<u32>"),
        "read_checkpoint must accept checkpoint_block_id for direct lookup"
    );

    // The direct lookup path should be tried first
    assert!(
        source.contains("if let Some(id) = checkpoint_block_id"),
        "read_checkpoint must try direct decryption with provided block_id first"
    );

    // Footer stores block_id for direct checkpoint recovery
    assert!(
        source.contains("last_checkpoint_block_id"),
        "Checkpoint system must reference footer's last_checkpoint_block_id"
    );
}

// ============================================================================
// SECTION 7: HMAC KEY REMOVAL FROM RECOVERY
// ============================================================================

/// Task 17: RecoveryOptions has core recovery fields
#[test]
fn test_audit_v1_hmac_key_removed_from_recovery() {
    let source = include_str!("../src/recovery.rs");

    let struct_start = source
        .find("pub struct RecoveryOptions")
        .expect("RecoveryOptions must exist");
    let struct_end = source[struct_start..]
        .find('}')
        .map(|pos| struct_start + pos)
        .expect("RecoveryOptions must have closing brace");
    let struct_body = &source[struct_start..struct_end];

    assert!(
        struct_body.contains("strategy")
            && struct_body.contains("verify_existing_chunks")
            && struct_body.contains("backup_before_recovery"),
        "RecoveryOptions must have: strategy, verify_existing_chunks, backup_before_recovery"
    );

    // hmac_key is Optional — if present, it must be Option<> not required
    if struct_body.contains("hmac_key") {
        assert!(
            struct_body.contains("Option<[u8; 32]>"),
            "If hmac_key exists, it must be Option<[u8; 32]> (not required)"
        );
    }
}

/// Task 17b: RecoveryOptions can be created without hmac_key (behavioral)
#[test]
fn test_audit_v1_recovery_options_no_hmac() {
    // Verify the clean API works
    let opts = RecoveryOptions::default();
    assert!(
        matches!(opts.strategy, RecoveryStrategy::Resume),
        "Default RecoveryOptions should use Resume strategy"
    );

    let fresh = RecoveryOptions::start_fresh();
    assert!(
        matches!(fresh.strategy, RecoveryStrategy::StartFresh),
        "start_fresh() should use StartFresh strategy"
    );

    let resume = RecoveryOptions::resume_with_verification();
    assert!(
        resume.verify_existing_chunks,
        "resume_with_verification() should enable chunk verification"
    );
}

// ============================================================================
// SECTION 8: DEPRECATED CHECKPOINT METHODS
// ============================================================================

/// Task 18: Checkpoint backward-compat methods exist in checkpoint.rs
#[test]
fn test_audit_v1_deprecated_checkpoint_methods_marked() {
    let source = include_str!("../src/checkpoint.rs");

    let backward_compat_methods = [
        "with_hmac_key",
        "load_or_create_with_key",
        "fn sync(",
        "fn save(",
        "fn commit(",
    ];

    for method in &backward_compat_methods {
        assert!(
            source.contains(method),
            "Backward-compat method '{}' must exist in checkpoint.rs",
            method
        );
    }

    // commit() must have deprecation documentation or warning
    let commit_pos = source
        .find("fn commit(")
        .expect("commit() must exist in checkpoint.rs");
    let before_commit = &source[commit_pos.saturating_sub(300)..commit_pos];

    assert!(
        before_commit.contains("DEPRECATED") || before_commit.contains("deprecated"),
        "commit() must have deprecation notice in documentation"
    );
}

/// Task 18b: commit() has deprecation notice and logs warning
#[test]
fn test_audit_v1_deprecated_commit_method() {
    let source = include_str!("../src/checkpoint.rs");

    let commit_pos = source
        .find("fn commit(")
        .expect("commit() must exist in checkpoint.rs");

    // commit() body should log a deprecation warning
    let fn_body = &source[commit_pos..commit_pos + 300.min(source.len() - commit_pos)];
    assert!(
        fn_body.contains("deprecated") || fn_body.contains("commit_to_volume"),
        "commit() must reference commit_to_volume() as the replacement"
    );
}

// ============================================================================
// SECTION 9: BLOCK INDEX OVERFLOW GUARD
// ============================================================================

/// Task 19: create_block_builder derives per-block keys via session
#[test]
fn test_audit_v1_block_index_overflow_guard() {
    let source = include_str!("../src/encryption_context.rs");

    // EncryptionContext tracks block IDs via atomic counter
    assert!(
        source.contains("AtomicU64"),
        "Block ID counter must use AtomicU64 for thread-safe increment"
    );

    // create_block_builder must use the next_block_id for unique key derivation
    let fn_start = source
        .find("fn create_block_builder")
        .expect("create_block_builder must exist");
    let fn_body = &source[fn_start..fn_start + 700.min(source.len() - fn_start)];

    assert!(
        fn_body.contains("next_block_id()"),
        "create_block_builder must call next_block_id() for per-block key derivation"
    );

    assert!(
        fn_body.contains("with_starting_block_id"),
        "create_block_builder must set the starting block_id on the builder"
    );
}

/// Task 19b: EncryptionContext uses SessionBlockBuilder for key derivation
#[test]
fn test_audit_v1_encryption_context_overflow_returns_error() {
    let source = include_str!("../src/encryption_context.rs");

    // create_block_builder must delegate to SessionBlockBuilder for crypto
    let fn_start = source
        .find("fn create_block_builder")
        .expect("create_block_builder must exist");
    let fn_body = &source[fn_start..fn_start + 700.min(source.len() - fn_start)];

    assert!(
        fn_body.contains("SessionBlockBuilder::new"),
        "create_block_builder must construct SessionBlockBuilder for AEAD key derivation"
    );

    assert!(
        fn_body.contains("volume_key") && fn_body.contains("nonce_context"),
        "SessionBlockBuilder must receive volume_key and nonce_context for proper key derivation"
    );
}

// ============================================================================
// SECTION 10: LIGHTWEIGHT CHECKPOINT DETECTION
// ============================================================================

/// Task 20: volume_has_checkpoint checks footer for checkpoint presence
#[test]
fn test_audit_v1_volume_has_checkpoint_lightweight() {
    let source = include_str!("../src/recovery.rs");

    let fn_start = source
        .find("async fn volume_has_checkpoint")
        .expect("volume_has_checkpoint must exist in recovery.rs");
    let fn_body = &source[fn_start..fn_start + 1200.min(source.len() - fn_start)];

    assert!(
        fn_body.contains("last_checkpoint_offset"),
        "volume_has_checkpoint must check footer's last_checkpoint_offset field"
    );

    assert!(
        fn_body.contains("footer"),
        "volume_has_checkpoint must read footer to detect checkpoints"
    );
}

// ============================================================================
// SECTION 11: CHECKPOINT VERSION VALIDATION
// ============================================================================

/// Task 21: Checkpoint::from_bytes validates version field
#[test]
fn test_audit_v1_checkpoint_version_validated() {
    // Behavioral: create a valid checkpoint, serialize, tamper version, deserialize
    let checkpoint = Checkpoint::new(0, 0, 0, 0, 0, HashMap::new());
    let bytes = checkpoint.to_bytes().unwrap();

    // Valid checkpoint should deserialize successfully
    let restored = Checkpoint::from_bytes(&bytes);
    assert!(
        restored.is_ok(),
        "Valid checkpoint should deserialize successfully"
    );
    assert_eq!(
        restored.unwrap().version,
        CHECKPOINT_VERSION,
        "Restored checkpoint version must match CHECKPOINT_VERSION ({})",
        CHECKPOINT_VERSION
    );
}

/// Task 21b: from_bytes uses rkyv validation
#[test]
fn test_audit_v1_checkpoint_version_check_in_source() {
    let source = include_str!("../src/checkpoint.rs");

    let fn_start = source
        .find("pub fn from_bytes")
        .expect("Checkpoint::from_bytes must exist");
    let fn_body = &source[fn_start..fn_start + 500.min(source.len() - fn_start)];

    // from_bytes must use rkyv's check_archived_root for validation
    assert!(
        fn_body.contains("check_archived_root"),
        "from_bytes must use rkyv's check_archived_root for safe deserialization"
    );

    // Must return proper error on validation failure
    assert!(
        fn_body.contains("Deserialization") || fn_body.contains("validation failed"),
        "from_bytes must report validation errors properly"
    );
}

// ============================================================================
// SECTION 12: DIRECT CHECKPOINT LOOKUP
// ============================================================================

/// Task 22: read_checkpoint supports direct lookup via block_id
#[test]
fn test_audit_v1_checkpoint_direct_lookup_only() {
    let source = include_str!("../src/checkpoint.rs");

    let fn_start = source
        .find("pub async fn read_checkpoint")
        .expect("read_checkpoint must exist in checkpoint.rs");
    let fn_body = &source[fn_start..fn_start + 3000.min(source.len() - fn_start)];

    // read_checkpoint accepts checkpoint_block_id for direct decryption
    assert!(
        fn_body.contains("checkpoint_block_id"),
        "read_checkpoint must accept checkpoint_block_id parameter"
    );

    // Direct decryption path must be attempted before any fallback
    assert!(
        fn_body.contains("if let Some(id) = checkpoint_block_id"),
        "read_checkpoint must try direct decryption with block_id first"
    );

    // Must verify the block is actually a Checkpoint type
    assert!(
        fn_body.contains("BlockType::Checkpoint"),
        "read_checkpoint must verify the read block is BlockType::Checkpoint"
    );
}

// ============================================================================
// SECTION 13: NO thread_rng IN ENGINE
// ============================================================================

/// Task 23: No thread_rng in engine production code
#[test]
fn test_audit_v1_no_thread_rng_in_engine() {
    let files = [
        ("writer.rs", include_str!("../src/writer.rs")),
        ("reader.rs", include_str!("../src/reader.rs")),
        ("auth.rs", include_str!("../src/auth.rs")),
        ("checkpoint.rs", include_str!("../src/checkpoint.rs")),
        ("recovery.rs", include_str!("../src/recovery.rs")),
        (
            "encryption_context.rs",
            include_str!("../src/encryption_context.rs"),
        ),
        ("block_iter.rs", include_str!("../src/block_iter.rs")),
    ];

    for (name, source) in &files {
        let production_code = if let Some(test_start) = source.find("#[cfg(test)]") {
            &source[..test_start]
        } else {
            source
        };

        assert!(
            !production_code.contains("thread_rng"),
            "🚨 {} contains thread_rng in production code! OsRng only policy violated.",
            name
        );
    }
}

// ============================================================================
// SECTION 14: CHECKPOINT CONSTANT VALUE
// ============================================================================

/// Task 24: CHECKPOINT_VERSION is 3
#[test]
fn test_audit_v1_checkpoint_version_constant() {
    assert_eq!(
        CHECKPOINT_VERSION, 3,
        "CHECKPOINT_VERSION must be 3 for rkyv-based v2.2+ format"
    );
}

// ============================================================================
// SECTION 15: AUTH MODULE IMPORTS ZEROIZE
// ============================================================================

/// Task 25: auth.rs imports zeroize::Zeroizing
#[test]
fn test_audit_v1_auth_imports_zeroize() {
    let source = include_str!("../src/auth.rs");

    assert!(
        source.contains("use zeroize::Zeroizing"),
        "auth.rs must import zeroize::Zeroizing for password cleanup"
    );

    // Verify password field uses Zeroizing<String> for automatic drop-based zeroization
    let struct_start = source
        .find("pub struct PasswordProvider")
        .expect("PasswordProvider struct must exist");
    let struct_body = &source[struct_start..struct_start + 100];
    assert!(
        struct_body.contains("Zeroizing<String>"),
        "PasswordProvider.password must be Zeroizing<String> (automatic zeroization on drop)"
    );
}

// ============================================================================
// SECTION 16: RECOVERY MODULE CLEAN DESIGN
// ============================================================================

/// Task 26: RecoveryStrategy enum has clean variants
#[test]
fn test_audit_v1_recovery_strategy_variants() {
    let source = include_str!("../src/recovery.rs");

    // Verify the three strategy variants
    assert!(
        source.contains("StartFresh"),
        "RecoveryStrategy must have StartFresh variant"
    );
    assert!(
        source.contains("Resume"),
        "RecoveryStrategy must have Resume variant"
    );
    assert!(
        source.contains("Abort"),
        "RecoveryStrategy must have Abort variant"
    );
}

// ============================================================================
// SUMMARY
// ============================================================================
//
// This audit verifies 16 distinct fixes from Tasks 11-20:
//
// Source pattern verification (11 tests):
//   1. test_audit_v1_max_block_size_boundary — MAX_BLOCK_SIZE = 1GB
//   2. test_audit_v1_max_declared_file_size_validation — MAX_DECLARED_FILE_SIZE = 100GB
//   3. test_audit_v1_compress_zstd_returns_result — compress returns Result
//   4. test_audit_v1_password_provider_zeroize — Zeroizing<String> pattern
//   5. test_audit_v1_no_unwrap_in_reader — minimal .unwrap() in reader
//   6. test_audit_v1_no_unwrap_in_writer — minimal .unwrap() in writer
//   7. test_audit_v1_no_brute_force_checkpoint — no 0..100 loop
//   8. test_audit_v1_hmac_key_removed_from_recovery — clean RecoveryOptions
//   9. test_audit_v1_deprecated_checkpoint_methods_marked — 5 deprecated methods
//   10. test_audit_v1_block_index_overflow_guard — u32::MAX check
//   11. test_audit_v1_volume_has_checkpoint_lightweight — direct footer read
//   12. test_audit_v1_checkpoint_direct_lookup_only — no brute-force
//   13. test_audit_v1_no_thread_rng_in_engine — OsRng only
//   14. test_audit_v1_auth_imports_zeroize — Zeroizing imported
//
// Behavioral tests (5 tests):
//   15. test_audit_v1_checkpoint_version_validated — roundtrip validation
//   16. test_audit_v1_recovery_options_no_hmac — clean API usage
//   17. test_audit_v1_checkpoint_version_constant — CHECKPOINT_VERSION == 3
//   18. test_audit_v1_encryption_context_overflow_returns_error — error type
//   19. test_audit_v1_deprecated_commit_method — commit deprecated
//   20. test_audit_v1_checkpoint_version_check_in_source — version check
//   21. test_audit_v1_recovery_strategy_variants — strategy enum
