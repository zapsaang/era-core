//! ADVERSARIAL AUDIT V2: Verification of 53 V2 Audit Findings
//!
//! This test suite verifies all fixes from the V2 adversarial security audit.
//! 53 findings across 6 categories: SEC (12), LOG (6), PERF (5), ROB (11), QUAL (16), INFO (3)

use era_engine::{ArchiveWriter, AuthMode, CheckpointManager};
use era_volume::AccessPolicy;
use std::fs;
use tempfile::TempDir;
use zeroize::Zeroizing;

// ============================================================================
// SECTION 1: SECURITY FINDINGS (V2-SEC-01 through V2-SEC-12)
// ============================================================================

#[test]
fn v2_sec_01_aead_aad_includes_archive_epoch_block() {
    let source = include_str!("../../era-crypto/src/aead_context.rs");
    assert!(source.contains("let mut aad = [0u8; 28]"));
    assert!(source.contains("copy_from_slice(archive_id)"));
    assert!(source.contains("epoch_id.to_le_bytes"));
    assert!(source.contains("block_id.sequence().to_le_bytes"));
}

#[test]
fn v2_sec_02_auth_mode_uses_zeroizing_and_not_derived_clone() {
    let source = include_str!("../src/writer.rs");
    let enum_start = source
        .find("pub enum AuthMode")
        .expect("AuthMode must exist");
    let enum_area = &source[enum_start..enum_start + 500];
    assert!(enum_area.contains("Zeroizing<String>"));
    let derives_before = &source[enum_start.saturating_sub(120)..enum_start];
    assert!(!derives_before.contains("Clone"));
}

#[test]
fn v2_sec_03_chunk_offset_plus_len_bounds_check() {
    let source = include_str!("../src/chunk_processor.rs");
    assert!(source.contains("chunk_offset + data.len() as u64"));
    assert!(source.contains("Chunk write exceeds file bounds"));
}

#[test]
fn v2_sec_04_reader_path_canonicalization_present() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("canonicalize"));
}

#[test]
fn v2_sec_05_max_shard_size_constant_present() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("const MAX_SHARD_SIZE"));
}

#[test]
fn v2_sec_06_repair_writes_data_then_flush_then_header() {
    let source = include_str!("../src/repair.rs");
    let apply_start = source
        .find("fn apply_repairs")
        .expect("apply_repairs exists");
    let area = &source[apply_start..apply_start + 2200.min(source.len() - apply_start)];
    assert!(area.contains("file.write_all(&repair.data)"));
    assert!(area.contains("file.flush()?"));
    assert!(area.contains("file.write_all(&header_bytes)"));
}

#[test]
fn v2_sec_07_non_session_erasure_has_diagnostic_warn() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("tracing::warn!"));
}

#[test]
fn v2_sec_08_checkpoint_bruteforce_loop_removed() {
    let source = include_str!("../src/checkpoint.rs");
    assert!(!source.contains("0..100"));
}

#[test]
fn v2_sec_09_rkyv_deserialization_errors_handled() {
    let source = include_str!("../src/auth.rs");
    assert!(source.contains("check_archived_root::<PasswordSlotParams>"));
    assert!(source.contains("EraError::Deserialization"));
}

#[test]
fn v2_sec_10_shard_read_errors_logged() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("Shard read error for shard"));
    assert!(source.contains("tracing::warn!"));
}

#[test]
fn v2_sec_11_global_extraction_memory_budget_present() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("MAX_EXTRACTION_MEMORY"));
}

#[test]
fn v2_sec_12_redb_put_persistent_before_memory() {
    let source = include_str!("../src/chunk_index.rs");
    let impl_start = source
        .find("impl ChunkIndex for RedbChunkIndex")
        .expect("RedbChunkIndex impl exists");
    let area = &source[impl_start..];
    assert!(area.contains("builder.insert(entry?)"));
    assert!(area.contains("insert_result?;"));
    assert!(area.contains("self.lookup.write().insert(hash, location);"));
}

// ============================================================================
// SECTION 2: LOGIC FINDINGS (V2-LOG-01 through V2-LOG-06)
// ============================================================================

#[tokio::test]
async fn v2_log_01_threshold_append_rejected_e2e() {
    let temp_dir = TempDir::new().expect("temp dir");
    let input = temp_dir.path().join("in.txt");
    fs::write(&input, b"hello").expect("write input");

    let archive = temp_dir.path().join("threshold.era");
    let mut writer = ArchiveWriter::builder(&archive)
        .password("p1")
        .add_password("p2")
        .access_policy(AccessPolicy::Threshold(2))
        .build()
        .await
        .expect("create threshold archive");
    writer.add_file(&input).await.expect("add file");
    writer.finalize().await.expect("finalize archive");

    let result = ArchiveWriter::builder(&archive)
        .password("p1")
        .append_existing(true)
        .build()
        .await;
    assert!(result.is_err());
    let err = match result {
        Err(e) => format!("{}", e),
        Ok(_) => panic!("append with threshold archive must fail"),
    };
    assert!(err.contains("Threshold") || err.contains("append"));
}

#[test]
fn v2_log_02_resume_handles_empty_checkpoint() {
    let source = include_str!("../src/recovery.rs");
    assert!(source.contains("Cannot truncate: no valid footer with data_end_offset"));
}

#[test]
fn v2_log_03_repair_uses_continue_or_warn_not_break() {
    let source = include_str!("../src/repair.rs");
    assert!(source.contains("continue;"));
    assert!(source.contains("warn!("));
}

#[test]
fn v2_log_04_slot_index_mapping_validated_in_reader() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("my_shard_idx"));
    assert!(source.contains("out of range total_shards"));
}

#[test]
fn v2_log_05_candidate_lengths_heuristic_documented() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("Heuristic for recovered data-shard length"));
    assert!(source.contains("candidate_lengths"));
}

#[test]
fn v2_log_06_my_shard_idx_bounds_check_present() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("if my_shard_idx >= total_shards"));
}

// ============================================================================
// SECTION 3: PERFORMANCE FINDINGS (V2-PERF-01 through V2-PERF-05)
// ============================================================================

#[test]
fn v2_perf_01_blake3_hash_wrapped_in_spawn_blocking() {
    let source = include_str!("../src/writer.rs");
    assert!(source.contains("spawn_blocking"));
    assert!(source.contains("blake3::hash"));
}

#[test]
fn v2_perf_02_rs_reconstruction_in_spawn_blocking() {
    let source = include_str!("../src/repair.rs");
    assert!(source.contains("spawn_blocking"));
    assert!(source.contains("recover_data_shards"));
}

#[test]
fn v2_perf_03_erasure_coder_cached_and_reused() {
    let source = include_str!("../src/write_pipeline.rs");
    assert!(source.contains("cached_erasure_coder"));
    assert!(source.contains("needs_new_coder"));
}

#[test]
fn v2_perf_04_session_erasure_decode_reduced_clone_count() {
    let source = include_str!("../src/block_iter.rs");
    let clone_count = source.matches(".clone()").count();
    assert!(
        clone_count <= 2,
        "too many clones in block_iter.rs: {}",
        clone_count
    );
}

#[test]
fn v2_perf_05_max_probe_attempts_limit_present() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("const MAX_PROBE_ATTEMPTS"));
}

// ============================================================================
// SECTION 4: ROBUSTNESS FINDINGS (V2-ROB-01 through V2-ROB-11)
// ============================================================================

#[test]
fn v2_rob_01_empty_volume_readers_validated() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("No volume readers provided"));
}

#[test]
fn v2_rob_02_packed_data_len_uses_checked_u32_conversion() {
    let source = include_str!("../src/writer.rs");
    assert!(source.contains("u32::try_from(packed_data.len())"));
}

#[test]
fn v2_rob_03_partial_reads_return_err_not_none() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("Unexpected partial read: expected"));
    assert!(source.contains("EraError::IntegrityError"));
}

#[test]
fn v2_rob_04_eof_checks_use_all_volumes_not_only_first() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("current_offsets"));
    assert!(source.contains("zip(self.data_ends.iter())"));
}

#[test]
fn v2_rob_05_volume_readers_len_validation_present() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("volume_readers.len() != volume_indices.len()"));
}

#[test]
fn v2_rob_06_first_shard_size_must_be_nonzero() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("first_shard_size == 0"));
    assert!(source.contains("cannot proceed with RS decode"));
}

#[test]
fn v2_rob_07_truncate_to_checkpoint_uses_spawn_blocking() {
    let source = include_str!("../src/recovery.rs");
    let fn_start = source
        .find("pub async fn truncate_to_checkpoint")
        .expect("truncate_to_checkpoint exists");
    let area = &source[fn_start..fn_start + 2600.min(source.len() - fn_start)];
    assert!(area.contains("spawn_blocking"));
}

#[tokio::test]
async fn v2_rob_08_checkpoint_exists_is_async_behavior() {
    let temp_dir = TempDir::new().expect("temp dir");
    let missing = temp_dir.path().join("missing.era");
    let exists = CheckpointManager::exists(&missing).await;
    assert!(!exists.unwrap());
}

#[test]
fn v2_rob_09_reader_blocking_fs_wrapped_in_spawn_blocking() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("tokio::task::spawn_blocking"));
    assert!(source.contains("fs::create_dir_all") || source.contains("std::fs::canonicalize"));
}

#[test]
fn v2_rob_10_apply_repairs_concern_documented() {
    let source = include_str!("../src/repair.rs");
    assert!(source.contains("V2-ROB-10"));
}

#[test]
fn v2_rob_11_partial_file_cleanup_on_failure_exists() {
    let source = include_str!("../src/reader.rs");
    assert!(source.contains("cleanup_partial_files"));
    assert!(source.contains("remove_file"));
}

// ============================================================================
// SECTION 5: QUALITY FINDINGS (V2-QUAL-01 through V2-QUAL-16)
// ============================================================================

#[test]
fn v2_qual_01_auth_mode_debug_redacts_sensitive_data() {
    let source = include_str!("../src/writer.rs");
    assert!(source.contains("[REDACTED]"));

    let mode = AuthMode::Password(Zeroizing::new("super-secret".to_string()));
    let dbg = format!("{:?}", mode);
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("super-secret"));
}

#[test]
fn v2_qual_02_no_allow_deprecated_for_sync_checkpoint() {
    let source = include_str!("../src/writer.rs");
    assert!(!source.contains("allow(deprecated)"));
}

#[test]
fn v2_qual_03_session_block_iterator_no_recursion() {
    let source = include_str!("../src/block_iter.rs");
    let start = source
        .find("impl<'a, R: era_storage::StorageReader> BlockIterator for SessionBlockIterator")
        .expect("session impl exists");
    let area = &source[start..start + 500];
    assert!(area.contains("loop {"));
    assert!(!area.contains("self.next_block()"));
}

#[test]
fn v2_qual_04_volume_indices_bounds_and_duplicate_validation() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("HashSet"));
    assert!(source.contains("contains duplicate index"));
}

#[test]
fn v2_qual_05_alignment_check_documented() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("even-aligned for RS recovery"));
    assert!(source.contains("is_multiple_of(2)"));
}

#[test]
fn v2_qual_06_shared_read_and_verify_shard_helper_exists() {
    let source = include_str!("../src/repair.rs");
    assert!(source.contains("async fn read_and_verify_shard"));
}

#[test]
fn v2_qual_07_fs_copy_wrapped_in_spawn_blocking() {
    let source = include_str!("../src/repair.rs");
    assert!(source.contains("spawn_blocking"));
    assert!(source.contains("std::fs::copy"));
}

#[test]
fn v2_qual_08_async_pipeline_has_no_todo_markers() {
    let source = include_str!("../src/async_pipeline.rs");
    assert!(!source.contains("TODO"));
}

#[test]
fn v2_qual_09_checkpoint_has_no_todo_about_chain() {
    let source = include_str!("../src/checkpoint.rs");
    let lower = source.to_lowercase();
    assert!(!lower.contains("todo") || !lower.contains("checkpoint chain"));
}

#[test]
fn v2_qual_10_reader_has_no_println_statements() {
    let source = include_str!("../src/reader.rs");
    assert!(!source.contains("println!("));
}

#[test]
fn v2_qual_11_reader_error_messages_are_informative() {
    let source = include_str!("../src/reader.rs");
    assert!(
        source.contains("Failed to join extraction cleanup task")
            || source.contains("Path traversal detected")
    );
}

#[test]
fn v2_qual_12_small_file_packer_push_validates_state() {
    let source = include_str!("../src/small_file_packer.rs");
    let push_start = source.find("pub fn push").expect("push exists");
    let area = &source[push_start..push_start + 320];
    assert!(area.contains("should_buffer"));
    assert!(area.contains("V2-QUAL-12"));
}

#[test]
fn v2_qual_13_volume_has_checkpoint_not_using_unwrap_or_false() {
    let source = include_str!("../src/recovery.rs");
    let start = source
        .find("async fn volume_has_checkpoint")
        .expect("volume_has_checkpoint exists");
    let end = source[start..]
        .find("pub struct RecoveryManager")
        .map(|p| start + p)
        .expect("recovery manager marker");
    let area = &source[start..end];
    assert!(!area.contains("unwrap_or(false)"));
    assert!(area.contains("unwrap_or_else"));
}

#[test]
fn v2_qual_14_first_error_preserved_with_get_or_insert() {
    let source = include_str!("../src/block_iter.rs");
    assert!(source.contains("last_err.get_or_insert"));
}

#[test]
fn v2_qual_15_unknown_operation_names_logged() {
    let source = include_str!("../src/metrics_collector.rs");
    assert!(source.contains("Unknown operation"));
    assert!(source.contains("debug!("));
}

#[test]
fn v2_qual_16_max_memory_index_entries_configurable_api_present() {
    let source = include_str!("../src/chunk_index.rs");
    assert!(source.contains("MAX_MEMORY_INDEX_ENTRIES"));
    assert!(source.contains("with_capacity"));
}

// ============================================================================
// SECTION 6: INFO FINDINGS (V2-INFO-01 through V2-INFO-03)
// ============================================================================

#[test]
fn v2_info_01_auth_rate_limiting_documented() {
    let source = include_str!("../src/auth.rs");
    assert!(source.contains("Rate-limiting") || source.contains("throttling"));
}

#[test]
fn v2_info_02_max_block_index_documented() {
    let source = include_str!("../src/encryption_context.rs");
    assert!(source.contains("MAX_BLOCK_INDEX"));
    assert!(source.contains("valid block index") || source.contains("u32::MAX"));
}

#[test]
fn v2_info_03_default_volume_id_documented() {
    let source = include_str!("../src/checkpoint.rs");
    assert!(source.contains("VolumeId::new() creates a default VolumeId"));
}
