mod high_severity {
    #[test]
    fn test_v3_sec_01_repair_enforces_max_shard_size_on_all_read_paths() {
        let source = include_str!("../src/repair.rs");

        assert!(
            source.contains("const MAX_SHARD_SIZE: u64 = 256 * 1024 * 1024;"),
            "repair.rs must define/reuse MAX_SHARD_SIZE"
        );

        let guard_count = source
            .matches("if shard_header.length as u64 > MAX_SHARD_SIZE")
            .count();
        assert!(
            guard_count >= 3,
            "expected MAX_SHARD_SIZE guard in all 3 shard-read paths, found {guard_count}"
        );
    }

    #[test]
    fn test_v3_log_01_repair_uses_shard_idx_keyed_offset_mapping() {
        let source = include_str!("../src/repair.rs");

        assert!(
            source.contains("let mut shard_offsets: Vec<Option<u64>> = vec![None; total_shards];"),
            "shard_offsets must be fixed-size Vec<Option<u64>>"
        );
        assert!(
            source.contains("shard_offsets[shard_idx] = Some(shard_header_offset);"),
            "shard offsets must be assigned by shard_idx"
        );
        assert!(
            source.contains("shard_offsets.get(shard_idx).and_then(|v| *v)"),
            "shard offset lookup must handle Option<u64>"
        );
    }

    #[test]
    fn test_v3_rob_01_write_pipeline_removes_runtime_unwrap_for_cached_coder() {
        let source = include_str!("../src/write_pipeline.rs");

        assert!(
            !source.contains("cached_erasure_coder.as_ref().unwrap().2"),
            "runtime unwrap on cached erasure coder must be removed"
        );
        assert!(
            source.contains("cached_erasure_coder") && source.contains("ok_or_else"),
            "cached erasure coder access should use Result-based error handling"
        );
    }
}

mod medium_severity {
    #[test]
    fn test_v3_sec_02_encryption_context_uses_bounded_acqrel_atomic_counter() {
        let source = include_str!("../src/encryption_context.rs");

        assert!(
            !source.contains("fetch_add(1, Ordering::Relaxed)"),
            "next_block_id must not use Relaxed fetch_add"
        );
        assert!(
            source.contains("fetch_update(Ordering::AcqRel, Ordering::Acquire"),
            "next_block_id must use bounded fetch_update with AcqRel/Acquire"
        );
        assert!(
            source.contains("if current <= MAX_BLOCK_INDEX"),
            "counter update must enforce MAX_BLOCK_INDEX boundary"
        );
        assert!(
            source.contains("self.next_block_id.load(Ordering::Acquire)"),
            "blocks_written must use Acquire ordering"
        );
    }

    #[test]
    fn test_v3_sec_03_writer_validates_whitespace_password_and_warns_on_empty() {
        let source = include_str!("../src/writer.rs");

        assert!(
            source.contains("password.is_empty()")
                && source.contains("warn!(")
                && source.contains("empty password"),
            "build() must warn when password is truly empty"
        );
        assert!(
            source.contains("password.trim().is_empty()")
                && source.contains("Password must not contain only whitespace"),
            "build() must reject non-empty all-whitespace passwords"
        );
    }

    #[test]
    fn test_v3_sec_04_checkpoint_validates_footer_checkpoint_offset_bounds() {
        let source = include_str!("../src/checkpoint.rs");

        assert!(
            source.contains(
                "let (data_region_start, data_region_end) = volume_reader.data_region();"
            ),
            "checkpoint recovery must derive data region bounds from volume reader"
        );
        assert!(
            source.contains(
                "checkpoint_offset < data_region_start || checkpoint_offset >= data_region_end"
            ),
            "checkpoint recovery must validate checkpoint offset before read"
        );
        assert!(
            source.contains("Footer checkpoint offset") || source.contains("Checkpoint offset"),
            "out-of-bounds checkpoint offset path must return a clear error"
        );
    }

    #[test]
    fn test_v3_log_02_reader_warns_and_surfaces_embedded_index_recovery_failure_status() {
        let source = include_str!("../src/reader.rs");

        assert!(
            source.contains("async fn restore_embedded_index(&mut self) -> Result<bool>"),
            "restore_embedded_index must propagate recovery status to caller"
        );
        assert!(
            source.contains("warn!(\n                                \"V2.1 index recovery failed, continuing without index: {}\"")
                || source.contains("warn!(\"V2.1 index recovery failed, continuing without index: {}\""),
            "embedded index recovery failure must be logged at warn level"
        );
        assert!(
            source.contains("let _index_recovered = self.restore_embedded_index().await?;")
                && source.contains("if self.embedded_index_recovery_failed")
                && source.contains("Embedded index recovery failed; continuing in degraded mode"),
            "preflight path must observe and surface degraded recovery status"
        );
    }
}

mod medium_perf_rob {
    #[test]
    fn test_v3_perf_01_writer_no_packed_data_clone_before_spawn_blocking() {
        let source = include_str!("../src/writer.rs");

        assert!(
            !source.contains("let packed_data_clone = packed_data.clone();"),
            "writer must not clone packed_data before blake3 spawn_blocking"
        );
        assert!(
            source.contains("let (packed_hash, packed_data) = tokio::task::spawn_blocking"),
            "writer should move packed_data into spawn_blocking and return it"
        );
    }

    #[test]
    fn test_v3_rob_02_recovery_volume_has_checkpoint_returns_result() {
        let source = include_str!("../src/recovery.rs");
        let normalized = source.split_whitespace().collect::<String>();

        assert!(
            source.contains("async fn volume_has_checkpoint(archive_path: &Path) -> Result<bool>"),
            "volume_has_checkpoint must return Result<bool, EraError>"
        );
        assert!(
            source.contains("volume_has_checkpoint(archive_path).await?")
                && normalized.contains(
                    "tokio::fs::try_exists(archive_path).await?&&volume_has_checkpoint(archive_path).await?"
                ),
            "all recovery callers must propagate volume_has_checkpoint errors"
        );
    }

    #[test]
    fn test_v3_rob_03_writer_uses_try_from_not_as_u32_for_chunk_lengths() {
        let source = include_str!("../src/writer.rs");

        assert!(
            source.contains("let chunk_len = u32::try_from(size)")
                && source.contains("let length = u32::try_from(chunk.data.len())")
                && source.contains("let chunk_len = u32::try_from(chunk.len())")
                && source.contains("let chunk_len = u32::try_from(data.len())"),
            "writer must use checked u32 conversions for chunk/file length metadata"
        );
        assert!(
            !source.contains("size as u32")
                && !source.contains("chunk.data.len() as u32")
                && !source.contains("chunk.len() as u32")
                && !source.contains("data.len() as u32"),
            "writer must not use lossy as u32 casts for chunk/file lengths"
        );
    }

    #[test]
    fn test_v3_rob_04_block_iter_erasure_tolerates_partial_volume_exhaustion() {
        let source = include_str!("../src/block_iter.rs");

        assert!(
            source.contains("let exhausted_volumes =")
                && source.contains("filter(|(offset, end)| *offset >= *end)")
                && source.contains("if exhausted_volumes > self.parity_shards as usize"),
            "non-session erasure iterator must continue while exhausted volumes stay within parity budget"
        );
        assert!(
            !source.contains(".any(|(offset, end)| offset >= end)"),
            "iterator must not terminate when any single volume reaches end"
        );
    }

    #[test]
    fn test_v3_rob_05_checkpoint_uses_safe_u32_conversion_for_sizes() {
        let source = include_str!("../src/checkpoint.rs");

        assert!(
            source.contains("let checkpoint_size = u32::try_from(checkpoint_bytes.len())"),
            "checkpoint writer must use checked usize->u32 conversion"
        );
        assert!(
            !source.contains("checkpoint_bytes.len() as u32"),
            "checkpoint writer must not use unchecked as u32 cast"
        );
    }
}

mod low_severity {
    #[test]
    fn test_v3_sec_05_threshold_passwords_use_zeroizing() {
        let source = include_str!("../src/writer.rs");

        assert!(
            source.contains("let mut all_passwords: Vec<zeroize::Zeroizing<String>>"),
            "threshold password collection must be typed as Vec<Zeroizing<String>>"
        );
        assert!(
            source.contains("zeroize::Zeroizing::new(pwd.as_str().to_string())")
                && source.contains(".map(|p| zeroize::Zeroizing::new(p.clone()))"),
            "primary and additional threshold passwords must be wrapped in Zeroizing"
        );
    }

    #[test]
    fn test_v3_qual_01_generic_writer_warns_on_empty_password() {
        let source = include_str!("../src/writer.rs");

        assert!(
            source.contains("self.password.unwrap_or_else(||")
                && source
                    .contains("GenericArchiveWriter: no password provided, using empty password"),
            "GenericArchiveWriter builder must warn on missing password fallback"
        );
        assert!(
            !source.contains("let password = self.password.unwrap_or_default();"),
            "GenericArchiveWriter builder must not silently use unwrap_or_default for password"
        );
    }

    #[test]
    fn test_v3_perf_02_reader_uses_async_path_exists() {
        let source = include_str!("../src/reader.rs");

        let count = source.matches("tokio::fs::try_exists(&").count();
        assert!(
            count >= 2,
            "reader must use async tokio::fs::try_exists at both discovery and extraction checks"
        );
        assert!(
            source.contains("tokio::fs::try_exists(&full_path).await.unwrap_or(false)")
                && source.contains("tokio::fs::try_exists(&output_path).await.unwrap_or(false)"),
            "reader must use async try_exists for full_path and output_path"
        );
    }

    #[test]
    fn test_v3_perf_03_writer_uses_async_path_exists() {
        let source = include_str!("../src/writer.rs");

        let count = source
            .matches("tokio::fs::try_exists(&self.output_path).await?")
            .count();
        assert!(
            count >= 2,
            "writer must use async tokio::fs::try_exists for preexisting and append checks"
        );
        assert!(
            !source.contains("self.output_path.exists()"),
            "writer must not use blocking Path::exists() in async build flow"
        );
    }

    #[test]
    fn test_v3_perf_04_recovery_uses_async_path_exists() {
        let source = include_str!("../src/recovery.rs");

        let count = source.matches("tokio::fs::try_exists(").count();
        assert!(
            count >= 3,
            "recovery must use async try_exists for analyze/new/truncate checks"
        );
        assert!(
            !source.contains("archive_path.exists()")
                && !source.contains("self.archive_path.exists()"),
            "recovery must not use blocking Path::exists() in async functions"
        );
    }

    #[test]
    fn test_v3_qual_02_repair_preserves_map_err_context() {
        let source = include_str!("../src/repair.rs");

        let contextual_count = source
            .matches("Invalid master key length: expected 32, got {}")
            .count();
        assert!(
            contextual_count >= 2,
            "repair must preserve master key length context in both map_err sites"
        );
        assert!(
            source.contains("map_err(|e: Vec<u8>|"),
            "repair map_err should capture conversion error payload for context"
        );
    }

    #[test]
    fn test_v3_qual_03_checkpoint_no_infallible_unwrap() {
        let source = include_str!("../src/checkpoint.rs");

        assert!(
            source.contains("match archived.deserialize(&mut rkyv::Infallible)")
                && source.contains("Err(infallible) => match infallible {}"),
            "checkpoint deserialization must match exhaustively on Infallible"
        );
        assert!(
            !source.contains("archived.deserialize(&mut rkyv::Infallible).unwrap()"),
            "checkpoint deserialization must not unwrap Infallible result"
        );
    }

    #[test]
    fn test_v3_qual_04_auth_preserves_map_err_context() {
        let source = include_str!("../src/auth.rs");

        assert!(
            source.contains("Invalid ephemeral public: expected 32 bytes, got {}")
                && source.contains("map_err(|e: Vec<u8>|"),
            "auth provider must include invalid ephemeral public length context"
        );
        assert!(
            !source
                .contains("map_err(|_| EraError::InvalidKey(\"Invalid ephemeral public\".into()))"),
            "auth provider must not drop try_into error context"
        );
    }

    #[test]
    fn test_v3_rob_06_volume_stage_safe_block_id_cast() {
        let source = include_str!("../src/volume_stage.rs");

        assert!(
            source.contains("let block_id = u32::try_from(block.block_id.sequence())")
                && source.contains("Block sequence ID exceeds u32::MAX"),
            "volume_stage must use checked conversion for block_id sequence"
        );
        assert!(
            !source.contains("let block_id = block.block_id.sequence() as u32;"),
            "volume_stage must not use unchecked as u32 cast for block_id"
        );
    }

    #[test]
    fn test_v3_qual_05_chunk_index_uses_capacity_parameter() {
        let source = include_str!("../src/chunk_index.rs");

        assert!(
            source.contains("HashMap::with_capacity(")
                && source.contains("max_entries.min(MAX_MEMORY_INDEX_ENTRIES)"),
            "MemoryChunkIndex::with_capacity must use max_entries with upper bound"
        );
        assert!(
            !source.contains("let _ = max_entries;"),
            "MemoryChunkIndex::with_capacity must not ignore max_entries parameter"
        );
    }
}
