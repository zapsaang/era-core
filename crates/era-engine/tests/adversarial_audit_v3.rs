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
            source.contains("let index_recovered = self.restore_embedded_index().await?;")
                && source.contains("if !index_recovered")
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

        assert!(
            source.contains("async fn volume_has_checkpoint(archive_path: &Path) -> Result<bool>"),
            "volume_has_checkpoint must return Result<bool, EraError>"
        );
        assert!(
            source.contains("volume_has_checkpoint(archive_path).await?")
                && source.contains(
                    "archive_path.exists() && volume_has_checkpoint(archive_path).await?"
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
