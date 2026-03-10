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
