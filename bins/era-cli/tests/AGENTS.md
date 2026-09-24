# CLI Tests

End-to-end integration tests for the `era` binary. All tests drive the compiled `era` command via `assert_cmd::Command` through `common::era_cmd()`.

## FILES

| File | Lines | Focus |
|------|------:|-------|
| `cli_tests.rs` | 79 | General CLI behavior. |
| `cli_boundary_tests.rs` | 760 | Boundary and input validation. |
| `cli_coverage_gap_tests.rs` | 2079 | Coverage gap scenarios. |
| `cli_e2e_gap_tests.rs` | 564 | Edge-case e2e scenarios. |
| `cli_e2e_tests.rs` | 2705 | Full e2e flows. |
| `cli_extreme_comprehensive_tests.rs` | 1150 | Extended extreme-input coverage. |
| `cli_extreme_tests.rs` | 3960 | Extreme input stress. |
| `cli_integration_tests.rs` | 3185 | Basic create/extract roundtrips. |
| `cli_integration_tests_comprehensive.rs` | 6217 | Extended command coverage. |
| `cli_stress_and_discovery_tests.rs` | 1319 | Concurrency and discovery stress. |
| `common/mod.rs` | 305 | Shared harness: `era_cmd()`, `create_test_file`/`create_large_test_file_streaming`, `generate_deterministic_data` (prime-modulus-251), `count_volume_files`/`get_volume_paths`, `corrupt_archive_shard`/`corrupt_footer`/`corrupt_header_magic`/`truncate_file`, `generate_test_keypair`/`generate_test_hybrid_keypair`, `create_archive_with_cert`, `repo_tmp_dir`. |

## RUN

```bash
cargo test -p era-cli
cargo test --release -p era-cli  # matches CI
```

See `bins/era-cli/AGENTS.md` and `src/AGENTS.md` for CLI architecture.
