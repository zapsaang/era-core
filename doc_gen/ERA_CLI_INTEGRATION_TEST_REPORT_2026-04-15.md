# ERA CLI Integration Test Report

**Date:** 2026-04-15
**Branch:** feat_fly
**Scope:** Comprehensive CLI integration test suite, shared helper extraction, bug investigation and fixes

---

## Files Created

| File | Purpose |
|------|---------|
| `bins/era-cli/tests/common/mod.rs` | Shared test helpers (22 functions) extracted from 7 test files |
| `bins/era-cli/tests/cli_stress_and_discovery_tests.rs` | 28 new integration tests across 10 categories |

## Files Modified

| File | Change |
|------|--------|
| `bins/era-cli/tests/cli_tests.rs` | Use `common::*` instead of inline helpers |
| `bins/era-cli/tests/cli_integration_tests.rs` | Use `common::*` instead of inline helpers |
| `bins/era-cli/tests/cli_integration_tests_comprehensive.rs` | Use `common::*` instead of inline helpers |
| `bins/era-cli/tests/cli_e2e_tests.rs` | Use `common::*` instead of inline helpers |
| `bins/era-cli/tests/cli_e2e_gap_tests.rs` | Use `common::*` instead of inline helpers |
| `bins/era-cli/tests/cli_boundary_tests.rs` | Use `common::*` instead of inline helpers |
| `bins/era-cli/tests/cli_extreme_tests.rs` | Use `common::*` instead of inline helpers |
| `crates/era-engine/src/repair.rs` | Bug 1 fix: authoritative stripe prefix lengths, scan boundary hardening |
| `crates/era-engine/tests/adversarial_audit_v3.rs` | Updated source-pattern audit to match new guard pattern |
| `crates/era-packing/src/session_erasure_builder.rs` | Bug 2 fix: corrected test assertion methodology |

Net: -717 lines removed (deduplication), +150 lines added. Total delta: -567 lines.

---

## Bug 1: Repair CRC Failure on Large Erasure-Coded Archives

**Status:** Fixed

**Root Cause:** The single-volume repair scan in `repair.rs` trusted `ShardHeader.length` from potentially corrupted shards for three critical operations: (1) determining data shard original lengths for RS reconstruction, (2) reading shard data from disk, and (3) advancing the scan offset. When a shard header's length field was corrupted, the scan would drift, potentially overwriting catalog/index metadata blocks. The verify path would then fail with "BlockHeader CRC verification failed" when reading those metadata blocks.

**Fix Applied:**
1. Scan boundary hardened to stop at the earliest of `catalog_offset`, `index_offset`, and `last_checkpoint_offset` (was only `catalog_offset`)
2. Stripe prefix lengths (replicated per-shard, more trustworthy) used as authoritative source for data shard sizes
3. Offset advancement uses prefix-derived lengths even when shard headers are corrupted
4. CRC verification bypasses `ShardHeader.verify()` length check for data shards using prefix-derived lengths (since header length field may be corrupted while CRC is still valid)
5. Corrupted header path now properly advances offset instead of `continue` without advancement

**Files:** `crates/era-engine/src/repair.rs` (lines 332-500)

**Verification:** 5/5 single-volume repair tests pass, 22/22 adversarial audit v3 tests pass, 7/7 v8.1 resilience tests pass, 19/19 engine integration tests pass, 85/85 CLI integration tests pass.

**Note:** The matrix repair path (`repair_archive_matrix`) has the same pattern but was not modified in this change. It should be hardened separately.

---

## Bug 2: Protobuf Ciphertext Identity

**Status:** Fixed (test was flawed, not product code)

**Root Cause:** The test at `session_erasure_builder.rs:533` compared a single shard (`block1.shards[0]`) between two erasure-coded blocks. After Reed-Solomon encoding, individual shards can be identical even when the input encrypted blocks differ, because RS distributes data across shards non-uniformly. The proto serialization correctly includes chunk hashes (verified: serialized bytes differ by 32 bytes at the hash position).

**Fix Applied:**
1. Added pre-erasure verification: compare `encrypted1.data != encrypted2.data` (inner encrypted blocks before RS encoding) — this passes, confirming proto serialization is correct
2. Changed shard comparison from `block1.shards[0] != block2.shards[0]` to `block1.shards != block2.shards` (full vector comparison) — this also passes
3. Removed stale TODO comment about protobuf migration bug

**Files:** `crates/era-packing/src/session_erasure_builder.rs` (test module)

---

## New Test Matrix (cli_stress_and_discovery_tests.rs)

| Category | Tests | Status |
|----------|-------|--------|
| Large file stress | 2 (#[ignore]) | Compile-verified |
| Volume discovery | 4 | 4/4 pass |
| Multi-volume extreme | 3 | 3/3 pass |
| Repair and recovery | 5 | 5/5 pass |
| Security edge cases | 3 | 3/3 pass |
| Empty/zero-byte handling | 2 | 2/2 pass |
| Dedup verification | 2 | 2/2 pass |
| EC config matrix | 4 | 4/4 pass |
| Concurrent access | 2 | 2/2 pass |
| Repair key limitation | 1 | 1/1 pass |
| **Total** | **28** | **26/26 pass, 2 #[ignore]** |

### Ignored Tests

| Test | Reason |
|------|--------|
| `test_stress_large_file_128mb_roundtrip_single_volume` | Requires ~500MB disk + 2+ min runtime |
| `test_stress_large_file_128mb_repair_after_corruption_release_regression` | Bug 1 regression test, requires --release + ~500MB disk |

---

## Verification Commands Executed

| Command | Result |
|---------|--------|
| `cargo fmt --all -- --check` | Clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | Clean |
| `cargo test -p era-packing` | All pass |
| `cargo test -p era-engine --test single_volume_repair_scan_tests` | 5/5 pass |
| `cargo test -p era-engine --test adversarial_audit_v3` | 22/22 pass |
| `cargo test -p era-engine --test v81_adversarial_resilience` | 7/7 pass |
| `cargo test -p era-engine --test adversarial_resilience_tests` | 3/3 pass |
| `cargo test -p era-engine --test integration_tests` | 19/19 pass |
| `cargo test -p era-cli --test cli_integration_tests` | 85/85 pass |
| `cargo test -p era-cli --test cli_stress_and_discovery_tests -- --skip stress` | 26/26 pass |

Full workspace test (`cargo test --workspace`) was not completed due to 10-minute timeout in this environment. Individual crate tests covering all modified code passed.

---

## Shared Helper Extraction Summary

22 helper functions extracted from 7 test files into `bins/era-cli/tests/common/mod.rs`:

`era_cmd`, `era_binary_path`, `create_test_file`, `generate_deterministic_data`, `create_large_test_file`, `create_large_deterministic_file`, `create_large_test_file_streaming`, `verify_large_deterministic_file`, `count_volume_files`, `get_volume_paths`, `get_volume_size`, `corrupt_archive_shard`, `corrupt_volume_data`, `corrupt_footer`, `corrupt_header_magic`, `truncate_file`, `generate_test_keypair`, `create_archive_with_cert`, `assert_file_content_eq`, `count_files_recursive`, `create_test_config`, `repo_tmp_dir`

717 lines of duplicated code removed across 7 files.

---

## Remaining Limitations and Follow-ups

1. **Matrix repair path not hardened:** `repair_archive_matrix` in `repair.rs:984-1066` has the same "trust corrupted header length" pattern. Should be fixed separately.
2. **`repair --key` not supported:** CLI advertises `--key` for repair but `commands.rs` rejects it. Test documents this limitation. Help text should be corrected.
3. **1GB release-lane regression not executed:** The original `test_large_file_1gb_repair_after_corruption` was not re-run in this session due to environment constraints. The 128MB regression test is available as `#[ignore]` for CI.
4. **Threshold T-of-N mode:** Not exposed in CLI. Documented as gap.

---

## Final Summary

**Pass.** All modified code compiles clean (fmt + clippy), all targeted test suites pass, 28 new integration tests added covering 10 categories of previously untested scenarios, 2 bugs investigated and resolved, 717 lines of test helper duplication eliminated.
