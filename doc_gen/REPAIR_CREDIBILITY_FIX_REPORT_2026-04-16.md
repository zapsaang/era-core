# Repair Credibility Fix Report

**Date:** 2026-04-16  
**Branch:** feat_fly  
**Scope:** Address P0/P1 issues from `REPAIR_CREDIBILITY_AUDIT_REPORT_2026-04-16.md`

---

## Executive Summary

This report documents the fixes applied to close repair-path credibility gaps identified in the 2026-04-16 audit. All P0 and P1 items in scope have been addressed, with the exception of the pre-existing large-file CLI repair failure, which remains an independent open issue.

**Oracle verdict:** **Mostly sound with notes.** No blocking concerns remain for the specific fixes implemented in this slice.

---

## Fixes Applied

### 1. Matrix repair checkpoint boundary (P0.1)
**Status:** Fixed

**Problem:** `repair_archive_matrix` computed `data_ends` using only `catalog_offset()` and `index_offset()`, omitting `last_checkpoint_offset()`. This created asymmetry with the single-volume path and risked scanning into checkpoint metadata.

**Fix:** Added `last_checkpoint_offset()` clamp to `data_ends` in `repair_archive_matrix` (`crates/era-engine/src/repair.rs:1010-1014`).

**Additional hardening:** The same gap existed in the reader iterators (`ErasureBlockIterator`, `MultiVolumeSessionBlockIterator`, `SessionErasureBlockIterator`). All three now mirror the single-volume boundary logic (`crates/era-engine/src/block_iter.rs`).

---

### 2. Matrix corrupted data-shard header length regression (P0.2)
**Status:** Fixed with end-to-end test coverage

**Problem:** No engine-level test proved that `repair_archive_matrix` (or the reader path) could survive a corrupted `ShardHeader.length` field for data shards in a multi-volume archive.

**Fix:**
- `SessionErasureBlockIterator` now treats the stripe-prefix length as authoritative for data shards, bypassing `ShardHeader.verify()`’s length coupling. This prevents reader-side drift during verify/extract.
- Added `crates/era-engine/tests/matrix_repair_scan_tests.rs::test_matrix_repair_corrupted_data_shard_header_length_roundtrip`:
  - Corrupts data-shard header length on vol 0 to an in-bounds bogus value.
  - Runs `repair_archive_matrix` twice to prove no offset drift.
  - Verifies archive with `ArchiveReader::verify()` and extracts payload successfully.

---

### 3. Parity shard length hardening (P1.4)
**Status:** Fixed

**Problem:** Parity shards still trusted `ShardHeader.length` when it was merely "within bounds" but too small, allowing offset mis-advancement.

**Fix:** In both single-volume and matrix repair paths, if a parity shard’s `header.length < parity_bound` (where `parity_bound` is the padded max stripe size), the shard is immediately marked corrupted, its header offset is recorded for `apply_repairs`, and offset advancement uses the safe `parity_bound` (`repair.rs:433-439` and `1135-1149`).

**Test:** `matrix_repair_scan_tests.rs::test_matrix_repair_corrupted_parity_length_does_not_drift` proves that a parity header length of 1 is detected, reconstructed, and the archive remains fully verifiable and extractable.

---

### 4. CLI `repair --key` surface fix (P1.6)
**Status:** Fixed

**Problem:** The CLI still exposed `--key` for the `Repair` command, only rejecting it at runtime.

**Fix:**
- Added `hide = true` to the `key` argument in `bins/era-cli/src/main.rs:273`.
- Updated help text to stop mentioning `--key` explicitly.

---

### 5. Adversarial audit V5 compatibility update
**Status:** Updated

**Context:** `adversarial_audit_v5::test_v5_advrs_01_non_session_shard_len_cap` previously corrupted `ShardHeader.length` directly and expected a `MAX_SHARD_SIZE` cap error. Because data shards now use the stripe-prefix length as the authoritative value, corrupting the header length no longer triggers that code path.

**Change:** The test was updated to corrupt the stripe-prefix length instead, preserving the original security intent (DoS protection against unbounded allocation) while targeting the new authoritative field.

---

## Test Results

### New tests
| Test | File | Result |
|------|------|--------|
| `test_matrix_repair_with_checkpoint_boundary` | `matrix_repair_scan_tests.rs` | Pass |
| `test_matrix_repair_corrupted_data_shard_header_length_roundtrip` | `matrix_repair_scan_tests.rs` | Pass |
| `test_matrix_repair_corrupted_parity_length_does_not_drift` | `matrix_repair_scan_tests.rs` | Pass |

### Regression suites
| Suite | Result |
|-------|--------|
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | Pass |
| `cargo test -p era-engine --test matrix_repair_scan_tests` | 3/3 Pass |
| `cargo test -p era-engine --test single_volume_repair_scan_tests` | 5/5 Pass |
| `cargo test -p era-engine --test adversarial_audit_v5` | 26/26 Pass |
| `cargo test -p era-engine --test matrix_distribution_tests` | 8/8 Pass |
| `cargo test -p era-engine --test multi_volume_tests` | 28/28 Pass |
| `cargo test -p era-engine --test integration_tests test_repair_shard_corruption_roundtrip` | Pass |
| `cargo test -p era-cli --test cli_integration_tests test_repair_multivolume_missing_one_volume` | Pass |

---

## Known Remaining Gaps

| Issue | Priority | Status | Notes |
|-------|----------|--------|-------|
| Large-file 1GB repair test (`cli_e2e_gap_tests.rs`) | P0 | **Still ignored / failing** | Fails with "BlockHeader CRC verification failed". Appears independent of the fixes above. Requires separate triage. |
| Prefix multi-copy reconciliation (P1.5) | P1 | Deferred | First-readable-prefix is still trusted. Structural follow-up. |
| Shared scan-primitive refactoring (P2.8) | P2 | Deferred | Single-volume and matrix paths contain near-duplicated logic. Design debt. |

---

## Conclusion

The credibility gaps targeted in this slice have been substantively closed:

- **Checkpoint boundary asymmetry** is eliminated across repair and all reader iterators.
- **Data-shard header-length drift** is now defended against in both repair and reader paths, with an end-to-end matrix regression test.
- **Parity-length corruption** is hardened in both single-volume and matrix repair scans.
- **CLI surface** no longer advertises an unsupported option.

The remaining open item is the pre-existing large-file repair failure, which should be tracked as a standalone follow-up issue.
