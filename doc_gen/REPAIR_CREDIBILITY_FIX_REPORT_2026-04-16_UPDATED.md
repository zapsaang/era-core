# Repair Credibility Fix Report (Updated)

**Date:** 2026-04-16  
**Branch:** feat_fly  
**Scope:** Address remaining P0/P1 issues from `REPAIR_CREDIBILITY_AUDIT_REPORT_2026-04-16.md`

---

## Executive Summary

This report documents the fixes applied to close the remaining repair-path credibility gaps identified in the 2026-04-16 audit. All targeted P0 and P1 items have been addressed.

**Oracle verdict:** **Approved with minor follow-up hardening.** The P0.3 large-file repair bug is substantively fixed, and P1.6 CLI contract cleanup is complete. One follow-up item (multi-block catalog continuation validation) is tracked for future hardening.

---

## Root Cause Analysis: P0.3 Large-File Repair Bug

### Problem

The `test_large_file_1gb_repair_after_corruption` CLI test (and its 128MB sibling) failed with:

```
Error: Verification failed
Caused by:
    Integrity error: BlockHeader CRC verification failed
```

This error occurred **during the repair command's initial analysis phase**, before any actual Reed-Solomon repair could begin.

### Why It Failed

1. The CLI test corrupts 100 bytes at **offset 5000** on volume 0.
2. In a typical multi-volume archive, the **catalog block** is written early in the data region (around offset 4608).
3. Offset 5000 falls **inside the catalog block**, corrupting its BlockHeader CRC.
4. `ArchiveReader::load_catalog()` only tried to read the catalog from the **first volume** (volume 0).
5. When volume 0's catalog was corrupted, `load_catalog()` returned a hard error.
6. This error propagated up through `ArchiveReader::open()` → `reader.verify()` → the `repair` CLI command, causing it to exit before repairing anything.

### Why It Affected Large Files

The bug was not specific to large files per se. It was specific to **multi-volume archives with matrix distribution** (which `--erasure 4:2` creates by default). The corruption at offset 5000 happened to land inside the catalog block because:
- The SuperHeader occupies the first ~4224 bytes
- The catalog is typically placed immediately after at ~4608 bytes
- Offset 5000 is within the catalog block's extent

Smaller tests often used `VolumeReader` to corrupt specific shard payloads, which avoided the catalog region. The CLI test used a fixed offset of 5000, which reliably hit the catalog.

### Key Insight

The catalog is **intentionally replicated to all volumes** via `VolumeStage::write_catalog_blocks_to_all()`. However, the reader only utilized the first replica. The fix leverages this built-in redundancy.

---

## Fixes Applied

### 1. Multi-volume catalog redundancy fallback (P0.3)
**Status:** Fixed

**File:** `crates/era-engine/src/reader.rs`

**Change:** Refactored `ArchiveReader::load_catalog()` to iterate through **all volumes** that have a catalog location, trying each one until a successful read is achieved. Added `assemble_catalog_data()` helper for multi-block catalog assembly.

**Hardening:** Per Oracle recommendation, `assemble_catalog_data()` now strictly validates that:
- Every continuation block yields at least one index entry
- Chunk bounds fit within the decoded block data
- The final reassembled buffer length exactly matches the advertised `total_len`

This prevents partial/malformed catalog assembly from reaching deserialization.

---

### 2. CLI `repair --key` contract removal (P1.6)
**Status:** Fixed

**Files:**
- `bins/era-cli/src/main.rs`
- `bins/era-cli/src/commands.rs`

**Change:**
- Removed the `key` field from `Commands::Repair` enum variant
- Removed `key_path` parameter from `commands::repair()`
- Removed runtime rejection branch for `--key`
- Updated help text to stop mentioning `--key` for repair

**Test updates:**
- `bins/era-cli/tests/cli_integration_tests.rs`: Now expects clap parse-time rejection
- `bins/era-cli/tests/cli_integration_tests_comprehensive.rs`: Now expects clap parse-time rejection
- `bins/era-cli/tests/cli_boundary_tests.rs`: Added `test_repair_help_does_not_show_key` to assert `repair --help` hides `--key` while `extract --help` still shows it

---

### 3. New TDD regression tests
**Status:** Added

**File:** `crates/era-engine/tests/matrix_repair_scan_tests.rs`

Added two tests:

| Test | Purpose |
|------|---------|
| `test_matrix_repair_large_layout_payload_corruption_roundtrip` | Creates a 16MB archive with many small blocks, corrupts a payload byte, and verifies exact byte restoration after repair |
| `test_matrix_repair_cli_style_offset_5000_corruption` | Reproduces the exact P0.3 bug: 128MB archive, 100-byte corruption at offset 5000, verify+extract succeed after repair |

Also fixed a pre-existing compilation issue in `test_matrix_repair_corrupted_data_shard_header_length_roundtrip` (renamed `_payload` to `payload` to match its usage).

---

## Test Results

### Engine tests
| Suite | Result |
|-------|--------|
| `cargo test -p era-engine --test matrix_repair_scan_tests` | 5/5 Pass |
| `cargo test -p era-engine --test single_volume_repair_scan_tests` | 5/5 Pass |
| `cargo test -p era-engine --test adversarial_audit_v5` | 26/26 Pass |
| `cargo test -p era-engine --test matrix_distribution_tests` | 8/8 Pass |

### CLI tests
| Suite | Result |
|-------|--------|
| `cargo test -p era-cli --test cli_integration_tests` | 85/85 Pass |
| `cargo test -p era-cli --test cli_integration_tests_comprehensive` | 111/111 Pass |
| `cargo test -p era-cli --test cli_stress_and_discovery_tests` | 26/26 Pass (2 ignored) |
| `cargo test -p era-cli --test cli_boundary_tests` | New boundary test passes |

### Bug-closure proof
| Test | Result |
|------|--------|
| `cargo test -p era-cli --test cli_e2e_gap_tests test_large_file_1gb_repair_after_corruption --release -- --ignored --exact` | **PASS** |
| `cargo test -p era-cli --test cli_stress_and_discovery_tests test_stress_large_file_128mb_repair_after_corruption_release_regression --release -- --ignored --exact` | **PASS** |

### Hygiene
| Check | Result |
|-------|--------|
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | Pass |

---

## Oracle Audit Verdict

**Overall: Approved with one follow-up hardening item.**

### Specific findings

1. **Catalog fallback is sound** for finalized multi-volume archives because `VolumeStage::write_catalog_blocks_to_all()` intentionally replicates the same catalog to every volume.

2. **`assemble_catalog_data` hardening is adequate** after the added length and bounds checks. The helper preserves the intended writer layout for single-block, multi-block, and legacy unprefixed catalogs.

3. **Security posture:** There is no new cryptographic bypass. The main remaining weakness is the lack of cross-replica consistency checking (e.g., hashing all readable replicas and requiring agreement). This is acceptable for corruption recovery but weak against active replay/stale-replica scenarios.

4. **Removing `repair --key` is correct UX** because the engine repair APIs only accept a password string today. Certificate and threshold users should use `verify --key` / `extract --key` instead.

### Follow-up recommendation (tracked, not blocking)

- Add explicit multi-block catalog fallback regressions:
  - "First catalog block OK, second catalog block corrupted on volume 0, fallback succeeds from volume 1"
  - "Continuation block decodes but contributes zero/short bytes → fail fast"
- These require forcing multi-block catalog creation (large file lists), so they are tracked as a follow-up hardening slice rather than blocking this fix.

---

## Known Remaining Gaps

| Issue | Priority | Status | Notes |
|-------|----------|--------|-------|
| Prefix multi-copy reconciliation (P1.5) | P1 | Deferred | First-readable-prefix is still trusted. Structural follow-up. |
| Shared scan-primitive refactoring (P2.8) | P2 | Deferred | Single-volume and matrix paths contain near-duplicated logic. Design debt. |
| Multi-block catalog fallback regressions | P2 | Tracked | Oracle follow-up: add tests for corrupted continuation blocks. |

---

## Conclusion

The credibility gaps targeted in this slice have been substantively closed:

- **P0.3 Large-file repair bug** is fixed. The root cause was catalog-read single-point-of-failure on volume 0. The reader now correctly falls back to catalog replicas on other volumes.
- **P1.6 CLI `--key` exposure** is fully removed from the repair command surface.
- All existing regressions remain green, and the previously-ignored 1GB CLI repair test now passes.

The remaining open items (P1.5 prefix reconciliation, P2.8 scan-primitive refactoring, and Oracle's multi-block catalog regression suggestion) are documented as follow-up work.
