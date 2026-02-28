# ERA Volume — Adversarial Audit V28 Report

**Audit Date:** 2026-02-27  
**Module:** `crates/era-volume`  
**Auditor:** Competitive Adversarial Audit (V28)  
**Previous Audit:** V27 (Score: 86/100, 16 findings — 14 fixed, 2 open)  
**Score This Round:** 90/100 (post-fix)

---

## Executive Summary

This V28 audit cycle performed two tasks:

1. **Verified all 16 V27 findings** — confirmed 14 were already fixed; identified 2 remaining open issues (V27-12, V27-14) and fixed them.
2. **Conducted a fresh competitive adversarial audit** targeting logic correctness, performance edge cases, space reservation consistency, and code quality. Discovered **8 new issues** (V28-01 through V28-08).

All 10 issues (2 carried from V27 + 8 new) have been fixed and verified:
- `cargo clippy -p era-volume --all-targets -- -D warnings` → **0 warnings**
- `cargo test -p era-volume` → **140 tests pass** (37 unit + 103 integration/audit)

### Key Improvements in V28

- **Checkpoint footer data integrity** (V27-12): `commit_checkpoint` now preserves catalog and index metadata via 6 new tracking fields and setter methods on `VolumeWriter`
- **DRY violation eliminated** (V27-14): Shared `volume_path()` utility extracted to `lib.rs`, both config types delegate to it
- **Error propagation for impossible-fit scenario** (V28-01): `needs_expansion()` now returns `Result<bool>` and errors when data can never fit
- **Consistent space reservation** (V28-02, V28-03): Both `volume_remaining_space()` and `VolumePoolStatusExt::can_fit` now reserve the full 4248-byte overhead (Footer + BackupHeader + BlockHeader + ShardHeader)
- **Scan recovery robustness** (V28-05): `scan_for_typed_blocks` skips by `BlockHeader::SIZE` instead of 1 byte on oversized-length detection

---

## V27 Verification Summary

All 16 V27 findings verified:

| ID | Severity | Status | Notes |
|----|----------|--------|-------|
| V27-01 | P0 | ✅ Fixed (prior) | `i64::try_from` on creation_time |
| V27-02 | P0 | ✅ Fixed (prior) | Footer version 0 rejected |
| V27-03 | P1 | ✅ Fixed (prior) | `BACKUP_HEADER_RESERVATION` used |
| V27-04 | P1 | ✅ Fixed (prior) | `u64::try_from` in `write_raw()` |
| V27-05 | P1 | ✅ Fixed (prior) | `u32::try_from` in `write_shard()` |
| V27-06 | P1 | ✅ Fixed (prior) | `u32::try_from` in `write_canonical_block()` |
| V27-07 | P1 | ✅ Fixed (prior) | `original_size` documented |
| V27-08 | P1 | ✅ Fixed (prior) | `u32::try_from` in `scan_for_typed_blocks()` |
| V27-09 | P2 | ✅ Fixed (prior) | Vec resize after rotation |
| V27-10 | P2 | ✅ Fixed (prior) | Non-deterministic `header()` method |
| V27-11 | P2 | ✅ Fixed (prior) | `MAX_SHARD_SIZE` validation added |
| V27-12 | P2 | ✅ **Fixed (V28)** | Checkpoint footer catalog/index loss |
| V27-13 | P3 | ✅ Fixed (prior) | Symmetric recipient validation |
| V27-14 | P3 | ✅ **Fixed (V28)** | Duplicate `volume_path()` logic |
| V27-15 | P3 | ✅ Fixed (prior) | Slot 0 preference addressed |
| V27-16 | P3 | ✅ Fixed (prior) | Test recipients fixed |

---

## Findings Summary

| ID | Severity | Category | File | Status |
|----|----------|----------|------|--------|
| V27-12 | P2 (Medium) | Logic | writer.rs | ✅ FIXED |
| V27-14 | P3 (Low) | Code Quality | lib.rs, multi_volume.rs, volume_pool.rs | ✅ FIXED |
| V28-01 | P2 (Medium) | Logic | volume_pool.rs | ✅ FIXED |
| V28-02 | P3 (Low) | Logic | volume_pool.rs | ✅ FIXED |
| V28-03 | P3 (Low) | Logic | distribution.rs | ✅ FIXED |
| V28-04 | P3 (Info) | Code Quality | volume_pool.rs | ✅ FIXED |
| V28-05 | P2 (Medium) | Performance/Logic | reader.rs | ✅ FIXED |
| V28-06 | P3 (Info) | Documentation | volume_pool.rs | ✅ FIXED |
| V28-07 | P3 (Info) | Documentation | volume_pool.rs | ✅ FIXED |
| V28-08 | P3 (Info) | Documentation | reader.rs | ✅ FIXED |

---

## Detailed Findings

### V27-12 [P2/Medium] — `commit_checkpoint` footer loses catalog/index info (CARRIED FROM V27)

**File:** `writer.rs`  
**Category:** Logic — Data Loss

**Problem:**  
The `commit_checkpoint()` method hardcoded 0 for all catalog and index fields when constructing the checkpoint footer:
```rust
let footer = crate::Footer::with_catalog(
    self.position, self.block_count, self.sequence,
    0, 0, 0,  // catalog_offset, catalog_size, catalog_block_id — always 0
    self.last_checkpoint_offset, self.last_checkpoint_block_id,
    0, 0, 0,  // index_offset, index_size, index_block_id — always 0
    backup_header_offset,
);
```
If a catalog or index block was written before the checkpoint, their locations are lost. On crash recovery, the recovered footer cannot locate the catalog or index.

**Impact:** Data loss of catalog/index metadata on crash recovery after checkpoint.

**Fix:**  
Added 6 new tracking fields to `VolumeWriter`:
- `catalog_offset`, `catalog_size`, `catalog_block_id`
- `index_offset`, `index_size`, `index_block_id`

Added corresponding setter methods (`set_catalog_info`, `set_index_info`). Updated `commit_checkpoint` to use these stored values. `finalize_with_catalog` also sets them before writing the final footer.

---

### V27-14 [P3/Low] — Duplicate `volume_path()` logic (CARRIED FROM V27)

**File:** `multi_volume.rs`, `volume_pool.rs`, `lib.rs`  
**Category:** Code Quality — DRY Violation

**Problem:**  
`MultiVolumeConfig::volume_path()` and `VolumePoolConfig::volume_path()` contained identical implementations for constructing volume file paths from a base path and volume index.

**Fix:**  
Extracted shared `volume_path(base_path: &Path, volume_index: u32) -> PathBuf` function to `lib.rs` with `pub use` re-export. Both config types now delegate to `crate::volume_path()`.

---

### V28-01 [P2/Medium] — `needs_expansion()` silent failure on impossible fit

**File:** `volume_pool.rs`  
**Category:** Logic — Silent Failure

**Problem:**  
`needs_expansion()` returned `bool` and would return `true` even when the requested data could never fit in any single volume (e.g., data larger than `max_volume_size`). Callers had no way to distinguish "needs more volumes" from "can never fit."

**Impact:** Infinite expansion loop — the pool keeps creating new volumes that can never hold the data.

**Fix:**  
Changed signature to `needs_expansion() -> Result<bool, EraError>`. Now returns `Err(EraError::InvalidConfig(...))` when data exceeds the maximum possible volume capacity, providing a clear error path for callers.

---

### V28-02 [P3/Low] — `volume_remaining_space()` inconsistent reservation

**File:** `volume_pool.rs`  
**Category:** Logic — Inconsistent Space Accounting

**Problem:**  
`volume_remaining_space()` reserved only `FOOTER_SIZE + BACKUP_HEADER_RESERVATION` (4224 bytes), but `volume_can_fit()` also accounted for `BlockHeader::SIZE + ShardHeader::SIZE` (152 bytes). This inconsistency meant `remaining_space()` could report space available that `can_fit()` would reject.

**Fix:**  
Updated `volume_remaining_space()` to reserve the full overhead: `FOOTER_SIZE + BACKUP_HEADER_RESERVATION + BlockHeader::SIZE + ShardHeader::SIZE` = 4248 bytes, consistent with `volume_can_fit()`.

---

### V28-03 [P3/Low] — `VolumePoolStatusExt::can_fit` inconsistent reservation

**File:** `distribution.rs`  
**Category:** Logic — Inconsistent Space Accounting

**Problem:**  
`VolumePoolStatusExt::can_fit` in `distribution.rs` used a different reservation calculation than `volume_can_fit()` in `volume_pool.rs`. The distribution calculator could approve a placement that the actual writer would reject.

**Impact:** Shard distribution decisions based on stale/incorrect capacity calculations.

**Fix:**  
Updated to use the same 4248-byte reservation as `volume_pool.rs`. Updated corresponding test assertions.

---

### V28-04 [P3/Info] — Duplicate `u32::try_from` in `write_shard()`

**File:** `volume_pool.rs`  
**Category:** Code Quality — Redundant Code

**Problem:**  
`write_shard()` called `u32::try_from(shard_data.len())` twice — once for `ShardHeader::new()` and once for size validation — with identical error handling.

**Fix:**  
Extracted to a single `let shard_len_u32 = u32::try_from(shard_data.len())?;` binding used by both call sites.

---

### V28-05 [P2/Medium] — `scan_for_typed_blocks` inefficient skip on oversized length

**File:** `reader.rs`  
**Category:** Performance/Logic — Degraded Recovery Performance

**Problem:**  
When `scan_for_typed_blocks` encounters a block header with a suspiciously large `length` field (exceeding remaining file size), it advanced the scan position by only 1 byte. In a corrupted volume, this means the scanner could process millions of single-byte advances through the data region, turning a linear scan into an extremely slow operation.

**Impact:** Recovery scan of a 4GB volume with early corruption could take hours instead of seconds.

**Fix:**  
Changed the skip distance from 1 byte to `BlockHeader::SIZE` bytes. Since a valid block header cannot start within the bytes of another header structure, this skip is safe and reduces worst-case scan time proportionally.

---

### V28-06 [P3/Info] — Missing documentation on `block_sequence` limitation

**File:** `volume_pool.rs`  
**Category:** Documentation

**Problem:**  
When opening a volume for append (`open_append`), `block_sequence` is initialized from the footer's `block_count`, but this may not reflect the true global sequence if blocks were distributed across multiple volumes. No comment explained this limitation.

**Fix:**  
Added clarifying comment explaining that `block_sequence` represents the local volume's block count and may diverge from the global sequence in multi-volume scenarios.

---

### V28-07 [P3/Info] — Unclear `total_volumes` semantics in `rotate_volumes`

**File:** `volume_pool.rs`  
**Category:** Documentation

**Problem:**  
The `rotate_volumes` method updates `total_volumes` but it was unclear whether this count represents the total across all rotations or just the current set. This ambiguity could confuse maintainers.

**Fix:**  
Added comment clarifying that `total_volumes` is the cumulative count across all rotation cycles, monotonically increasing.

---

### V28-08 [P3/Info] — Undocumented sentinel values in `read_typed_block`

**File:** `reader.rs`  
**Category:** Documentation

**Problem:**  
`read_typed_block` constructs `EncryptedMacroBlock` with `original_size: 0` and `chunk_count: 0`, but these are sentinel values meaning "unknown at read time," not actual zeros. Without documentation, consumers cannot distinguish "unknown" from "actually zero."

**Fix:**  
Added doc section on `read_typed_block` explaining that `original_size` and `chunk_count` are set to 0 as sentinel values because the `BlockHeader` on-disk format does not carry this metadata. Consumers should treat 0 as "not available."

---

## Score Breakdown

| Category | Weight | Score | Notes |
|----------|--------|-------|-------|
| Security | 35% | 33/35 | All V27 security fixes verified; no new security issues |
| Logic | 25% | 22/25 | Checkpoint data loss fixed; needs_expansion error path added; space reservation consistent |
| Performance | 15% | 13/15 | Scan skip improved; slot 0 preference previously addressed |
| Code Quality | 15% | 13/15 | DRY violation eliminated; duplicate code reduced |
| Testing | 10% | 9/10 | 140 tests passing; good coverage |

**Total Score: 90/100** (post-fix)

Improvement from V27: **+4 points** (86 → 90)

---

## Verification

```
$ cargo clippy -p era-volume --all-targets -- -D warnings
# 0 warnings, 0 errors

$ cargo test -p era-volume
# 140 tests: 140 passed, 0 failed, 0 ignored
```

---

## Recommended Next Steps (V29)

1. Re-examine `open_append` block_sequence initialization for multi-volume correctness
2. Audit `finalize_with_catalog` and `commit_checkpoint` interaction when both catalog and index are written in the same session
3. Investigate whether `VolumeWriter::set_catalog_info` / `set_index_info` should validate that offsets are within the current volume bounds
4. Review error message quality across all `EraError::InvalidConfig` paths for operator-actionable diagnostics
5. Assess whether `scan_for_typed_blocks` skip logic handles alignment-sensitive storage backends correctly
6. Deep-dive into `distribution.rs` matrix distribution for edge cases with heterogeneous volume sizes
