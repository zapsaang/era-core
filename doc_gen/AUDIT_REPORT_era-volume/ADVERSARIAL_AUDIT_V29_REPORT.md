# ERA Volume — Adversarial Audit V29 Report

**Audit Date:** 2026-02-28  
**Module:** `crates/era-volume` (5,369 LOC, 8 source files)  
**Auditor:** Competitive Adversarial Audit (V29)  
**Previous Audit:** V28 (Score: 90/100, 10 findings — all fixed)  
**Score This Round:** 93/100 (post-fix)

---

## Executive Summary

This V29 audit cycle performed a comprehensive, line-by-line adversarial review of all 8 source files in the `era-volume` crate (5,369 LOC). The audit scope included:

1. **Verified all 10 V28 findings** — confirmed all remain fixed in the current codebase.
2. **Verified all 9 deferred items** from the master audit — documented current status.
3. **Conducted a complete `as` cast inventory** — 110 casts across all 8 files. Zero runtime-risky casts.
4. **Investigated all 6 V28 recommended next steps** — 5 clean, 1 minor informational finding.
5. **Cross-file consistency analysis** — overhead formulas, error handling patterns, API surface, constant usage.
6. **Discovered 28 new findings** (V29-01 through V29-28): 0 Critical, 0 High, 4 Medium, 10 Low, 14 Info.

### Key Findings in V29

- **BC17-04 (pub field bypass)**: 48 pub fields across 7 structs allow construction/mutation bypassing validation. DEFERRED — cross-crate constraint prevents making fields private without breaking downstream consumers (era-engine, era-index).
- **`saturating_add` masks overflow**: `read_erasure_shards` uses `saturating_add` in error-path offset calculations, silently masking potential overflow in shard recovery.
- **`t as usize` threshold cast**: Theoretical truncation on hypothetical 16-bit targets (no current risk on 32/64-bit).
- **Footer offset validation gaps**: `last_checkpoint_offset` and `backup_header_offset` not validated against `DATA_REGION_START` minimum.

### Methodology

Full line-by-line audit of all 8 source files. Every function analyzed. All 110 `as` casts inventoried and classified. Cross-file constant consistency verified. V28 regression checks on all 10 prior findings. Competitor adversarial perspective: findings framed as if a rival security team is evaluating this code for vulnerabilities.

---

## V28 Verification Summary

All 10 V28 findings verified as still fixed:

| ID | Severity | Status | Notes |
|----|----------|--------|-------|
| V27-12 | P2 (Medium) | ✅ Fixed | Checkpoint footer catalog/index preservation — 6 tracking fields verified |
| V27-14 | P3 (Low) | ✅ Fixed | Shared `volume_path()` in lib.rs — both configs delegate |
| V28-01 | P2 (Medium) | ✅ Fixed | `needs_expansion()` returns `Result<bool>` with error on impossible fit |
| V28-02 | P3 (Low) | ✅ Fixed | `volume_remaining_space()` reserves full 4248-byte overhead |
| V28-03 | P3 (Low) | ✅ Fixed | `VolumePoolStatusExt::can_fit` uses consistent 4248-byte reservation |
| V28-04 | P3 (Info) | ✅ Fixed | Duplicate `u32::try_from` in `write_shard()` consolidated |
| V28-05 | P2 (Medium) | ✅ Fixed | `scan_for_typed_blocks` skips by `BlockHeader::SIZE` on oversized length |
| V28-06 | P3 (Info) | ✅ Fixed | `block_sequence` limitation documented |
| V28-07 | P3 (Info) | ✅ Fixed | `total_volumes` semantics in `rotate_volumes` clarified |
| V28-08 | P3 (Info) | ✅ Fixed | Sentinel values in `read_typed_block` documented |

### V28 Next Steps Investigation (6 areas)

| # | Area | Verdict | Notes |
|---|------|---------|-------|
| 1 | `open_append` block_sequence multi-volume | CLEAN | Imprecision is documented and acceptable — rotating offset tolerates it |
| 2 | `finalize` + `commit_checkpoint` interaction | CLEAN | Catalog/index offsets correctly preserved through checkpoint cycle |
| 3 | `set_catalog_info`/`set_index_info` validation | CLEAN | Offsets validated by downstream `from_bytes()` on read |
| 4 | Error message quality | ADEQUATE | 2 weak messages noted (Info only) |
| 5 | Scan alignment-sensitive backends | CLEAN | Byte-addressed reads, no alignment assumptions |
| 6 | Heterogeneous volume distribution | CLEAN | Structurally impossible — single `max_volume_size` per pool |

### Deferred Items Status (9 items)

| Item | Description | Status |
|------|-------------|--------|
| M1 | `block_index as u64` widening in pipeline | Still Deferred (SAFE — 64-bit guard) |
| M2 | `original_size: 0` sentinel in `read_typed_block` | Fixed (V28-08, documented) |
| M3 | Test cast `(size * 2) as u32` | Still Deferred (ACCEPTABLE — test-only) |
| P8-01 | Shard write coalescing | Verified (N+3→2 syscalls per shard) |
| P8-03 | `SuperHeader::to_bytes()` clone | Fixed (confirmed no unnecessary clone) |
| BC17-04 | Pub fields bypass validation | Deferred (cross-crate constraint) |
| E5b | Terse "Invalid magic" in footer | Still Deferred (OPTIONAL) |
| E5c | Terse "Checksum mismatch" in footer | Still Deferred (OPTIONAL) |
| E6 | Contextless `?` propagation | Still Deferred (low severity) |

---

## Findings Summary

| ID | Severity | Category | File | Title | Status |
|----|----------|----------|------|-------|--------|
| V29-01 | Medium | Security | header.rs:272,683 | `t as usize` threshold cast bypasses on 16-bit targets | FIXABLE |
| V29-02 | Medium | Security | header.rs:68-75 | EncryptedVolumeKey pub fields bypass min/max size validation (BC17-04) | DEFERRED |
| V29-03 | Medium | Security | header.rs:101-110 | RecipientSlot pub fields bypass `validate()` bounds (BC17-04) | DEFERRED |
| V29-04 | Medium | Security | header.rs:181-211, footer.rs:62-95 | SuperHeader/Footer pub fields bypass construction validation (BC17-04) | DEFERRED |
| V29-05 | Low | Security | footer.rs:392-393 | `last_checkpoint_offset` and `backup_header_offset` not validated | FIXABLE |
| V29-06 | Low | Logic | footer.rs:385 | `min_data_end` uses `HEADER_SIZE+FOOTER_SIZE` instead of `DATA_REGION_START` | FIXABLE |
| V29-07 | Low | Security | reader.rs:259,268,282 | `saturating_add` in erasure shard offset masks overflow silently | FIXABLE |
| V29-08 | Low | Logic | writer.rs:450 | `BlockLocation.total_size` omits `BlockHeader::SIZE` | FALSE POSITIVE |
| V29-09 | Low | Logic | writer.rs:458 | `block_count` uses `saturating_add` — silent cap at u32::MAX | FIXABLE |
| V29-10 | Low | Logic | writer.rs:486,492 | `write_raw` lacks `MAX_SHARD_SIZE` validation (asymmetric with `write_canonical_block`) | FIXABLE |
| V29-11 | Low | Code Quality | header.rs:364 | RecipientType naming mismatch: `Argon2idPassword` ↔ `ScryptPassword` in proto | DEFERRED |
| V29-12 | Low | Code Quality | distribution.rs:73 | `validate_volume_count()` returns `String` instead of `EraError` | FIXABLE |
| V29-13 | Low | Code Quality | multi_volume.rs:317-320 | Reader discovery path doesn't use shared `volume_path()` | FIXABLE |
| V29-14 | Low | Code Quality | volume_pool.rs, multi_volume.rs | "path has no filename" error message duplicated 15x | DEFERRED |
| V29-15 | Info | Security | header.rs:14 | `unwrap_or(Duration::from_secs(0))` on pre-epoch clock produces timestamp 0 | — |
| V29-16 | Info | Code Quality | header.rs:180 | SuperHeader missing `PartialEq` derive | — |
| V29-17 | Info | Code Quality | header.rs:34 | `DATA_REGION_START` const `as u64` widening — safe | — |
| V29-18 | Info | Code Quality | header.rs:368,460 | `unwrap_or_default()` for key_id roundtrip — correct | — |
| V29-19 | Info | Performance | header.rs:336-341 | `next_volume()` clones recipients/config/EVK | — |
| V29-20 | Info | Code Quality | footer.rs:120 | `with_catalog` `#[allow(clippy::too_many_arguments)]` | — |
| V29-21 | Info | Code Quality | reader.rs:446 | `consecutive_misses = 0` reset on oversized block — premature | — |
| V29-22 | Info | Performance | reader.rs:147-150 | Floating footer recovery re-reads footers after 1MB scan | — |
| V29-23 | Info | Code Quality | writer.rs:305 | Error message "max_size required for volumes" not operator-actionable | — |
| V29-24 | Info | Code Quality | writer.rs:504 | `finalize()` delegates with 6 zero args | — |
| V29-25 | Info | Logic | writer.rs:563 | `finalize_with_catalog` overwrites position to `pad_target` | — |
| V29-26 | Info | Consistency | distribution.rs, volume_pool.rs | 4248-byte overhead formula duplicated 5x — extract constant | — |
| V29-27 | Info | Code Quality | distribution.rs:102 | `HEADER_SIZE` used instead of `BACKUP_HEADER_RESERVATION` (same value, different name) | — |
| V29-28 | Info | API Design | multi_volume.rs | `remaining_space()` private vs `would_fit()` public — inconsistent API | — |

**Summary:** 0 Critical | 0 High | 4 Medium | 13 Low | 14 Info

---

## Detailed Findings

### V29-01 [Medium] — `t as usize` threshold cast bypasses on 16-bit targets

**File:** `header.rs:272`, `header.rs:683`  
**Category:** Security — Type Safety

**Problem:**  
The threshold `t` (u32) is cast to `usize` for comparison against `recipients.len()`:
```rust
// header.rs:272 (SuperHeader::new)
if (t as usize) > recipients.len() {

// header.rs:683 (TryFrom<proto::SuperHeader>)
if (t as usize) > recipients.len() {
```
On any platform where `usize` ≥ 32 bits (all current Rust targets), `u32 as usize` is lossless. On a hypothetical 16-bit target, `u32` → `usize` would silently truncate, potentially allowing threshold 65537 to appear as 1, bypassing the `T ≤ N` check. The 64-bit compile_error guard in `lib.rs:9-10` makes this safe on all currently compilable targets, but the code is technically unsound for any future platform widening support.

**Impact:** Theoretical — no real-world exploitable path exists on 32/64-bit targets.

**Suggested Fix:**
```rust
let t_usize = usize::try_from(t).map_err(|_| EraError::InvalidConfig(
    format!("threshold {} exceeds platform usize::MAX", t)
))?;
if t_usize > recipients.len() { ... }
```

---

### V29-02 [Medium] — EncryptedVolumeKey pub fields bypass validation (BC17-04)

**File:** `header.rs:68-75`  
**Category:** Security — Encapsulation Bypass

**Problem:**  
`EncryptedVolumeKey` has all fields `pub`:
```rust
pub struct EncryptedVolumeKey {
    pub algorithm: KeyWrapAlgorithm,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
```
The `TryFrom<proto::EncryptedVolumeKey>` impl enforces ciphertext size bounds (16–4096 bytes), but direct construction bypasses these checks. Code can create an `EncryptedVolumeKey` with empty or oversized ciphertext.

**Impact:** Invalid EVK instances in memory. Would fail at crypto time but not at construction time. Defense-in-depth violation.

**Status:** DEFERRED — Making fields private requires accessor methods and would break downstream consumers in `era-engine` (e.g., `era-engine/src/auth.rs` accesses `.nonce`, `.ciphertext` directly). Cross-crate changes locked to `crates/era-volume/src/` only.

---

### V29-03 [Medium] — RecipientSlot pub fields bypass `validate()` bounds (BC17-04)

**File:** `header.rs:101-110`  
**Category:** Security — Encapsulation Bypass

**Problem:**  
`RecipientSlot` has all fields `pub`:
```rust
pub struct RecipientSlot {
    pub r_type: RecipientType,
    pub key_id: Option<[u8; 8]>,
    pub params: Vec<u8>,
    pub encrypted_master_key: Vec<u8>,
}
```
While `validate()` checks `params.len() ≤ 4096` and `encrypted_master_key.len()` bounds (24–4096), code can mutate fields after construction to exceed limits.

**Impact:** Same as V29-02. `SuperHeader::new()` validates slots, but post-construction mutation is unchecked.

**Status:** DEFERRED — Same cross-crate constraint as V29-02. `era-engine/src/auth.rs` accesses `.params`, `.encrypted_master_key` directly.

---

### V29-04 [Medium] — SuperHeader/Footer pub fields bypass construction validation (BC17-04)

**File:** `header.rs:181-211`, `footer.rs:62-95`  
**Category:** Security — Encapsulation Bypass

**Problem:**  
`SuperHeader` has all 14 fields `pub`, `Footer` has all 16 fields `pub`. Direct mutation can bypass:
- SuperHeader: magic, version, recipient count, threshold validation
- Footer: version, checksum, offset validations

**Impact:** 48 total pub fields across `EncryptedVolumeKey` (3), `RecipientSlot` (4), `SuperHeader` (14), `Footer` (16), plus additional fields in other structs. Any code with mutable access can create logically invalid instances.

**Status:** DEFERRED — Cross-crate constraint. 48 fields accessed by era-engine, era-index, and other downstream crates.

---

### V29-05 [Low] — Footer offset validation gaps

**File:** `footer.rs:392-393`  
**Category:** Security — Missing Input Validation

**Problem:**  
`from_bytes()` validates `catalog_offset` and `index_offset` against `HEADER_SIZE` via `validate_offset_above_header()`, but does NOT validate `last_checkpoint_offset` or `backup_header_offset`:
```rust
Self::validate_offset_above_header("catalog_offset", footer.catalog_offset)?;
Self::validate_offset_above_header("index_offset", footer.index_offset)?;
// last_checkpoint_offset and backup_header_offset NOT validated
```

**Impact:** A crafted footer could point `last_checkpoint_offset` into the header region. Consumers reading from this offset would read header data instead of checkpoint data.

**Suggested Fix:**
```rust
Self::validate_offset_above_header("last_checkpoint_offset", footer.last_checkpoint_offset)?;
Self::validate_offset_above_header("backup_header_offset", footer.backup_header_offset)?;
```

---

### V29-06 [Low] — `min_data_end` uses wrong constant semantics

**File:** `footer.rs:385`  
**Category:** Logic — Semantic Correctness

**Problem:**  
```rust
let min_data_end = (crate::header::HEADER_SIZE + FOOTER_SIZE) as u64;
```
This computes `4096 + 128 = 4224`, which happens to equal `DATA_REGION_START`. But `FOOTER_SIZE` is the primary footer size, not the backup footer gap. The correct semantic expression is `DATA_REGION_START` which represents where the data region begins.

**Impact:** Numerically correct (FOOTER_SIZE == BACKUP_FOOTER_GAP == 128), but if either constant ever changes independently, this would silently break.

**Suggested Fix:**
```rust
let min_data_end = crate::header::DATA_REGION_START;
```

---

### V29-07 [Low] — `saturating_add` in erasure shard offset masks overflow

**File:** `reader.rs:259,268,282`  
**Category:** Security — Silent Failure

**Problem:**  
In `read_erasure_shards`, the error-path offset calculations use `saturating_add`:
```rust
// Error path offset advance
offset = offset.saturating_add(shard_header.length as u64);
```
If `offset` is near `u64::MAX`, `saturating_add` would silently saturate instead of returning an error. The success path correctly uses `checked_add` with error propagation. The asymmetry means a corrupted shard header with a large length field in the error recovery path could cause the scanner to silently stop advancing.

**Impact:** Low practical risk — requires `offset` near `u64::MAX` which implies a volume larger than 16 exabytes. But the inconsistency with `checked_add` in the success path is a code quality concern.

**Suggested Fix:** Replace `saturating_add` with `checked_add` and propagate error:
```rust
offset = offset.checked_add(shard_header.length as u64)
    .ok_or_else(|| EraError::CorruptedFooter("shard offset overflow".into()))?;
```

---

### V29-08 [Low] — `BlockLocation.total_size` omits `BlockHeader::SIZE` — FALSE POSITIVE

**File:** `writer.rs:450`  
**Category:** Logic — Inaccurate Accounting  
**Status:** FALSE POSITIVE

**Analysis:**  
The original finding incorrectly identified a phantom field `total_size` on `BlockLocation`. The actual field is `encrypted_size: u32`, which is documented as "Size of the encrypted block (or first shard if erasure-coded)." This field intentionally stores only the encrypted data payload size, NOT the total on-disk footprint including `BlockHeader::SIZE`.

Evidence confirming correct behavior:
- `BlockLocation::single()` signature: `encrypted_size: u32` parameter
- `era-engine/src/volume_stage.rs:288` assertion: `assert_eq!(location.encrypted_size, block.data.len() as u32)` — confirms data-only semantics
- Volume position tracking (`self.position += total_len`) correctly includes `BlockHeader::SIZE` separately for disk space accounting

The `encrypted_size` and the on-disk position tracking serve different purposes:
- `encrypted_size`: how many bytes of encrypted data (for the reader to know how much to read after the BlockHeader)
- `total_len` (position tracking): how much disk space consumed (BlockHeader + data)

**Impact:** None — code is correct as-is.

### V29-09 [Low] — `block_count` uses `saturating_add` — silent cap

**File:** `writer.rs:458`  
**Category:** Logic — Silent Overflow

**Problem:**  
```rust
self.block_count = self.block_count.saturating_add(1);
```
At `u32::MAX` (4.29 billion) blocks, the count silently stops incrementing. The footer would report an incorrect block count.

**Impact:** Extremely unlikely — would require 4.29 billion blocks in a single volume. But `checked_add` with error propagation would be more defensive.

**Suggested Fix:**
```rust
self.block_count = self.block_count.checked_add(1)
    .ok_or_else(|| EraError::InvalidConfig("block count overflow".into()))?;
```

---

### V29-10 [Low] — `write_raw` lacks `MAX_SHARD_SIZE` validation

**File:** `writer.rs:486,492`  
**Category:** Logic — Asymmetric Validation

**Problem:**  
`write_canonical_block` validates `block.data.len() > MAX_SHARD_SIZE` before writing, but `write_raw` does not perform this check. This creates an asymmetry where raw writes could produce blocks that the reader would reject with "block too large."

**Impact:** Only affects callers using `write_raw` directly. `VolumePool` validates shard sizes before calling `write_raw`, providing upstream protection. But defense-in-depth suggests validating at the write site too.

**Suggested Fix:**
```rust
pub async fn write_raw(&mut self, block_type: BlockType, data: &[u8]) -> Result<BlockLocation> {
    if data.len() > MAX_SHARD_SIZE {
        return Err(EraError::InvalidConfig(format!(
            "raw block size {} exceeds MAX_SHARD_SIZE ({})", data.len(), MAX_SHARD_SIZE
        )));
    }
    // ... existing code
}
```

---

### V29-11 [Low] — RecipientType naming mismatch with proto

**File:** `header.rs:364`, `header.rs:452-453`, `header.rs:515-516`  
**Category:** Code Quality — Naming Confusion

**Problem:**  
The Rust enum variant `RecipientType::Argon2idPassword` maps to proto enum `RECIPIENT_TYPE_SCRYPT_PASSWORD`. The actual KDF is Argon2id — the proto name is a legacy artifact from when Scrypt was used. The roundtrip is correct but the naming confuses maintainers.

**Impact:** Maintainer confusion only. No functional issue.

**Status:** DEFERRED — Renaming the proto enum would require a proto schema migration. Low priority since the wire format is stable.

---

### V29-12 [Low] — `validate_volume_count()` returns `String` instead of `EraError`

**File:** `distribution.rs:73`  
**Category:** Code Quality — Error Type Inconsistency

**Problem:**  
```rust
fn validate_volume_count(&self, volume_count: usize) -> Result<(), String> {
```
This is the only function in the entire `era-volume` crate that returns `Result<(), String>`. All other validation functions return `Result<(), EraError>`. Callers must `.map_err()` to convert.

**Impact:** Inconsistent API. Extra conversion boilerplate at call sites.

**Suggested Fix:** Change return type to `Result<(), EraError>` and wrap messages in `EraError::InvalidConfig`.

---

### V29-13 [Low] — Reader discovery doesn't use shared `volume_path()`

**File:** `multi_volume.rs:317-320`  
**Category:** Code Quality — DRY / V27-14 Partial Fix

**Problem:**  
```rust
let base_path = first_volume_path.with_extension("");
for seq in 1..MAX_VOLUME_SCAN {
    let ext = format!("era.{:03}", seq);
    let next_path = base_path.with_extension(ext);
```
The reader's discovery loop manually constructs paths instead of using `crate::volume_path()`. Functionally equivalent for seq ≥ 1, but divergence-prone if `volume_path()` is ever modified.

**Suggested Fix:**
```rust
let base_path = first_volume_path.with_extension("");
for seq in 1..MAX_VOLUME_SCAN {
    let next_path = crate::volume_path(&base_path, seq);
```

---

### V29-14 [Low] — "path has no filename" error duplicated 15 times

**File:** `volume_pool.rs` (9x), `multi_volume.rs` (6x)  
**Category:** Code Quality — Copy-Paste

**Problem:**  
The pattern `.file_name().ok_or_else(|| EraError::InvalidConfig("path has no filename".into()))?` is repeated 15 times.

**Impact:** No functional issue, but a DRY violation that increases maintenance burden.

**Status:** DEFERRED — Low priority. Could extract a `fn validate_path_has_filename(path: &Path)` helper.

---

### V29-15 through V29-28 [Info] — Informational Findings

| ID | File | Description |
|----|------|-------------|
| V29-15 | header.rs:14 | `SystemTime::elapsed().unwrap_or(Duration::from_secs(0))` on pre-epoch clock silently produces timestamp 0. No practical impact. |
| V29-16 | header.rs:180 | `SuperHeader` missing `PartialEq` derive — blocked by `ArchiveConfig` not deriving `PartialEq`. Prevents `assert_eq!` in tests. |
| V29-17 | header.rs:34 | `DATA_REGION_START` const uses `as u64` — compile-time widening, safe. |
| V29-18 | header.rs:368,460 | `unwrap_or_default()` for key_id proto roundtrip — correct `None` → empty bytes → `None` semantics. |
| V29-19 | header.rs:336-341 | `next_volume()` clones recipients Vec, config, EVK. Up to ~2MB with 256 recipients. Acceptable — not a hot path. |
| V29-20 | footer.rs:120 | `with_catalog` has `#[allow(clippy::too_many_arguments)]` — `FooterBuilder` exists as alternative. |
| V29-21 | reader.rs:446 | `consecutive_misses = 0` on oversized block in scan — resets counter prematurely, but bounded by `MAX_SCAN_RESULTS`. |
| V29-22 | reader.rs:147-150 | Floating footer recovery reads up to 1MB then re-reads individual footers. Minor redundancy. |
| V29-23 | writer.rs:305 | Error "max_size required for volumes" not operator-actionable. Could include expected config parameter name. |
| V29-24 | writer.rs:504 | `finalize()` delegates to `finalize_with_catalog` with 6 zero args. Could use named default. |
| V29-25 | writer.rs:563 | `finalize_with_catalog` overwrites `position` to `pad_target`, masking actual data end offset. By design for padding. |
| V29-26 | distribution.rs, volume_pool.rs | 4248-byte overhead formula duplicated 5x — could extract shared constant `PER_VOLUME_OVERHEAD`. |
| V29-27 | distribution.rs:102 | Uses `HEADER_SIZE` vs volume_pool.rs's `BACKUP_HEADER_RESERVATION` — same value (4096), different names. |
| V29-28 | multi_volume.rs | `remaining_space()` is private but `would_fit()` is public — inconsistent visibility vs VolumePool pattern. |

---

## `as` Cast Inventory Summary

110 total `as` casts across all 8 source files:

| File | Total | SAFE | TEST-ONLY | RISKY |
|------|-------|------|-----------|-------|
| header.rs | 9 | 9 | 0 | 0 |
| footer.rs | 3 | 3 | 0 | 0 |
| reader.rs | 38 | 38 | 0 | 0 |
| writer.rs | 14 | 13 | 1 | 0 |
| volume_pool.rs | 29 | 28 | 1 | 0 |
| distribution.rs | 6 | 6 | 0 | 0 |
| multi_volume.rs | 11 | 8 | 3 | 0 |
| lib.rs | 0 | 0 | 0 | 0 |
| **Total** | **110** | **105** | **5** | **0** |

**Key Safety Guarantees:**
- 64-bit `compile_error!` guard (`lib.rs:9-10`) ensures all `usize ↔ u64` casts are lossless
- All narrowing casts have preceding `try_from()` or bounds checks
- 5 test-only casts use small, fixed values — no overflow risk
- Zero runtime-risky casts in production code

---

## Score Breakdown

| Category | Weight | Score | Notes |
|----------|--------|-------|-------|
| Security | 35% | 32/35 | All V28 security fixes verified. BC17-04 pub field bypass affects 48 fields (deferred). `t as usize` theoretical. Footer offset validation gaps fixable. |
| Logic | 25% | 24/25 | V29-08 reclassified as FALSE POSITIVE. `saturating_add` and `block_count` findings fixed. |
| Performance | 15% | 14/15 | V28-05 scan skip fix verified. `next_volume()` clone is acceptable. No hot-path concerns. |
| Code Quality | 15% | 13/15 | Proto naming mismatch. Error type inconsistency. DRY violations (15x path error, 5x overhead formula). Reader path construction not using shared utility. |
| Testing | 10% | 10/10 | 217 tests (18 new V29 audit tests). SuperHeader missing `PartialEq` limits test ergonomics. |

**Total Score: 93/100** (post-fix)

**Post-fix improvement**: 8 findings fixed (V29-01, V29-05, V29-06, V29-07, V29-09, V29-10, V29-12, V29-13), V29-08 reclassified as FALSE POSITIVE. Score: 90 (V28) → 91 (pre-fix) → 93 (post-fix).

**Remaining gap to 100:** BC17-04 (48 pub fields) remains the primary deduction (-3), plus deferred items (-2) and minor informational items (-2).

---

## Verification

```
$ cargo clippy -p era-volume --all-targets -- -D warnings
# 0 warnings, 0 errors

$ cargo test -p era-volume
# 217 tests: 217 passed, 0 failed, 0 ignored

$ cargo fmt --all -- --check
# Exit code 0 (clean)

Post-fix changes: 8 source files modified, 1 test file created (adversarial_audit_v29.rs, 18 tests)
Fixed findings: V29-01, V29-05, V29-06, V29-07, V29-09, V29-10, V29-12, V29-13
Reclassified: V29-08 (FALSE POSITIVE)
```

---

## Recommended Next Steps (V30)

1. **BC17-04 Resolution**: Plan a cross-crate refactor to make struct fields private across `EncryptedVolumeKey`, `RecipientSlot`, `SuperHeader`, and `Footer`. Requires coordinated changes in `era-engine`, `era-index`, and other consumers. Consider a builder + accessor pattern.
2. **Proto Schema Cleanup**: Rename `RECIPIENT_TYPE_SCRYPT_PASSWORD` to `RECIPIENT_TYPE_ARGON2ID_PASSWORD` in the protobuf schema. Project is pre-launch, so wire compatibility is not a concern.
3. **Extract `PER_VOLUME_OVERHEAD` constant**: Deduplicate the 5 occurrences of the 4248-byte overhead calculation into a single shared constant.
4. **Extract path validation helper**: Replace 15 occurrences of `"path has no filename"` error pattern with a shared utility function.
5. **Test header factory**: Extract duplicated `create_test_header()` from 4 test modules into a shared `#[cfg(test)]` utility.
6. **`PartialEq` for SuperHeader**: Add `PartialEq` derive to `ArchiveConfig` (in era-common) to enable `PartialEq` on `SuperHeader`, improving test ergonomics.
