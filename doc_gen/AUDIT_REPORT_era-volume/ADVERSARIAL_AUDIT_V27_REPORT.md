# ERA Volume — Adversarial Audit V27 Report

**Audit Date:** 2026-02-27  
**Module:** `crates/era-volume`  
**Auditor:** Competitive Adversarial Audit (V27)  
**Previous Audit:** V26 (Score: 84/100, 21 findings — 14 fully fixed, 7 partially fixed/accepted)  
**Score This Round:** 86/100 (pre-fix)

---

## Executive Summary

This V27 audit builds on the V26 cycle. All 21 V26 findings were verified:
- **14 fully fixed** (P0-1 through P3-7)
- **7 partially fixed or accepted as-is** (P1-6, P2-1, P3-2 through P3-6)

V27 discovered **16 new issues** across security, logic, performance, and code quality categories. Two are P0 (critical) and could lead to silent data corruption or incorrect archive parsing. One P2 issue (Vec resize after rotation) is the most dangerous runtime bug — it can cause a panic in production.

---

## Findings Summary

| ID | Severity | Category | File | Status |
|----|----------|----------|------|--------|
| V27-01 | P0 (Critical) | Security | header.rs:139,164 | OPEN |
| V27-02 | P0 (Critical) | Logic | footer.rs:343 | OPEN |
| V27-03 | P1 (High) | Code Quality | multi_volume.rs:210 | OPEN |
| V27-04 | P1 (High) | Security | writer.rs:323 | OPEN |
| V27-05 | P1 (High) | Security | volume_pool.rs:503 | OPEN |
| V27-06 | P1 (High) | Security | multi_volume.rs:134 | OPEN |
| V27-07 | P1 (High) | Logic | reader.rs:331 | OPEN |
| V27-08 | P1 (High) | Security | reader.rs:399 | OPEN |
| V27-09 | P2 (Medium) | Logic/Runtime | volume_pool.rs:600 | OPEN |
| V27-10 | P2 (Medium) | Logic | multi_volume.rs:320 | OPEN |
| V27-11 | P2 (Medium) | Security | volume_pool.rs | OPEN |
| V27-12 | P2 (Medium) | Logic | writer.rs:197-204 | OPEN |
| V27-13 | P3 (Low) | Consistency | header.rs:128/375 | OPEN |
| V27-14 | P3 (Low) | Code Quality | multi_volume.rs/volume_pool.rs | OPEN |
| V27-15 | P3 (Low) | Performance | volume_pool.rs:535 | OPEN |
| V27-16 | P3 (Low) | Testing | writer.rs:465 | OPEN |

---

## Detailed Findings

### V27-01 [P0/Critical] — `as i64` cast on `creation_time` silently truncates after year 2262

**File:** `header.rs` lines 136-139, 161-164  
**Category:** Security — Silent Data Corruption

**Problem:**  
Both `SuperHeader::new()` and `next_volume()` compute `creation_time` as:
```rust
.as_secs() as i64
```
`Duration::as_secs()` returns `u64`. After year 2262 (when `u64` seconds exceeds `i64::MAX`), this cast silently truncates to a negative timestamp, producing a corrupted header that may confuse downstream tools or archival verification.

**Impact:** Silent data corruption on any system where system clock exceeds year 2262. While unlikely today, archival systems are designed for long-term storage and should handle time correctly.

**Fix:**  
```rust
i64::try_from(duration.as_secs())
    .map_err(|_| EraError::InvalidConfig("creation_time exceeds i64::MAX".into()))?
```

---

### V27-02 [P0/Critical] — Footer `version == 0` accepted during deserialization

**File:** `footer.rs` line 343  
**Category:** Logic — Invalid State Accepted

**Problem:**  
The footer version validation rejects future versions (`version > FOOTER_VERSION`) but accepts `version == 0`. There is no valid footer format with version 0. Accepting it means a zeroed-out footer (e.g., from an incomplete write or uninitialized storage) could pass validation if it happens to have a valid checksum.

**Current code:**
```rust
if footer.version > FOOTER_VERSION { // allows version 0
```

**Fix:**
```rust
if footer.version == 0 || footer.version > FOOTER_VERSION {
```

---

### V27-03 [P1/High] — Hardcoded magic number `4096` in `remaining_space()`

**File:** `multi_volume.rs` line 210  
**Category:** Code Quality — Fragile Constants

**Problem:**
```rust
let reserved = FOOTER_SIZE as u64 + 4096; // Reserve for footer + padding
```
The `4096` is a hardcoded magic number that should reference `BACKUP_HEADER_RESERVATION` (already defined in `volume_pool.rs`) or `HEADER_SIZE`. If the header size ever changes, this reservation would silently become incorrect.

**Fix:** Use `HEADER_SIZE as u64` (which equals 4096 and is the correct semantic meaning — backup header reservation).

---

### V27-04 [P1/High] — `data.len() as u64` unchecked cast in `write_raw()`

**File:** `writer.rs` lines 323, 329  
**Category:** Security — Integer Overflow

**Problem:**
```rust
self.position += data.len() as u64;
self.raw_bytes_written += data.len() as u64;
```
While `usize` to `u64` is safe on 64-bit platforms, this is architecturally inconsistent with the project's discipline of using `u32::try_from()` / `u64::try_from()` for all narrowing casts. On a 32-bit platform, `usize` is always ≤ `u32::MAX` so the cast is safe, but the code should document this assumption or use explicit conversion.

**Fix:** Add `u64::try_from(data.len())` for consistency, or document the safety assumption.

---

### V27-05 [P1/High] — `shard_data.len() as u32` unchecked truncation in `write_shard()`

**File:** `volume_pool.rs` line 503  
**Category:** Security — Silent Truncation

**Problem:**
```rust
let shard_header = ShardHeader::new(shard_data.len() as u32, crc);
```
If `shard_data.len() > u32::MAX` (4GB), this silently truncates the length field. While `validate_shard_size()` limits to `max_volume_size`, there is no explicit check that shard size fits in `u32`. The `MAX_SHARD_SIZE` is 16MB which is well within u32 range, but the defensive check is missing.

**Fix:** Use `u32::try_from(shard_data.len())`.

---

### V27-06 [P1/High] — `block.data.len() as u32` unchecked truncation in `write_canonical_block()`

**File:** `multi_volume.rs` line 134  
**Category:** Security — Silent Truncation

**Problem:**
```rust
let block_size = block.data.len() as u32;
```
Same issue as V27-05. The `MAX_SHARD_SIZE` constant makes overflow practically impossible, but the code should use `u32::try_from()` for defense-in-depth.

---

### V27-07 [P1/High] — `original_size` hardcoded to 0 in `read_typed_block()`

**File:** `reader.rs` line 331  
**Category:** Logic — Information Loss

**Problem:**
```rust
let block = EncryptedMacroBlock {
    block_id: BlockId::new(location.slot_index as u64),
    data,
    original_size: 0,    // always 0
    compressed_size: header.length,
    chunk_count: 0,      // always 0
};
```
The reader constructs an `EncryptedMacroBlock` with `original_size: 0` even though the correct size could be inferred from the data. This is a documentation/design issue — the reader has no access to original size from BlockHeader alone. This should be documented as "unknown at read time" rather than silently set to 0.

**Impact:** Downstream consumers cannot distinguish "original_size unknown" from "original_size is actually 0".

**Fix:** Document clearly with a comment. If a sentinel value is available, use it (e.g., `u32::MAX` for "unknown"). Otherwise, document that `original_size` and `chunk_count` are not available from the on-disk format.

---

### V27-08 [P1/High] — `found_blocks.len() as u32` potential overflow in `scan_for_typed_blocks()`

**File:** `reader.rs` line 399  
**Category:** Security — Integer Overflow

**Problem:**
```rust
found_blocks.push(BlockLocation::single(
    self.header.volume_id,
    found_blocks.len() as u32, // truncates if > 4B blocks
    current_offset,
    BlockHeader::SIZE as u32 + header.length,
));
```
If a malicious volume claims to have >4 billion blocks, `found_blocks.len() as u32` wraps. Practically impossible with `MAX_SHARD_SIZE` limits, but the code should use `u32::try_from()`.

**Fix:** Use `u32::try_from(found_blocks.len())` with an error return.

---

### V27-09 [P2/Medium] — `volumes_with_header` Vec resize bug after rotation (MOST CRITICAL BUG)

**File:** `volume_pool.rs` line 600  
**Category:** Logic/Runtime — Potential Panic

**Problem:**
```rust
let mut volumes_with_header: Vec<bool> = vec![false; self.writers.len()];
// ...
for (shard_idx, shard_data) in shards.iter().enumerate() {
    let slot = self.shard_volume_slot(shard_idx)?;
    let need_header = !volumes_with_header[slot]; // INDEX OUT OF BOUNDS if rotation happened
```
The Vec is sized to `self.writers.len()` at the start. If any `write_shard()` call triggers `rotate_volumes()` (which replaces all writers), the subsequent `shard_volume_slot()` returns an index into the new writer set, but `volumes_with_header` is still sized to the old count. If the new writer count differs, this causes an index-out-of-bounds panic.

**Impact:** Runtime panic during erasure block writes when volumes are full.

**Fix:** Re-size `volumes_with_header` after any rotation, or pre-calculate all slots and check capacity before writing.

---

### V27-10 [P2/Medium] — Non-deterministic `header()` method

**File:** `multi_volume.rs` line 320  
**Category:** Logic — Non-deterministic Behavior

**Problem:**
```rust
pub fn header(&self) -> Option<&SuperHeader> {
    self.volume_paths
        .first()
        .and_then(|_| self.readers.values().next())
        .map(|r| r.header())
}
```
`HashMap::values().next()` returns an arbitrary value — the iteration order is non-deterministic. This means `header()` might return the header from any volume, not necessarily the first one.

**Fix:** Look up the first volume's reader by its volume ID (stored during open), or use an `IndexMap` that preserves insertion order.

---

### V27-11 [P2/Medium] — No `MAX_SHARD_SIZE` validation in `write_shard()` for shard_data

**File:** `volume_pool.rs`  
**Category:** Security — Missing Validation

**Problem:**
`write_shard()` calls `validate_shard_size()` which only checks against `max_volume_size`, not against `MAX_SHARD_SIZE`. A shard could be larger than `MAX_SHARD_SIZE` (16MB) but smaller than `max_volume_size`, and would be written successfully but rejected by the reader.

**Fix:** Add `MAX_SHARD_SIZE` validation in `write_shard()`.

---

### V27-12 [P2/Medium] — `commit_checkpoint` footer loses catalog/index info

**File:** `writer.rs` lines 193-206  
**Category:** Logic — Data Loss

**Problem:**
```rust
let footer = crate::Footer::with_catalog(
    self.position, self.block_count, self.sequence,
    0, 0, 0,  // catalog_offset, catalog_size, catalog_block_id
    self.last_checkpoint_offset, self.last_checkpoint_block_id,
    0, 0, 0,  // index_offset, index_size, index_block_id
    backup_header_offset,
);
```
The checkpoint footer hardcodes 0 for catalog and index fields. If a catalog or index was written before the checkpoint, their locations are lost in the checkpoint footer. On crash recovery, the recovered footer won't have catalog/index pointers.

**Fix:** Store catalog and index offsets in `VolumeWriter` state and include them in checkpoint footers.

---

### V27-13 [P3/Low] — `SuperHeader::new()` allows empty recipients; `from_bytes()` rejects them

**File:** `header.rs` lines 128/375  
**Category:** Consistency — Asymmetric Validation

**Problem:**
- `SuperHeader::new()` accepts `recipients: Vec<RecipientSlot>` with no length check
- `SuperHeader::from_bytes()` → `TryFrom<proto::SuperHeader>` rejects `recipients.is_empty()`

This means code can construct a header that fails serialization roundtrip.

**Fix:** Add `assert!(!recipients.is_empty())` or return `Result` from `new()`.

---

### V27-14 [P3/Low] — Duplicate `volume_path()` logic

**File:** `multi_volume.rs:44-51` and `volume_pool.rs:72-79`  
**Category:** Code Quality — DRY Violation

**Problem:**
Both `MultiVolumeConfig::volume_path()` and `VolumePoolConfig::volume_path()` have identical implementations. This duplication creates maintenance risk.

**Fix:** Extract to a shared utility function.

---

### V27-15 [P3/Low] — `write_canonical_block` always prefers slot 0

**File:** `volume_pool.rs` line 535  
**Category:** Performance — Uneven Load Distribution

**Problem:**
```rust
let preferred_slot = 0; // For non-erasure, always use first volume
```
Non-erasure blocks always target slot 0 first. In a multi-volume pool, the first volume fills up while others remain empty until slot 0 is full. This is suboptimal for load distribution.

**Fix:** Use round-robin or the distribution calculator for non-erasure blocks too.

---

### V27-16 [P3/Low] — Test uses empty recipients vector

**File:** `writer.rs` line 465  
**Category:** Testing — Invalid Test Input

**Problem:**
Multiple test functions in `writer.rs` create headers with `vec![]` recipients:
```rust
let header = SuperHeader::new(ArchiveId::new(), vec![], ...);
```
This bypasses `SuperHeader::new()` with empty recipients, which would fail `from_bytes()` roundtrip. Tests should use valid recipients.

**Fix:** Use `vec![mock_recipient()]` in all tests.

---

## Score Breakdown

| Category | Weight | Score | Notes |
|----------|--------|-------|-------|
| Security | 35% | 30/35 | Two P0 casts, missing MAX_SHARD_SIZE check |
| Logic | 25% | 20/25 | Vec resize bug, non-deterministic header, checkpoint data loss |
| Performance | 15% | 13/15 | Slot 0 preference, magic numbers |
| Code Quality | 15% | 13/15 | Duplicate code, asymmetric validation |
| Testing | 10% | 10/10 | Good existing coverage, minor test input issue |

**Total Score: 86/100** (pre-fix)

---

## Recommended Fix Priority

1. **V27-09** — Vec resize bug (runtime panic risk)
2. **V27-01** — creation_time truncation (silent corruption)
3. **V27-02** — Footer version 0 (invalid state accepted)
4. **V27-05, V27-06, V27-08** — Unchecked `as u32` casts
5. **V27-04** — Unchecked `as u64` cast
6. **V27-11** — MAX_SHARD_SIZE validation gap
7. **V27-03** — Magic number 4096
8. **V27-10** — Non-deterministic header
9. **V27-12** — Checkpoint data loss
10. **V27-07** — Document original_size=0
11. **V27-13** — Asymmetric validation
12. **V27-14** — Duplicate volume_path
13. **V27-15** — Slot 0 preference
14. **V27-16** — Test recipients

---

## V26 Verification Summary

All 21 V26 findings verified. See V26 report for details.

**Fully Fixed (14):** P0-1, P0-2, P0-3, P0-4, P0-5, P1-1, P1-2, P1-3, P1-4, P1-5, P2-2, P2-3, P3-1, P3-7  
**Partially Fixed / Accepted (7):** P1-6, P2-1, P3-2, P3-3, P3-4, P3-5, P3-6
