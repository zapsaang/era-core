# ERA Volume — Adversarial Audit V30 Report

**Audit Date:** 2026-02-28  
**Module:** `crates/era-volume` (5,369 LOC, 8 source files)  
**Auditor:** Competitive Adversarial Audit (V30)  
**Previous Audit:** V29 (Score: 93/100, 28 findings — 8 fixed, 4 deferred, 1 false positive, 14 info)  
**Score This Round:** 85/100

---

## Executive Summary

This V30 audit cycle re-evaluates the `era-volume` crate under a **changed constraint**: the project is now confirmed **pre-launch**, meaning backward compatibility is NOT a constraint. All items previously deferred under the "cross-crate breaking change" rationale are now **actionable findings** with no valid reason to remain open.

The audit scope included:

1. **Verified all 8 V29-fixed findings** — confirmed V29-01, V29-05, V29-06, V29-07, V29-09, V29-10, V29-12, V29-13 remain fixed.
2. **Promoted 4 previously-deferred items** to actionable findings (BC17-04 pub fields, V29-11 proto rename, V29-14 path helper, V29-26 overhead constant).
3. **Promoted 2 previously-deferred error quality items** (E5b terse "Invalid magic", E5c terse "Checksum mismatch").
4. **Discovered 4 new findings** from line-by-line source review not previously reported.
5. **Documented 1 design decision** (SuperHeader lacks independent checksum — AEAD tag provides implicit integrity).

### Score Delta Explanation: 93 → 85 (−8 points)

The score **decreased** because:
- **−5 points**: BC17-04 (37 pub fields across 4 structs) was deferred in V29 due to "cross-crate constraint." Pre-launch status removes this constraint. 37 pub fields allowing construction/mutation that bypasses validation is now a HIGH-severity encapsulation gap.
- **−2 points**: Previously-deferred items (proto rename, path duplication, overhead constant, terse errors) are now actionable. Their continued existence degrades code quality.
- **−1 point**: 4 new findings discovered (distribution zero-volume, missing `#[must_use]`, floating footer archive cross-check, backup header bounds).

### Methodology

Full findings-based audit leveraging complete line-by-line review of all 8 source files (5,369 LOC). V29 regression verification. All previously-deferred items re-evaluated under pre-launch constraints. Competitor adversarial perspective: findings framed as if a rival security team is evaluating this code for production readiness.

### Design Decision: SuperHeader Checksum

The SuperHeader lacks an independent integrity checksum (unlike the Footer which has Blake3). This is a **design decision, NOT a bug**:
- The SuperHeader's `EncryptedVolumeKey` is wrapped with XChaCha20-Poly1305 AEAD, which provides implicit integrity via the authentication tag.
- Any tampering with header bytes causes AEAD decryption failure, which is a hard error.
- Adding an independent checksum would require a format version migration (v8.1 → v8.2 or v9).
- The AEAD tag already provides stronger integrity guarantees than a standalone checksum.

**Recommendation**: If a header checksum is ever desired, it should be planned as part of a major format revision, not retrofitted.

---

## V29 Verification Summary

All 8 V29-fixed findings verified as still fixed:

| ID | Severity | Status | Notes |
|----|----------|--------|-------|
| V29-01 | Medium | ✅ Fixed | `t as usize` now uses `usize::try_from()` with error propagation |
| V29-05 | Low | ✅ Fixed | `last_checkpoint_offset` and `backup_header_offset` validated |
| V29-06 | Low | ✅ Fixed | `min_data_end` uses `DATA_REGION_START` |
| V29-07 | Low | ✅ Fixed | `saturating_add` replaced with `checked_add` in erasure recovery |
| V29-09 | Low | ✅ Fixed | `block_count` uses `checked_add` |
| V29-10 | Low | ✅ Fixed | `write_raw` validates `MAX_SHARD_SIZE` |
| V29-12 | Low | ✅ Fixed | `validate_volume_count()` returns `EraError` |
| V29-13 | Low | ✅ Fixed | Reader discovery uses `crate::volume_path()` |

V29-08 remains correctly classified as FALSE POSITIVE (no regression).

### Previously-Deferred Items — Status Change

All items previously deferred under "cross-crate breaking change" or "optional" rationale are now **promoted to actionable findings**. Pre-launch status means there are zero downstream compatibility constraints.

| Item | V29 Status | V30 Status | Reason |
|------|-----------|-----------|--------|
| BC17-04 (pub fields) | Deferred (cross-crate) | **PROMOTED → V30-01** | Pre-launch: no backward compat constraint |
| V29-11 (proto rename) | Deferred (wire compat) | **PROMOTED → V30-05** | Pre-launch: wire format not stable |
| V29-14 (path helper) | Deferred (low priority) | **PROMOTED → V30-06** | No excuse for 15x copy-paste |
| V29-26 (overhead constant) | Info | **PROMOTED → V30-07** | 5x duplication of magic formula is fixable |
| E5b (terse "Invalid magic") | Deferred (optional) | **PROMOTED → V30-08** | Error quality matters for production |
| E5c (terse "Checksum mismatch") | Deferred (optional) | **PROMOTED → V30-09** | Error quality matters for production |

---

## Findings Summary

| ID | Severity | Category | File | Title | Status |
|----|----------|----------|------|-------|--------|
| V30-01 | High | Security | header.rs, footer.rs | 37 pub fields across 4 structs bypass all validation (BC17-04) | FIXABLE |
| V30-02 | Medium | Logic | distribution.rs:38-40 | `calculate_volume()` returns 0 on `volume_count=0` — `debug_assert` only | FIXABLE |
| V30-03 | Medium | Security | reader.rs:147-170 | Floating footer recovery lacks `archive_id` cross-check | FIXABLE |
| V30-04 | Low | Security | writer.rs:550-560 | `backup_header_offset` not validated against volume bounds before write | FIXABLE |
| V30-05 | Low | Code Quality | header.rs:370-371 | Proto enum `ScryptPassword` ↔ `Argon2idPassword` naming mismatch (V29-11) | FIXABLE |
| V30-06 | Low | Code Quality | volume_pool.rs, multi_volume.rs | "path has no filename" error pattern duplicated ~15x (V29-14) | FIXABLE |
| V30-07 | Low | Consistency | distribution.rs, volume_pool.rs | 4248-byte overhead formula duplicated 5x — extract `PER_VOLUME_OVERHEAD` (V29-26) | FIXABLE |
| V30-08 | Low | Code Quality | footer.rs:354 | "Invalid magic" error lacks hex dump of actual bytes (E5b) | FIXABLE |
| V30-09 | Low | Code Quality | footer.rs:380 | "Checksum mismatch" error lacks partial hash context (E5c) | FIXABLE |
| V30-10 | Info | Code Quality | header.rs | Key accessor methods (`to_bytes`, `from_bytes`) missing `#[must_use]` | — |
| V30-11 | Info | Consistency | distribution.rs:102 | `HEADER_SIZE` used instead of `BACKUP_HEADER_RESERVATION` (V29-27 carry) | — |
| V30-12 | Info | API Design | multi_volume.rs | `remaining_space()` private vs `would_fit()` public — inconsistent (V29-28 carry) | — |
| V30-13 | Info | Code Quality | footer.rs:338 | "Footer too small" error lacks actual vs expected size | — |
| V30-14 | Info | Code Quality | header.rs:180 | SuperHeader missing `PartialEq` derive (V29-16 carry) | — |
| V30-15 | Info | Performance | header.rs:336-341 | `next_volume()` clones recipients/config/EVK (V29-19 carry) | — |

**Summary:** 0 Critical | 1 High | 2 Medium | 6 Low | 6 Info

---

## Detailed Findings

### V30-01 [High] — 37 pub fields across 4 structs bypass all validation (BC17-04)

**File:** `header.rs:68-75`, `header.rs:101-110`, `header.rs:181-211`, `footer.rs:62-95`  
**Category:** Security — Encapsulation Bypass  
**Carried from:** V29-02, V29-03, V29-04 (all previously DEFERRED)

**Problem:**  
Four core structs expose all fields as `pub`, allowing direct construction and mutation that bypasses validation:

| Struct | File | Pub Fields | Validation Bypassed |
|--------|------|-----------|---------------------|
| `EncryptedVolumeKey` | header.rs:68-75 | 3 (`algorithm`, `nonce`, `ciphertext`) | Ciphertext size bounds (16–4096 bytes) |
| `RecipientSlot` | header.rs:101-110 | 4 (`r_type`, `key_id`, `params`, `encrypted_master_key`) | `params.len() ≤ 4096`, `encrypted_master_key` bounds (24–4096) |
| `SuperHeader` | header.rs:181-211 | 14 (magic, version, volume_id, archive_id, etc.) | Magic bytes, version, threshold ≤ recipients, recipient validation |
| `Footer` | footer.rs:62-95 | 16 (magic, version, flags, offsets, checksum, etc.) | Version, offset minimums, checksum integrity |

```rust
// Example: constructing an invalid EncryptedVolumeKey that bypasses TryFrom validation
let bad_evk = EncryptedVolumeKey {
    algorithm: KeyWrapAlgorithm::XChaCha20Poly1305,
    nonce: [0u8; 24],
    ciphertext: vec![],  // Empty! TryFrom enforces 16-4096 bytes, but direct construction doesn't
};
```

**Impact:** Any code with access to these types (which includes all downstream crates: `era-engine`, `era-index`, etc.) can create logically invalid instances. Invalid instances would fail at crypto/IO time, but not at construction time. This violates defense-in-depth: validation should happen at the point of construction, not deferred to the point of use.

**V29 deferral rationale was:** "Making fields private requires accessor methods and would break downstream consumers." **V30 re-assessment:** The project is pre-launch. There are no external consumers. Breaking changes are expected and acceptable. The fix is straightforward:
1. Make all fields private (or `pub(crate)` where cross-crate access is needed)
2. Add `pub fn` getter methods for read access
3. Use builder patterns or validated constructors for write access
4. Update `era-engine` and `era-index` call sites (same repository, same PR)

**Note:** `pub(crate)` alone is insufficient because `era-engine` accesses these fields. The correct approach is private fields with public getter methods.

**Suggested Fix:**
```rust
pub struct EncryptedVolumeKey {
    algorithm: KeyWrapAlgorithm,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl EncryptedVolumeKey {
    pub fn new(algorithm: KeyWrapAlgorithm, nonce: [u8; 24], ciphertext: Vec<u8>) -> Result<Self, EraError> {
        if ciphertext.len() < 16 || ciphertext.len() > 4096 {
            return Err(EraError::InvalidConfig(format!(
                "ciphertext length {} outside bounds [16, 4096]", ciphertext.len()
            )));
        }
        Ok(Self { algorithm, nonce, ciphertext })
    }
    pub fn algorithm(&self) -> KeyWrapAlgorithm { self.algorithm }
    pub fn nonce(&self) -> &[u8; 24] { &self.nonce }
    pub fn ciphertext(&self) -> &[u8] { &self.ciphertext }
}
```

---

### V30-02 [Medium] — `calculate_volume()` returns 0 on `volume_count=0`

**File:** `distribution.rs:38-40`  
**Category:** Logic — Silent Failure

**Problem:**  
The `RoundRobinDistribution::calculate_volume()` method handles `volume_count == 0` with only a `debug_assert`:
```rust
fn calculate_volume(&self, shard_index: usize, volume_count: usize) -> usize {
    debug_assert!(volume_count > 0, "volume_count must be > 0");
    if volume_count == 0 { return 0; }
    shard_index % volume_count
}
```

In release builds, `debug_assert!` is compiled out. The function silently returns `0` for an invalid configuration. Callers using the returned index may access `writers[0]` when no writers exist, causing an index-out-of-bounds panic elsewhere.

This was noted in V26 as P3-3 but never fixed — only a `debug_assert` was added.

**Impact:** Configuration error masked in release builds. Downstream panic when index 0 is used against an empty writers array.

**Suggested Fix:**
```rust
fn calculate_volume(&self, shard_index: usize, volume_count: usize) -> Result<usize, EraError> {
    if volume_count == 0 {
        return Err(EraError::InvalidConfig("volume_count must be > 0".into()));
    }
    Ok(shard_index % volume_count)
}
```

**Note:** This changes the trait signature for `DistributionCalculator::calculate_volume`. Since the project is pre-launch, this is acceptable.

---

### V30-03 [Medium] — Floating footer recovery lacks `archive_id` cross-check

**File:** `reader.rs:147-170`  
**Category:** Security — Missing Validation

**Problem:**  
The `try_floating_footer_recovery()` method scans backward from the end of the volume to find a valid footer. When it finds a footer that passes `Footer::from_bytes()` validation (magic, version, checksum), it returns it as the recovered footer.

However, the recovered footer is not cross-checked against the volume's `archive_id` from the primary header. In a scenario where:
1. A volume file is truncated or has trailing data from a different archive appended
2. The trailing data contains a valid footer from a different archive

The recovery would return a footer belonging to a different archive. Subsequent operations would use mismatched header/footer pairs, leading to silent data corruption or confusing error messages downstream.

**Impact:** Low probability (requires specific file corruption pattern), but high impact when triggered — cross-archive footer confusion would be extremely difficult to debug.

**Suggested Fix:**
After recovering a floating footer, validate that the footer's semantic content (e.g., `block_count`, `data_end_offset`) is plausible given the header's context. If the `SuperHeader` contains an `archive_id`, the footer could include a corresponding field in a future format revision. In the interim, validate `data_end_offset ≤ file_size` and `data_end_offset ≥ DATA_REGION_START`.

---

### V30-04 [Low] — `backup_header_offset` not validated against volume bounds before write

**File:** `writer.rs:550-560` (approximate — in `finalize_with_catalog`)  
**Category:** Security — Missing Bounds Check

**Problem:**  
When computing `backup_header_offset` during finalization, the writer calculates the position based on the current data end offset. This offset is then used to seek and write the backup header. However, the computed offset is not validated to ensure it:
1. Falls within the volume's `max_volume_size` bounds
2. Does not overlap with the primary footer region
3. Is greater than `DATA_REGION_START`

While the normal write path makes these conditions naturally hold, an adversarial or buggy caller using `write_raw()` to advance `position` beyond expected bounds could trigger an out-of-bounds write.

**Impact:** Low — requires adversarial `write_raw` usage. But defense-in-depth suggests validating before seeking.

**Suggested Fix:**
```rust
if backup_header_offset < DATA_REGION_START as u64
    || backup_header_offset + HEADER_SIZE as u64 > max_volume_size
{
    return Err(EraError::InvalidConfig(format!(
        "backup_header_offset {} out of bounds [{}..{}]",
        backup_header_offset, DATA_REGION_START, max_volume_size
    )));
}
```

---

### V30-05 [Low] — Proto enum `ScryptPassword` ↔ `Argon2idPassword` naming mismatch

**File:** `header.rs:370-371`, `header.rs:467-468`  
**Category:** Code Quality — Naming Confusion  
**Carried from:** V29-11 (previously DEFERRED)

**Problem:**  
The Rust enum variant `RecipientType::Argon2idPassword` maps to/from the protobuf enum `RECIPIENT_TYPE_SCRYPT_PASSWORD`:
```rust
// header.rs:370-371 (Rust → Proto)
RecipientType::Argon2idPassword => proto::recipient_slot::RecipientType::ScryptPassword,

// header.rs:467-468 (Proto → Rust)
proto::recipient_slot::RecipientType::ScryptPassword => RecipientType::Argon2idPassword,
```

The actual KDF is Argon2id. The proto name "SCRYPT" is a legacy artifact from when Scrypt was the password KDF. The roundtrip is functionally correct, but the naming actively misleads maintainers reading the protobuf schema.

**V29 deferral rationale was:** "Renaming the proto enum would require a proto schema migration. Low priority since the wire format is stable." **V30 re-assessment:** The project is pre-launch. The wire format is NOT stable. Renaming `RECIPIENT_TYPE_SCRYPT_PASSWORD` to `RECIPIENT_TYPE_ARGON2ID_PASSWORD` in the `.proto` file is a trivial change with no compatibility impact.

**Suggested Fix:**
1. Rename in `era-common/proto/`: `RECIPIENT_TYPE_SCRYPT_PASSWORD` → `RECIPIENT_TYPE_ARGON2ID_PASSWORD`
2. Update the mapping in `header.rs` (2 match arms)
3. Run `cargo build` to regenerate protobuf code

---

### V30-06 [Low] — "path has no filename" error duplicated ~15 times

**File:** `volume_pool.rs` (lines 170-175, 229-234, 288-290, 387-392, 986-988), `multi_volume.rs` (lines 95-97, 201-203, 303-306, 321-322)  
**Category:** Code Quality — Copy-Paste / DRY Violation  
**Carried from:** V29-14 (previously DEFERRED)

**Problem:**  
The pattern:
```rust
let file_name = volume_path
    .file_name()
    .ok_or_else(|| EraError::InvalidConfig("path has no filename".into()))?;
```
is repeated approximately 15 times across `volume_pool.rs` and `multi_volume.rs`. Each instance is identical in structure and error message.

**V29 deferral rationale was:** "Low priority." **V30 re-assessment:** 15 copies of the same validation pattern is not "low priority" — it's a maintenance liability. If the error message or validation logic needs to change, 15 sites must be updated.

**Suggested Fix:**
```rust
// In lib.rs or a shared utility module
pub(crate) fn validate_filename(path: &Path) -> Result<&OsStr, EraError> {
    path.file_name()
        .ok_or_else(|| EraError::InvalidConfig(
            format!("path has no filename: {}", path.display())
        ))
}
```

Replace all 15 occurrences with `crate::validate_filename(&volume_path)?`.

---

### V30-07 [Low] — 4248-byte overhead formula duplicated 5 times

**File:** `volume_pool.rs` (lines ~466-469, ~482-485, ~507-510, ~1014-1017), `distribution.rs` (lines 102-105)  
**Category:** Consistency — Magic Formula Duplication  
**Carried from:** V29-26 (previously Info)

**Problem:**  
The per-volume overhead calculation:
```rust
FOOTER_SIZE as u64 + BACKUP_HEADER_RESERVATION + BlockHeader::SIZE as u64 + ShardHeader::SIZE as u64
// = 128 + 4096 + 128 + 24 = 4376 bytes  (or 4248 depending on which components are included)
```
appears 5 times across two files, with a subtle inconsistency: `distribution.rs:102` uses `HEADER_SIZE` where `volume_pool.rs` uses `BACKUP_HEADER_RESERVATION` (same value: 4096, but different semantic names — see V30-11).

**Impact:** If any overhead component changes (e.g., ShardHeader grows), 5 locations must be updated in lockstep. The inconsistent naming between files increases the risk of a partial update.

**Suggested Fix:**
```rust
// In lib.rs
pub const PER_VOLUME_OVERHEAD: u64 = FOOTER_SIZE as u64
    + BACKUP_HEADER_RESERVATION as u64
    + BlockHeader::SIZE as u64
    + ShardHeader::SIZE as u64;
```

---

### V30-08 [Low] — "Invalid magic" error lacks context

**File:** `footer.rs:354`  
**Category:** Code Quality — Error Diagnostics  
**Carried from:** E5b (previously DEFERRED as "optional")

**Problem:**  
```rust
if footer.magic != FOOTER_MAGIC {
    return Err(EraError::CorruptedFooter("Invalid magic".into()));
}
```

The error message does not include the actual bytes found or the expected bytes. An operator receiving this error cannot distinguish between:
- A completely zeroed footer (uninitialized storage)
- A footer from a different format (wrong file type)
- A footer with a single bit flip (media corruption)

**Suggested Fix:**
```rust
if footer.magic != FOOTER_MAGIC {
    return Err(EraError::CorruptedFooter(format!(
        "Invalid magic: expected {:?}, got {:?}",
        FOOTER_MAGIC, footer.magic
    )));
}
```

---

### V30-09 [Low] — "Checksum mismatch" error lacks context

**File:** `footer.rs:380`  
**Category:** Code Quality — Error Diagnostics  
**Carried from:** E5c (previously DEFERRED as "optional")

**Problem:**  
```rust
if computed_checksum != footer.checksum {
    return Err(EraError::CorruptedFooter("Checksum mismatch".into()));
}
```

No information about the expected vs actual checksum. Including the first 8 bytes of each hash would help operators assess whether this is bit rot (similar hashes) or a complete data mismatch (unrelated hashes).

**Suggested Fix:**
```rust
if computed_checksum != footer.checksum {
    return Err(EraError::CorruptedFooter(format!(
        "Checksum mismatch: expected {:02x}{:02x}{:02x}{:02x}..., got {:02x}{:02x}{:02x}{:02x}...",
        footer.checksum[0], footer.checksum[1], footer.checksum[2], footer.checksum[3],
        computed_checksum[0], computed_checksum[1], computed_checksum[2], computed_checksum[3],
    )));
}
```

---

### V30-10 [Info] — Key accessor methods missing `#[must_use]`

**File:** `header.rs` (various methods)  
**Category:** Code Quality — API Safety

Methods like `SuperHeader::to_bytes()`, `Footer::to_bytes()`, and other pure functions that return values without side effects lack the `#[must_use]` attribute. A caller could accidentally write `header.to_bytes();` (discarding the result) with no compiler warning.

**Impact:** Negligible in practice — these methods are always used for their return value. But `#[must_use]` is a zero-cost compile-time safety net.

---

### V30-11 [Info] — `HEADER_SIZE` vs `BACKUP_HEADER_RESERVATION` inconsistency

**File:** `distribution.rs:102`  
**Category:** Consistency  
**Carried from:** V29-27

`distribution.rs` uses `HEADER_SIZE` (4096) in the overhead formula while `volume_pool.rs` uses `BACKUP_HEADER_RESERVATION` (also 4096) for the same semantic purpose. These are the same value but different named constants. If `PER_VOLUME_OVERHEAD` is extracted (V30-07), this inconsistency is resolved automatically.

---

### V30-12 [Info] — `remaining_space()` private vs `would_fit()` public

**File:** `multi_volume.rs`  
**Category:** API Design — Inconsistent Visibility  
**Carried from:** V29-28

`MultiVolumeWriter::remaining_space()` is private while `would_fit()` is public. In `VolumePool`, the equivalent `volume_remaining_space()` is public. This inconsistency makes the API harder to reason about for callers.

---

### V30-13 [Info] — "Footer too small" error lacks size context

**File:** `footer.rs:338`  
**Category:** Code Quality — Error Diagnostics

```rust
if data.len() < FOOTER_SIZE {
    return Err(EraError::CorruptedFooter("Footer too small".into()));
}
```

Should include `format!("Footer too small: {} bytes, need {}", data.len(), FOOTER_SIZE)`.

---

### V30-14 [Info] — SuperHeader missing `PartialEq` derive

**File:** `header.rs:180`  
**Category:** Code Quality — Test Ergonomics  
**Carried from:** V29-16

`SuperHeader` cannot derive `PartialEq` because it contains `ArchiveConfig` (from `era-common`) which does not implement `PartialEq`. This prevents `assert_eq!` in tests, forcing manual field-by-field comparison.

---

### V30-15 [Info] — `next_volume()` clones recipients/config/EVK

**File:** `header.rs:336-341`  
**Category:** Performance  
**Carried from:** V29-19

`next_volume()` clones the entire `recipients` Vec, `config`, and `EncryptedVolumeKey`. With 256 recipients, this could be ~2MB of cloning. Acceptable since this is not a hot path (called once per volume rotation), but an `Arc`-based approach would eliminate the allocation.

---

## Score Breakdown

| Category | Weight | V29 | V30 | Delta | Notes |
|----------|--------|-----|-----|-------|-------|
| Security | 35% | 32/35 | 28/35 | −4 | BC17-04 promoted from deferred to HIGH. 37 pub fields across 4 structs allow validation bypass. Floating footer archive cross-check missing. |
| Logic | 25% | 24/25 | 23/25 | −1 | `calculate_volume` zero-volume silent failure (V30-02). Backup header bounds not validated (V30-04). |
| Performance | 15% | 14/15 | 14/15 | 0 | No new performance findings. `next_volume()` clone acceptable. |
| Code Quality | 15% | 13/15 | 11/15 | −2 | Proto naming mismatch, 15x path duplication, 5x formula duplication, terse errors — all now actionable. |
| Testing | 10% | 10/10 | 9/10 | −1 | SuperHeader `PartialEq` still blocks `assert_eq!`. Test ergonomics degraded. |

**Total Score: 85/100**

**Score movement**: 93 (V29 post-fix) → 85 (V30 pre-fix). The −8 delta is primarily driven by re-classifying previously-deferred BC17-04 (37 pub fields) as a HIGH finding now that the pre-launch constraint is removed.

**Path to 100:**
- Fix V30-01 (pub fields → private + getters): +5
- Fix V30-02, V30-03 (logic gaps): +2
- Fix V30-04 through V30-09 (code quality): +3
- Fix V30-10 through V30-15 (info items): +5

---

## Verification

```
$ cargo clippy -p era-volume --all-targets -- -D warnings
# 0 warnings, 0 errors

$ cargo test -p era-volume
# All tests pass

$ cargo fmt --all -- --check
# Exit code 0 (clean)
```

No source code changes were made in this audit cycle — all findings are documented for remediation.

---

## Recommended Next Steps (V31)

1. **BC17-04 Resolution (V30-01)**: Execute the cross-crate refactor to make struct fields private across `EncryptedVolumeKey`, `RecipientSlot`, `SuperHeader`, and `Footer`. Add validated constructors and pub getter methods. Update all call sites in `era-engine`, `era-index`, and tests. This is the single highest-impact improvement — it would recover +5 points.

2. **Proto Schema Rename (V30-05)**: Rename `RECIPIENT_TYPE_SCRYPT_PASSWORD` to `RECIPIENT_TYPE_ARGON2ID_PASSWORD` in `era-common/proto/`. Single-PR change, no compatibility impact pre-launch.

3. **Extract Shared Utilities (V30-06, V30-07)**: Create `validate_filename()` helper and `PER_VOLUME_OVERHEAD` constant. Eliminates 15x + 5x duplication.

4. **Error Context Enhancement (V30-08, V30-09, V30-13)**: Add actual-vs-expected values to "Invalid magic", "Checksum mismatch", and "Footer too small" error messages.

5. **Distribution Safety (V30-02)**: Change `calculate_volume()` to return `Result` and error on `volume_count == 0`. Requires trait signature update.

6. **Floating Footer Hardening (V30-03)**: Add `data_end_offset` plausibility check after floating footer recovery.
