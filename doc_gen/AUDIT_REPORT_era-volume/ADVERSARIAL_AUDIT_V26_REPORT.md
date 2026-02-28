# Adversarial Audit V26 — ERA Volume Module

**Audit Date:** 2026-02-27
**Target:** `era-volume` crate (8 source files, ~2,800 lines)
**Methodology:** Competitive adversarial audit — analyzing from the perspective of a competitor trying to expose encapsulation, validation, performance, and robustness issues.
**Previous Score:** V25 = 99/100 (for `era-index`)
**V26 Target Score:** 84/100 (due to 21 findings across volume logic)

---

## Regression Status

| ID | Finding | Status |
|----|---------|--------|
| V9-F16 | Footer `.unwrap()` calls | ❌ OPEN (Carried forward as P0-1) |
| V9-F17 | SystemTime unwrap | ✅ FIXED (Uses `unwrap_or` in `header.rs:158`) |
| RED_TEAM P1-6 | Footer `from_bytes()` accepts absurd values | ✅ VERIFIED |
| RED_TEAM P1-7 | `finalize_with_catalog()` accepts bogus offsets | ✅ VERIFIED |
| RED_TEAM P1-8 | Footer checksum has no domain separation | ✅ VERIFIED |
| RED_TEAM P1-9 | `write_raw()` does not update `block_count` | ✅ VERIFIED |

---

## V26 Findings

| ID | Severity | Category | Title | Status |
|----|----------|----------|-------|--------|
| P0-1 | Security | Robustness | 16 `.unwrap()` calls in `Footer::read_fields_from()` and `from_bytes()` | OPEN |
| P0-2 | Security | Logic | `volume_sequence` u16 overflow in `next_volume()` and `rotate_volumes()` | OPEN |
| P0-3 | Security | Validation | Multiple `as u16` truncation casts in volume_pool.rs and header.rs | OPEN |
| P0-4 | Security | Validation | Writer lacks MAX_SHARD_SIZE validation (asymmetric with reader) | OPEN |
| P0-5 | Security | Validation | `proto.version as u16` truncation bypass of version validation | OPEN |
| P1-1 | High | Logic | `scan_for_typed_blocks` creates wrong VolumeId | OPEN |
| P1-2 | High | Logic | `write_canonical_block` uses `block.data.len() as u32` truncation | OPEN |
| P1-3 | High | Validation | `open_append` trusts `footer.data_end_offset` without bounds checking | OPEN |
| P1-4 | High | Logic | `volume_can_fit` doesn't account for BlockHeader overhead | OPEN |
| P1-5 | High | DoS | No upper bound on recipients vector in header | OPEN |
| P1-6 | High | Logic | MultiVolumeReader scans up to 1000 volumes with hardcoded limit | OPEN |
| P2-1 | Medium | Perf | Floating footer scan is O(n) byte-by-byte reverse iteration | OPEN |
| P2-2 | Medium | Perf | `rotate_volumes` clones `sequences` unnecessarily | OPEN |
| P2-3 | Medium | Perf | `write_erasure_block` uses HashSet for volume header tracking | OPEN |
| P3-1 | Low | Quality | `with_catalog()` takes 12 positional arguments | OPEN |
| P3-2 | Low | Quality | Redundant `unwrap_or_default()` on `file_name()` | OPEN |
| P3-3 | Low | Quality | Distribution `calculate_volume` returns 0 for volume_count=0 | OPEN |
| P3-4 | Low | Quality | `VolumePoolStatus::can_fit` doesn't reserve footer space | OPEN |
| P3-5 | Low | Quality | `finalize_with_catalog` (singular) broadcasts same offset to all volumes | OPEN |
| P3-6 | Low | Quality | `pad_to_size` uses OsRng for 16KB chunks | OPEN |
| P3-7 | Low | Quality | Hardcoded `4096` magic number in `volume_can_fit` | OPEN |

---

## Detailed Analysis

### P0-1: 16 `.unwrap()` calls in `Footer::read_fields_from()` and `from_bytes()` [SECURITY — Robustness]

**Location:** `footer.rs:253-268, 294, 298`

**Analysis:** The `era-volume` footer parser contains multiple `.unwrap()` calls on `Cursor::read_exact()` results. While the cursor wraps a fixed-size byte array, this pattern violates the project-wide "no-unwrap in runtime paths" mandate. A future refactor that changes buffer sizes without updating the parser would lead to a panic instead of a clean error.

**Fix:** Replace `.unwrap()` with `map_err(|_| EraError::CorruptedFooter("msg".into()))?`.

### P0-2: `volume_sequence` u16 overflow in `next_volume()` and `rotate_volumes()` [SECURITY — Logic]

**Location:** `header.rs:152` and `volume_pool.rs:280`

**Analysis:** Incrementing the `volume_sequence` (u16) is performed via unchecked addition (`+ 1`). If an archive exceeds 65,535 volumes, this will overflow and panic (in debug) or wrap (in release), potentially leading to filename collisions or invalid volume discovery.

**Fix:** Use `checked_add().ok_or(EraError::InvalidFormat("Volume sequence overflow".into()))?`.

### P0-3: Multiple `as u16` truncation casts [SECURITY — Validation]

**Location:** `volume_pool.rs:130, 131, 133, 138, 178, 280, 695, 699` and `header.rs:341, 374`

**Analysis:** The codebase uses `as u16` for casting various values (sequence numbers, versions, block counts). Silent truncation occurs if the source value exceeds 65,535, which can be used to bypass validation checks or cause logic errors in volume rotation.

**Fix:** Use `u16::try_from(x).map_err(...)`.

### P0-4: Writer lacks MAX_SHARD_SIZE validation [SECURITY — Validation]

**Location:** `writer.rs:236` (`write_canonical_block`)

**Analysis:** The reader enforces a `MAX_SHARD_SIZE` to prevent memory exhaustion, but the writer lacks a corresponding check. This asymmetry allows the creation of "legal" volumes that are unreadable by standard clients, or can be used to probe reader limits.

**Fix:** Add `if block.data.len() > MAX_SHARD_SIZE { return Err(...); }` to writer.

### P0-5: `proto.version as u16` truncation bypass of version validation [SECURITY — Validation]

**Location:** `header.rs:341`

**Analysis:** The protobuf version field (typically u32) is cast to u16 via `as` before comparison with `HEADER_VERSION`. An attacker can craft a protobuf with `version: 0x30003` (196611) which truncates to `3`, bypassing the check while carrying unexpected version metadata.

**Fix:** Use `u16::try_from(proto.version)` and validate before casting.

### P1-1: `scan_for_typed_blocks` creates wrong VolumeId [HIGH — Logic]

**Location:** `reader.rs:382`

**Analysis:** When scanning for blocks, the reader instantiates a new volume identifier using `VolumeId::new()` (which generates a fresh UUID) instead of using the `volume_id` persisted in the volume's own header. This breaks block-to-volume affinity checks.

**Fix:** Use `self.header.volume_id` instead of `VolumeId::new()`.

### P1-2: `write_canonical_block` uses `block.data.len() as u32` truncation [HIGH — Logic]

**Location:** `writer.rs:243`

**Analysis:** Block length is cast to `u32` for the header. If a block exceeds 4GB (possible with certain configurations or malicious input), the length is truncated, leading to corrupt volumes where the header disagrees with actual data on disk.

**Fix:** Validate `len <= u32::MAX` and use `try_from`.

### P1-3: `open_append` trusts `footer.data_end_offset` without bounds checking [HIGH — Validation]

**Location:** `writer.rs:88`

**Analysis:** When opening a volume for appending, the writer trusts the `data_end_offset` from the footer to seek to the end of the data region. A corrupted or malicious footer could point outside the file or into the header/footer regions, leading to data corruption on the next write.

**Fix:** Validate that `data_end_offset` is between `HEADER_SIZE` and `file_len - FOOTER_SIZE`.

### P1-4: `volume_can_fit` doesn't account for BlockHeader overhead [HIGH — Logic]

**Location:** `volume_pool.rs:347`

**Analysis:** The capacity check only reserves `FOOTER_SIZE + 4096` bytes. It does not account for the `BlockHeader` and `ShardHeader` overhead added to every block, leading to "Volume Full" errors during write even when `can_fit` returned true.

**Fix:** Add `BLOCK_HEADER_SIZE` to the fit calculation.

### P1-5: No upper bound on recipients vector in header [HIGH — DoS]

**Location:** `header.rs` (`TryFrom` impl)

**Analysis:** The `SuperHeader` allows an arbitrary number of recipient slots. An attacker can provide a header with millions of slots, causing the reader to allocate a massive `Vec<RecipientSlot>` and exhaust memory before any authentication occurs.

**Fix:** Enforce `MAX_RECIPIENT_SLOTS` (e.g., 256) in `TryFrom`.

### P1-6: MultiVolumeReader scans up to 1000 volumes with hardcoded limit [HIGH — Logic]

**Location:** `multi_volume.rs:262`

**Analysis:** The multi-volume discovery logic is hardcoded to scan a maximum of 1000 volumes. Large archives exceeding this limit will have their trailing volumes ignored, leading to "Missing Shard" errors during extraction.

**Fix:** Make the limit configurable or base it on the archive manifest.

### P2-1: Floating footer scan is O(n) byte-by-byte reverse iteration [MEDIUM — Perf]

**Location:** `reader.rs:145`

**Analysis:** Finding the footer by scanning backwards from the end of the file is implemented using a manual loop. For large volumes with trailing garbage, this is inefficient.

**Fix:** Use `memchr` crate for vectorized reverse byte scanning.

### P2-2: `rotate_volumes` clones `sequences` unnecessarily [MEDIUM — Perf]

**Location:** `volume_pool.rs:260`

**Analysis:** The `sequences` vector is cloned on every volume rotation. In archives with thousands of volumes, this adds significant allocation pressure to the hot path.

**Fix:** Use references or `Arc` if shared access is required.

### P2-3: `write_erasure_block` uses HashSet for volume header tracking [MEDIUM — Perf]

**Location:** `volume_pool.rs:556`

**Analysis:** A `HashSet` is allocated and populated to track which volume headers need updating. Since the number of volumes is typically small and fixed per operation, a bitset or simple array would be more efficient.

**Fix:** Replace `HashSet` with a stack-allocated bitfield or fixed array.

### P3-1: `with_catalog()` takes 12 positional arguments [LOW — Quality]

**Location:** `footer.rs`

**Analysis:** `Footer::with_catalog` has a high cognitive load and is prone to argument swapping errors due to its long list of positional parameters.

**Fix:** Use a builder pattern or a `FooterConfig` struct.

### P3-2: Redundant `unwrap_or_default()` on `file_name()` [LOW — Quality]

**Location:** `multi_volume.rs` (85, 165, 249, 265) and `volume_pool.rs` (134, 179, 224, 287, 702)

**Analysis:** `Path::file_name()` is called followed by `unwrap_or_default()` in multiple places where the path is guaranteed to be a valid file. This adds unnecessary noise to the code.

**Fix:** Consolidate into a helper method or use `expect`.

### P3-3: Distribution `calculate_volume` returns 0 for volume_count=0 [LOW — Quality]

**Location:** `distribution.rs:34`

**Analysis:** If `volume_count` is 0, the function returns volume 0 instead of erroring. This masks configuration errors.

**Fix:** Return `Result<usize, EraError>` and error on `volume_count == 0`.

### P3-4: `VolumePoolStatus::can_fit` doesn't reserve footer space [LOW — Quality]

**Location:** `distribution.rs:93`

**Analysis:** Inconsistent with `VolumePool`, the distribution helper doesn't account for the space required by the footer when checking if a block fits.

**Fix:** Include `FOOTER_SIZE` in the calculation.

### P3-5: `finalize_with_catalog` (singular) broadcasts same offset to all volumes [LOW — Quality]

**Location:** `volume_pool.rs:594`

**Analysis:** The method sends the same catalog offset to every volume in the pool. This is documented as intentional for the current matrix distribution model, but lacks explicit code comments explaining the rationale.

**Fix:** Add explanatory comments.

### P3-6: `pad_to_size` uses OsRng for 16KB chunks [LOW — Quality]

**Location:** `writer.rs`

**Analysis:** Using `OsRng` to generate padding data is acceptable but slower than a userspace PRNG. Since padding doesn't require cryptographic strength (it just needs to not be all zeros for some backends), this is a performance-security trade-off.

**Fix:** Document the rationale or switch to a faster CSPRNG.

### P3-7: Hardcoded `4096` magic number in `volume_can_fit` [LOW — Quality]

**Location:** `volume_pool.rs:347`

**Analysis:** The value `4096` is used as a hardcoded buffer for header space.

**Fix:** Replace with `HEADER_SIZE` constant.

---

## Scoring

| Dimension | Score | Notes |
|-----------|-------|-------|
| Robustness | 80/100 | P0-1 (unwraps) and P0-2 (overflows) are significant risks. |
| Validation | 85/100 | Multiple truncation issues (P0-3, P0-5) and missing bounds (P1-3, P1-5). |
| Logic | 82/100 | Volume ID mismatch (P1-1) and capacity calculation errors (P1-4). |
| Performance | 90/100 | Minor O(n) scan and unnecessary cloning. |
| Maintainability | 88/100 | Positional argument bloat and magic numbers. |

**Overall Score: 84/100**

---

## Test Coverage

Verification of findings is performed by the `crates/era-volume/tests/adversarial_audit_v26.rs` suite (to be implemented), covering overflow paths, truncation bypasses, and capacity edge cases.
