# Adversarial Audit V23 — ERA Index Module

**Audit Date:** 2026-02-27
**Target:** `era-index` crate (9 source files, ~3,500 lines)
**Methodology:** Competitive adversarial audit — analyzing from the perspective of a competitor trying to expose encapsulation, validation, performance, and robustness issues.
**Previous Score:** V22 = 98/100

---

## V22 Regression Status (All FIXED/VERIFIED)

| ID | Finding | Status |
|----|---------|--------|
| V22-F1 | `insert_batch()` opens per-candidate read_txn for bloom-confirmed duplicates | ✅ VERIFIED |
| V22-F2 | builder `finalize()` `Vec::new()` causes encrypted_blocks reallocation | ✅ VERIFIED |
| V22-F3 | `from_memory()` uses `try_new()` on already-sorted entries | ✅ VERIFIED |
| V22-F4 | `add_page()` duplicate block_id scan O(n) cost undocumented | ✅ VERIFIED |
| V22-F5 | `BloomFilterData` lacks validated constructor | ✅ VERIFIED |
| V22-F6 | `for_each_sorted_page` has no progress logging for large iterations | ✅ VERIFIED |
| V22-F7 | `recover_from_volume` allocates new `candidate_block_ids` Vec per iteration | ✅ VERIFIED |
| V22-F8 | `finalize()` clones entire bloom bitmap just to serialize | ✅ VERIFIED |
| V22-F9 | `IndexEntry` has no `Display` impl for human-readable logging | ✅ VERIFIED |
| V22-F10 | `IndexStore` has no way to query staging database disk usage | ✅ VERIFIED |
| V22-F11 | `recover_from_volume` `embedded_pages` HashMap uses default capacity | ✅ VERIFIED |
| V22-F12 | `with_batch_size(0)` silently clamps to 1 | ✅ VERIFIED |

---

## V23 Findings

| ID | Severity | Category | Title | Status |
|----|----------|----------|-------|--------|
| V23-F1 | Medium | Encapsulation | `BloomFilterData` fields are `pub` — allows bypass of `new()` validation | ✅ FIXED |
| V23-F2 | Medium | Validation | `from_bloom()` constructs `BloomFilterData` directly bypassing validation | ✅ FIXED |
| V23-F3 | Low | Maintainability | Triplicated validation logic across `new()`, `to_bloom()`, `from_bytes()` | ✅ FIXED |
| V23-F4 | Low | Documentation | `to_bytes()` copies `AlignedVec→Vec` via `.to_vec()` without documenting why | ✅ FIXED |
| V23-F5 | Low | Encapsulation | `from_bloom()` is `pub` but only used within the crate | ✅ FIXED |
| V23-F6 | Low | Documentation | Duplicate doc comment on `try_new_presorted` in `lib.rs` | ✅ FIXED |
| V23-F7 | Low | API Hygiene | `_caller_bloom` unused params in `from_memory()` and `from_pages()` | ✅ FIXED |
| V23-F8 | Low | Correctness | `for_each_sorted_page` progress logging fires inside inner loop | ✅ FIXED |
| V23-F9 | Info | Safety | `.expect()` in `try_new`/`try_new_presorted` — safe but could use defensive indexing | INFO ONLY |
| V23-F10 | Low | Performance | `set_bloom_filter` deserializes full `Bloom<ChunkHash>` just to validate | ✅ FIXED |

### Carried Forward (Info — no code change required)

| ID | Origin | Title | Status |
|----|--------|-------|--------|
| V23-CF1 | V19-F7 | `builder.rs` `finalize()` CPU-heavy serialization on async thread (Redb ReadTransaction is `!Send`) | INFO — architectural constraint |
| V23-CF2 | V18-F10 | `chunk_index.rs` `finalize()` materializes all pages in Vec before IndexReader creation | INFO — required by IndexReader API |

---

## Detailed Analysis

### V23-F1: `BloomFilterData` fields are `pub` — allows bypass of `new()` validation [MEDIUM — Encapsulation]

**Location:** `bloom_serde.rs:17-37` (`struct BloomFilterData`)

**Analysis:** All fields of `BloomFilterData` (version, bitmap, bitmap_bits, k_num, sip_keys) are declared `pub`. This means any code within the crate — or any code outside the crate since `BloomFilterData` is re-exported in `lib.rs` — can construct a `BloomFilterData` via struct literal syntax, completely bypassing the validated `new()` constructor added in V22-F5. A competitor could demonstrate that the validated constructor is security theater when the fields remain publicly writable.

The existing test `test_bloom_version_validation` at line 308 directly mutates `data.version = 2`, confirming that field-level mutation is possible and used. While convenient for tests, this pattern undermines the validation guarantees `new()` was designed to provide.

**Fix:** Changed all fields from `pub` to `pub(crate)`. Internal callers (`from_bloom()`, tests) can still access fields directly since they are within the crate. External consumers must use `new()` or `from_bytes()`. Updated the test at line 308 to use a helper method instead of direct field mutation.

### V23-F2: `from_bloom()` constructs `BloomFilterData` directly bypassing validation [MEDIUM — Validation]

**Location:** `bloom_serde.rs:114-128` (`BloomFilterData::from_bloom()`)

**Analysis:** `from_bloom()` creates a `BloomFilterData` via struct literal `Self { version: 1, bitmap, ... }` without calling `new()` or any validation. While `Bloom<T>` should always produce valid parameters, a defensive-in-depth approach requires validating even "trusted" inputs at construction boundaries. A bug in the `bloomfilter` crate (e.g., returning 0 for `number_of_hash_functions()`) would produce an invalid `BloomFilterData` that silently propagates.

**Fix:** Changed `from_bloom()` to call `Self::validate()` (the new consolidated validation method from V23-F3) and return `Result<Self>`. Updated all callers to propagate the error.

### V23-F3: Triplicated validation logic across `new()`, `to_bloom()`, `from_bytes()` [LOW — Maintainability]

**Location:** `bloom_serde.rs:56-73, 136-153, 196-228`

**Analysis:** The same four validation checks (bitmap_bits > 0, k_num > 0, bitmap length sufficient, sip_keys not all-zero) are copy-pasted across three methods with slightly different error message prefixes. This creates a maintenance burden: adding a new validation check (e.g., bitmap_bits alignment) requires updating all three sites. The `from_bytes()` method additionally checks version and maximum bitmap size — these are specific to deserialization and should remain separate.

**Fix:** Extracted a shared `validate(&self) -> Result<()>` method containing the four common checks. All three call sites now delegate to `validate()`. The `from_bytes()`-specific checks (version, max size) remain inline since they are deserialization-specific.

### V23-F4: `to_bytes()` copies `AlignedVec→Vec` via `.to_vec()` without documenting why [LOW — Documentation]

**Location:** `bloom_serde.rs:165` (`BloomFilterData::to_bytes()`)

**Analysis:** `rkyv::to_bytes()` returns an `AlignedVec`, and `.to_vec()` copies into a standard `Vec<u8>`. This copy is necessary because `AlignedVec` does not implement `Into<Vec<u8>>` (different allocator alignment), but the reason is non-obvious and could be seen as an unnecessary allocation by a reviewer.

**Fix:** Added a comment explaining why the `.to_vec()` copy from `AlignedVec` is necessary.

### V23-F5: `from_bloom()` is `pub` but only used within the crate [LOW — Encapsulation]

**Location:** `bloom_serde.rs:114` (`BloomFilterData::from_bloom()`)

**Analysis:** `from_bloom()` is declared `pub` but is only called from `serialize_bloom()` in the same file and indirectly from within the crate. Exposing it publicly leaks an internal conversion API that external consumers should not rely on.

**Fix:** Changed `from_bloom()` from `pub` to `pub(crate)`.

### V23-F6: Duplicate doc comment on `try_new_presorted` [LOW — Documentation]

**Location:** `lib.rs:220-223`

**Analysis:** The doc comment for `try_new_presorted` contains a verbatim duplicate of the V17-F2 fix description (lines 220-223 are identical to lines 213-216). This was likely a merge artifact. The duplicate text is confusing and clutters the documentation.

**Fix:** Removed the duplicate lines 220-223.

### V23-F7: `_caller_bloom` unused params in `from_memory()` and `from_pages()` [LOW — API Hygiene]

**Location:** `reader.rs:142, 196` (`IndexReader::from_memory()`, `IndexReader::from_pages()`)

**Analysis:** Both `from_memory()` and `from_pages()` accept a `_caller_bloom: Bloom<ChunkHash>` parameter that is completely unused — the bloom filter is rebuilt from entries/pages internally (V19-F5, V20-F1 fixes). The parameter persists as a vestige of the pre-V19 API. Callers (`chunk_index.rs:228`) still construct a placeholder bloom to satisfy the signature, wasting both allocations and cognitive overhead.

**Fix:** Removed the `_caller_bloom` parameter from both methods. Updated the call site in `chunk_index.rs` to remove the placeholder bloom construction.

### V23-F8: `for_each_sorted_page` progress logging fires inside inner loop [LOW — Correctness]

**Location:** `store.rs:547-552`

**Analysis:** The progress logging check `if block_id_counter > 0 && block_id_counter.is_multiple_of(100)` is placed inside the `for result in table.iter()` loop, but it checks `block_id_counter` which only increments when a page boundary is crossed. After a page boundary, the counter increments and on the very next entry (the first entry of the next page), the check fires. However, for the 99th and subsequent entries in that page, `block_id_counter` remains the same value, and `.is_multiple_of(100)` returns true for every entry in the page following the boundary. This means the log fires once per entry for an entire page worth of entries (8192 times) instead of once per 100 pages.

**Fix:** Moved the progress logging to fire immediately after a page is emitted (after the `callback` call), so it runs exactly once per page boundary.

### V23-F9: `.expect()` in `try_new`/`try_new_presorted` — safe but could use defensive indexing [INFO]

**Location:** `lib.rs:197-203, 257-264`

**Analysis:** The `.expect("guaranteed non-empty after is_empty check")` calls on `entries.first()` and `entries.last()` are safe because the empty check returns early. This is idiomatic Rust. No change required.

### V23-F10: `set_bloom_filter` deserializes full `Bloom<ChunkHash>` just to validate [LOW — Performance]

**Location:** `lib.rs:456-460` (`MetaIndex::set_bloom_filter()`)

**Analysis:** `set_bloom_filter()` calls `crate::deserialize_bloom(&bloom_data)?` which performs full rkyv deserialization into `BloomFilterData`, then constructs a `Bloom<ChunkHash>` from it, only to discard both objects. The goal is validation, but constructing the full `Bloom<ChunkHash>` allocates the bitmap into memory unnecessarily. Using `BloomFilterData::from_bytes()` instead validates the rkyv data and bloom parameters without constructing the full `Bloom`.

**Fix:** Changed `set_bloom_filter()` to use `BloomFilterData::from_bytes()` for validation instead of `deserialize_bloom()`. This validates the serialized data without constructing the full `Bloom<ChunkHash>` bitmap.

---

## Scoring

| Dimension | Score | Notes |
|-----------|-------|-------|
| Encapsulation | 99/100 | V23-F1/F5 fixed: fields now `pub(crate)`, internal APIs properly scoped |
| Validation | 99/100 | V23-F2/F3 fixed: consolidated validation, all construction paths validated |
| Performance | 99/100 | V23-F8/F10 fixed: logging placement corrected, unnecessary deserialization removed |
| Maintainability | 99/100 | V23-F3/F4/F6 fixed: DRY validation, documented copies, cleaned duplicate docs |
| API Hygiene | 99/100 | V23-F7 fixed: removed dead parameters from public API |

**Overall Score: 99/100** (up from 98/100 in V22)

The remaining 1 point reflects the carried-forward architectural constraints (V23-CF1, V23-CF2) which require broader refactoring beyond the scope of a single crate audit.

---

## Test Coverage

All V23 findings are covered by the `adversarial_audit_v23.rs` test suite with both source-level verification and behavioral tests.
