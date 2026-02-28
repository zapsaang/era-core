# Adversarial Audit V21 — ERA Index Module

**Audit Date:** 2026-02-27
**Target:** `era-index` crate (7 source files, ~2,800 lines)
**Methodology:** Competitive adversarial audit — analyzing from the perspective of a competitor trying to expose performance, security, logic, and robustness issues.
**Previous Score:** V20 = 98/100

---

## V20 Regression Status (All FIXED/VERIFIED)

| ID | Finding | Status |
|----|---------|--------|
| V20-F1 | `from_pages()` trusts caller bloom (same V19-F5 pattern) | ✅ VERIFIED |
| V20-F2 | `RwLock` on read-only `IndexReader` (unnecessary sync overhead) | ✅ VERIFIED |
| V20-F3 | `insert()` opens write txn for known duplicates | ✅ VERIFIED |
| V20-F4 | `read_sorted()` duplicates `for_each_sorted_page()` logic | ✅ VERIFIED |
| V20-F5 | `BloomFilterData` allows all-zero sip_keys | ✅ VERIFIED |
| V20-F6 | `load_page` uses `InvalidFormat` instead of `IndexError` | ✅ VERIFIED |
| V20-F7 | Drop impl deletes staging file on flush failure | ✅ VERIFIED |
| V20-F8 | `from_pages()` receives full bloom clone unnecessarily | ✅ VERIFIED |
| V20-F9 | `recover_from_volume` re-scans pages in step 3 | ✅ VERIFIED |
| V20-F10 | `contains_range()` missing `#[must_use]` | ✅ VERIFIED |
| V20-F11 | `open_readonly` bloom rebuild has no progress logging | ✅ VERIFIED |
| V20-F12 | `bloom_expected_items()` missing doc comment | ✅ VERIFIED |

---

## V21 Findings

| ID | Severity | Category | Title | Status |
|----|----------|----------|-------|--------|
| V21-F1 | Low | Documentation | `insert()` inline read_txn logic undocumented | ✅ FIXED |
| V21-F2 | Medium | Performance | `candidates` Vec hardcoded capacity in reader | ✅ FIXED |
| V21-F3 | Medium | API Safety | `try_new_presorted` unnecessarily restricted to `pub(crate)` | ✅ FIXED |
| V21-F4 | High | Security | `to_bloom()` returns unvalidated `Bloom<T>` | ✅ FIXED |
| V21-F5 | Low | Observability | `rebuild_bloom_if_needed()` triggers silently | ✅ FIXED |
| V21-F6 | Low | Observability | `finalize()` logs entry count after bloom serialization | ✅ FIXED |
| V21-F7 | Low | Documentation | `MIN/MAX_INDEX_PAGE_SIZE` constants undocumented | ✅ FIXED |
| V21-F8 | Medium | Configurability | `BATCH_SIZE` hardcoded in `IndexBuilder` | ✅ FIXED |
| V21-F9 | Medium | Performance | `insert_batch()` skips bloom pre-filtering | ✅ FIXED |
| V21-F10 | Low | Observability | `find_page()` `Err(0)` case unlogged | ✅ FIXED |
| V21-F11 | Low | API Completeness | No `total_entry_count()` on `IndexReader` | ✅ FIXED |
| V21-F12 | Low | Correctness | `align_buf` in `for_each_sorted_page` hardcoded to 256 | ✅ FIXED |

---

## Detailed Analysis

### V21-F1: `insert()` inline read_txn logic undocumented [LOW — Documentation]

**Location:** `store.rs:180-210` (`IndexStore::insert()`)

**Analysis:** The `insert()` method contains an early-return path that opens a read transaction and checks for an existing entry — logic that is nearly identical to the `get()` method. Without a comment explaining why this is inlined rather than delegated to `get()`, future maintainers may attempt to "simplify" by calling `get()`, inadvertently introducing a double bloom check (once in `insert()`'s bloom pre-filter from V20-F3, once inside `get()`). The intentional inlining is a performance optimization that avoids redundant bloom filter lookups.

**Fix:** Added a comment documenting that `insert()`'s early-return path intentionally inlines the read_txn logic instead of calling `get()` to avoid a double bloom check. This preserves the optimization while making the intent explicit.

### V21-F2: `candidates` Vec hardcoded capacity in reader [MEDIUM — Performance]

**Location:** `reader.rs:200-230` (`IndexReader` lookup methods)

**Analysis:** The `candidates` vector used to collect potential matches during L2 page scanning was initialized with `Vec::with_capacity(512)`. This hardcoded value is suboptimal in both directions: for queries matching few entries, it wastes 512 × sizeof(IndexEntry) bytes; for queries matching many entries (e.g., in large archives), it triggers unnecessary reallocations. The actual upper bound is known after computing how many pages contain the target range — the `upper_bound` value is already calculated but not used for capacity planning.

**Fix:** Replaced `Vec::with_capacity(512)` with `let mut candidates = Vec::new()` followed by `candidates.reserve(upper_bound as usize)` after the upper_bound is computed. This right-sizes the allocation based on actual query selectivity.

### V21-F3: `try_new_presorted` unnecessarily restricted to `pub(crate)` [MEDIUM — API Safety]

**Location:** `lib.rs:120-140` (`IndexPage::try_new_presorted()`)

**Analysis:** `IndexPage::try_new_presorted()` was marked `pub(crate)`, preventing external consumers from constructing an `IndexPage` from pre-sorted data. This forces external users to use `try_new()` which sorts and deduplicates — unnecessary overhead when the caller can guarantee sorted, deduplicated input (e.g., when reconstructing pages from serialized data or building test fixtures). The method already validates its invariants (non-empty, sorted, deduplicated), so exposing it publicly is safe.

**Fix:** Changed `try_new_presorted` from `pub(crate)` to `pub` with an updated doc comment explaining when to prefer it over `try_new()`. The existing validation ensures callers cannot create invalid pages.

### V21-F4: `to_bloom()` returns unvalidated `Bloom<T>` [HIGH — Security]

**Location:** `bloom_serde.rs:50-80` (`BloomFilterData::to_bloom()`)

**Analysis:** `BloomFilterData::to_bloom()` constructed a `Bloom<T>` directly from deserialized fields without validating structural integrity. A malicious or corrupted serialized bloom could have: (1) `bitmap_bits == 0`, creating a degenerate bloom that always returns false positives, (2) `k_num == 0`, creating a bloom that never hashes (always returns true), (3) bitmap byte length mismatched with `bitmap_bits`, causing silent truncation or padding. V20-F5 added sip_keys validation but the structural fields were still unchecked.

**Fix:** Changed `to_bloom()` return type from `Bloom<T>` to `Result<Bloom<T>>` and added validation: `bitmap_bits > 0`, `k_num > 0`, `bitmap.len() == (bitmap_bits + 7) / 8`, and sip_keys not all-zero. This is a **BREAKING CHANGE** — all callers updated to propagate the `Result`. Invalid bloom filters are now rejected at deserialization time with `EraError::IndexError`.

### V21-F5: `rebuild_bloom_if_needed()` triggers silently [LOW — Observability]

**Location:** `store.rs:280-310` (`IndexStore::rebuild_bloom_if_needed()`)

**Analysis:** `rebuild_bloom_if_needed()` checks whether the bloom filter's capacity is sufficient for the current entry count and rebuilds it if not. This rebuild is a potentially expensive operation (iterating all entries, rehashing into a new bloom) that happened with no logging. Operators monitoring index performance had no visibility into when and why bloom rebuilds occurred — a critical diagnostic gap when investigating unexpected I/O spikes.

**Fix:** Added `tracing::info!` when `rebuild_bloom_if_needed()` triggers, logging old_capacity, new_capacity, and entry_count. This provides operational visibility into bloom lifecycle events without impacting performance.

### V21-F6: `finalize()` logs entry count after bloom serialization [LOW — Observability]

**Location:** `chunk_index.rs:150-180` (`ChunkIndex::finalize()`)

**Analysis:** The `tracing::info!("Index finalized: {} total entries", entries_count)` log was emitted after `serialize_bloom()`. If bloom serialization failed (e.g., out of memory), the finalization log would never appear, making it unclear whether the failure occurred before or after entry collection completed. Moving the log before bloom serialization ensures operators see the entry count even if serialization fails.

**Fix:** Moved the `tracing::info!` log to before the `serialize_bloom()` call. This ensures the entry count is logged regardless of whether bloom serialization succeeds.

### V21-F7: `MIN/MAX_INDEX_PAGE_SIZE` constants undocumented [LOW — Documentation]

**Location:** `reader.rs:20-30` (module-level constants)

**Analysis:** `MIN_INDEX_PAGE_SIZE` and `MAX_INDEX_PAGE_SIZE` are critical constants that bound the size of L2 index pages loaded from storage. Without doc comments, the derivation of their values (why 64? why 1048576?) was unclear. These constants directly affect memory allocation bounds and security (preventing allocation bombs from malicious pages), so their rationale should be documented.

**Fix:** Added detailed doc comments to both constants explaining their derivation: `MIN_INDEX_PAGE_SIZE` is the minimum viable page (single entry + overhead), `MAX_INDEX_PAGE_SIZE` is the maximum safe allocation (1 MiB cap to prevent memory exhaustion from malicious inputs).

### V21-F8: `BATCH_SIZE` hardcoded in `IndexBuilder` [MEDIUM — Configurability]

**Location:** `builder.rs:30-50` (`IndexBuilder`)

**Analysis:** `IndexBuilder` used a hardcoded `const BATCH_SIZE: usize` for flush thresholds. Different workloads benefit from different batch sizes: small files with high dedup rates benefit from smaller batches (faster bloom updates), while large sequential ingests benefit from larger batches (fewer Redb transactions). The batch size was not configurable, forcing a one-size-fits-all compromise.

**Fix:** Renamed the const to `DEFAULT_BATCH_SIZE`, added a `batch_size: usize` field to `IndexBuilder` (initialized to `DEFAULT_BATCH_SIZE`), and added a `with_batch_size(mut self, batch_size: usize) -> Self` builder method. The flush check now uses `self.batch_size` instead of the const. Existing code using `IndexBuilder::new()` retains the default behavior.

### V21-F9: `insert_batch()` skips bloom pre-filtering [MEDIUM — Performance]

**Location:** `store.rs:230-270` (`IndexStore::insert_batch()`)

**Analysis:** `insert_batch()` opened a write transaction for all entries in the batch without checking the bloom filter first. V20-F3 added bloom pre-filtering to single `insert()`, but the batch variant was missed. For high-dedup workloads, this means `insert_batch()` opens expensive write transactions to insert entries that are already present — exactly the performance issue V20-F3 fixed for single inserts.

**Fix:** Added bloom pre-check filtering to `insert_batch()`: before opening the write transaction, the method filters out entries whose hashes are already confirmed present in the bloom filter. Only entries that pass the bloom filter (potential new entries) proceed to the write transaction. This significantly reduces write transaction overhead for high-dedup batch inserts.

### V21-F10: `find_page()` `Err(0)` case unlogged [LOW — Observability]

**Location:** `lib.rs:250-270` (`IndexPage::find_page()` / `MetaIndex::find_page()`)

**Analysis:** When `find_page()` binary search returns `Err(0)`, the target hash falls before the first page's range. This is a valid but potentially diagnostic case — it means the index was queried for a hash outside its covered range. Without logging, operators cannot detect when queries systematically miss the index range, which could indicate misconfigured chunking parameters or index corruption.

**Fix:** Added `tracing::trace!` log for the `Err(0)` case, logging the target hash and the first page's range start. The `trace` level ensures zero overhead in production (trace is typically disabled) while providing diagnostic detail when enabled.

### V21-F11: No `total_entry_count()` on `IndexReader` [LOW — API Completeness]

**Location:** `reader.rs:300-350` (`IndexReader`)

**Analysis:** `IndexReader` provides `page_count()` and per-page `len()`, but no aggregate `total_entry_count()` method. Callers needing the total entry count (e.g., for progress reporting, capacity planning, or bloom filter sizing) had to manually iterate pages and sum lengths. This is a common operation that should be a first-class method.

**Fix:** Added `total_entry_count() -> usize` method to `IndexReader` that sums `entries.len()` from all `embedded_pages`. This provides a zero-allocation O(pages) count without materializing entries.

### V21-F12: `align_buf` in `for_each_sorted_page` hardcoded to 256 [LOW — Correctness]

**Location:** `store.rs:400-440` (`IndexStore::for_each_sorted_page()`)

**Analysis:** `for_each_sorted_page()` used a hardcoded `align_buf` size of 256 bytes for rkyv alignment. This value was chosen to exceed `IndexEntry::memory_size()` but had no explicit relationship to the type being aligned. If `IndexEntry`'s layout changed (e.g., additional fields increasing its size beyond 128 bytes), the hardcoded buffer would silently become insufficient, causing rkyv deserialization UB or panics.

**Fix:** Changed `align_buf` from hardcoded 256 to `IndexEntry::memory_size() * 2`. This maintains a 2× safety margin while automatically adapting to layout changes. The relationship between the buffer size and the aligned type is now explicit.

---

## Score

**V21 Score: 98/100**

Improvements over V20:
- `to_bloom()` now validates all structural fields (bitmap_bits, k_num, bitmap length, sip_keys), closing the last unvalidated deserialization path (V21-F4)
- `insert_batch()` now has bloom pre-filtering parity with `insert()`, eliminating the batch/single performance asymmetry (V21-F9)
- `BATCH_SIZE` made configurable, enabling workload-specific tuning (V21-F8)
- `try_new_presorted` made public, enabling zero-overhead page construction for trusted callers (V21-F3)
- Dynamic `candidates` capacity based on query selectivity eliminates wasted allocations (V21-F2)
- `align_buf` tied to `IndexEntry::memory_size()` for layout-safe rkyv deserialization (V21-F12)
- Comprehensive observability improvements across bloom rebuild, finalization, and range miss paths (V21-F1, F5, F6, F7, F10, F11)

Remaining concerns:
- finalize() CPU-heavy work on async thread (-1, documented V19-F7, carried from V18-F7)
- ChunkIndex::finalize materializes all pages (-1, carried from V18-F10)

---

## Recommendations for V22

1. Restructure `finalize()` to use `spawn_blocking` for serialization/encryption (V19-F7 / V18-F7 — carried 4 audits)
2. Add streaming `IndexReader` construction to avoid materializing all pages (V18-F10 — carried 4 audits)
3. Add fuzz targets for `BloomFilterData` deserialization with structurally invalid fields (zero bitmap_bits, zero k_num, mismatched bitmap length)
4. Property-based testing (proptest) for `IndexPage` sort/dedup invariants
5. Benchmark `insert_batch()` bloom pre-filter vs. direct write for varying dedup rates
6. Consider making `DEFAULT_BATCH_SIZE` a runtime-tunable configuration parameter exposed through `ChunkIndex`
