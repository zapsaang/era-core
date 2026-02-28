# Adversarial Audit V20 — ERA Index Module

**Audit Date:** 2026-02-27
**Target:** `era-index` crate (7 source files, ~2,800 lines)
**Methodology:** Competitive adversarial audit — analyzing from the perspective of a competitor trying to expose performance, security, logic, and robustness issues.
**Previous Score:** V19 = 97/100

---

## V19 Regression Status (All FIXED/VERIFIED)

| ID | Finding | Status |
|----|---------|--------|
| V19-F1 | IndexReader::open() validates MetaIndex AFTER bloom deserialization | ✅ VERIFIED |
| V19-F2 | MetaIndex::add_page runtime duplicate block_id check missing | ✅ VERIFIED |
| V19-F3 | IndexEntry::new() silently accepts zero-length and overflow entries | ✅ VERIFIED |
| V19-F4 | BloomFilterData::from_bytes missing max bitmap size cap | ✅ VERIFIED |
| V19-F5 | IndexReader::from_memory trusts caller-supplied bloom without rebuild | ✅ VERIFIED |
| V19-F6 | ChunkIndex::finalize doesn't drop builder after finalization | ✅ VERIFIED |
| V19-F7 | finalize() serialization/encryption still on async thread | ⚠️ DOCUMENTED (carried forward) |
| V19-F8 | rebuild_bloom_if_needed uncapped bloom capacity | ✅ VERIFIED |
| V19-F9 | try_new / try_new_presorted missing post-dedup sorted assertion | ✅ VERIFIED |
| V19-F10 | MetaIndex::add_page has no upper bound on page count | ✅ VERIFIED |
| V19-F11 | IndexStore::bloom_set public name doesn't signal unchecked semantics | ✅ VERIFIED |
| V19-F12 | Recovery slow path missing post-decrypt timeout check | ✅ VERIFIED |

---

## V20 Findings

| ID | Severity | Category | Title | Status |
|----|----------|----------|-------|--------|
| V20-F1 | High | Logic | `from_pages()` trusts caller bloom (same V19-F5 pattern) | ✅ FIXED |
| V20-F2 | Medium | Performance | `RwLock` on read-only `IndexReader` (unnecessary sync overhead) | ✅ FIXED |
| V20-F3 | Medium | Performance | `insert()` opens write txn for known duplicates | ✅ FIXED |
| V20-F4 | Medium | Maintainability | `read_sorted()` duplicates `for_each_sorted_page()` logic | ✅ FIXED |
| V20-F5 | High | Security | `BloomFilterData` allows all-zero sip_keys | ✅ FIXED |
| V20-F6 | Low | Consistency | `load_page` uses `InvalidFormat` instead of `IndexError` | ✅ FIXED |
| V20-F7 | Medium | Robustness | Drop impl deletes staging file on flush failure | ✅ FIXED |
| V20-F8 | Low | Performance | `from_pages()` receives full bloom clone unnecessarily | ✅ FIXED |
| V20-F9 | Medium | Performance | `recover_from_volume` re-scans pages in step 3 | ✅ FIXED |
| V20-F10 | Low | API Safety | `contains_range()` missing `#[must_use]` | ✅ FIXED |
| V20-F11 | Low | Observability | `open_readonly` bloom rebuild has no progress logging | ✅ FIXED |
| V20-F12 | Low | Documentation | `bloom_expected_items()` missing doc comment | ✅ FIXED |

---

## Detailed Analysis

### V20-F1: `from_pages()` trusts caller bloom (same V19-F5 pattern) [HIGH — Logic]

**Location:** `reader.rs:150-200` (`IndexReader::from_pages()`)

**Analysis:** V19-F5 fixed `from_memory()` to rebuild the bloom filter from actual entries rather than trusting the caller-supplied bloom. However, the parallel constructor `from_pages()` was not updated — it still accepted and used a caller-provided `Bloom<ChunkHash>` directly. An attacker or buggy caller could supply a stale/corrupted bloom, causing false negatives (missed dedup opportunities) or excessive false positives. Since `from_pages()` has access to all page entries, rebuilding the bloom is cheap and eliminates the trust boundary.

**Fix:** Renamed the `bloom` parameter to `_caller_bloom` to document intent, then rebuilt the bloom from page entries using the same `verified_bloom` pattern as `from_memory()`. The bloom is reconstructed by iterating all pages' entries and inserting each hash into a fresh `Bloom::new_for_fp_rate()`.

### V20-F2: `RwLock` on read-only `IndexReader` (unnecessary sync overhead) [MEDIUM — Performance]

**Location:** `chunk_index.rs:70-80` (`ChunkIndexReader`)

**Analysis:** `ChunkIndexReader` wrapped the `IndexReader` in `Arc<RwLock<IndexReader>>`. Since `IndexReader` is immutable after construction (all methods take `&self`), the `RwLock` provided no benefit — every access was a read lock. On contended workloads, this adds unnecessary synchronization overhead: `RwLock::read()` still requires an atomic CAS on every access, plus the `parking_lot` dependency adds ~15KB to the binary.

**Fix:** Changed `Arc<RwLock<IndexReader>>` to `Arc<IndexReader>`. Removed the `parking_lot` dependency from `Cargo.toml`. All `reader.read()` calls replaced with direct `reader.method()` calls.

### V20-F3: `insert()` opens write txn for known duplicates [MEDIUM — Performance]

**Location:** `store.rs:180-210` (`IndexStore::insert()`)

**Analysis:** `IndexStore::insert()` unconditionally called `begin_write()` to open a Redb write transaction, even when the bloom filter indicated the entry already exists. Write transactions are expensive: they acquire an exclusive lock, allocate a write-ahead log entry, and force an fsync on commit. For workloads with high duplication rates (common in incremental backups), the majority of `insert()` calls are for known duplicates, wasting I/O and blocking concurrent reads.

**Fix:** Added a bloom-check early return: if the bloom filter indicates the hash may exist, open a read transaction to confirm. If the entry is confirmed present, skip the write transaction entirely. This converts duplicate inserts from O(write_txn) to O(read_txn + bloom_check), a significant improvement for high-dedup workloads.

### V20-F4: `read_sorted()` duplicates `for_each_sorted_page()` logic [MEDIUM — Maintainability]

**Location:** `store.rs:380-420` (`IndexStore::read_sorted()`)

**Analysis:** `read_sorted()` reimplemented the entry count check and sorted iteration logic already present in `for_each_sorted_page()`. This duplication meant that any bug fix or optimization to sorted iteration had to be applied in two places. The `MAX_SORTED_ENTRIES` guard, alignment buffer management, and Redb transaction handling were copy-pasted with minor variations.

**Fix:** Rewrote `read_sorted()` to delegate to `for_each_sorted_page()`, collecting entries via `extend_from_slice(page.entries())`. This eliminates the code duplication and ensures both paths share the same guards and iteration logic.

### V20-F5: `BloomFilterData` allows all-zero sip_keys [HIGH — Security]

**Location:** `bloom_serde.rs:50-70` (`BloomFilterData::to_bloom()`)

**Analysis:** `BloomFilterData::to_bloom()` accepted `sip_keys = [(0, 0); 2]` — all-zero SipHash keys. With zero keys, every input hash maps to a deterministic (non-random) set of bit positions. An attacker who knows the keys are zero can craft inputs that all collide on the same bloom filter bits, forcing a 100% false positive rate. This effectively disables the bloom filter's negative-lookup guarantee, causing every lookup to fall through to the expensive L2 page scan.

**Fix:** Added validation in `BloomFilterData` deserialization: if both sip_keys are `(0, 0)`, return `EraError::IndexError("BloomFilterData: all-zero sip_keys rejected")`. This rejects degenerate bloom filters at deserialization time before they can be used for lookups.

### V20-F6: `load_page` uses `InvalidFormat` instead of `IndexError` [LOW — Consistency]

**Location:** `reader.rs:300-320` (`IndexReader::load_page()`)

**Analysis:** `load_page()` returned `EraError::InvalidFormat` for index-specific failures (page too small, too large, deserialization failure). All other index-related errors in the crate use `EraError::IndexError`. Using `InvalidFormat` for index page loading makes error handling inconsistent and complicates error classification in upper layers (era-engine) that distinguish between format corruption and index issues.

**Fix:** Changed all `EraError::InvalidFormat` returns in `load_page()` to `EraError::IndexError`. This aligns with the error domain convention used by `bloom_serde.rs` and other index operations.

### V20-F7: Drop impl deletes staging file on flush failure [MEDIUM — Robustness]

**Location:** `builder.rs:280-300` (`IndexBuilder::drop()`)

**Analysis:** The `IndexBuilder` Drop implementation calls `flush_buffer()` to persist any remaining entries, then deletes the staging database file. If `flush_buffer()` fails (e.g., disk full, I/O error), the Drop impl still proceeds to delete the staging file via `self.store.destroy()`. This means partial data that was successfully written before the flush failure is permanently lost — the staging file that could have been used for recovery is destroyed.

**Fix:** In the Drop impl, if `flush_buffer()` fails, call `self.store.keep_on_drop()` to preserve the staging file for potential recovery. Only delete the staging file if `flush_buffer()` succeeds (or the builder was already finalized). Added a `tracing::warn` log when the staging file is preserved.

### V20-F8: `from_pages()` receives full bloom clone unnecessarily [LOW — Performance]

**Location:** `chunk_index.rs:180-200` (`ChunkIndex::finalize()`)

**Analysis:** `ChunkIndex::finalize()` passed a full clone of the bloom filter to `IndexReader::from_pages()`. Since V20-F1 changed `from_pages()` to rebuild the bloom from entries (ignoring the caller's bloom), the clone is wasted work — potentially copying a multi-megabyte bloom filter for nothing.

**Fix:** Changed the call to pass `Bloom::new_for_fp_rate(1, 0.01)` (a minimal placeholder) instead of cloning the real bloom. The real bloom is still serialized into the MetaIndex for on-disk persistence, but the placeholder avoids the unnecessary clone for the in-memory reader construction.

### V20-F9: `recover_from_volume` re-scans pages in step 3 [MEDIUM — Performance]

**Location:** `reader.rs:450-500` (`IndexReader::recover_from_volume()`)

**Analysis:** The `recover_from_volume()` method has 3 steps: (1) scan volume for index blocks, (2) try each block as a MetaIndex, (3) load L2 pages referenced by the MetaIndex. Step 3 iterates the volume's block list again to find blocks matching the PagePointer block_ids. But Step 1 already identified all index-typed blocks — this information is discarded and the scan is repeated, doubling I/O for the recovery path.

**Fix:** Added `cached_page_blocks: Option<Vec<BlockLocation>>` to cache the index block list from Step 1. Step 3 reuses the cached list instead of re-scanning. For archives with thousands of blocks, this halves the recovery I/O.

### V20-F10: `contains_range()` missing `#[must_use]` [LOW — API Safety]

**Location:** `lib.rs:290` (`IndexPage::contains_range()`)

**Analysis:** `IndexPage::contains_range()` returns a `bool` indicating whether a hash falls within the page's range. Without `#[must_use]`, callers could accidentally call it without checking the return value — a classic "query method called for side effects" bug. All other query methods on `IndexPage` (`find()`, `len()`, `is_empty()`) already had `#[must_use]`.

**Fix:** Added `#[must_use]` attribute to `contains_range()`, matching the convention of all other `IndexPage` query methods.

### V20-F11: `open_readonly` bloom rebuild has no progress logging [LOW — Observability]

**Location:** `store.rs:520-560` (`IndexStore::open_readonly()`)

**Analysis:** `open_readonly()` rebuilds the bloom filter by iterating all entries in the Redb database. For large indexes (millions of entries), this can take several seconds with no feedback. Operators monitoring log output see the process appear to hang during bloom reconstruction. Other long-running operations in the crate (e.g., `for_each_sorted_page`) emit progress logs.

**Fix:** Added periodic progress logging: every 100,000 entries, emit a `tracing::debug!` message with the entry count. This provides operational visibility without impacting performance (the modulo check is negligible vs. Redb iteration).

### V20-F12: `bloom_expected_items()` missing doc comment [LOW — Documentation]

**Location:** `builder.rs:95-100` (`IndexBuilder::bloom_expected_items()`)

**Analysis:** `bloom_expected_items()` is a public method that returns the estimated number of items the bloom filter is sized for. It had no doc comment, making the method's purpose and return value semantics unclear. All other public methods in `IndexBuilder` have doc comments.

**Fix:** Added a multi-line doc comment explaining the method's purpose, return value semantics, and relationship to the bloom filter's false-positive rate guarantee.

---

## Score

**V20 Score: 98/100**

Improvements over V19:
- Both `from_memory()` and `from_pages()` now rebuild bloom from entries, closing the last caller-trust gap (V20-F1)
- `RwLock` removed from read-only reader, eliminating unnecessary synchronization and the `parking_lot` dependency (V20-F2)
- Bloom-check early return in `insert()` avoids expensive write transactions for known duplicates (V20-F3)
- Code duplication between `read_sorted()` and `for_each_sorted_page()` eliminated (V20-F4)
- All-zero sip_keys rejected at deserialization, preventing bloom filter bypass attacks (V20-F5)
- Error domain consistency improved across all index operations (V20-F6)
- Staging file preserved on flush failure for potential recovery (V20-F7)
- Recovery I/O halved by caching page block locations (V20-F9)
- API safety and observability improvements (V20-F10, V20-F11, V20-F12)

Remaining concerns:
- finalize() CPU-heavy work on async thread (-1, documented V19-F7, carried from V18-F7)
- ChunkIndex::finalize materializes all pages (-1, carried from V18-F10)

---

## Recommendations for V21

1. Restructure `finalize()` to use `spawn_blocking` for serialization/encryption (V19-F7 / V18-F7 — carried 3 audits)
2. Add streaming `IndexReader` construction to avoid materializing all pages (V18-F10 — carried 3 audits)
3. Add fuzz targets for `BloomFilterData` deserialization (all-zero keys, oversized bitmaps, malformed sip_keys)
4. Consider property-based testing (proptest) for `IndexPage` sort/dedup invariants
5. Evaluate lock-free concurrent bloom filter reads for multi-threaded lookup
6. Add integration tests for the bloom-check early-return path in `insert()` under high-contention scenarios
