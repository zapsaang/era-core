# Adversarial Audit V8 Report — ERA-Index Post-Competitor Implementation

**Audit Date:** 2026-02-25  
**Auditor:** V8 Red-Team  
**Target:** `era-index` crate (all modules)  
**Test Suite:** `crates/era-index/tests/adversarial_audit_v8.rs` — **63 tests, all passing**  
**Clippy:** Zero warnings  
**Scope:** Memory safety, data integrity, spec compliance, performance regression  

---

## Executive Summary

The competitor claims to have implemented ERA-Index V2.1 and resolved all issues from previous audits (V6, V7). While the core Redb migration is functional and the P0/P1 fixes from V8 are verified, this adversarial audit has uncovered **6 new critical or high-severity vulnerabilities**, **4 medium-severity issues**, and **3 low-severity issues** that undermine the safety, correctness, and performance guarantees of the implementation.

**Overall Score: 55/100** (pass threshold: 80)

The most severe finding is that `MetaIndex` public fields completely bypass the ordering validation that was the V8 P0-4 fix — meaning the fix is trivially circumventable. The second most critical finding is that bloom filter false positive rate silently degrades 13.5x before the resize threshold is reached, directly impacting deduplication performance.

---

## Scoring Breakdown

| Category | Weight | Score | Notes |
|---|---|---|---|
| Data Integrity | 25% | 12/25 | MetaIndex pub fields (F1), silent dedup in try_new (F15) |
| Memory Safety | 20% | 10/20 | read_sorted_pages not streaming (F3), unbounded page cache (F7), no deser bounds (F10) |
| Spec Compliance | 15% | 4/15 | No ENTRIES_PER_PAGE enforcement (F2), no streaming finalize (F3), disabled benchmarks (F8) |
| Security | 15% | 10/15 | XOR domain separation weakness (F11), no bloom validation (F5) |
| Performance | 15% | 12/15 | Bloom FP degradation (F4), entry_count O(buffer) cost (F9) |
| Code Quality | 10% | 7/10 | test_hash inconsistency (F13), stale benchmark file (F8) |

---

## Findings

### P0 — Critical (Deployment Blockers)

#### V8-F1: MetaIndex `pages` and `bloom_filter` fields are PUBLIC [CRITICAL]

**Severity:** P0  
**Files:** `lib.rs:196-198`  
**Proof Tests:** `f1a`, `f1b`, `f1c`

**Description:** The V8 audit claimed P0-4 was fixed by adding ordering validation to `MetaIndex::add_page()`. However, both `pages: Vec<PagePointer>` and `bloom_filter: Vec<u8>` are declared `pub`, allowing any caller to bypass validation entirely.

**Impact:** Any code can do `meta.pages.push(...)` to insert out-of-order, overlapping, or duplicate page pointers. This corrupts the binary search in `find_page()`, causing:
- Silent incorrect lookups (wrong page returned)
- Silent data loss (valid entries not found)
- Overlapping page ranges causing ambiguous results

**Proof (f1a):**
```rust
let mut meta = MetaIndex::new();
// Bypass add_page() entirely via pub field
meta.pages.push(PagePointer { min_hash: test_hash(1000), ... });
meta.pages.push(PagePointer { min_hash: test_hash(0), ... }); // OUT OF ORDER!
// Binary search now broken
```

**Root Cause:** `MetaIndex` struct fields are `pub` in the rkyv-derived struct. The `add_page()` gatekeeper exists but is trivially bypassed.

**Recommended Fix:** Make `pages` and `bloom_filter` private. Add getters. All construction must go through `add_page()` and `set_bloom_filter()` (which itself needs validation — see V8-F5).

---

#### V8-F2: IndexPage::try_new() accepts unbounded entry count [CRITICAL]

**Severity:** P0  
**Files:** `lib.rs:118-132`  
**Proof Tests:** `f2a`, `f2b`, `f2c`, `f2d`

**Description:** The V2.1 spec defines `ENTRIES_PER_PAGE = 8192` as a hard limit ensuring each page fits in L2 cache (~320KB). However, `try_new()` has NO entry count validation. A page with 100,000 entries (12.2x the limit, ~6.25MB) is silently accepted.

**Impact:**
- Pages exceeding L2 cache defeat the core cache optimization
- Binary search within oversized pages is slower
- Serialized page sizes become unpredictable
- Memory allocation during deserialization is unbounded (see V8-F10)

**Proof (f2d — measured):**
```
V8-F2: Oversized page = 100000 entries (12.2x spec limit, ~6250KB vs ~512KB target)
```

**Root Cause:** `try_new()` only validates non-emptiness and sorts/dedup, but does not enforce the `ENTRIES_PER_PAGE` upper bound.

**Recommended Fix:** Add `if entries.len() > ENTRIES_PER_PAGE { return Err(...) }` to `try_new()`.

---

### P1 — High Severity

#### V8-F3: read_sorted_pages() falsely claims streaming behavior [HIGH]

**Severity:** P1  
**Files:** `store.rs:338-382`  
**Proof Tests:** `f3a`, `f3b`

**Description:** The docstring says _"never holds more than one page of entries in memory at a time"_ but the function returns `Vec<(IndexPage, BlockId)>`, which materializes ALL pages in memory simultaneously. `builder::finalize()` stores this entire Vec in a local variable.

**Impact:** For 1M entries at ~80 bytes each, this is ~80MB of pages held simultaneously — identical to `read_sorted()`. The "streaming, low-memory" architecture claimed in the V2.1 spec Section 5.1 is not implemented.

**Root Cause:** The function collects all pages into a Vec before returning. A true streaming implementation would return an Iterator.

**Proof (f3a):**
```rust
let pages = builder.read_sorted_pages().unwrap();
// ALL 4 pages materialized simultaneously — NOT streaming
assert_eq!(pages.len(), 4);
```

---

#### V8-F4: Bloom filter FP rate silently degrades 13.5x before resize [HIGH]

**Severity:** P1  
**Files:** `store.rs:227-256`  
**Proof Tests:** `f4a`, `f4b`

**Description:** `rebuild_bloom_if_needed()` only triggers when `entry_count > bloom_capacity * 2`. Between 1x and 1.99x capacity, the false positive rate degrades from the promised 1% to 13.26% — a **13.5x degradation** — with no warning, no log, and no resize.

**Impact:** Deduplication performance is severely impacted. At 13% FP rate, 13% of negative lookups will proceed to the expensive Redb read transaction + L2 page load path unnecessarily. This transforms O(1) bloom rejections into O(log N) disk reads.

**Proof (f4a — measured):**
```
V8-F4: Bloom FP rate at 1.0x capacity: 0.98%, at 1.9x capacity: 13.26%
WARNING: FP rate degraded 13.5x before resize threshold was reached
```

**Recommended Fix:** Lower the resize threshold to 1.5x, or implement continuous FP rate monitoring with adaptive resizing.

---

#### V8-F5: set_bloom_filter() performs no validation [HIGH]

**Severity:** P1  
**Files:** `lib.rs:268-270`  
**Proof Tests:** `f5a`, `f5b`, `f5c`

**Description:** `MetaIndex::set_bloom_filter()` accepts arbitrary bytes without verifying they deserialize to a valid `BloomFilterData`. Garbage, empty, and truncated data are all accepted silently. The error only surfaces at lookup time when `deserialize_bloom()` fails.

**Impact:** Violates fail-fast principle. Corrupted bloom data propagates through serialization to disk, making recovery impossible without rebuild. A crafted archive with garbage bloom_filter bytes will fail on every lookup attempt.

---

#### V8-F8: All benchmarks are disabled — zero performance regression detection [HIGH]

**Severity:** P1  
**Files:** `benches/index_bench.rs`  
**Proof Tests:** `f8a`, `f8b`, `f8c`

**Description:** The entire benchmark suite uses `#[cfg(any())]` (always-false condition). The only active benchmark computes `1 + 1`. There is ZERO capacity to detect performance regressions.

**Measured baseline (from audit tests):**
```
Insert throughput: 33,131 ops/sec (50K entries)
Lookup throughput (hit):  102,088 ops/sec
Lookup throughput (miss): 4,024,441 ops/sec (bloom fast path)
Finalize: 2,967 → 88,754 entries/sec (scales with batch size)
100K stress: insert 2.99s, finalize 0.69s, lookup 1.08s
```

**Recommended Fix:** Implement Criterion benchmarks for insert, lookup (hit/miss), finalize, and bloom operations using the V2.1 API.

---

### P2 — Medium Severity

#### V8-F6: from_memory() with non-empty MetaIndex produces inconsistent state [MEDIUM]

**Severity:** P2  
**Files:** `reader.rs:64-84`  
**Proof Test:** `f6a`

**Description:** `IndexReader::from_memory()` takes a `MetaIndex` parameter and adds pages to it. If the caller passes a non-empty MetaIndex (one that already has pages), the new pages are appended. The existing pages have no corresponding `embedded_pages` entries, causing silent lookup failures for hashes in those phantom pages.

---

#### V8-F7: Page cache has no eviction policy [MEDIUM]

**Severity:** P2  
**Files:** `reader.rs:44`  
**Proof Test:** `f7a`

**Description:** `page_cache: RwLock<HashMap<BlockId, IndexPage>>` grows without limit. In filesystem mode, every page accessed is cached permanently. For large indexes with many pages accessed sequentially (e.g., during full verification), this causes unbounded memory growth.

**Recommended Fix:** Implement LRU eviction with a configurable max cache size.

---

#### V8-F9: entry_count() has O(buffer × Redb_query) cost per call [MEDIUM]

**Severity:** P2  
**Files:** `builder.rs:107-115`  
**Proof Test:** `f9a`

**Description:** Each call to `entry_count()` creates a `HashSet<ChunkHash>` from buffer entries and queries Redb individually for each unique hash. With a nearly-full buffer (999 entries), each call takes ~4.7ms.

**Proof (f9a — measured):**
```
V8-F9: 1000 entry_count() calls with 999-entry buffer: 4667ms (4667µs/call)
```

**Impact:** If `entry_count()` is called in a progress loop during ingest, the overhead is catastrophic.

**Recommended Fix:** Cache the count with a dirty flag. Only recompute when buffer contents change.

---

#### V8-F10: No deserialization allocation bounds [MEDIUM]

**Severity:** P2  
**Files:** `store.rs:32-47`, `reader.rs:447-454`  
**Proof Test:** `f10a`

**Description:** `rkyv::check_archived_root` validates structure but does not enforce maximum allocation sizes. A crafted `IndexPage` payload with millions of entries would be accepted by both the staging store and the reader.

**Impact:** Denial-of-service vector. A malicious `.era` archive with an oversized IndexPage would OOM the reader during recovery.

---

### P3 — Low Severity

#### V8-F11: XOR domain separation between index and data blocks [LOW]

**Severity:** P3  
**Files:** `builder.rs:169-170`  
**Proof Tests:** `f11a`, `f11b`

**Description:** Index block keys are derived by XORing `nonce_context[0]` with `0xFF`. When `nonce_context[0]` is `0xFF`, the XOR produces `0x00` — potentially colliding with a different archive's data block context. Additionally, double-XOR returns to the original value.

**Status:** Known issue (V7-F13), deferred. Documented here for completeness.

---

#### V8-F13: test_hash inconsistency across test files [LOW]

**Severity:** P3  
**Files:** All test files  
**Proof Test:** `f13a`

**Description:** Different test files use incompatible `test_hash` implementations:
- `builder.rs`, `reader.rs`: `bytes[..8]` with `to_le_bytes()` — **inverted sort order**
- `store.rs`, `lsm_tree.rs`, `lib.rs`: `bytes[24..32]` with `to_be_bytes()` — natural order

LE hashes sort counter-intuitively: `test_hash(256) < test_hash(1)` for byte comparison. This makes cross-file test composition fragile.

---

#### V8-F15: IndexPage::try_new() dedup uses unstable sort (non-deterministic survivor) [LOW]

**Severity:** P3  
**Files:** `lib.rs:121-128`  
**Proof Tests:** `f15a`, `f15b`

**Description:** `try_new()` calls `sort_unstable_by_key` followed by `dedup_by_key`. For entries with identical hashes but different locations (multi-volume scenario), `sort_unstable` does not guarantee a stable order. This means which entry survives dedup is non-deterministic.

**Impact:** While `try_new()` is a safety net (Redb handles primary dedup), the non-determinism makes debugging difficult and violates the first-write-wins contract.

---

## V2.1 Spec Compliance Gap Analysis

| V2.1 Spec Section | Status | Notes |
|---|---|---|
| §3.1 IndexPage (ENTRIES_PER_PAGE=8192 hard limit) | **NOT ENFORCED** | `try_new()` accepts any count (V8-F2) |
| §3.2 MetaIndex encapsulation | **VIOLATED** | Fields are `pub` (V8-F1) |
| §4.1 Secure Spiller (ephemeral XChaCha20) | **NOT IMPLEMENTED** | Replaced by Redb. No encrypted temp files. |
| §4.2 MemTable + Bloom + Spill Check | **PARTIALLY** | Redb replaces memtable/spiller. Bloom implemented. |
| §5.1 Tiered Merger (recursive, fan-in=64) | **NOT IMPLEMENTED** | Replaced by Redb sorted iteration. |
| §5.2 Streaming finalization | **NOT IMPLEMENTED** | `read_sorted_pages()` materializes all pages (V8-F3) |
| §6 Reader (Bloom + L1 + L2) | **IMPLEMENTED** | Working correctly with RwLock-based cache. |
| §7 Crash Recovery (Bloom snapshots) | **NOT IMPLEMENTED** | No bloom snapshots. Redb ACID provides basic recovery. |
| §8 Benchmarks | **DISABLED** | All real benchmarks are `#[cfg(any())]` (V8-F8) |

**Architectural Note:** The replacement of Spiller/TieredMerger with Redb is a legitimate design decision that simplifies the codebase significantly. However, the spec should be updated to reflect this change, and the spec-mandated invariants (ENTRIES_PER_PAGE bounds, streaming finalize) must still be enforced.

---

## Verification

```bash
# Run the V8 adversarial audit test suite
cargo test -p era-index --test adversarial_audit_v8        # 63 tests, all pass
cargo clippy -p era-index --test adversarial_audit_v8 -- -D warnings  # Zero warnings

# Verify existing audit tests are not regressed
cargo test -p era-index --test adversarial_audit_v7        # 41 tests, all pass

# Run with diagnostics to see measured values
cargo test -p era-index --test adversarial_audit_v8 -- --nocapture 2>&1 | grep "^V8-F"
```

---

## Recommended Remediation Priority

| Priority | Finding | Effort | Impact |
|---|---|---|---|
| **Immediate** | V8-F1: Make MetaIndex fields private | Low | Closes P0-4 bypass |
| **Immediate** | V8-F2: Enforce ENTRIES_PER_PAGE in try_new() | Low | Restores spec invariant |
| **This Sprint** | V8-F4: Lower bloom resize threshold to 1.5x | Low | 13.5x FP improvement |
| **This Sprint** | V8-F5: Validate bloom bytes in set_bloom_filter() | Low | Fail-fast on corruption |
| **This Sprint** | V8-F8: Implement real benchmarks | Medium | Performance regression detection |
| **Next Sprint** | V8-F3: True streaming read_sorted_pages() via Iterator | Medium | Memory-bounded finalize |
| **Next Sprint** | V8-F7: LRU page cache eviction | Medium | Bounded reader memory |
| **Next Sprint** | V8-F9: Cached entry_count() | Low | 4667µs → ~0µs per call |
| **Backlog** | V8-F10: Deserialization allocation bounds | Medium | DoS prevention |
| **Backlog** | V8-F13: Standardize test_hash across files | Low | Test reliability |

---

## Test Suite Summary

**File:** `crates/era-index/tests/adversarial_audit_v8.rs`  
**Total:** 63 tests  
**Status:** All 63 passing  
**Clippy:** Zero warnings  

| Finding | Tests | Category |
|---|---|---|
| V8-F1 (MetaIndex pub fields) | f1a, f1b, f1c | Data Integrity |
| V8-F2 (Unbounded page size) | f2a, f2b, f2c, f2d | Spec Compliance |
| V8-F3 (Non-streaming finalize) | f3a, f3b | Memory Safety |
| V8-F4 (Bloom FP degradation) | f4a, f4b | Performance |
| V8-F5 (Bloom validation) | f5a, f5b, f5c | Data Integrity |
| V8-F6 (from_memory inconsistency) | f6a, f6b | Data Integrity |
| V8-F7 (Unbounded page cache) | f7a | Memory Safety |
| V8-F8 (Disabled benchmarks) | f8a, f8b, f8c | Performance |
| V8-F9 (entry_count cost) | f9a, f9b, f9c | Performance |
| V8-F10 (Deser bounds) | f10a | Memory Safety |
| V8-F11 (XOR domain) | f11a, f11b | Security |
| V8-F12 (from_pages ordering) | f12a, f12b | Data Integrity |
| V8-F13 (test_hash inconsistency) | f13a | Code Quality |
| V8-F14 (State machine) | f14a, f14b, f14c | Correctness |
| V8-F15 (Dedup non-determinism) | f15a, f15b | Data Integrity |
| V8-F16 (Concurrent correctness) | f16a | Concurrency |
| V8-F17 (Bloom false negatives) | f17a, f17b | Correctness |
| V8-F18 (Sort correctness) | f18a, f18b | Correctness |
| V8-F19 (MetaIndex boundaries) | f19a-f19e | Correctness |
| V8-F20 (E2E roundtrip) | f20a, f20b | Correctness |
| V8-F21 (Bloom roundtrip) | f21a | Correctness |
| V8-F22 (Discard semantics) | f22a, f22b | Lifecycle |
| V8-F23 (Page find boundaries) | f23a-f23d | Correctness |
| V8-F24 (Multi-volume) | f24a | Correctness |
| V8-F25 (First-write-wins) | f25a, f25b | Correctness |
| V8-F26 (100K stress) | f26a | Scalability |
| V8-F27 (Serialization sizes) | f27a | Performance |
| V8-F28 (Extreme hashes) | f28a | Edge Cases |
| V8-F29 (Read-only enforcement) | f29a, f29b | Correctness |
| V8-F30 (File cleanup) | f30a, f30b | Lifecycle |
