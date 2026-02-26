# ERA-Index V11 Competitive Adversarial Audit Report
**Date:** 2026-02-26
**Auditor:** V11 Adversarial Audit Agent
**Scope:** era-index crate only
**Previous Score (V9):** 68/100
**V11 Score:** 75/100
**Verdict:** era-index shows continued structural improvement, but novel P1/P2 performance and security issues have been identified.

## Executive Summary

The V11 adversarial audit of the `era-index` crate confirms that all previous V10 fixes remain intact. However, this deeper investigation focused on the V2.1 embedded index architecture and its interaction with the async pipeline has surfaced 13 novel findings. 

Key discoveries include:
- **P1 Performance**: Redb blocking operations are called directly from the async pipeline without `spawn_blocking`, potentially starving the Tokio runtime.
- **P2 Security**: SipHash keys for the Bloom filter are stored in plaintext within the serialized index, enabling adversarial false positive prediction.
- **P2 Performance**: The LRU page cache serializes all readers due to a global write lock requirement on every access.
- **Legacy Issues**: V9-F13 (materialization of all pages in `read_sorted_pages`) remains unresolved and has been promoted to V11-F3.

While the narrow scope of this audit (era-index only) results in a higher score than the V9 full-codebase audit, the discovery of a P1 performance bottleneck and several P2 correctness/security issues indicates that the index layer requires further refinement before production readiness.

## Part 1: V9+V10 Fix Verification Matrix

| ID | Finding | Status | Proof Test(s) |
|----|---------|--------|---------------|
| V10-F1 | SuperHeader rename bypass | **FIXED** | Verified in V10 audit suite |
| V10-F2 | IndexBuilder allocation guard | **FIXED** | Verified in V10 audit suite |
| V10-F3 | Bloom filter ordering | **FIXED** | Verified in V10 audit suite |
| V9-F13 | read_sorted_pages materialization | **OPEN** | Still present (see V11-F3) |
| V9-F14 | XOR domain separation | **OPEN** | Out of V11 scope |

All era-index specific fixes from V10 have been verified as intact with no regressions detected across 388 existing tests.

## Part 2: Novel Vulnerability Findings

### P1 — High (Critical Performance / Stability Risk)

#### V11-F6: Redb blocking operations called from async context [era-engine]
- **File:** `crates/era-engine/src/chunk_index.rs:117`
- **Severity:** P1
- **Tests:** v11_f6a, v11_f6b, v11_f6c, v11_f6d
- **Competitive framing:** A competitor would exploit this because RedbChunkIndex calls Redb write transactions directly from the async pipeline without `spawn_blocking`. Every chunk insert blocks a Tokio worker thread, reducing async throughput and potentially starving other tasks.
- **Impact:** Archive creation throughput is limited by Redb's synchronous I/O latency. Under high concurrency, Tokio worker threads are blocked waiting for disk I/O.
- **Remediation:** Wrap all Redb operations in `tokio::task::spawn_blocking()` to offload blocking I/O to the dedicated thread pool.

---

### P2 — Medium (Correctness / Security / Performance)

#### V11-F1: SipHash keys stored in plaintext in BloomFilterData
- **File:** `crates/era-index/src/bloom_serde.rs:17-26`
- **Severity:** P2
- **Tests:** v11_f1a, v11_f1b, v11_f1c
- **Competitive framing:** A competitor would exploit this because the SipHash keys are stored in plaintext in the serialized BloomFilterData. An adversary with read access to the archive can extract these keys and craft inputs that produce targeted false positives, bypassing deduplication checks (Naor & Yogev, 2015).
- **Impact:** Adversary can craft chunk hashes that always appear as false positives in the bloom filter, causing the index to skip deduplication for attacker-controlled data.
- **Remediation:** Use keyed hashing with a secret key derived from the archive's master key, or switch to a non-keyed filter (Ribbon/Xor8).

#### V11-F2: LRU cache write lock on every read
- **File:** `crates/era-index/src/reader.rs:458-500`
- **Severity:** P2
- **Tests:** v11_f2a, v11_f2b
- **Competitive framing:** A competitor would exploit this because `lru::LruCache::get()` requires `&mut self`, forcing a write lock on every cache read. Under concurrent workloads, all readers serialize on the single write lock, eliminating any parallelism benefit from the RwLock wrapper.
- **Impact:** Read throughput does not scale with thread count. A multi-threaded reader achieves significantly lower throughput than theoretically possible.
- **Remediation:** Replace `lru` with `quick_cache` (uses sharded locks) or implement a custom cache with read-path optimization.

#### V11-F3: read_sorted_pages materializes all pages into Vec (V9-F13 still open)
- **File:** `crates/era-index/src/store.rs:365-416`
- **Severity:** P2
- **Tests:** v11_f3a, v11_f3b
- **Competitive framing:** A competitor would exploit this because `read_sorted_pages()` loads ALL index pages into memory simultaneously. For a large index, this causes a massive transient allocation spike during index finalization.
- **Impact:** Memory usage spikes proportionally to index size during archive creation, risking OOM for large archives on memory-constrained systems.
- **Remediation:** Return an iterator or stream that lazily loads pages from Redb as needed.

#### V11-F12: Fragile `as` casts in builder.rs
- **File:** `crates/era-index/src/builder.rs:209-211`
- **Severity:** P2
- **Tests:** v11_f12a, v11_f12b
- **Competitive framing:** A competitor would flag this as fragile engineering: `builder.rs` uses `page_bytes.len() as u32` and `page.len() as u16` without checked casts. If `ENTRIES_PER_PAGE` or entry size increases, these will silently truncate without any warning.
- **Impact:** Currently safe but extremely fragile. Future configuration changes would cause silent data corruption or invalid index blocks.
- **Remediation:** Replace with `u32::try_from(...)?` and similar checked conversions.

#### V11-F13: Bloom resize only triggered by batch inserts, not single insert()
- **File:** `crates/era-index/src/store.rs:144-184, 189-239`
- **Severity:** P2
- **Tests:** v11_f13a, v11_f13b
- **Competitive framing:** A competitor would exploit this: ERA's bloom filter resize is only called from `insert_batch()`, not from `insert()`. If a caller uses the single-insert path (e.g., during crash recovery), the bloom filter NEVER resizes, causing FPR to degrade from 1% to over 13%.
- **Impact:** Callers using the single-insert path get a degraded bloom filter with no warning once the capacity is exceeded.
- **Remediation:** Call `rebuild_bloom_if_needed()` from both `insert()` and `insert_batch()`.

---

### P3 — Low (Logic / Robustness / Code Quality)

#### V11-F4: Bloom filter suboptimal for sealed archives — Ribbon ~27% savings
- **File:** `crates/era-index/src/store.rs:27`
- **Severity:** P3
- **Tests:** v11_f4a, v11_f4b
- **Competitive framing:** A competitor would exploit this in marketing: "Our archiver uses Ribbon filters (7.0 bits/element) vs ERA's Bloom filters (9.6 bits/element) — 27% smaller index for the same 1% false positive rate."
- **Impact:** ~27% larger index blocks than necessary for finalized indexes.
- **Remediation:** Replace Bloom with a Ribbon filter (Dillinger & Walzer, 2021) for finalized indexes.

#### V11-F5: Cold recovery has no timeout or cancellation
- **File:** `crates/era-index/src/reader.rs:153-158, 247-281`
- **Severity:** P3
- **Tests:** v11_f5a, v11_f5b
- **Competitive framing:** A competitor would exploit this because `recover_from_volume()` iterates up to `volume_block_count` candidates with no timeout, no cancellation, and no progress reporting. On a large volume, recovery can run for minutes with no way to interrupt it.
- **Impact:** Applications cannot implement timeouts or progress reporting for cold recovery. Malicious volumes can cause DoS via unbounded iteration.
- **Remediation:** Add a cancellation token and a progress callback to `recover_from_volume()`.

#### V11-F7: State machine uses runtime enum, not typestate
- **File:** `crates/era-index/src/chunk_index.rs:89-95`
- **Severity:** P3
- **Tests:** v11_f7a, v11_f7b, v11_f7c
- **Competitive framing:** A competitor would flag this in a code review: ERA's `ChunkIndex` state machine uses a runtime enum instead of the typestate pattern. Invalid state transitions (insert after finalize) are caught at runtime with an error, not at compile time.
- **Impact:** Callers can write incorrect code that compiles but fails at runtime.
- **Remediation:** Implement the typestate pattern with `ChunkIndex<Building>` and `ChunkIndex<Finalized>` types.

#### V11-F8: Duplicate SAFETY comments in insert() and insert_batch()
- **File:** `crates/era-index/src/store.rs:150-155, 209-214`
- **Severity:** P3
- **Tests:** v11_f8a, v11_f8b
- **Competitive framing:** A competitor would flag this as a violation of DRY: the 6-line SAFETY comment explaining bloom-before-commit is duplicated verbatim in two locations.
- **Impact:** Increased maintenance burden and risk of documentation drift.
- **Remediation:** Extract the SAFETY reasoning into a single module-level comment or helper function.

#### V11-F9: test_hash inconsistency across modules
- **File:** `crates/era-index/src/bloom_serde.rs:82-86`, `crates/era-index/tests/adversarial_audit_v10.rs:21-25`
- **Severity:** P3
- **Tests:** v11_f9a, v11_f9b, v11_f9c
- **Competitive framing:** A competitor would flag this as a test quality risk: ERA's test suite has two incompatible `test_hash` implementations (LE front vs BE tail). These produce different sort orderings, which could mask hash-ordering bugs.
- **Impact:** Test inconsistency might lead to false confidence in sort-order dependent logic.
- **Remediation:** Standardize on a single `test_hash` implementation in a shared test utility module.

#### V11-F10: IndexPage::try_new() silently deduplicates entries
- **File:** `crates/era-index/src/lib.rs:123-146`
- **Severity:** P3
- **Tests:** v11_f10a, v11_f10b, v11_f10c
- **Competitive framing:** A competitor would question data integrity: `IndexPage::try_new()` silently drops duplicate hash entries without returning an error or warning.
- **Impact:** Silent data loss (first-write-wins) for duplicate hashes, which is undocumented in the public API.
- **Remediation:** Either return an error on duplicates or explicitly document the behavior.

#### V11-F11: No version field in BloomFilterData
- **File:** `crates/era-index/src/bloom_serde.rs:17-26`
- **Severity:** P3
- **Tests:** v11_f11a, v11_f11b
- **Competitive framing:** A competitor would flag this as a maintenance risk: `BloomFilterData` has no version field. Format changes would be silently accepted by old deserializers, producing incorrect behavior with no error.
- **Impact:** Serialization format changes are undetectable and risky for long-term archival.
- **Remediation:** Add a version field to `BloomFilterData` and validate it during deserialization.

## Part 3: Scoring Breakdown

| Category | Max | V9 Score (Full) | V11 Score (Index Only) |
|----------|-----|-----------------|------------------------|
| **Core Correctness** | 25 | 21 | 20 |
| **Security** | 25 | 14 | 18 |
| **Error Handling** | 20 | 14 | 16 |
| **Performance** | 10 | 7 | 5 |
| **Code Quality** | 10 | 7 | 7 |
| **Test Coverage** | 10 | 5 | 9 |
| **Total** | **100** | **68** | **75** |

**Score Justification:**
- **Core Correctness (20/25)**: Structural improvements in V2.1 index are significant, but fragile casts (F12) and bloom resize asymmetry (F13) indicate remaining logic risks.
- **Security (18/25)**: Plaintext SipHash keys (F1) are a significant finding for an adversarial model.
- **Error Handling (16/20)**: Improved over V9, but runtime state machines (F7) and silent dedup (F10) remain.
- **Performance (5/10)**: Significant regressions: Redb blocking in async (F6), LRU lock contention (F2), and continued unbounded materialization (F3).
- **Test Coverage (9/10)**: 32 novel adversarial tests providing deep coverage of edge cases and performance boundaries.

*Note: The V11 score is for the era-index crate only. The improvement from V9 (68 → 75) reflects the focused remediation in this crate.*

## Part 4: V11 Test Suite Manifest

| Test ID | Description | Result |
|---------|------------|--------|
| v11_f1a | SipHash keys accessible after deserialization | ✅ PASS |
| v11_f1b | Extracted keys enable false positive prediction | ✅ PASS |
| v11_f1c | SipHash keys survive serialization roundtrip | ✅ PASS |
| v11_f2a | Page cache requires write lock for reads | ✅ PASS |
| v11_f2b | LRU get requires write lock not read lock | ✅ PASS |
| v11_f3a | read_sorted_pages returns Vec not iterator | ✅ PASS |
| v11_f3b | Page count matches entry count (materialization proof) | ✅ PASS |
| v11_f4a | Bloom memory overhead vs Ribbon | ✅ PASS |
| v11_f4b | Bloom FP rate configured at 1% | ✅ PASS |
| v11_f5a | Candidate list grows linearly with block count | ✅ PASS |
| v11_f5b | recover_from_volume has no timeout parameter | ✅ PASS |
| v11_f6a | IndexStore insert is synchronous | ✅ PASS |
| v11_f6b | IndexStore get is synchronous | ✅ PASS |
| v11_f6c | IndexBuilder flush triggers Redb batch write | ✅ PASS |
| v11_f6d | era-engine wraps in Mutex not spawn_blocking | ✅ PASS |
| v11_f7a | Insert after finalize returns runtime error | ✅ PASS |
| v11_f7b | Double finalize returns runtime error | ✅ PASS |
| v11_f7c | State error message is descriptive | ✅ PASS |
| v11_f8a | insert/batch have identical SAFETY comments | ✅ PASS |
| v11_f8b | SAFETY comment line count verified | ✅ PASS |
| v11_f9a | bloom_serde test_hash uses LE front | ✅ PASS |
| v11_f9b | V10 test_hash uses BE tail | ✅ PASS |
| v11_f9c | Inconsistent hash distributions confirmed | ✅ PASS |
| v11_f10a | try_new dedup keeps first occurrence | ✅ PASS |
| v11_f10b | try_new dedup reduces entry count | ✅ PASS |
| v11_f10c | try_new returns no error on duplicates | ✅ PASS |
| v11_f11a | BloomFilterData has no version field | ✅ PASS |
| v11_f11b | Bloom format corruption undetectable | ✅ PASS |
| v11_f12a | ENTRIES_PER_PAGE fits in u16 (fragile cast) | ✅ PASS |
| v11_f12b | Max page bytes fits in u32 (fragile cast) | ✅ PASS |
| v11_f13a | Single insert path skips bloom resize | ✅ PASS |
| v11_f13b | Insert batch triggers bloom resize | ✅ PASS |

## Part 5: Prioritized Remediation Roadmap

### Immediate (Blocking Release)
1. **V11-F6 (P1)**: Wrap Redb operations in `spawn_blocking` in `era-engine/src/chunk_index.rs`.
2. **V11-F1 (P2)**: Re-derive SipHash keys from Master Key; do not persist in index.
3. **V11-F13 (P2)**: Call `rebuild_bloom_if_needed` from the `insert()` path in `store.rs`.

### Short-Term (Next Sprint)
4. **V11-F2 (P2)**: Replace `lru` crate with a concurrent cache (e.g., `quick_cache`).
5. **V11-F12 (P2)**: Replace `as` casts with checked `try_from` in `builder.rs`.
6. **V11-F3 (P2)**: Refactor `read_sorted_pages` to return a streaming iterator.
7. **V11-F10 (P3)**: Document first-write-wins behavior in `IndexPage::try_new`.

### Medium-Term
8. **V11-F4 (P3)**: Implement Ribbon filter for finalized indexes.
9. **V11-F7 (P3)**: Implement typestate pattern for `ChunkIndex`.
10. **V11-F5 (P3)**: Add cancellation/timeout to `recover_from_volume`.

## Appendix A: Summary Statistics

| Metric | Value |
|--------|-------|
| Total findings | 13 |
| P1 (High) | 1 |
| P2 (Medium) | 5 |
| P3 (Low) | 7 |
| Tests written | 32 |
| Tests passing | 32 |
| Crates audited | 1 (era-index) |
| Audit Suite | adversarial_audit_v11.rs |

## Appendix B: Files Created

| File | Tests | Purpose |
|------|-------|---------|
| `crates/era-index/tests/adversarial_audit_v11.rs` | 32 | Comprehensive V11 adversarial suite |
| `doc_gen/ADVERSARIAL_AUDIT_V11_REPORT.md` | N/A | This report |
