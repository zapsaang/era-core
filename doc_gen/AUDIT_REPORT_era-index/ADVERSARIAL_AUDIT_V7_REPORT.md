# ADVERSARIAL AUDIT V7 — Deep Semantic & Correctness Attack Surface

**Audit Date:** 2026-02-24
**Auditor:** Senior Rust Systems Engineer (Red Team, Round 7)
**Target:** Post-V6-remediation `crates/era-index/` (all CLAUDE.md P0/P1 fixes applied, V6 findings unresolved)
**Test Suite:** `crates/era-index/tests/adversarial_audit_v7.rs` (41 tests, all passing)
**Total Test Suite:** 298 tests across all suites (22 unit + 8 V2 + 31 V3 + 47 V4 + 38 V5 + 47 V6 + 41 V7 + 21 compliance + 2 cold_recovery + 27 persistence + 12 architecture + 2 doc-tests), zero failures
**Prior Audits:**
- V6 (`adversarial_audit_v6.rs`, 47 tests): [ADVERSARIAL_AUDIT_V6_REPORT.md](./ADVERSARIAL_AUDIT_V6_REPORT.md)
- V5 (`adversarial_audit_v5.rs`, 38 tests): [ADVERSARIAL_AUDIT_V5_REPORT.md](./ADVERSARIAL_AUDIT_V5_REPORT.md)
- V4 (`adversarial_audit_v4.rs`, 47 tests): [ADVERSARIAL_AUDIT_V4_REPORT.md](./ADVERSARIAL_AUDIT_V4_REPORT.md)
- V3 (`adversarial_audit_v3.rs`, 31 tests): [COUNTER_AUDIT_REPORT.md](./COUNTER_AUDIT_REPORT.md)
- V2 (`audit_redb_compliance.rs`, 21 tests): [RED_TEAM_AUDIT_REPORT.md](./RED_TEAM_AUDIT_REPORT.md)

---

## Executive Summary

**The V6 audit scored 62/100 and confirmed all CLAUDE.md P0/P1 fixes as genuine.** This V7 audit does not re-test those fixes. Instead, it performs a deep semantic correctness analysis of the post-fix codebase, focusing on **algorithmic bugs, invariant violations, and design flaws** that the V6 audit flagged but did not fully exploit.

### Key Discovery: The CC3 "Fix" Introduced a NEW Bug

The CLAUDE.md P1 finding CC3 ("Builder entry_count Uses Bloom") was fixed by switching from `bloom_contains()` to `store.entry_count() + buffer.len()`. The V6 audit scored this as "✅ FIXED". **It is not fixed — it is broken in the opposite direction.** The old code **undercounted** (bloom false positives). The new code **overcounts** because `buffer.len()` includes entries whose hashes are already in Redb. At 100% duplicate input, `entry_count()` returns 2× the actual count.

### Regression/Persistence Analysis

| V6 Finding | V6 Severity | V7 Status | Evidence |
|------------|-------------|-----------|----------|
| V6-F3: from_memory() single-page | CRITICAL | **UNFIXED** | V7-F2c confirms `meta_page_count()==1` for all sizes |
| V6-F5: IndexLocation drops volume_id | HIGH | **UNFIXED** | V7-F5a/b confirm 3-field struct at `reader.rs:23` |
| V6-F7: page_cache Mutex contention | HIGH | **UNFIXED** | V7-F12a confirms `page_cache: Mutex<HashMap>` at `reader.rs:38` |
| V5-CC6: Bloom never resized | HIGH | **UNFIXED** | V7-F4a/b/c confirm no resize mechanism exists |
| CC3: entry_count bloom fix | "FIXED" | **REGRESSED** | V7-F1a/b/c/d demonstrate overcounting |

---

### V7 Audit Score: 48/100

| Category | Score | Max | Notes |
|----------|-------|-----|-------|
| CC3/P1 Remediation Quality | 0 | 10 | Overcounting is worse than undercounting (bloom FP ≈1% vs overcounting = buffer%) |
| V6 CRITICAL Fixes | 0 | 15 | from_memory() single-page UNFIXED, most impactful V6 finding |
| V6 HIGH Fixes | 0 | 10 | IndexLocation volume_id, bloom resize, page_cache Mutex all UNFIXED |
| Correctness Invariants | 6 | 15 | Dedup strategy divergence, MetaIndex ordering unenforced |
| Memory Safety | 8 | 10 | drain_sorted O(N) RAM, finalize double-iteration |
| API Defense-in-Depth | 6 | 10 | No page integrity verification, pub struct fields |
| Crypto Hygiene | 7 | 10 | XOR domain separation is minimal but functional |
| Performance Design | 10 | 10 | Embedded mode zero-contention confirmed, bloom fast-path works |
| Test Base Quality | 11 | 10 | 298 tests, all behavioral, 7 audit rounds — exemplary (+1 bonus) |

**Score dropped from V6's 62/100 to 48/100** because:
1. CC3 "fix" is a regression, not a fix (−10)
2. Three V6 CRITICALs remain untouched after being reported (−15)
3. Novel correctness bugs found (dedup divergence, MetaIndex ordering) (−4)
4. Bonus for test infrastructure quality (+1)

---

## V7 Findings Detail

---

### V7-F1 [CRITICAL]: entry_count() Overcounts with Duplicates — CC3 "Fix" Is a Regression

**File:** `crates/era-index/src/builder.rs:102-103`
**Code:**
```rust
pub fn entry_count(&self) -> usize {
    self.store.entry_count() + self.buffer.len()
}
```

**Root Cause:** `buffer.len()` counts all entries pushed since the last flush, including entries whose hashes already exist in Redb from previous flushes. After flush, `store.entry_count()` reflects exact Redb count (Redb deduplicates on insert via `is_new` tracking in `store.rs:185`). But the buffer is a plain `Vec` with no dedup awareness.

**Impact:**
- At 50% duplicate rate, overcounting by ~50% of buffer size
- At 100% duplicate rate (re-inserting all existing entries), reported count = 2× actual count
- Bloom filter sizing uses `entry_count()` → oversized bloom wastes memory
- External callers trusting `entry_count()` for capacity planning get wrong answers

**Proof (V7-F1a–d):**

| Test | Scenario | Expected | Actual | Overcounting |
|------|----------|----------|--------|-------------|
| f1a | 500 unique + 500 same within buffer | 500 | 1000 | 2.00× |
| f1b | 500 in Redb, re-insert 500 into buffer | 500 | 1000 | 2.00× |
| f1c | 1000 entries, then re-insert all 1000 | 1000 | 2000 | 2.00× |
| f1d | Accumulating divergence tracking | Monotonic | Grows unbounded | N/A |

**Fix:** Either:
- (a) Check `store.bloom_contains(&entry.hash)` and `buffer` hashset before incrementing  
- (b) Compute exact count: `store.entry_count() + buffer.iter().filter(|e| !store.bloom_contains(&e.hash)).count()`
- (c) Track a `HashSet<ChunkHash>` of unique hashes in buffer (memory cost: 32 bytes/hash)

**Severity Rationale:** CRITICAL because `entry_count()` is the public API for callers to determine index size. Wrong count → wrong bloom sizing → incorrect capacity decisions.

---

### V7-F2 [CRITICAL]: from_memory() Ignores ENTRIES_PER_PAGE — All Entries in One Page

**File:** `crates/era-index/src/reader.rs:62-89` and `crates/era-index/src/lsm_tree.rs:166-204`
**Status:** UNFIXED from V6-F3. Zero code changes since V6 report.

**Root Cause:** `LsmTree::finalize()` at `lsm_tree.rs:178` calls `builder.drain_sorted()` to get all entries as a `Vec<IndexEntry>`, then calls `IndexReader::from_memory()` which wraps ALL entries into a single `IndexPage`, regardless of `ENTRIES_PER_PAGE = 8192`.

**Proof (V7-F2a/c):**

| Test | Entries Inserted | Pages Created | Expected Pages | Violations |
|------|-----------------|---------------|----------------|------------|
| f2a | 8192, 16384, 50000 | 1, 1, 1 | 1, 2, 7 | 0, 1, 6 |
| f2c | 100, 8192, 16384 | 1, 1, 1 | 1, 1, 2 | — always 1 |

**Impact:**
1. **Lookup performance:** Binary search on 50,000-entry page = 16 comparisons. With proper 8192-entry pages, it would be 2 comparisons (page lookup) + 13 comparisons (within page) = 15, BUT with much better cache locality per page.
2. **Serialization size:** One giant page doesn't benefit from page-level compression or selective caching.
3. **Contract violation:** `ENTRIES_PER_PAGE` is a public constant that callers can reasonably assume is enforced.

**Fix:** In `from_memory()` or `LsmTree::finalize()`, chunk the sorted entries into groups of `ENTRIES_PER_PAGE` before constructing `IndexPage` objects and `MetaIndex`.

---

### V7-F3 [CRITICAL]: Dedup Strategy Divergence — Redb Last-Write-Wins vs IndexPage First-Occurrence-Wins

**File:** `crates/era-index/src/store.rs:165-200` (Redb insert) vs `crates/era-index/src/lib.rs:128-140` (IndexPage::new)

**Root Cause:** Two independent deduplication stages use opposite strategies:

1. **Redb store** (`store.rs:185`): When inserting a batch, if a hash already exists, Redb overwrites (`insert()` replaces). The `is_new` flag tracks this but the entry IS overwritten. **Last-write-wins.**

2. **IndexPage::new()** (`lib.rs:132-133`): After sorting, calls `entries.dedup_by_key(|e| e.hash)` which keeps the **first** occurrence of each hash and drops subsequent ones. **First-occurrence-wins.**

**Impact:** If the same hash appears with different metadata (different volume_id, block_id, offset, or length):
- Redb stores the LAST version inserted
- But `drain_sorted()` reads from Redb (which has last-write version), then IndexPage dedup has no effect because Redb already deduped

The real risk: if entries with the same hash but different metadata are inserted in the same batch (same `flush_buffer()` call), the batch is passed to `insert_batch()` which iterates in order. Redb will keep the last. But if they somehow bypass Redb (e.g., `from_memory()` path), IndexPage keeps the first.

**Proof (V7-F3a/b/c):**

| Test | Scenario | Winner |
|------|----------|--------|
| f3a | Redb: same hash, two different offsets | Last insertion (offset 2000) |
| f3b | IndexPage: same hash, two different offsets | First occurrence (offset 1000) |
| f3c | End-to-end via LsmTree (Redb path) | Last insertion (offset 2000) |

**Fix:** Choose ONE dedup strategy. Recommendation: first-write-wins everywhere (matches content-addressed semantics — same hash = same content, first sighting is canonical). Use `insert_if_not_exists` pattern in Redb.

---

### V7-F4 [HIGH]: Bloom Filter Never Resized — FP Rate Degrades with Scale

**File:** `crates/era-index/src/store.rs:50-60` (bloom creation) and `crates/era-index/src/builder.rs:55-65`
**Status:** UNFIXED from V5-CC6. Zero code changes since V5 report.

**Root Cause:** Bloom filter is sized once at `IndexBuilder::new()` based on `mem_limit / 80` (with `max(1024)`). If more entries are inserted than initially planned, the bloom saturates. At 10× overcapacity, false positive rate exceeds 30%, making the bloom nearly useless as a negative filter.

**Proof (V7-F4a/b/c):**

| Test | Bloom Capacity | Entries Inserted | FP Rate | Status |
|------|----------------|-----------------|---------|--------|
| f4a | 1024 | 1024 (1×) | <5% | OK |
| f4a | 1024 | 5120 (5×) | ~15% | Degraded |
| f4a | 1024 | 10240 (10×) | ~30% | Useless |
| f4a | 1024 | 20480 (20×) | ~50%+ | Broken |
| f4b | 1024 | 10240 | >20% | Confirmed |
| f4c | — | — | No resize mechanism | No `bloom = Bloom::new(...)` after initial creation |

**Impact:** Without bloom resize, large indices degrade to checking Redb for every lookup, eliminating the bloom filter's purpose (O(1) negative response).

**Fix:** Add bloom rebuilding when `entry_count > bloom_capacity * 2`:
```rust
fn maybe_resize_bloom(&mut self) {
    if self.store.entry_count() > self.bloom_capacity * 2 {
        self.bloom_capacity *= 4;
        self.store.rebuild_bloom(self.bloom_capacity);
    }
}
```

---

### V7-F5 [HIGH]: IndexLocation Drops volume_id — Multi-Volume Lookups Broken

**File:** `crates/era-index/src/reader.rs:22-27`
**Status:** UNFIXED from V6-F5.

```rust
pub struct IndexLocation {
    pub block_id: BlockId,
    pub offset: u32,
    pub length: u32,
}
```

**Root Cause:** `IndexEntry` has 5 fields: `hash`, `volume_id`, `block_id`, `offset`, `length`. `IndexLocation` (the lookup result) has only 3: `block_id`, `offset`, `length`. The `volume_id` is silently dropped during the `entry → location` conversion at `reader.rs:371`.

**Proof (V7-F5a/b):**

| Test | Scenario | Result |
|------|----------|--------|
| f5a | Two volumes with same block_id, different offsets | Location has no volume_id — caller cannot resolve which volume to read from |
| f5b | sizeof(IndexEntry) vs sizeof(IndexLocation) | 76 vs 12 bytes — 64 bytes of data lost per lookup (including hash + volume_id) |

**Impact:** In multi-volume deployments, the caller receives `block_id + offset + length` but cannot determine WHICH volume the data is in. This makes the index fundamentally broken for multi-volume use cases.

**Fix:** Add `volume_id: VolumeId` to `IndexLocation`.

---

### V7-F6 [HIGH]: drain_sorted() Loads Entire Index into RAM

**File:** `crates/era-index/src/store.rs:265-285`

**Root Cause:** `drain_sorted()` reads ALL entries from Redb into a `Vec<IndexEntry>`, sorts them, and returns the full vector. For large indices, this is O(N) RAM.

**Proof (V7-F6a/b):**

| Test | Entries | RAM (Vec only) | Time |
|------|---------|-----------------|------|
| f6a | 1,000 | 0.07 MB | ~10ms |
| f6a | 5,000 | 0.37 MB | ~50ms |
| f6a | 20,000 | 1.49 MB | ~500ms |
| Projected | 10,000,000 | 725 MB | — |

At `sizeof(IndexEntry) = 76 bytes`, 10M entries = 725 MB in RAM just for the sorted vector, on top of the Redb file.

**Impact:** `finalize()` calls `drain_sorted()`, meaning every finalization loads the entire index into RAM. This is the primary memory bottleneck and could cause OOM on memory-constrained systems.

**Fix:** Redb stores entries in sorted order (B-tree). Use a streaming iterator over Redb's sorted range instead of materializing the entire vector:
```rust
pub fn drain_sorted_iter(&self) -> Result<impl Iterator<Item = IndexEntry>> { ... }
```

---

### V7-F7 [HIGH]: MetaIndex add_page Has No Ordering Validation

**File:** `crates/era-index/src/lib.rs:212-222`

```rust
pub fn add_page(&mut self, min_hash: ChunkHash, max_hash: ChunkHash, block_id: BlockId) {
    self.pages.push(PagePointer { min_hash, max_hash, block_id });
}
```

**Root Cause:** `add_page()` pushes to the vector without checking that the new page's `min_hash > previous page's max_hash`. `find_page()` uses binary search on `min_hash`, which assumes sorted, non-overlapping pages.

**Proof (V7-F7a/b/c):**

| Test | Scenario | Result |
|------|----------|--------|
| f7a | Pages added in reverse order | `find_page()` returns wrong page (binary search on unsorted data) |
| f7b | Pages added out of order | No error raised; silently accepted |
| f7c | Overlapping page ranges [0-200], [100-300] | No error raised; hash in overlap zone may map to either page |

**Impact:** Corrupt `MetaIndex` with unsorted or overlapping pages → lookups return wrong page → stale/missing data. This is a latent correctness bug waiting for any caller to add pages in wrong order.

**Fix:**
```rust
pub fn add_page(&mut self, min_hash: ChunkHash, max_hash: ChunkHash, block_id: BlockId) -> Result<()> {
    if let Some(last) = self.pages.last() {
        if min_hash <= last.max_hash {
            return Err(IndexError::OverlappingPages);
        }
    }
    self.pages.push(PagePointer { min_hash, max_hash, block_id });
    Ok(())
}
```

---

### V7-F8 [HIGH]: finalize() Double-Iterates All Entries (Bloom Rebuild Waste)

**File:** `crates/era-index/src/lsm_tree.rs:166-204` and `crates/era-index/src/reader.rs:62-89`

**Root Cause:** During `LsmTree::finalize()`:
1. `builder.drain_sorted()` — iterates all Redb entries into Vec (**1st full scan**)
2. `IndexReader::from_memory()` — constructs bloom filter by iterating all entries again (**2nd full scan**)

The builder's existing bloom filter (which already contains all hashes) is discarded when the builder is dropped. The reader creates a brand new bloom from scratch.

**Proof (V7-F8a):**

| Test | Entries | finalize() Time | Notes |
|------|---------|-----------------|-------|
| f8a | 10,000 | ~950ms | Includes bloom rebuild (~40% of time) |

**Impact:** ~40% of finalize time is wasted on rebuilding a bloom that already existed. For large indices, this is significant.

**Fix:** Pass the builder's bloom filter to `from_memory()` instead of rebuilding:
```rust
pub fn from_memory(entries: Vec<IndexEntry>, existing_bloom: Bloom) -> Self { ... }
```

---

### V7-F9 [MEDIUM]: No Post-Construction Page Integrity Verification

**File:** `crates/era-index/src/lib.rs:115-145`

**Root Cause:** `IndexPage` has all `pub` fields (`min_hash`, `max_hash`, `entries`). Anyone can construct an invalid page with:
- `max_hash < min_hash`
- Unsorted entries
- Entries outside the declared `[min_hash, max_hash]` range

`IndexPage::new()` does validate (sort + dedup), but direct struct construction bypasses it.

**Proof (V7-F9a/b):**

| Test | Scenario | Result |
|------|----------|--------|
| f9a | Manual construction with max < min, unsorted entries | No error; `find()` returns undefined results |
| f9b | Entry with hash=500 in page claiming range [100, 200] | Entry permanently invisible — MetaIndex never routes hash=500 to this page |

**Impact:** Deserialized pages from untrusted sources (volume recovery, corrupt storage) could silently contain invalid data.

**Fix:** Make `IndexPage` fields private, provide `IndexPage::new()` as the only constructor, add `validate(&self) -> Result<()>` for post-deserialization checks.

---

### V7-F10 [MEDIUM]: open_readonly Bloom Rebuild is O(N) With No Size Guard

**File:** `crates/era-index/src/store.rs:91-130`

**Root Cause:** `IndexStore::open_readonly()` opens a Redb file and immediately iterates ALL entries to rebuild the bloom filter. For a 10M-entry index, this is a multi-second blocking operation on open.

**Proof (V7-F10a):**

| Test | Entries | open_readonly Time |
|------|---------|-------------------|
| f10a | 10,000 | ~4.2s (debug mode) |
| Projected | 10,000,000 | ~70+ minutes |

**Impact:** Opening a large existing index for read-only queries requires rebuilding the entire bloom, with no streaming/progress, no cancellation, and no pre-built bloom cache.

**Fix:** Persist the serialized bloom filter alongside the Redb file. On `open_readonly()`, deserialize the bloom instead of rebuilding from scratch.

---

### V7-F11 [MEDIUM]: Bloom Says Yes, Redb Says No During Buffer Window

**File:** `crates/era-index/src/builder.rs:82-90`

**Root Cause:** `insert()` calls `store.bloom_set(&entry.hash)` at line 84, adds to buffer at line 85, but only flushes buffer to Redb at `BATCH_SIZE` boundary. During the window between `bloom_set` and flush, the bloom reports "maybe present" but a direct Redb `get()` would return `None`.

**Proof (V7-F11a):**

| Test | Scenario | Bloom | Redb | Consistency |
|------|----------|-------|------|-------------|
| f11a | Insert 100 entries (below BATCH_SIZE=1000) | `contains()` = true | `get()` = None | **Inconsistent** |

**Impact:** Any component that checks bloom + Redb directly (not through the builder's buffer-aware `lookup()`) will see false positives with no corresponding Redb data. This is a design-level state consistency issue.

---

### V7-F12 [MEDIUM]: page_cache Mutex Serializes Cache Misses (UNFIXED V6-F7)

**File:** `crates/era-index/src/reader.rs:38` and `reader.rs:392`
**Status:** UNFIXED from V6-F7.

```rust
page_cache: Mutex<HashMap<BlockId, IndexPage>>,
```

**Root Cause:** `lookup()` acquires `page_cache.lock()` for both cache hits AND cache misses. In filesystem-mode (volume-backed), a cache miss triggers I/O while holding the mutex, serializing all concurrent lookups during I/O.

**Proof (V7-F12a):** In embedded mode (from_memory), `embedded_pages` HashMap is used directly, bypassing `page_cache`. Concurrent lookups achieve zero contention. But in filesystem-mode, contention is O(concurrent_readers × miss_rate).

**Fix:** Replace `Mutex<HashMap>` with `DashMap<BlockId, IndexPage>` or `RwLock<HashMap>` with a separate `Mutex` only for I/O loading.

---

### V7-F13 [LOW]: Domain Separation via Single-Byte XOR

**File:** `crates/era-index/src/builder.rs:finalize()` (nonce context XOR)

```rust
index_nonce_context[0] ^= 0xFF;
```

**Root Cause:** Index block nonces are derived from the same volume nonce context, with only the first byte XOR'd by `0xFF`. This is functional domain separation, but:
1. Single byte XOR is reversible and minimal
2. If nonce_context[0] happens to be 0x00 for volume and 0xFF for index, a second XOR (accidental double-application) would revert to the original — nonce collision

**Proof (V7-F13a/b):**

| Test | Scenario | Result |
|------|----------|--------|
| f13a | XOR always produces different context | ✅ Confirmed |
| f13b | Double XOR reverts to original | ⚠️ Confirmed — `ctx ^ 0xFF ^ 0xFF == ctx` |

**Impact:** LOW. The XOR is applied exactly once in a controlled code path. But defense-in-depth would use a separate HKDF derivation with distinct info string, not a single-byte mutation.

**Fix:** Use HKDF with distinct info labels:
```rust
let index_key = hkdf_expand(prk, b"ERA_INDEX_BLOCK_KEY_v8.1");
let data_key  = hkdf_expand(prk, b"ERA_DATA_BLOCK_KEY_v8.1");
```

---

### V7-F14 [LOW]: Dead Code Still Shipped (UNFIXED V6-F11)

**File:** `crates/era-index/src/config.rs` (~80 lines) and `crates/era-index/src/metrics.rs` (~40 lines)
**Status:** UNFIXED from V6-F11.

Both modules are compiled and exported but never used by any production code path. `LsmTreeConfig` and `IndexMetrics` appear in no call site.

---

## Edge Cases & Boundary Tests (10 tests)

The V7 audit includes 10 edge-case tests that verify correct handling of boundary conditions:

| Test | Scenario | Result |
|------|----------|--------|
| `edge_all_same_hash` | 100 entries with identical hash | ✅ 1 unique entry after Redb dedup |
| `edge_exact_batch_size` | Exactly BATCH_SIZE entries | ✅ Flush triggered correctly |
| `edge_batch_size_plus_one` | BATCH_SIZE + 1 entries | ✅ Two flushes, count correct |
| `edge_exact_entries_per_page` | Exactly ENTRIES_PER_PAGE entries | ✅ Finalize creates 1 page (from_memory bug means always 1) |
| `edge_zero_entry_finalize` | Empty LsmTree finalized | ✅ Returns error, not panic |
| `edge_single_entry_finalize` | One entry finalized | ✅ Works correctly |
| `edge_extreme_hash_values` | Hash values 0 and u64::MAX | ✅ Lookup succeeds for both |
| `edge_sort_order_correctness` | Random insertion order → sorted drain | ✅ drain_sorted returns sorted order |
| `edge_store_destroy_missing_file` | Destroy non-existent store | ✅ Returns Ok, not panic |
| `edge_discard_idempotency` | Discard called; builder dropped | ✅ File removed, no error |

---

## Performance Benchmarks (3 tests)

| Test | Metric | Result |
|------|--------|--------|
| `bench_insert_throughput` | 5000 entries insertion | ~42k entries/sec (debug), ~500k+ (release) |
| `bench_finalize_scaling` | finalize() at 1000 and 5000 entries | Sub-linear scaling: 5× entries → ~3× time |
| `bench_lookup_throughput` | 10000 lookups (mix of hits + misses) | ~500 ns/lookup (debug), ~50ns (release projected) |

---

## Remediation Priority

### Must Fix Before Production (Blockers)

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| **P0** | V7-F1: entry_count overcounting | 1 hour | Data integrity — all callers get wrong count |
| **P0** | V7-F2: from_memory single-page | 2 hours | Performance at scale — O(log N) degrades to O(log 8N) |
| **P0** | V7-F3: Dedup strategy divergence | 1 hour | Correctness — different code paths return different results |
| **P0** | V7-F5: IndexLocation missing volume_id | 30 min | Multi-volume support completely broken |

### Should Fix Before Scale (High Priority)

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| **P1** | V7-F4: Bloom never resized | 2 hours | Performance degrades at scale |
| **P1** | V7-F6: drain_sorted O(N) RAM | 4 hours | OOM risk at 10M+ entries |
| **P1** | V7-F7: MetaIndex no ordering validation | 1 hour | Latent correctness bug |
| **P1** | V7-F8: finalize bloom rebuild waste | 1 hour | ~40% wasted finalize time |

### Nice to Have (Medium/Low)

| Priority | Finding | Effort |
|----------|---------|--------|
| P2 | V7-F9: Page integrity verification | 2 hours |
| P2 | V7-F10: open_readonly bloom rebuild | 3 hours |
| P2 | V7-F11: Bloom/Redb consistency window | 1 hour |
| P2 | V7-F12: page_cache Mutex contention | 2 hours |
| P3 | V7-F13: XOR domain separation | 1 hour |
| P3 | V7-F14: Dead code removal | 30 min |

---

## Verification Commands

```bash
# Run V7 adversarial tests (41/41 must pass)
cargo test -p era-index --test adversarial_audit_v7

# Run ALL era-index tests (298/298 must pass)
cargo test -p era-index

# Confirm V7-F1 bug exists (entry_count overcounting)
cargo test -p era-index --test adversarial_audit_v7 -- f1a

# Confirm V7-F2 bug exists (from_memory single page)
cargo test -p era-index --test adversarial_audit_v7 -- f2c

# Confirm V7-F3 bug exists (dedup divergence)
cargo test -p era-index --test adversarial_audit_v7 -- f3c

# Confirm V7-F7 bug exists (MetaIndex ordering)
cargo test -p era-index --test adversarial_audit_v7 -- f7a
```

---

## Methodology

All V7 tests are **behavioral** — they exercise actual code paths and verify observable outcomes. Zero source scanning (`include_str!`, `grep`, `rg`) is used. This addresses the V5 methodology critique that string-matching tests can be defeated by variable renaming.

Each finding includes:
1. **Exact file:line location** of the defective code
2. **Behavioral test(s)** that demonstrate the bug via actual API calls
3. **Impact analysis** with concrete numbers (overcounting factor, FP rate, RAM usage)
4. **Minimal fix** with code sample

The `meta_page_count()` accessor was added to `reader.rs:380` to enable V7-F2 testing without source scanning. This is the only production code modification made by V7.

---

## Conclusion

The competitor's post-V6 codebase has **regressed** on CC3 (entry_count), **ignored** three V6 CRITICAL/HIGH findings, and contains 10 novel vulnerabilities. The entry_count regression is particularly concerning because it was explicitly flagged in CLAUDE.md as a P1, "fixed", verified by V6 as "✅ FIXED", and is now demonstrated to be broken in the opposite direction.

The codebase works correctly for simple use cases (single-volume, small indices, no duplicates). It breaks under:
- Duplicate insertions (V7-F1, V7-F3)
- Large indices (V7-F2, V7-F4, V7-F6, V7-F10)
- Multi-volume deployments (V7-F5)
- Adversarial/corrupt input (V7-F7, V7-F9)

**Recommended next step:** Fix V7-F1 (entry_count regression) immediately — it is the most impactful single-line fix (change `buffer.len()` to count only truly new entries).

---

**Document Version:** 7.0
**Last Updated:** 2026-02-24
**Test File:** `crates/era-index/tests/adversarial_audit_v7.rs` (41 tests, 1468 lines)
**Production Modification:** Added `meta_page_count()` accessor to `crates/era-index/src/reader.rs:380`
