# Adversarial Audit V16 — ERA Index Module

**Audit Date:** 2026-02-26
**Target:** `era-index` crate (7 source files, ~2,600 lines)
**Methodology:** Competitive adversarial audit — analyzing from the perspective of a competitor trying to expose performance, security, logic, and robustness issues.
**Previous Score:** V15 = 92/100

---

## V15 Regression Status (All FIXED)

| ID | Finding | Status |
|----|---------|--------|
| V15-F1 | unwrap_or_default → explicit match + tracing::warn | ✅ FIXED |
| V15-F2 | MAX_RECOVERY_CANDIDATES cap on candidates | ✅ FIXED |
| V15-F3 | Doc comment updated on load_page() | ✅ FIXED |
| V15-F4 | Clarifying comment on bloom_set in builder | ✅ FIXED |
| V15-F5 | No #[must_use] on Result-returning methods | ✅ FIXED |
| V15-F6 | Comment explaining VolumeId::new() placeholder | ✅ FIXED |
| V15-F7 | #[must_use] on path() only | ✅ FIXED |
| V15-F9 | temp_dir removed from ChunkIndexConfig | ✅ FIXED |
| V15-F11 | Duplicate doc line removed | ✅ FIXED |
| V15-F12 | Deadline checks before critical scan calls | ✅ FIXED |

---

## V16 Findings

| ID | Severity | Category | Title |
|----|----------|----------|-------|
| V16-F1 | High | Performance | `rebuild_bloom_if_needed` uses 1.5× growth factor — too aggressive rebuild frequency |
| V16-F2 | Medium | Logic | `from_memory()` shadow-rebinds `meta` without `let mut` pattern clarity |
| V16-F3 | Medium | Security | `validate_rkyv_size` lower bound is too low — allows near-empty payloads |
| V16-F4 | Medium | Performance | `for_each_sorted_page` re-allocates `Vec::with_capacity` per page but doesn't reuse |
| V16-F5 | Low | Robustness | `IndexPage::try_new` uses `unwrap()` on `entries.first()` / `entries.last()` after empty check — safe but unclear |
| V16-F6 | Medium | Logic | `open_readonly` bloom rebuild scans all entries but doesn't use `deserialize_entry_with_buf` — inconsistent deserialization |
| V16-F7 | Low | Documentation | `contains_range` doc comment says "not used by production" but no `#[cfg(test)]` guard |
| V16-F8 | Medium | Performance | Cold recovery candidate loop allocates `HashSet` + `Vec` even when footer fast path succeeds |
| V16-F9 | Low | Robustness | `MetaIndex::new()` creates an empty `bloom_filter: Vec::new()` — deserialize_bloom on empty vec produces unclear error |
| V16-F10 | Medium | Security | `bloom_expected_items` clamp lower bound of 1024 could allocate oversized bloom for very small archives |
| V16-F11 | Low | Code Quality | `IndexBuilder::entry_count` takes `&mut self` but `flush_buffer` could be split to avoid forcing mutable borrow |
| V16-F12 | Medium | Logic | Recovery completeness check counts `embedded_pages.len() < meta.pages().len()` but HashMap deduplicates by BlockId — if two pages share a BlockId, one is silently lost |

---

## Detailed Analysis

### V16-F1: rebuild_bloom_if_needed growth factor [HIGH — Performance]

**Location:** `store.rs:327`

The bloom filter rebuild triggers at `entry_count > bloom_sized_for * 3 / 2` (1.5×) and resizes to `entry_count * 4`. The 1.5× trigger is too aggressive — it causes frequent full-table scans. A 2× or 3× trigger would be more appropriate. Additionally, the 4× growth factor means after the first rebuild, the next one won't trigger until 6× entries (4× × 1.5), creating a jagged rebuild pattern.

**Fix:** Change growth threshold to `2×` and resize to `entry_count * 2` for predictable amortized cost.

### V16-F2: from_memory meta shadow rebinding [MEDIUM — Logic]

**Location:** `reader.rs:107`

```rust
let mut meta = meta;  // shadow rebind
meta.clear_pages();
```

While functional, this `let mut meta = meta` shadow-rebinding is a code smell that obscures mutation intent. The parameter should be `mut meta: MetaIndex` directly.

**Fix:** Change function signature to take `mut meta: MetaIndex`.

### V16-F3: validate_rkyv_size minimum too low [MEDIUM — Security]

**Location:** `reader.rs:41,49`

`MIN_INDEX_PAGE_SIZE = 40` and `MIN_META_INDEX_SIZE = 40` are too small. A valid rkyv-archived `IndexPage` with 1 entry has overhead + 1 × sizeof(ArchivedIndexEntry). The minimum should account for rkyv's 8-byte alignment header + at least the Vec header (12 bytes on 32-bit, 24 bytes on 64-bit) + archived ChunkHash fields. 40 bytes could allow through malformed partial data that passes the size check but fails validation, wasting CPU on `check_archived_root`.

**Fix:** Increase `MIN_INDEX_PAGE_SIZE` to 64 and `MIN_META_INDEX_SIZE` to 48 based on actual rkyv overhead analysis.

### V16-F4: for_each_sorted_page chunk Vec re-allocation [MEDIUM — Performance]

**Location:** `store.rs:442`

```rust
let mut chunk = Vec::with_capacity(entries_per_page);
```

When the chunk hits capacity and is consumed by `IndexPage::try_new(std::mem::take(&mut chunk))`, the replacement Vec (from `take`) has capacity 0. The next page's entries go through multiple re-allocations until hitting `entries_per_page` again. Since we know every page except the last will be exactly `entries_per_page` entries, we should re-allocate with capacity after take.

**Fix:** After `std::mem::take(&mut chunk)`, immediately set `chunk = Vec::with_capacity(entries_per_page)`.

### V16-F5: IndexPage::try_new unwrap after empty check [LOW — Robustness]

**Location:** `lib.rs:143-144`

```rust
let min_hash = entries.first().unwrap().hash;
let max_hash = entries.last().unwrap().hash;
```

These `unwrap()` calls are safe because the `entries.is_empty()` check above returns early. However, per project conventions ("no unwrap() in runtime"), these should use an explicit pattern even though they're guaranteed safe.

**Fix:** Replace with `expect()` calls that document the invariant: `.expect("guaranteed non-empty after is_empty check")`.

### V16-F6: open_readonly inconsistent deserialization [MEDIUM — Logic]

**Location:** `store.rs:138-146`

The `open_readonly` bloom rebuild loop only reads keys (hashes), not values, which is correct. However, it constructs `ChunkHash::from_bytes(*key.value())` directly without any validation. This is fine for hash keys but inconsistent with the defensive deserialization approach used elsewhere (rkyv validation). Not a bug, but the inconsistency could mask issues if the key format ever changes.

**Fix:** Add a comment explaining that key-only iteration is intentional and doesn't need entry deserialization.

### V16-F7: contains_range no cfg(test) guard [LOW — Documentation]

**Location:** `lib.rs:191-198`

The doc comment says `contains_range` is "not used by the production lookup path" and is "retained for test coverage." If it's truly test-only, it should have a `#[cfg(test)]` guard or be `pub(crate)`. Currently it's `pub`, meaning external consumers could depend on it.

**Fix:** Keep `pub` but update the doc comment to note it's available as a utility method, not just for tests.

### V16-F8: Cold recovery allocations on fast path [MEDIUM — Performance]

**Location:** `reader.rs:250-389`

The `candidates` Vec and `seen` HashSet in the slow path are only allocated inside the `else` branch (lines 293-328), which is correct — they're not allocated on the fast path. **No issue.** (Verified on re-read.)

**Reclassified:** Non-issue. The cold recovery code properly gates allocations in the else branch.

### V16-F9: MetaIndex::new() empty bloom [LOW — Robustness]

**Location:** `lib.rs:225-230`

`MetaIndex::new()` creates `bloom_filter: Vec::new()`. If `deserialize_bloom` is called on this empty vec, rkyv will return a deserialization error. The error message from rkyv will be cryptic. This isn't a bug (callers always set bloom_filter before use), but the empty default is a footgun.

**Fix:** Add a doc comment on `bloom_filter` field noting it must be set via `set_bloom_filter()` before use.

### V16-F10: bloom_expected_items lower clamp [MEDIUM — Security]

**Location:** `builder.rs:25`

`bloom_expected_items` clamps to minimum 1024 items. With 1% FPR, a 1024-item bloom filter allocates ~1.2KB. For an archive with only 1-10 chunks, this wastes memory proportionally. While 1.2KB is negligible absolutely, the principle of right-sizing is violated.

**Fix:** Reduce minimum clamp to 128 for small archives while maintaining the 1% FPR guarantee.

### V16-F11: entry_count requires &mut self [LOW — Code Quality]

**Location:** `builder.rs:111`

`entry_count(&mut self)` needs `&mut self` because it calls `flush_buffer()`. This is correct behavior (you need an accurate count), but it prevents calling `entry_count()` while holding an immutable reference to the builder.

**Fix:** Non-issue after analysis — the `&mut self` is intentional for accuracy. Add a doc comment clarifying why.

### V16-F12: Recovery HashMap dedup by BlockId [MEDIUM — Logic]

**Location:** `reader.rs:465`

```rust
embedded_pages.insert(page_ptr.block_id, Arc::new(page));
```

If the MetaIndex somehow contains two page pointers with the same `block_id` (which shouldn't happen in well-formed data), the second insert would silently overwrite the first. The completeness check at line 484 compares `embedded_pages.len() < meta.pages().len()` — this would correctly fail because the HashMap has fewer entries than expected. So this is technically self-detecting, but the error message is misleading ("Incomplete recovery") when the real issue is duplicate block_ids.

**Fix:** Add a debug assertion or tracing::warn when a block_id collision is detected during recovery.

---

## Score

**V16 Score: 93/100**

Improvements over V15:
- All V15 findings verified fixed
- Code quality continues to improve
- No new high-severity security issues

Remaining concerns:
- Bloom rebuild frequency (-3)
- Minor robustness gaps in error messaging (-2)
- Small performance inefficiency in page streaming (-2)

---

## Recommendations for V17

1. Consider adding a `#[cfg(debug_assertions)]` invariant check in `MetaIndex::add_page` that block_ids are unique
2. The `for_each_sorted_page` pattern could benefit from a reusable page buffer pool
3. Consider exposing bloom filter statistics (FPR, bit utilization) for operational diagnostics
