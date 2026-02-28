# ERA Index — Adversarial Audit V15 Report

**Date**: 2026-02-26
**Auditor**: Competitive Adversarial Analysis (V15)
**Target**: `crates/era-index/` (post-V14 remediation)
**Scope**: Performance, security, logic correctness, code hygiene
**Previous Score**: 90/100 (V14)

## Executive Summary

V14 remediation was successful: all 12 findings addressed, `quick_cache` dependency removed, `page_cache` dead allocation eliminated. The codebase is significantly cleaner. V15 focuses on cold recovery robustness, edge-case memory safety, and remaining documentation inconsistencies.

**V15 Score: 92/100** (+2 from V14)

## Findings

### V15-F1 [P2 — Medium] `unwrap_or_default()` swallows I/O errors in cold recovery

**File**: `reader.rs` line 273
**Code**:
```rust
let page_blocks_for_hint = volume_reader
    .scan_for_typed_blocks(BlockType::IndexPage)
    .await
    .unwrap_or_default();
```

**Impact**: If `scan_for_typed_blocks` fails due to I/O error, the error is silently swallowed and `page_count_hint` becomes 0. This doesn't break recovery (the fallback candidate expansion covers it) but masks real I/O failures that could indicate volume corruption. An attacker could exploit this to make recovery silently degrade to brute-force without any log entry.

**Recommendation**: Replace with explicit error handling that logs the failure:
```rust
let page_blocks_for_hint = match volume_reader
    .scan_for_typed_blocks(BlockType::IndexPage)
    .await
{
    Ok(blocks) => blocks,
    Err(e) => {
        tracing::warn!("Failed to scan for IndexPage hint blocks: {}", e);
        Vec::new()
    }
};
```

---

### V15-F2 [P2 — Medium] `recover_from_volume` lacks upper bound on candidates vec

**File**: `reader.rs` lines 278-310
**Code**:
```rust
let volume_block_count = volume_reader.block_count() as u64;
let upper_bound = if volume_block_count > 0 {
    volume_block_count + 1
} else {
    (page_count_hint + 1).saturating_mul(4).max(1024)
};
for id in 0..upper_bound {
    if seen.insert(id) {
        candidates.push(id);
    }
}
```

**Impact**: A malicious volume reporting `block_count()` as `u64::MAX / 2` would cause OOM from the candidates vec. The `Vec::with_capacity(512)` on line 279 mitigates initial allocation but the loop can push billions of entries.

**Recommendation**: Cap `upper_bound` at a reasonable maximum (e.g., 100,000):
```rust
const MAX_RECOVERY_CANDIDATES: u64 = 100_000;
let upper_bound = upper_bound.min(MAX_RECOVERY_CANDIDATES);
```

---

### V15-F3 [P3 — Low] Stale doc comment on `load_page()`

**File**: `reader.rs` line 529
**Code**: `/// Load an L2 page (with caching)`

**Impact**: Documentation says "with caching" but the page cache was removed in V14-F12. This misleads future maintainers.

**Recommendation**: Update to `/// Load an L2 page from embedded pages`.

---

### V15-F4 [P2 — Medium] Bloom phantom entries on buffer flush failure

**File**: `builder.rs` lines 84-89
**Code**:
```rust
let hash = entry.hash;
self.buffer.push(entry);
self.store.bloom_set(&hash);
if self.buffer.len() >= BATCH_SIZE {
    self.flush_buffer()?;
}
```

**Impact**: `bloom_set` is called eagerly before `flush_buffer`. If `flush_buffer` fails (Redb I/O error), the bloom filter contains hashes for entries that never reached Redb. Unlike `store.insert()` where bloom is set AFTER commit (V13-F4 fix), the builder path sets bloom BEFORE flush. This is by design (V6-F9: bloom must reflect buffer contents for dedup checks) but creates an asymmetry that could confuse future auditors.

**Note**: This is an intentional design trade-off documented in V6-F9. The bloom's job here is early dedup detection during the write pipeline, where false positives (phantom entries) only cause harmless redundant storage. However, the code lacks a comment explaining why this is different from the store's post-commit bloom pattern.

**Recommendation**: Add a clarifying comment:
```rust
// NOTE: bloom_set is called BEFORE flush_buffer (unlike store.insert which
// sets bloom AFTER commit). This is intentional — the builder's bloom must
// reflect buffered entries for early dedup detection (V6-F9). Phantom entries
// on flush failure are harmless: they only cause redundant storage lookups.
```

---

### V15-F5 [P3 — Low] Missing `#[must_use]` on key Result-returning methods

**File**: `reader.rs` lines 78, 95, 134, 170, 485
**Methods**: `open()`, `from_memory()`, `from_pages()`, `recover_from_volume()`, `lookup()`

**Impact**: Callers could discard the `Result` without handling errors. While Rust's unused-Result lint catches some cases, `#[must_use]` on the method level provides explicit intent.

**Recommendation**: Add `#[must_use]` to `lookup()` at minimum (the constructors already return Self which is typically used).

---

### V15-F6 [P2 — Medium] `VolumeId::new()` creates random UUID in cold recovery fast path

**File**: `reader.rs` line 191
**Code**:
```rust
let location = BlockLocation::single(
    era_common::VolumeId::new(),  // ← random UUID, not the actual volume's ID
    footer.index_block_id,
    footer.index_offset,
    footer.index_size,
);
```

**Impact**: `VolumeId::new()` generates a fresh random UUID. The constructed `BlockLocation` has a bogus `volume_id`. If `read_typed_block` or any downstream code uses the volume_id from this location, it won't match the actual volume. Currently `read_typed_block` likely ignores the volume_id (single-volume read), but this is a latent bug for multi-volume scenarios.

**Recommendation**: Use the volume reader's actual volume ID if available, or create a sentinel `VolumeId` for "current volume":
```rust
// If VolumeReader exposes its VolumeId:
let location = BlockLocation::single(
    volume_reader.volume_id(),
    footer.index_block_id,
    footer.index_offset,
    footer.index_size,
);
```

---

### V15-F7 [P3 — Low] Missing `#[must_use]` on `IndexStore::path()` and other accessors

**File**: `store.rs` line 481
**Methods**: `path()`, `get()`, `read_sorted()`, `read_sorted_pages()`

**Impact**: Pure accessor methods returning references or values that should always be consumed.

**Recommendation**: Add `#[must_use]` to all pure accessor methods.

---

### V15-F8 [P3 — Low] `rebuild_bloom_if_needed` TOCTOU between count check and iteration

**File**: `store.rs` lines 327-353

**Impact**: In theory, between `self.entry_count` check and the Redb iteration, another thread could modify the table. However, `IndexStore` takes `&mut self` for all write operations, so concurrent writes are prevented by the borrow checker. This is NOT a real bug — the single-writer guarantee makes this safe.

**Status**: Non-issue. The borrow checker prevents concurrent modification.

---

### V15-F9 [P3 — Low] `ChunkIndexConfig::temp_dir` field is unused

**File**: `chunk_index.rs` lines 30-31
**Code**:
```rust
pub struct ChunkIndexConfig {
    pub mem_limit: usize,
    pub temp_dir: PathBuf,  // ← never read
}
```

**Impact**: `ChunkIndex::new()` calls `IndexBuilder::new(config.mem_limit)` which creates its own temp file via `tempfile::Builder`. The `temp_dir` field is never used, wasting memory and misleading callers who think they can control temp file location.

**Recommendation**: Either remove the field (backward compat not required) or pass it through to `IndexBuilder`.

---

### V15-F10 [P3 — Low] `block_id as u64` cast in `from_memory()`

**File**: `reader.rs` line 113
**Code**: `let bid = BlockId::new(block_id as u64);`

**Impact**: `enumerate()` returns `usize`. On 64-bit targets, `usize as u64` is lossless. On 32-bit targets it's a zero-extending widening cast (also safe). This is a non-issue on current supported targets.

**Status**: Non-issue on all targets (usize → u64 is always safe).

---

### V15-F11 [P3 — Low] Duplicate documentation line in store.rs

**File**: `store.rs` lines 3-5
**Code**:
```rust
//! Wraps a Redb 2.1 database for ACID-compliant chunk indexing during
//! archive creation. Uses a single embedded Redb B-tree database.
//! Uses a single embedded Redb B-tree database.
```

**Impact**: "Uses a single embedded Redb B-tree database." appears twice. This is residual from V14-F5 fix that removed a different duplicate but missed this one.

**Recommendation**: Remove the duplicate line.

---

### V15-F12 [P2 — Medium] No timeout on `scan_for_typed_blocks` calls in cold recovery

**File**: `reader.rs` lines 254-256, 270-273, 375-377

**Impact**: Three `scan_for_typed_blocks` calls lack deadline checks:
1. Line 254: Scan for IndexManifest blocks
2. Line 270: Scan for IndexPage blocks (hint)
3. Line 375: Scan for IndexPage blocks (main)

Each scan involves reading all blocks in the volume. A malicious volume with millions of blocks could make these scans run indefinitely, even though the timeout is checked in the candidate loop and page recovery loop.

**Recommendation**: Check deadline before each scan:
```rust
if let Some(dl) = deadline {
    if Instant::now() >= dl {
        return Err(EraError::IndexError("Cold recovery timed out".into()));
    }
}
```

---

## Summary Table

| Finding | Severity | Category | Status |
|---------|----------|----------|--------|
| V15-F1 | P2 | Error Handling | OPEN |
| V15-F2 | P2 | Memory Safety | OPEN |
| V15-F3 | P3 | Documentation | OPEN |
| V15-F4 | P2 | Documentation | OPEN (clarify, not fix) |
| V15-F5 | P3 | Code Hygiene | OPEN |
| V15-F6 | P2 | Logic | OPEN |
| V15-F7 | P3 | Code Hygiene | OPEN |
| V15-F8 | P3 | Concurrency | NON-ISSUE |
| V15-F9 | P3 | Dead Code | OPEN |
| V15-F10 | P3 | Portability | NON-ISSUE |
| V15-F11 | P3 | Documentation | OPEN |
| V15-F12 | P2 | Robustness | OPEN |

## Scoring

| Category | Score | Notes |
|----------|-------|-------|
| Correctness | 24/25 | VolumeId::new() in recovery (V15-F6) |
| Security | 24/25 | Candidate vec unbounded (V15-F2) |
| Robustness | 21/25 | Error swallowing (V15-F1), no scan timeouts (V15-F12) |
| Code Quality | 23/25 | Stale docs (V15-F3, F11), unused config field (V15-F9) |
| **Total** | **92/100** | |

## V14 Regression Check

All V14 findings verified as fixed:
- ✅ V14-F1: Multi-byte domain separation (IDX\x01) in builder.rs and reader.rs
- ✅ V14-F3: `bloom_set` is `pub(crate)`
- ✅ V14-F4: test_hash uses BE-tail consistently
- ✅ V14-F5: Duplicate doc removed
- ✅ V14-F7: entry_count incremented after commit
- ✅ V14-F8: chunk_count documented
- ✅ V14-F9: Materialization documented
- ✅ V14-F10: Performance warning on insert()
- ✅ V14-F11: `#[must_use]` on key methods
- ✅ V14-F12: page_cache + quick_cache fully removed
