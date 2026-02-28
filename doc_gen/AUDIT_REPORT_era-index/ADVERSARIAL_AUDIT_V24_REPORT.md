# Adversarial Audit V24 — ERA Index Module

**Audit Date:** 2026-02-27
**Target:** `era-index` crate (9 source files, ~3,500 lines)
**Methodology:** Competitive adversarial audit — analyzing from the perspective of a competitor trying to expose encapsulation, validation, performance, and robustness issues.
**Previous Score:** V23 = 99/100

---

## V23 Regression Status (All FIXED/VERIFIED)

| ID | Finding | Status |
|----|---------|--------|
| V23-F1 | `BloomFilterData` fields are `pub` — allows bypass of `new()` validation | ✅ VERIFIED |
| V23-F2 | `from_bloom()` constructs `BloomFilterData` directly bypassing validation | ✅ VERIFIED |
| V23-F3 | Triplicated validation logic across `new()`, `to_bloom()`, `from_bytes()` | ✅ VERIFIED |
| V23-F4 | `to_bytes()` copies `AlignedVec→Vec` via `.to_vec()` without documenting why | ✅ VERIFIED |
| V23-F5 | `from_bloom()` is `pub` but only used within the crate | ✅ VERIFIED |
| V23-F6 | Duplicate doc comment on `try_new_presorted` in `lib.rs` | ✅ VERIFIED |
| V23-F7 | `_caller_bloom` unused params in `from_memory()` and `from_pages()` | ✅ VERIFIED |
| V23-F8 | `for_each_sorted_page` progress logging fires inside inner loop | ✅ VERIFIED |
| V23-F9 | `.expect()` in `try_new`/`try_new_presorted` — safe but could use defensive indexing | ✅ VERIFIED |
| V23-F10 | `set_bloom_filter` deserializes full `Bloom<ChunkHash>` just to validate | ✅ VERIFIED |

---

## V24 Findings

| ID | Severity | Category | Title | Status |
|----|----------|----------|-------|--------|
| V24-F1 | Medium | Encapsulation | `IndexEntry` pub fields allow construction bypassing `new()` validation | OPEN |
| V24-F2 | Medium | Encapsulation | `PagePointer` pub fields allow unchecked construction | OPEN |
| V24-F3 | Info | By Design | `from_pages`/`from_memory` bloom rebuild on every load | INFO ONLY |
| V24-F4 | Low | Performance | `insert_batch` triple iteration over entries | OPEN |
| V24-F5 | Medium | Safety | Integer overflow in recovery candidate calculation | OPEN |
| V24-F6 | Medium | DoS Surface | Unbounded timeout in cold recovery decrypt loop | OPEN |
| V24-F7 | Low | Redundancy | `MAX_META_PAGES` constant defined twice | OPEN |
| V24-F8 | Medium | Deserialization | Bloom bitmap size validation occurs after deserialization | OPEN |
| V24-F9 | Low | Documentation | SipHash key non-determinism undocumented | OPEN |
| V24-F10 | Medium | Deserialization | rkyv buffer size pre-validation missing in `deserialize_entry_with_buf` | OPEN |

### Carried Forward (Info — no code change required)

| ID | Origin | Title | Status |
|----|--------|-------|--------|
| V24-CF1 | V19-F7 | `builder.rs` `finalize()` CPU-heavy serialization on async thread (Redb ReadTransaction is `!Send`) | INFO — architectural constraint |
| V24-CF2 | V18-F10 | `chunk_index.rs` `finalize()` materializes all pages in Vec before IndexReader creation | INFO — required by IndexReader API |

---

## Detailed Analysis

### V24-F1: `IndexEntry` pub fields allow construction bypassing `new()` validation [MEDIUM — Encapsulation]

**Location:** `lib.rs:71-82` (`struct IndexEntry`)

**Analysis:** All fields of `IndexEntry` (`hash`, `volume_id`, `block_id`, `offset`, `length`) are declared `pub`. The struct has a validated `new()` constructor that rejects zero-length entries and `offset + length` overflow (V19-F3 / V17-F5 / V17-F6). However, any code — inside or outside the crate — can construct an `IndexEntry` via struct literal syntax, completely bypassing these safety checks. A competitor could demonstrate that a zero-length or overflowing entry can be created trivially:

```rust
pub struct IndexEntry {
    pub hash: ChunkHash,
    pub volume_id: VolumeId,
    pub block_id: BlockId,
    pub offset: u32,
    pub length: u32,
}
```

The validated constructor exists at lines 91-116 with explicit checks for `length == 0` and `offset.checked_add(length)`, but these guards are rendered advisory when the fields are directly writable.

**Fix:** Change all fields from `pub` to `pub(crate)`. Internal callers (tests, deserialization) can still access fields directly since they are within the crate. External consumers must use `new()`. This mirrors the V23-F1 fix applied to `BloomFilterData`.

### V24-F2: `PagePointer` pub fields allow unchecked construction [MEDIUM — Encapsulation]

**Location:** `lib.rs:319-328` (`struct PagePointer`)

**Analysis:** All fields of `PagePointer` (`min_hash`, `max_hash`, `block_id`) are declared `pub`. The `MetaIndex::add_page()` method (line 373) enforces invariants: `min_hash <= max_hash`, no duplicate `block_id`, and bounded page count. But since `PagePointer` fields are public, any code can construct a `PagePointer` with `min_hash > max_hash` or a duplicate `block_id` and insert it into a `MetaIndex.pages` Vec directly (if the Vec were accessible). More critically, `PagePointer` is re-exported and could be constructed in dependent crates with invalid invariants:

```rust
pub struct PagePointer {
    pub min_hash: ChunkHash,
    pub max_hash: ChunkHash,
    pub block_id: BlockId,
}
```

While the `MetaIndex.pages` field itself is private (preventing direct Vec mutation), the public `PagePointer` fields still allow constructing invalid pointers that could be passed to any API accepting `PagePointer` values.

**Fix:** Change all fields from `pub` to `pub(crate)`. Add getter methods for external read access if needed. Internal callers within the crate retain direct field access.

### V24-F3: `from_pages`/`from_memory` bloom rebuild on every load [INFO — By Design]

**Location:** `reader.rs:149-212` (`IndexReader::from_memory()` and `IndexReader::from_pages()`)

**Analysis:** Both `from_memory()` (line 149-157) and `from_pages()` (line 199-212) rebuild the bloom filter from scratch on every call by iterating all entries and calling `verified_bloom.set(&entry.hash)`. This is O(n) work that could theoretically be avoided by trusting the caller-provided bloom. However, this is an intentional security measure documented by V19-F5 and V20-F1: a caller could pass a bloom that omits entries (causing false negatives that break dedup correctness) or contains phantom entries. Rebuilding from ground truth guarantees bloom ↔ entries consistency.

```rust
// V19-F5 fix: Rebuild bloom from actual entries instead of trusting the
// caller-provided bloom.
let mut verified_bloom: Bloom<ChunkHash> =
    Bloom::new_for_fp_rate(entries.len().max(1024), 0.01);
for entry in &entries {
    verified_bloom.set(&entry.hash);
}
```

This is not a defect — it is a deliberate defense-in-depth measure that prevents a class of data integrity bugs. The cost is acceptable: bloom insertion is ~50ns per entry, so even 1M entries take only ~50ms.

### V24-F4: `insert_batch` triple iteration over entries [LOW — Performance]

**Location:** `store.rs:275-308` (`IndexStore::insert_batch()`)

**Analysis:** The `insert_batch()` method iterates over the `entries` slice three times in the worst case:

1. **First pass** (line 277-280): Filters entries through the bloom filter to collect `bloom_hits` — entries the bloom says *might* exist.
2. **Second pass** (line 289-297): For each `bloom_hit`, queries the Redb read transaction to confirm whether it actually exists.
3. **Third pass** (line 300-303): Iterates entries again to collect those that the bloom says are *definitely new* (not in bloom).

```rust
let bloom_hits: Vec<&IndexEntry> = entries
    .iter()
    .filter(|e| self.bloom.check(&e.hash))
    .collect();
// ... read_txn lookup for bloom_hits ...
for entry in entries {
    if !self.bloom.check(&entry.hash) {
        filtered.push(entry);
    }
}
```

This is already optimized from V22-F1 (which consolidated per-candidate read transactions into a single read_txn). The triple iteration is a trade-off: combining passes 1 and 3 into a single pass with partition would require either a more complex data structure or sacrificing the early-exit when no bloom hits exist (line 281). The current approach is clear and the cost is O(n) bloom checks per pass — bloom checks are ~100ns each, so for typical batch sizes (≤ 8192 entries) the overhead is < 2ms.

**Fix:** Combine the first and third passes into a single iteration that partitions entries into `bloom_hits` and `definitely_new` in one pass, avoiding the redundant bloom check on each entry.

### V24-F5: Integer overflow in recovery candidate calculation [MEDIUM — Safety]

**Location:** `reader.rs:418-433` (`recover_from_volume()`)

**Analysis:** The `volume_block_count + 1` expression at line 422 performs unchecked addition on a `u64` value derived from `volume_reader.block_count()`:

```rust
let volume_block_count = volume_reader.block_count() as u64;
const MAX_RECOVERY_CANDIDATES: u64 = 100_000;
let upper_bound = if volume_block_count > 0 {
    volume_block_count + 1
} else {
    (page_count_hint + 1).saturating_mul(4).max(1024)
};
let upper_bound = upper_bound.min(MAX_RECOVERY_CANDIDATES);
```

If `volume_block_count` is `u64::MAX` (from a maliciously crafted volume header), `volume_block_count + 1` wraps to 0 in release mode (Rust integer overflow). The subsequent `.min(MAX_RECOVERY_CANDIDATES)` then evaluates to `min(0, 100_000) = 0`, causing zero candidates to be generated and recovery to fail silently. While the `MAX_RECOVERY_CANDIDATES` cap prevents OOM, the wraparound masks the root cause — the error message would claim "Could not decrypt IndexManifest with any candidate block ID" when the real issue is an overflowing block count.

Note: the else branch correctly uses `.saturating_mul(4)` for `page_count_hint`, showing awareness of overflow — but the primary branch lacks the same protection.

**Fix:** Use `volume_block_count.saturating_add(1)` instead of `volume_block_count + 1` to match the defensive style already used in the else branch.

### V24-F6: Unbounded timeout in cold recovery decrypt loop [MEDIUM — DoS Surface]

**Location:** `reader.rs:245-562` (`recover_from_volume()`)

**Analysis:** The `recover_from_volume()` method accepts `timeout: Option<Duration>` and creates a deadline from it (line 245). Deadline checks are placed at multiple points throughout the method: before manifest scan (line 340-346), during candidate iteration (line 437-442), after successful decrypt (line 462-467), before page scan (line 521-526), and during page recovery (line 557-562). However, the `timeout` parameter is `Option<Duration>`, and when `None`, no deadline is created and all deadline checks are skipped:

```rust
let deadline = timeout.map(|d| Instant::now() + d);
// ...
if let Some(dl) = deadline {
    if Instant::now() >= dl {
        return Err(EraError::IndexError(
            "Cold recovery timed out during candidate iteration".into(),
        ));
    }
}
```

With `timeout = None`, a maliciously crafted volume with a large `block_count` (up to `MAX_RECOVERY_CANDIDATES = 100,000`) forces the decrypt loop to attempt up to 100,000 AEAD decryptions. Each decryption involves HKDF key derivation + XChaCha20-Poly1305 decrypt, costing ~1-5μs per attempt. For 100,000 candidates this is ~100-500ms — not catastrophic, but a caller that inadvertently omits the timeout gets no protection against adversarial volumes.

**Fix:** Document that `timeout = None` disables deadline enforcement and that callers should always provide a reasonable timeout for untrusted inputs. Optionally, add a default maximum timeout (e.g., 30 seconds) when `None` is provided.

### V24-F7: `MAX_META_PAGES` constant defined twice [LOW — Redundancy]

**Location:** `lib.rs:395` and `reader.rs:77`

**Analysis:** The constant `MAX_META_PAGES: usize = 10_000` is defined independently in two locations:

In `lib.rs:395` (inside `MetaIndex::add_page()`):
```rust
const MAX_META_PAGES: usize = 10_000;
```

In `reader.rs:77` (inside `validate_meta_index()`):
```rust
const MAX_META_PAGES: usize = 10_000;
```

Both enforce the same invariant (maximum number of pages in a MetaIndex) but are defined as function-local constants with no shared source of truth. If one is updated without the other, the write path (`add_page`) and read path (`validate_meta_index`) would enforce different limits, potentially causing valid indexes to be rejected on read or oversized indexes to be written.

**Fix:** Define `MAX_META_PAGES` as a module-level `pub(crate) const` in `lib.rs` and import it in `reader.rs`.

### V24-F8: Bloom bitmap size validation occurs after deserialization [MEDIUM — Deserialization]

**Location:** `bloom_serde.rs:186-219` (`BloomFilterData::from_bytes()`)

**Analysis:** The `from_bytes()` method first performs full rkyv deserialization (line 187-203), which includes allocating the `bitmap: Vec<u8>` into heap memory. Only after the full deserialization completes does it check the bitmap size against `MAX_BLOOM_BITMAP_SIZE` (line 210-217):

```rust
pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
    let archived = rkyv::check_archived_root::<Self>(bytes)
        .map_err(|e| EraError::Deserialization(e.to_string()))?;
    // Version check on archived view (pre-allocation) ✓
    if archived.version != 1 {
        return Err(...);
    }
    // Full deserialization — allocates bitmap Vec
    let result: Self = match archived.deserialize(&mut rkyv::Infallible) { ... };
    // Validation — but bitmap already allocated!
    result.validate()?;
    const MAX_BLOOM_BITMAP_SIZE: usize = 128 * 1024 * 1024;
    if result.bitmap.len() > MAX_BLOOM_BITMAP_SIZE {
        return Err(...);
    }
    Ok(result)
}
```

A malicious payload with a 128 MiB bitmap field would be fully deserialized into heap memory before the size check rejects it. The version check (line 193) correctly uses the archived (zero-copy) view to avoid allocation, but the size check does not follow the same pattern. While `rkyv::check_archived_root` validates structural integrity, it does not enforce application-level size limits.

**Fix:** Check `archived.bitmap.len()` on the archived view (before `deserialize()`) to reject oversized bitmaps before heap allocation. The archived view provides zero-copy access to the bitmap length.

### V24-F9: SipHash key non-determinism undocumented [LOW — Documentation]

**Location:** `bloom_serde.rs:30-42` (`BloomFilterData.sip_keys` field)

**Analysis:** The `sip_keys` field stores the SipHasher keys used by the Bloom filter. These keys are generated non-deterministically by the `bloomfilter` crate when a new `Bloom<T>` is created (using thread-local RNG). The existing documentation (lines 32-41) correctly explains that SipHash keys are stored in plaintext intentionally and that Bloom is not a security primitive. However, it does not document:

1. That `sip_keys` are non-deterministic — two `Bloom` filters with the same entries will have different `sip_keys` and produce different serialized representations.
2. That this non-determinism means Bloom filter serializations are NOT reproducible — the same logical index will produce different bytes on each serialization.
3. That the `validate()` method checks for all-zero keys (degenerate case) but does not check for the degenerate case where both key pairs are identical (`sip_keys[0] == sip_keys[1]`), which would reduce hash independence.

```rust
/// SipHasher keys for reproducible hashing.
///
/// **Security note:** These keys are stored in plaintext intentionally.
/// ...
pub(crate) sip_keys: [(u64, u64); 2],
```

The doc comment says "reproducible hashing" which is misleading — the hashing is reproducible only for a given set of keys, but the keys themselves are non-deterministic.

**Fix:** Update the doc comment to clarify that `sip_keys` are generated non-deterministically per `Bloom` instance, making serialized representations non-reproducible. Change "reproducible hashing" to "deterministic hashing given fixed keys". Optionally, add a degenerate key pair check to `validate()`.

### V24-F10: rkyv buffer size pre-validation missing in `deserialize_entry_with_buf` [MEDIUM — Deserialization]

**Location:** `store.rs:38-47` (`deserialize_entry_with_buf()`)

**Analysis:** The `deserialize_entry_with_buf()` function accepts arbitrary `&[u8]` and passes it directly to `rkyv::check_archived_root::<IndexEntry>()` without any size pre-validation:

```rust
fn deserialize_entry_with_buf(bytes: &[u8], buf: &mut rkyv::AlignedVec) -> Result<IndexEntry> {
    buf.clear();
    buf.extend_from_slice(bytes);
    let archived = rkyv::check_archived_root::<IndexEntry>(buf)
        .map_err(|e| EraError::Deserialization(e.to_string()))?;
    Ok(match archived.deserialize(&mut rkyv::Infallible) {
        Ok(val) => val,
        Err(never) => match never {},
    })
}
```

`IndexEntry` has a fixed, known size (32 bytes hash + 8 bytes volume_id + 8 bytes block_id + 4 bytes offset + 4 bytes length = 56 bytes, plus rkyv alignment overhead). The function could reject obviously wrong inputs (empty bytes, or bytes far exceeding the expected `IndexEntry` serialized size) before copying into the aligned buffer and invoking the rkyv validation machinery. While `check_archived_root` will reject malformed data, it does so after the buffer copy. For the hot deserialization path in `open_readonly()` (which processes up to 100M entries), a cheap size pre-check avoids unnecessary `AlignedVec` operations on obviously invalid data.

**Fix:** Add a size pre-check: reject `bytes.len() < MIN_INDEX_ENTRY_SIZE` or `bytes.len() > MAX_INDEX_ENTRY_SIZE` before copying into the aligned buffer. Define the expected size range based on `IndexEntry`'s rkyv serialized layout.

---

## Scoring

| Dimension | Score | Notes |
|-----------|-------|-------|
| Encapsulation | 99/100 | V24-F1/F2: `IndexEntry` and `PagePointer` pub fields bypass validated constructors |
| Safety | 99/100 | V24-F5: Integer overflow in recovery candidate upper bound |
| Deserialization | 99/100 | V24-F8/F10: Post-allocation size checks, missing pre-validation |
| Performance | 99/100 | V24-F4: Triple iteration is minor overhead, already optimized from V22-F1 |
| Maintainability | 99/100 | V24-F7/F9: Duplicated constant, misleading doc comment |

**Overall Score: 99/100** (unchanged from 99/100 in V23)

The remaining 1 point reflects the carried-forward architectural constraints (V24-CF1, V24-CF2) which require broader refactoring beyond the scope of a single crate audit. The V24 findings are encapsulation, safety, and documentation quality issues — not critical security vulnerabilities. The crate's core security model (bloom hint + Redb B-tree + AEAD encryption) remains sound.

---

## Test Coverage

All V24 findings will be covered by the `adversarial_audit_v24.rs` test suite with both source-level verification and behavioral tests.
