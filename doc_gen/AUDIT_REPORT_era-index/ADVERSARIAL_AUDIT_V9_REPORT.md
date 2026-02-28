# ERA-Core V9 Adversarial Audit Report

**Date:** 2026-02-26  
**Auditor:** V9 Adversarial Audit Agent  
**Scope:** Full codebase — era-index, era-crypto, era-codec, era-packing, era-engine, era-volume  
**Previous Score (V8):** 55/100  
**V9 Score:** 68/100  
**Verdict:** Significant improvement in era-index; critical defects remain in crypto, codec, packing, and engine layers.

---

## Executive Summary

The competitor claims to have resolved all V8 OPEN findings. **This claim is correct for era-index** — all 10 OPEN items from the V8 audit are verified fixed with test evidence. The era-index crate is now the strongest layer in the system.

However, the competitor's work was **narrowly scoped to era-index** and ignored systemic vulnerabilities across the rest of the codebase. This audit discovered **17 novel findings** across 5 other crates, including:
- **1 P0** — unconditional `panic!()` in a public crypto API method
- **7 P1** — decompression bombs, unbounded allocation from untrusted input, `.expect()` in hot paths, truncated archive DoS
- **6 P2** — key material stack residue, LZ4 level silently ignored, silent failures
- **3 P3** — code quality and robustness issues

### Test Evidence

| Crate | Tests Written | Tests Passed | Tests Failed | Findings Proved |
|-------|--------------|-------------|-------------|-----------------|
| era-index | 49 | 49 | 0 | 10 V8 fixes verified + 3 novel |
| era-crypto | 19 | 19 | 0 | 1 P0 panic proved, 2 P2 documented |
| era-codec | 17 | 17 | 0 | 3 findings demonstrated |
| era-engine | 9 | 8 | 1* | Truncated archive DoS found |
| **Total** | **94** | **93** | **1** | **19 findings** |

\*v9_e6a: `ArchiveReader::open()` succeeds on truncated archives without detecting corruption; extraction then hangs (DoS).

---

## Part 1: V8 Fix Verification Matrix

All 10 V8 OPEN items in era-index have been verified fixed with passing tests.

| V8 ID | Finding | Status | Proof Test(s) |
|-------|---------|--------|---------------|
| V8-F1 | MetaIndex pub fields allow invariant bypass | **FIXED** | `v9_f1a_meta_index_fields_encapsulated`, `v9_f1b_meta_index_ordering_enforced` |
| V8-F2 | IndexPage no upper bound on entry count | **FIXED** | `v9_f2a_index_page_rejects_oversized`, `v9_f2b_index_page_accepts_exact_limit`, `v9_f2c_index_page_rejects_empty` |
| V8-F3 | bloom_serde docstring lie | **FIXED** | Code review (docstring corrected) |
| V8-F4 | Bloom FP degradation at 2× scale | **FIXED** | `v9_f6a_bloom_resize_threshold` (1.5× threshold verified) |
| V8-F5 | set_bloom_filter missing validation | **FIXED** | `v9_f3a_set_bloom_rejects_garbage`, `v9_f3b_set_bloom_rejects_empty`, `v9_f3c_set_bloom_accepts_valid` |
| V8-F6 | Disabled benchmarks | **FIXED** | 4 real Criterion benchmarks in `index_bench.rs` |
| V8-F7 | Unbounded page cache | **FIXED** | `v9_f4a_page_cache_bounded` (LRU cap=256 verified) |
| V8-F8 | entry_count O(n) scan cost | **FIXED** | `v9_f5a_entry_count_cached_performance`, `v9_f5c_entry_count_accurate_across_flush` |
| V7-F5 | IndexLocation missing volume_id | **FIXED** | `v9_f14a_index_location_has_volume_id`, `v9_f14b_multi_volume_lookup_preserves_volume_id` |
| V7-F2 | from_memory single-page bug | **FIXED** | `v9_f16a_from_memory_chunks_pages_correctly`, `v9_f16b_from_memory_single_page` |

**Additional era-index improvements verified:**
- `v9_f9a_index_page_dedup_deterministic` — page dedup confirmed
- `v9_f15a_first_write_wins_in_store`, `v9_f15b_first_write_wins_in_batch` — dedup strategy consistent
- `v9_f12a_double_finalize_rejected`, `v9_f12b_insert_after_finalize_rejected` — state machine correct
- `v9_f17a_100k_roundtrip` — 100K entry roundtrip verified
- `v9_f18a_bloom_no_false_negatives` — bloom never returns false negatives across 10K entries

---

## Part 2: Novel Vulnerability Findings

### P0 — Critical (Production-Blocking)

#### V9-F1: `panic!()` in `HybridSecretKey::public_key()` [era-crypto]

**File:** `crates/era-crypto/src/hybrid_kem.rs` lines 129–137  
**Severity:** P0  
**Test:** `v9_c1a_hybrid_secret_key_public_key_panics` (passes with `#[should_panic]`)

```rust
pub fn public_key(&self) -> HybridPublicKey {
    // ...
    panic!("Use the public key stored during key generation");
}
```

A `pub fn` on `HybridSecretKey` unconditionally panics. Any caller invoking `.public_key()` causes an unrecoverable abort. This violates the Rust API contract — public methods must not panic. The method should either return `Result<HybridPublicKey>`, be removed, or be marked `#[deprecated]` with a compile-time warning.

**Impact:** Any downstream code (including future key rotation logic) calling this method crashes the process.

**Remediation:** Remove the method or implement it properly by storing the public key during generation.

---

### P1 — High (Exploitable / Data Loss Risk)

#### V9-F2: Zstd Decompression Bomb [era-codec]

**File:** `crates/era-codec/src/compression.rs` lines 50–57  
**Severity:** P1  
**Test:** `v9_d1c_zstd_malformed_input` (partial coverage)

```rust
fn decompress(&self, data: &[u8]) -> Result<Bytes> {
    let decompressed = zstd::decode_all(data)
        .map_err(|e| EraError::decompression(e.to_string()))?;
    Ok(Bytes::from(decompressed))
}
```

`zstd::decode_all()` decompresses without any output size cap. A crafted Zstd frame with a massive decompressed-size header (e.g. 4 GB declared, 100 bytes compressed) triggers unbounded memory allocation, causing OOM and process abort.

**Impact:** An attacker who can supply a crafted `.era` archive can crash any reader with a ~100-byte payload.

**Remediation:** Use `zstd::Decoder` with `set_parameter(CParameter::WindowLogMax(...))` or wrap in `Read::take()` with a maximum decompressed size (e.g. `MAX_BLOCK_SIZE * 2`).

#### V9-F3: LZ4 Decompression Bomb [era-codec]

**File:** `crates/era-codec/src/compression.rs` lines 116–123  
**Severity:** P1  
**Test:** `v9_d2b_lz4_crafted_size_prefix`

```rust
fn decompress(&self, data: &[u8]) -> Result<Bytes> {
    match lz4_flex::decompress_size_prepended(data) {
        Ok(decompressed) => Ok(Bytes::from(decompressed)),
        Err(e) => Err(EraError::decompression(format!("LZ4 decompression failed: {}", e))),
    }
}
```

`lz4_flex::decompress_size_prepended()` reads the output size from the first 4 bytes of input. An attacker can set a huge size value (e.g. 4 GB), causing a massive allocation before any decompression occurs.

**Impact:** Same as V9-F2 — crafted archive causes OOM crash.

**Remediation:** Read the prepended size, validate it against a maximum (e.g. `4 * compressed_size` or absolute cap), then decompress.

#### V9-F4: Unbounded Allocation in PackedChunk::deserialize() [era-packing]

**File:** `crates/era-packing/src/packed_chunk.rs` lines 190–214  
**Severity:** P1  

```rust
let entry_count = header.entry_count;          // attacker-controlled u32
let total_data_size = header.total_data_size;  // attacker-controlled u64
let mut entries = Vec::with_capacity(entry_count as usize);  // up to ~16 GB
// ...
let mut file_data = vec![0u8; total_data_size as usize];     // up to 2^64 bytes
```

`entry_count` and `total_data_size` are read from the serialized header with **no validation** against `data.len()` or any reasonable upper bound.

**Impact:** A crafted packed chunk header can cause OOM or exhaust system memory.

**Remediation:** Validate `entry_count * sizeof(PackedEntry) + total_data_size <= data.len()` before allocation.

#### V9-F5: 11 `.expect()` Calls in Crypto Key Types [era-crypto]

**File:** `crates/era-crypto/src/key_session.rs` (11 locations)  
**Severity:** P1  
**Selected locations:**
- Line 43: `.expect("Failed to allocate secure memory for IntermediateKey")`
- Line 73: `.expect("Failed to allocate secure memory for VolumeKey")`
- Line 125: `.expect("Failed to allocate secure memory for BlockKey")`
- Line 298: `.expect("Default build failed")` in `from_derived_key()`
- Line 350: `.expect("HKDF expand should not fail")` in `derive_block_key()`
- Line 401: `.expect("Failed to allocate secure memory for KeySession clone")`

`SecureBuffer::with_config()` can fail under `mlock` limits (common in containers). When it does, these `.expect()` calls cause an unrecoverable panic in the crypto layer.

**Impact:** Systems running under restrictive mlock limits (Docker, Kubernetes, systemd with `LimitMEMLOCK`) will crash on key operations.

**Remediation:** Propagate `Result` from all `SecureBuffer` allocations. Replace `.expect()` with `?` operator.

#### V9-F6: `.expect()` in Write Pipeline Hot Path [era-engine]

**File:** `crates/era-engine/src/write_pipeline.rs` lines 192, 226  
**Severity:** P1  

```rust
let padding_block = padding_blocks[i]
    .as_ref()
    .expect("Padding block should be prepared");  // line 192

let encrypted_block = padding_blocks[i]
    .take()
    .expect("Padding block should be prepared");  // line 226
```

Two `.expect()` calls on `Option` in the stripe-write hot path. An off-by-one in padding preparation panics the entire archive operation.

**Impact:** Archive creation fails unrecoverably mid-write, potentially leaving corrupt/incomplete volumes on disk.

**Remediation:** Replace with `.ok_or(EraError::Internal(...))?`.

#### V9-F7: `.expect()` on Catalog Volume Footer [era-engine]

**File:** `crates/era-engine/src/reader.rs` line 553  
**Severity:** P1  

```rust
let footer = reader
    .footer()
    .expect("Catalog volume must have valid footer");
```

Reading the catalog footer `.expect()`s it to be `Some`. On a partially-written or corrupted volume, `footer()` returns `None` → panic during archive open.

**Impact:** Corrupted archives crash the reader instead of returning a recoverable error.

**Remediation:** Replace with `.ok_or(EraError::Corruption(...))?`.

#### V9-F8: Truncated Archive Accepted Without Detection [era-engine]

**File:** `crates/era-engine/src/reader.rs` (`open()` method)  
**Severity:** P1  
**Test:** `v9_e6a_truncated_archive` (VULNERABILITY DISCOVERED)

`ArchiveReader::open()` succeeds on a truncated archive (truncated to half its original size). No integrity check is performed during open. Subsequent `extract_all()` either hangs indefinitely or produces corrupt output.

**Impact:** A truncated `.era` file is silently accepted, leading to either a hang (DoS) or silent data loss during extraction.

**Remediation:** Validate that the archive footer is readable and its CRC matches during `open()`. Return `EraError::Corruption` for truncated files.

---

### P2 — Medium (Correctness / Security Hygiene)

#### V9-F9: `derive_checkpoint_key()` Returns Raw `[u8; 32]` [era-crypto]

**File:** `crates/era-crypto/src/key_session.rs` lines 377–386  
**Severity:** P2  
**Test:** `v9_c7a_checkpoint_key_is_raw_bytes`

Returns a raw `[u8; 32]` without `Zeroize` or `mlock`. Key material persists in memory after the array goes out of scope. Inconsistent with `BlockKey`/`VolumeKey` which use `SecureBuffer`.

**Remediation:** Return a `DerivedKey` or `SecureBuffer<32>` instead.

#### V9-F10: `derive_block_key()` Stack Residue [era-crypto]

**File:** `crates/era-crypto/src/key_session.rs` line 343  
**Severity:** P2  
**Test:** `v9_c13a_derive_block_key_stack_residue_documented`

```rust
let mut okm = [0u8; 32];
derive_key_hkdf(..., &mut okm).expect(...);
BlockKey::from_bytes(okm)  // copies into SecureBuffer, but okm remains on stack
```

The `okm` array holds raw key material and is never explicitly zeroized. The compiler may optimize away any implicit clearing.

**Remediation:** Add `okm.zeroize()` after the `BlockKey::from_bytes()` call, or use `Zeroizing<[u8; 32]>`.

#### V9-F11: LZ4 Compression Level Silently Ignored [era-codec]

**File:** `crates/era-codec/src/compression.rs` lines 109–113  
**Severity:** P2  
**Test:** `v9_d2c_lz4_level_silently_ignored`

```rust
let _level = self.level;  // unused!
let compressed = lz4_flex::compress_prepend_size(data);
```

The user-configured compression level is silently discarded. `lz4_flex` does not accept a level parameter. Users who select LZ4 with level 9 get the same output as level 1.

**Remediation:** Either remove the level parameter from LZ4 config, emit a warning during config validation, or switch to an LZ4 library that supports levels (e.g., `lz4` crate with `lz4::EncoderBuilder`).

#### V9-F12: `.expect()` in Writer Hash-to-Index Lookup [era-engine]

**File:** `crates/era-engine/src/writer.rs` line 1428  
**Severity:** P2  

```rust
let file_index = *hash_to_index
    .get(&entry.hash)
    .expect("packed file index must exist");
```

HashMap lookup `.expect()`d during packed-chunk catalog construction. Hash collision or logic bug → panic mid-archive.

**Remediation:** Replace with `.ok_or(EraError::Internal(...))?`.

#### V9-F13: `read_sorted_pages` Materializes All Pages [era-index]

**File:** `crates/era-index/src/store.rs` (read_sorted_pages method)  
**Severity:** P2  
**Test:** `v9_f8a_read_sorted_pages_materializes_all`

The function loads ALL index pages into memory at once (not streaming). For indexes with millions of entries across thousands of pages, this causes a large transient allocation spike.

**Remediation:** Return an iterator/stream that lazily loads pages from Redb as needed.

#### V9-F14: XOR-Only Domain Separation [era-index/era-engine]

**File:** `crates/era-index/src/builder.rs` (nonce_context XOR)  
**Severity:** P2  
**Test:** `v9_f11a_xor_domain_separation_uniqueness`

Index block encryption uses `nonce_context[0] ^= 0xFF` to derive a distinct nonce context from data blocks. While functional, XOR of a single byte provides only 1 bit of effective domain separation. Standard practice is to use distinct HKDF labels or 128-bit domain IDs.

**Remediation:** Use a separate HKDF derivation with label `"ERA_INDEX_BLOCK_v8.1"` for index blocks.

---

### P3 — Low (Robustness / Code Quality)

#### V9-F15: Dead Code in era-engine (ChunkIndex/MemoryChunkIndex)

**File:** `crates/era-engine/src/chunk_index.rs`  
**Severity:** P3  

`MemoryChunkIndex` struct and methods `delete`, `len`, `flush` on `ChunkIndex` trait are never used (compiler warnings emitted). Dead code increases maintenance burden and confuses auditors.

#### V9-F16: `unwrap()` Calls in Footer::read_fields_from [era-volume]

**File:** `crates/era-volume/src/footer.rs`  
**Severity:** P3  

14 `.unwrap()` calls on `Cursor::read_exact()` within `read_fields_from()`. While these are technically safe (the cursor wraps a known-size buffer), they reduce robustness and violate the project's `no-expect/unwrap` coding standard.

#### V9-F17: `SystemTime::now().duration_since(UNIX_EPOCH).expect()` [era-volume]

**File:** `crates/era-volume/src/super_header.rs`  
**Severity:** P3  

`SystemTime::now().duration_since(UNIX_EPOCH).expect(...)` panics if the system clock is before 1970. While rare, embedded systems or misconfigured VMs may have this condition.

---

## Part 3: Scoring Breakdown

| Category | Max | V8 Score | V9 Score | Notes |
|----------|-----|----------|----------|-------|
| **Core Correctness** | 25 | 12 | 21 | era-index all fixes verified; decompression bombs remain |
| **Security** | 25 | 14 | 14 | P0 panic in crypto still present; .expect() epidemic unchanged |
| **Error Handling** | 20 | 12 | 14 | era-index improved; engine/crypto still panic-prone |
| **Performance** | 10 | 5 | 7 | Real benchmarks added; read_sorted_pages still unbounded |
| **Code Quality** | 10 | 6 | 7 | Dead code, style consistency improved |
| **Test Coverage** | 10 | 6 | 5 | New tests only in era-index; no new cross-crate tests before this audit |
| **Total** | **100** | **55** | **68** | +13 points |

**Score justification:**
- +9 for complete era-index remediation (10/10 V8 fixes verified)
- +2 for benchmarks and documentation improvements
- +2 for bloom resize and entry_count caching performance
- -0 for no regression in other crates (but also no improvement)
- New findings offset further gains: P0 panic, 7 P1s, 6 P2s remain

---

## Part 4: V9 Test Suite Manifest

### era-index — 49 tests (`crates/era-index/tests/adversarial_audit_v9.rs`)

| Test ID | Description | Result |
|---------|------------|--------|
| v9_f1a | MetaIndex fields encapsulated | ✅ PASS |
| v9_f1b | MetaIndex ordering enforced | ✅ PASS |
| v9_f2a | IndexPage rejects oversized | ✅ PASS |
| v9_f2b | IndexPage accepts exact limit | ✅ PASS |
| v9_f2c | IndexPage rejects empty | ✅ PASS |
| v9_f3a | set_bloom rejects garbage | ✅ PASS |
| v9_f3b | set_bloom rejects empty | ✅ PASS |
| v9_f3c | set_bloom accepts valid | ✅ PASS |
| v9_f4a | Page cache bounded (LRU 256) | ✅ PASS |
| v9_f5a | Entry count cached performance | ✅ PASS |
| v9_f5b | Entry count accurate with duplicates | ✅ PASS |
| v9_f5c | Entry count accurate across flush | ✅ PASS |
| v9_f6a | Bloom resize threshold 1.5× | ✅ PASS |
| v9_f8a | read_sorted_pages materializes all | ✅ PASS |
| v9_f9a | IndexPage dedup deterministic | ✅ PASS |
| v9_f10a | from_memory with non-empty meta | ✅ PASS |
| v9_f11a | XOR domain separation uniqueness | ✅ PASS |
| v9_f11b | XOR double application reverts | ✅ PASS |
| v9_f12a | Double finalize rejected | ✅ PASS |
| v9_f12b | Insert after finalize rejected | ✅ PASS |
| v9_f12c | Empty finalize | ✅ PASS |
| v9_f13a | Entry count buffer internal dedup | ✅ PASS |
| v9_f13b | Entry count mixed buffer and redb | ✅ PASS |
| v9_f14a | IndexLocation has volume_id | ✅ PASS |
| v9_f14b | Multi-volume lookup preserves volume_id | ✅ PASS |
| v9_f15a | First-write-wins in store | ✅ PASS |
| v9_f15b | First-write-wins in batch | ✅ PASS |
| v9_f16a | from_memory chunks pages correctly | ✅ PASS |
| v9_f16b | from_memory single page | ✅ PASS |
| v9_f17a | 100K entry roundtrip | ✅ PASS |
| v9_f18a | Bloom no false negatives | ✅ PASS |
| v9_f19a | find_page exact boundaries | ✅ PASS |
| v9_f20a | from_pages ordering | ✅ PASS |
| v9_f20b | from_pages rejects disorder | ✅ PASS |
| v9_f21a | Bloom roundtrip correctness | ✅ PASS |
| v9_f22a | Readonly insert rejected | ✅ PASS |
| v9_f22b | Readonly batch insert rejected | ✅ PASS |
| v9_f23a | Concurrent lookups | ✅ PASS |
| v9_f24a | Zero length entry | ✅ PASS |
| v9_f24b | Max offset entry | ✅ PASS |
| v9_f25a | Open readonly bloom correct | ✅ PASS |
| v9_f26a | Discard removes file | ✅ PASS |
| v9_f26b | Discard idempotent | ✅ PASS |
| v9_f27a | Cross-page lookup correctness | ✅ PASS |
| v9_f28a | Binary search all entries | ✅ PASS |
| v9_f29a | Memtable size estimate | ✅ PASS |
| v9_f30a | Bloom serialization size | ✅ PASS |
| v9_f31a | Builder drop cleans staging | ✅ PASS |
| v9_f32a | Extreme hash values | ✅ PASS |

### era-crypto — 19 tests (`crates/era-crypto/tests/adversarial_audit_v9.rs`)

| Test ID | Description | Result |
|---------|------------|--------|
| v9_c1a | HybridSecretKey::public_key() panics | ✅ PASS (should_panic) |
| v9_c2a | DerivedKey basic operations | ✅ PASS |
| v9_c3a | AEAD cross-block replay prevented | ✅ PASS |
| v9_c3b | AEAD cross-nonce replay prevented | ✅ PASS |
| v9_c4a | KeySession derive_block_key separation | ✅ PASS |
| v9_c4b | KeySession deterministic derivation | ✅ PASS |
| v9_c5a | Volume key wrap/unwrap roundtrip | ✅ PASS |
| v9_c5b | Volume key wrong session fails | ✅ PASS |
| v9_c6a | Hybrid KEM roundtrip | ✅ PASS |
| v9_c6b | Hybrid KEM wrong key behavior | ✅ PASS |
| v9_c7a | Checkpoint key is raw bytes (documents P2) | ✅ PASS |
| v9_c8a | XOR domain different keys | ✅ PASS |
| v9_c9a | BLAKE3 deterministic | ✅ PASS |
| v9_c9b | BLAKE3 different inputs | ✅ PASS |
| v9_c10a | AEAD ciphertext bit-flip detected | ✅ PASS |
| v9_c11a | AEAD empty plaintext | ✅ PASS |
| v9_c12a | Password verification tags differ | ✅ PASS |
| v9_c12b | Password verification roundtrip | ✅ PASS |
| v9_c13a | derive_block_key stack residue documented | ✅ PASS |

### era-codec — 17 tests (`crates/era-codec/tests/adversarial_audit_v9.rs`)

| Test ID | Description | Result |
|---------|------------|--------|
| v9_d1a | Zstd roundtrip basic | ✅ PASS |
| v9_d1b | Zstd compress ratio for repetitive data | ✅ PASS |
| v9_d1c | Zstd malformed input | ✅ PASS |
| v9_d1d | Zstd empty input | ✅ PASS |
| v9_d2a | LZ4 roundtrip basic | ✅ PASS |
| v9_d2b | LZ4 crafted size prefix | ✅ PASS |
| v9_d2c | LZ4 level silently ignored | ✅ PASS |
| v9_d2d | LZ4 malformed input | ✅ PASS |
| v9_d3a | No compressor roundtrip | ✅ PASS |
| v9_d4a | Erasure basic roundtrip | ✅ PASS |
| v9_d4b | Erasure recovery with missing shards | ✅ PASS |
| v9_d4c | Erasure too many missing fails | ✅ PASS |
| v9_d4d | Erasure config validation | ✅ PASS |
| v9_d5a | Zstd level clamped | ✅ PASS |
| v9_d5b | Zstd negative level | ✅ PASS |
| v9_d6a | Zstd empty data | ✅ PASS |
| v9_d6b | LZ4 empty data | ✅ PASS |

### era-engine — 9 tests (`crates/era-engine/tests/adversarial_audit_v9.rs`)

| Test ID | Description | Result |
|---------|------------|--------|
| v9_e1a | Basic archive roundtrip | ✅ PASS |
| v9_e2a | Wrong password fails | ✅ PASS |
| v9_e3a | Empty archive | ✅ PASS |
| v9_e4a | Large file (2 MB) | ✅ PASS |
| v9_e5a | Dedup identical files | ✅ PASS |
| v9_e6a | Truncated archive | ⚠️ VULNERABILITY (open succeeds, extract hangs) |
| v9_e6b | Bit-flipped archive | ✅ PASS (corruption detected) |
| v9_e7a | Non-existent archive | ✅ PASS |
| v9_e8a | Zero-byte file | ✅ PASS |

---

## Part 5: Existing Test Suite Health

**era-index existing tests:** 124+ tests, 0 failures (20 unit + 8 integration + 47 V8 audit + 49+ V6/V7 audit)

No regressions detected. The competitor's fixes did not break any existing tests.

---

## Part 6: Prioritized Remediation Roadmap

### Immediate (Before Release)

1. **V9-F1 (P0):** Remove or implement `HybridSecretKey::public_key()` — 5 min fix
2. **V9-F2 (P1):** Add size cap to Zstd decompression — 10 min fix
3. **V9-F3 (P1):** Add size cap to LZ4 decompression — 10 min fix
4. **V9-F4 (P1):** Validate PackedChunk header against data length — 15 min fix
5. **V9-F8 (P1):** Validate archive footer on open — 20 min fix

### Short-Term (Next Sprint)

6. **V9-F5 (P1):** Replace all `.expect()` in key_session.rs with `Result` propagation — 1–2 hours
7. **V9-F6 (P1):** Replace `.expect()` in write_pipeline.rs hot path — 15 min
8. **V9-F7 (P1):** Replace `.expect()` in reader.rs footer access — 10 min

### Medium-Term

9. **V9-F9 (P2):** Return `DerivedKey` from `derive_checkpoint_key()` — 15 min
10. **V9-F10 (P2):** Zeroize `okm` in `derive_block_key()` — 5 min
11. **V9-F11 (P2):** Document or fix LZ4 level parameter — 10 min
12. **V9-F12 (P2):** Replace `.expect()` in writer.rs hash lookup — 10 min
13. **V9-F13 (P2):** Streaming `read_sorted_pages` — 2–4 hours
14. **V9-F14 (P2):** Proper domain separation for index blocks — 30 min

---

## Appendix A: Summary Statistics

| Metric | Value |
|--------|-------|
| Total findings | 17 |
| P0 (Critical) | 1 |
| P1 (High) | 7 |
| P2 (Medium) | 6 |
| P3 (Low) | 3 |
| V8 fixes verified | 10/10 |
| Tests written | 94 |
| Tests passing | 93 |
| Vulnerabilities discovered by tests | 1 (V9-F8 truncated archive) |
| Crates audited | 6/10 |
| Score improvement | +13 (55 → 68) |

## Appendix B: Files Created

| File | Tests | Purpose |
|------|-------|---------|
| `crates/era-index/tests/adversarial_audit_v9.rs` | 49 | V8 fix verification + novel era-index findings |
| `crates/era-crypto/tests/adversarial_audit_v9.rs` | 19 | Crypto panic paths, AEAD binding, key hygiene |
| `crates/era-codec/tests/adversarial_audit_v9.rs` | 17 | Decompression bombs, erasure coding, compression levels |
| `crates/era-engine/tests/adversarial_audit_v9.rs` | 9 | End-to-end roundtrip, corruption detection, edge cases |
