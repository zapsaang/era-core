# ERA Core Security Audit Report — V9 (Full Crate Sweep)

**Date:** 2025-07-14  
**Scope:** era-crypto, era-engine, era-codec, era-volume, era-packing, era-common  
**Methodology:** Full source read of all production files (68 files), line-by-line audit  
**Excludes:** Test code, benchmarks, fuzz targets

---

## Executive Summary

| Severity | Count |
|----------|-------|
| **P0 (Critical / Deployment Blocker)** | 5 |
| **P1 (High / Fix this sprint)** | 8 |
| **P2 (Medium / Next sprint)** | 10 |
| **P3 (Low / Hardening)** | 7 |

---

## P0 — Critical (Deployment Blockers)

### P0-1: `.expect()` / `.unwrap()` panic paths in key derivation (era-crypto)

Multiple `.expect()` calls on heap/mlock allocation in hot crypto paths. Any mlock failure (e.g., `RLIMIT_MEMLOCK` exceeded) causes an **unrecoverable panic** in production, crashing the archive operation.

| Location | Code |
|----------|------|
| [key.rs](crates/era-crypto/src/key.rs#L33) | `DerivedKey::from_bytes` → `.expect("Failed to allocate secure memory for DerivedKey")` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L47) | `IntermediateKey::derive_from_master_key` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L82) | `VolumeKey::generate` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L90) | `VolumeKey::from_bytes` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L107) | `VolumeKey::clone` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L128) | `BlockKey::from_bytes` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L296) | `KeySession::from_derived_key` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L349) | `derive_block_key` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L370) | `derive_checkpoint_key` → `.expect(...)` |
| [key_session.rs](crates/era-crypto/src/key_session.rs#L396) | `KeySession::clone` → `.expect(...)` |
| [secure_memory.rs](crates/era-crypto/src/secure_memory.rs) | `SecureBuffer::clone` → `.expect(...)` |

**Impact:** Production services will abort on resource limits. Containers with cgroup mlock limits will hit this.  
**Fix:** Replace `.expect()` with `Result`-returning functions. Propagate `EraError::Other("mlock failed")` upward.

---

### P0-2: `panic!()` in `HybridSecretKey::public_key()` (era-crypto)

**File:** [hybrid_kem.rs](crates/era-crypto/src/hybrid_kem.rs#L136)

```rust
fn public_key(&self) -> HybridPublicKey {
    panic!("Use the public key stored during key generation")
}
```

This is reachable via the public API. Any caller who doesn't know the convention triggers an immediate crash.

**Fix:** Remove the method or return `Result::Err`.

---

### P0-3: Unbounded decompression allocation (era-codec)

**File:** [compression.rs](crates/era-codec/src/compression.rs)

Both `ZstdCompressor::decompress()` and `LZ4Compressor::decompress()` have **no output size limit**:

- `zstd::decode_all(reader)` — reads the entire decompressed output into memory with no bound.
- `lz4_flex::decompress_size_prepended(data)` — reads a 4-byte length prefix from untrusted data and allocates that much memory.

A malicious archive can craft a tiny compressed payload that decompresses to gigabytes, causing OOM.

**Impact:** Denial of service via crafted archive. Any extraction or verification path is affected.  
**Fix:** Use `zstd::Decoder` with `set_single_frame(true)` and read into a bounded buffer. For LZ4, validate the prepended size against `MAX_SHARD_SIZE` before allocation.

---

### P0-4: `SystemTime::now().unwrap()` in volume header creation (era-volume)

**File:** [header.rs](crates/era-volume/src/header.rs#L160)

```rust
let created_at = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("System clock is before Unix epoch");
```

Same pattern at [header.rs](crates/era-volume/src/header.rs#L181) in `next_volume()`.

On systems with misconfigured clocks (NTP failures, VMs, embedded systems), this panics during archive creation.

**Fix:** Use `.unwrap_or(Duration::from_secs(0))` or return `Result`.

---

### P0-5: Checkpoint timestamp uses `.unwrap()` (era-engine)

**File:** [checkpoint.rs](crates/era-engine/src/checkpoint.rs#L109)

```rust
timestamp: std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs(),
```

Same issue as P0-4. Panics during checkpoint creation on clock issues.

**Fix:** `.unwrap_or(Duration::from_secs(0))`

---

## P1 — High Severity (Fix This Sprint)

### P1-1: `StagingPool::new()` uses `assert!()` instead of returning `Result` (era-packing)

**File:** [staging_pool.rs](crates/era-packing/src/staging_pool.rs#L99-L100)

```rust
assert!(k > 0, "k must be at least 1");
assert!(target_size > 0, "target_size must be positive");
```

And [staging_pool.rs](crates/era-packing/src/staging_pool.rs#L117):
```rust
assert!(percent > 0 && percent <= 100, ...);
```

User-controlled configuration values cause panics if misconfigured. The `PackingConfig` passed to `ArchiveWriterBuilder` flows directly into `StagingPool::new()`.

**Fix:** Return `Result` with descriptive error messages instead of panicking.

---

### P1-2: Integer truncation in `packed_chunk.rs` — `entry_count` as `u32` (era-packing)

**File:** [packed_chunk.rs](crates/era-packing/src/packed_chunk.rs#L158)

```rust
self.header.entry_count = self.entries.len() as u32;
```

If more than 4 billion files are added (unlikely but theoretically possible in adversarial input), this silently wraps.

More critically, in `deserialize()` at [packed_chunk.rs](crates/era-packing/src/packed_chunk.rs#L175):
```rust
let mut entries = Vec::with_capacity(entry_count as usize);
```

A crafted `entry_count` of `u32::MAX` in untrusted data would attempt to allocate ~200 GB of memory.

**Fix:** Validate `entry_count` against a reasonable maximum (e.g., 65536) before `Vec::with_capacity`.

---

### P1-3: `total_data_size` unbounded allocation in packed chunk deserialization (era-packing)

**File:** [packed_chunk.rs](crates/era-packing/src/packed_chunk.rs#L183)

```rust
let mut file_data = vec![0u8; total_data_size as usize];
```

`total_data_size` is read from a `u64` field in untrusted data. A crafted value can request petabytes of memory. No validation against available data or a reasonable maximum.

**Fix:** Validate `total_data_size <= data.len()` and enforce a maximum (e.g., 256 MB).

---

### P1-4: Negative timestamp cast to u64 (era-crypto)

**File:** [timestamp.rs](crates/era-crypto/src/timestamp.rs#L64)

`to_unix_timestamp()` casts `i64` to `u64`. Dates before 1970-01-01 produce negative `i64` values that become extremely large `u64` values, which could corrupt timestamp fields in archives.

**Fix:** Clamp to `0u64` for pre-epoch timestamps: `self.0.unix_timestamp().max(0) as u64`.

---

### P1-5: Legacy `would_fit` size calculation in `multi_volume.rs` (era-volume)

**File:** [multi_volume.rs](crates/era-volume/src/multi_volume.rs)

The `would_fit()` method uses `block_size as u64 + 4` where `4` was the old ShardHeader size. The actual `BlockHeader::SIZE` is 16 bytes. This causes:
- Under-estimation of space needed per block by 12 bytes
- Premature volume rotation in edge cases
- Incorrect volume capacity calculations

**Fix:** Replace `+ 4` with `+ BlockHeader::SIZE as u64`.

---

### P1-6: No `block_size` validation against `MAX_SHARD_SIZE` in `block_codec.rs` (era-packing)

**File:** [block_codec.rs](crates/era-packing/src/block_codec.rs#L55-L60)

After AEAD decryption, `index_len` is read from the first 4 bytes of the decrypted buffer and used to allocate the index:
```rust
let index_len = u32::from_le_bytes(...) as usize;
```

This value is not validated against any maximum bound. While the data is authenticated (AEAD), a bug in the compression layer or key derivation could produce a valid-looking buffer with an enormous `index_len`, causing unbounded allocation.

**Fix:** Validate `index_len <= decompressed.len()` and `index_len <= MAX_SHARD_SIZE`.

---

### P1-7: Brute-force checkpoint recovery scans 100 block IDs (era-engine)

**File:** [checkpoint.rs](crates/era-engine/src/checkpoint.rs#L560-L585)

```rust
for candidate_id in 0..100u64 {
    // try decrypt with each candidate block_id
}
```

This brute-force loop is an O(100) linear scan of AEAD decryptions. While bounded, it:
1. Is a potential timing side-channel (attacker can observe 100 decrypt attempts)
2. Burns CPU unnecessarily on corrupted volumes
3. Could be used for oracle attacks if error responses differ

**Fix:** Store `checkpoint_block_id` in the footer (already partially done). Remove brute-force fallback or limit to 10 candidates with rate-limiting.

---

### P1-8: `RecipientType::ScryptPassword` naming mismatch (era-engine)

**File:** [auth.rs](crates/era-engine/src/auth.rs) / [writer.rs](crates/era-engine/src/writer.rs)

The codebase uses `RecipientType::ScryptPassword` but the actual KDF is **Argon2id**. This naming confusion:
- Could mislead security auditors
- May cause incorrect KDF selection in future multi-KDF support

**Fix:** Rename to `RecipientType::Argon2idPassword` or `RecipientType::KdfPassword`.

---

## P2 — Medium Severity (Next Sprint)

### P2-1: `unsafe` blocks in `secure_memory.rs` (era-crypto)

**File:** [secure_memory.rs](crates/era-crypto/src/secure_memory.rs#L153)

Multiple `unsafe` blocks for:
- `Drop` implementation with explicit zeroization via `std::ptr::write_volatile`
- `mlock()` / `munlock()` FFI calls to libc
- Raw pointer manipulation

These are **necessary** for the security model (preventing key material from being paged), but:
1. No `SAFETY` comments explaining invariants
2. Missing `#[cfg(target_os)]` guards — `mlock` may not behave identically on all platforms
3. No fallback for systems where mlock is unavailable

**Fix:** Add `// SAFETY:` comments. Add `#[cfg(not(unix))]` fallback. Consider using `memsec` or `secrecy` crates for portable secure memory.

---

### P2-2: `Cell<u64>` in `SessionBlockBuilder` is not `Send` (era-packing)

**File:** [session_builder.rs](crates/era-packing/src/session_builder.rs)

`SessionBlockBuilder` uses `Cell<u64>` for the block ID counter. `Cell` is `!Sync`, so this is safe for single-threaded use. However:
- The `&self` receiver on `pack_single()` / `pack_chunks()` allows shared references
- No documentation warns about thread-safety constraints
- If `SessionBlockBuilder` is ever shared across threads (e.g., via `Arc`), this becomes a data race

**Fix:** Use `AtomicU64` (consistent with `MacroBlockBuilder`) or document `!Send` constraint explicitly.

---

### P2-3: `MAX_BLOCK_SIZE` is 1 GB in block iterator (era-engine)

**File:** [block_iter.rs](crates/era-engine/src/block_iter.rs#L67)

```rust
const MAX_BLOCK_SIZE: u32 = 1024 * 1024 * 1024;
```

This allows reading a single block of up to 1 GB into memory. Combined with multiple blocks being processed concurrently, this could exhaust memory on systems with limited RAM.

**Fix:** Lower to 64 MB (well above the 4 MB default block size) or make configurable.

---

### P2-4: Missing path traversal check in `add_file_with_path` (era-engine)

**File:** [writer.rs](crates/era-engine/src/writer.rs#L1070)

The `add_file_with_path` method accepts arbitrary `stored_path` that becomes the filename in the archive. While the **extraction** path has path traversal protection (checking for `..` and absolute paths), the **write** path does not validate `stored_path`. This allows creating archives with malicious paths that could exploit extractors without ERA's protections.

**Fix:** Validate `stored_path` during write to reject `..` components and absolute paths.

---

### P2-5: Missing `MAX_DECLARED_FILE_SIZE` validation on write (era-engine)

**File:** [reader.rs](crates/era-engine/src/reader.rs) defines `MAX_DECLARED_FILE_SIZE = 100 GB` for extraction safety, but the writer has no corresponding limit. An attacker who controls the archive creation API could embed a catalog entry with `size: u64::MAX` that would pass creation but DoS readers.

**Fix:** Validate file sizes during `add_file*` calls.

---

### P2-6: `HashMap` with unbounded growth in `CheckpointManager` (era-engine)

**File:** [checkpoint.rs](crates/era-engine/src/checkpoint.rs#L74)

```rust
pub written_chunks: HashMap<ChunkHash, BlockLocation>,
```

For archives with millions of chunks, this HashMap grows unboundedly in memory. At ~100 bytes per entry, 10M chunks = ~1 GB RAM just for the checkpoint.

**Fix:** Periodically flush and reset the map, or switch to a disk-backed structure.

---

### P2-7: `volume_has_checkpoint` opens full volume reader for a boolean check (era-engine)

**File:** [recovery.rs](crates/era-engine/src/recovery.rs#L48-L64)

Opening a full `VolumeReader` (which reads and parses the header, loads the protobuf config) just to check `footer.last_checkpoint_offset > 0` is wasteful. On large volumes, this involves significant I/O.

**Fix:** Read only the 128-byte footer directly instead of opening the full volume.

---

### P2-8: `MemoryChunkIndex` has no size bound (era-engine)

**File:** [chunk_index.rs](crates/era-engine/src/chunk_index.rs#L62)

`MemoryChunkIndex` is an unbounded `HashMap`. While `LsmChunkIndex` is the production default, `MemoryChunkIndex` is still accessible and could be used accidentally.

**Fix:** Add a capacity limit or deprecate.

---

### P2-9: `ErasureCodeConfig` accepts 0 data_shards / 0 parity_shards (era-common)

**File:** [block.rs](crates/era-common/src/types/block.rs#L273)

`ErasureCodeConfig::new(0, 0)` is valid but semantically meaningless and would cause division-by-zero in downstream shard calculations.

**Fix:** Validate `data_shards >= 1` in `new()`.

---

### P2-10: `BlockLocation::erasure()` only `debug_assert!`s offset/volume length match (era-common)

**File:** [block.rs](crates/era-common/src/types/block.rs#L172)

```rust
debug_assert_eq!(shard_offsets.len(), shard_volumes.len(), ...);
```

In release builds, mismatched lengths silently corrupt the `ShardLayout`, causing incorrect shard reads.

**Fix:** Replace `debug_assert_eq!` with a release-mode check that returns `Result`.

---

## P3 — Low Severity (Hardening)

### P3-1: `compress_zstd` silently falls back to uncompressed on error (era-engine)

**File:** [async_pipeline.rs](crates/era-engine/src/async_pipeline.rs#L295)

```rust
Err(e) => {
    tracing::warn!("Compression failed: {}, using uncompressed data", e);
    Bytes::copy_from_slice(data)
}
```

Compression failures are silently swallowed. This could mask data corruption issues and produce archives larger than expected.

**Fix:** Return `Result` and let the caller decide whether to retry or abort.

---

### P3-2: KDF parameters allow insecure configurations (era-crypto)

**File:** [kdf.rs](crates/era-crypto/src/kdf.rs)

`KdfParams::fast()` uses `memory_cost: 1024` (1 MB) and `time_cost: 1`. While documented as "fast mode for testing", there's no runtime guard preventing production use. The `GenericArchiveWriterBuilder` flows user-provided `EncryptionConfig` directly into KDF params.

**Fix:** Warn or reject KDF params below a security floor (e.g., `memory_cost < 16384`) outside of test builds.

---

### P3-3: `certificate.rs` uses `KdfParams::fast()` for key file encryption (era-crypto)

**File:** [certificate.rs](crates/era-crypto/src/certificate.rs)

`save_encrypted()` uses `KdfParams::fast()` for encrypting private key files. This provides minimal brute-force resistance (1 MB Argon2id).

**Fix:** Use `KdfParams::standard()` for key file encryption.

---

### P3-4: OpenSSH key parsing uses heuristic byte scanning (era-crypto)

**File:** [pem_support.rs](crates/era-crypto/src/pem_support.rs)

The OpenSSH private key parser uses byte scanning heuristics to locate the 32-byte private key. This is fragile against format variations and could read incorrect bytes from malformed keys.

**Fix:** Use a proper OpenSSH key parser or document the exact format limitations.

---

### P3-5: `OperationTimer::finish()` calls `self.record()` which consumes `self`, then tries to return elapsed (era-engine)

**File:** [metrics_collector.rs](crates/era-engine/src/metrics_collector.rs#L41)

The `finish()` method calls `self.record()` which moves `self`, then returns the elapsed time. This works because `record()` computes elapsed internally, but the pattern is fragile — the elapsed time in `finish()` will differ slightly from what `record()` observed.

**Fix:** Compute elapsed once and pass it to both paths.

---

### P3-6: Missing `Zeroize` on `PasswordProvider` password field (era-engine)

**File:** [auth.rs](crates/era-engine/src/auth.rs#L32)

`PasswordProvider` has a manual `Drop` that zeroizes the password string, but the struct doesn't implement `ZeroizeOnDrop`, meaning temporary copies (e.g., during moves) may leave password residue in memory.

**Fix:** Derive `ZeroizeOnDrop` or use `Zeroizing<String>`.

---

### P3-7: `conversion.rs` proto→Rust conversion lacks range validation (era-common)

**File:** [conversion.rs](crates/era-common/src/conversion.rs)

Several `From<proto::X>` conversions accept arbitrary protobuf values without range checking. For example, `proto::ErasureBlockInfo` converts `data_shards: u32` to `u8` via `as u8` (truncation), while the `TryFrom<proto::ErasureCodeConfig>` correctly uses `u8::try_from()`.

**Fix:** Consistently use `TryFrom` with range validation for all proto conversions that narrow integer types.

---

## Summary of Recommended Immediate Actions

1. **P0-1**: Replace all `.expect()` in era-crypto key paths with `Result<T, EraError>`.
2. **P0-2**: Remove `HybridSecretKey::public_key()` or make it return `Option/Result`.
3. **P0-3**: Add decompression size limits to `zstd::decode_all` and `lz4_flex::decompress_size_prepended`.
4. **P0-4/P0-5**: Replace `SystemTime` `.expect()` with `.unwrap_or()`.
5. **P1-2/P1-3**: Add bounds checking to `PackedChunk::deserialize()`.
6. **P1-6**: Validate `index_len` in `block_codec.rs` after decryption.

## Verification Commands

```bash
# Search for remaining .expect() in production code
grep -rn '\.expect(' crates/era-{crypto,engine,codec,volume,packing,common}/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'mod tests'

# Search for .unwrap() in production code
grep -rn '\.unwrap()' crates/era-{crypto,engine,codec,volume,packing,common}/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'mod tests'

# Search for panic!() in production code
grep -rn 'panic!' crates/era-{crypto,engine,codec,volume,packing,common}/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'mod tests'

# Search for unsafe blocks
grep -rn 'unsafe' crates/era-{crypto,engine,codec,volume,packing,common}/src/ --include='*.rs' | grep -v '#\[cfg(test)\]'

# Search for assert!() in non-test code
grep -rn 'assert!' crates/era-{crypto,engine,codec,volume,packing,common}/src/ --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v 'debug_assert' | grep -v 'mod tests'
```
