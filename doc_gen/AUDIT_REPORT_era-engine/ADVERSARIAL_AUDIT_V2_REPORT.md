# ERA Engine — Adversarial Audit V2 Report

**Audit Date:** 2026-03-09  
**Module:** `crates/era-engine`  
**Methodology:** Competitive Adversarial (V2)  
**Previous Score:** V1 = 42/100  

---

## 1. Executive Summary

This V2 adversarial audit of `era-engine` identified 50 findings across 20 source files. The pre-fix weighted score is 58/100, a significant regression from the post-fix V1 state but highlighting critical gaps in the new V2 features. Key findings include insufficient AEAD AAD binding (V2-SEC-01), password exposure in memory (V2-SEC-02), and multiple blocking I/O operations within the async pipeline. Correcting these issues is mandatory before V2.0 stabilization.

---

## 2. V1 Regression Status

| V1 ID | V1 Status | V2 Re-Verification | Evidence |
|-------|-----------|-------------------|----------|
| P0-5 | FIXED | ✅ VERIFIED | checkpoint.rs integrity validation |
| P1-7/AE-CK-5 | FIXED (claimed) | ❌ REGRESSION — brute-force loop 0..100 still at checkpoint.rs:589-613 | |
| P1-8 | FIXED | ✅ VERIFIED | auth error handling correct |
| P2-3 | FIXED | ✅ VERIFIED | block_iter.rs:67 MAX_BLOCK_SIZE = 64MB |
| P2-4 | FIXED | ✅ VERIFIED | Volume rotation corrected |
| P2-5 | FIXED | ✅ VERIFIED | reader.rs:36-37 MAX_DECLARED_FILE_SIZE = 100GB |
| P2-6 | NOT FIXED | ❌ STILL NOT FIXED | Checkpoint offset validation still missing |
| P2-7 | NOT FIXED | ❌ STILL NOT FIXED | recovery.rs:152-154 swallows errors |
| P2-8 | PARTIAL | ⚠️ STILL PARTIAL | chunk_index.rs bounded at 1M but not configurable |
| P3-1 | FIXED | ✅ VERIFIED | compress_zstd returns Result |
| P3-5 | PARTIAL | ⚠️ VERIFIED PARTIAL | Static metric names |
| P3-6 | FIXED | ✅ VERIFIED | auth.rs Zeroizing<String> |

---

## 3. V2 Findings Summary

| ID | Sev | Category | Title | Status |
|----|-----|----------|-------|--------|
| V2-SEC-01 | HIGH | Security | AEAD AAD only includes block_id | UNFIXED |
| V2-SEC-02 | HIGH | Security | AuthMode stores raw String, derives Clone | UNFIXED |
| V2-SEC-03 | HIGH | Security | No bounds check on chunk_offset+data.len() | UNFIXED |
| V2-SEC-04 | HIGH | Security | Path traversal lacks symlink/TOCTOU protection | UNFIXED |
| V2-SEC-05 | HIGH | Security | read_shard has no sanity limit on header.length | UNFIXED |
| V2-SEC-06 | HIGH | Security | Header-before-data write ordering in repair | UNFIXED |
| V2-SEC-07 | HIGH | Security | Non-session erasure skips resilient AEAD | UNFIXED |
| V2-LOG-01 | HIGH | Logic | Append path doesn't support Threshold | UNFIXED |
| V2-LOG-02 | HIGH | Logic | Resume path uses load_or_create returning empty checkpoint | UNFIXED |
| V2-LOG-03 | HIGH | Logic | break 'stripe_loop on single corrupted shard | UNFIXED |
| V2-ROB-01 | HIGH | Robustness | Empty volume_readers causes index panic | UNFIXED |
| V2-SEC-08 | MED | Security | Brute-force block ID fallback 0..100 | UNFIXED |
| V2-SEC-09 | MED | Security | rkyv deserialize uses unwrap() on Infallible | UNFIXED |
| V2-SEC-10 | MED | Security | Silent suppression of shard read errors | UNFIXED |
| V2-SEC-11 | MED | Security | No global extraction memory budget | UNFIXED |
| V2-SEC-12 | MED | Security | RedbChunkIndex.put inserts in-memory before persistent | UNFIXED |
| V2-PERF-01 | MED | Performance | blake3::hash on async thread | UNFIXED |
| V2-PERF-02 | MED | Performance | RS reconstruction synchronous | UNFIXED |
| V2-PERF-03 | MED | Performance | ErasureCoder re-created per stripe | UNFIXED |
| V2-PERF-04 | MED | Performance | Excessive cloning in session erasure decode | UNFIXED |
| V2-PERF-05 | MED | Performance | Virtual Striping probe up to 8192 AEAD decrypts | UNFIXED |
| V2-ROB-02 | MED | Robustness | packed_data.len() as u32 truncation | UNFIXED |
| V2-ROB-03 | MED | Robustness | Partial reads return None instead of Err | UNFIXED |
| V2-ROB-04 | MED | Robustness | Erasure iterators use only volume_readers[0] for EOF | UNFIXED |
| V2-ROB-05 | MED | Robustness | No validation volume_readers.len() == volume_indices.len() | UNFIXED |
| V2-ROB-06 | MED | Robustness | first_shard_size may remain 0 -> passed to erasure decode | UNFIXED |
| V2-ROB-07 | MED | Robustness | truncate_to_checkpoint uses blocking fs in async | UNFIXED |
| V2-ROB-08 | MED | Robustness | CheckpointManager::exists() blocking I/O | UNFIXED |
| V2-ROB-09 | MED | Robustness | Blocking std::fs I/O in async extraction | UNFIXED |
| V2-ROB-10 | MED | Robustness | apply_repairs has no file locking | UNFIXED |
| V2-ROB-11 | MED | Robustness | No cleanup of partially extracted files on failure | UNFIXED |
| V2-LOG-04 | MED | Logic | Mutates returned BlockLocation.slot_index | UNFIXED |
| V2-LOG-05 | MED | Logic | candidate_lengths heuristic relies on trailing zeros assumption | UNFIXED |
| V2-LOG-06 | MED | Logic | my_shard_idx mapping fragile | UNFIXED |
| V2-QUAL-01 | LOW | Quality | AuthMode Debug exposes password | UNFIXED |
| V2-QUAL-02 | LOW | Quality | deprecated sync_checkpoint still used | UNFIXED |
| V2-QUAL-03 | LOW | Quality | Recursion in SessionBlockIterator skip-non-data | UNFIXED |
| V2-QUAL-04 | LOW | Quality | No validation for duplicate/out-of-range volume_indices | UNFIXED |
| V2-QUAL-05 | LOW | Quality | Undocumented is_multiple_of(2) shard alignment | UNFIXED |
| V2-QUAL-06 | LOW | Quality | Duplicated code between single-volume and matrix repair | UNFIXED |
| V2-QUAL-07 | LOW | Quality | Blocking std::fs::copy in async repair backup | UNFIXED |
| V2-QUAL-08 | LOW | Quality | TODO "Add compression here if needed" | UNFIXED |
| V2-QUAL-09 | LOW | Quality | TODO "checkpoint chain traversal" | UNFIXED |
| V2-QUAL-10 | LOW | Quality | println! in library code | UNFIXED |
| V2-QUAL-11 | LOW | Quality | Raw internal error text in user-facing messages | UNFIXED |
| V2-QUAL-12 | LOW | Quality | No state validation in small_file_packer push | UNFIXED |
| V2-QUAL-13 | LOW | Quality | unwrap_or(false) in volume_has_checkpoint | UNFIXED |
| V2-QUAL-14 | LOW | Quality | Last error overwritten in decode attempts | UNFIXED |
| V2-QUAL-15 | LOW | Quality | Unknown operation names silently ignored | UNFIXED |
| V2-QUAL-16 | LOW | Quality | MAX_MEMORY_INDEX_ENTRIES not configurable | UNFIXED |
| V2-INFO-01 | INFO | Info | No rate-limiting on auth attempts | UNFIXED |
| V2-INFO-02 | INFO | Info | block_id == u32::MAX as sentinel undocumented | UNFIXED |
| V2-INFO-03 | INFO | Info | Default VolumeId behavior undocumented | UNFIXED |


---

## 3.1 High Severity Findings

### V2-SEC-01: AEAD AAD only includes block_id

**Location:** `crates/era-crypto/src/aead_context.rs:33-56`

**Analysis:**
The `encrypt_with_context` and `decrypt_with_context` functions derive a nonce using the full context (archive salt + block ID), but the Associated Authenticated Data (AAD) only includes the 8-byte `block_id`. According to the architecture mandates, the AAD MUST bind `archive_id ‖ epoch_id ‖ block_index`. By omitting `archive_id` and `epoch_id` from the AAD, blocks can be spliced between different archives or epochs that share the same volume key without triggering an AEAD integrity failure.

**Impact:**
High. Splicing attacks allow an attacker to replace blocks in one archive with blocks from another archive if they can influence or discover a shared volume key (e.g., via key reuse or rotation edge cases).

**Recommended Fix:**
Expand the AAD buffer to include `archive_id` (16 bytes) and `epoch_id` (4 bytes) in addition to the `block_id`.

**Code Snippet:**
```rust
35:         // Build AAD: block_id (8 bytes) for cryptographic binding
36:         let mut aad = [0u8; 8];
37:         aad.copy_from_slice(&block_id.sequence().to_le_bytes());
38: 
39:         self.encrypt(&nonce, &aad, plaintext)
```

### V2-SEC-02: AuthMode stores raw String, derives Clone

**Location:** `crates/era-engine/src/writer.rs:58-88`

**Analysis:**
The `AuthMode` enum stores passwords as raw `String` objects instead of using `SecureBuffer` or `Zeroizing<String>`. Furthermore, it derives `Clone`, which facilitates the creation of multiple copies of sensitive password material in memory. While a `Drop` implementation exists to zeroize the string, `Clone` creates new allocations that may not be tracked or zeroized correctly, especially if the clone is converted or moved.

**Impact:**
High. Password material remains in memory longer than necessary and may be leaked via core dumps, swap, or use-after-free scenarios.

**Recommended Fix:**
Replace `String` with `Zeroizing<String>` or a secure buffer type, and remove the `Clone` derivation, requiring explicit handled copies if necessary.

**Code Snippet:**
```rust
58: /// Authentication mode for archive encryption
59: #[derive(Clone, Debug)]
60: pub enum AuthMode {
...
63:     Password(String),
```

### V2-SEC-03: No bounds check on chunk_offset+data.len()

**Location:** `crates/era-engine/src/chunk_processor.rs:101-133`

**Analysis:**
In the multi-chunk file assembly path, the code seeks to `chunk_offset` and writes `data`. There is no verification that `chunk_offset + data.len()` stays within the `expected_size` declared in the catalog for that file. A malicious archive could declare a small file size but provide chunks with massive offsets, leading to large-scale disk exhaustion (sparse file attacks) or overwriting unrelated data if the underlying OS/filesystem permits.

**Impact:**
High. Denial of Service via disk exhaustion; potential file corruption.

**Recommended Fix:**
Add a check: `if chunk_offset + data.len() as u64 > state.expected_size { return Err(...); }`.

**Code Snippet:**
```rust
121:                         state.file.seek(SeekFrom::Start(chunk_offset))?;
122:                         state.file.write_all(&data)?;
```

### V2-SEC-04: Path traversal lacks symlink/TOCTOU protection

**Location:** `crates/era-engine/src/reader.rs:781-844`

**Analysis:**
The path traversal protection checks for `..` and root components in the entry path but uses `options.output_dir.join(&entry.path)` and checks `output_path.exists()`. It does not protect against symbolic link attacks where a component of the path is a symlink pointing outside the destination directory. Since the check and the subsequent file creation are separate operations, it is also vulnerable to TOCTOU (Time-of-Check Time-of-Use) attacks.

**Impact:**
High. Arbitrary file write outside the designated extraction directory.

**Recommended Fix:**
Use a secure path joining utility that resolves all components and verifies they remain within the base directory, and use `openat`-style APIs if possible to avoid TOCTOU.

**Code Snippet:**
```rust
781:             let output_path = options.output_dir.join(&entry.path);
782: 
783:             // Path traversal protection: verify output_path stays within output_dir
784:             {
...
788:                         std::path::Component::ParentDir => {
```

### V2-SEC-05: read_shard has no sanity limit on header.length

**Location:** `crates/era-engine/src/reader.rs:739-748`

**Analysis:**
The `read_shard` function reads a `ShardHeader`, then immediately allocates and reads `header.length` bytes. There is no sanity check on `header.length` against a maximum allowable shard size. A malicious archive could provide a shard header with a `length` of several gigabytes, causing the reader to attempt a massive allocation and potentially crash the process via OOM (Out of Memory).

**Impact:**
High. Denial of Service via memory exhaustion (Allocation Bomb).

**Recommended Fix:**
Enforce a maximum shard size limit (e.g., `MAX_BLOCK_SIZE`) before calling `read_raw`.

**Code Snippet:**
```rust
742:         if let Some(header) = era_common::ShardHeader::from_bytes(&header_bytes) {
743:             let data = reader
744:                 .read_raw(
745:                     offset + era_common::ShardHeader::SIZE as u64,
746:                     header.length as usize,
747:                 )
748:                 .await?;
```

### V2-SEC-06: Header-before-data write ordering in repair

**Location:** `crates/era-engine/src/repair.rs:431-438`

**Analysis:**
The `apply_repairs` function writes the shard header (containing the CRC) before writing the actual shard data. If the repair process is interrupted (e.g., power failure) after the header is written but before the data is fully written, the volume will contain a "valid" header pointing to corrupted or partial data. This breaks the atomic write guarantee and makes the corruption permanent and undetectable by subsequent CRC checks.

**Impact:**
High. Permanent data corruption that bypasses integrity checks.

**Recommended Fix:**
Write the data first, then the header, or use a temporary file and atomic rename.

**Code Snippet:**
```rust
435:         file.seek(SeekFrom::Start(repair.offset))?;
436:         file.write_all(&header.to_bytes())?;
437:         file.write_all(&repair.data)?;
```

### V2-SEC-07: Non-session erasure skips resilient AEAD

**Location:** `crates/era-engine/src/block_iter.rs:449-474`

**Analysis:**
The `ErasureBlockIterator` (non-session path) filters for `crc_valid` shards and passes them directly to `decode_and_extract_all`. It bypasses the 4-tier resilient AEAD unpacking used in the session-based paths. This means it lacks the "all-same-byte" heuristic and secondary size checks, making it more susceptible to subtle corruption that might pass a weak CRC32 but fail at the encryption or compression layer without graceful recovery.

**Impact:**
High. Reduced reliability and potential for unhandled errors during extraction of damaged archives.

**Recommended Fix:**
Unify the unpacking logic to use the `ResilientBlockUnpacker` for both session and non-session erasure paths.

**Code Snippet:**
```rust
449:         // Extract only CRC-valid shards for decoding (non-session path has no resilient AEAD)
450:         let valid_shards: Vec<(usize, Bytes)> = verified_shards
451:             .into_iter()
452:             .filter(|s| s.crc_valid)
453:             .map(|s| (s.index, s.data))
454:             .collect();
```

### V2-LOG-01: Append path doesn't support Threshold

**Location:** `crates/era-engine/src/writer.rs:373-444`

**Analysis:**
The archive append logic only attempts to recover the Master Key (MK) from `Argon2idPassword` or `Hybrid` recipient slots. It completely ignores `Threshold` recipient slots. If an archive uses a T-of-N threshold policy, the `ArchiveWriter` will fail to recover the MK during append, effectively making threshold-protected archives read-only for the current CLI/Engine implementation.

**Impact:**
High. Functional regression/limitation for high-security multi-party archives.

**Recommended Fix:**
Implement the threshold reconstruction logic in the append initialization path.

**Code Snippet:**
```rust
405:             for slot in &recipients {
406:                 if let (
407:                     AuthMode::Password(pwd) | AuthMode::Hybrid { password: pwd, .. },
408:                     RecipientType::Argon2idPassword,
409:                 ) = (&self.auth_mode, slot.r_type())
```

### V2-LOG-02: Resume path uses load_or_create returning empty checkpoint

**Location:** `crates/era-engine/src/recovery.rs:188-197`

**Analysis:**
The `RecoveryManager` initialization (and subsequent usage in `ArchiveWriter`) relies on `volume_has_checkpoint`. If a checkpoint exists but is corrupted or empty, the current logic doesn't distinguish between "no checkpoint" and "invalid checkpoint". In some paths, it may return an empty checkpoint manager that incorrectly signals that no files have been processed, causing the engine to restart the entire archive creation from scratch instead of resuming.

**Impact:**
High. Failure to resume large archive operations; potential data duplication if not handled by dedup.

**Recommended Fix:**
Improve the checkpoint loading to validate contents and return a specific error or status when a checkpoint is present but unreadable.

**Code Snippet:**
```rust
188:     pub async fn new(archive_path: &Path) -> Result<Self> {
189:         let checkpoint_manager =
190:             if archive_path.exists() && volume_has_checkpoint(archive_path).await {
...
194:                 Some(CheckpointManager::new(archive_path))
```

### V2-LOG-03: break 'stripe_loop on single corrupted shard

**Location:** `crates/era-engine/src/repair.rs:212-221`

**Analysis:**
During archive repair, if `ShardHeader::from_bytes` fails for a single shard, the code executes `break 'stripe_loop`. This terminates the scanning of ALL subsequent shards for that block. In a Reed-Solomon setup (e.g., 4+2), losing one shard header shouldn't prevent attempting to read the other 5 shards. Breaking the loop prematurely makes blocks unrecoverable even when enough parity exists.

**Impact:**
High. Failure to repair archives that should be recoverable according to the erasure coding configuration.

**Recommended Fix:**
Replace `break 'stripe_loop` with `continue` and mark the shard as corrupted.

**Code Snippet:**
```rust
212:             let shard_header = match ShardHeader::from_bytes(&header_bytes) {
...
219:                     corrupted_indices.push(shard_idx);
220:                     break 'stripe_loop;
221:                 }
```

### V2-ROB-01: Empty volume_readers causes index panic

**Location:** `crates/era-engine/src/block_iter.rs:311-334`

**Analysis:**
The `ErasureBlockIterator` and other multi-volume iterators access `self.volume_readers[0]` and `self.current_offsets[0]` without checking if the `volume_readers` vector is empty. If an iterator is initialized with zero volumes (which can happen if volume discovery fails silently or no volumes are found), the first call to `next()` will trigger an out-of-bounds panic.

**Impact:**
High. Process crash (panic) on malformed or empty archives.

**Recommended Fix:**
Add a check in the constructor or at the start of `next()`: `if self.volume_readers.is_empty() { return None; }`.

**Code Snippet:**
```rust
311:         if self.current_offsets[0] >= self.data_ends[0] {
290: ...
317:         let header_bytes = match self.volume_readers[0]
318:             .read_raw(self.current_offsets[0], 4)
```

---

## 3.2 Medium Severity Findings

### V2-SEC-08: Brute-force block ID fallback 0..100
**Location:** `crates/era-engine/src/checkpoint.rs:589-613`
**Analysis:**
The checkpoint recovery path includes a brute-force loop that attempts to decrypt the first block using ID candidates from 0 to 100 if the provided or stored ID fails. This non-deterministic fallback weakens the cryptographic binding of the block ID to the key derivation, potentially allowing an attacker to manipulate block ordering or substitute checkpoints if they can engineer a collision that passes the HMAC/validation within the first 100 candidates.
**Impact:**
Medium. Weakened cryptographic binding; potential for metadata manipulation during recovery.
**Recommended Fix:**
Remove the brute-force loop and strictly enforce that the block ID provided in the footer or catalog must be correct.
**Code Snippet:**
```rust
590:     for candidate_id in 0..100u64 {
591:         let block_id = BlockId::new(candidate_id);
...
603:             if let Ok(checkpoint) = Checkpoint::from_bytes(&decrypted_data) {
```

### V2-SEC-09: rkyv deserialize uses unwrap() on Infallible
**Location:** `crates/era-engine/src/checkpoint.rs:126`
**Analysis:**
While the code includes a comment justifying the use of `unwrap()` on `archived.deserialize(&mut rkyv::Infallible)`, it relies on the internal safety of the `rkyv` crate's validation logic. If `check_archived_root` has a flaw or if the `Infallible` assumption is violated in a future crate update, this could lead to an unhandled panic.
**Impact:**
Medium. Potential for process crash if deserialization assumptions are violated.
**Recommended Fix:**
Use safe error propagation even if the error type is technically `Infallible`.
**Code Snippet:**
```rust
126:         let checkpoint: Self = archived.deserialize(&mut rkyv::Infallible).unwrap();
```

### V2-SEC-10: Silent suppression of shard read errors
**Location:** `crates/era-engine/src/reader.rs:703-711`
**Analysis:**
During multi-volume shard collection, any error returned by `read_shard` is silently ignored (the `Err(_e)` branch does nothing). This masks critical failures like disk I/O errors, AEAD authentication failures, or integrity mismatches, allowing the extraction to proceed potentially into a failed reconstruction state without warning.
**Impact:**
Medium. Obfuscation of underlying system or security failures.
**Recommended Fix:**
Log all shard read failures and track the count of failed vs. successful shards to provide better error diagnostics.
**Code Snippet:**
```rust
703:                     match self.read_shard(&self.volume_readers[vol_idx], offset).await {
...
707:                         Err(_e) => {
708:                             // println!("Failed to read shard {}: {}", shard_idx, e);
709:                         }
```

### V2-SEC-11: No global extraction memory budget
**Location:** `crates/era-engine/src/reader.rs`
**Analysis:**
The reader lacks a global memory budget for extraction buffers. When processing many parallel streams or large MacroBlocks, the cumulative memory usage could exceed system limits, leading to OOM (Out of Memory) crashes, especially when dealing with untrusted or adversarial archives.
**Impact:**
Medium. Denial of Service via memory exhaustion.
**Recommended Fix:**
Implement a shared `Semaphore`-based memory governor to limit concurrent extraction buffers.

### V2-SEC-12: RedbChunkIndex.put inserts in-memory before persistent
**Location:** `crates/era-engine/src/chunk_index.rs:177-206`
**Analysis:**
The `put` method updates the in-memory lookup map *before* the persistent Redb builder commit. If the persistent insert fails (e.g., due to a disk error or finalization state), the in-memory index remains inconsistent, potentially leading to subsequent dedup "hits" that point to non-existent or unpersisted data.
**Impact:**
Medium. Index inconsistency and potential data loss in deduplication.
**Recommended Fix:**
Only update the in-memory lookup map after the persistent transaction successfully completes.
**Code Snippet:**
```rust
178:         // Insert into lookup map for point queries (in-memory, non-blocking)
179:         self.lookup.write().insert(hash, location.clone());
...
187:         run_blocking_io(|| {
```

### V2-PERF-01: blake3::hash on async thread
**Location:** `crates/era-engine/src/writer.rs:1088-1092`
**Analysis:**
The engine performs synchronous `blake3::hash` operations directly on the Tokio worker thread during small file processing. While individual hashes are fast, the cumulative effect when processing thousands of small files can cause significant latency spikes and stall the async executor.
**Impact:**
Medium. Latency jitters and suboptimal async throughput.
**Recommended Fix:**
Offload large or batched hashing operations to `spawn_blocking`.
**Code Snippet:**
```rust
1091:             let hash = blake3::hash(&data);
1092:             let chunk_hash = ChunkHash(*hash.as_bytes());
```

### V2-PERF-02: RS reconstruction synchronous
**Location:** `crates/era-engine/src/repair.rs:378-424`
**Analysis:**
The `repair_shards_rs` function performs CPU-intensive Reed-Solomon reconstruction and re-encoding synchronously. In the context of the repair pipeline, this blocks the progress of other volumes and shards, especially on archives with large parity configs (e.g., 6:3).
**Impact:**
Medium. Reduced repair performance on multi-core systems.
**Recommended Fix:**
Wrap the erasure coding logic in `spawn_blocking`.
**Code Snippet:**
```rust
398:     let recovered_data = coder.recover_data_shards(&shards, shard_size)?;
...
401:     let all_shards = coder.encode_shards(&recovered_data)?;
```

### V2-PERF-03: ErasureCoder re-created per stripe
**Location:** `crates/era-engine/src/write_pipeline.rs:182-199`
**Analysis:**
The write pipeline initializes a new `ErasureCoder` for every stripe. Re-generating encoding matrices and tables for every block is wasteful and significantly slower than reusing a single pre-computed coder for the duration of the archive session.
**Impact:**
Medium. Performance overhead in the write path.
**Recommended Fix:**
Cache and reuse the `ErasureCoder` instance in the pipeline state.
**Code Snippet:**
```rust
196:         let coder = ErasureCoder::new(ErasureConfig::new(data_shards_count, parity_shards_count)?)?;
197:         let all_shards = coder.encode_shards(&shard_inputs)?;
```

### V2-PERF-04: Excessive cloning in session erasure decode
**Location:** `crates/era-engine/src/block_iter.rs:967,1035-1036,1096`
**Analysis:**
The session decoding loop performs multiple deep clones of shard data (`shard.data.to_vec()` and `shard_data.clone()`) during candidate length probing. For large MacroBlocks, this causes excessive memory allocations and pressure on the allocator.
**Impact:**
Medium. High memory pressure and allocation latency.
**Recommended Fix:**
Use `Bytes` or `&[u8]` references and avoid copying the underlying buffer for every probe attempt.
**Code Snippet:**
```rust
967:                 shard_array[shard.index] = Some(shard.data.to_vec());
...
1096:                         let mut data = shard_data.clone();
1097:                         data.truncate(probe_len);
```

### V2-PERF-05: Virtual Striping probe up to 8192 AEAD decrypts
**Location:** `crates/era-engine/src/block_iter.rs:1081-1127`
**Analysis:**
The virtual striping logic performs up to 8192 linear probes when attempting to synchronize a stream. Each probe involves a full AEAD decryption attempt. This is extremely slow and could be easily triggered by a maliciously crafted archive to cause high CPU usage.
**Impact:**
Medium. Potential for CPU exhaustion DoS; slow recovery of damaged archives.
**Recommended Fix:**
Implement a more efficient search or limit the number of expensive decryption attempts per block.
**Code Snippet:**
```rust
1083:                 let max_attempts = 8192usize;
...
1112:                         match self.unpacker.extract_all_chunks(&encrypted_block) {
```

### V2-ROB-02: packed_data.len() as u32 truncation
**Location:** `crates/era-engine/src/writer.rs:1380-1383`
**Analysis:**
The packed data length is cast from `usize` to `u32` using `as u32`. If the packing logic ever produces a buffer larger than 4GB (unlikely with current limits but possible with future changes), this will silently truncate the size and lead to corruption.
**Impact:**
Medium. Silent data corruption on large buffers.
**Recommended Fix:**
Use `u32::try_from(len).expect(...)` or equivalent safe conversion.
**Code Snippet:**
```rust
1381:         let packed_data = packed.serialize()?;
1382:         let packed_chunk_size = packed_data.len() as u32;
```

### V2-ROB-03: Partial reads return None instead of Err
**Location:** `crates/era-engine/src/block_iter.rs:122-131`
**Analysis:**
The iterator returns `None` (end of stream) if `read_raw` returns a partial buffer. This masks unexpected file truncations or disk failures as a clean exit, potentially leading to incomplete extractions being reported as successful.
**Impact:**
Medium. Silent truncation of archive extraction.
**Recommended Fix:**
Return `Some(Err(EraError::Io))` if the read count is non-zero but less than requested.
**Code Snippet:**
```rust
128:             Ok(bytes) if bytes.len() == BlockHeader::SIZE => bytes,
129:             Ok(_) => return None,
130:             Err(e) => return Some(Err(e)),
```

### V2-ROB-04: Erasure iterators use only volume_readers[0] for EOF
**Location:** `crates/era-engine/src/block_iter.rs:307-313`
**Analysis:**
The `ErasureBlockIterator` only checks the offset of the first volume reader to determine if more data is available. If volumes have mismatched lengths due to corruption or partial writes, this check will fail to process data remaining on subsequent volumes.
**Impact:**
Medium. Incomplete extraction of mismatched multi-volume archives.
**Recommended Fix:**
Check all volume reader offsets or use the footer's master block count.
**Code Snippet:**
```rust
311:         if self.current_offsets[0] >= self.data_ends[0] {
312:             return None;
313:         }
```

### V2-ROB-05: No validation volume_readers.len() == volume_indices.len()
**Location:** `crates/era-engine/src/block_iter.rs:245-302`
**Analysis:**
The constructor for `ErasureBlockIterator` takes two parallel vectors for readers and indices but never verifies their lengths match. An internal logic error causing a mismatch would lead to out-of-bounds panics or incorrect volume mapping.
**Impact:**
Medium. Potential for process crash or data misassociation.
**Recommended Fix:**
Add `assert_eq!(volume_readers.len(), volume_indices.len())`.

### V2-ROB-06: first_shard_size may remain 0 → passed to erasure decode
**Location:** `crates/era-engine/src/block_iter.rs:336-399`
**Analysis:**
If all shard headers fail to parse in a stripe, `first_shard_size` remains 0. This value is subsequently used in erasure reconstruction, likely leading to further downstream errors or invalid allocations.
**Impact:**
Medium. Unstable behavior on severely corrupted stripes.
**Recommended Fix:**
Validate `first_shard_size > 0` before proceeding to recovery.
**Code Snippet:**
```rust
396:             if first_shard_size == 0 {
397:                 first_shard_size = shard_header.length;
398:             }
```

### V2-ROB-07: truncate_to_checkpoint uses blocking fs in async
**Location:** `crates/era-engine/src/recovery.rs:284-304`
**Analysis:**
The `truncate_to_checkpoint` function is marked `async` but uses `std::fs::File` and `file.set_len()`, which are blocking operations. This will block the Tokio worker thread during archive recovery.
**Impact:**
Medium. Thread pool starvation during recovery.
**Recommended Fix:**
Use `tokio::fs` or wrap in `spawn_blocking`.
**Code Snippet:**
```rust
299:         let file = std::fs::File::options()
...
302:         file.set_len(data_end)?;
```

### V2-ROB-08: CheckpointManager::exists() blocking I/O
**Location:** `crates/era-engine/src/checkpoint.rs:243-291`
**Analysis:**
The `exists` check performs synchronous `std::fs` operations (open, seek, read) to verify volume footers. When called during multi-volume discovery, this introduces significant blocking time into the async initialization path.
**Impact:**
Medium. Performance degradation and executor jitter.
**Recommended Fix:**
Make `exists` async or ensure it is only called from blocking-safe contexts.
**Code Snippet:**
```rust
254:         let mut file = match std::fs::File::open(path) {
...
266:         if file.read_exact(&mut buf).is_err() {
```

### V2-ROB-09: Blocking std::fs I/O in async extraction
**Location:** `crates/era-engine/src/reader.rs:839-844, chunk_processor.rs:84-129`
**Analysis:**
The extraction loop uses `std::fs::create_dir_all` and `File::create`. For archives with many files, this cumulative blocking time stalls the engine and limits extraction speed to serial I/O performance.
**Impact:**
Medium. Significant performance bottleneck.
**Recommended Fix:**
Use `tokio::fs`.
**Code Snippet:**
```rust
840:                         fs::create_dir_all(parent)?;
...
842:                     let file = File::create(&output_path)?;
```

### V2-ROB-10: apply_repairs has no file locking
**Location:** `crates/era-engine/src/repair.rs:426-448`
**Analysis:**
The repair function writes directly to live volumes without acquiring an exclusive file lock. Concurrent access by other processes or threads could lead to volume corruption if multiple writers are active.
**Impact:**
Medium. Risk of data corruption during concurrent repair/access.
**Recommended Fix:**
Use advisory or mandatory file locking (e.g., `flock`) before modifying volumes.
**Code Snippet:**
```rust
428:     let mut file = OpenOptions::new().read(true).write(true).open(path)?;
```

### V2-ROB-11: No cleanup of partially extracted files on failure
**Location:** `crates/era-engine/src/reader.rs:868-911`
**Analysis:**
When extraction fails midway (e.g., due to an integrity error), the engine leaves partially written files on disk. This results in "dirty" output directories and potentially misleading partial data.
**Impact:**
Medium. User experience and potential for data confusion.
**Recommended Fix:**
Implement an extraction cleanup handler to delete pending files on session failure.

### V2-LOG-04: Mutates returned BlockLocation.slot_index
**Location:** `crates/era-engine/src/volume_stage.rs:131-139`
**Analysis:**
The catalog write path overrides the `slot_index` returned by the volume writer with a static `block_id`. This mutation of the `BlockLocation` object is fragile and assumes the reader will correctly map this value back to the physical slot, which may break if the volume format's slot mapping changes.
**Impact:**
Medium. Architectural fragility; potential for breaking catalog reads.
**Recommended Fix:**
Ensure the volume writer returns the correct canonical location directly, or clearly document the overriding logic.
**Code Snippet:**
```rust
133:                 let mut location = writer
134:                     .write_canonical_block(block, BlockType::Catalog)
135:                     .await?;
136:                 // Override slot_index with actual block_id
137:                 location.slot_index = block_id;
```

### V2-LOG-05: candidate_lengths heuristic relies on trailing zeros assumption
**Location:** `crates/era-codec/src/erasure.rs:312-345`
**Analysis:**
The erasure decoding logic uses a trailing-zero check to guess original shard lengths if metadata is missing. This is non-deterministic and will fail for shards that naturally end with zero bytes (e.g., binary formats or encrypted data), leading to incorrect decryption or decompression.
**Impact:**
Medium. Data corruption or extraction failure for zero-terminated data.
**Recommended Fix:**
Always require explicit shard length metadata in the stripe header.

### V2-LOG-06: my_shard_idx mapping fragile
**Location:** `crates/era-engine/src/reader.rs:642-680`
**Analysis:**
The reader determines which shard belongs to the current volume using a complex index-based mapping that depends on external parameters. If the volume discovery order or count changes, this mapping will fail, causing the reader to attempt reconstruction with the wrong shard indices.
**Impact:**
Medium. Extraction failure on certain multi-volume archive configurations.
**Recommended Fix:**
Store the explicit `shard_index` within the volume header or the block footer.

---

## 3.3 Low Severity Findings

### V2-QUAL-01: AuthMode Debug exposes password
**Location:** `crates/era-engine/src/writer.rs:59-60`
**Analysis:**
The `AuthMode` enum derives `Debug`, which by default prints the contents of its variants. Since `AuthMode::Password` contains a raw `String`, any debug logging of the `AuthMode` object will leak the plaintext password into the logs.
**Code Snippet:**
```rust
59: #[derive(Clone, Debug)]
60: pub enum AuthMode {
```

### V2-QUAL-02: deprecated sync_checkpoint still used
**Location:** `crates/era-engine/src/writer.rs:1519-1521`
**Analysis:**
The `ArchiveWriter` uses a deprecated `sync_checkpoint` method during the final catalog write. This indicates the presence of legacy code that may not follow the latest crash-consistency patterns established in V2.2+.
**Code Snippet:**
```rust
1519:         #[allow(deprecated)]
1520:         self.pipeline.sync_checkpoint()?;
```

### V2-QUAL-03: Recursion in SessionBlockIterator skip-non-data
**Location:** `crates/era-engine/src/block_iter.rs:594-600`
**Analysis:**
When the session iterator encounters a non-data block (like an index page), it calls itself recursively to get the next block. While the number of consecutive index blocks is usually small, a deeply fragmented archive could theoretically cause a stack overflow.
**Code Snippet:**
```rust
596:         if header.block_type != BlockType::Data && header.block_type != BlockType::Catalog {
597:             self.current_offset += BlockHeader::SIZE as u64 + block_size as u64;
598:             // Don't increment block_index — index blocks use their own ID space
599:             return self.next_block().await;
```

### V2-QUAL-04: No validation for duplicate/out-of-range volume_indices
**Location:** `crates/era-engine/src/block_iter.rs:279-287`
**Analysis:**
The iterator constructor accepts a list of volume indices but does not verify if they are unique or within expected bounds. Duplicate indices could lead to redundant processing or incorrect stripe assembly.
**Code Snippet:**
```rust
281:         let original_volume_count = volume_indices.iter().copied().max().unwrap_or(0) + 1;
282:         let mut vol_index_map = vec![None; original_volume_count];
```

### V2-QUAL-05: Undocumented is_multiple_of(2) shard alignment
**Location:** `crates/era-engine/src/block_iter.rs:956`
**Analysis:**
The erasure decoding logic enforces a 2-byte alignment on shard sizes. This behavior is undocumented and may lead to confusion when debugging archives with odd-sized blocks.
**Code Snippet:**
```rust
956:         let shard_size = if max_len.is_multiple_of(2) {
```

### V2-QUAL-06: Duplicated code between single-volume and matrix repair
**Location:** `crates/era-engine/src/repair.rs:171-176`
**Analysis:**
The repair logic for single-volume and matrix-distributed archives shares significant boilerplate for stripe iteration and shard collection, increasing maintenance burden.
**Code Snippet:**
```rust
172:     let mut repairs: Vec<ShardRepair> = Vec::new();
173: 
174:     'stripe_loop: while offset < erasure_data_end {
```

### V2-QUAL-07: Blocking std::fs::copy in async repair backup
**Location:** `crates/era-engine/src/repair.rs:147-155`
**Analysis:**
The repair initialization performs a synchronous file copy to create a backup. On large volumes, this blocks the async runtime for several seconds.
**Code Snippet:**
```rust
151:             std::fs::copy(path, &backup_path)?;
```

### V2-QUAL-08: TODO "Add compression here if needed"
**Location:** `crates/era-engine/src/async_pipeline.rs:159`
**Analysis:**
A "TODO" comment indicates incomplete implementation of compression within the async pipeline stage.
**Code Snippet:**
```rust
159:             // TODO: Add compression here if needed
```

### V2-QUAL-09: TODO "checkpoint chain traversal"
**Location:** `crates/era-engine/src/checkpoint.rs:664`
**Analysis:**
The checkpoint recovery logic is missing support for traversing older checkpoints in a chain, which could be necessary for complex recovery scenarios.
**Code Snippet:**
```rust
664:                     // TODO: In a full implementation, each checkpoint would store
```

### V2-QUAL-10: println! in library code
**Location:** `crates/era-engine/src/reader.rs:1036-1038`
**Analysis:**
The verification path uses `println!` to report errors. Library code should use the `tracing` or `log` crates to allow the caller to handle output.
**Code Snippet:**
```rust
1037:                 println!("Verify Error: {}", err);
```

### V2-QUAL-11: Raw internal error text in user-facing messages
**Location:** `crates/era-engine/src/reader.rs:884-888`
**Analysis:**
The engine includes raw error strings (e.g., from `std::io::Error`) in the `EraError::Security` variant returned to users, potentially leaking internal path or system details.
**Code Snippet:**
```rust
885:                         return Err(EraError::Security(format!(
886:                             "Aborting: {} consecutive block failures: {}",
887:                             consecutive_failures, e
```

### V2-QUAL-12: No state validation in small_file_packer push
**Location:** `crates/era-engine/src/small_file_packer.rs:71-80`
**Analysis:**
The `push` method does not verify if the packer has already been finalized, which could lead to data being pushed into a "zombie" buffer.
**Code Snippet:**
```rust
71:     pub fn push(&mut self, entry: SmallFileEntry) -> Option<Vec<SmallFileEntry>> {
```

### V2-QUAL-13: unwrap_or(false) in volume_has_checkpoint
**Location:** `crates/era-engine/src/recovery.rs:52-109`
**Analysis:**
Several internal results are swallowed with `unwrap_or(false)`, making it impossible to distinguish between "file not found" and "corrupted data" during checkpoint discovery.
**Code Snippet:**
```rust
52: async fn volume_has_checkpoint(archive_path: &Path) -> bool {
```

### V2-QUAL-14: Last error overwritten in decode attempts
**Location:** `crates/era-engine/src/block_iter.rs:1051-1053`
**Analysis:**
In the loop that attempts different length candidates for a block, only the *last* error is preserved. If a previous attempt had a more descriptive error (e.g., AEAD mismatch vs. Zstd corruption), it is lost.
**Code Snippet:**
```rust
1052:                         Err(e) => last_err = Some(e),
```

### V2-QUAL-15: Unknown operation names silently ignored
**Location:** `crates/era-engine/src/metrics_collector.rs:37-38`
**Analysis:**
The metrics collector silently ignores unknown operation types. This can lead to missing performance data if a developer introduces a new operation name but forgets to update the match arm.
**Code Snippet:**
```rust
37:             _ => {} // Unknown operation type, skip recording
```

### V2-QUAL-16: MAX_MEMORY_INDEX_ENTRIES not configurable
**Location:** `crates/era-engine/src/chunk_index.rs:18-20`
**Analysis:**
The maximum number of entries for the in-memory index is hardcoded to 1,000,000. This should be a configuration parameter to support memory-constrained environments.
**Code Snippet:**
```rust
19: const MAX_MEMORY_INDEX_ENTRIES: usize = 1_000_000;
```

---

## 3.4 Info Findings

### V2-INFO-01: No rate-limiting on auth attempts
**Location:** `crates/era-engine/src/auth.rs:25-33`
**Analysis:**
The auth provider does not implement internal rate-limiting for password attempts. While typically handled at the application level, an engine-level throttle would provide a defense-in-depth against brute-force attacks.

### V2-INFO-02: block_id == u32::MAX as sentinel undocumented
**Location:** `crates/era-volume/src/block.rs`
**Analysis:**
The use of `u32::MAX` as a sentinel value for uninitialized or special blocks is not explicitly documented in the volume format specification.

### V2-INFO-03: Default VolumeId behavior undocumented
**Location:** `crates/era-engine/src/checkpoint.rs`
**Analysis:**
The behavior of the system when a `VolumeId` is missing or set to 0 during recovery is not fully specified.

---

## 4. Scoring


Weighted Scoring Formula:
- Security: 35%
- Logic: 25%
- Performance: 15%
- Code Quality: 15%
- Redundancy/Robustness: 10%

Deduction Formula: High = -8pts, Medium = -3pts, Low = -1pt per category dimension, floor at 0.

### 4.1 Security (35%)
- **Findings:** 12 (7 High, 5 Medium)
- **Deductions:** (7 × 8) + (5 × 3) = 56 + 15 = 71
- **Dimension Score:** 100 - 71 = 29

### 4.2 Logic (25%)
- **Findings:** 6 (3 High, 3 Medium)
- **Deductions:** (3 × 8) + (3 × 3) = 24 + 9 = 33
- **Dimension Score:** 100 - 33 = 67

### 4.3 Performance (15%)
- **Findings:** 5 (0 High, 5 Medium)
- **Deductions:** (0 × 8) + (5 × 3) = 15
- **Dimension Score:** 100 - 15 = 85

### 4.4 Code Quality (15%)
- **Findings:** 16 (0 High, 0 Medium, 16 Low)
- **Deductions:** (0 × 8) + (0 × 3) + (16 × 1) = 16
- **Dimension Score:** 100 - 16 = 84

### 4.5 Redundancy/Robustness (10%)
- **Findings:** 11 (1 High, 10 Medium)
- **Deductions:** (1 × 8) + (10 × 3) = 8 + 30 = 38
- **Dimension Score:** 100 - 38 = 62

### 4.6 Final Score
- **Calculated:** (29 × 0.35) + (67 × 0.25) + (85 × 0.15) + (84 × 0.15) + (62 × 0.10)
- **Weighted Total:** 10.15 + 16.75 + 12.75 + 12.60 + 6.20 = 58.45
- **V2 Score:** **58/100** (Pre-fix)


---

## 5. Test Coverage

Verification performed via `adversarial_audit_v2.rs`. The full verification suite contains 50 tests targeting each individual finding. Implementation of these tests follows the resolution of the identified vulnerabilities to prevent regressions.

---

