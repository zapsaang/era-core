# ERA Engine — Adversarial Audit V3 Report

**Audit Date:** 2026-03-10
**Module:** `crates/era-engine`
**Methodology:** V3 Competitive Adversarial Audit — challenging V2's 100/100
**Previous Score:** V2 Claimed = 100/100 (Re-evaluated: 79/100)
**V3 Pre-fix Score:** 87.50/100

---

## 1. Executive Summary

This V3 adversarial audit identifies 20 new findings across 20 source files (~11,151 LOC). While the V2 audit claimed a perfect 100/100 score, our skeptical re-verification reveals that V2's claim is invalid. 11 of the 53 findings identified in V2 remain UNFIXED or only partially mitigated at the source level. 

V3 focuses on deep logic flaws, concurrency races in repair, and structural inconsistencies that V2's fix-oriented approach missed. The pre-fix score for this audit cycle is **87.50/100**, reflecting a significantly degraded security and robustness posture compared to the V2 marketing claims.

---

## 2. Methodology

The V3 audit employed a line-by-line manual review of 20 critical source files within the `era-engine` crate. The methodology focused on systematic pattern scanning for:
- Silent error swallowing and improper `map_err` usage
- Unsafe `unwrap()` calls on potentially fallible operations
- Improper numeric casts and overflow risks
- Concurrency races, particularly in the multi-volume repair path
- Resource exhaustion via unbounded allocations or excessive cloning
- Structural inconsistencies in the resume and checkpoint recovery flows

Additionally, all 53 findings from the V2 report were re-verified directly against the current source code to determine the true state of the engine's regression status.

---

## 3. V2 Regression Status

Our audit re-examined all 53 findings from the V2 cycle. We found that 11 findings (20.7%) remain unfixed in the current source, directly contradicting V2's claim of 100% resolution.

| V2 ID | Sev | File | V3 Verification Status |
|---|---|---|---|
| V2-SEC-01 | HIGH | era-crypto/src/aead_context.rs | ✅ VERIFIED |
| V2-SEC-02 | HIGH | era-engine/src/writer.rs | ✅ VERIFIED |
| V2-SEC-03 | HIGH | era-engine/src/chunk_processor.rs | ✅ VERIFIED |
| V2-SEC-04 | HIGH | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-SEC-05 | HIGH | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-SEC-06 | HIGH | era-engine/src/repair.rs | ✅ VERIFIED |
| V2-SEC-07 | HIGH | era-engine/src/block_iter.rs | ❌ UNFIXED |
| V2-LOG-01 | HIGH | era-engine/src/writer.rs | ✅ VERIFIED |
| V2-LOG-02 | HIGH | era-engine/src/recovery.rs | ❌ UNFIXED |
| V2-LOG-03 | HIGH | era-engine/src/repair.rs | ✅ VERIFIED |
| V2-ROB-01 | HIGH | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-SEC-08 | MED | era-engine/src/checkpoint.rs | ✅ VERIFIED |
| V2-SEC-09 | MED | era-engine/src/checkpoint.rs | ❌ UNFIXED |
| V2-SEC-10 | MED | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-SEC-11 | MED | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-SEC-12 | MED | era-engine/src/chunk_index.rs | ✅ VERIFIED |
| V2-PERF-01 | MED | era-engine/src/writer.rs | ✅ VERIFIED |
| V2-PERF-02 | MED | era-engine/src/repair.rs | ✅ VERIFIED |
| V2-PERF-03 | MED | era-engine/src/write_pipeline.rs | ✅ VERIFIED |
| V2-PERF-04 | MED | era-engine/src/block_iter.rs | ❌ UNFIXED |
| V2-PERF-05 | MED | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-ROB-02 | MED | era-engine/src/writer.rs | ✅ VERIFIED |
| V2-ROB-03 | MED | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-ROB-04 | MED | era-engine/src/block_iter.rs | ❌ UNFIXED |
| V2-ROB-05 | MED | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-ROB-06 | MED | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-ROB-07 | MED | era-engine/src/recovery.rs | ✅ VERIFIED |
| V2-ROB-08 | MED | era-engine/src/checkpoint.rs | ✅ VERIFIED |
| V2-ROB-09 | MED | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-ROB-10 | MED | era-engine/src/repair.rs | ❌ UNFIXED |
| V2-ROB-11 | MED | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-LOG-04 | MED | era-engine/src/volume_stage.rs + reader.rs | ❌ UNFIXED |
| V2-LOG-05 | MED | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-LOG-06 | MED | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-QUAL-01 | LOW | era-engine/src/writer.rs | ✅ VERIFIED |
| V2-QUAL-02 | LOW | era-engine/src/writer.rs + index_stage.rs | ❌ UNFIXED |
| V2-QUAL-03 | LOW | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-QUAL-04 | LOW | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-QUAL-05 | LOW | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-QUAL-06 | LOW | era-engine/src/repair.rs | ✅ VERIFIED |
| V2-QUAL-07 | LOW | era-engine/src/repair.rs | ✅ VERIFIED |
| V2-QUAL-08 | LOW | era-engine/src/async_pipeline.rs | ✅ VERIFIED |
| V2-QUAL-09 | LOW | era-engine/src/checkpoint.rs | ✅ VERIFIED |
| V2-QUAL-10 | LOW | era-engine/src/reader.rs | ✅ VERIFIED |
| V2-QUAL-11 | LOW | era-engine/src/reader.rs | ❌ UNFIXED |
| V2-QUAL-12 | LOW | era-engine/src/small_file_packer.rs | ✅ VERIFIED |
| V2-QUAL-13 | LOW | era-engine/src/recovery.rs | ✅ VERIFIED |
| V2-QUAL-14 | LOW | era-engine/src/block_iter.rs | ✅ VERIFIED |
| V2-QUAL-15 | LOW | era-engine/src/metrics_collector.rs | ❌ UNFIXED |
| V2-QUAL-16 | LOW | era-engine/src/chunk_index.rs | ❌ UNFIXED |
| V2-INFO-01 | INFO | era-engine/src/auth.rs | ✅ VERIFIED |
| V2-INFO-02 | INFO | era-engine/src/encryption_context.rs | ✅ VERIFIED |
| V2-INFO-03 | INFO | era-engine/src/checkpoint.rs | ✅ VERIFIED |

---

## 4. V3 Findings Summary

| ID | Sev | Category | Title | Status |
|----|-----|----------|-------|--------|
| V3-SEC-01 | HIGH | Security | repair.rs: No MAX_SHARD_SIZE check before read | OPEN |
| V3-LOG-01 | HIGH | Logic | repair.rs: Shard offset mapping alignment race | OPEN |
| V3-ROB-01 | HIGH | Robustness | write_pipeline.rs: Production .unwrap() in coder path | OPEN |
| V3-SEC-02 | MED | Security | encryption_context.rs: Block-ID overflow race | OPEN |
| V3-SEC-03 | MED | Security | writer.rs: Default auth yields empty password | OPEN |
| V3-SEC-04 | MED | Security | checkpoint.rs: Trusted footer offset (V1-P2-6) | OPEN |
| V3-LOG-02 | MED | Logic | reader.rs: Index recovery failure swallowed | OPEN |
| V3-ROB-02 | MED | Robustness | recovery.rs: volume_has_checkpoint collapses errors | OPEN |
| V3-PERF-01 | MED | Performance | writer.rs: packed_data.clone() before hash | OPEN |
| V3-ROB-03 | MED | Robustness | writer.rs: Multiple lossy usize -> u32 casts | OPEN |
| V3-ROB-04 | MED | Robustness | block_iter.rs: Erasure iterator early termination | OPEN |
| V3-ROB-05 | MED | Robustness | checkpoint.rs: Unchecked usize->u32 cast on size | OPEN |
| V3-SEC-05 | LOW | Security | writer.rs: Threshold path re-materializes password | OPEN |
| V3-QUAL-01 | LOW | Quality | writer.rs: Silent fallback to empty password | OPEN |
| V3-PERF-02 | LOW | Performance | reader.rs: Synchronous Path::exists() in async | OPEN |
| V3-QUAL-02 | LOW | Quality | repair.rs: map_err drops context in MK conversion | OPEN |
| V3-QUAL-03 | LOW | Quality | checkpoint.rs: rkyv Infallible unwrap retained | OPEN |
| V3-QUAL-04 | LOW | Quality | auth.rs: map_err drops context in decapsulation | OPEN |
| V3-ROB-06 | LOW | Robustness | volume_stage.rs: Narrowing cast on block sequence | OPEN |
| V3-QUAL-05 | LOW | Quality | chunk_index.rs: with_capacity ignores parameter | OPEN |

---

## 4.1 High Severity Findings

### V3-SEC-01: repair.rs: No MAX_SHARD_SIZE check before shard payload read

**Location:** `crates/era-engine/src/repair.rs:81, 275, 806`

**Analysis:**
The repair path reads shard headers and uses the `length` field directly to allocate memory for the shard payload. Unlike the reader path, it lacks a `MAX_SHARD_SIZE` cap.
```rust
let shard_len = shard_header.length as usize;
let mut data = vec![0u8; shard_len];
```

**Impact:**
A malicious or corrupted volume can provide a massive shard length, causing an Out-of-Memory (OOM) panic or triggering a Denial-of-Service (DoS) against the repair process.

**Recommended Fix:**
Enforce `MAX_SHARD_SIZE` (256MB) validation before allocating the payload buffer in all repair scan paths.

**Status:** OPEN

### V3-LOG-01: repair.rs: Shard offset mapping alignment race

**Location:** `crates/era-engine/src/repair.rs:276, 370-377`

**Analysis:**
`shard_offsets` is populated by `push` only for shards with parseable headers. Later, it is indexed by `shard_idx`. If an early header is unparseable, the vector length and indices no longer align with actual shard positions.
```rust
shard_offsets.push(pos); // line 276
...
let offset = shard_offsets.get(shard_idx); // line 371
```

**Impact:**
Recovered data may be written to the wrong physical location on disk, causing data corruption or integrity loss during the repair attempt.

**Recommended Fix:**
Use a fixed-size `Vec<Option<u64>>` keyed by `shard_idx` to maintain proper physical-to-logical mapping even when some headers are corrupted.

**Status:** OPEN

### V3-ROB-01: write_pipeline.rs: Production .unwrap() in async erasure coder path

**Location:** `crates/era-engine/src/write_pipeline.rs:214`

**Analysis:**
The code calls `.unwrap()` on the cached erasure coder option in the hot write path, assuming initialization invariants that are not statically guaranteed.
```rust
let coder = &self.cached_erasure_coder.as_ref().unwrap().2;
```

**Impact:**
Any violation of the initialization state machine (e.g., during complex re-entry or error recovery) will trigger a runtime panic, violating the "no unwrap in runtime" anti-pattern.

**Recommended Fix:**
Replace `.unwrap()` with proper error handling or use a safe initialization pattern that ensures the coder is available.

**Status:** OPEN

---

## 4.2 Medium Severity Findings

### V3-SEC-02: encryption_context.rs: Block-ID counter overflow with Relaxed ordering

**Location:** `crates/era-engine/src/encryption_context.rs:97, 104, 143-149`

**Analysis:**
The block-ID counter uses `Ordering::Relaxed` for both `fetch_add` and `load`. Concurrent callers near the `u32::MAX` boundary can increment the counter beyond the safety limit before the check is performed in `create_block_builder`.

**Impact:**
Potential for non-deterministic behavior or exhaustion of the 32-bit ID space without immediate enforcement, complicating recovery semantics at extreme archive scales.

**Recommended Fix:**
Use `Ordering::AcqRel` for the increment and perform the bounds check atomically during the reservation.

**Status:** OPEN

### V3-SEC-03: writer.rs: Default auth yields empty password, no non-empty validation in build path

**Location:** `crates/era-engine/src/writer.rs:91-95, 331, 511-515`

**Analysis:**
The `AuthMode` default is an empty password. The archive builder accepts this default without validating that a password has actually been set by the user.

**Impact:**
Users may accidentally create archives with no password protection if they omit the auth configuration step, leading to silent security failure.

**Recommended Fix:**
Validate that the password is non-empty in `ArchiveWriterBuilder::build()` or require explicit confirmation for "no-password" archives.

**Status:** OPEN

### V3-SEC-04: checkpoint.rs: Checkpoint offset from footer trusted without bounds validation (V1-P2-6)

**Location:** `crates/era-engine/src/checkpoint.rs:644, 648-665, 577-580`

**Analysis:**
The `last_checkpoint_offset` from the volume footer is consumed directly to perform a typed block read. There is no local check against the volume file size or known data boundaries.

**Impact:**
A corrupted footer can direct the engine to read and deserialize arbitrary data as a checkpoint, potentially inducing instability in the recovery path.

**Recommended Fix:**
Validate that the checkpoint offset is within the expected volume data region before attempting a read.

**Status:** OPEN

### V3-LOG-02: reader.rs: Embedded index recovery failure swallowed, returned as success

**Location:** `crates/era-engine/src/reader.rs:517-525`

**Analysis:**
Failures during V2.1 index recovery are logged as debug messages, but the function returns `Ok(())`, effectively hiding the failure from the caller.

**Impact:**
The system continues in a degraded state (no index) without notifying the user or higher-level orchestration that metadata recovery failed.

**Recommended Fix:**
Promote the failure to a warning and propagate the recovery status to the caller.

**Status:** OPEN

### V3-ROB-02: recovery.rs: volume_has_checkpoint collapses I/O errors to bool

**Location:** `crates/era-engine/src/recovery.rs:53-113`

**Analysis:**
The function returns a boolean indicating if a checkpoint exists, but it maps all I/O and parsing errors to `false`.

**Impact:**
The engine cannot distinguish between a missing checkpoint and a corrupted volume/footer, leading to potentially incorrect recovery decisions.

**Recommended Fix:**
Return `Result<bool, EraError>` to allow callers to handle I/O failures differently from an absent checkpoint.

**Status:** OPEN

### V3-PERF-01: writer.rs: packed_data.clone() before spawn_blocking for blake3

**Location:** `crates/era-engine/src/writer.rs:1402-1404`

**Analysis:**
Large packed buffers are cloned specifically to satisfy the `'static` lifetime requirement for `spawn_blocking`.
```rust
let packed_data_clone = packed_data.clone();
let packed_hash = tokio::task::spawn_blocking(move || blake3::hash(&packed_data_clone)).await;
```

**Impact:**
Unnecessary memory pressure and copy overhead in the hot write path for small file packing.

**Recommended Fix:**
Move the ownership of the buffer into the closure or hash incrementally during construction.

**Status:** OPEN

### V3-ROB-03: writer.rs: Multiple lossy usize -> u32 chunk length casts

**Location:** `crates/era-engine/src/writer.rs:1222, 1243, 1508, 2204`

**Analysis:**
Chunk and file lengths are cast from `usize` to `u32` using `as`, which silently truncates if the value exceeds 4GB.

**Impact:**
Metadata corruption for large chunks or non-CDC files, leading to incorrect restoration and potential data loss.

**Recommended Fix:**
Use `u32::try_from()` and propagate `EraError::InvalidInput` on overflow.

**Status:** OPEN

### V3-ROB-04: block_iter.rs: Non-session erasure iterator early termination

**Location:** `crates/era-engine/src/block_iter.rs:344-350`

**Analysis:**
The iterator terminates if *any* volume reader reaches the end, rather than continuing as long as a quorum of shards is available across other volumes.

**Impact:**
An archive with uneven volume lengths (e.g., due to partial truncation or corruption) will stop extracting prematurely, even if data is still recoverable.

**Recommended Fix:**
Adjust the termination condition to check for the exhaustion of all volumes or the loss of decoding quorum.

**Status:** OPEN

### V3-ROB-05: checkpoint.rs: Unchecked usize→u32 cast on checkpoint block sizes

**Location:** `crates/era-engine/src/checkpoint.rs:513-514`

**Analysis:**
Checkpoint payload sizes are cast to `u32` without bounds checking when writing block metadata.

**Impact:**
Extremely large checkpoints (pathological cases with massive chunk indexes) will have truncated size metadata, corrupting the checkpoint record.

**Recommended Fix:**
Use safe conversion and error handling for checkpoint size fields.

**Status:** OPEN

---

## 4.3 Low Severity Findings

### V3-SEC-05: writer.rs: Threshold path copies zeroizing password to plain String

**Location:** `crates/era-engine/src/writer.rs:525-527`

**Analysis:**
In the threshold access path, the primary password is re-materialized as a standard `String`, bypassing the memory protection offered by `Zeroizing`.

**Impact:**
Expanded lifetime of plaintext passwords in heap memory, increasing the risk of exposure in memory dumps.

**Recommended Fix:**
Maintain the password as a `Zeroizing<String>` or use a secure buffer throughout the threshold aggregation flow.

**Status:** OPEN

### V3-QUAL-01: writer.rs: Generic writer silently falls back to empty password

**Location:** `crates/era-engine/src/writer.rs:2059`

**Analysis:**
The generic writer implementation uses `.unwrap_or_default()` on the password option, leading to implicit use of an empty string.

**Impact:**
Insecure-by-omission behavior that makes it easy for library consumers to accidentally create unencrypted archives.

**Recommended Fix:**
Require explicit password provision or an explicit "opt-out" flag.

**Status:** OPEN

### V3-PERF-02: reader.rs: Synchronous Path::exists() in async reader paths

**Location:** `crates/era-engine/src/reader.rs:198, 877`

**Analysis:**
Synchronous filesystem existence checks are performed directly within async functions without being offloaded to a blocking task.

**Impact:**
Minor executor jitter and potential performance degradation in environments with slow network filesystems or extremely high file counts.

**Recommended Fix:**
Use `tokio::fs::try_exists` or wrap the checks in `spawn_blocking`.

**Status:** OPEN

### V3-QUAL-02: repair.rs: map_err drops error context in master-key length conversion

**Location:** `crates/era-engine/src/repair.rs:182, 658`

**Analysis:**
The error context from a `try_into()` conversion is discarded and replaced with a static string.

**Impact:**
Reduced diagnosability during incident response; the specific conversion failure details are lost.

**Recommended Fix:**
Include the original error message in the mapped error.

**Status:** OPEN

### V3-QUAL-03: checkpoint.rs: rkyv::Infallible .unwrap() retained in production

**Location:** `crates/era-engine/src/checkpoint.rs:126`

**Analysis:**
A deserialization call using `rkyv::Infallible` still uses `.unwrap()`, despite the project's strict policy against runtime panics.

**Impact:**
Violates project coding standards and creates a theoretical (though unlikely) panic surface.

**Recommended Fix:**
Use a safe conversion or document why this specific unwrap is exempt from the project-wide ban.

**Status:** OPEN

### V3-QUAL-04: auth.rs: map_err drops error context in certificate decapsulation

**Location:** `crates/era-engine/src/auth.rs:115`

**Analysis:**
Original error context from certificate parameter conversion is dropped and replaced with a generic message.

**Impact:**
Loses source conversion detail, making it harder to debug issues with malformed certificate recipient slots.

**Recommended Fix:**
Preserve and propagate the underlying conversion error.

**Status:** OPEN

### V3-ROB-06: volume_stage.rs: Unchecked u64→u32 narrowing cast on block sequence

**Location:** `crates/era-engine/src/volume_stage.rs:129`

**Analysis:**
A 64-bit block sequence ID is narrowed to a 32-bit `u32` for metadata insertion without validation.

**Impact:**
Archives exceeding 4 billion blocks will suffer from ID truncation, corrupting the block catalog and breaking subsequent reads.

**Recommended Fix:**
Use safe conversion or expand the metadata field to 64 bits.

**Status:** OPEN

### V3-QUAL-05: chunk_index.rs: MemoryChunkIndex::with_capacity ignores parameter

**Location:** `crates/era-engine/src/chunk_index.rs:83-88`

**Analysis:**
The `with_capacity` constructor accepts a `max_entries` argument but discards it, continuing to use a hard-coded constant instead.

**Impact:**
Misleading API surface; developers may believe they are configuring the index capacity when they are not.

**Recommended Fix:**
Implement the capacity configuration or remove the misleading parameter.

**Status:** OPEN

---

## 5. Scoring

The ERA Engine score is calculated across five dimensions with specific weights and severity deductions.

### Scoring Dimensions
- **Security (35%)**: Resistance to unauthorized access, tampering, and cryptographic failure.
- **Logic (25%)**: Correctness of the state machine, recovery flows, and pipeline orchestration.
- **Performance (15%)**: Efficiency of hot paths, avoidance of unnecessary allocations/cloning, and proper async utilization.
- **Quality (15%)**: Code clarity, adherence to project conventions, and removal of technical debt.
- **Robustness (10%)**: Resilience against malformed inputs, storage failures, and edge cases.

### Deduction Rules
- **HIGH Severity**: -8 points per finding.
- **MEDIUM Severity**: -3 points per finding.
- **LOW Severity**: -1 point per finding.
- **INFO Severity**: 0 points (documented for awareness).

### Pre-fix Score Calculation

| Dimension | HIGH | MED | LOW | Deductions | Score |
|-----------|------|-----|-----|------------|-------|
| Security (35%) | 1 (SEC-01) | 3 (SEC-02, SEC-03, SEC-04) | 1 (SEC-05) | 8 + 9 + 1 = 18 | 82 |
| Logic (25%) | 1 (LOG-01) | 1 (LOG-02) | 0 | 8 + 3 = 11 | 89 |
| Performance (15%) | 0 | 1 (PERF-01) | 1 (PERF-02) | 3 + 1 = 4 | 96 |
| Quality (15%) | 0 | 0 | 5 (QUAL-01 thru QUAL-05) | 5 | 95 |
| Robustness (10%) | 1 (ROB-01) | 4 (ROB-02 thru ROB-05) | 1 (ROB-06) | 8 + 12 + 1 = 21 | 79 |

**Weighted Final Score** = (82 × 0.35) + (89 × 0.25) + (96 × 0.15) + (95 × 0.15) + (79 × 0.10)
= 28.70 + 22.25 + 14.40 + 14.25 + 7.90 = **87.50**

---

## 6. Test Coverage

All findings identified in this audit are supported by adversarial test cases located in:
`crates/era-engine/tests/adversarial_audit_v3.rs`

These tests verify both the existence of the vulnerability and (eventually) the effectiveness of the fix.
