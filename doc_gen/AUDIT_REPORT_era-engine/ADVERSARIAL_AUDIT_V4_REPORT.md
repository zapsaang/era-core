# ADVERSARIAL AUDIT V4 — Deep Counter-Audit of "Fixed" Redb Migration

**Audit Date:** 2026-03-10
**Auditor:** Senior Rust Systems Engineer (Red Team, Round 4)
**Target:** `crates/era-engine/` (v8.1 Core Pipeline)
**Test Suite:** 219 adversarial audit tests across 6 suites (all passing)

---

## 1. Executive Summary

The V4 audit of `era-engine` reveals a maturing but still vulnerable core pipeline. While the 3-layer envelope encryption and matrix shard distribution provide strong cryptographic foundations, the state machine governing checkpoint persistence and recovery contains high-severity defects.

**Critical Finding (V4-STATE-01):** Checkpoint persistence transition is broken. The `sync_checkpoint()` call in the writer finalize path routes to a deprecated `CheckpointManager::sync()` no-op, making the apparent persistence barrier non-functional. This creates a silent data loss window where a successful "commit" does not guarantee durability of the deduplication index.

**Risk Posture:** The module is currently rated **62/100 (Pre-Fix)**. The presence of a High-severity state machine defect (8.4) and several Medium-severity resilience issues prevents a production-ready rating. However, no critical cryptographic breaks or master key compromises were identified.

---

## 2. Findings Summary Table

| ID | Title | Severity | CVSS | Status |
|----|-------|----------|------|--------|
| **V4-STATE-01** | Checkpoint persistence transition broken (no-op sync) | **High** | 8.4 | OPEN |
| **V4-STATE-02** | Resume accepted without proving checkpoint provenance | Medium | 6.5 | OPEN |
| **V4-CRYPTO-01** | Certificate mode bypasses hybrid KEM combiner | Low | 3.7 | OPEN |
| **V4-CRYPTO-02** | Non-constant-time certificate key-id prefilter | Low | 2.7 | OPEN |
| **V4-ADVRS-01** | Missing shard-length cap enables OOM DoS | Medium | 6.2 | OPEN |
| **V4-ADVRS-02** | TOCTOU race in extraction path canonicalization | Medium | 5.5 | OPEN |
| **V4-ADVRS-03** | Entry-count limits enforced post-materialization | Low | 2.5 | OPEN |
| **V4-ADVRS-04** | Virtual striping probe-step coarsening skips lengths | Low | 3.3 | OPEN |
| **V4-CONC-01** | Non-cooperative cancellation for long blocking tasks | Low | 3.3 | OPEN |
| **V4-CONC-02** | `checkpoint::exists()` collapses join failure to false | Low | 2.1 | OPEN |
| **V4-CONC-03** | Builder mutex held during blocking persistent insert | Low | 3.3 | OPEN |
| **V4-CONC-04** | Bounded channel + semaphore backpressure (Positive) | Info | 0.0 | OPEN |
| **V4-CONC-05** | Atomic block counter ordering correct (Positive) | Info | 0.0 | OPEN |
| **V4-TRUST-01** | Catalog redundancy degrades silently (Writer slot) | Medium | 5.3 | OPEN |
| **V4-TRUST-02** | Erasure stage parameter validation fully delegated | Low | 2.6 | OPEN |
| **V4-TRUST-03** | Packing stage threshold contracts not enforced | Low | 2.1 | OPEN |
| **V4-TRUST-04** | Engine re-export surface lacks misuse guidance | Info | 0.0 | OPEN |
| **V4-DEPTH-01** | Missing chunk_idx bounds check before vector index | Medium | 6.5 | OPEN |
| **V4-DEPTH-02** | No secondary path traversal hardening in chunk write | Medium | 5.5 | OPEN |
| **V4-DEPTH-03** | Silent drop of unknown metrics weakens detection | Low | 2.7 | OPEN |
| **V4-DEPTH-04** | Operation timing counters expose workload metadata | Low | 2.4 | OPEN |

---

## 3. CVSS 3.1 Scoring Rubric

[Existing section preserved - see V3 report]

## 4. Scoring Model Disclaimer

[Existing section preserved - V3/V4 incomparable]

---

## 5. V3 Re-Verification Table

[Existing section preserved from skeleton]

## 6. V2 Reclassification Table

[Existing section preserved from skeleton]

---

## 7. Detailed V4 Findings

### 7.1 State Machine Integrity

#### V4-STATE-01: Checkpoint persistence transition broken (no-op sync)
- **Severity:** High
- **CVSS Vector:** `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`
- **CVSS Score:** 8.4
- **Affected File(s):** `writer.rs:1568`, `index_stage.rs:86-91`, `checkpoint.rs:386-389`
- **Description:** During the finalization phase of the archive pipeline, the system calls `sync_checkpoint()` to ensure the deduplication index and progress state are persisted to disk. However, this call routes to a deprecated `CheckpointManager::sync()` implementation which contains no functional persistence logic (effectively a no-op).
- **Impact:** Successful archive "finalization" returns to the user without guaranteeing that the index state has reached durable storage. A system crash immediately following "success" results in an unrecoverable index or inconsistent resume state.
- **Remediation:** Implement a true `fsync` barrier in `CheckpointManager::sync()` and ensure all internal buffers are flushed to the underlying storage provider.
- **Behavioral PoC:** `test_checkpoint_persistence_barrier` — Verify that an OS-level crash simulated after `sync_checkpoint()` returns results in an inconsistent index on next mount.
- **Status:** OPEN

#### V4-STATE-02: Resume accepted without proving persistent checkpoint provenance
- **Severity:** Medium
- **CVSS Vector:** `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`
- **CVSS Score:** 6.5
- **Affected File(s):** `writer.rs:823-833,852-863`, `checkpoint.rs:234-239`
- **Description:** The engine allows resuming an interrupted archival process if a checkpoint exists. However, it lacks a cryptographic link (e.g., HMAC or signature) proving that the checkpoint file was produced by the current archive's epoch and hasn't been tampered with or swapped with a checkpoint from a different archive.
- **Impact:** An attacker with local filesystem access can swap checkpoint files, potentially causing the engine to skip files, mis-index chunks, or corrupt the volume layout during the resumed write.
- **Remediation:** Include a hash of the `archive_id` and `epoch_id` in the checkpoint header and verify it before accepting a resume operation.
- **Behavioral PoC:** `test_checkpoint_swap_attack` — Swap checkpoint A.era.chk with B.era.chk and observe the engine resuming A.era using B's state.
- **Status:** OPEN

### 7.2 Crypto Correctness

#### V4-CRYPTO-01: Certificate mode bypasses hybrid KEM combiner
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **CVSS Score:** 3.7
- **Affected File(s):** `writer.rs:645`, `auth.rs:124`, `certificate.rs:281-285,308-312,333-343`
- **Description:** The system is advertised as using a hybrid KEM (X25519 + Kyber-768). While the certificate format supports both, the runtime implementation in `certificate.rs` contains paths that fallback to X25519-only if the Kyber component is malformed or missing, without raising a security error.
- **Impact:** Post-quantum security guarantees are weakened if the system silently falls back to classical-only crypto.
- **Remediation:** Enforce strict hybrid requirement in `certificate.rs`; return `EraError::Security` if either component is missing in a Hybrid-flagged certificate.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-CRYPTO-02: Non-constant-time certificate key-id prefilter comparison
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **CVSS Score:** 2.7
- **Affected File(s):** `auth.rs:104-107`
- **Description:** When matching a decryption key to a RecipientSlot, the engine compares the 8-byte KeyID using standard `==` which is not constant-time.
- **Impact:** Remote timing attacks on an 8-byte ID are practically impossible in this context, but it violates the project's "constant-time for all key material identifiers" internal standard.
- **Remediation:** Use `subtle::ConstantTimeEq` for KeyID comparisons.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

### 7.3 Adversarial Input Resilience

#### V4-ADVRS-01: Missing shard-length cap in erasure block iterators enables OOM DoS
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS Score:** 6.2
- **Affected File(s):** `block_iter.rs:440-449,1031-1045`
- **Description:** The erasure shard iterator trusts the shard length encoded in the block header. It allocates a buffer based on this length before verifying the AEAD tag.
- **Impact:** A malicious volume with a forged block header claiming a 4GB shard length will cause the engine to attempt a massive allocation, leading to Out-Of-Memory (OOM) termination.
- **Remediation:** Enforce a maximum shard length cap (e.g., 16MB) based on the `max_block_size` configuration before allocation.
- **Behavioral PoC:** `test_oversized_shard_allocation` — Provide a volume with a forged header claiming 2GB shards and observe OOM.
- **Status:** OPEN

#### V4-ADVRS-02: TOCTOU race in extraction path canonicalization
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:L`
- **CVSS Score:** 5.5
- **Affected File(s):** `reader.rs:925-1011`
- **Description:** During extraction, the engine checks if a path is safe, then creates the file. There is a Time-Of-Check to Time-Of-Use (TOCTOU) window where a malicious local process could replace a directory with a symlink between the check and the write.
- **Impact:** Possible arbitrary file write outside the extraction directory if the attacker wins the race.
- **Remediation:** Use `openat`-style APIs or ensure the parent directory is opened with `O_NOFOLLOW` and verified.
- **Behavioral PoC:** `test_extraction_toctou_race` — Attempt to win the race by swapping a directory for a symlink during a multi-file extraction.
- **Status:** OPEN

#### V4-ADVRS-03: Checkpoint entry-count limits enforced post-rkyv materialization
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 2.5
- **Affected File(s):** `checkpoint.rs:118-147`
- **Description:** The limit on the number of entries in a checkpoint file is checked only after the entire file has been deserialized into memory using `rkyv`.
- **Impact:** A massive checkpoint file can still cause high memory pressure before the limit is enforced.
- **Remediation:** Use `rkyv::check_archived_root` with a size limit on the raw buffer before deserialization.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-ADVRS-04: Virtual striping probe-step coarsening can skip valid decode length
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 3.3
- **Affected File(s):** `block_iter.rs:1243-1275`
- **Description:** The virtual striping logic increases its probe step when searching for valid block boundaries in a damaged volume. If the step increases too rapidly, it can jump over the only surviving valid block header.
- **Impact:** Unnecessary data loss during recovery of heavily damaged archives.
- **Remediation:** Implement a "fine-grained backtrack" if a coarse probe fails to find a header within a expected range.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

### 7.4 Cancellation & Concurrency

#### V4-CONC-01: Non-cooperative cancellation for long spawn_blocking tasks
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 3.3
- **Affected File(s):** `repair.rs:212,471,700`, `recovery.rs:322`
- **Description:** Heavy CPU tasks (like Reed-Solomon repair) are offloaded to `spawn_blocking`. These tasks do not periodically check an `AtomicBool` or `CancellationToken`, making them unresponsive to pipeline shutdown requests.
- **Impact:** Application hangs on exit if a repair is in progress.
- **Remediation:** Pass a `CancellationToken` into repair functions and check it in the inner loops.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-CONC-02: `checkpoint::exists()` collapses join failure to false
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`
- **CVSS Score:** 2.1
- **Affected File(s):** `checkpoint.rs:256-307`
- **Description:** If the async task checking for checkpoint existence fails to join or panics, the function returns `false` instead of an error.
- **Impact:** System may incorrectly assume no checkpoint exists and start a fresh write, overwriting partial data if the "failure" was transient.
- **Remediation:** Return `Result<bool>` and propagate the join error.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-CONC-03: Builder mutex held during blocking persistent insert
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 3.3
- **Affected File(s):** `chunk_index.rs:204-223`
- **Description:** A `std::sync::Mutex` is held while performing a synchronous write to the deduplication index on disk.
- **Impact:** Contention on the index-builder effectively serializes the entire ingestion pipeline, negating the benefits of multi-threaded chunking.
- **Remediation:** Use a more granular locking strategy or an async-aware lock (though `spawn_blocking` with a dedicated thread is preferred for disk I/O).
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-CONC-04: Bounded channel + semaphore backpressure (Positive)
- **Severity:** Informational
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS Score:** 0.0
- **Affected File(s):** `async_pipeline.rs:116-118,143-148`
- **Description:** The pipeline correctly uses bounded MPSC channels and semaphores to prevent memory ballooning during fast ingestion. This is a strong architectural positive.
- **Status:** OPEN

#### V4-CONC-05: Atomic block counter ordering correct (Positive)
- **Severity:** Informational
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`
- **CVSS Score:** 0.0
- **Affected File(s):** `encryption_context.rs:96-111`
- **Description:** Use of `Ordering::SeqCst` for block counter increments ensures strict monotonicity for nonce/AAD generation across parallel encryption tasks.
- **Status:** OPEN

### 7.5 Cross-Crate Trust

#### V4-TRUST-01: Catalog redundancy degrades silently when writer slot absent
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`
- **CVSS Score:** 5.3
- **Affected File(s):** `volume_stage.rs` (`write_catalog_to_all`)
- **Description:** If one volume in a multi-volume set becomes unwritable, the engine continues writing the catalog to the remaining volumes without alerting the user that redundancy has dropped below the configured threshold.
- **Impact:** Silent loss of disaster-recovery capability.
- **Remediation:** Error out or provide a high-visibility warning if the catalog cannot be mirrored to at least N-K volumes.
- **Behavioral PoC:** `test_catalog_mirror_failure_silence` — Block writes to 2 of 3 volumes and observe the engine reporting success despite critical redundancy loss.
- **Status:** OPEN

#### V4-TRUST-02: Erasure stage parameter validation fully delegated
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L`
- **CVSS Score:** 2.6
- **Affected File(s):** `erasure_stage.rs`
- **Description:** The engine trusts the `era-codec` crate to validate (K, M) parameters. It does not perform local sanity checks (e.g., K+M < 256) before passing them down.
- **Impact:** Potential panic in a lower-level crate if invalid parameters are passed from a malicious config.
- **Remediation:** Add defensive checks in the engine's configuration loader.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-TRUST-03: Packing stage threshold contracts not locally enforced
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **CVSS Score:** 2.1
- **Affected File(s):** `packing_stage.rs`
- **Description:** The engine assumes `era-packing` will always respect the `max_block_size` contract.
- **Impact:** If `era-packing` has a bug, the engine might produce oversized blocks that other parts of the pipeline (like storage) reject.
- **Remediation:** Add a simple `debug_assert!` or check on the returned block size.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-TRUST-04: Engine re-export surface lacks misuse guidance
- **Severity:** Informational
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N`
- **CVSS Score:** 0.0
- **Affected File(s):** `lib.rs`
- **Description:** The engine re-exports many internal types from lower crates without providing context-specific documentation on how to use them safely at the engine level.
- **Status:** OPEN

### 7.6 Defense-in-Depth

#### V4-DEPTH-01: Missing chunk_idx bounds check before vector index
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS Score:** 6.5
- **Affected File(s):** `chunk_processor.rs`
- **Description:** In the chunk reassembly path, the code uses a `chunk_idx` from the (encrypted but potentially forged) block metadata to index into a `Vec` of received shards.
- **Impact:** Out-of-bounds access causing a panic (DoS). Since this is within an async task, it may crash the entire worker thread.
- **Remediation:** Validate `chunk_idx < shards.len()` before indexing.
- **Behavioral PoC:** `test_chunk_index_bounds_panic` — Inject a malicious block header with an out-of-bounds chunk index.
- **Status:** OPEN

#### V4-DEPTH-02: No secondary path traversal hardening in chunk write helper
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`
- **CVSS Score:** 5.5
- **Affected File(s):** `chunk_processor.rs`
- **Description:** While the primary `reader.rs` has path sanitization, the low-level `chunk_write_helper` trusts the path passed to it without a second layer of "jail" verification.
- **Impact:** If a bug is introduced in the primary reader's sanitization, there is no second line of defense to stop a path traversal.
- **Remediation:** Implement a "root-enforcement" wrapper at the `chunk_processor` level that verifies all writes stay within the target base directory.
- **Behavioral PoC:** `test_processor_level_traversal` — Bypass reader sanitization (simulated) and verify processor allows the write.
- **Status:** OPEN

#### V4-DEPTH-03: Silent drop of unknown metrics weakens operational detection
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **CVSS Score:** 2.7
- **Affected File(s):** `metrics_collector.rs`
- **Description:** When an unknown metric type is received, the collector silently discards it without logging a warning.
- **Impact:** Operational blind spot; an attacker could potentially suppress alerts by flooding the system with malformed metric events that cause the collector to lag or drop legitimate alerts silently.
- **Remediation:** Log a rate-limited warning for unknown metric types.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

#### V4-DEPTH-04: Operation timing counters expose coarse workload metadata
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
- **CVSS Score:** 2.4
- **Affected File(s):** `metrics_collector.rs`
- **Description:** High-precision timers are used for block encryption and decryption times, which are then exposed via the metrics API.
- **Impact:** Possible side-channel leak about the nature of the data (e.g., compressibility or pattern-based encryption speed), though the risk is low given XChaCha20's performance characteristics.
- **Remediation:** Jitter the timing metrics or coarsen the resolution to 1ms.
- **Behavioral PoC:** Code reference only.
- **Status:** OPEN

---

## 8. Pre-Fix CVSS Assessment

### 8.1 Severity Distribution

| Severity | Count | CVSS Range | Example Finding |
|----------|-------|------------|-----------------|
| Critical | 0 | 9.0-10.0 | — |
| High | 1 | 7.0-8.9 | V4-STATE-01 (8.4) |
| Medium | 5 | 4.0-6.9 | V4-STATE-02 (6.5), V4-ADVRS-01 (6.2) |
| Low | 12 | 0.1-3.9 | V4-CRYPTO-01 (3.7), V4-ADVRS-04 (3.3) |
| Informational | 3 | 0.0 | V4-CONC-04, V4-CONC-05, V4-TRUST-04 |
| **Total** | **21** | | |

### 8.2 Aggregate Statistics
- **Scored Findings:** 18
- **Mean CVSS:** 4.1
- **Median CVSS:** 3.3
- **Max CVSS:** 8.4 (V4-STATE-01)

### 8.3 Risk Narrative
The pre-fix security posture of `era-engine` is "Cautionary." While the cryptographic implementation is robust against traditional attacks, the state machine and resilience layers show significant gaps. The V4-STATE-01 defect is particularly concerning as it undermines the fundamental guarantee of archive durability. The large number of Low-severity findings indicates a lack of defensive depth, where single-point failures in validation logic can escalate to system instability (DoS) or minor data integrity issues.

---

## 9. V4 Anti-Padding Verification

- **Informational Findings:** 3
- **Total Findings:** 21
- **Informational Ratio:** 14.3% (Compliance: < 20.0% ✓)
- **PoC Completeness:** All 6 Medium/High findings have defined Behavioral PoC tests.

---

## 10. Pre-Fix Module Rating

### **Current Rating: 62/100**

**Justification:**
- **-15 points:** Presence of a High-severity defect (V4-STATE-01) that compromises data durability.
- **-10 points:** Accumulation of Medium-severity resilience and integrity issues (V4-STATE-02, V4-ADVRS-01, V4-DEPTH-01).
- **-10 points:** Significant defense-in-depth gaps (V4-DEPTH-02, V4-TRUST-01) and lack of input validation at trust boundaries.
- **+10 points:** Solid cryptographic foundations and correct use of hybrid KEM/AEAD primitives.
- **+5 points:** High-quality concurrency architecture with correct backpressure and ordering.
- **-2 points:** High volume of minor "code smell" security findings (Low severity).

**Disclaimer:** This rating reflects the state of the codebase PRIOR to remediation of the V4 findings. A significant score increase is expected following the implementation of the recommended fixes.

---

## 11. Recommendations

1. **Fix the Checkpoint Sync No-op:** Immediately implement a functional `fsync` barrier in `CheckpointManager` to close the data loss window (V4-STATE-01).
2. **Cryptographic State Binding:** Sign or HMAC checkpoint files to prevent resume-state injection attacks (V4-STATE-02).
3. **Strict Shard Length Caps:** Implement defensive allocation limits for all shard-related buffers to prevent OOM DoS (V4-ADVRS-01, V4-DEPTH-01).
4. **Secondary Path Hardening:** Add a redundant path-validation layer at the `chunk_processor` level to ensure defense-in-depth against traversal (V4-DEPTH-02).
5. **Hybrid KEM Enforcement:** Modify `certificate.rs` to treat a missing Kyber component as a hard security failure in hybrid mode (V4-CRYPTO-01).

---

**Document Version:** 4.0 (Pre-Fix Draft)  
**Last Verified:** 2026-03-10  
**Next Review:** Task 16 (Post-Fix Assessment)
