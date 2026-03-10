# ADVERSARIAL AUDIT V4 — Deep Counter-Audit of "Fixed" Redb Migration

**Audit Date:** 2026-03-10
**Auditor:** Senior Rust Systems Engineer (Red Team, Round 4)
**Target:** `crates/era-engine/` (v8.1 Core Pipeline)
**Test Suite:** 219 adversarial audit tests across 6 suites (all passing)

---

## 1. Executive Summary

The V4 audit of `era-engine` reveals a maturing but still vulnerable core pipeline. While the 3-layer envelope encryption and matrix shard distribution provide strong cryptographic foundations, the state machine governing checkpoint persistence and recovery contains high-severity defects.

**High-Severity Finding (V4-STATE-01):** Checkpoint persistence state transition is broken — `sync_checkpoint()` in writer finalize routes to deprecated `CheckpointManager::sync()` no-op, making the apparent persistence barrier non-functional. This can lead to data loss on crash during/after finalize.

**V4 Inventory:** 0 Critical, 1 High, 6 Medium, 11 Low, 3 Informational (21 findings total).

**Risk Posture:** The module is currently rated **62/100 (Pre-Fix)**. The presence of a High-severity state machine defect (8.4) and several Medium-severity resilience issues prevents a production-ready rating. However, no critical cryptographic breaks or master key compromises were identified.

---

## 2. Findings Summary Table

| ID | Title | Severity | CVSS | Status |
|----|-------|----------|------|--------|
| **V4-STATE-01** | Checkpoint persistence transition broken in Writer Finalize | **High** | 8.4 | OPEN |
| **V4-STATE-02** | Resume accepted without persistent checkpoint provenance | Medium | 6.5 | OPEN |
| **V4-CRYPTO-01** | Certificate mode bypasses hybrid KEM combiner | Low | 3.7 | OPEN |
| **V4-CRYPTO-02** | Non-constant-time certificate key-id prefilter | Low | 2.7 | OPEN |
| **V4-ADVRS-01** | Missing shard-length cap in erasure block iterators | Medium | 6.2 | OPEN |
| **V4-ADVRS-02** | TOCTOU race in extraction path canonicalization | Medium | 5.5 | OPEN |
| **V4-ADVRS-03** | Checkpoint entry-count limits enforced post-materialization | Low | 2.5 | OPEN |
| **V4-ADVRS-04** | Virtual striping probe-step coarsening skips valid length | Low | 3.3 | OPEN |
| **V4-CONC-01** | Non-cooperative cancellation for long spawn_blocking tasks | Low | 3.3 | OPEN |
| **V4-CONC-02** | `checkpoint::exists()` collapses join failure to false | Low | 2.1 | OPEN |
| **V4-CONC-03** | Builder mutex held during blocking persistent insert | Low | 3.3 | OPEN |
| **V4-CONC-04** | Bounded channel + semaphore backpressure (Positive) | Info | 0.0 | OPEN |
| **V4-CONC-05** | Atomic block counter ordering correct (Positive) | Info | 0.0 | OPEN |
| **V4-TRUST-01** | Catalog redundancy degrades silently (Writer slot) | Medium | 5.3 | OPEN |
| **V4-TRUST-02** | Erasure stage parameter validation fully delegated | Low | 2.6 | OPEN |
| **V4-TRUST-03** | Packing stage threshold contracts not locally enforced | Low | 2.1 | OPEN |
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

### 7.1 Crypto Correctness (V4-CRYPTO-*)

#### V4-CRYPTO-01: Certificate Mode Bypasses Hybrid KEM Combiner
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **CVSS Score:** 3.7
- **Affected File(s):** `crates/era-engine/src/writer.rs:645`, `crates/era-engine/src/auth.rs:124`, `crates/era-crypto/src/certificate.rs:281-285,308-312,333-343`
- **Description:** Engine certificate auth path uses `EraKeyPair::encapsulate_for/decapsulate` (X25519 ECDH + HKDF) but does NOT invoke the `hybrid_kem` combiner path. The advertised hybrid (X25519+Kyber-768) security property is not realized on the certificate code path; practical security is classical X25519-based.
- **Impact:** Reduced security margin — post-quantum protection not active for certificate-mode archives.
- **Remediation:** Wire certificate auth through `hybrid_kem::{encapsulate,decapsulate}` or document that certificate mode is X25519-only until hybrid integration is complete.
- **PoC:** Code reference — verify ciphertext structure corresponds to certificate format (32-byte ephemeral public + encrypted_mk) rather than hybrid KEM 1120-byte combined ciphertext.
- **Status:** OPEN

#### V4-CRYPTO-02: Non-Constant-Time Certificate Key-ID Prefilter
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **CVSS Score:** 2.7
- **Affected File(s):** `crates/era-engine/src/auth.rs:104-107`
- **Description:** `CertificateProvider::try_unlock` uses `*slot_kid != my_kid[..8]` — a regular slice comparison that can short-circuit by first mismatch position, creating minor timing distinguishability for key-id prefixes.
- **Impact:** Under high-resolution local observation, an attacker could determine at which byte position the key-id diverges.
- **Remediation:** Replace with `subtle::ConstantTimeEq` or `ct_eq` for the 8-byte prefix comparison.
- **PoC:** Code reference — statistical timing analysis of mismatch positions.
- **Status:** OPEN

### 7.2 State Machine Integrity (V4-STATE-*)

#### V4-STATE-01: Checkpoint Persistence Transition Broken in Writer Finalize
- **Severity:** High
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`
- **CVSS Score:** 8.4
- **Affected File(s):** `crates/era-engine/src/writer.rs:1568`, `crates/era-engine/src/index_stage.rs:86-91`, `crates/era-engine/src/checkpoint.rs:386-389` (durable path exists but unused: `checkpoint.rs:483-551`)
- **Description:** Writer finalize calls `self.pipeline.sync_checkpoint()` expecting it to be a persistence barrier before catalog write. The actual call chain routes through `IndexStage::sync_checkpoint()` to deprecated `CheckpointManager::sync()` which is a no-op. The durable `commit_to_volume()/write_checkpoint()` path exists but is not invoked from the writer orchestration.
- **Impact:** Crash during/after finalize window loses the intended recovery point. Resume semantics become non-deterministic despite checkpoint-enabled configuration. Potential data loss.
- **Remediation:** Route writer finalize's checkpoint sync through the durable `write_checkpoint()` → `commit_checkpoint()` path instead of the deprecated no-op.
- **PoC:** `test_v4_state_01_checkpoint_sync_is_noop` — Build archive with `enable_checkpoint(true)`, inject crash after sync_checkpoint safe point, verify absence of durable typed checkpoint.
- **Status:** OPEN

#### V4-STATE-02: Resume Accepted Without Persistent Checkpoint Provenance
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`
- **CVSS Score:** 6.5
- **Affected File(s):** `crates/era-engine/src/writer.rs:823-833,852-863`, `crates/era-engine/src/checkpoint.rs:234-239`
- **Description:** `ArchiveWriterBuilder` with `RecoveryStrategy::Resume` uses `CheckpointManager::load_or_create` which returns a fresh manager in v2.2 compat mode without requiring a persisted checkpoint. This differs from `RecoverableWriter::new` which rejects resume when no prior checkpoint data exists.
- **Impact:** State machine silently transitions to "resume" while actually starting from near-fresh index state. Operator expectation mismatch; potential duplicate work and inconsistent skip behavior.
- **Remediation:** Enforce persisted checkpoint provenance check before entering resume path in `ArchiveWriterBuilder`. Return error if no durable checkpoint exists.
- **PoC:** `test_v4_state_02_resume_without_checkpoint` — Start checkpoint-enabled write, terminate before finalize, re-run with Resume, verify manager content is empty/fresh.
- **Status:** OPEN

### 7.3 Adversarial Input Resilience (V4-ADVRS-*)

#### V4-ADVRS-01: Missing Shard-Length Cap in Erasure Block Iterators
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS Score:** 6.2
- **Affected File(s):** `crates/era-engine/src/block_iter.rs:440-449,1031-1045`
- **Description:** `ErasureBlockIterator` and `SessionErasureBlockIterator` parse `ShardHeader.length` from untrusted input and call `read_raw(..., shard_len)` without enforcing `MAX_SHARD_SIZE`. Storage backend allocates `vec![0u8; len]` directly. This bypasses both engine-local and era-volume typed block path guards.
- **Impact:** Crafted shard headers with huge length values force large allocations before cryptographic validation — process OOM kill / extraction denial.
- **Remediation:** Add `MAX_SHARD_SIZE` bounds check after parsing `ShardHeader.length` and before `read_raw` allocation in both iterator implementations.
- **PoC:** `test_v4_advrs_01_shard_length_oom` — Construct archive with crafted shard header containing oversized length, attempt iteration, verify bounded rejection.
- **Status:** OPEN

#### V4-ADVRS-02: TOCTOU Race in Extraction Path Canonicalization
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:L`
- **CVSS Score:** 5.5
- **Affected File(s):** `crates/era-engine/src/reader.rs:925-1011`
- **Description:** Reader canonicalizes and validates path containment, then later performs file creation/writes in separate async/blocking operations. Between check and use, an attacker can swap path components with symlinks.
- **Impact:** In shared or attacker-writable extraction targets, race window enables redirecting output outside intended directory.
- **Remediation:** Use `O_NOFOLLOW` + `openat(2)` semantics or re-verify containment immediately before each write operation.
- **PoC:** `test_v4_advrs_02_toctou_symlink_race` — Set up concurrent symlink swap during extraction, verify detection or containment failure.
- **Status:** OPEN

#### V4-ADVRS-03: Checkpoint Entry-Count Limits Enforced Post-rkyv Materialization
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 2.5
- **Affected File(s):** `crates/era-engine/src/checkpoint.rs:118-147`
- **Description:** `Checkpoint::from_bytes` performs `check_archived_root` then deserializes the entire structure. `MAX_CHECKPOINT_ENTRIES` validation runs only after deserialize returns, so cardinality checks are not pre-materialization guards.
- **Impact:** Potential excess CPU/memory work during adversarial checkpoint payload handling; bounded in typical volume path but still a hardening deficit.
- **Remediation:** Add pre-deserialization entry count check by inspecting archived root metadata before full materialization.
- **PoC:** Code reference — inspect deserialization ordering.
- **Status:** OPEN

#### V4-ADVRS-04: Virtual Striping Probe-Step Coarsening Skips Valid Decode Length
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 3.3
- **Affected File(s):** `crates/era-engine/src/block_iter.rs:1243-1275`
- **Description:** Probe search for candidate shard lengths is capped by `MAX_PROBE_ATTEMPTS=256`. For large padding ranges, step increases (coarsens). A valid decode length can be skipped entirely, resulting in false recovery failure.
- **Impact:** Availability degradation — recoverable blocks flagged as unrecoverable under adversarial padding ranges.
- **Remediation:** Use binary search or finer-grained adaptive stepping that guarantees hitting all valid candidate lengths.
- **PoC:** Code reference — analyze probe step coverage for adversarial padding values.
- **Status:** OPEN

### 7.4 Cancellation & Concurrency (V4-CONC-*)

#### V4-CONC-01: Non-Cooperative Cancellation for Long spawn_blocking Tasks
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 3.3
- **Affected File(s):** `crates/era-engine/src/repair.rs:212,471,700`, `crates/era-engine/src/recovery.rs:322`
- **Description:** No cancellation token/select/abort integration around long blocking closures (large file copies, RS reconstruction). Dropping parent future does not preempt closure execution.
- Impact: Work continues after caller cancellation, extending disk/CPU pressure and delaying shutdown.
- **Remediation:** Integrate `CancellationToken` checks within long-running blocking closures.
- **PoC:** Code reference — trace spawn_blocking call sites without cancellation hooks.
- **Status:** OPEN

#### V4-CONC-02: checkpoint::exists() Collapses Join Failure to false
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N`
- **CVSS Score:** 2.1
- **Affected File(s):** `crates/era-engine/src/checkpoint.rs:256-307`
- **Description:** `.await.unwrap_or(false)` converts join panic/cancellation into "checkpoint absent" signal, potentially misleading recovery decision path.
- **Impact:** Recovery decision path misled after executor failure in probe task.
- **Remediation:** Propagate join errors as `EraError` instead of silently converting to `false`.
- **PoC:** Code reference — trace error collapse behavior.
- **Status:** OPEN

#### V4-CONC-03: Builder Mutex Held During Blocking Persistent Insert
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`
- **CVSS Score:** 3.3
- **Affected File(s):** `crates/era-engine/src/chunk_index.rs:204-223`
- **Description:** `builder` mutex held while performing insert that may include blocking I/O via `run_blocking_io`. Serializes concurrent writers under high ingest concurrency.
- **Impact:** Amplified tail latency under concurrent ingest workloads.
- **Remediation:** Release mutex before blocking I/O or use async-aware lock.
- **PoC:** Code reference — trace lock scope across blocking boundary.
- **Status:** OPEN

#### V4-CONC-04: Bounded Channel + Semaphore Backpressure (Positive Control)
- **Severity:** Informational
- **CVSS Vector:** N/A
- **CVSS Score:** 0.0
- **Affected File(s):** `crates/era-engine/src/async_pipeline.rs:116-118,143-148`
- **Description:** Pipeline uses bounded `mpsc` and semaphore permits; no unbounded channel found. Reduces OOM risk from producer overrun.
- **Impact:** Positive — good engineering practice confirmed.
- **Status:** OPEN

#### V4-CONC-05: Atomic Block Counter Ordering Correct (Positive Control)
- **Severity:** Informational
- **CVSS Vector:** N/A
- **CVSS Score:** 0.0
- **Affected File(s):** `crates/era-engine/src/encryption_context.rs:96-111`
- **Description:** `AtomicU64` uses `AcqRel/Acquire` with bounded `fetch_update`; errors after max representable `u32` block index. Prevents duplicate post-limit block IDs.
- **Impact:** Positive — correct concurrent implementation confirmed.
- **Status:** OPEN

### 7.5 Cross-Crate Trust (V4-TRUST-*)

#### V4-TRUST-01: Catalog Redundancy Degrades Silently When Writer Slot Absent
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`
- **CVSS Score:** 5.3
- **Affected File(s):** `crates/era-engine/src/volume_stage.rs` (`write_catalog_to_all`)
- **Description:** Stage assumes writer presence across all logical slots; absent writer is silently skipped via `if let Some(writer)`, returning fewer catalog copies without an explicit error or warning.
- **Impact:** Reduced catalog redundancy impairs recovery and increases susceptibility to data-loss after volume failure.
- **Remediation:** Log warning or return error when expected writer slot is absent during catalog fanout.
- **PoC:** `test_v4_trust_01_catalog_silent_skip` — Simulate missing writer slot, verify catalog copy count matches expected volume count.
- **Status:** OPEN

#### V4-TRUST-02: Erasure Stage Parameter Validation Fully Delegated
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L`
- **CVSS Score:** 2.6
- **Affected File(s):** `crates/era-engine/src/erasure_stage.rs`
- **Description:** No local sanity checks on erasure config shape; depends entirely on lower-layer validation.
- **Impact:** Future lower-layer behavior changes could introduce weak config without local guardrails.
- **Remediation:** Add local assertions on erasure config bounds (min data shards, max total shards).
- **PoC:** Code reference — verify absence of local config checks.
- **Status:** OPEN

#### V4-TRUST-03: Packing Stage Threshold Contracts Not Locally Enforced
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **CVSS Score:** 2.1
- **Affected File(s):** `crates/era-engine/src/packing_stage.rs`
- **Description:** Documentation states threshold percent bounds; enforcement delegated to `era_packing::StagingPool`.
- Impact: Contract drift between layers could cause unexpected flush behavior.
- **Remediation:** Add local `debug_assert!` or runtime check on threshold percent range.
- **PoC:** Code reference — verify absence of local threshold validation.
- **Status:** OPEN

#### V4-TRUST-04: Engine Re-Export Surface Lacks Misuse Guidance
- **Severity:** Informational
- **CVSS Vector:** N/A
- **CVSS Score:** 0.0
- **Affected File(s):** `crates/era-engine/src/lib.rs`
- **Description:** `lib.rs` re-exports `KeySession`, `EraCertificate`, `EraKeyPair`, `KeyEncapsulation` — advanced crypto types with minimal security-focused usage documentation.
- **Impact:** Misuse risk by downstream callers; no immediate exploit in-scope.
- **Status:** OPEN

### 7.6 Defense-in-Depth (V4-DEPTH-*)

#### V4-DEPTH-01: Missing chunk_idx Bounds Check Before Vector Index
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS Score:** 6.5
- **Affected File(s):** `crates/era-engine/src/chunk_processor.rs`
- **Description:** `state.chunks_written[chunk_idx] = true` — `chunk_idx` is trusted from mapping state with no explicit guard ensuring `< state.total_chunks`.
- **Impact:** Malformed/corrupted upstream mapping triggers panic and aborts extraction/verification flow — DoS via crafted archive.
- **Remediation:** Add bounds check `if chunk_idx >= state.chunks_written.len() { return Err(...) }` before indexing.
- **PoC:** `test_v4_depth_01_chunk_idx_oob` — Supply chunk_idx >= total_chunks, verify bounded error instead of panic.
- **Status:** OPEN

#### V4-DEPTH-02: No Secondary Path Traversal Hardening in Chunk Write Helper
- **Severity:** Medium
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`
- **CVSS Score:** 5.5
- **Affected File(s):** `crates/era-engine/src/chunk_processor.rs`
- **Description:** Module writes directly to caller-supplied `output_path`; relies on upstream sanitization contract with no secondary barrier.
- **Impact:** If upstream path sanitization invariants regress, this layer provides no defense-in-depth before filesystem writes.
- **Remediation:** Add local path containment check or `starts_with(output_root)` assertion in chunk write helper.
- **PoC:** `test_v4_depth_02_path_traversal_secondary` — Bypass upstream sanitization simulation, verify secondary check catches traversal.
- **Status:** OPEN

#### V4-DEPTH-03: Silent Drop of Unknown Metrics Weakens Operational Detection
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`
- **CVSS Score:** 2.7
- **Affected File(s):** `crates/era-engine/src/metrics_collector.rs`
- **Description:** Unknown metric names in `record_bytes_processed`, `record_operation`, `record_gauge` are silently ignored (`_ => {}`).
- **Impact:** Monitoring regressions/misconfigurations go unnoticed, weakening incident detection.
- **Remediation:** Log a warning or increment an "unknown_metric" counter for unrecognized keys.
- **PoC:** Code reference — verify silent drop pattern in match arms.
- **Status:** OPEN

#### V4-DEPTH-04: Operation Timing Counters Expose Coarse Workload Metadata
- **Severity:** Low
- **CVSS Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
- **CVSS Score:** 2.4
- **Affected File(s):** `crates/era-engine/src/metrics_collector.rs`
- **Description:** Timing and byte metrics can reveal archive activity profile when metrics backend visibility is broad.
- **Impact:** Limited confidentiality leakage of usage patterns (not key material/content).
- **Remediation:** Document metrics exposure surface and recommend restricted metrics backend access.
- **PoC:** Code reference — identify exposed metric fields.
- **Status:** OPEN

---

## 8. Pre-Fix CVSS Assessment

### 8.1 Severity Distribution

| Severity | Count | CVSS Range | Findings |
|----------|-------|------------|----------|
| Critical | 0 | 9.0–10.0 | — |
| High | 1 | 7.0–8.9 | V4-STATE-01 (8.4) |
| Medium | 6 | 4.0–6.9 | V4-STATE-02 (6.5), V4-DEPTH-01 (6.5), V4-ADVRS-01 (6.2), V4-ADVRS-02 (5.5), V4-DEPTH-02 (5.5), V4-TRUST-01 (5.3) |
| Low | 11 | 0.1–3.9 | V4-CRYPTO-01 (3.7), V4-ADVRS-04 (3.3), V4-CONC-01 (3.3), V4-CONC-03 (3.3), V4-CRYPTO-02 (2.7), V4-DEPTH-03 (2.7), V4-TRUST-02 (2.6), V4-ADVRS-03 (2.5), V4-DEPTH-04 (2.4), V4-TRUST-03 (2.1), V4-CONC-02 (2.1) |
| Informational | 3 | 0.0 | V4-CONC-04, V4-CONC-05, V4-TRUST-04 |
| **Total** | **21** | | |

### 8.2 Aggregate Statistics
- **Scored Findings:** 18
- **Mean CVSS:** 4.12
- **Median CVSS:** 3.3
- **Max CVSS:** 8.4 (V4-STATE-01)

### 8.3 Risk Narrative
The pre-fix security posture of `era-engine` is "Cautionary." While the cryptographic implementation is robust against traditional attacks, the state machine and resilience layers show significant gaps. The V4-STATE-01 defect is particularly concerning as it undermines the fundamental guarantee of archive durability. The large number of Low-severity findings indicates a lack of defensive depth, where single-point failures in validation logic can escalate to system instability (DoS) or minor data integrity issues. Additionally, the presence of 6 Medium-severity findings across multiple domains (state machine, adversarial input, trust boundary, and defense-in-depth) suggests systematic deficits in boundary validation and resilience.

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
The single High finding (broken checkpoint persistence) represents a significant data integrity risk. Six Medium findings across state machine, adversarial input, trust boundary, and defense-in-depth categories indicate systematic gaps. However, the absence of Critical findings, strong baseline crypto implementation (nonce freshness, AAD binding), and existing decompression bomb protections show solid foundational security.

**Scoring Breakdown:**
- **-15 points:** Presence of a High-severity defect (V4-STATE-01) that compromises data durability.
- **-10 points:** Accumulation of Medium-severity resilience and integrity issues (V4-STATE-02, V4-ADVRS-01, V4-DEPTH-01).
- **-10 points:** Significant defense-in-depth gaps (V4-DEPTH-02, V4-TRUST-01) and lack of input validation at trust boundaries.
- **+10 points:** Solid cryptographic foundations and correct use of hybrid KEM/AEAD primitives.
- **+5 points:** High-quality concurrency architecture with correct backpressure and ordering.
- **-2 points:** High volume of minor security hardening deficits (Low severity).

**Disclaimer:** This is a pre-fix rating. Post-fix rating will be computed in Task 16. A significant score increase is expected following the implementation of the recommended fixes.

---

## 11. Recommendations

1. **Fix V4-STATE-01 immediately:** Checkpoint persistence is a data loss risk; route writer finalize's checkpoint sync through the durable `write_checkpoint()` path.
2. **Implement Shard-Length Caps:** Add `MAX_SHARD_SIZE` bounds checks in erasure block iterators (V4-ADVRS-01) to prevent allocation-based DoS.
3. **Strengthen Indexing Safety:** Add explicit bounds checking for `chunk_idx` before vector indexing in `chunk_processor.rs` (V4-DEPTH-01).
4. **Enforce Checkpoint Provenance:** Require persistent checkpoint provenance (e.g., cryptographic binding to archive/epoch) for Resume operations (V4-STATE-02).
5. **Upgrade Certificate Security:** Consider wiring certificate auth through the hybrid KEM combiner (V4-CRYPTO-01) to realize the advertised post-quantum security property.

---

**Document Version:** 4.0 (Pre-Fix Draft)  
**Last Verified:** 2026-03-10  
**Next Review:** Task 16 (Post-Fix Assessment)
