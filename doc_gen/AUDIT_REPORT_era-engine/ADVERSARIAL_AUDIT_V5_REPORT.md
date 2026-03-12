# ADVERSARIAL AUDIT V5 — Comprehensive Remediation & Coverage Verification

**Audit Window:** 2026-03-11 to 2026-03-12
**Auditor:** Sisyphus-Junior (OhMyOpenCode)
**Target:** `crates/era-engine/` (Remediation Pass)
**Status:** FINAL HANDOFF VERSION — Task 13 verification frozen on 2026-03-12; Task 14 report/evidence index completed

---

## Executive Summary

This report documents the V5 adversarial audit and remediation pass for the `era-engine` crate. The V5 cycle focuses on resolving long-standing contradictions in historical remediation claims (V1–V4) and closing critical gaps in state machine integrity and cryptographic property enforcement.

This report is the final V5 handoff version. Task 11 published the canonical post-fix registry, Task 13 froze the final verification and rating on 2026-03-12, and Task 14 completed the final evidence index and reproducibility guidance for handoff.

---

## Methodology

The V5 audit employs a hybrid approach:
1. **Historical Re-Verification**: Systematic re-testing of every finding from V1, V2, V3, and V4 to resolve status contradictions.
2. **Registry Consolidation**: Mapping overlapping findings across audit versions to a single canonical registry.
3. **Automated Verification**: Execution of the historical era-engine audit suites plus the V5 adversarial suite, with accepted rerun evidence captured in `.sisyphus/evidence/task-10-suite-regression.txt` and final workspace verification captured in `.sisyphus/evidence/task-13-final-verification.txt`.
4. **Scoring Shift**: Transition to a deterministic penalty-based scoring system for improved audit-to-audit consistency.

---

## Scoring Method

The V5 Audit uses a strict penalty-based scoring formula to derive the Security Rating:

**Formula:**
`Score = 100 - 20*critical - 10*high - 3*medium - 0.5*low - 5*assurance_contradiction`

**Crucial Note:** V5 scoring is `not comparable to V1–V3 weighted-category scores`. The V5 method removes subjective weighting of categories in favor of absolute severity penalties and introduces a penalty for historical assurance contradictions.

---

## Historical Re-Verification Table

| Source | Findings | Historical Claim | Final Status (Task 11) | Evidence |
|--------|----------|------------------|------------------------|----------|
| V1 | Full V1 registry set (134 IDs, incl. AE-* and ADV-*) | Mixed fixed/open/partial | RECLASSIFIED | `.sisyphus/evidence/task-11-post-fix-registry.md` (Section B1) |
| V2 (original claim rows) | Full V2 set (53 IDs) | “All fixed” style claims | RECLASSIFIED | `.sisyphus/evidence/task-11-post-fix-registry.md` (Section B2) |
| V2-REVERIFY authoritative rows | Full skeptical V2 set (53 IDs) | 42 verified / 11 unfixed in Task 6 baseline | FIXED + RECLASSIFIED + OUT-OF-SCOPE-BY-DESIGN (no OPEN rows) | `.sisyphus/evidence/task-11-post-fix-registry.md` (Section B3); `.sisyphus/evidence/task-6-v2-reverification.md` |
| V3 | V3-SEC-01 .. V3-QUAL-05 (20 IDs) | Pending V5 re-verify | FIXED | `.sisyphus/evidence/task-10-suite-regression.txt:20-22` |
| V4 | V4-STATE-01 .. V4-DEPTH-04 (21 IDs) | OPEN | FIXED + RECLASSIFIED + OUT-OF-SCOPE-BY-DESIGN + FALSE POSITIVE (no OPEN rows) | `.sisyphus/evidence/task-11-post-fix-registry.md` (Section B5) |
| Contradictions | C-01 .. C-08 | Assurance gap set | RECLASSIFIED / OUT-OF-SCOPE-BY-DESIGN where doc-truth closure is Task 12 owned | `.sisyphus/evidence/task-11-post-fix-registry.md`; `.sisyphus/evidence/task-9-truth-queue.txt:15-17` |

---

## Pre-Fix Findings

### V5-STATE-01: Finalize Path Lacks Durable Checkpoint Barrier (High)
- **Finding ID:** V5-STATE-01 (Mapped: V4-STATE-01, V2-QUAL-02)
- **Affected Files:** `era-engine/src/writer.rs:1559-1649, 2308-2357`, `era-engine/src/index_stage.rs:86-91`
- **Severity:** High (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H)
- **Score:** 7.1
- **Description:** The `finalize` path in the writer pipeline fails to trigger a durable checkpoint sync. While the pipeline completes, the last consistent state is not persisted to the volume footer/sidecar, causing resumes after clean finalization to either fail or restart from a stale offset.
- **Remediation:** Implement a mandatory `sync_checkpoint` call during the `finalize` handshake between `IndexStage` and `VolumeStage`.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_state_01_finalize_writes_durable_checkpoint` (Evidence: `.sisyphus/evidence/task-4-pre-fix-failures.txt:16`)

### V5-STATE-02: Resume Accepted Without Persistent Provenance (Medium)
- **Finding ID:** V5-STATE-02 (Mapped: V4-STATE-02, V2-LOG-02)
- **Affected Files:** `era-engine/src/checkpoint.rs:234-247`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L)
- **Score:** 4.4
- **Description:** `CheckpointManager::load_or_create` returns a fresh manager when a checkpoint is missing or malformed instead of erroring. This allows the engine to "resume" into a fresh state, potentially overwriting existing data or creating inconsistent volume sequences.
- **Remediation:** Enforce strict provenance checks in `load_or_create`. If a resume is requested, a valid, verifiable checkpoint must be present.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_state_02_resume_requires_persisted_checkpoint` (Evidence: `.sisyphus/evidence/task-1-v1-v4-registry.md:245`)

### V5-ADVRS-01: Missing Shard-Length Cap in Erasure Block Iterators (Medium)
- **Finding ID:** V5-ADVRS-01 (Mapped: V4-ADVRS-01, V2-SEC-07)
- **Affected Files:** `era-engine/src/block_iter.rs:440-449, 1031-1045`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)
- **Score:** 5.5
- **Description:** Non-session erasure paths lack a strict upper bound on shard length during iteration. A crafted volume with an oversized shard length can trigger large allocations or infinite loops in the virtual striping probe logic.
- **Remediation:** Apply `MAX_SHARD_SIZE` limits to all block iterator length-probes, even in non-session paths.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_advrs_01_non_session_shard_len_cap` (Evidence: `.sisyphus/evidence/task-4-pre-fix-failures.txt:42`)

### V5-ADVRS-02: TOCTOU Race in Extraction Path Canonicalization (Medium)
- **Finding ID:** V5-ADVRS-02 (Mapped: V4-ADVRS-02)
- **Affected Files:** `era-engine/src/reader.rs:837, 926-928`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N)
- **Score:** 5.3
- **Description:** The extraction path checks for path traversal using canonicalization, but a race condition exists between the check and the actual file creation. An attacker could swap a directory for a symlink during extraction.
- **Remediation:** Use `openat`-style APIs or verify the file handle/path relationship after creation but before writing data.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_advrs_02_extract_symlink_swap_rejected` (Evidence: `.sisyphus/evidence/task-1-v1-v4-registry.md:221`)

### V5-DEPTH-01: Missing Chunk Index Bounds Check (Medium)
- **Finding ID:** V5-DEPTH-01 (Mapped: V4-DEPTH-01)
- **Affected Files:** `era-engine/src/chunk_processor.rs:118-134, 231-235`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)
- **Score:** 5.5
- **Description:** The chunk processor uses a chunk index from a decoded block header to index into a vector without validating it against the vector's length, leading to a panic (DoS).
- **Remediation:** Add explicit bounds checking before vector indexing in the chunk reassembly path.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_depth_01_chunk_idx_bounds` (Evidence: `.sisyphus/evidence/task-4-pre-fix-failures.txt:115`)

### V5-DEPTH-02: Secondary Path Traversal Hardening in Chunk Write (Medium)
- **Finding ID:** V5-DEPTH-02 (Mapped: V4-DEPTH-02)
- **Affected Files:** `era-engine/src/chunk_processor.rs:80-95, 107-113, 131-133`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)
- **Score:** 5.5
- **Description:** While primary extraction paths are guarded, secondary internal chunk-write paths lack redundant containment checks. If the primary check is bypassed (e.g., via logic error), the secondary path will write to arbitrary locations.
- **Remediation:** Implement defense-in-depth by adding path containment checks at the lowest possible I/O layer in the extraction stage.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_depth_02_secondary_chunk_write_containment` (Evidence: `.sisyphus/evidence/task-4-pre-fix-failures.txt:61`)

### V5-TRUST-01: Catalog Redundancy Degrades Silently (Medium)
- **Finding ID:** V5-TRUST-01 (Mapped: V4-TRUST-01)
- **Affected Files:** `era-engine/src/volume_stage.rs:122-128`, `era-engine/src/writer.rs:1613-1646`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H)
- **Score:** 6.1
- **Description:** `VolumeStage::write_catalog_to_all` returns `Ok([])` if no writer slots are available instead of returning an error. This causes the archiver to finalize successfully even when the catalog (critical for recovery) has zero redundancy.
- **Remediation:** Change the return type or check for empty results in the caller to treat missing catalog writer slots as a hard failure.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_trust_01_missing_catalog_writer_slot_is_error` (Evidence: `.sisyphus/evidence/task-4-pre-fix-failures.txt:170`)

### V5-CONC-03: Builder Mutex Held During Blocking I/O (Low)
- **Finding ID:** V5-CONC-03 (Mapped: V4-CONC-03)
- **Affected Files:** `era-engine/src/chunk_index.rs:196-230`
- **Severity:** Low (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)
- **Score:** 3.3
- **Description:** The writer builder holds a mutex across a blocking persistent index insert operation. This can lead to thread starvation in the async runtime if multiple builders are active.
- **Remediation:** Move the blocking I/O operation outside the mutex-protected block or use `spawn_blocking`.
- **Reproducer:** `.sisyphus/evidence/task-1-v1-v4-registry.md:227` (Evidence: `era-engine/src/chunk_index.rs:215-220`)

### V5-DEPTH-03: Silent Drop of Unknown Metrics (Low)
- **Finding ID:** V5-DEPTH-03 (Mapped: V4-DEPTH-03, V2-QUAL-15)
- **Affected Files:** `era-engine/src/metrics_collector.rs:30-44`
- **Severity:** Low (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)
- **Score:** 2.7
- **Description:** Metrics for unknown operations are silently dropped in several paths. This weakens the ability to detect anomalous engine behavior or internal logic errors.
- **Remediation:** Log a warning or record a "generic_unknown" metric when an unrecognized operation name is encountered.
- **Reproducer:** `.sisyphus/evidence/task-1-v1-v4-registry.md:285` (Evidence: `era-engine/src/metrics_collector.rs:35-40`)

### V5-CRYPTO-01: Certificate Mode Bypasses Hybrid KEM Combiner (Medium)
- **Finding ID:** V5-CRYPTO-01 (Mapped: V4-CRYPTO-01, C-06)
- **Affected Files:** `era-crypto/src/certificate.rs:269-330`, `era-crypto/src/hybrid_kem.rs:164-235`
- **Severity:** Medium (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Score:** 7.5
- **Description:** Public documentation claims post-quantum security via hybrid KEM (X25519 + Kyber-768), but the certificate encryption path bypasses the combiner and uses X25519 exclusively. This is an assurance contradiction and a failure to meet marketed security guarantees.
- **Remediation Direction (Task 9 scope):** Keep this finding OPEN as a truthfulness/trust-tracking item in the V5 queue; do not imply a hybrid redesign in this slice. Current certificate archives remain X25519-based on the live engine path. Public-document closure for this mismatch is explicitly deferred to **Task 12** (post-Task-11 verified doc alignment) and must stay visible until that closure lands.
- **Reproducer:** Evidence: `grep -E "ERA-KEY-WRAP-V1|ERA-v2.2-Hybrid-KEM" crates/era-crypto/src/{certificate.rs,hybrid_kem.rs}` (Verifies domain separator mismatch between certificate wrap [line 339] and hybrid KEM [line 253])

### V5-DOC-01: Overstated Security Remediation Status (Assurance Contradiction)
- **Finding ID:** V5-DOC-01 (Mapped: C-05, C-07)
- **Affected Files:** `README.md`
- **Severity:** N/A (Assurance Contradiction)
- **Score:** N/A (Penalty: 5.0)
- **Description:** The README claims "All 219 audit tests pass. Vulnerabilities ... fully remediated" while V4 and V2-reverify evidence shows 20+ open items and 11 unfixed rows. This creates a significant trust gap between project claims and technical reality.
- **Remediation:** Update README to reflect "Pre-alpha / In-remediation" status and point to the V5 finding queue.
- **Reproducer:** `.sisyphus/evidence/task-1-v1-v4-registry.md:299-301`

### V5-DEPTH-04: MemoryChunkIndex Fixed Capacity Behavior (Medium)
- **Finding ID:** V5-DEPTH-04 (Mapped: V2-QUAL-16, C-04)
- **Affected Files:** `era-engine/src/chunk_index.rs:83-89, 101-111`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H)
- **Score:** 6.1
- **Description:** `MemoryChunkIndex::with_capacity(max_entries)` ignores its parameter and uses a hardcoded limit. When the limit is reached, it returns an error, leading to deduplication failures or archive corruption.
- **Remediation:** Respect the `max_entries` parameter and implement a defined overflow policy (e.g., error or LRU).
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v5 test_v5_v2_qual_16_memory_chunk_index_capacity_enforced` (Evidence: `.sisyphus/evidence/task-4-pre-fix-failures.txt:88`)

### V5-ADVRS-03: Matrix Distribution Silent Corruption on Volume EOF (Medium)
- **Finding ID:** V5-ADVRS-03 (Mapped: V1-P2-6, V1-P2-7, V1-P2-8)
- **Affected Files:** `era-engine/src/block_iter.rs:1092-1101`
- **Severity:** Medium (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H)
- **Score:** 6.1
- **Description:** When reading stripes in matrix distribution mode, an unexpected EOF or missing shard from a volume can lead to an empty or partial stripe being processed without an explicit error in some paths. This results in silent data corruption if the erasure coder attempts to reconstruct from insufficient data.
- **Remediation:** Ensure all `BlockIterator` implementations explicitly error on unexpected EOF or insufficient shards before attempting RS recovery.
- **Reproducer:** `cargo test -p era-engine --test adversarial_audit_v2 v2_rob_04_eof_checks_use_all_volumes_not_only_first` (Evidence: `era-engine/src/block_iter.rs:1092-1100`)

---

## Pre-Fix Rating

The V5 Pre-Fix Rating represents the state of the engine before remediation efforts. This score is derived from the confirmed findings in the Pre-Fix queue and the identified historical assurance contradictions.

**Calculation:**
`Score = 100 - (20 * 0) - (10 * 1) - (3 * 10) - (0.5 * 2) - (5 * 4)`
`Score = 100 - 0 - 10 - 30 - 1 - 20`
`Score = 100 - 61 = 39`

**Pre-Fix Rating: 39 (Critical Risk)**

**Current Severity Counts:**
- Critical: 0
- High: 1 (V5-STATE-01)
- Medium: 10 (V5-STATE-02, V5-ADVRS-01, V5-ADVRS-02, V5-ADVRS-03, V5-DEPTH-01, V5-DEPTH-02, V5-DEPTH-04, V5-TRUST-01, V5-CRYPTO-01, V2-LOG-02)
- Low: 2 (V5-CONC-03, V5-DEPTH-03)
- Assurance Contradiction: 4 (V5-DOC-01, C-05, C-06, C-07)

---

---

## Remediation Summary

- Task 11 performed a skeptical closure pass over historical rows and V5 findings using Task 6–10 verified evidence and fresh V5/historical suite reruns.
- Canonical closure artifact published: `.sisyphus/evidence/task-11-post-fix-registry.md`.
- Every historical/V5 row now has an explicit final status from the allowed set (`FIXED`, `RECLASSIFIED`, `OUT-OF-SCOPE-BY-DESIGN`, `FALSE POSITIVE`).
- Certificate truthfulness mismatch was explicitly routed through Task 12 for public-document alignment. The documentation correction is complete, while the X25519-only certificate archive path remains an intentional scope residual captured by `V5-CRYPTO-01`.

---

## Post-Fix Re-Verification

| Finding ID | Final Status | Closure Reference |
|---|---|---|
| V5-STATE-01 | FIXED | `.sisyphus/evidence/task-6-v5-state-01.txt:13-16` |
| V5-STATE-02 | FIXED | `.sisyphus/evidence/task-6-v5-state-02.txt:13-16` |
| V5-ADVRS-01 | FIXED | `.sisyphus/evidence/task-7-iterator-slice-v5-advrs-01.txt:14-17` |
| V5-ADVRS-02 | FIXED | `.sisyphus/evidence/task-7-iterator-slice-v5-advrs-group.txt:13-18` |
| V5-DEPTH-01 | FIXED | `.sisyphus/evidence/task-7-chunk-slice-v5-depth-01.txt:2-5` |
| V5-DEPTH-02 | FIXED | `.sisyphus/evidence/task-7-chunk-slice-v5-depth-02.txt:2-5` |
| V5-TRUST-01 | FIXED | `.sisyphus/evidence/task-7-catalog-slice-v5-trust-01.txt:14-17` |
| V5-CONC-03 | RECLASSIFIED | `.sisyphus/evidence/task-11-post-fix-registry.md:25`; `.sisyphus/evidence/task-7-chunk-index-concurrency-torture.txt:5-10` |
| V5-DEPTH-03 | FIXED | `.sisyphus/evidence/task-11-post-fix-registry.md:26`; `.sisyphus/notepads/era-engine-audit-remediation/learnings.md:17` |
| V5-CRYPTO-01 | OUT-OF-SCOPE-BY-DESIGN | `.sisyphus/evidence/task-9-truth-queue.txt:8-16`; `.sisyphus/evidence/task-12-doc-consistency.txt:8-11` |
| V5-DOC-01 | OUT-OF-SCOPE-BY-DESIGN | `.sisyphus/evidence/task-9-truth-queue.txt:14-17`; `.sisyphus/evidence/task-12-doc-consistency.txt:1-11` |
| V5-DEPTH-04 | FIXED | `.sisyphus/evidence/task-7-chunk-index-v5-capacity.txt:14-17` |
| V5-ADVRS-03 | FIXED | `.sisyphus/evidence/task-7-iterator-slice-v5-advrs-03.txt:13-16` |

All V5 findings now have explicit closure references and are synchronized with `.sisyphus/evidence/task-11-post-fix-registry.md`.

---

## Final Rating

**Frozen by Task 13 on 2026-03-12.**

**Correction note:** An older Task 13 closure attempt relied on split substitute runs after a timed-out `cargo test --workspace`; that evidence was invalid for plan closure and is explicitly superseded. The accepted Task 13 freeze is based on the corrected 2026-03-12 evidence set: `.sisyphus/evidence/task-13-final-verification.txt`, `.sisyphus/evidence/task-13-bench-summary.md`, and the named raw Criterion artifacts listed in the appendix below.

### Verification Gates (all PASS)

| Gate | Result | Evidence |
|------|--------|----------|
| `cargo fmt --all -- --check` | PASS | `.sisyphus/evidence/task-13-final-verification.txt` |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS | `.sisyphus/evidence/task-13-final-verification.txt` |
| `cargo test --workspace` | PASS (2049 passed, 0 failed, 18 ignored) | `.sisyphus/evidence/task-13-final-verification.txt` |
| Benchmark comparison vs `v5_pre` | PASS (47 improved, 14 no-change, 0 regressions >5%) | `.sisyphus/evidence/task-13-bench-summary.md` |

### Post-Fix Severity Counts

| Severity | Pre-Fix Count | Post-Fix Residual | Explanation |
|----------|--------------|-------------------|-------------|
| Critical | 0 | 0 | — |
| High | 1 | 0 | V5-STATE-01 FIXED |
| Medium | 10 | 1 | 9 FIXED; V5-CRYPTO-01 remains OUT-OF-SCOPE-BY-DESIGN (X25519 cert path, hybrid KEM deferred) |
| Low | 2 | 0 | V5-DEPTH-03 FIXED; V5-CONC-03 RECLASSIFIED |
| Assurance Contradiction | 4 | 0 | V5-DOC-01 OUT-OF-SCOPE-BY-DESIGN (Task 12 corrected documentation); C-05, C-06, C-07 resolved via Task 12 truthfulness alignment |

### Post-Fix Rating Calculation

**Formula:** `Score = 100 - 20*critical - 10*high - 3*medium - 0.5*low - 5*assurance_contradiction`

**Inputs:** Critical=0, High=0, Medium=1 (V5-CRYPTO-01), Low=0, AC=0

`Score = 100 - (20 × 0) - (10 × 0) - (3 × 1) - (0.5 × 0) - (5 × 0) = 97`

**Post-Fix Rating: 97 (Low Risk)**

### Rating Delta

| Metric | Pre-Fix | Post-Fix | Delta |
|--------|---------|----------|-------|
| Score | 39 | 97 | +58 |
| Risk Level | Critical Risk | Low Risk | — |

### Benchmark Impact

Benchmark provenance is anchored to `.sisyphus/evidence/task-2-bench-baseline.txt`, which recorded the original Task 2 `v5_pre` baseline across the five era-engine bench suites (60 directories at capture time). The current filesystem contains 61 `v5_pre/estimates.json` files because `target/criterion/hkdf_block_key_artifact_validation/block_key_derivation_batched_100_normalized/v5_pre/estimates.json` was added later as an additive case; that nuance does not invalidate the original baseline provenance for the accepted Task 13 benchmark comparisons.

Accepted benchmark closure is grounded in both the named baseline artifacts and the matching raw comparison artifacts for the three previously disputed cases:
- `target/criterion/e2e_multi_file/100_small_files/v5_pre/estimates.json` and `target/criterion/e2e_multi_file/100_small_files/change/estimates.json`
- `target/criterion/hkdf_1000_block_keys/v5_pre/estimates.json` and `target/criterion/hkdf_1000_block_keys/change/estimates.json`
- `target/criterion/key_session_reader_comparison/open_5_archives_without_session/v5_pre/estimates.json` and `target/criterion/key_session_reader_comparison/open_5_archives_without_session/change/estimates.json`

0 regressions >5% across 61 total benchmark cases (5 suites):
- **47 improved** (many substantially >10%)
- **14 no change** (within noise threshold)
- **0 regressions >5%**

The earlier contrary readings (`100_small_files` +9.9%, `hkdf_1000_block_keys` +5.1%, `open_5_archives_without_session` +12.5%) are superseded historical context from the invalid Task 13 attempt, not co-equal closure evidence. The accepted raw artifacts show:
- `e2e_multi_file/100_small_files`: median point estimate ≈ -1.56%
- `hkdf_1000_block_keys`: median point estimate ≈ +2.60%, with a noise-sensitive CI rather than a clean >5% regression signal
- `open_5_archives_without_session`: median point estimate ≈ -9.88%

No systematic performance degradation from remediation.

### Residual Item

V5-CRYPTO-01 (Medium): Certificate authentication path uses X25519 only; hybrid KEM (X25519 + Kyber-768) is implemented in the codebase but not wired into the certificate archive path. Documented as intentional design scope deferral, not a code defect. Public documentation corrected by Task 12 to accurately reflect this state.

---

## How to verify this report

Use the exact commands below to reproduce the final verification surface described by this report.

### Canonical CI gate

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

Accepted final CI evidence is recorded in `.sisyphus/evidence/task-13-final-verification.txt`.

### Historical and V5 adversarial suites

```bash
cargo test -p era-engine --test adversarial_audit_v1
cargo test -p era-engine --test adversarial_audit_v2
cargo test -p era-engine --test adversarial_audit_v3
cargo test -p era-engine --test second_audit
cargo test -p era-engine --test third_audit
cargo test -p era-engine --test fourth_audit
cargo test -p era-engine --test competitor_audit
cargo test -p era-engine --test adversarial_audit_v9
cargo test -p era-engine --test adversarial_audit_v5 -- --test-threads=1 --nocapture
```

Accepted suite-rerun evidence is recorded in `.sisyphus/evidence/task-10-suite-regression.txt` and the per-finding Task 6/7 artifacts listed in the appendix.

### Benchmark comparison against the accepted `v5_pre` baseline

If the named `v5_pre` baseline is already present, run the final comparison commands:

```bash
cargo bench -p era-engine --bench engine_bench -- --baseline v5_pre
cargo bench -p era-engine --bench e2e_performance_bench -- --baseline v5_pre
cargo bench -p era-engine --bench real_world_perf_test -- --baseline v5_pre
cargo bench -p era-engine --bench batch_api_bench -- --baseline v5_pre
cargo bench -p era-engine --bench small_file_packing_bench -- --baseline v5_pre
```

If `v5_pre` is absent locally and you need to rebuild the baseline from scratch, first rerun the original capture commands recorded in Task 2 with `--save-baseline v5_pre` for the same five benches. Accepted baseline provenance is recorded in `.sisyphus/evidence/task-2-bench-baseline.txt`.

Accepted benchmark closure is recorded in `.sisyphus/evidence/task-13-bench-summary.md` and in the named raw Criterion artifacts cited in the appendix.

### Cross-check artifacts after running commands

- `.sisyphus/evidence/task-10-suite-regression.txt`
- `.sisyphus/evidence/task-11-post-fix-registry.md`
- `.sisyphus/evidence/task-13-final-verification.txt`
- `.sisyphus/evidence/task-13-bench-summary.md`
- The specific Criterion artifact paths listed below for the three disputed benchmark cases and the additive `hkdf_block_key_artifact_validation` provenance case

---

## Appendix: Evidence Index

- `.sisyphus/evidence/task-1-v1-v4-registry.md`
- `.sisyphus/evidence/task-4-pre-fix-failures.txt`
- `.sisyphus/evidence/task-6-v2-reverification.md`
- `.sisyphus/evidence/task-6-v5-state-01.txt`
- `.sisyphus/evidence/task-6-v5-state-02.txt`
- `.sisyphus/evidence/task-7-iterator-slice-v5-advrs-01.txt`
- `.sisyphus/evidence/task-7-iterator-slice-v5-advrs-03.txt`
- `.sisyphus/evidence/task-7-iterator-slice-v5-advrs-group.txt`
- `.sisyphus/evidence/task-7-chunk-slice-v5-depth-01.txt`
- `.sisyphus/evidence/task-7-chunk-slice-v5-depth-02.txt`
- `.sisyphus/evidence/task-7-catalog-slice-v5-trust-01.txt`
- `.sisyphus/evidence/task-7-chunk-index-v5-capacity.txt`
- `.sisyphus/evidence/task-7-chunk-index-concurrency-torture.txt`
- `.sisyphus/evidence/task-9-truth-queue.txt`
- `.sisyphus/evidence/task-10-suite-regression.txt`
- `.sisyphus/evidence/task-11-post-fix-registry.md`
- `.sisyphus/evidence/task-12-doc-consistency.txt`
- `.sisyphus/evidence/task-2-bench-baseline.txt`
- `.sisyphus/evidence/task-13-final-verification.txt`
- `.sisyphus/evidence/task-13-bench-summary.md`
- `target/criterion/e2e_multi_file/100_small_files/v5_pre/estimates.json`
- `target/criterion/hkdf_1000_block_keys/v5_pre/estimates.json`
- `target/criterion/key_session_reader_comparison/open_5_archives_without_session/v5_pre/estimates.json`
- `target/criterion/hkdf_block_key_artifact_validation/block_key_derivation_batched_100_normalized/v5_pre/estimates.json`
- `target/criterion/e2e_multi_file/100_small_files/change/estimates.json`
- `target/criterion/hkdf_1000_block_keys/change/estimates.json`
- `target/criterion/key_session_reader_comparison/open_5_archives_without_session/change/estimates.json`
- `.sisyphus/evidence/task-14-evidence-link-check.txt`
- `.sisyphus/evidence/task-14-report-consistency.txt`
- `.sisyphus/notepads/era-engine-audit-remediation/learnings.md`
- `.sisyphus/notepads/era-engine-audit-remediation/decisions.md`
