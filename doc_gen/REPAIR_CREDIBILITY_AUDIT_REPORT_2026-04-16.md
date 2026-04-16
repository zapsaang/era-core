# Repair Credibility Audit Report

**Date:** 2026-04-16  
**Branch:** feat_fly  
**Subject:** Post-fix credibility audit of repair-path changes in `crates/era-engine/src/repair.rs` and related CLI/test coverage  
**Verdict:** **Partially credible.** The recent fix is real and addresses the original data-shard header-length drift bug in both scan paths, but it does **not** justify a claim of complete repair correctness, strict end-to-end TDD, or complete test coverage.

---

## Executive Summary

This audit reviewed the current repair implementation, targeted repair tests, CLI behavior, and prior investigation artifacts to answer four questions:

1. Is the repair fix real?
2. Was it developed strictly under TDD?
3. Do current tests fully cover the relevant cases?
4. Did the fix introduce new problems or leave high-risk gaps?

### Final assessment

- **Yes, the fix is real** for the original data-shard drift bug.
- **No, the overall work does not meet a strict TDD standard** across all affected paths.
- **No, coverage is not complete**, especially for the matrix repair path.
- **No obvious new catastrophic regression was introduced**, but the code remains **asymmetric and only partially hardened**, especially in matrix repair and parity-length handling.

The strongest supported claim is:

> The code now correctly avoids trusting a corrupted **data shard** header length for read length, reconstruction length, and offset advancement.

The strongest unsupported claim would be:

> “Repair is now fully correct for all single-volume and multi-volume corruption cases.”

That statement is **not** supported by the current code or test matrix.

---

## Scope and Evidence Reviewed

### Primary code paths

- `crates/era-engine/src/repair.rs`
  - single-volume repair scan: around lines `332-615`
  - matrix repair scan: around lines `990-1272`
- `bins/era-cli/src/main.rs`
- `bins/era-cli/src/commands.rs`

### Primary tests

- `crates/era-engine/tests/single_volume_repair_scan_tests.rs`
- `crates/era-engine/tests/matrix_distribution_tests.rs`
- `crates/era-engine/tests/multi_volume_tests.rs`
- `bins/era-cli/tests/cli_stress_and_discovery_tests.rs`
- `bins/era-cli/tests/cli_e2e_gap_tests.rs`
- `bins/era-cli/tests/cli_integration_tests.rs`

### Supporting reports / artifacts

- `doc_gen/TEST_DESIGN_single_volume_repair_scan_2026-04-14.md`
- `doc_gen/REPAIR_BUG_INVESTIGATION_REPORT_2026-04-14.md`
- `doc_gen/ERA_CLI_INTEGRATION_TEST_REPORT_2026-04-15.md`

### Additional review sources

- Two internal explore audits focused on repair coverage and TDD evidence
- One Oracle review focused on soundness, hidden failure modes, and remaining risk

---

## What Has Been Credibly Fixed

## 1. Data-shard header-length trust bug

### Problem

In the original failure mode, repair logic trusted `ShardHeader.length` even when the shard header itself was corrupted. That created three coupled errors:

1. wrong read length
2. wrong original shard length used for RS reconstruction
3. wrong offset advancement during scan

Once offset advancement drifted, later data could be read or rewritten at the wrong location, eventually surfacing as verification failures such as `BlockHeader CRC verification failed`.

### Current fix

In the **single-volume** path, the code now derives data-shard length from `stripe_lengths` parsed from the stripe prefix rather than blindly trusting `ShardHeader.length`:

- `repair.rs:382-390` — compute `authoritative_len` for data shards
- `repair.rs:404-452` — use prefix-derived length for `shard_len`
- `repair.rs:461-463` — advance offset even on corrupted-header path
- `repair.rs:485-492` — bypass `ShardHeader.verify()` length equality check when prefix-derived length is authoritative

In the **matrix** path, the same pattern now exists:

- `repair.rs:1079-1087` — compute `authoritative_len` for data shards
- `repair.rs:1092-1142` — use prefix-derived length for `shard_len`
- `repair.rs:1151-1156` — advance `volume_offsets[reader_idx]` on corrupted-header path
- `repair.rs:1179-1186` — bypass `ShardHeader.verify()` when using authoritative prefix length

### Audit conclusion

This change is **substantive and real**. It directly addresses the original “corrupted data-shard header length causes scan drift” class of bugs.

Confidence: **High**

---

## 2. Single-volume scan boundary hardening

### Problem

Repair scanning must not continue into metadata/checkpoint regions.

### Current fix

The single-volume path now stops at the earliest of:

- `catalog_offset`
- `index_offset`
- `last_checkpoint_offset`

See `repair.rs:332-347`.

### Audit conclusion

This is a meaningful hardening change and reduces the chance of over-scanning into non-erasure regions.

Confidence: **High**

---

## 3. CLI help example was corrected, but the interface is not truly fixed

### What changed

The help text was updated to stop using `repair --key` as the primary example and to steer users toward password mode.

### What remains true

The CLI still exposes:

- `bins/era-cli/src/main.rs:271-273` — `key: Option<PathBuf>` for `Repair`

and only later rejects it at runtime:

- `bins/era-cli/src/commands.rs:866-870`

### Audit conclusion

This is a **documentation/UX improvement**, not a full surface fix.

Confidence: **High**

---

## What Is Not Yet Proven Correct

## 1. Matrix repair is not fully hardened

Although the matrix path now mirrors the data-shard length fix, it still differs from the single-volume path in an important way.

### Current asymmetry

Single-volume stop boundary:

- `repair.rs:332-347`
- includes `last_checkpoint_offset()`

Matrix stop boundary:

- `repair.rs:990-1007`
- considers `catalog_offset()` and `index_offset()`
- **does not consider `last_checkpoint_offset()`**

### Why this matters

If matrix repair scans beyond the last valid erasure-coded data and into checkpointed metadata, the repair logic may still drift into non-data regions even after the data-shard length fix.

### Audit conclusion

The matrix fix is **partial**, not complete.

Confidence: **High**

---

## 2. Parity-length handling is only partially defended

The new fix hardens **data shard** handling by using stripe-prefix lengths.

Parity shards, however, still depend on `ShardHeader.length` when that value is merely “within bounds”:

- single-volume: `repair.rs:414-435`
- matrix: `repair.rs:1101-1122`

The code does clamp parity length to a bound derived from the max data stripe size, which is better than before, but this still leaves a gap:

- a **too-small but syntactically valid** corrupted parity length can still affect offset progression
- `ShardHeader::from_bytes(...)` is permissive; “header parsed successfully” does not imply semantic correctness

### Audit conclusion

Parity corruption remains a credible unresolved risk.

Confidence: **Medium-High**

---

## 3. The “authoritative” prefix is taken from the first readable copy

In matrix repair, each shard stores the same length prefix, but the current scan takes the **first readable shard’s prefix** and treats that as authoritative:

- `repair.rs:1044-1062`

If that first readable copy is itself corrupted, then the now-authoritative lengths may still be wrong.

The same structural concern exists in single-volume logic:

- `repair.rs:367-380`

### Audit conclusion

The fix assumes the first usable prefix is trustworthy enough. That may be acceptable operationally, but it is **not formally hardened** against prefix corruption.

Confidence: **Medium**

---

## 4. The 1GB ignored test still signals a real remaining product problem

The ignored test:

- `bins/era-cli/tests/cli_e2e_gap_tests.rs:163-229`
- `test_large_file_1gb_repair_after_corruption`

is still annotated as a pre-existing bug and still fails when executed in the prior session.

Important nuance:

- it is **not** the best primary diagnostic for the exact root cause
- but it **is** valid as a signal that repair correctness is still not closed for large real-world archives

The right interpretation is:

> This test should not be used as the sole proof that the recent fix failed, but it does prove that repair correctness is not fully complete yet.

Confidence: **High**

---

## TDD Assessment

## What supports a TDD claim

The strongest evidence for TDD exists in the **single-volume** repair work:

- `doc_gen/TEST_DESIGN_single_volume_repair_scan_2026-04-14.md` lays out phased repro/test work before the fix
- `crates/era-engine/tests/single_volume_repair_scan_tests.rs` contains purpose-built regression tests rather than generic smoke tests
- especially:
  - `test_single_volume_repair_roundtrip_repro`
  - `test_single_volume_repair_exact_offset_5000_release_style_repro`

This is consistent with a genuine TDD-style cycle:

1. isolate topology
2. create failing repro
3. identify boundary conditions
4. add regression lock-in

## What prevents a strict TDD verdict

### 1. The matrix path lacks equivalent focused regression tests

There is no matrix-path engine-level repro test matching the single-volume ones in precision.

The key missing test is something like:

1. create a controlled multi-volume archive
2. corrupt a data-shard header length in one volume
3. run `repair_archive_matrix`
4. run `verify`
5. extract and validate content

That specific proof does not currently exist.

### 2. Existing CLI tests are not enough to prove matrix-path TDD

CLI tests do exercise repair flows, but they are not precise enough to prove root-cause closure on matrix repair.

### 3. Ignored failing regressions remain open

As long as the ignored large-file repair regressions still stand unresolved, the project cannot credibly claim strict repair-path TDD closure.

## TDD verdict

**Single-volume repair work:** mostly consistent with TDD  
**Overall repair hardening:** **not** strict TDD

---

## Test Coverage Audit

## What is well covered

### Single-volume repair path

Covered well by:

- `crates/era-engine/tests/single_volume_repair_scan_tests.rs`
- targeted repros
- verify-after-repair assertions
- extract-after-repair assertions
- topology distinction (`volume_count(1)` vs default multi-volume)

### General CLI repair flows

Covered by:

- `bins/era-cli/tests/cli_stress_and_discovery_tests.rs`
- `bins/era-cli/tests/cli_integration_tests.rs`

These provide confidence that normal repair workflows still execute.

## What is under-covered or missing

### 1. Matrix repair root-cause regression coverage

This is the largest gap.

There is still no matrix equivalent of the single-volume repro tests that directly lock in:

- corrupted data-shard header length
- correct offset progression
- verify success after repair
- extract correctness after repair

### 2. Matrix checkpoint-boundary regression

No focused regression test currently proves that matrix repair stops safely before checkpoint metadata.

### 3. Parity-length corruption regression

No dedicated test currently proves that corrupted parity length fields cannot still mis-advance offsets.

### 4. Prefix-corruption regression

No focused test currently proves behavior when the replicated stripe-prefix lengths themselves are corrupted.

### 5. CLI surface consistency for `repair --key`

There is coverage of the runtime rejection behavior, but not a true interface cleanup, because the option still exists on the command surface.

## Coverage verdict

**Good for single-volume root cause. Incomplete overall. Clearly incomplete for matrix and parity edge cases.**

---

## Potential New Problems or Residual Risks

No clear evidence was found that the current change introduced a brand-new catastrophic regression in happy-path repair.

However, it did leave behind several structural risks.

## Risk 1. Repair-path asymmetry

Single-volume and matrix repair are now closer, but still not fully aligned.

That creates a maintenance hazard:

- one path appears more hardened
- the other appears “mirrored” at a glance
- but subtle boundary behavior still differs

This is exactly the kind of asymmetry that causes future false confidence.

## Risk 2. Hidden reliance on permissive header parsing

The logic still depends on successfully parsing headers that may be syntactically valid but semantically bogus.

That matters most for parity shards and for choosing fallback progression lengths.

## Risk 3. Oversized repair tolerance vs volume-layer contract

Oracle also noted a contract mismatch:

- repair path uses a much looser `MAX_SHARD_SIZE`
- volume layer enforces a tighter on-disk shard contract

That means corrupted lengths may remain acceptable inside repair logic longer than they should be according to actual storage format assumptions.

This needs follow-up validation.

---

## Detailed List of Problems Still Not Fixed

## P0 — High priority, still unresolved

### 1. Matrix repair does not stop at checkpoint boundary

**Files:**

- `crates/era-engine/src/repair.rs:990-1007`
- compare with single-volume `crates/era-engine/src/repair.rs:332-347`

**Problem:** matrix repair does not use `last_checkpoint_offset()` when computing scan end.

**Risk:** may scan or reason across checkpointed metadata.

**Status:** Unfixed.

---

### 2. No dedicated matrix regression for corrupted data-shard header length

**Problem:** current matrix coverage is indirect and insufficiently targeted.

**Missing proof:** a regression test that shows `repair_archive_matrix` truly resolves the same drift bug under controlled multi-volume corruption.

**Status:** Unfixed.

---

### 3. Large-file repair bug remains unresolved

**File:** `bins/era-cli/tests/cli_e2e_gap_tests.rs:163-229`

**Problem:** large real-world repair scenarios still do not verify cleanly after repair.

**Status:** Unfixed. Still represented by ignored failing regression.

---

## P1 — Important hardening gaps

### 4. Parity shard length corruption is not robustly closed

**Files:**

- single-volume: `repair.rs:414-435`
- matrix: `repair.rs:1101-1122`

**Problem:** parity progression can still rely on corrupted but in-range header length.

**Status:** Unfixed.

---

### 5. Prefix corruption is not guarded by multi-copy reconciliation

**Files:**

- single-volume: `repair.rs:367-380`
- matrix: `repair.rs:1044-1062`

**Problem:** first readable prefix is treated as truth instead of cross-checking replicated copies.

**Status:** Unfixed.

---

### 6. `repair --key` is still exposed in the CLI contract

**Files:**

- `bins/era-cli/src/main.rs:271-273`
- `bins/era-cli/src/commands.rs:866-870`

**Problem:** user can still discover the option and only gets rejected later.

**Status:** Partially fixed in help text only.

---

## P2 — Medium-priority cleanup / credibility issues

### 7. Repair confidence is currently overstated by prior report text

Some earlier generated reports claimed that matrix repair had effectively been covered or fully resolved. That is too strong given the current evidence.

**Status:** Documentation debt.

---

### 8. Single-volume and matrix logic should likely be refactored into shared scan primitives

The two paths now contain near-mirrored but still drifting logic.

**Problem:** correctness fixes can land in one path and not the other.

**Status:** Design debt.

---

## Recommended Next Steps

## Immediate

1. Add an **engine-level matrix regression** for corrupted data-shard header length.
2. Add an **engine-level matrix checkpoint-boundary regression**.
3. Add a **parity-length corruption regression**.

## Short-term

4. Remove or hide `repair --key` from the CLI repair surface instead of only updating examples.
5. Re-run the ignored 1GB repair regression **after** the two matrix regressions above are in place.

## Structural

6. Consider extracting shared scan/reconstruction logic so single-volume and matrix repair cannot drift semantically.
7. Consider validating stripe-prefix lengths using multiple copies rather than trusting the first readable one.

---

## Final Verdict

### Credibility score

| Dimension | Verdict |
|---|---|
| Fix is real | Yes |
| Fix is complete | No |
| Strict TDD | No |
| Single-volume coverage | Good |
| Matrix coverage | Incomplete |
| Large-file repair closed | No |
| New severe regression introduced | Not proven |

### Plain-language conclusion

The current repair fix is **credible as a partial bug fix**, especially for the single-volume data-header drift scenario. It is **not credible as a full repair-path closure**. The remaining matrix-boundary, parity-length, prefix-trust, and large-file issues mean the project should treat this work as:

> **“important repair hardening landed, but repair correctness is still not fully proven.”**
