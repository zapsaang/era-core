# ADVERSARIAL AUDIT V5 — Public-Path Delta Addendum

**Audit Window:** 2026-03-12  
**Auditor:** Sisyphus (OhMyOpenCode)  
**Target:** `crates/era-engine/` (public-path delta addendum)  
**Status:** FINAL DELTA ADDENDUM — non-superseding to `ADVERSARIAL_AUDIT_V5_REPORT.md`

---

## Executive Summary

This addendum re-tested the Oracle residuals from V5 against the current public entry points of
`era-engine`, using the approved public-path delta plan in
`.sisyphus/plans/era-engine-public-path-delta-audit.md`. The scoped targets were T1 resume/build
wiring, T2 catalog fanout, T3 append/index persistence, T4 extraction containment, and T5
iterator/repair failure handling.

The delta confirmed that T1, T2, T3, and the current public containment/read-path hard-fail
surfaces are green. It also found one new public-path Medium issue during T5: matrix repair could
recurse between `repair_archive(...)` and `repair_archive_matrix(...)` when only one matrix volume
survived, causing stack overflow instead of an explicit unrecoverable repair error. That issue was
fixed in-slice, the current public-path delta suite now passes end to end, and the final
current-state score remains **97**.

---

## Methodology

This addendum followed the approved delta plan and used a narrow public-path verification surface:

1. **Targeted public-path proofs** — exact T1–T5 proof commands from
   `.sisyphus/plans/era-engine-public-path-delta-audit.md:154-189`.
2. **Focused overlap reruns** — fresh reruns of `adversarial_audit_v5`, `competitor_audit`,
   `adversarial_audit_v9`, `index_persistence_audit`, and repair-overlap tests after the T5 fix.
3. **Current-state scoring** — inherited V5 baseline `97`, then apply delta penalties only for
   residual reopened/new findings that remain unresolved after the delta slice.
4. **Final repository gates** — `cargo fmt --all -- --check`,
   `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --workspace`.

---

## Scoring Method

This addendum keeps the V5 deterministic penalty model and applies it to the **current residual
state** after the public-path delta slice.

**Inherited V5 baseline:** `97`

**Delta penalty formula:**

`delta_penalty = 20*critical + 10*high + 3*medium + 0.5*low + 5*assurance_contradiction`

**Current-module score:**

`current_module_score = 97 - delta_penalty`

For this slice, the current residual delta penalty is `0` because the only new confirmed public-path
finding was fixed in-slice and no V5-closed high/critical issue reopened.

---

## Public-Path Re-Verification Summary

| Target | Outcome | Evidence |
|---|---|---|
| T1 Resume / build / finalize wiring drift | CONFIRMED GREEN | `.sisyphus/evidence/task-31-public-path-t1-resume.txt:4-15` |
| T2 Inline catalog fanout drift | CONFIRMED GREEN | `.sisyphus/evidence/task-31-public-path-t2-catalog.txt:4-15` |
| T3 Append / embedded-index persistence drift | CONFIRMED GREEN | `.sisyphus/evidence/task-31-public-path-t3-append.txt:5-8` |
| T4 Extraction containment hard-fail | CONFIRMED GREEN | `.sisyphus/evidence/task-31-public-path-t4-extract.txt:4-7` |
| T5 Iterator / repair heuristic drift | NEW MEDIUM FOUND + FIXED | `.sisyphus/evidence/task-31-pre-fix-repair-recursion.md:5-13`; `.sisyphus/evidence/task-31-public-path-t5-iterator.txt:4-7`; `.sisyphus/evidence/task-31-public-path-t5-repair.txt:4-7`; `.sisyphus/evidence/task-31-repair-overlap.txt:5-17` |

The full public-path delta binary is green after remediation: `.sisyphus/evidence/task-31-public-path-delta-suite.txt:5-17`.

---

## Pre-Fix Delta Finding

### PPD-REPAIR-01: Matrix Repair Recurred on Single-Surviving-Volume Degradation (Medium)
- **Finding ID:** `PPD-REPAIR-01`
- **Affected Files:** `era-engine/src/repair.rs:214-216, 720-723`
- **Severity:** Medium (availability-focused)
- **Pre-Fix Penalty if unresolved:** `-3`
- **Description:** The public repair path delegated any multi-volume archive from
  `repair_archive(...)` into `repair_archive_matrix(...)`. When only one matrix-distributed volume
  survived, the matrix path fell back into `repair_archive(...)` again. Under the public T5
  insufficient-shards repro, this re-entry loop overflowed the stack instead of returning a clean
  unrecoverable repair error.
- **Remediation:** Remove the recursive single-volume fallback for matrix-distributed archives and
  return an explicit `EraError::ErasureError("Matrix-distributed archive has insufficient surviving volumes for repair")`.
- **Pre-Fix Reproducer:** `cargo test -p era-engine --test competitor_public_path_delta test_public_repair_rejects_insufficient_shards_without_silent_success -- --nocapture` (Evidence: `.sisyphus/evidence/task-31-pre-fix-repair-recursion.md:5-13`)
- **Post-Fix Closure:** `.sisyphus/evidence/task-31-public-path-t5-repair.txt:4-7`; `.sisyphus/evidence/task-31-repair-overlap.txt:5-17`

---

## Remediation Summary

- `writer.rs` now distinguishes explicit recovery configuration from ordinary checkpoint-enabled
  fresh builds, so `enable_checkpoint(true)` no longer behaves like an implicit resume request.
- `competitor_public_path_delta.rs` now carries the approved public-path proof surface for T1, T2,
  T4, and T5, while `zero_drift_append_tests.rs` supplies the active T3 append proof.
- `repair.rs` now fails closed for matrix-distributed archives with only one surviving volume,
  returning an explicit unrecoverable repair error instead of recursing.

---

## Post-Fix Re-Verification

| Item | Final Status | Closure Reference |
|---|---|---|
| T1 public resume/build/finalize wiring | FIXED / CONFIRMED | `.sisyphus/evidence/task-31-public-path-t1-resume.txt:4-15` |
| T2 public catalog fanout and copy readability | FIXED / CONFIRMED | `.sisyphus/evidence/task-31-public-path-t2-catalog.txt:4-15` |
| T3 append/index persistence low-drift proof | FIXED / CONFIRMED | `.sisyphus/evidence/task-31-public-path-t3-append.txt:5-8` |
| T4 public extraction containment hard-fail | FIXED / CONFIRMED | `.sisyphus/evidence/task-31-public-path-t4-extract.txt:4-7` |
| T5 iterator fail-closed behavior | FIXED / CONFIRMED | `.sisyphus/evidence/task-31-public-path-t5-iterator.txt:4-7` |
| `PPD-REPAIR-01` matrix repair recursion | FIXED | `.sisyphus/evidence/task-31-public-path-t5-repair.txt:4-7`; `.sisyphus/evidence/task-31-repair-overlap.txt:5-17` |

Fresh targeted overlap verification is green:

- `adversarial_audit_v5`, `competitor_audit`, `adversarial_audit_v9`, and `index_persistence_audit`
  all passed in the delta rerun capture: `.sisyphus/evidence/task-31-delta-verification.txt:5-132`
- The matrix-repair overlap checks also passed after the fix:
  `.sisyphus/evidence/task-31-repair-overlap.txt:5-17`

---

## Final Rating

### Delta Disposition

This slice is a **non-superseding V5 public-path delta addendum**. It is not a pure confirming
addendum because a real public-path defect was found and remediated. It is not a V6 supersession
because no V5-closed high/critical issue reopened, no `5+` point score drop occurred, and the Task
11 / Task 13 evidence chain remains reproducible within this scope.

### Current-State Rating Calculation

- Inherited V5 baseline: `97`
- Current residual new/reopened findings after delta remediation: `0`
- `delta_penalty = 0`
- `current_module_score = 97 - 0 = 97`

**Current-module score: 97 (Low Risk)**

### Pre-Fix Equivalent Delta Note

Before remediation inside this slice, the newly discovered `PPD-REPAIR-01` would have represented
one Medium public-path finding. If it had remained unresolved, the scoped score would have been:

`97 - 3 = 94`

That is **not** the final score. Final scoring reflects the current residual state after the slice,
not the transient pre-fix discovery state.

### Verification Gates

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | PASS | `.sisyphus/evidence/task-31-final-verification-summary.md:7` |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS | `.sisyphus/evidence/task-31-final-verification-summary.md:8` |
| `cargo test --workspace` | PASS | `.sisyphus/evidence/task-31-final-verification-summary.md:9` |
| Public-path delta suite | PASS (10/10) | `.sisyphus/evidence/task-31-public-path-delta-suite.txt:5-17` |

### Residual Item

This addendum does not change the canonical V5 residual item:

- `V5-CRYPTO-01` remains the single Medium residual from V5, documented as
  `OUT-OF-SCOPE-BY-DESIGN` in `ADVERSARIAL_AUDIT_V5_REPORT.md:289-291`.

---

## How to Verify This Addendum

Use the exact commands below to reproduce the current public-path delta surface.

### Required T1–T5 proof commands

```bash
cargo test -p era-engine --test competitor_public_path_delta test_public_resume_requires_durable_checkpoint_state -- --nocapture
cargo test -p era-engine --test competitor_public_path_delta test_public_finalize_persists_authoritative_checkpoint_before_catalog -- --nocapture
cargo test -p era-engine --test competitor_public_path_delta test_public_catalog_fanout_fails_on_missing_writer_slot -- --nocapture
cargo test -p era-engine --test competitor_public_path_delta test_public_catalog_copies_are_readable_via_public_paths -- --nocapture
cargo test -p era-engine --test zero_drift_append_tests test_zero_drift_append_dedup -- --nocapture
cargo test -p era-engine --test competitor_public_path_delta test_public_extract_rejects_symlink_parent_swap -- --nocapture
cargo test -p era-engine --test competitor_public_path_delta test_public_iterator_probe_limit_fails_closed -- --nocapture
cargo test -p era-engine --test competitor_public_path_delta test_public_repair_rejects_insufficient_shards_without_silent_success -- --nocapture
```

### Targeted overlap verification

```bash
cargo test -p era-engine --test competitor_public_path_delta -- --nocapture
cargo test -p era-engine --test adversarial_audit_v5 -- --test-threads=1 --nocapture
cargo test -p era-engine --test competitor_audit
cargo test -p era-engine --test adversarial_audit_v9
cargo test -p era-index --test index_persistence_audit
cargo test -p era-engine --test multi_volume_tests test_e2e_too_many_volumes_lost_should_fail -- --nocapture
cargo test -p era-engine --test aead_resilience_tests test_repair_erasure_coded_single_volume_loss -- --nocapture
```

### Final repository gates

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

---

## Appendix: Evidence Index

- `.sisyphus/plans/era-engine-public-path-delta-audit.md`
- `.sisyphus/evidence/task-11-post-fix-registry.md`
- `.sisyphus/evidence/task-13-final-verification.txt`
- `.sisyphus/evidence/task-31-pre-fix-repair-recursion.md`
- `.sisyphus/evidence/task-31-public-path-t1-resume.txt`
- `.sisyphus/evidence/task-31-public-path-t2-catalog.txt`
- `.sisyphus/evidence/task-31-public-path-t3-append.txt`
- `.sisyphus/evidence/task-31-public-path-t4-extract.txt`
- `.sisyphus/evidence/task-31-public-path-t5-iterator.txt`
- `.sisyphus/evidence/task-31-public-path-t5-repair.txt`
- `.sisyphus/evidence/task-31-public-path-delta-suite.txt`
- `.sisyphus/evidence/task-31-delta-verification.txt`
- `.sisyphus/evidence/task-31-repair-overlap.txt`
- `.sisyphus/evidence/task-31-final-verification.txt`
- `.sisyphus/evidence/task-31-final-verification-summary.md`
- `doc_gen/AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_REPORT.md`
