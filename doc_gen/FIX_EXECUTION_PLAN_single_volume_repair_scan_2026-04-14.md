# Fix Execution Plan: Single-Volume Repair Scan Bug

**Date:** 2026-04-14  
**Status:** Ready for execution  
**Plan review:** Momus verdict = **OKAY**  
**Related test design:** `doc_gen/TEST_DESIGN_single_volume_repair_scan_2026-04-14.md`

---

## 1. Objective

Execute a TDD fix for the suspected single-volume repair bug in `crates/era-engine/src/repair.rs` without changing unrelated behavior.

---

## 2. Non-Negotiable Rules

1. Tests first.
2. No speculative fix before a failing repro exists.
3. Do **not** change `apply_repairs` ordering.
4. Keep the change localized unless tests prove broader changes are necessary.
5. Preserve the multi-volume control path.

---

## 3. Primary Files

### Expected code target

- `crates/era-engine/src/repair.rs`

### Expected new test target

- `crates/era-engine/tests/single_volume_repair_scan_tests.rs`

### Optional supporting targets

- helper reuse from existing engine tests
- CLI tests only if behavior at the CLI layer must also be pinned down

---

## 4. Root-Cause Decision Tree

The implementation must not assume the root cause. Use this order:

### Step 1 — prove single-volume repro

If repro does not fail, stop. The current diagnosis is incomplete.

### Step 2 — prove layout behavior

If raw-byte tests show repeated `stripe_lengths` per shard, reject any fix based on “prefix once per stripe only”.

### Step 3 — prove boundary behavior

If `catalog_offset()` and `data_end_offset()` differ in a way that explains the failure, prefer the smaller boundary fix.

### Step 4 — only then change scan logic

Apply the smallest fix that is directly supported by tests.

---

## 5. Implementation Phases

### Phase 1 — add focused tests

Add the new test file and implement:

1. true single-volume control test
2. default multi-volume control test
3. failing repair roundtrip repro

**Gate:** at least one new test fails before code changes.

### Phase 2 — add diagnostics

Add tests that inspect:

1. footer boundaries
2. raw shard layout
3. offset progression through damaged data

**Gate:** one root-cause candidate becomes strongly supported.

### Phase 3 — implement minimal fix

Possible fix classes:

1. boundary selection fix in single-volume scan
2. offset/scanner interpretation fix in single-volume scan
3. damaged-shard metadata handling fix if tests prove it

**Gate:** failing repro now passes.

### Phase 4 — regression tests

Add narrow cases for:

1. early corruption
2. later corruption
3. control multi-volume archive remains correct

### Phase 5 — validation

Run targeted tests, then broader crate validation.

### Phase 6 — Oracle audit and final test report

After code is green, request Oracle review and then write the final report under `doc_gen/`.

---

## 6. Validation Commands

Run in this order, expanding only if each stage is green:

1. focused new test file
2. related repair-focused engine tests
3. `cargo test -p era-engine`
4. CLI repair tests if touched

If needed after code stabilizes:

- formatting / diagnostics checks
- wider workspace validation

---

## 7. Risk Controls

### Risk A — wrong path again

Mitigation:

- assert single physical volume in the repro
- keep multi-volume control test beside it

### Risk B — fix the wrong hypothesis

Mitigation:

- raw-layout test before code change
- boundary test before code change

### Risk C — regress matrix repair

Mitigation:

- preserve dedicated multi-volume control test
- avoid touching matrix code unless explicitly proven necessary

### Risk D — overfitting to one corruption offset

Mitigation:

- regression tests at multiple corruption positions

---

## 8. Minimal Acceptable Fix

The fix is acceptable only if:

1. it is localized,
2. it is backed by a failing-then-passing test,
3. it leaves `apply_repairs` ordering untouched,
4. it keeps the multi-volume control path green.

---

## 9. Stop Conditions

Stop and re-plan if any occur:

1. true single-volume repro cannot be made to fail
2. raw-byte layout contradicts the intended fix
3. suspected boundary bug is disproven and no other supported cause emerges
4. the smallest viable fix spills into unrelated writer/reader refactors

---

## 10. Completion Criteria

The execution plan is complete when:

1. new single-volume repro tests exist,
2. root cause is proven by tests,
3. fix is implemented minimally,
4. validation passes,
5. Oracle review is complete,
6. final test report is written into `doc_gen/`.
