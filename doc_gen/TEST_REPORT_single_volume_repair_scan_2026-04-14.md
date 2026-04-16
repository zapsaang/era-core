# Test Report: Single-Volume Repair Scan Investigation

**Date:** 2026-04-14  
**Status:** Completed  
**Outcome:** **No production fix applied** — suspected bug not reproduced under validated single-volume scenarios.

---

## 1. Goal

Validate the suspected single-volume erasure-repair bug with a TDD workflow before making any production changes.

---

## 2. Documents Produced

- `.sisyphus/plans/single-volume-repair-scan-tdd-2026-04-14.md`
- `doc_gen/TEST_DESIGN_single_volume_repair_scan_2026-04-14.md`
- `doc_gen/FIX_EXECUTION_PLAN_single_volume_repair_scan_2026-04-14.md`
- `doc_gen/REPAIR_BUG_INVESTIGATION_REPORT_2026-04-14.md`

---

## 3. Test Artifact Added

New focused test file:

- `crates/era-engine/tests/single_volume_repair_scan_tests.rs`

Added tests:

1. `test_single_volume_erasure_archive_stays_single_file`
2. `test_default_erasure_archive_uses_multi_volume_layout`
3. `test_single_volume_repair_roundtrip_repro`
4. `test_single_volume_footer_boundaries_show_catalog_inside_data_region`
5. `test_single_volume_repair_exact_offset_5000_release_style_repro`

---

## 4. What Was Proven

### A. True single-volume EC archives are reachable and behave as expected

The new tests proved that using `volume_count(1)` with erasure enabled creates:

- exactly one physical archive file
- `header.total_volumes() == 1`
- a healthy single-volume archive before corruption

### B. Default 4+2 EC remains multi-volume

The control test proved the default `4:2` path still creates 6 physical volume files and remains distinct from the single-volume repair path.

### C. Single-volume repair roundtrip currently works

The new single-volume repro test:

- created a single-volume EC archive
- injected corruption into first-shard payload data
- verified pre-repair warnings / repair-needed state
- ran `repair_archive(...)`
- verified post-repair clean state
- extracted and byte-compared payload successfully

Result: **pass**.

### D. The original “offset 5000 / 100-byte corruption” pattern also passed

A stronger targeted repro using:

- true single-volume archive
- corruption at offset `5000`
- corruption length `100`
- 8 MiB input payload

also passed repair + verify + extract.

This passed in:

- debug test build
- release test build

### E. Footer boundary semantics do not support the earlier repair-boundary theory

The footer diagnostic test plus direct code review confirmed:

- `data_region().1 == footer.data_end_offset()`
- `footer.catalog_offset() < footer.data_end_offset()`

This means:

- `data_end_offset()` is the real outer data-region boundary
- `catalog_offset()` is an interior location

This strengthens the prior conclusion that the original report’s boundary assumptions were not reliable.

---

## 5. Validation Run Results

### Targeted debug run

Command:

```bash
cargo test -p era-engine --test single_volume_repair_scan_tests
```

Result:

- **5 passed, 0 failed**

### Targeted release run

Command:

```bash
cargo test -p era-engine --release --test single_volume_repair_scan_tests
```

Result:

- **5 passed, 0 failed**

---

## 6. Oracle Review Outcome

Oracle review conclusion:

- with the current TDD evidence, there is **no justified production change**
- the original bug report likely described a **different scenario, topology, data scale, commit state, or code path** than the one now validated
- speculative changes to `repair.rs` would be unjustified and risky

---

## 7. Production Code Changes

### Applied

- **None** in production code

### Reason

No failing single-volume repro was obtained, even after:

- true single-volume path validation
- exact-offset corruption repro
- release-mode validation
- footer-boundary diagnostics

Per TDD discipline, a production fix without a failing repro would be guesswork.

---

## 8. Final Conclusion

The suspected single-volume repair bug is **not reproduced** by the validated scenarios implemented in this investigation.

Therefore:

1. **Do not change `crates/era-engine/src/repair.rs` yet.**
2. Keep the new tests as regression coverage and as proof of path distinctions.
3. Treat the earlier report as either:
   - describing a different scenario, or
   - based on an invalid path assumption.

---

## 9. Recommended Next Step (If You Want To Continue)

If deeper pursuit is still desired, the next meaningful expansion is **not** a speculative fix. It is one of these:

1. reproduce the original ignored test conditions more faithfully at larger scale,
2. compare behavior against the exact historical commit where the report was authored,
3. inspect whether the ignored CLI test actually exercises a different path than the validated single-volume engine tests.
