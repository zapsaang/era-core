# Test Design: Single-Volume Repair Scan Bug

**Date:** 2026-04-14  
**Status:** Design approved for TDD execution  
**Related plan:** `.sisyphus/plans/single-volume-repair-scan-tdd-2026-04-14.md` (Momus: OKAY)

---

## 1. Purpose

Design a minimal but decisive TDD test suite for the suspected single-volume erasure-repair bug in `crates/era-engine/src/repair.rs`.

The test design must avoid a known investigation pitfall:

- default `4:2` erasure archives are usually **multi-volume**,
- so tests that do not force single-volume behavior can accidentally exercise `repair_archive_matrix(...)` instead of `repair_archive(...)`.

---

## 2. Verified Context

1. `repair_archive(...)` routes to `repair_archive_matrix(...)` when `header.total_volumes() > 1`.
2. Existing test coverage does **not** currently validate repair on a true single-volume erasure-coded archive.
3. Existing raw-layout evidence shows the serialized shard form includes repeated `stripe_lengths` prefix bytes before each shard header/data.
4. A competing hypothesis remains open: single-volume scan may choose the wrong end boundary (`catalog_offset()` vs `data_end_offset()`).
5. `apply_repairs` ordering must remain unchanged.

---

## 3. Scope

### In scope

- true single-volume erasure repair repro
- multi-volume control case
- boundary/offset/layout diagnostic tests needed to prove root cause
- regression tests once a fix is applied

### Out of scope

- refactoring unrelated repair code
- changing matrix repair unless tests prove it is also wrong
- changing CLI defaults
- changing `apply_repairs` write ordering

---

## 4. Proposed Test File

Create a new focused test file:

- `crates/era-engine/tests/single_volume_repair_scan_tests.rs`

Reason:

- current coverage is split across broad files
- the bug is narrow and path-sensitive
- isolating the tests makes TDD clearer and easier to run repeatedly

---

## 5. Test Strategy

### Phase A — prove path selection

We must first prove which code path is being exercised.

#### Test A1: `test_true_single_volume_ec_archive_stays_single_volume`

**Goal:** prove the archive used for repro is truly single-volume.

**Setup:**

- create archive with erasure enabled and `volume_count(1)` (or equivalent true single-volume builder config)
- use moderate-size payload (e.g. 8-32 MiB)

**Assertions:**

- only one archive file exists
- archive header reports single-volume
- repair path cannot be mistaken for matrix path

#### Test A2: `test_default_ec_archive_is_multi_volume_control`

**Goal:** preserve the known control behavior.

**Setup:**

- create archive with default erasure config (`4:2`) and no forced single-volume override

**Assertions:**

- multiple volume files exist
- behavior remains consistent with matrix-repair expectations

---

### Phase B — minimal failing repro

#### Test B1: `test_single_volume_ec_repair_roundtrip_after_corruption`

**Goal:** produce a failing test before any fix.

**Setup:**

- create true single-volume erasure archive
- save original payload bytes
- corrupt a known data-region offset in the archive file

**Execution:**

- call `repair_archive(...)`
- reopen archive with `ArchiveReader`
- run verify
- extract contents

**Expected result before fix:**

- this test should fail in a way that demonstrates the bug (repair failure, post-repair verify failure, or extract mismatch)

**Expected result after fix:**

- repair succeeds
- verify succeeds
- extracted bytes equal original bytes

---

### Phase C — disambiguate root cause

These tests exist to decide between the two strongest candidates:

- wrong scan boundary
- wrong single-volume scan interpretation/offset handling

#### Test C1: `test_single_volume_scan_boundary_matches_footer_data_end`

**Goal:** compare `catalog_offset()` and `data_end_offset()` behavior in a true single-volume EC archive.

**Assertions:**

- capture footer values
- prove whether scan should terminate at data end or catalog offset
- fail if current implementation uses a boundary inconsistent with actual data layout

#### Test C2: `test_single_volume_raw_layout_repeats_stripe_lengths_per_shard`

**Goal:** lock down writer layout so we do not fix the wrong thing.

**Assertions:**

- raw read first several shard segments from disk
- verify repeated prefix + `ShardHeader` + shard data pattern
- reject the “prefix once per stripe only” theory if raw bytes disprove it

#### Test C3: `test_single_volume_scan_offset_walk_matches_raw_layout`

**Goal:** prove the scanner’s walking logic against actual bytes.

**Assertions:**

- derived next offsets match actual serialized shard boundaries for at least one damaged case

---

### Phase D — regression coverage after fix

#### Test D1: `test_single_volume_repair_regression_first_stripe_corruption`

Corrupt near the first shard region.

#### Test D2: `test_single_volume_repair_regression_later_stripe_corruption`

Corrupt a later stripe to avoid false confidence from only first-stripe success.

#### Test D3: `test_multi_volume_repair_control_still_ok`

Ensure the single-volume fix does not regress the matrix path.

---

## 6. Test Data Choices

### Initial repro size

Use a moderate archive size that is:

- large enough to generate multiple stripes/blocks
- small enough for fast TDD iteration

Recommended starting payload: **8-32 MiB**.

### Compression

Prefer deterministic/simple settings where possible to reduce debugging noise.

### Corruption style

Use direct byte flipping in the archive file at controlled data-region offsets.

---

## 7. Helpers to Reuse or Add

### Reuse if suitable

- existing byte-flip corruption helpers from repair/adversarial tests
- `TempDir`
- existing archive creation helpers where they can truly force single-volume EC

### Add if needed

- dedicated helper to create a true single-volume EC archive
- helper to enumerate created archive files
- helper to extract and compare restored bytes

---

## 8. Pass/Fail Criteria

### Before fix

The suite is acceptable only if:

- a true single-volume EC repair test fails reproducibly
- multi-volume control still behaves as expected

### After fix

The suite is acceptable only if:

- the failing repro passes
- root-cause diagnostic tests support the chosen fix
- multi-volume control still passes

---

## 9. Risks and Anti-False-Positive Rules

1. Do not accept a repro that accidentally creates multiple volumes.
2. Do not treat a “repair returned Ok” result as success unless verify + extract also pass.
3. Do not treat layout assumptions as proven without raw-byte confirmation.
4. Do not remove or weaken assertions just to make tests pass.

---

## 10. Exit Condition

The test design phase is complete when:

1. the new focused test file is created,
2. at least one single-volume EC repair repro test fails before code changes,
3. at least one diagnostic test clearly supports the eventual fix direction.
