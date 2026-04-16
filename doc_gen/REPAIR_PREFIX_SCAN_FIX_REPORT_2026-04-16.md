# Prefix Multi-Copy Reconciliation + Shared Scan-Primitive Fix Report

**Date:** 2026-04-16  
**Branch:** feat_fly  
**Scope:** Fix P1.5 (Prefix multi-copy reconciliation) and P2.8 (Shared scan-primitive refactoring) from `REPAIR_CREDIBILITY_FIX_REPORT_2026-04-16.md`

---

## Executive Summary

This report documents the fixes applied to close the two remaining gaps identified in the 2026-04-16 repair credibility audit:

1. **Prefix multi-copy reconciliation (P1.5)** — Previously, both repair paths and the session erasure iterator treated the **first readable prefix copy** as authoritative for data-shard lengths. This created an offset-drift vector when that prefix was corrupted.
2. **Shared scan-primitive refactoring (P2.8)** — Single-volume and matrix repair paths contained ~12 near-identical duplicated code blocks for shard scanning, parity-bound calculation, data-length normalization, and `data_ends` boundary computation.

**Oracle verdict:** **GO.** All blocking correctness concerns from the audit have been addressed.

---

## Design Decisions

- **Quorum rule**: `reconcile_stripe_prefixes` requires **exactly one** candidate prefix byte sequence to have the **strict maximum count** among all readable copies, and that count must be at least 2. Ties return `None`.
- **Fallback**: When no consensus exists, data-shard lengths fall back to `ShardHeader.length`, protected by existing parity-bound hardening.
- **Pre-pass navigation**: The prefix-collection pre-pass advances offsets using `ShardHeader.length`, so a corrupted prefix cannot itself cause drift during collection.
- **Refactoring boundary**: Extracted shared helpers into `erasure_scan.rs` and migrated all three erasure iterator constructors plus both repair paths.

---

## Fixes Applied

### 1. Multi-copy prefix reconciliation

**Files:** `crates/era-engine/src/repair.rs`, `crates/era-engine/src/block_iter.rs`

**Before:** `stripe_lengths` was set from the first readable shard's prefix bytes and immediately trusted.

**After:** A pre-pass collects **all** readable prefix copies for the current stripe, then calls `crate::erasure_scan::reconcile_stripe_prefixes`. Only if a unique majority consensus exists are the parsed lengths used as authoritative for data shards.

**Call sites updated:**
- `repair_archive` (single-volume repair)
- `repair_archive_matrix` (matrix repair)
- `SessionErasureBlockIterator::next_block()`

### 2. Shared scan-primitive extraction

**New file:** `crates/era-engine/src/erasure_scan.rs`

**Helpers introduced:**
| Function | Purpose |
|----------|---------|
| `reconcile_stripe_prefixes` | Quorum-based prefix consensus (unique max count ≥ 2) |
| `erasure_data_end` | Unified data-region end clamp (checkpoint < index < catalog) |
| `parity_bound_from_lengths` | Padded max stripe size for parity length bounding |
| `even_aligned_shard_size` | Round-up to even boundary for RS recovery |
| `normalize_data_lengths` | Backfill missing data lengths from consensus prefix |

**Refactoring migrated to shared helpers:**
- `data_ends` computation in `ErasureBlockIterator::new`, `MultiVolumeSessionBlockIterator::new`, `SessionErasureBlockIterator::new`
- Inline `data_ends` computation in `repair_archive` and `repair_archive_matrix`
- Duplicated parity-bound logic in both repair paths
- Duplicated even-alignment and normalization logic in `repair.rs` and `block_iter.rs`

### 3. Adversarial audit V5 compatibility update

**File:** `crates/era-engine/tests/adversarial_audit_v5.rs`

**Change:** `test_v5_advrs_01_non_session_shard_len_cap` previously corrupted the stripe-prefix length on a single volume and expected a `MAX_SHARD_SIZE` cap error. Because prefix reconciliation can recover from a single corrupted copy, the test was updated to **corrupt ALL volume prefixes** so that quorum fails and the `MAX_SHARD_SIZE` cap path is still exercised.

---

## Test Results

### New tests

| Test | File | Result |
|------|------|--------|
| `test_single_volume_repair_reconciles_corrupted_first_prefix_copy` | `single_volume_repair_scan_tests.rs` | Pass |
| `test_single_volume_repair_does_not_trust_non_consensus_prefixes` | `single_volume_repair_scan_tests.rs` | Pass |
| `test_matrix_repair_reconciles_corrupted_first_prefix_copy` | `matrix_repair_scan_tests.rs` | Pass |
| `test_matrix_repair_does_not_trust_non_consensus_prefixes` | `matrix_repair_scan_tests.rs` | Pass |
| `test_virtual_striping_reconciles_corrupted_first_prefix_copy` | `virtual_striping_tests.rs` | Pass |
| `test_reconcile_stripe_prefixes_returns_none_on_two_way_tie` | `erasure_scan.rs` (unit) | Pass |
| `test_reconcile_stripe_prefixes_returns_none_on_three_way_tie` | `erasure_scan.rs` (unit) | Pass |
| `test_reconcile_stripe_prefixes_exactly_two_identical_copies_wins` | `erasure_scan.rs` (unit) | Pass |
| `test_reconcile_stripe_prefixes_wins_despite_lower_tie` | `erasure_scan.rs` (unit) | Pass |
| `test_reconcile_stripe_prefixes_wins_despite_later_lower_tie` | `erasure_scan.rs` (unit) | Pass |

### Regression suites

| Suite | Result |
|-------|--------|
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | Pass |
| `cargo test -p era-engine --lib erasure_scan` | 14/14 Pass |
| `cargo test -p era-engine --test single_volume_repair_scan_tests` | 7/7 Pass |
| `cargo test -p era-engine --test matrix_repair_scan_tests` | 7/7 Pass |
| `cargo test -p era-engine --test virtual_striping_tests` | 2/2 Pass |
| `cargo test -p era-engine --test adversarial_audit_v2` | 53/53 Pass |
| `cargo test -p era-engine --test adversarial_audit_v5` | 26/26 Pass |
| `cargo test -p era-engine --test multi_volume_tests` | 28/28 Pass |
| `cargo test -p era-cli --test cli_integration_tests` | 85/85 Pass |

---

## Files Changed

```
crates/era-engine/src/block_iter.rs                | 187 +++++++---------
crates/era-engine/src/lib.rs                       |   1 +
crates/era-engine/src/repair.rs                    | 248 +++++++++------------
crates/era-engine/tests/adversarial_audit_v5.rs    |  25 +++-
.../era-engine/tests/matrix_repair_scan_tests.rs   | 147 +++++++++++++
.../tests/single_volume_repair_scan_tests.rs       | 162 ++++++++++++++
crates/era-engine/tests/virtual_striping_tests.rs  |  77 +++++++
7 files changed, 598 insertions(+), 249 deletions(-)
```

---

## Oracle Audit Notes (Non-blocking)

1. **Quorum strength**: The current 2-copy minimal quorum is sufficient for random corruption recovery but remains a weak adversarial guarantee. Under an active attacker model, two identically corrupted readable copies could still win consensus. This is bounded by `MAX_SHARD_SIZE`, so impact is limited to availability degradation rather than unbounded allocation.
2. **Iterator parity hardening**: `SessionErasureBlockIterator` does **not** yet apply the same parity-length sanity hardening that repair paths do. Parity header corruption in the read path could still cause offset misalignment. This is pre-existing design debt and was not in scope for this slice.

---

## Conclusion

The two targeted credibility gaps have been substantively closed:

- **First-readable-prefix trust** is eliminated in both repair and session-iterator paths.
- **Duplicated scan logic** is consolidated into a single shared module (`erasure_scan.rs`) used by all erasure iterator constructors and both repair paths.
- **Deterministic consensus logic** is now fully verified, including tie handling and mixed-count scenarios.

All targeted regression suites pass, and Oracle has given a GO verdict for this slice.
