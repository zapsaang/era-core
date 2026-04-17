# era-cli Integration Test Coverage Gap Analysis

**Generated:** 2026-04-17  
**Branch:** feat_fly  
**Scope:** CLI-level integration tests for era-cli (create/extract/verify/repair/repack)

---

## Executive Summary

Current CLI integration test coverage is approximately **85-90%** for typical production scenarios. This document catalogs the remaining coverage gaps, categorized by priority and effort.

**Test inventory at time of writing:** 9 test files, 2000+ tests across all workspace crates.

---

## Coverage Heatmap

| Dimension | Coverage | Key Gaps |
|-----------|----------|----------|
| File size | 90% | >4GB files, sparse files |
| EC configurations | 95% | Most common configs covered |
| Corruption location | 90% | Random-offset corruption |
| Auth modes | 95% | 5+ certificate threshold |
| Compression + EC | 40% | Most tests use `--no-compression` |
| Concurrency | 60% | Concurrent repair missing |
| Error recovery | 70% | Signal interruption missing |
| Metadata preservation | 50% | xattr, permissions post-repair |
| Volume management | 85% | Cross-archive splicing detection |
| Backup validation | 50% | Backup extractability not verified |

---

## P0 (High Priority) Gaps

### 1. Compression + Erasure Coding Repair Interaction

**Gap:** Almost all repair/corruption tests use `--no-compression`. There is no dedicated test verifying that a `zstd-19` + `4:2` archive can be corrupted, repaired, and extracted with bit-for-bit fidelity.

**Risk:** Compression and EC layers may have subtle alignment or padding interactions that only surface under real compressed payloads.

**Suggested test:**
```rust
#[test]
fn test_repair_zstd_compressed_ec_archive() {
    // Create with zstd level 19 + 4:2 EC
    // Corrupt at offset 5000
    // Repair -> Verify -> Extract
    // Assert exact byte match
}
```

---

### 2. Exact Parity Capacity Boundary

**Gap:** Tests exist for "under parity limit" (success) and "over parity limit" (failure), but not the **exact boundary**.

**Risk:** Off-by-one errors in parity calculation could make archives unrecoverable at the exact tolerance threshold.

**Suggested test:**
```rust
#[test]
fn test_repair_exact_parity_boundary_4_plus_2() {
    // Corrupt exactly 2 shards -> must succeed
    // Corrupt 3 shards -> must fail
}
```

---

### 3. Cross-Archive Volume Splicing Detection

**Gap:** No test verifies that the CLI rejects or handles a multi-volume archive where volumes from *different* archives are accidentally (or maliciously) mixed.

**Risk:** Silent data corruption or information leakage if archive IDs are not strictly validated during repair/extract from secondary volumes.

**Suggested test:**
```rust
#[test]
fn test_repair_rejects_spliced_volumes_from_different_archives() {
    // Create archiveA (volumes 0..3) and archiveB (volumes 0..3)
    // Swap one volume from B into A's directory
    // Extract/Repair should detect archive ID mismatch
}
```

---

## P1 (Medium Priority) Gaps

### 4. Repair Backup Integrity

**Gap:** Tests verify that `--force` creates a `.backup` file, but no test attempts to **extract** from that backup to prove it is a valid, complete archive.

**Risk:** A corrupted or truncated backup provides false confidence.

**Suggested test:**
```rust
#[test]
fn test_repair_backup_archive_is_extractable() {
    // Repair with --force
    // Extract from `.era.backup`
    // Assert content matches original
}
```

---

### 5. Metadata Preservation After Repair

**Gap:** No test verifies that file permissions, modification times, or extended attributes survive the `create -> corrupt -> repair -> extract` chain.

**Risk:** Repair path might reconstruct content correctly but drop metadata.

**Suggested test:**
```rust
#[test]
fn test_repair_preserves_file_metadata() {
    // Create file with mode 755 and xattr
    // Full corrupt-repair-extract chain
    // Assert mode and xattr preserved
}
```

---

### 6. Random-Offset Corruption

**Gap:** All current corruption tests use fixed offsets (5000, 10000, etc.). These may accidentally miss alignment-sensitive regions.

**Risk:** Corner cases at shard boundaries, footer boundaries, or header gaps are under-tested.

**Suggested approach:**
- Property-based test using `proptest` with random offsets and corruption lengths.
- Or a parameterized test sweeping offsets at shard-size boundaries.

---

### 7. Concurrent Repair Scenarios

**Gap:** There are concurrent *verify* and *extract* tests, but no concurrent *repair* test.

**Risk:** File locking or temporary file naming collisions during parallel repair jobs.

**Suggested test:**
```rust
#[test]
fn test_concurrent_repair_on_same_archive_races_safely() {
    // Spawn two repair --force processes on the same archive
    // Neither should panic; at least one should succeed
}
```

---

## P2 (Low Priority) Gaps

### 8. Repair Interrupt / Resume

**Gap:** No test simulates a SIGINT during repair and verifies that the archive remains in a recoverable state.

**Effort:** High (requires process control in tests).

---

### 9. Very Small File + High EC Overhead

**Gap:** A 1-byte file with `4:2` EC has extreme padding ratios. No test exercises this boundary.

**Effort:** Low.

---

### 10. Repair -> Repack -> Repair Chain

**Gap:** Chains longer than `repair -> repack` are not covered (e.g., `repair -> repack -> corrupt -> repair`).

**Effort:** Low.

---

### 11. >4GB File Roundtrip

**Gap:** A 5GB test exists but is `#[ignore]`d due to CI constraints. No regular coverage for files exceeding 32-bit address space.

**Effort:** Requires dedicated CI runner or nightly job.

---

## Recommendations

### Immediate (Next PR)
1. Add **Cross-Archive Volume Splicing Detection** test — security implication.
2. Add **Compression + EC Repair** test — high practical value, low effort.

### Short Term (This Sprint)
3. Add **Exact Parity Boundary** test.
4. Add **Repair Backup Extractability** test.
5. Add **Metadata Preservation** test.

### Long Term (Backlog)
6. Introduce property-based corruption tests (random offsets/sizes).
7. Add concurrent repair safety test.
8. Set up nightly job for the 5GB ignored test.

---

## Related Documents

- `REPAIR_BUG_ANALYSIS_REPORT.md` — Root cause of P0.3 catalog-read bug
- `REPAIR_CREDIBILITY_FIX_REPORT_2026-04-16_UPDATED.md` — Fix verification for P0.3
- `ERA_CLI_INTEGRATION_TEST_REPORT_2026-04-15.md` — Historical test coverage report
- `crates/*/tests/AGENTS.md` — Crate-level test surface maps
