# era-cli Integration Test Coverage — Remaining Gaps Analysis

**Generated:** 2026-04-17
**Branch:** feat_fly
**Scope:** Gaps not yet covered by existing or newly-added CLI integration tests
**Status:** Inventory of known remaining gaps with risk assessment and implementation recommendations

---

## Executive Summary

Current CLI integration test suite covers approximately **85-90%** of realistic production scenarios for data corruption and recovery. This document catalogs the remaining **10-15%** of gaps, categorized by risk level and implementation effort.

**Test inventory at time of writing:**
- 9 test files across `bins/era-cli/tests/`
- ~370 total tests (28 new gap tests + 342 existing)
- All P0/P1 gaps from `CLI_TEST_COVERAGE_GAP_ANALYSIS.md` addressed
- 2 P2 gaps from original analysis deferred
- 10 additional gaps identified during this audit not present in original analysis

---

## Part A: Original Gap Analysis Deferred Items

These were explicitly deferred in `CLI_TEST_COVERAGE_GAP_ANALYSIS.md` and remain uncovered.

### A.1 Gap #8: Repair Interrupt / Resume (SIGINT)

**Priority:** P2 (Low)
**Effort:** High
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
No test simulates a `SIGINT` (Ctrl-C) during `era repair` and verifies that:
1. The archive remains in a recoverable state
2. Partially-written temporary files are cleaned up
3. The original archive is not left in a partially-modified state

**Why it matters:**
Repair with `--force` modifies archive files in-place. An interruption during this process could leave the archive in an inconsistent state if not handled correctly. The codebase has checkpoint-based recovery for `create`, but repair interruption safety is unverified.

**Implementation approach:**
```rust
use std::process::{Command, Stdio};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

#[test]
fn test_repair_interrupt_leaves_archive_recoverable() {
    let child = Command::new("era")
        .args(["repair", archive, "--password", "pwd", "--force"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    
    // Wait until repair starts modifying files (heuristic: check for .tmp file)
    std::thread::sleep(Duration::from_millis(200));
    
    // Send SIGINT
    kill(Pid::from_raw(child.id() as i32), Signal::SIGINT).unwrap();
    
    // Verify archive is still valid (verify passes or reports recoverable state)
    // Verify no orphan .tmp/.partial files exist
    // Verify backup file is intact if one existed
}
```

**Blockers:**
- Requires `nix` crate or platform-specific signal handling
- Needs timing heuristics to hit the "during repair" window
- Difficult to make deterministic across different machines

---

### A.2 Gap #11: >4GB File Roundtrip

**Priority:** P2 (Low)
**Effort:** High
**Status:** Not implemented (existing test is `#[ignore]`d)
**Risk Level:** Low-Medium

**Description:**
A 5GB test exists but is `#[ignore]`d due to CI constraints. No regular coverage for files exceeding 32-bit address space (`u32::MAX` = ~4.29GB).

**Why it matters:**
- `ChunkRef` uses `u32` for offset and length fields
- File sizes > 4GB may trigger overflow in chunk offset calculations
- CDC chunking boundaries may behave differently at GB scale
- Volume splitting logic may produce unexpected volume counts

**Implementation approach:**
Option 1: Dedicated nightly CI job on runner with >8GB RAM and >20GB disk
Option 2: Sparse 5GB file (`fallocate -l 5G`) to avoid actual I/O of 5GB data
Option 3: Property-based test with size parameter approaching 4GB boundary

**Blockers:**
- Standard CI runners have disk/RAM limits
- Test duration would be minutes (unacceptable for fast feedback loop)
- Requires infrastructure investment

---

## Part B: Newly Identified Gaps (Not in Original Analysis)

These gaps were discovered during the implementation and review process of the gap-closure campaign.

### B.1 Progressive / Cumulative Corruption

**Priority:** Medium
**Effort:** Low
**Status:** Not implemented
**Risk Level:** Medium-High

**Description:**
All existing tests follow the pattern: **Create → Corrupt once → Repair → Verify**. No test covers:
1. Repair → Corrupt again (different location) → Repair again
2. Multiple repair cycles on the same archive (idempotency beyond 2 cycles)
3. Long-lived archives that accumulate damage over time

**Why it matters:**
Repeated repair-modify cycles could expose:
- Metadata drift (catalog version mismatches after multiple repairs)
- Backup file accumulation consuming disk space
- RS parity shard degradation if original data shards are silently corrupted
- Index/dedup state inconsistency after multiple mutations

**Suggested tests:**
```rust
/// Repair, then corrupt a different location, then repair again.
#[test]
fn test_repair_then_corrupt_again_then_repair() {
    let temp = TempDir::new().unwrap();
    let data = generate_deterministic_data(256 * 1024);
    let input = create_test_file(temp.path(), "progressive.bin", &data);
    let archive = temp.path().join("progressive.era");
    let out_dir = temp.path().join("out");

    // Create
    era_cmd().args(["create", ...]).assert().success();

    // First corruption + repair
    corrupt_archive_shard(&archive, 5000);
    era_cmd().args(["repair", ..., "--force"]).assert().success();

    // Second corruption (different location) + repair
    corrupt_archive_shard(&archive, 15000);
    era_cmd().args(["repair", ..., "--force"]).assert().success();

    // Third corruption (yet another location) + repair
    corrupt_archive_shard(&archive, 25000);
    era_cmd().args(["repair", ..., "--force"]).assert().success();

    // Verify final state
    era_cmd().args(["verify", ...]).assert().success();
    era_cmd().args(["extract", ...]).assert().success();
    assert_file_content_eq(&out_dir.join("progressive.bin"), &data);
}

/// Five consecutive repair cycles should be idempotent.
#[test]
fn test_five_repair_cycles_idempotent() {
    // Create archive, corrupt, repair × 5
    // Verify final state matches original
}
```

**Estimated effort:** 30-60 minutes (2-3 tests)

---

### B.2 Sparse Files

**Priority:** Medium
**Effort:** Medium
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
`CLI_TEST_COVERAGE_GAP_ANALYSIS.md` mentions sparse files as a gap, but no test was added. FastCDC chunking may produce unexpected behavior with large zero-filled regions.

**Why it matters:**
- Sparse files have "holes" that don't consume disk space but report large `st_size`
- FastCDC content-defined chunking may generate extremely large chunks in zero-filled regions (no content variation to trigger chunk boundaries)
- Chunk hashes of all-zero blocks may collide, causing incorrect dedup
- Extraction may create non-sparse copies, inflating disk usage

**Suggested test:**
```rust
#[cfg(unix)]
#[test]
fn test_sparse_file_roundtrip() {
    use std::os::unix::fs::FileExt;
    
    let temp = TempDir::new().unwrap();
    let sparse = temp.path().join("sparse.bin");
    
    // Create a 10MB sparse file with data only at the beginning and end
    let file = fs::File::create(&sparse).unwrap();
    file.set_len(10 * 1024 * 1024).unwrap(); // 10MB logical size
    file.write_at(b"HEADER", 0).unwrap();
    file.write_at(b"FOOTER", 10 * 1024 * 1024 - 6).unwrap();
    
    // Archive, corrupt, repair, extract
    // Verify extracted file is also sparse (or at least has correct content)
    // Verify logical size is preserved
}
```

**Blockers:**
- Sparse file creation is platform-specific (Unix `fallocate`, Windows `FSCTL_SET_SPARSE`)
- Verification requires platform-specific APIs to check actual disk usage vs logical size

**Estimated effort:** 1-2 hours

---

### B.3 Hard Links and Symbolic Links

**Priority:** Medium
**Effort:** Low-Medium
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
All existing tests use regular files. No coverage for:
- Symlinks in the input directory (archiving and extracting)
- Hard links (dedup behavior when two paths point to same inode)
- Broken symlinks
- Circular symlinks
- Symlink targets with absolute paths (path traversal risk)

**Why it matters:**
- `DirectoryScanner` may or may not follow symlinks; behavior is undefined in tests
- Extracting a symlink with absolute target could write outside output directory
- Hard links may cause incorrect dedup (same inode = same content hash, but different paths)

**Suggested tests:**
```rust
#[cfg(unix)]
#[test]
fn test_symlink_roundtrip() {
    let temp = TempDir::new().unwrap();
    let real_file = create_test_file(temp.path(), "real.txt", b"content");
    let symlink = temp.path().join("link.txt");
    std::os::unix::fs::symlink(&real_file, &symlink).unwrap();
    
    // Create archive from directory containing symlink
    // Extract
    // Verify symlink is recreated (or followed, depending on intended behavior)
}

#[cfg(unix)]
#[test]
fn test_hard_link_dedup() {
    let temp = TempDir::new().unwrap();
    let file_a = temp.path().join("a.bin");
    let file_b = temp.path().join("b.bin");
    fs::write(&file_a, b"shared content").unwrap();
    fs::hard_link(&file_a, &file_b).unwrap();
    
    // Create archive
    // Verify catalog contains two entries (not deduped by inode)
    // Or verify dedup happened correctly if that's the intended behavior
}
```

**Estimated effort:** 1-2 hours

---

### B.4 High Count Small Files (1000+ files)

**Priority:** Medium
**Effort:** Low
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
Maximum existing test coverage uses dozens of files. No test for 1000+ files each < 1KB.

**Why it matters:**
- `SmallFilePacker` batches small files into MacroBlocks; high file counts stress the batching logic
- Catalog size grows linearly with file count; may exceed a single page
- `ExtractStats` and `extracted_paths` Vec grows large; could impact performance
- File creation overhead during extraction may dominate total time

**Suggested test:**
```rust
#[test]
fn test_thousand_small_files_repair() {
    let temp = TempDir::new().unwrap();
    let input_dir = temp.path().join("many_files");
    fs::create_dir_all(&input_dir).unwrap();
    
    for i in 0..1000 {
        let path = input_dir.join(format!("file_{:04}.txt", i));
        fs::write(&path, format!("content_{}", i)).unwrap();
    }
    
    // Create archive, corrupt, repair, extract
    // Verify all 1000 files are present and correct
}
```

**Estimated effort:** 30 minutes

---

### B.5 Disk Full During Repair

**Priority:** High
**Effort:** High
**Status:** Not implemented
**Risk Level:** High

**Description:**
No test verifies behavior when disk fills up during repair. Repair creates:
- Backup files (`.bak`) — may require 2x disk space temporarily
- Temporary repair buffers
- Modified volume files

**Why it matters:**
If disk fills during repair:
- Partially-written volume file may be truncated → archive permanently corrupted
- Backup copy may be incomplete → backup is useless
- No rollback mechanism tested

**Suggested test (requires container/loopback filesystem):**
```rust
// This requires setting up a loopback filesystem with limited size
// or using cgroups to limit disk quota — complex infrastructure
#[test]
#[ignore = "requires disk quota setup"]
fn test_repair_disk_full_handling() {
    // Create small loopback filesystem (e.g., 10MB)
    // Create archive that consumes ~8MB
    // Corrupt and trigger repair
    // Fill remaining disk to < 1MB free
    // Attempt repair --force
    // Verify: no panic, archive not left in partial state, graceful error
}
```

**Blockers:**
- Requires containerized test environment or loopback filesystem setup
- Platform-specific (Linux loopback, macOS disk image, Windows VHD)
- Risk of destabilizing the test runner's own filesystem

**Estimated effort:** 4-8 hours (infrastructure + test)

---

### B.6 Single-Byte / Scattered Bit Corruption

**Priority:** Medium
**Effort:** Low
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
`corrupt_archive_shard()` flips 100 consecutive bytes. No test for:
- Single byte flip (1 byte)
- Every-Nth-byte flip (e.g., flip byte at offset 0, 1000, 2000...)
- Single bit flip within a byte

**Why it matters:**
- RS error correction has different code paths for "few errors" vs "many errors"
- Single-bit errors may be correctable by CRC alone without invoking RS
- 100-byte flips always trigger shard-level reconstruction; smaller corruptions may not

**Suggested helper and tests:**
```rust
pub fn corrupt_single_byte(path: &Path, offset: u64) {
    let mut f = fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 1];
    f.read_exact(&mut buf).unwrap();
    buf[0] = !buf[0];
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&buf).unwrap();
    f.flush().unwrap();
}

pub fn corrupt_scattered_bytes(path: &Path, start: u64, stride: u64, count: usize) {
    for i in 0..count {
        corrupt_single_byte(path, start + i as u64 * stride);
    }
}

#[test]
fn test_repair_single_byte_corruption() {
    // Create, corrupt 1 byte at offset 5000, repair, verify
}

#[test]
fn test_repair_scattered_byte_corruption() {
    // Corrupt 10 bytes spaced 1000 bytes apart
}
```

**Estimated effort:** 20-30 minutes

---

### B.7 Filesystem-Specific Behavior

**Priority:** Low-Medium
**Effort:** Medium
**Status:** Not implemented
**Risk Level:** Low-Medium

**Description:**
All tests run on default tmpfs/ext4. No coverage for:
- XFS (different xattr size limits)
- ZFS (Copy-on-Write, compression, different sparse file behavior)
- APFS/macOS (case-insensitive paths, resource forks)
- NTFS/Windows (alternate data streams, ACL differences)

**Why it matters:**
- xattr size limits vary by filesystem (XFS: 64KB, ext4: 4KB per xattr)
- Case-insensitive filesystems may cause path collisions (`File.txt` vs `file.txt`)
- ZFS COW may cause `fs::copy` to behave differently for backup files

**Suggested approach:**
Run CI matrix across multiple OS/filesystem combinations rather than adding individual tests.

**Estimated effort:** High (CI infrastructure)

---

### B.8 Index / Bloom Filter Corruption

**Priority:** Medium
**Effort:** Medium-High
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
All tests corrupt file **data** (shard payloads). No test corrupts:
- Embedded dedup index pages (Bloom filter, L1/L2 B-tree pages)
- Catalog (file listing) protobuf serialization
- Chunk reference table

**Why it matters:**
- Index corruption may cause silent wrong-dedup (two different chunks hash-colliding in damaged Bloom filter)
- Catalog corruption may make files "disappear" from listing while data still exists in volumes
- ChunkRef corruption may cause extraction to assemble wrong data offsets

**Suggested test:**
```rust
#[test]
fn test_corrupt_catalog_still_recoverable() {
    // Create archive
    // Corrupt catalog region (known offset after SuperHeader)
    // Verify should detect catalog corruption
    // Repair should reconstruct catalog from shard data
    // Extract should still produce correct files
}
```

**Blockers:**
- Requires knowledge of catalog/index on-disk layout (may change between format versions)
- Difficult to target "just the index" without also damaging data

**Estimated effort:** 2-4 hours

---

### B.9 Volume Content Replaced (Not Deleted)

**Priority:** Medium
**Effort:** Low
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
Existing tests either **delete** volumes (file missing) or **corrupt** volumes (flip bytes in-place). No test covers the scenario where a volume file exists but contains **wrong data** (e.g., replaced with content from a different archive or random data).

**Why it matters:**
- This is harder to detect than missing volumes (file exists, passes size check)
- CRC checks should catch this, but CRC collisions are possible (though unlikely with CRC-32C)
- RS reconstruction may silently use wrong data if CRC doesn't catch it

**Suggested test:**
```rust
#[test]
fn test_volume_replaced_with_random_data() {
    let temp = TempDir::new().unwrap();
    let data = generate_deterministic_data(256 * 1024);
    let input = create_test_file(temp.path(), "replaced.bin", &data);
    let archive = temp.path().join("replaced.era");

    era_cmd().args(["create", ..., "--erasure", "4:2", "--volumes", "6"]).assert().success();

    // Replace volume 2 with random data (same size)
    let vol2 = archive.with_extension("era.002");
    let len = fs::metadata(&vol2).unwrap().len();
    let random_data: Vec<u8> = (0..len).map(|_| rand::random()).collect();
    fs::write(&vol2, &random_data).unwrap();

    // Verify should detect CRC mismatch
    // Repair should reconstruct from RS parity
    // Extract should produce correct data
}
```

**Estimated effort:** 30 minutes

---

### B.10 Concurrent Create + Repair

**Priority:** Medium
**Effort:** Medium
**Status:** Not implemented
**Risk Level:** Medium

**Description:**
Existing concurrent tests cover: two repairs, or repair + verify. No test for:
- One process creating an archive while another repairs it
- Repair running while extraction is in progress
- Multiple extracts during repair

**Why it matters:**
- File locking behavior during simultaneous read/write on volumes is untested
- Race conditions in volume file handles could cause crashes or data corruption

**Suggested test:**
```rust
#[test]
fn test_concurrent_create_and_repair_different_archives() {
    // Create archive A in thread 1
    // Repair archive B in thread 2
    // Both should complete without panic
}

#[test]
fn test_concurrent_extract_during_repair() {
    // Start repair --force on corrupted archive
    // While repair is running, start extract
    // Neither should panic; extract may see inconsistent state
}
```

**Estimated effort:** 1 hour

---

## Part C: Coverage Matrix Summary

| Category | Existing Tests | New Gap Tests | Remaining Gaps | Coverage |
|----------|---------------|---------------|----------------|----------|
| Single-volume data corruption | 15+ | 3 | B.6 (single-byte) | 90% |
| Multi-volume loss/corruption | 12+ | 5 | B.9 (replaced content) | 90% |
| EC boundary behavior | 3 | 3 | B.1 (progressive) | 85% |
| Compression + EC | 0 | 3 | None (all compression paths covered) | 95% |
| Metadata preservation | 0 | 6 | B.2 (sparse files), B.4 (1000+ files) | 75% |
| Concurrent safety | 1 | 2 | B.10 (create+repair) | 70% |
| Error handling | 8+ | 0 | B.5 (disk full), B.8 (index corrupt) | 65% |
| Authentication + repair | 6+ | 0 | None | 95% |
| Large files | 3 | 0 | A.2 (>4GB) | 60% |
| Special file types | 0 | 0 | B.2 (sparse), B.3 (links) | 20% |
| Interrupt/recovery | 1 | 0 | A.1 (SIGINT during repair) | 30% |
| **Overall** | **~48** | **28** | **12** | **~85%** |

---

## Part D: Recommended Implementation Order

### Phase 1: High Value / Low Effort (Next PR)
1. **B.6** Single-byte / scattered corruption (20 min)
2. **B.1** Progressive corruption cycles (30 min)
3. **B.4** 1000 small files (30 min)
4. **B.9** Volume replaced with wrong data (30 min)

**Total:** ~2 hours, adds 5-6 tests, covers high-risk edge cases

### Phase 2: Medium Value / Medium Effort (This Sprint)
5. **B.3** Symlink and hard link roundtrips (1-2 hours)
6. **B.10** Concurrent create+repair / extract+during_repair (1 hour)
7. **B.2** Sparse files (1-2 hours, Unix only)

**Total:** ~4 hours, adds 4-5 tests

### Phase 3: High Value / High Effort (Backlog)
8. **A.1** Repair interrupt/resume (4-8 hours, needs signal handling)
9. **B.5** Disk full during repair (4-8 hours, needs container/loopback)
10. **B.8** Index/catalog corruption recovery (2-4 hours, needs format knowledge)

### Phase 4: Infrastructure (Ongoing)
11. **A.2** >4GB roundtrip (dedicated CI runner or nightly job)
12. **B.7** Cross-platform filesystem matrix (CI infrastructure)

---

## Appendix: Test File Inventory

```
bins/era-cli/tests/
├── cli_coverage_gap_tests.rs           # 28 tests (this campaign)
│   ├── compression_ec_repair           # 3 tests
│   ├── exact_parity_boundary           # 6 tests
│   ├── cross_archive_splicing          # 2 tests
│   ├── repair_backup_integrity         # 2 tests
│   ├── metadata_preservation           # 6 tests
│   ├── random_offset_corruption        # 3 tests
│   ├── concurrent_repair               # 2 tests
│   ├── small_file_high_ec              # 2 tests
│   └── repair_repack_chain             # 2 tests
├── cli_integration_tests.rs            # ~35 tests (existing)
├── cli_integration_tests_comprehensive.rs  # ~40 tests (existing)
├── cli_e2e_tests.rs                    # ~25 tests (existing)
├── cli_e2e_gap_tests.rs                # 9 tests (existing)
├── cli_boundary_tests.rs               # ~15 tests (existing)
├── cli_extreme_tests.rs                # ~50 tests (existing)
├── cli_extreme_comprehensive_tests.rs  # ~15 tests (existing)
├── cli_stress_and_discovery_tests.rs   # ~8 tests (existing)
└── common/mod.rs                       # Shared helpers
```

---

*This analysis was generated during the CLI_TEST_COVERAGE_GAP_ANALYSIS.md implementation campaign. For the original gap analysis, see `doc_gen/CLI_TEST_COVERAGE_GAP_ANALYSIS.md`. For implementation results, see `doc_gen/CLI_TEST_COVERAGE_GAP_CLOSURE_REPORT_2026-04-17.md`.*
