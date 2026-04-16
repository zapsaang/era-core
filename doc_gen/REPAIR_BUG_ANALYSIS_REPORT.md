# Repair Bug Analysis Report: test_large_file_1gb_repair_after_corruption

**Date:** 2026-04-14
**Test:** `bins/era-cli/tests/cli_e2e_gap_tests.rs::test_large_file_1gb_repair_after_corruption`
**Status:** `#[ignore]` - Pre-existing known bug
**Symptom:** Repair claims success, but `era verify` fails with `Integrity error: BlockHeader CRC verification failed`
**Trigger:** Release mode only (`--release`), not debug mode

---

## 1. Problem Analysis

### Test Flow
1. Create 1GB file with `--erasure "4:2"` (4 data + 2 parity shards)
2. Corrupt 100 bytes at offset 5000 via `corrupt_archive_shard(archive, 5000)`
3. Run `era repair --force --password pwd`
4. Repair reports success
5. Run `era verify --password pwd`
6. **FAIL:** `Integrity error: BlockHeader CRC verification failed`

### Error Source
```
era-volume/src/reader.rs:416
"BlockHeader CRC verification failed".into()
```
The `BlockHeader::verify()` CRC check fails during verify.

---

## 2. Root Cause Analysis

### A. Archive Type Determination

The archive created with `--erasure "4:2"` (no `--max-volume-size`) is a **single-volume** archive:
- Only `.era` file exists, NO `.era.001` 
- `header.total_volumes() = 0` (never set during creation)
- CLI detects single-volume via `archive.era.001` existence check
- Engine uses `repair_archive` (single-volume path), NOT `repair_archive_matrix`

**Call path:**
```
era repair --force archive.era
  → commands.rs:876-893 (CLI handler)
  → repair_archive(archive, password, options)  [NOT repair_archive_matrix]
  → repair.rs:305 preflight_metadata_recovery()
  → repair.rs:320+ single-volume shard repair loop (RS decoding per-block)
```

### B. Data Layout at Offset 5000

```
Offset 0-4095:     Primary Header (4096 bytes) - MAGIC "ERA\x08\x01"
Offset 4096-4223:  Backup Footer gap (128 bytes)  
Offset 4224+:      Data Region

Offset 5000 is 776 bytes into the data region (5000 - 4224 = 776)
```

For 4+2 erasure (6 shards per block), each block has:
- `prefix_bytes`: 16 bytes (4 × 4-byte length fields for each data shard)
- Per shard: `ShardHeader` (8 bytes: 4 length + 4 CRC) + data

Offset 5000 falls **inside shard data**, NOT in a header. The 100-byte corruption at offset 5000 inverts bits in shard content.

### C. Release vs Debug Difference Hypothesis

The bug only manifests in `--release` mode. This strongly suggests:

**Hypothesis: Padding/Alignment or Compiler Optimization Issue**

The `ShardRepair` struct contains:
```rust
struct ShardRepair {
    offset: u64,       // 8 bytes
    shard_idx: usize,  // 8 bytes (on 64-bit)
    data: Bytes,       // 24 bytes (ptr + len + capacity)
}
```

In **debug mode**, padding is zero-initialized. In **release mode**, aggressive compiler optimizations could:
1. Reorder memory operations
2. Cache values in registers across awaits
3. Eliminate "redundant" reads that are actually necessary for correctness

### D. Memory/Ownership Analysis (Ruled Out)

The `Bytes` ownership in `repair_shards_rs` is **safe**:
- `Bytes::from(Vec<u8>)` performs a **full ownership transfer**, NOT copy-on-write
- Each shard is cloned before wrapping in `Bytes`
- No dangling reference is possible

```rust
// repair.rs:636-644 - SAFE
let mut data = all_shards[idx].clone();  // data owns Vec<u8>
repaired.push((idx, Bytes::from(data)));  // Bytes takes FULL ownership
```

**However**, there's an **unnecessary allocation** at line 685:
```rust
// WASTEFUL: clone() then Bytes::from() - double copy
let read_crc = compute_shard_crc(&Bytes::from(read_buffer.clone()));

// BETTER: direct borrow
let read_crc = compute_shard_crc(&read_buffer);  // Vec coerces to &[u8]
```

---

## 3. Likely Root Cause

**Most likely bug location: `apply_repairs` function (repair.rs:656-702)**

The repair writes shards at offsets determined during the **scan phase**, but:
1. The offsets come from `shard_offsets` populated during scanning
2. Scanning uses `header_prefix_len = erasure_config.data_shards * 4` (16 bytes for 4+2)
3. But the actual block structure might differ from what repair expects

**The key issue**: If `repair.offset` is computed based on wrong assumptions about block structure (e.g., assuming `ShardHeader` format when the data actually uses a different format), then:
- Repair writes repaired data to correct offset
- But verify reads from a different offset and finds wrong data
- OR: Repair writes to wrong offset, verification passes (by luck), but subsequent read fails

```rust
// apply_repairs lines 659-699
fn apply_repairs(path: &Path, repairs: &[ShardRepair]) -> Result<()> {
    for repair in repairs {
        let crc = compute_shard_crc(&repair.data);  // CRC of REPAIRED data
        let header = ShardHeader::new(repair.data.len() as u32, crc);
        
        // Writes HEADER at repair.offset
        file.seek(SeekFrom::Start(repair.offset))?;
        file.write_all(&header_bytes)?;  // ← ShardHeader written FIRST
        
        // Writes DATA at repair.offset + header_bytes.len()
        file.seek(SeekFrom::Start(data_offset))?;
        file.write_all(&repair.data)?;
        
        // Verification reads back
        file.read_exact(&mut read_buffer)?;
        let read_crc = compute_shard_crc(&read_buffer);
        if read_crc != crc {  // ← This would catch write failures
            return Err(...);
        }
    }
}
```

---

## 4. Fix Strategies Comparison

| Method | Effort | Risk | Impact | Complexity |
|--------|--------|------|--------|------------|
| **A. TDD Test-First Isolation** | Low | None | Diagnoses exact cause | Simple |
| **B. Add Debug Assertions** | Low | None | Better diagnostics | Simple |
| **C. Fix apply_repairs Ordering** | Medium | Low | Likely fixes the bug | Localized |
| **D. Re-examine verify Path** | High | Medium | May miss root cause | Broad |

---

## 5. Recommended Approach: TDD with Focused Tests

### Step 1: Write Isolating Tests

```rust
// In era-engine/tests/repair_crc_tests.rs (new file)

/// Test that repair + verify works on small erasure-coded archive
#[test]
fn test_repair_single_shard_corruption_small() {
    // 1. Create small archive with 4:2 erasure (16MB input)
    // 2. Corrupt 10 bytes at known offset in data region
    // 3. Run repair
    // 4. Run verify - should pass
    // 5. Extract and compare - should match original
}

/// Test that post-write CRC verification catches mismatches
#[test]
fn test_repair_read_back_verification() {
    // Explicitly tests apply_repairs line 678-691
    // If written CRC != computed CRC, repair should fail
}

/// Test large file pattern at reduced scale
#[test]
fn test_repair_large_file_pattern_16mb() {
    // Reproduce 1GB pattern at smaller scale
    // See if bug manifests at smaller sizes
}
```

### Step 2: Add Diagnostic Instrumentation

```rust
// In apply_repairs, add before/after hex dumps for first N repairs
fn apply_repairs(path: &Path, repairs: &[ShardRepair]) -> Result<()> {
    for (i, repair) in repairs.iter().enumerate() {
        if i < 3 {
            debug!("Repair #{}: offset={}, len={}", 
                   i, repair.offset, repair.data.len());
        }
        
        // Existing code...
        
        // Add: explicit offset verification
        let computed_offset = repair.offset;
        file.seek(SeekFrom::Start(computed_offset))?;
        
        // Verify written CRC matches computed CRC
        let verify_crc = compute_shard_crc(&repair.data);
        if verify_crc != crc {
            return Err(EraError::IntegrityError(format!(
                "Repair #{}: CRC mismatch at offset {}: expected {}, got {}",
                i, computed_offset, crc, verify_crc
            )));
        }
    }
}
```

### Step 3: Potential Simple Fix

```rust
// Change line 682-685 from:
let mut read_buffer = vec![0u8; repair.data.len()];
file.read_exact(&mut read_buffer)?;
let read_crc = compute_shard_crc(&Bytes::from(read_buffer.clone())));

// To (simpler, more reliable):
let mut read_buffer = Vec::with_capacity(repair.data.len());
read_buffer.resize(repair.data.len(), 0);
file.read_exact(&mut read_buffer)?;
let read_crc = compute_shard_crc(&read_buffer);  // Direct slice, no Bytes wrapper
```

---

## 6. Verification Test Plan

| Test | Purpose | Expected Result |
|------|---------|-----------------|
| `test_repair_verification_after_small_corruption` | Does repair + verify work on small file? | Pass |
| `test_repair_verification_after_large_corruption` | Does 100-byte corruption get repaired? | Should Pass (currently fails) |
| `test_repair_read_back_integrity` | Is CRC correct after write? | Should Pass |
| `test_release_repair_same_as_debug` | Is release same as debug? | Should Pass |

---

## 7. Summary

**The bug is most likely in `apply_repairs` (repair.rs:656-702)**:
- The "post-write CRC verification" (lines 678-691) should catch any write issues
- But if repair writes CORRECT data to WRONG offset, verification would still pass
- The verify path then fails because it reads from the CORRECT offset (which still has corrupted data)

**The fix should focus on**:
1. Writing a TDD test that reproduces the issue at smaller scale
2. Verifying that `repair.offset` is correct for each repaired shard
3. Ensuring the verify path uses the same offset calculation as repair

**Low-risk fix location**: `apply_repairs` function, ensuring `repair.offset` is debuggable and adding explicit offset verification before write.

---

## 8. Key Files to Investigate

| File | Lines | Relevance |
|------|-------|-----------|
| `era-engine/src/repair.rs` | 656-702 | `apply_repairs` - likely bug location |
| `era-engine/src/repair.rs` | 345-440 | Single-volume shard scanning |
| `era-volume/src/reader.rs` | 380-431 | `read_typed_block` - verify path |
| `era-engine/src/block_iter.rs` | 1140-1300 | SessionErasureBlockIterator |
| `era-common/src/types/block.rs` | 450-516 | `BlockHeader::verify()` |
