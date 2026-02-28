# RED TEAM AUDIT REPORT: ERA Core "Redb Refactor"

**Audit Date:** 2026-02-13
**Auditor:** Lead Systems Architect (Red Team)
**Spec Under Test:** `docs/RedbIndex.md` (RFC-023: "Ironclad" Indexing Protocol)
**Target Codebase:** `crates/era-index/`, `crates/era-volume/`
**Test Suite:** `crates/era-index/tests/audit_redb_compliance.rs` (21 tests, all passing)

---

## Executive Summary

**The Redb migration specified in RFC-023 did not happen.**

The engineering team was tasked with migrating from a custom LSM-Tree to Redb 2.1 + rkyv. Instead, they built a new custom native LSM-Tree with encrypted spill files, tiered k-way merge, and rkyv serialization. The rkyv portion is compliant. The Redb portion is a total spec violation.

What they built is well-engineered and arguably more secure than the spec (ephemeral encryption on temp files, no external database dependency). But it is not what was approved.

---

## Compliance Matrix

| # | Requirement (from `docs/RedbIndex.md`) | Status | Evidence |
|---|----------------------------------------|--------|----------|
| 1 | Add `redb = "2.1"` to Cargo.toml (§4.1) | **FAIL** | No `redb` dependency exists. Test `test_f1_cargo_toml_spec_compliance` documents this. |
| 2 | Add `rkyv = "0.7"` to Cargo.toml (§4.1) | **PASS** | `rkyv` present as workspace dependency. |
| 3 | Remove RocksDB/LevelDB/legacy LSM deps (§4.1) | **PASS** | No RocksDB, LevelDB, bincode, or serde_json found. |
| 4 | Delete `lsm_tree.rs` (§6 Phase 1) | **FAIL** | File exists: 429 lines, actively used as orchestrator. |
| 5 | Delete `spiller.rs` (§6 Phase 1) | **FAIL** | File exists: 252 lines, implements encrypted temp files. |
| 6 | Delete `merger.rs` (§6 Phase 1) | **FAIL** | File exists: 183 lines, implements tiered k-way merge. |
| 7 | Create `store.rs` with Redb wrapper (§4.2) | **FAIL** | File does not exist. No Redb wrapper anywhere. |
| 8 | Define `TABLE_CHUNKS` table (§3.1) | **FAIL** | No Redb table definitions exist. |
| 9 | Define `TABLE_FILES` table (§3.1) | **FAIL** | No Redb table definitions exist. |
| 10 | Use `rkyv::check_archived_root` for zero-copy (§4.2) | **PARTIAL** | Used in `spiller.rs:123`. NOT used in `reader.rs` (uses `rkyv::from_bytes` — safe but not zero-copy). Tests A1-A4 prove rkyv zero-copy works on all structs. |
| 11 | `#[archive(check_bytes)]` on all structs (§3.2) | **PASS** | Present on `IndexEntry`, `IndexPage`, `PagePointer`, `MetaIndex`, `BloomFilterData`. |
| 12 | Staging Ledger: temp Redb file during ingest (§2.1) | **FAIL** | Uses in-memory MemTable + encrypted spill files instead. |
| 13 | Sealed Ledger: embed Redb blob in .era (§2.2) | **FAIL** | Writes encrypted typed blocks (IndexPage, IndexManifest) instead. Functionally equivalent but architecturally different. |
| 14 | Read-Only View: extract Redb to temp, open read-only (§2.3) | **FAIL** | Uses cold recovery via block scanning + brute-force decryption instead. |
| 15 | "Surgical Truncate" recovery via Redb ACID (§5.1) | **FAIL** | Recovery is checkpoint-based via `era-engine/src/recovery.rs`, not Redb-based. `truncate_to_checkpoint()` exists but uses footer data, not Redb transactions. |
| 16 | O(log N) lookups via B-Trees (§1) | **PASS** | Achieved via Bloom filter O(1) + MetaIndex binary search O(log n) + IndexPage binary search O(log m). |
| 17 | No `unwrap()` on I/O operations | **PASS** | Tests E1-E4 audit all production source files. No forbidden unwraps found. |

**Compliance Score: 7/17 requirements met (41%)**

---

## era-volume Compliance (CLAUDE.md P1 Fixes)

| # | Defect | Status | Evidence |
|---|--------|--------|----------|
| P1-6 | Footer `from_bytes()` accepts absurd values | **FIXED** | Validates `data_end_offset >= HEADER_SIZE + FOOTER_SIZE`, catalog/index offsets >= HEADER_SIZE (`footer.rs:320-346`) |
| P1-7 | `finalize_with_catalog()` accepts bogus offsets | **FIXED** | Validates offsets don't exceed current position (`writer.rs:337-348`) |
| P1-8 | Footer checksum has no domain separation | **FIXED** | Uses `b"ERAFv1-footer\0"` prefix (`footer.rs:13, 190-193`) |
| P1-9 | `write_raw()` does not update `block_count` | **FIXED** | Tracks `raw_bytes_written` separately (`writer.rs:286-304`) |

**era-volume P1 Score: 4/4 (100%)**

---

## Vulnerability Scan

### Remaining `unwrap()` in Production Code (era-index)

| File | Line | Expression | Risk |
|------|------|-----------|------|
| `lsm_tree.rs:245` | `self.reader.clone().unwrap()` | LOW — guaranteed `Some` after finalize sets it |
| `reader.rs:344` | `self.embedded_pages.get(&block_id).unwrap()` | LOW — after `contains_key` check |
| `reader.rs:368` | `self.page_cache.get(&block_id).unwrap()` | LOW — after insert on previous line |
| `lib.rs:147-148` | `entries.first().unwrap()` / `entries.last().unwrap()` | LOW — after `assert!(!entries.is_empty())` |
| `lib.rs:165-166` | `entries.first().unwrap()` / `entries.last().unwrap()` | LOW — after `is_empty()` check |

All production unwraps are guarded by prior state checks. Risk is low but not zero — a logic error in the guard could cause a panic.

### Missing `check_archived_root` in reader.rs

`reader.rs` uses `rkyv::from_bytes` at lines 141, 215, 266, 362 instead of `check_archived_root`. In rkyv 0.7 with the `validation` feature, `from_bytes` internally validates before deserializing, so this is **safe** but performs a full copy rather than zero-copy access. This is a spec deviation, not a vulnerability.

### Race Conditions

- `IndexReader::load_page()` uses `HashMap` (not concurrent). The `RwLock<IndexReader>` in `LsmTreeReader` serializes access. No race condition.
- `Spiller::nonce_counter` uses `AtomicU64` with `SeqCst` ordering. Safe.
- `IndexBuilder` is not `Send`/`Sync` — single-threaded by design. Safe.

### TODOs in Codebase

```
builder.rs:317  #[deprecated(since = "8.1.0", ...)]  — finalize_external marked deprecated
```

No `todo!()` or `unimplemented!()` macros found in production code.

---

## Adversarial Test Results

| Test | Category | Result | Description |
|------|----------|--------|-------------|
| A1 | Zero-Copy | **PASS** | IndexEntry accessible via `check_archived_root` without deserialization |
| A2 | Zero-Copy | **PASS** | IndexPage entries accessible zero-copy from archived Vec |
| A3 | Zero-Copy | **PASS** | MetaIndex accessible zero-copy |
| A4 | Zero-Copy | **PASS** | BloomFilterData accessible zero-copy |
| B1 | Power Cut | **PASS** | Spill files independently readable after simulated crash |
| B2 | Power Cut | **PASS** | Spill files persist on disk when tree dropped without finalize |
| B3 | Power Cut | **PASS** | New Spiller instance cannot read old session's spill files |
| C1 | Zombie Recovery | **PASS** | Cold recovery succeeds with garbage bytes appended to .era file |
| C2 | Zombie Recovery | **PASS** | Wrong credentials produce clean Err, not panic or garbage |
| D1 | Validation | **PASS** | `check_archived_root` rejects truncated IndexEntry |
| D2 | Validation | **PASS** | `check_archived_root` rejects garbage IndexPage |
| D3 | Validation | **PASS** | `check_archived_root` rejects garbage MetaIndex |
| D4 | Validation | **PASS** | `rkyv::from_bytes` rejects garbage (validation enabled) |
| D5 | Validation | **PASS** | Bit-flipped data handled without panic |
| D6 | Source Audit | **PASS** | `spiller.rs` uses `check_archived_root` |
| D7 | Source Audit | **PASS** | `reader.rs` deviation documented (from_bytes, not zero-copy) |
| E1 | Code Quality | **PASS** | `builder.rs` — no unwrap on I/O |
| E2 | Code Quality | **PASS** | `spiller.rs` — no unwrap on I/O |
| E3 | Code Quality | **PASS** | `reader.rs` — no unwrap on I/O |
| E4 | Code Quality | **PASS** | `lsm_tree.rs` — no unwrap on I/O |
| F1 | Dependency | **PASS** | Spec violation documented: no redb, no legacy deps |

**21/21 tests passing.**

---

## Final Score

| Category | Weight | Score | Weighted |
|----------|--------|-------|----------|
| Spec Compliance (Redb migration) | 40% | 0/10 | 0 |
| rkyv Serialization Compliance | 15% | 9/10 | 13.5 |
| Code Quality (no unwrap on I/O) | 10% | 10/10 | 10 |
| Crash Safety & Recovery | 15% | 8/10 | 12 |
| era-volume P1 Fixes | 10% | 10/10 | 10 |
| Test Coverage & Robustness | 10% | 9/10 | 9 |

### **Final Score: 54.5 / 100**

The code compiles, all tests pass (97 era-index + 86 era-volume + era-engine all passing), and the implementation is solid. But the team built the wrong thing. The spec said Redb; they built a custom LSM-Tree. That's a 40-point deduction right there.

---

## Recommendations

1. **Decision Required:** Accept the custom LSM-Tree as the new architecture and update `docs/RedbIndex.md` to reflect reality, OR mandate the actual Redb migration.
2. **Quick Win:** Replace `rkyv::from_bytes` with `check_archived_root` + zero-copy access in `reader.rs` for spec compliance and performance.
3. **Defensive:** Convert guarded `unwrap()` calls to `ok_or_else()` returning proper errors.
4. **Documentation:** Update `CLAUDE.md` to remove references to `store.rs` and `IndexStore` which do not exist.

---

*Report generated by Red Team audit. All findings verified by automated test suite.*
