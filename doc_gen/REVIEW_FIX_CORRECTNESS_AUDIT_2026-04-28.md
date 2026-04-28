# Review Fix Correctness Audit Report

**Date:** 2026-04-28  
**Auditor:** Oracle (Sisyphus Orchestration Layer)  
**Scope:** Correctness and completeness of fixes applied to address findings from cross-review report `20260427-165250-review.md` (33 findings: 1 critical, 8 high, 19 medium, 5 low).  
**Status:** PARTIAL — fixes are directionally correct but two residual security-level issues remain.

---

## 1. Executive Summary

The fix set addresses the majority of the cross-review findings with sound, targeted changes. However, **the fix set is NOT ready for merge** because two residual issues of security relevance were identified during audit:

1. **Critical-class residual:** Catalog blocks replicated across multiple volumes may encrypt with the same key+nonce pair, violating the XChaCha20-Poly1305 uniqueness contract.
2. **High-class residual:** Secondary index fanout blocks and the `IndexReader` recovery path disagree on the AEAD context string and ciphertext framing, which will cause cold-recovery failures.

Both issues stem from the same root cause: the fix set added typed AAD binding and catalog multi-volume replication, but did not fully thread the `volume_index` into the nonce derivation path for metadata blocks, and did not align the index fanout write contract with the reader's decryption contract.

---

## 2. Background: Original Review Findings

The cross-review (`20260427-165250-review.md`) identified 33 findings across five severity classes. The most impactful were:

| ID | Severity | Finding | Fixed? |
|---|---|---|---|
| GLOBAL-001 | Critical | Checkpoint block ID collision (`next_block_id()` not advanced) | Yes |
| GLOBAL-004 | High | Precheck sizing incomplete (index + manifest not counted) | Yes |
| GLOBAL-009 | High | Typed AAD missing type identifier | Yes |
| (various) | Medium | Rotation logic drained active writers before rotating | Yes |

---

## 3. Fixes Applied (Verified)

All of the following fixes were verified by Oracle and found to be **correct and complete**:

### 3.1 Block ID Reservation Fix (GLOBAL-001)
- **Location:** `crates/era-engine/src/write_pipeline.rs`
- **Change:** `checkpoint_commit()` now calls `next_block_id()` (reserving 1) or `reserve_block_id(n)` (reserving N) before writing checkpoint blocks.
- **Verification:** Confirmed that no two checkpoint blocks share the same logical block ID within an epoch.

### 3.2 Typed AAD Binding (GLOBAL-009)
- **Location:** `crates/era-crypto/src/aead_context.rs`, `crates/era-packing/src/session_builder.rs`
- **Change:** `build_aad()` now includes the `BlockType` discriminant in the AAD: `archive_id ‖ epoch_id ‖ volume_index ‖ block_index ‖ block_type`.
- **Verification:** Confirmed that typed blocks cannot be cross-spliced between `Data`, `Index`, `Manifest`, or `Catalog` roles.

### 3.3 Precheck Sizing (GLOBAL-004)
- **Location:** `crates/era-engine/src/writer.rs`, `crates/era-index/src/builder.rs`
- **Change:**
  - `estimated_finalized_disk_size()` added to `era-index` builder; performs a full serialization pass of the index without writing to disk.
  - `precheck_and_rotate_if_needed()` now receives total on-disk estimates that **include** catalog, index, and manifest sizes.
  - `BlockHeader::SIZE` overhead removed from pool precheck; callers now include header + encryption overhead explicitly.
- **Verification:** Confirmed that the precheck no longer underestimates space requirements.

### 3.4 Rotation Logic Cleanup
- **Location:** `crates/era-volume/src/volume_pool.rs`
- **Change:** Rotation no longer drains active writers before closing the current volume.
- **Verification:** Confirmed that in-flight blocks are not lost during rotation.

### 3.5 Compilation & Style Fixes
- `#[allow(clippy::too_many_arguments)]` added where needed.
- `CatalogBlockSets` type alias extracted to satisfy `type_complexity` lint.
- All targeted test suites pass:
  - `cargo test -p era-index`
  - `cargo test -p era-engine --test manifest_roundtrip`
  - `cargo test -p era-volume typed_block_precheck`
  - `cargo fmt --all -- --check`
  - `cargo clippy -p era-engine -p era-index -p era-volume --all-targets -- -D warnings`

---

## 4. Residual Issues (NOT FIXED)

### 4.1 Critical-Class Residual: Catalog Multi-Volume Nonce Uniqueness

**Observation:** When a catalog block is replicated to multiple volumes, the same `logical_block_id` is used across all volumes, but the `volume_index` is only bound into the **AAD**, not into the **nonce**.

**Code locations:**
- `crates/era-engine/src/writer.rs:1375-1388` — `build_catalog_block_sets()` assigns the same `logical_block_id` to catalog replicas on different volumes.
- `crates/era-packing/src/session_builder.rs:184-193` — `encrypt_with_context_for_type()` uses the generic typed AEAD path.
- `crates/era-crypto/src/aead_context.rs:59-61` — Nonce derivation is:
  ```rust
  nonce = HKDF-Expand(PRK=volume_key, info=nonce_context ‖ block_id)
  ```
  The `volume_index` is **not** part of the nonce info.

**Why this matters:** XChaCha20-Poly1305 requires that `(key, nonce)` pairs never repeat for distinct plaintexts. The current code guarantees key uniqueness per volume (each volume has its own `VK`), but **nonce uniqueness is only guaranteed per `(volume, block_id)` pair**. If the same `block_id` is used on the same volume twice, or if the HKDF info is not volume-unique, nonce reuse is possible.

**Threat scenario:** An attacker who can observe two catalog ciphertexts encrypted with the same `(VK, nonce)` but different AADs can exploit the AEAD stream-cipher properties to XOR the ciphertexts and recover the XOR of the two plaintexts. While the AAD differs, the underlying ChaCha20 keystream is identical, which violates the security contract.

**Fix required:** Include `volume_index` in the nonce derivation info string:
```rust
nonce = HKDF-Expand(PRK=volume_key, info=nonce_context ‖ volume_index ‖ block_id)
```
This must be done for **all** metadata block types that support multi-volume replication (catalog, and potentially manifest if it is ever replicated).

---

### 4.2 High-Class Residual: Index Fanout / Reader Contract Mismatch

**Observation:** The secondary index fanout blocks written during finalization do not use the same AEAD context string or ciphertext framing that `IndexReader` expects during cold recovery.

**Code locations:**
- `crates/era-index/src/builder.rs:334-357` and `:426-441` — Canonical index pages use context `"ERA_IDX_v2.1_Page"` (or equivalent) and a typed AEAD path.
- `crates/era-engine/src/volume_stage.rs:430-463` — Secondary index fanout uses the **base** context string (not the index-specific one) and writes `nonce ‖ ciphertext` as raw bytes.
- `crates/era-index/src/reader.rs:411-420` — `IndexReader` recovery expects the canonical index context `"ERA_IDX_v2.1_Page"` and does **not** strip a prepended nonce.

**Why this matters:** If a secondary index fanout block is ever read by `IndexReader` (e.g., during a repair or cold-recovery scenario where the primary index is lost), decryption will fail because:
1. The context string mismatch causes HKDF to derive the wrong key.
2. The nonce prefix causes the ciphertext to be misaligned, leading to AEAD tag verification failure.

**Fix required:** Align the fanout write path in `volume_stage.rs` with the canonical index encryption contract in `builder.rs`. Specifically:
- Use the same `BlockType::Index` typed AEAD path.
- Do **not** prepend a separate nonce; let the typed AEAD path handle nonce generation and framing.
- Ensure `IndexReader` can decrypt both canonical index pages and fanout blocks without branch divergence.

---

## 5. Additional Technical Debt Identified

### 5.1 Manifest / Commitment Verification Gap
- **Location:** `crates/era-engine/tests/manifest_roundtrip.rs:135-179`
- **Observation:** Tests verify that raw bytes and nonces differ between volumes, and that the footer is present. They do **not** decrypt or deserialize the manifest from non-primary volumes, nor do they verify catalog/index cryptographic commitments.
- **Recommendation:** Add a test that mounts a non-primary volume and performs a full manifest decryption + catalog/index commitment verification.

### 5.2 Fragile Audit-Marker Tests
- **Location:** `crates/era-index/src/reader.rs` (multiple lines)
- **Observation:** Some tests rely on string matching of audit-marker comments rather than behavioral assertions.
- **Recommendation:** Replace comment-string tests with property-based or behavioral tests (e.g., "decrypting with wrong context fails with `Security` error").

---

## 6. Recommendations

| Priority | Action | Owner | Effort |
|---|---|---|---|
| P0 (Blocker) | Include `volume_index` in metadata nonce derivation | Crypto / Engine | Small |
| P0 (Blocker) | Align index fanout write path with `IndexReader` decrypt contract | Engine / Index | Medium |
| P1 | Add non-primary volume manifest decryption test | Engine QA | Small |
| P1 | Replace audit-marker string tests with behavioral tests | Index QA | Small |
| P2 | Document the typed AAD + nonce derivation contract in `aead_context.rs` | Docs | Small |

---

## 7. Conclusion

The fix set is **directionally correct** and resolves the majority of the original cross-review findings. However, **it cannot be merged as-is** because:

1. **Catalog nonce reuse across volumes** is a violation of the AEAD security contract.
2. **Index fanout / reader contract mismatch** will cause cold-recovery failures.

Both issues require targeted fixes before the PR is considered complete. Once those fixes are applied, a re-audit focused specifically on nonce uniqueness and index fanout symmetry should be performed.

**Oracle verdict:** Fix set is **incomplete**. Address residual issues and re-verify.

---

*Report generated by Oracle agent (session: `ses_22e2c1a0effexeQ3bjf1UpP0M1`) as part of Sisyphus orchestration.*
