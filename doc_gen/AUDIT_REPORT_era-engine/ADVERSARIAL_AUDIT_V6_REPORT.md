# ADVERSARIAL AUDIT V6 — Current-State Competitive Remediation

**Audit Window:** 2026-03-12  
**Auditor:** Sisyphus (OhMyOpenCode)  
**Target:** `crates/era-engine/` (current-state competitive remediation)  
**Status:** FINAL CURRENT-STATE REMEDIATION REPORT  
**Canonical Plan:** `.sisyphus/plans/era-engine-current-state-competitive-remediation.md`  
**Plan Review:** Momus approved the canonical plan before execution after an initial inline-plan rejection; approval was recorded in the resumed Momus review session `ses_31ed7ccd4ffenaw1UxUnQVha8s`.

---

## Executive Summary

This report closes the current-state competitive audit/remediation slice for `era-engine` using the V5 report and the V5 public-path delta addendum as the baseline. The current pass did **not** reopen any previously closed high/critical public-path issue. Instead, it confirmed and fixed a narrower set of live issues in async filesystem hygiene, non-session iterator semantics, public recovery API truthfulness, and durable checkpoint commit behavior.

The code and verification work for this slice are complete. All newly confirmed V6 findings were fixed in-slice, the current-state verification gates are green, and the current module score remains **97/100 (Low Risk)**. That score is unchanged from the V5 public-path delta baseline because this slice closed all newly confirmed residuals and did not alter the single inherited scored residual from V5.

---

## Review Workflow and Baseline

This slice followed the required Oracle → plan → Momus → execution sequence:

1. **Oracle baseline review** re-checked the V5/V5-delta audit posture and narrowed scope to current-state residuals instead of re-litigating closed historical findings.
2. **Prometheus-equivalent planning** produced the canonical plan at `.sisyphus/plans/era-engine-current-state-competitive-remediation.md`.
3. **Momus plan review** approved the canonical plan after requiring it to exist as a real `.sisyphus/plans/*.md` artifact.
4. **Execution/remediation** implemented the confirmed fixes, tightened the stale audit taxonomy, and ran full verification gates.
5. **Oracle closure review** later confirmed that the remaining missing deliverable was this report itself; publishing this artifact closes that gap.

Historical baseline artifacts used for this slice:

- `doc_gen/AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_REPORT.md`
- `doc_gen/AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_PUBLIC_PATH_DELTA_REPORT.md`

Scope interpretation of the user’s “repeat 30 times” instruction followed the approved plan: it was treated as an ultrawork continuation budget, not as a request for 30 cloned reports.

---

## Baseline Delta From V5 and the V5 Public-Path Addendum

The V5 report and the V5 public-path delta addendum remained the authoritative baseline for this pass. Current-source review and fresh verification did **not** show a reopened high/critical public-path failure. The meaningful current-state residuals instead clustered around four narrower surfaces:

1. blocking `Path::exists()` checks in async writer/recovery flows,
2. non-session erasure iterator validation that contradicted its own sparse original-index contract,
3. a public `RecoverableWriter` resume surface that was not truthful about durable checkpoint support, and
4. a durable-checkpoint commit path that could report success without a recoverable footer on growable volumes.

This slice also confirmed an audit-surface hygiene issue: `competitor_vulnerability_audit.rs` still mixed real current probes with already-fixed or intentionally fenced behavior under stale “vulnerability” labels.

---

## Current Residual Surfaces Audited

### Outcome 1 — Async path checks now match the async engine model

The archive writer and recovery manager both had blocking `Path::exists()` checks inside async flows. These were replaced with `tokio::fs::try_exists(...).await?`, which both removes runtime blocking and stops silently collapsing I/O failures into a false “does not exist” result.

### Outcome 2 — Iterator and recovery contracts are now truthful

The non-session `ErasureBlockIterator::new(...)` constructor documented `volume_indices` as original sequence numbers, but it still validated them against the number of currently present readers. That rejected valid sparse sets such as `[0, 2]`. The incorrect bounds check was removed while duplicate detection was preserved.

The public `RecoverableWriter::new(Resume)` path also no longer pretends to support durable resume. It now fails explicitly and directs callers to the truthful supported path: `ArchiveWriterBuilder` with `recovery_options(RecoveryOptions::resume())`.

### Outcome 3 — Durable checkpoint commit behavior is now recoverable in current write paths

The checkpoint write path previously swallowed a failed footer commit and could claim success after only syncing data. That left checkpoint bytes written without a recoverable footer reference. The engine path now requires the commit to succeed, and `era-volume::VolumeWriter::commit_checkpoint(...)` was updated so growable volumes persist checkpoint state through the reserved backup footer gap instead of failing or silently degrading.

### Outcome 4 — The audit surface is less misleading

`competitor_vulnerability_audit.rs` was tightened so obviously fixed or intentionally fenced behavior is no longer mislabeled as an active vulnerability. Real current/compatibility probes remain, but the suite now better distinguishes active issues from regression guards.

---

## Findings Table

| ID | Area | Severity | Pre-Fix State | Disposition |
|---|---|---:|---|---|
| `V6-PERF-01` | Async filesystem hygiene | Low | `writer.rs` and `recovery.rs` used sync `Path::exists()` in async paths | **FIXED** |
| `V6-LOGIC-01` | Non-session erasure iterator semantics | Medium | `ErasureBlockIterator::new(...)` rejected valid sparse original indices like `[0, 2]` | **FIXED** |
| `V6-API-01` | Public recovery API truthfulness | Medium | `RecoverableWriter::new(Resume)` relied on fresh-state compatibility behavior and did not truthfully model durable resume | **FIXED** |
| `V6-STATE-01` | Durable checkpoint commit correctness | High | checkpoint commit could report success without a recoverable footer path on growable volumes | **FIXED** |
| `V6-AUDIT-01` | Audit/test taxonomy drift | Low | stale “vulnerability” labeling remained in `competitor_vulnerability_audit.rs` for fixed/fenced behavior | **FIXED** |

---

## Fixed vs Still Open

| Item | Status | Notes |
|---|---|---|
| `V6-PERF-01` async exists checks | FIXED | Async `try_exists` now used in writer/recovery hot paths |
| `V6-LOGIC-01` sparse iterator indices | FIXED | Non-session iterator now accepts documented sparse original-index sets |
| `V6-API-01` public resume truthfulness | FIXED | `RecoverableWriter` now errors explicitly instead of implying durable resume |
| `V6-STATE-01` durable checkpoint footer persistence | FIXED | Checkpoint commit now requires footer persistence and supports growable-volume backup-footer commits |
| `V6-AUDIT-01` stale audit labeling | FIXED | Fixed/fenced cases were renamed/reclassified in the competitor audit suite |
| `V5-CRYPTO-01` inherited certificate-path residual | STILL OPEN | Unchanged from V5/V5-delta; current certificate archive path remains X25519-based and is still tracked as `OUT-OF-SCOPE-BY-DESIGN` |

Compatibility-only behaviors that remain intentionally non-durable but are now truthful and fenced:

- `CheckpointManager::load_or_create()` remains a fresh-state compatibility shim.
- `CheckpointManager::{commit(), sync()}` remain deprecated non-durable no-ops.
- `RecoverableWriter` remains an in-memory checkpoint helper rather than a durable resume API.

These were **not** scored as open V6 defects because the public/current-state semantics are now explicit and the supported durable path is the main `ArchiveWriterBuilder` resume flow.

---

## Score Calculation and Final Rating

This slice keeps the deterministic V5/V5-delta penalty model:

`Score = 100 - 20*critical - 10*high - 3*medium - 0.5*low - 5*assurance_contradiction`

Final scoring is based on the **current residual state after remediation**, not on transient pre-fix discoveries.

### Current residual counts after V6 remediation

- Critical: `0`
- High: `0`
- Medium: `1` (`V5-CRYPTO-01`, inherited and unchanged)
- Low: `0`
- Assurance contradiction: `0`

### Calculation

`Score = 100 - (20 × 0) - (10 × 0) - (3 × 1) - (0.5 × 0) - (5 × 0)`

`Score = 97`

**Final current-module rating: 97 / 100 (Low Risk)**

The score remains the same as the V5 public-path delta addendum because this slice fixed every newly confirmed current-state finding and did not change the inherited single scored residual.

---

## Verification Commands and Results

### Targeted verification

| Command / Surface | Result |
|---|---|
| `cargo test -p era-engine --test adversarial_audit_v3 -- --nocapture` | PASS (`22/22`) |
| `cargo test -p era-engine --test adversarial_audit_v5 -- --nocapture` | PASS (`22/22`) |
| `cargo test -p era-engine --test competitor_public_path_delta -- --nocapture` | PASS (`11/11`) |
| `cargo test -p era-engine --test competitor_vulnerability_audit -- --nocapture` | PASS (`21/21`) |
| `cargo test -p era-volume --test adversarial_audit_v2 test_commit_checkpoint_without_max_size_persists_backup_footer -- --nocapture` | PASS (`1/1`) |
| `cargo test -p era-volume --test competitor_vulnerability_audit -- --nocapture` | PASS (`15/15`) |

### Full repository gates

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo test -p era-engine` | PASS |
| `cargo test --workspace` | PASS |

### Diagnostics

`lsp_diagnostics` was run on all touched Rust source and test files for this slice, with **zero** reported diagnostics.

---

## Manual QA Summary

Manual QA was executed through real feature paths and targeted end-to-end tests, not just source-pattern checks.

| Scenario | Evidence of observed outcome |
|---|---|
| Durable checkpoint footer persisted before final closure path | `test_public_checkpoint_commit_persists_footer_before_finalize` passed and observed a recoverable backup-footer checkpoint after write/finalize flow |
| Corrupted durable checkpoint rejected via supported public resume path | `test_v5_state_03_resume_rejects_corrupted_durable_checkpoint` passed |
| Sparse original volume indices accepted by non-session iterator contract | `test_erasure_iterator_accepts_sparse_original_indices` passed and observed `[0, 2] -> [Some(0), None, Some(1)]` mapping |
| Unsupported `RecoverableWriter` durable resume fails explicitly | `test_recoverable_writer_resume_is_explicitly_unsupported` passed |

---

## Evidence Index

- `.sisyphus/plans/era-engine-current-state-competitive-remediation.md`
- `doc_gen/AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_REPORT.md`
- `doc_gen/AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_PUBLIC_PATH_DELTA_REPORT.md`
- `crates/era-engine/src/writer.rs`
- `crates/era-engine/src/recovery.rs`
- `crates/era-engine/src/block_iter.rs`
- `crates/era-engine/src/checkpoint.rs`
- `crates/era-volume/src/writer.rs`
- `crates/era-engine/tests/adversarial_audit_v3.rs`
- `crates/era-engine/tests/adversarial_audit_v5.rs`
- `crates/era-engine/tests/competitor_public_path_delta.rs`
- `crates/era-engine/tests/competitor_vulnerability_audit.rs`
- `crates/era-volume/tests/adversarial_audit_v2.rs`
- `crates/era-volume/tests/competitor_vulnerability_audit.rs`

---

## Final Disposition

This V6 slice confirms a closed current-state remediation pass for the issues it identified. The code, tests, verification gates, and current-state report are now aligned. The current module remains at **97/100**, with no new unresolved V6 finding left open.
