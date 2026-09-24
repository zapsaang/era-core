# Engine Integration Tests

52 Rust test files (~23.5k LOC) plus this `AGENTS.md` in the era-engine integration/audit surface. 279+ adversarial security audit tests. Per convention, files are grouped by role rather than enumerated individually.

## Audit Suites (numbered rounds)

| File | Lines | Focus |
|------|------:|-------|
| `competitor_audit.rs` | 1369 | Core crypto, nonce safety, AEAD correctness |
| `second_audit.rs` | 1311 | Key wrapping, Shamir secret sharing, multi-party access |
| `third_audit.rs` | 1572 | Memory zeroization, TryFrom bounds, source patterns |
| `fourth_audit.rs` | 1649 | Context-bound AAD, path traversal, allocation limits, VK resilience |

## Adversarial Waves

- `adversarial_audit_v1.rs` through `adversarial_audit_v9.rs` — successive adversarial baselines retained for regression lock-in (v5: state machine integrity, resume provenance; v9: splicing/corruption end-to-end; v2: skeptical baseline 53 cases)
- `adversarial_e2e.rs`, `adversarial_resilience_tests.rs`, `aead_resilience_tests.rs`, `v81_adversarial_resilience.rs` — mixed corruption, random bit-flips, AEAD recovery, V8.1 format corruption

## Matrix Cluster

- `matrix_distribution_tests.rs` (709), `matrix_repair_scan_tests.rs` (614), `matrix_validation_test.rs` (244), `matrix_repro_panic.rs` (53) — shard matrix distribution, repair scans, validation, panic repro

## Multi-Volume

- `multi_volume_tests.rs` (1106), `volume_adjustment_test.rs`, `volume_expansion_test.rs` — volume rotation, size adjustment, expansion

## Repair / Recovery

- `single_volume_repair_scan_tests.rs` (501), `cold_recovery_bulletproof.rs` (322), `fault_tolerance_test.rs`, `simple_fault_test.rs` — RS repair scans, cold recovery, failure-mode handling

## Resilience / Auth / Core Topics

- `integration_tests.rs` (946), `engine_gap_tests.rs` (951) — roundtrips and pipeline gap coverage
- `envelope_adversarial.rs` (589), `key_session_tests.rs` (406), `security_tests.rs` (336), `certificate_auth_tests.rs` (633) — envelope lifecycle, KeySession invariants, auth paths
- `virtual_striping_tests.rs` (386), `deep_verification_test.rs` (281), `dedup_pending_tests.rs` (278) — striping resilience, verification, dedup
- `batch_api_tests.rs` (255), `append_committed_end_invariant.rs` (256), `manifest_roundtrip.rs` (249), `small_file_packing_tests.rs` (240) — batch API, append invariants, manifest, packing
- `root_cause_analysis_test.rs` (215), `overhaul_integration.rs` (192), `checkpoint_block_id_test.rs` (169), `self_inclusion_test.rs` (160) — diagnosis and resume continuity
- `archive_health_status_test.rs` (129), `distributed_storage_tests.rs` (115), `zero_drift_append_tests.rs` (111), `catalog_debug_test.rs` (112), `concurrency_torture.rs` (93) — health reporting, storage backends, append drift, concurrency
- `native_recursion_test.rs` (57), `mandatory_defaults.rs` (52), `shard_analysis_test.rs` (50), `preflight_manifest_dedup_test.rs` (48) — recursion, config defaults, shard analysis, preflight dedup

## Running Tests

```bash
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit
cargo test -p era-engine --test adversarial_audit_v5
```

## Test Pattern

Most tests use `#[tokio::test]` + `tempfile::TempDir`:
1. Create `ArchiveWriter` with TempDir output
2. Add files or raw buffers
3. `finalize()` to commit volumes + headers
4. Open with `ArchiveReader` using password/key
5. Extract and compare hashes against source

## Notes

- Audit waves lock in historical fixes; do not remove them just because a newer suite overlaps.
- When adding a new test file, extend the grouped bullet instead of enumerating every file.
