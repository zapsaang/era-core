# Engine Integration Tests

43 Rust test files plus this `AGENTS.md` in the era-engine integration/audit surface. This crate includes 279+ adversarial security audit tests across historical and V5 suites. Workspace-wide March 2026 verification recorded 2049 passed, 0 failed, 18 ignored.

## Audit Suites

| File | Tests | Focus |
|------|-------|-------|
| `competitor_audit.rs` | 44 | Core crypto, nonce safety, AEAD correctness |
| `second_audit.rs` | 42 | Key wrapping, Shamir secret sharing, multi-party access |
| `third_audit.rs` | 43 | Memory zeroization (M1-M3), TryFrom bounds, source patterns |
| `fourth_audit.rs` | 46 | Context-bound AAD, path traversal, allocation limits, VK resilience |
| `adversarial_audit_v5.rs` | 22 | State machine integrity, resume provenance, path containment checks |
| `adversarial_audit_v1.rs` | — | Earlier adversarial baseline coverage retained for regression lock-in |
| `adversarial_audit_v3.rs` | 20 | V3 specific adversarial coverage (all fixed) |
| `adversarial_audit_v9.rs` | 9 | End-to-end adversarial scenarios: splicing, corruption |
| `adversarial_audit_v2.rs` | 53 | Skeptical baseline verification (all fixed) |
| `competitor_vulnerability_audit.rs` | — | Additional adversarial/competitor framing for edge-case regressions |

## Resilience Tests

| File | Focus |
|------|-------|
| `aead_resilience_tests.rs` | Random bit-flips, shard corruption, AEAD recovery |
| `adversarial_resilience_tests.rs` | Mixed corruption and recovery-path stress cases |
| `cold_recovery_bulletproof.rs` | Cold recovery from volume headers when index is lost |
| `fault_tolerance_test.rs` | Failure-mode handling when writes or reads degrade mid-run |
| `simple_fault_test.rs` | Smaller repro-style failure injections |
| `v81_adversarial_resilience.rs` | V8.1 format-specific corruption scenarios |
| `virtual_striping_tests.rs` | Iterator and striping resilience under erasure-coded layouts |

## Integration Tests

| File | Focus |
|------|-------|
| `batch_api_tests.rs` | Multi-file / batch archive API flows |
| `certificate_auth_tests.rs` | Certificate-based auth-path coverage |
| `checkpoint_block_id_test.rs` | Checkpoint resume and block-ID continuity |
| `catalog_debug_test.rs` | Catalog/debugging-oriented archive inspection coverage |
| `concurrency_torture.rs` | Concurrency stress around writer/reader integration paths |
| `deep_verification_test.rs` | Heavier end-to-end verification scenarios |
| `distributed_storage_tests.rs` | Distributed / multi-volume storage-path behavior |
| `envelope_adversarial.rs` | Envelope lifecycle edge cases spanning engine + crypto boundaries |
| `integration_tests.rs` | Basic create/extract roundtrips |
| `key_session_tests.rs` | Engine-facing `KeySession` integration and invariants |
| `mandatory_defaults.rs` | Builder/config default behavior expected by higher-level flows |
| `matrix_repro_panic.rs` | Regression repro for matrix-path panic scenarios |
| `multi_volume_tests.rs` | Volume rotation, multi-volume archives |
| `matrix_distribution_tests.rs` | Matrix shard distribution across volumes |
| `matrix_validation_test.rs` | Matrix-configuration validation and invariants |
| `native_recursion_test.rs` | Deep/nested tree extraction behavior |
| `overhaul_integration.rs` | Broad post-refactor integration regression coverage |
| `root_cause_analysis_test.rs` | Focused repros for previously diagnosed failures |
| `security_tests.rs` | Engine-level security regression checks outside named audit waves |
| `shard_analysis_test.rs` | Shard placement / reconstruction analysis coverage |
| `small_file_packing_tests.rs` | Small-file packing integration against engine flows |
| `volume_adjustment_test.rs` | Volume sizing / adjustment behavior |
| `volume_expansion_test.rs` | Growth and continuation across expanded volume sets |
| `zero_drift_append_tests.rs` | Append-path regression coverage for offset / state drift |
| `adversarial_e2e.rs` | End-to-end adversarial scenarios |

## Coverage Notes

- Audit waves lock in historical fixes; do not remove them just because a newer suite overlaps.
- Session/key, matrix/distribution, append/resume, and certificate-auth tests cover engine invariants that also depend on lower crates.
- Several files are narrow repro harnesses. Keep them terse and regression-focused rather than folding them into broader suites.

## Running Tests

```bash
cargo test -p era-engine                                    # all engine tests
cargo test -p era-engine --test fourth_audit                 # specific audit
cargo test -p era-engine --test adversarial_audit_v5         # V5 audit suite
```

## Test Pattern

Most tests use `#[tokio::test]` + `tempfile::TempDir`:
1. Create `ArchiveWriter` with TempDir output
2. Add files or raw buffers
3. `finalize()` to commit volumes + headers
4. Open with `ArchiveReader` using password/key
5. Extract and compare hashes against source

## Known Tracked Issues

- M1-M3: PasswordProvider/AuthMode zeroization gaps (fourth_audit, third_audit)
- RV3-RV4: Reader key material cleanup gaps (third_audit)
- All documented as non-exploitable in current threat model
