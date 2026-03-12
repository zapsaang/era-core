# Engine Integration Tests

39 test files in the era-engine integration/audit surface. This crate includes 279+ adversarial security audit tests across historical and V5 suites. Workspace-wide March 2026 verification recorded 2049 passed, 0 failed, 18 ignored.

## Audit Suites

| File | Tests | Focus |
|------|-------|-------|
| `competitor_audit.rs` | 44 | Core crypto, nonce safety, AEAD correctness |
| `second_audit.rs` | 42 | Key wrapping, Shamir secret sharing, multi-party access |
| `third_audit.rs` | 43 | Memory zeroization (M1-M3), TryFrom bounds, source patterns |
| `fourth_audit.rs` | 46 | Context-bound AAD, path traversal, allocation limits, VK resilience |
| `adversarial_audit_v5.rs` | 22 | State machine integrity, resume provenance, path containment checks |
| `adversarial_audit_v3.rs` | 20 | V3 specific adversarial coverage (all fixed) |
| `adversarial_audit_v9.rs` | 9 | End-to-end adversarial scenarios: splicing, corruption |
| `adversarial_audit_v2.rs` | 53 | Skeptical baseline verification (all fixed) |

## Resilience Tests

| File | Focus |
|------|-------|
| `aead_resilience_tests.rs` | Random bit-flips, shard corruption, AEAD recovery |
| `cold_recovery_bulletproof.rs` | Cold recovery from volume headers when index is lost |
| `v81_adversarial_resilience.rs` | V8.1 format-specific corruption scenarios |

## Integration Tests

| File | Focus |
|------|-------|
| `integration_tests.rs` | Basic create/extract roundtrips |
| `multi_volume_tests.rs` | Volume rotation, multi-volume archives |
| `matrix_distribution_tests.rs` | Matrix shard distribution across volumes |
| `adversarial_e2e.rs` | End-to-end adversarial scenarios |

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
