# Engine Integration Tests

43 Rust test files plus this `AGENTS.md` in the era-engine integration/audit surface. 279+ adversarial security audit tests. Workspace-wide March 2026 verification: 2049 passed, 0 failed, 18 ignored.

## Audit Suites

| File | Tests | Focus |
|------|-------|-------|
| `competitor_audit.rs` | 44 | Core crypto, nonce safety, AEAD correctness |
| `second_audit.rs` | 42 | Key wrapping, Shamir secret sharing, multi-party access |
| `third_audit.rs` | 43 | Memory zeroization (M1-M3), TryFrom bounds, source patterns |
| `fourth_audit.rs` | 46 | Context-bound AAD, path traversal, allocation limits, VK resilience |
| `adversarial_audit_v5.rs` | 22 | State machine integrity, resume provenance, path containment checks |
| `adversarial_audit_v1.rs` | — | Earlier adversarial baseline retained for regression lock-in |
| `adversarial_audit_v3.rs` | 20 | V3 specific adversarial coverage (all fixed) |
| `adversarial_audit_v9.rs` | 9 | End-to-end adversarial scenarios: splicing, corruption |
| `adversarial_audit_v2.rs` | 53 | Skeptical baseline verification (all fixed) |

## Resilience Tests

| File | Focus |
|------|-------|
| `aead_resilience_tests.rs` | Random bit-flips, shard corruption, AEAD recovery |
| `adversarial_resilience_tests.rs` | Mixed corruption and recovery-path stress cases |
| `cold_recovery_bulletproof.rs` | Cold recovery from volume headers when index is lost |
| `fault_tolerance_test.rs` | Failure-mode handling when writes or reads degrade mid-run |
| `v81_adversarial_resilience.rs` | V8.1 format-specific corruption scenarios |
| `virtual_striping_tests.rs` | Iterator and striping resilience under erasure-coded layouts |

## Integration Tests

| File | Focus |
|------|-------|
| `integration_tests.rs` | Basic create/extract roundtrips |
| `multi_volume_tests.rs` | Volume rotation, multi-volume archives |
| `certificate_auth_tests.rs` | Certificate-based auth-path coverage |
| `checkpoint_block_id_test.rs` | Checkpoint resume and block-ID continuity |
| `concurrency_torture.rs` | Concurrency stress around writer/reader integration paths |
| `envelope_adversarial.rs` | Envelope lifecycle edge cases spanning engine + crypto boundaries |
| `key_session_tests.rs` | Engine-facing `KeySession` integration and invariants |
| `small_file_packing_tests.rs` | Small-file packing integration against engine flows |

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
- When adding a new audit wave, extend the grouped bullet instead of enumerating every file in the crate root.
