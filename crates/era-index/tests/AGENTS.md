# era-index tests

27 test files: adversarial audit waves plus canonical persistence, compliance, recovery, and spec suites.

## Groups

- `adversarial_audit_v2, v3, v4, v6..v9, v10..v25` (23 files) — regression waves for builder/reader/store correctness and adversarial inputs. v1/v5 are absent: wave numbering is workspace-global across crates, and each crate owns only the waves that touched it.
- `index_persistence_audit.rs` (1300 LOC) — canonical V2.1 embedded index audit, 30 tests (Bloom correctness, L1/L2 pages, cold recovery)
- `audit_redb_compliance.rs` (667 LOC) — redb 3.1.1 ACID compliance expectations
- `cold_recovery_test.rs` (248 LOC) — recovery-from-volume contract checks
- `v2_architecture_spec.rs` (456 LOC) — architecture contract checks

## Run

```bash
cargo test -p era-index
cargo test -p era-index --test index_persistence_audit
cargo test -p era-index --test audit_redb_compliance
```

## Notes

- This directory documents the test harness only; source-file ownership lives in `../src/AGENTS.md`.
- When adding a new adversarial wave, update the grouped range instead of creating a line per file.
