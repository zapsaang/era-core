# era-index tests

Large audit surface for persistence, cold recovery, and Redb-backed index invariants.

## Groups

- `adversarial_audit_v2.rs` through `adversarial_audit_v25.rs` — regression waves for builder/reader/store correctness and adversarial inputs
- `index_persistence_audit.rs` — canonical V2.1 persistence audit (30 tests)
- `cold_recovery_test.rs` and `v2_architecture_spec.rs` — recovery and architecture-contract checks
- `audit_redb_compliance.rs` — storage/backend-specific expectations

## Run

```bash
cargo test -p era-index
cargo test -p era-index --test index_persistence_audit
cargo test -p era-index --test audit_redb_compliance
```

## Notes

- This directory documents the test harness only; source-file ownership lives in `../src/AGENTS.md`.
- When adding a new adversarial wave, update the grouped range instead of creating a line per file in the crate root.