# CLI Tests

End-to-end integration tests for the `era` binary.

## FILES

| File | Focus |
|------|-------|
| `cli_integration_tests.rs` | Basic create/extract roundtrips |
| `cli_integration_tests_comprehensive.rs` | Extended command coverage |
| `cli_e2e_tests.rs` | Full e2e flows |
| `cli_e2e_gap_tests.rs` | Edge-case e2e scenarios |
| `cli_boundary_tests.rs` | Boundary and input validation |
| `cli_extreme_tests.rs` | Extreme input stress |
| `cli_stress_and_discovery_tests.rs` | Concurrency and discovery stress |
| `cli_tests.rs` | General CLI behavior |
| `common/mod.rs` | Shared test harness helpers |

## RUN

```bash
cargo test -p era-cli
cargo test --release -p era-cli  # matches CI
```

See `bins/era-cli/AGENTS.md` for CLI architecture.
