# era-common crate

Shared types, EraError, Result, protobuf codegen, and config types. L0. Bottom of stack.

## SURFACES
- `src/AGENTS.md` — error types, config, protobuf codegen, serialization helpers
- `tests/compact_proto_schema.rs` — protobuf schema validation
- `proto/` — protobuf definitions compiled by `build.rs`

## WHEN CHANGING
- Error variants added here affect all crates; use consistent error categorization.
- Protobuf schema changes require `cargo build` to regenerate from `build.rs`.

## VALIDATION
```bash
cargo test -p era-common
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.