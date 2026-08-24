# era-common crate

L0 foundation. EraError enum (49 variants), Result, protobuf codegen, and config types — bottom of stack, depended on by every other crate.

## OVERVIEW

`era-common` owns shared types, the workspace error type (`EraError` enum (49 variants)), and protobuf definitions consumed by `build.rs`. It has no upward dependencies.

## SURFACES

- `src/AGENTS.md` — error types, config, protobuf codegen, serialization helpers
- `tests/compact_proto_schema.rs` — protobuf schema validation
- `proto/` — protobuf definitions compiled by `build.rs`

## BOUNDARY

`era-common` depends on nothing inside this workspace. Every other crate depends on `era-common`. Cross-crate types flow upward only.

## WHEN CHANGING

- Error variants added here affect all crates; use consistent error categorization and update the `EraError` enum count (currently 49 variants).
- Protobuf schema changes require `cargo build` to regenerate from `build.rs`.
- New shared types belong here only when every other crate will read them; otherwise push them down to `era-codec`, `era-crypto`, or `era-volume` per layer.

## VALIDATION

```bash
cargo test -p era-common
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.