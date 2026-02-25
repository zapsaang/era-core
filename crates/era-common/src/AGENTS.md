# Common Source

Shared types, error handling, and protobuf definitions. Bottom of the dependency stack — all crates depend on this.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports (facade pattern) |
| `error.rs` | `EraError` enum (30+ variants), `Result<T>` alias |
| `config.rs` | Configuration types (archive, erasure, compression) |
| `conversion.rs` | Type conversions, `TryFrom` for untrusted input |
| `types/` | Shared type definitions (IDs, metadata, protobuf wrappers) |
| `types/ids.rs` | ArchiveId, EpochId — UUID-based, rkyv zero-copy (1 unsafe block) |

## PROTOBUF

- Schemas in `proto/`: `era_common.proto`, `test_evolution.proto`
- Build-time codegen via `build.rs` using `prost_build`
- Conversion pattern: `From<T> for proto::T` (trusted), `TryFrom<proto::T> for T` (untrusted, bounded)

## CONVENTIONS

- `EraError` for ALL public Result types across the workspace
- Builder methods: `EraError::encryption()`, `EraError::security()`, etc.
- All `TryFrom` conversions enforce maximum sizes (DoS prevention)
