# Common Source

Shared types, error handling, and protobuf definitions. Bottom of the dependency stack — all crates depend on this.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports (facade pattern) |
| `error.rs` | `EraError` enum (30+ variants), `Result<T>` alias |
| `config.rs` | Configuration types (archive, erasure, compression) |
| `conversion.rs` | Type conversions, `TryFrom` for untrusted input |
| `serde.rs` | Safe protobuf serialization helpers with deserialization size limits |
| `types/mod.rs` | `types/` facade. Re-exports block, chunk, ID, and matrix type groups. |
| `types/block.rs` | MacroBlock, encrypted block, shard layout, and block-header-oriented shared types. |
| `types/chunk.rs` | `ChunkVec`, raw/unique chunk, and stack-optimized chunk container definitions. |
| `types/ids.rs` | ArchiveId, VolumeId, EpochId, and UUID/rkyv-backed identifier types. |
| `types/matrix.rs` | Matrix distribution config, strategy, and shard-location metadata shared across engine/volume code. |

## PROTOBUF

- Schemas in `proto/`: `era_common.proto`, `test_evolution.proto`
- Build-time codegen via `build.rs` using `prost_build`
- Conversion pattern: `From<T> for proto::T` (trusted), `TryFrom<proto::T> for T` (untrusted, bounded)

## CONVENTIONS

- `EraError` for ALL public Result types across the workspace
- Builder methods: `EraError::encryption()`, `EraError::security()`, etc.
- All `TryFrom` conversions enforce maximum sizes (DoS prevention)
