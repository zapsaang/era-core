# era-common crate

Shared types, EraError, Result, protobuf codegen, and config types. L0. Bottom of stack.

## SURFACES
- `src/AGENTS.md` — error types, config, protobuf codegen, serialization helpers
- `tests/compact_proto_schema.rs` — protobuf schema validation
- `proto/` — protobuf definitions compiled by `build.rs`

## STRUCTURE

```
era-common/src/
├── lib.rs         # Re-exports: EraError, Result, config types
├── error.rs       # EraError enum (35 variants)
├── config.rs      # ArchiveConfig, CompressionConfig, etc.
├── conversion.rs  # Config ↔ protobuf conversions
├── serde.rs       # Bounded deserialize_proto helpers
└── types/
    ├── mod.rs     # Re-exports block/chunk/ids/matrix
    ├── block.rs   # BlockLocation, ShardLayout, VerifiedShard
    ├── chunk.rs   # RawChunk, UniqueChunk, ChunkLocation
    ├── ids.rs     # ArchiveId, VolumeId, BlockId, ChunkHash
    └── matrix.rs  # MatrixDistributionConfig
```

## WHEN CHANGING
- Error variants added here affect all crates; use consistent error categorization.
- Protobuf schema changes require `cargo build` to regenerate from `build.rs`.

## VALIDATION
```bash
cargo test -p era-common
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.