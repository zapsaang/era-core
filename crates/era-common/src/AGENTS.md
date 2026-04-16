# Common Source

Shared types, EraError, Result, protobuf codegen, and config types. L0. Bottom of stack.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports: EraError, Result, config types, serialization helpers |
| `error.rs` | `EraError` enum (35 variants), `Result<T>` alias |
| `config.rs` | `ArchiveConfig`, `CompressionConfig`, `EncryptionConfig`, etc. |
| `conversion.rs` | `From`/`TryFrom` between config types and protobuf |
| `serde.rs` | Bounded `deserialize_proto` helpers |
| `types/mod.rs` | Re-exports: block, chunk, ids, matrix |
| `types/block.rs` | `BlockLocation`, `ShardLayout`, `VerifiedShard`, `compute_shard_crc()` |
| `types/chunk.rs` | `RawChunk`, `UniqueChunk`, `ChunkLocation`, `ChunkVec` |
| `types/ids.rs` | `ArchiveId`, `VolumeId`, `BlockId`, `ChunkHash` (rkyv/bytecheck) |
| `types/matrix.rs` | `MatrixDistributionConfig`, `MatrixBlockLocation` |

## BUILD

`build.rs` compiles `proto/era_common.proto` and `proto/test_evolution.proto` via `prost-build`.

## TEST

```bash
cargo test -p era-common
```

See `crates/era-common/AGENTS.md` for crate boundary docs.
