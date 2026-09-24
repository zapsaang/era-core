# Common Source

Shared types, EraError, Result, protobuf codegen, config types. L0. Bottom of stack.

## FILES

| File | LOC | Purpose |
|------|-----|---------|
| `lib.rs` | 24 | facade, re-exports of error/config/serde/types |
| `config.rs` | 232 | `ArchiveConfig` etc., typed config structs |
| `conversion.rs` | 449 | bounded protobuf `From`/`TryFrom` conversions |
| `error.rs` | 332 | `EraError` (~49 variants), most cross-cut type in workspace |
| `serde.rs` | 41 | bounded `deserialize_proto` helpers |
| `build.rs` | 9 | prost codegen over `proto/` |

## PROTO

`proto/era_common.proto` (331 LOC) + `proto/test_evolution.proto` (14 LOC), compiled by `build.rs` into OUT_DIR. Schema changes require `cargo build` regen.

## TYPES/ SUBDIR

Block, chunk, id, manifest, matrix, typed-block types. Split as:

| File | LOC | Purpose |
|------|-----|---------|
| `types/mod.rs` | 15 | re-exports |
| `types/block.rs` | 597 | `BlockType`, `BlockHeader`, `BlockLocation`, `ShardLayout`, `VerifiedShard`, `compute_shard_crc()` |
| `types/chunk.rs` | 88 | `RawChunk`, `UniqueChunk`, `ChunkLocation` |
| `types/ids.rs` | 183 | `ChunkHash`, `ArchiveId`, `VolumeId`, `BlockId` (rkyv/bytecheck) |
| `types/manifest.rs` | 387 | v8.2 `ArchiveManifest`, epoch/finalize sequencing, committed horizons, commitments |
| `types/matrix.rs` | 187 | `MatrixDistributionConfig`, `MatrixBlockLocation` |
| `types/typed_block.rs` | 56 | `TypedBlockKind` (Manifest/Catalog/Index) |

## TEST

Single test: `tests/compact_proto_schema.rs` (24 LOC, protobuf schema validation).

```bash
cargo test -p era-common
```

See `crates/era-common/AGENTS.md` for crate boundary docs.
