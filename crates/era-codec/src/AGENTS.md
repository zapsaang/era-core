# Codec Source

Compression (Zstd/LZ4) and Reed-Solomon erasure coding. L2.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 13 | Re-exports: ZstdCompressor, LZ4Compressor, ErasureCoder, ErasureConfig |
| `compression.rs` | — | `Compressor` trait + Zstd/LZ4/no-op implementations |
| `erasure.rs` | — | Reed-Solomon encode/decode, shard alignment, `ErasureConfig` |

## ANTI-PATTERNS

- NEVER silently drop failed shards — always report `EraError::ErasureCoding`
- ALWAYS validate `data + parity ≤ 256` before constructing `ErasureConfig`

## TEST

```bash
cargo test -p era-codec
cargo bench -p era-codec
```

See `crates/era-codec/AGENTS.md` for crate boundary docs.
