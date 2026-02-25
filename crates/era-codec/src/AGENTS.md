# Codec Source

Compression and erasure coding. L2 — transforms data before encryption.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports |
| `compression.rs` | `Compressor` trait + Zstd/LZ4/NoCompressor implementations |
| `erasure.rs` | Reed-Solomon coding (655 lines). Encode/decode with configurable data/parity shards. |

## COMPRESSION

- `ZstdCompressor`: Zstd algorithm, configurable levels (1-22)
- `LZ4Compressor`: LZ4 for speed (~2 GB/s)
- `NoCompressor`: Pass-through (no compression)
- All implement `Compressor` trait for pluggable dispatch

## ERASURE CODING

- Reed-Solomon via `reed-solomon-simd` crate
- Default: 4 data + 2 parity shards (tolerates 2 losses)
- Configurable via `ErasureConfig`
- Supports Virtual Striping for multi-volume distribution
- Shard padding handled transparently
