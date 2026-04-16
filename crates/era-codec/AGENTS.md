# era-codec crate

Compression (Zstd/LZ4) and Reed-Solomon erasure coding. L2.

## SURFACES
- `src/AGENTS.md` — `Compressor` trait, `ErasureCoder`, `ErasureConfig` internals
- `tests/` — adversarial compression and erasure coding coverage
- `benches/codec_bench.rs`, `benches/erasure_bench.rs` — throughput benchmarks

## STRUCTURE

```
era-codec/src/
├── lib.rs          # Re-exports: ZstdCompressor, LZ4Compressor, ErasureCoder
├── compression.rs  # Compressor trait + Zstd/LZ4/no-op impls
└── erasure.rs      # Reed-Solomon encode/decode, ErasureConfig
```

## WHEN CHANGING
- Compression algorithm or level changes affect era-engine write throughput and archive size.
- Erasure coding parameter changes (n data shards, n parity shards) affect data redundancy and repair capabilities.
- Test with both small and large inputs; compression behavior differs significantly by input size.

## VALIDATION
```bash
cargo test -p era-codec
cargo bench -p era-codec
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.