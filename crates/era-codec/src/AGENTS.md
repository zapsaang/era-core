# Codec Source

Compression (Zstd/LZ4) and Reed-Solomon erasure coding. L2. Only dep: era-common.

## FILES

| File | LOC | Purpose |
|------|-----|---------|
| `lib.rs` | 13 | facade, re-exports |
| `compression.rs` | 218 | `Compressor` trait + Zstd/LZ4/NoCompressor impls |
| `erasure.rs` | 663 | `ErasureCoder`, `ErasureConfig`, Reed-Solomon encode/decode (4+2 default) |

## ANTI-PATTERNS

- NEVER silently drop failed shards — always report `EraError::ErasureCoding`
- ALWAYS validate `data + parity ≤ 256` before constructing `ErasureConfig`

## TESTS

Audit numbering is workspace-global (not per-crate):

| File | LOC | Coverage |
|------|-----|----------|
| `tests/adversarial_audit_v2.rs` | 156 | erasure/compression edge cases |
| `tests/adversarial_audit_v9.rs` | 284 | splicing, corruption scenarios |

## BENCHES

`benches/codec_bench.rs`, `benches/erasure_bench.rs`.

```bash
cargo test -p era-codec
cargo bench -p era-codec
```

See `crates/era-codec/AGENTS.md` for crate boundary docs.
