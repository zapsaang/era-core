# era-codec crate

Compression and Reed-Solomon building blocks used by packing, volume, and engine layers. See root `AGENTS.md` for workspace-wide rules and `src/AGENTS.md` for implementation detail.

## SURFACES
- `src/AGENTS.md` — `compression.rs` and `erasure.rs`
- `tests/` — adversarial coverage for codec boundaries
- `benches/codec_bench.rs` and `benches/erasure_bench.rs` — throughput and shard-cost baselines

## WHEN CHANGING
- Compression defaults ripple into CLI UX and engine write/read throughput.
- Erasure config validation here must stay consistent with `era-volume` shard layout and `era-engine` repair logic.
- Keep public types (`Compressor`, `ErasureCoder`, `ErasureConfig`) small and stable; routing state machines live elsewhere.

## VALIDATION
```bash
cargo test -p era-codec
cargo bench -p era-codec
```
