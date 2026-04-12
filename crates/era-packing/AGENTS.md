# era-packing crate

k-Bounded Best-Fit MacroBlock packing with resilient AEAD unpacking. L3.

## SURFACES
- `src/AGENTS.md` — `MacroBlockBuilder`, `SessionBlockBuilder`, `StagingPool`, `ResilientBlockUnpacker` internals
- `tests/` — vulnerability and resilience test coverage
- `benches/packing_bench.rs` — packing efficiency benchmarks

## WHEN CHANGING
- Packing algorithm changes affect era-engine writer and reader flows.
- 4-tier corruption detection (CRC flag → CRC re-verify → size check → all-same-byte heuristic) is a security contract; do not weaken it.
- Small-file buffering is handled by `era-engine/src/small_file_packer.rs`; changes there may affect packing efficiency.

## VALIDATION
```bash
cargo test -p era-packing
cargo bench -p era-packing
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.