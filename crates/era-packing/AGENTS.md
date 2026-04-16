# era-packing crate

k-Bounded Best-Fit MacroBlock packing with resilient AEAD unpacking. L3.

## SURFACES
- `src/AGENTS.md` — `MacroBlockBuilder`, `SessionBlockBuilder`, `StagingPool`, `ResilientBlockUnpacker` internals
- `tests/` — vulnerability and resilience test coverage
- `benches/packing_bench.rs` — packing efficiency benchmarks

## STRUCTURE

```
era-packing/src/
├── lib.rs                          # Re-exports: MacroBlockBuilder, SessionBlockBuilder, StagingPool
├── builder.rs                      # MacroBlockBuilder
├── session_builder.rs              # SessionBlockBuilder
├── erasure_builder.rs              # Erasure-aware builder
├── session_erasure_builder.rs      # Session + erasure builder
├── staging_pool.rs                 # k-Bounded Best-Fit staging
├── resilient_aead.rs               # 4-tier corruption detection
├── block_codec.rs                  # Block encoding helpers
├── packed_chunk.rs                 # Packed chunk types
├── stripe.rs                       # Stripe layout
├── unpacker.rs                     # ResilientBlockUnpacker
├── erasure_unpacker.rs             # Erasure-aware unpacker
├── test_helpers.rs                 # Cross-crate test fixtures
└── integration_performance_tests.rs # In-src integration test module
```

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