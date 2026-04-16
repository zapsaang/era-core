# Packing Source

k-Bounded Best-Fit MacroBlock packing with resilient AEAD unpacking. L3.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports: MacroBlockBuilder, SessionBlockBuilder, StagingPool, ResilientBlockUnpacker |
| `builder.rs` | `MacroBlockBuilder` — standard macroblock construction |
| `session_builder.rs` | `SessionBlockBuilder` — session-aware construction |
| `erasure_builder.rs` | Erasure-aware builder |
| `session_erasure_builder.rs` | Combined session + erasure builder |
| `staging_pool.rs` | k-Bounded Best-Fit staging pool |
| `resilient_aead.rs` | 4-tier corruption detection implementation |
| `block_codec.rs` | Block encoding helpers |
| `packed_chunk.rs` | Packed chunk types |
| `stripe.rs` | Stripe layout math |
| `unpacker.rs` | `ResilientBlockUnpacker` |
| `erasure_unpacker.rs` | Erasure-aware unpacker |
| `test_helpers.rs` | Cross-crate test fixtures (`test_key`, `test_session`) |
| `integration_performance_tests.rs` | In-source integration performance test module |

## SECURITY

4-tier corruption detection (audit-enforced):
1. CRC flag check
2. CRC re-verify
3. Size check
4. All-same-byte heuristic

## TEST

```bash
cargo test -p era-packing
cargo bench -p era-packing
```

See `crates/era-packing/AGENTS.md` for crate boundary docs.
