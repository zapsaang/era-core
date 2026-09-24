# Packing Source

k-Bounded Best-Fit MacroBlock packing with resilient AEAD unpacking. L3.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 56 | Facade. Re-exports: MacroBlockBuilder, SessionBlockBuilder, StagingPool, ResilientBlockUnpacker, BlockContext |
| `builder.rs` | 370 | `MacroBlockBuilder`; `nonce_context` MUST be unique per archive |
| `session_builder.rs` | 523 | `SessionBlockBuilder` — session-aware construction |
| `session_erasure_builder.rs` | 604 | Combined session + erasure builder |
| `erasure_builder.rs` | 231 | Erasure-aware builder |
| `unpacker.rs` | 369 | `ResilientBlockUnpacker` |
| `erasure_unpacker.rs` | 328 | Erasure-aware unpacker |
| `staging_pool.rs` | 465 | k-Bounded Best-Fit staging pool |
| `packed_chunk.rs` | 430 | Packed chunk types |
| `resilient_aead.rs` | 415 | 4-tier corruption detection (see SECURITY; security contract, do not weaken) |
| `block_codec.rs` | 233 | Block encoding helpers |
| `stripe.rs` | 121 | Stripe layout math |
| `test_helpers.rs` | 43 | #[cfg(test)] cross-crate fixtures: test_key/test_session/TEST_NONCE_CONTEXT — used by era-crypto tests |
| `integration_performance_tests.rs` | 664 | FLAG: test file living in src/; #[cfg(test)]-gated (verified) — anomaly, keep gating |

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
