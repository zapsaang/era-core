# Packing Source

k-Bounded Best-Fit algorithm for MacroBlock construction + resilient AEAD for corruption recovery.

## FILES

| File | Purpose |
|------|---------|
| `builder.rs` | MacroBlock builder — groups chunks into fixed-size blocks |
| `lib.rs` | Crate facade and public re-exports for builders, unpackers, stripe helpers, and recovery paths |
| `session_builder.rs` | Packing session — manages builder lifecycle across multiple blocks |
| `session_erasure_builder.rs` | Erasure coding integration — wraps session with RS encode |
| `staging_pool.rs` | Staging memory pool — pre-allocates buffers for packing |
| `packed_chunk.rs` | Packed chunk representation — chunk + metadata after packing |
| `resilient_aead.rs` | Resilient AEAD unwrapping — 4-tier corruption detection for extraction |
| `block_codec.rs` | Block encoding/decoding — serialization of packed blocks |
| `erasure_builder.rs` | Reed-Solomon builder — encode packed blocks into shards |
| `erasure_unpacker.rs` | Reed-Solomon unpacker — decode shards back to blocks |
| `stripe.rs` | Stripe and StripeBuffer types — hold data blocks, parity shards, and metadata for erasure handoff |
| `test_helpers.rs` | Shared test utilities (key derivation, session setup) |
| `unpacker.rs` | MacroBlock unpacker — decrypts, decompresses, and extracts chunk payloads from encrypted blocks |
| `integration_performance_tests.rs` | In-source test module for real-world packing-efficiency and throughput comparisons |

## RESILIENT AEAD (4-tier corruption detection)

During extraction, `ResilientBlockUnpacker` detects corrupted shards:
1. **CRC flag**: Check `VerifiedShard.crc_valid` from volume reader
2. **CRC re-verify**: Recompute CRC32 on shard bytes
3. **Size check**: Validate shard length against expected
4. **All-same-byte heuristic**: Detect zero-filled or pattern-filled corruption

Corrupted shards are excluded before Reed-Solomon recovery.

## KEY PATTERNS

- k-Bounded Best-Fit: pack chunks into blocks with ≤k wasted bytes
- `VerifiedShard` carries CRC status through entire pipeline
- Staging pool pre-allocates to avoid per-block allocation overhead

## TEST

```bash
cargo test -p era-packing
```
