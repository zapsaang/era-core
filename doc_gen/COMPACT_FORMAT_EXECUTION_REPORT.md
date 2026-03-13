# Compact Read-Only Archive Format (.erac) — Execution Report

**Date:** 2026-03-13
**Branch:** feat_fly
**Status:** Complete — all tests passing, full CI clean

## Objective

Implement a compact read-only archive format (`.erac`) with end-to-end roundtrip: ERA archive → compact bundle → extract files. The format retains all encryption (XChaCha20-Poly1305 AEAD with context binding), redundancy (Reed-Solomon erasure coding), and compression (Zstd) features. Encrypted blocks are preserved verbatim (no re-encryption).

## Architecture

### New Crate: era-compact

Layer L2, depends on: `era-codec`, `era-volume`, `era-common`.

| File | Purpose |
|------|---------|
| `header.rs` | `CompactSuperHeader` — 4096-byte header preserving archive identity, recipients, salt, encrypted volume key |
| `footer.rs` | `CompactVolumeFooter` — directory location, catalog/index offsets, Blake3 checksums |
| `directory.rs` | `CompactDirectory` — block-to-offset mapping with duplicate/overlap validation |
| `stripe.rs` | `CompactShardInput` (boundary type), `CompactShardRecordHeader` (on-disk shard metadata with CRC) |
| `writer.rs` | `CompactVolumeWriter` — single-volume writer with shard records and replicated blocks |
| `bundle_writer.rs` | `CompactBundleWriter` — multi-volume orchestrator: RS encoding, matrix distribution, catalog/index replication |
| `bundle_reader.rs` | `CompactBundleReader` — multi-volume reader: RS recovery, block lookup, catalog/index retrieval |
| `reader.rs` | `CompactVolumeReader` — single-volume reader with header/footer/directory parsing |
| `set.rs` | Volume path discovery and layout planning |

### era-engine Extensions

| File | Purpose |
|------|---------|
| `compact_compactor.rs` | `CompactSourcePreflight` (volume set validation), `CompactPreparedSource` (live block discovery + snapshot materialization) |
| `source_block_snapshot.rs` | `SourceDataBlockSnapshot` — captures encrypted bytes, stripe position, and RS metadata per block |
| `compact_writer.rs` | `compact_archive()` — ERA → .erac: opens source, groups snapshots into stripes, pads incomplete stripes, writes via `CompactBundleWriter` |
| `compact_reader.rs` | `CompactArchiveReader` — .erac → files: derives keys from compact header, decrypts blocks, extracts files via catalog |

### Data Flow

```
Write: ArchiveReader → CompactPreparedSource → group by stripe → pad incomplete stripes
     → CompactBundleWriter (RS encode → matrix distribute → write shards + parity)
     → write replicated catalog → finalize (directory + footer)

Read:  CompactBundleReader → derive KeySession from header → unwrap VolumeKey
     → read catalog → build chunk→block map (decrypt blocks, index chunks)
     → extract files (decrypt block → decompress → extract chunk → reassemble)
```

## Key Design Decisions

1. **No re-encryption**: Encrypted bytes from source archive are preserved verbatim. The compact format stores the same AEAD ciphertext, same nonce context, same archive/epoch IDs.

2. **Sync I/O in era-compact**: The compact crate uses `std::fs` (synchronous), while era-engine uses tokio async. The `compact_archive()` function bridges via `await` on the async `ArchiveReader`.

3. **Catalog as replicated block**: The catalog is serialized as protobuf bytes and stored as a replicated block (copied to all volumes), not as an encrypted data block.

4. **Index omitted**: The embedded index is not stored in the compact format (`IndexReader` has no `to_bytes()`). The compact reader builds a chunk→block map by decrypting data blocks directly.

5. **CompactShardInput boundary type**: Defined in era-compact to avoid circular dependency with era-engine. era-engine maps `SourceDataBlockSnapshot → CompactShardInput` at the crate boundary.

6. **Synthetic block IDs**: Padding data shards use IDs above `u64::MAX / 2` so `data_block_ids()` filters them out. Parity shards use IDs near `u64::MAX`.

## Bugs Fixed

### Bug 1: Synthetic padding block IDs below filter threshold
- **Symptom**: "target shard index 5 out of range" — reader tried to decrypt padding blocks
- **Root cause**: Padding block IDs at `u64::MAX / 4` were below the `u64::MAX / 2` filter in `data_block_ids()`
- **Fix**: Changed padding ID base to `u64::MAX / 2 + 1`

### Bug 2: Parity shard block_id collision with real blocks
- **Symptom**: Parity shards had `BlockId::new(0)` in shard headers, matching real block sequence 0
- **Root cause**: `bundle_writer.rs` assigned `BlockId::new(0)` to parity shards
- **Fix**: Parity shards now use `BlockId::new(u64::MAX - offset)` (same as directory entries)

### Bug 3: Catalog block_id collision with data blocks
- **Symptom**: "duplicate compact directory block_id 1" — catalog replicated block used `block_id=1`
- **Root cause**: Real data blocks can have sequence 1, colliding with catalog's `block_id=1`
- **Fix**: Catalog uses `block_id = u64::MAX / 2 + u64::MAX / 4` (well above real block range)

### Bug 4: RS recovery returning padded shard data
- **Symptom**: AEAD decryption failure on recovered blocks
- **Root cause**: RS recovery returns uniform-size shards; original `encrypted_bytes` may be shorter
- **Fix**: `read_encrypted_block()` now truncates recovered data to `encrypted_len` from shard header

### Bug 5: `pad_stripe_inputs` corrupting real block ciphertext
- **Symptom**: AEAD decryption failure on multi-file archives
- **Root cause**: `pad_stripe_inputs` resized real blocks' `encrypted_bytes` to max_len, appending zeros to valid AEAD ciphertext
- **Fix**: Removed the resize loop for existing inputs; RS `encode_shards()` handles padding internally

### Bug 6: Clone count regression in block_iter.rs
- **Symptom**: `v2_perf_04_session_erasure_decode_reduced_clone_count` audit test failed (4 clones > 2 threshold)
- **Root cause**: `source_snapshot` feature added `.clone()` calls for `stripe_lengths`
- **Fix**: Replaced `stripe_lengths.clone().unwrap_or_default()` with `as_deref().unwrap_or_default()`, and `.clone()` with `.to_vec()` in snapshot construction

## Test Coverage

### New Tests (era-compact)
- `header_footer_roundtrip.rs` — 3 tests: header/footer roundtrip, catalog/index fields, checksum tampering
- `compact_bundle_roundtrip.rs` — 2 tests: basic roundtrip, variable block sizes
- `compact_set_layout.rs` — 1 test: volume-per-failure-domain layout
- `directory_invariants.rs` — 1 test: duplicate/overlap rejection
- `stripe_roundtrip.rs` — 1 test: shard record roundtrip + CRC
- `rejects_era_magic.rs` — 1 test: legacy magic rejection
- `threshold_validation.rs` — 1 test: threshold policy preservation
- `fuzz_registration.rs` — 1 test: fuzz target registration

### New Tests (era-engine)
- `compact_e2e_roundtrip.rs` — 4 tests: single-file roundtrip, multi-file roundtrip, wrong password rejection, catalog preservation
- `compact_preflight.rs` — 4 tests: complete volume set, incomplete rejection, live block IDs, padding exclusion
- `compact_live_block_ids.rs` — 3 tests: live block discovery, padding exclusion, iterator equivalence
- `compact_source_materialization.rs` — 2 tests: snapshot collection, padding exclusion
- `compact_source_snapshot.rs` — 4 tests: block ID preservation, stripe semantics, volume set validation, rotating offset

## Verification

```
cargo fmt --all -- --check    ✓ clean
cargo clippy --all-targets --all-features -- -D warnings    ✓ clean
cargo test --workspace    ✓ all passing, 0 failures
```

All pre-existing tests continue to pass including all 6 adversarial audit suites (279+ tests).
