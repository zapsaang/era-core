# Engine Source

Orchestration layer for archive create/extract/verify/repair/repack. This file owns the source-tree map; crate-wide rules stay in parent docs.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 62 | Crate facade. Re-exports archive APIs, iterators, checkpoint types, recovery, repair, and repack entrypoints. |
| `writer.rs` | 2348 | Archive creation. MK generation, auth modes, VK wrapping, CDC→pack→encode→encrypt→volume. Append + create state machine. |
| `reader.rs` | 1540 | Archive extraction. Multi-volume discovery, VK unwrap, per-block HKDF key derivation, chunk reassembly. |
| `block_iter.rs` | 1174 | 4 iterator types (Standard/Erasure × Basic/Session). Virtual Striping with 8192 length probes. |
| `repair.rs` | 889 | RS-based shard recovery. Scans volumes for CRC failures, reconstructs via Reed-Solomon. |
| `checkpoint.rs` | 770 | WAL-based binary checkpoints. V2.2+ stores as typed blocks in-volume. rkyv + HMAC integrity. |
| `repack.rs` | 103 | Extract-to-tempdir then re-create with new config. Password and keypair auth modes. |
| `async_pipeline.rs` | — | Public chunk-pipeline plumbing and pipeline config types. |
| `auth.rs` | — | Auth provider abstraction and password / certificate helpers used by writer and reader paths. |
| `chunk_index.rs` | — | Engine-side dedup index abstraction. Wraps memory-backed and Redb-backed chunk lookup/record flows. |
| `chunk_processor.rs` | — | Shared extraction/verification chunk routing helpers. Tracks file assembly and packed-chunk output state. |
| `encryption_context.rs` | — | Write-path crypto context. Holds `KeySession`, volume key, nonce context, archive/epoch IDs, and block counter state. |
| `erasure_stage.rs` | — | Stripe buffering stage between encryption and volume writing. Validates erasure config and emits complete stripes. |
| `index_stage.rs` | — | Dedup lookup / record stage. Bridges `ChunkIndex` and checkpoint sync, then extracts the embedded index builder at finalize time. |
| `metrics_collector.rs` | — | Operation timing helpers and histogram emission for create/extract/compression/encryption paths. |
| `packing_stage.rs` | — | k-Bounded Best-Fit stage wrapper. Aggregates chunks into packed blocks with flush-threshold validation. |
| `recovery.rs` | — | Cold-recovery helpers for interrupted writers and volume/header discovery. |
| `small_file_packer.rs` | — | Small-file buffering policy. Batches tiny files before flush to improve packing efficiency. |
| `volume_stage.rs` | — | Physical write stage. Owns volume-pool interaction, shard writes, matrix sequencing, and rotation-sensitive persistence. |
| `write_pipeline.rs` | — | Coordinator for the decomposed write stages and archive-create flow. |

## PIPELINE

```text
Write: files → FastCDC chunks → dedup check → k-BFF pack → Zstd compress → AEAD encrypt → RS encode → volume distribute
Read:  volumes → CRC verify → RS decode → AEAD decrypt → decompress → unpack → reassemble files
```

## STAGE SPLIT

- `packing_stage.rs` — pre-encryption aggregation
- `encryption_context.rs` — per-block crypto state
- `erasure_stage.rs` — stripe buffering / parity handoff
- `volume_stage.rs` — physical persistence and rotation
- `index_stage.rs` — dedup + checkpoint synchronization

## KEY PATTERNS

- Checkpoint-based crash recovery and resume
- Multi-auth: password, certificate, threshold
- Matrix shard distribution across multiple volumes
- Stage decomposition exists to keep `writer.rs` from growing further

## TEST

```bash
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit
```
