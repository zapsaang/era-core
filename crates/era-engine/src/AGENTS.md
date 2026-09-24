# Engine Source

Orchestration layer for archive create/extract/verify/repair/repack. This file owns the source-tree map; crate-wide rules stay in parent docs.

## FILES

| File | Lines | Purpose |
|------|------:|---------|
| `lib.rs` | 81 | Crate facade. Re-exports archive APIs, iterators, checkpoint types, recovery, repair, and repack entrypoints. |
| `writer.rs` | 3649 | Archive creation. MK generation, auth modes, VK wrapping, CDC→pack→encode→encrypt→volume. Append + create state machine. Stage split prevents further growth. |
| `reader.rs` | 2633 | Archive extraction. Multi-volume discovery, VK unwrap, per-block HKDF key derivation, chunk reassembly. |
| `block_iter.rs` | 2019 | 5 iterator types: `StandardBlockIterator`, `ErasureBlockIterator`, `SessionBlockIterator`, `MultiVolumeSessionBlockIterator`, `SessionErasureBlockIterator`. Virtual striping with `MAX_PROBE_ATTEMPTS = 256` (see `block_iter.rs:69`). |
| `repair.rs` | 1507 | RS-based shard recovery. Scans volumes for CRC failures, reconstructs via Reed-Solomon. |
| `checkpoint.rs` | 935 | WAL-based binary checkpoints. V2.2+ stores as typed blocks in-volume. rkyv + HMAC integrity. `commit()`/`sync()` DEPRECATED in favor of `commit_to_volume()`. |
| `recovery.rs` | 911 | Crash recovery: checkpoint detection, in-progress file tracking, resume logic. |
| `write_pipeline.rs` | 806 | Pipeline orchestration: encryption→erasure buffering→volume→index stages. |
| `volume_stage.rs` | 645 | Physical persistence and volume rotation. |
| `chunk_processor.rs` | 595 | Shared extraction/verification logic: MultiChunkState, path containment enforcement. |
| `repack.rs` | 447 | Extract-to-tempdir then re-create with new config. Password and keypair auth modes. |
| `async_pipeline.rs` | 427 | Async pipeline scaffolding for write path. |
| `chunk_index.rs` | 381 | Dedup index glue between engine and era-index. |
| `encryption_context.rs` | 313 | Per-block crypto state. |
| `erasure_scan.rs` | 251 | Shared erasure stripe prefix parsing and multi-copy reconciliation. |
| `erasure_stage.rs` | 246 | Stripe buffering / parity handoff. |
| `small_file_packer.rs` | 221 | Small-file aggregation into packed blocks. |
| `packing_stage.rs` | 215 | Pre-encryption chunk aggregation. |
| `metrics_collector.rs` | 194 | Pipeline metrics collection. |
| `auth.rs` | 164 | Password, certificate, threshold auth-mode handling. |
| `index_stage.rs` | 128 | Dedup + checkpoint synchronization stage. |
| `sequence.rs` | 72 | Finalize sequence tracking. |

## PIPELINE

```
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
