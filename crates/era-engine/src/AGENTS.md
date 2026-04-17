# Engine Source

Orchestration layer for archive create/extract/verify/repair/repack. This file owns the source-tree map; crate-wide rules stay in parent docs.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 62 | Crate facade. Re-exports archive APIs, iterators, checkpoint types, recovery, repair, and repack entrypoints. |
| `writer.rs` | 2554 | Archive creation. MK generation, auth modes, VK wrapping, CDC→pack→encode→encrypt→volume. Append + create state machine. |
| `reader.rs` | 2313 | Archive extraction. Multi-volume discovery, VK unwrap, per-block HKDF key derivation, chunk reassembly. |
| `block_iter.rs` | 1699 | 4 iterator types (Standard/Erasure × Basic/Session). Virtual Striping with 8192 length probes. |
| `repair.rs` | 1451 | RS-based shard recovery. Scans volumes for CRC failures, reconstructs via Reed-Solomon. |
| `checkpoint.rs` | 929 | WAL-based binary checkpoints. V2.2+ stores as typed blocks in-volume. rkyv + HMAC integrity. |
| `recovery.rs` | 855 | Crash recovery: checkpoint detection, in-progress file tracking, resume logic. |
| `write_pipeline.rs` | 681 | Pipeline orchestration: encryption→erasure buffering→volume→index stages. |
| `chunk_processor.rs` | 590 | Shared extraction/verification logic: MultiChunkState, path containment enforcement. |
| `repack.rs` | 103 | Extract-to-tempdir then re-create with new config. Password and keypair auth modes. |
| `erasure_scan.rs` | 251 | Shared erasure stripe prefix parsing and multi-copy reconciliation. |

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
