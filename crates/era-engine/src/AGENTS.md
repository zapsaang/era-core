# Engine Source

Orchestration layer — async pipeline for archive create/extract/verify/repair.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `writer.rs` | 2348 | Archive creation. MK generation, auth modes, VK wrapping, CDC→pack→encode→encrypt→volume. Append + create state machine. |
| `reader.rs` | 1540 | Archive extraction. Multi-volume discovery, VK unwrap, per-block HKDF key derivation, chunk reassembly. |
| `block_iter.rs` | 1174 | 4 iterator types (Standard/Erasure × Basic/Session). Virtual Striping with 8192 length probes. |
| `repair.rs` | 889 | RS-based shard recovery. Scans volumes for CRC failures, reconstructs via Reed-Solomon. |
| `checkpoint.rs` | 770 | WAL-based binary checkpoints. V2.2+ stores as typed blocks in-volume. rkyv + HMAC integrity. |
| `write_pipeline.rs` | — | Write path stage coordination. |
| `async_pipeline.rs` | — | Core async pipeline plumbing. |
| `recovery.rs` | — | Cold recovery from volume headers. |
| `auth.rs` | — | AuthProvider trait (password/certificate). |

## PIPELINE STAGES

```
Write: files → FastCDC chunks → dedup check → k-BFF pack → Zstd compress → AEAD encrypt (per-block HKDF key) → RS encode → volume distribute
Read:  volumes → CRC verify → RS decode → AEAD decrypt → decompress → unpack → reassemble files
```

## KEY PATTERNS

- `spawn_blocking` for all CPU-heavy work (compression, crypto, RS)
- Checkpoint-based crash recovery (resume interrupted writes)
- Multi-auth: password (Argon2id), certificate (hybrid KEM), threshold (Shamir)
- Volume pool with automatic rotation at size limits
- Matrix shard distribution across multiple volumes

## ANTI-PATTERNS

- NEVER call `unwrap()` in async paths — `EraError` + `?`
- NEVER block the async runtime — use `spawn_blocking`
- NEVER skip context binding in AEAD (archive_id ‖ epoch_id ‖ block_index)

## TEST

```bash
cargo test -p era-engine
cargo test -p era-engine --test fourth_audit  # specific audit
```
