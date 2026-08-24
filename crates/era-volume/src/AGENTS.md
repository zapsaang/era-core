# Volume Source

Physical volume format v8.2 and multi-volume management. L2.

## FILES

| File | Lines | Purpose |
|------|------:|---------|
| `lib.rs` | 92 | Crate facade. Public constants (`MAX_SHARD_SIZE`, `HEADER_SIZE`, `FOOTER_SIZE`), module declarations, and re-exports. |
| `header.rs` | 1231 | SuperHeader (4096B), RecipientSlot, EncryptedVolumeKey, KeyWrapAlgorithm |
| `footer.rs` | 990 | Footer (128B), FOOTER_MAGIC, Blake3 checksum, block count, index location |
| `reader.rs` | 700 | VolumeReader — async read with length validation against MAX_SHARD_SIZE |
| `writer.rs` | 918 | VolumeWriter — async write with padding |
| `distribution.rs` | 325 | Matrix distribution calculation helpers (`canonical_erasure_volume_count`, strategy canonicalization) |
| `multi_volume.rs` | 671 | MultiVolumeReader, MultiVolumeWriter — multi-disk coordination |
| `volume_pool.rs` | 1559 | Volume pool — rotation state machine, matrix shard distribution, space tracking |

## VOLUME FORMAT v8.2

```
┌─ Primary Header (4096B) ─── magic "ERA\x08\x02", archive_id, encrypted VK, recipient slots
├─ Backup Footer (128B)
├─ Data Region ──────────── encrypted blocks with RS shards, V2.1 index pages
├─ Backup Header (4096B)
└─ Primary Footer (128B) ── block count, index location, Blake3 checksum
```

## KEY CONSTANTS

- `MAX_SHARD_SIZE`: 16MB (DoS protection — all length fields validated)
- `HEADER_SIZE`: 4096 bytes
- `FOOTER_SIZE`: 128 bytes (single disk sector for atomic writes)

## SECURITY

- All length fields validated against MAX_SHARD_SIZE before allocation
- Symmetric validation on read and write paths
- Corrupted magic bytes cause hard failure (no silent recovery)

## TEST

```bash
cargo test -p era-volume
cargo test -p era-volume --test adversarial_audit_v30
```
