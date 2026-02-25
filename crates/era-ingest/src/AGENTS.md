# Ingest Source

File ingestion and content-defined chunking. L3.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Re-exports |
| `chunker.rs` | FastCDC implementation (standard) |
| `chunker_zerocopy.rs` | Zero-copy chunker variant |
| `chunker_ringbuf.rs` | Ring buffer chunker — 1 unsafe block (ptr::copy for <64KB remainders) |
| `reader.rs` | FileReader, DirectoryScanner (recursive with walkdir) |
| `entry.rs` | FileEntry, ChunkRef, Catalog |
| `acl.rs` | ACL handling (libacl1 on Linux) |

## CHUNKING

- FastCDC: content-defined chunking algorithm (~1.5 GB/s)
- Default sizes: 16KB min, 64KB avg, 256KB max (configurable via `--cdc-min/avg/max`)
- 3 implementations: standard, zero-copy, ring buffer
- Ring buffer: `ZERO-COPY GUARANTEE` — never calls copy_within/memmove except for <64KB remainders

## UNSAFE BLOCK (1, justified)

- `chunker_ringbuf.rs`: `std::ptr::copy` for ring buffer compaction
- Bounds-checked, only for small data (<64KB), performance optimization

## TEST

```bash
cargo test -p era-ingest
cargo bench -p era-ingest  # FastCDC throughput + memory benchmarks
```
