# Ingest Source

File ingestion, FastCDC content-defined chunking, and directory scanning. L3.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 28 | Facade. Re-exports: Chunker, StreamingChunker, StreamingChunkerZeroCopy, DirectoryScanner, FileReader |
| `chunker.rs` | 498 | FastCDC chunking (16KB-64KB-256KB) |
| `chunker_zerocopy.rs` | 371 | `StreamingChunkerZeroCopy` — zero-copy streaming chunker |
| `entry.rs` | 477 | Ingest entry types: Catalog/FileEntry/ChunkRef |
| `reader.rs` | 466 | FileReader/DirectoryScanner |
| `acl.rs` | 226 | POSIX ACL handling, unix cfg-gated |

## UNIQUE STYLES

- Streaming and non-streaming chunkers share the same FastCDC parameters
- ACL code is `#[cfg(unix)]`-gated; non-unix targets get no-op stubs

## TESTS

- `../tests/acl_support.rs` 55 — macOS early-return guard
- `../tests/directory_scanning_test.rs` 138
- `../tests/ignore_support.rs` 60
- `../tests/test_streaming_chunker.rs` 62 — /dev/urandom incompressible stream
- `../tests/zerocopy_integration.rs` 200
- Benches: `../benches/ingest_bench.rs`, `../benches/streaming_memory_bench.rs`

## TEST

```bash
cargo test -p era-ingest
cargo bench -p era-ingest
```

See `crates/era-ingest/AGENTS.md` for crate boundary docs.
