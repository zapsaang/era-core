# Ingest Source

File ingestion, FastCDC content-defined chunking, and directory scanning. L3.

## FILES

| File | Lines | Purpose |
|------|-------|---------|
| `lib.rs` | 28 | Re-exports: Chunker, StreamingChunker, DirectoryScanner, FileReader |
| `chunker.rs` | — | FastCDC chunking implementation |
| `chunker_zerocopy.rs` | — | Zero-copy chunker paths |
| `reader.rs` | — | FileReader for buffered file I/O |
| `entry.rs` | — | Ingest entry types |
| `acl.rs` | — | Platform ACL handling (Unix/Windows cfg-gated) |

## UNIQUE STYLES

- Streaming and non-streaming chunkers share the same FastCDC parameters

## TEST

```bash
cargo test -p era-ingest
cargo bench -p era-ingest
```

See `crates/era-ingest/AGENTS.md` for crate boundary docs.
