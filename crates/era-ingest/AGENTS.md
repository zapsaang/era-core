# era-ingest crate

File ingestion, FastCDC content-defined chunking, and directory scanning. L3.

## SURFACES
- `src/AGENTS.md` — `Chunker`, `StreamingChunker`, `DirectoryScanner`, `FileReader` internals
- `tests/AGENTS.md` — five integration suites (zerocopy, directory scanning, ignore handling, streaming chunker, ACL support) and `cargo test -p era-ingest`
- `benches/ingest_bench.rs`, `benches/streaming_memory_bench.rs` — chunking throughput

## STRUCTURE

```
era-ingest/src/
├── lib.rs               # Re-exports: Chunker, StreamingChunker, StreamingChunkerZeroCopy, DirectoryScanner
├── chunker.rs           # FastCDC chunking (16KB-64KB-256KB)
├── chunker_zerocopy.rs  # StreamingChunkerZeroCopy
├── reader.rs            # FileReader, DirectoryScanner
├── entry.rs             # Catalog/FileEntry/ChunkRef
└── acl.rs               # POSIX ACL handling (unix cfg-gated)
```

## WHEN CHANGING
- Chunking algorithm changes affect deduplication effectiveness and era-engine write throughput.
- Platform-specific ACL handling (unix extensions) is gated behind cfg flags; test on both unix and windows.

## VALIDATION
```bash
cargo test -p era-ingest
cargo bench -p era-ingest
```

See root `AGENTS.md` for workspace-wide rules and anti-patterns.