# era-ingest crate

File ingestion, FastCDC content-defined chunking, and directory scanning. L3.

## SURFACES
- `src/AGENTS.md` — `Chunker`, `StreamingChunker`, `DirectoryScanner`, `FileReader` internals
- `tests/` — zerocopy, directory scanning, and platform-specific ACL handling
- `benches/ingest_bench.rs`, `benches/streaming_memory_bench.rs` — chunking throughput

## STRUCTURE

```
era-ingest/src/
├── lib.rs               # Re-exports: Chunker, StreamingChunker, DirectoryScanner
├── chunker.rs           # FastCDC chunking implementation
├── chunker_zerocopy.rs  # Zero-copy chunker paths
├── chunker_ringbuf.rs   # Ring-buffer chunker (NEVER calls copy_within)
├── reader.rs            # FileReader
├── entry.rs             # Ingest entry types
└── acl.rs               # Platform ACL handling
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