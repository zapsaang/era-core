# era-ingest crate

File scanning, ACL capture, and FastCDC chunking entrypoints. See root `AGENTS.md` for workspace rules and `src/AGENTS.md` for module detail.

## SURFACES
- `src/AGENTS.md` — chunker variants, `FileReader`, `DirectoryScanner`, and ACL helpers
- `tests/` — directory scanning, ignore handling, zero-copy integration, and ACL support
- `benches/ingest_bench.rs` and `benches/streaming_memory_bench.rs` — chunking throughput and memory baselines

## WHEN CHANGING
- Chunk-size defaults ripple into packing efficiency, dedup hit rate, and CLI defaults.
- ACL or filesystem metadata behavior must stay platform-aware and should not leak into higher layers.
- Zero-copy and ring-buffer changes need extra scrutiny because they trade readability for throughput.

## VALIDATION
```bash
cargo test -p era-ingest
cargo bench -p era-ingest
```
