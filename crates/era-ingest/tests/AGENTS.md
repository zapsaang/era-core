# era-ingest tests

Integration tests under `crates/era-ingest/tests/`. They exercise the public `era_ingest` API surface only: directory scanning with pattern/ACL/xattr extraction (`DirectoryScanner`, `ScanOptions`, `FileType`) and FastCDC chunking (`StreamingChunker`, `StreamingChunkerZeroCopy`, `ChunkerConfig`) driven via `std::io::Cursor` and, for one suite, `/dev/urandom`. No internal-only entry points are touched.

## SUITES

| File | Lines | Purpose |
|------|-------|---------|
| `acl_support.rs` | 55 | macOS-only: `test_acl_ingestion_macos` is a sync `#[test]` that early-returns via `if !cfg!(target_os = "macos") { return; }`. Creates a `tempfile::TempDir`, writes `secret.txt`, runs `chmod +a "nobody allow read,write" <file>`, builds `DirectoryScanner` with `ScanOptions { extract_acls: true, ..Default::default() }`, scans, and asserts `entry.acl.is_some()` plus non-empty bytes. |
| `directory_scanning_test.rs` | 138 | Sync `#[test]` (`test_end_to_end_directory_scanning`). Creates a `tempfile::TempDir`, populates a fake project tree (src/, target/, scripts/, README.md), sets unix permissions and `user.era_test` xattr where supported, configures `DirectoryScanner::new(ScanOptions { include_patterns, exclude_patterns, extract_xattrs, extract_acls, .. })`, and verifies file-type classification, include/exclude pattern filtering, executable permission bit, and xattr round-trip. |
| `ignore_support.rs` | 60 | Sync `#[test]` (`test_ignore_files_respected`). Creates a `tempfile::TempDir`, writes `.gitignore` (`ignored.log`), `.ignore` (`tmp/`), and `.eraignore` (`secret.bin`) alongside test entries, runs `DirectoryScanner::new(ScanOptions { include_patterns: vec![], exclude_patterns: vec![], extract_xattrs: false, extract_acls: false, .. })`, and asserts ignore patterns are honored against a real on-disk tree. |
| `test_streaming_chunker.rs` | 62 | Async `#[tokio::test]` (`test_streaming_chunker_directly`). Reads exactly 1 MiB from `/dev/urandom` via `File::open("/dev/urandom")` + `read_exact`, wraps the resulting `Vec<u8>` in `std::io::Cursor`, drives `StreamingChunker::new(reader, ChunkerConfig::default()).into_stream()`, and asserts the chunk count is `> 8` and `< 25`. |
| `zerocopy_integration.rs` | 200 | Async `#[tokio::test]` set (10 tests). Generates in-memory byte vectors via the `generate_test_data(size, pattern)` helper, wraps each in `std::io::Cursor`, and asserts that `StreamingChunker` and `StreamingChunkerZeroCopy` produce identical chunk counts, sizes, hashes, and contents across small/medium/large sizes, custom `ChunkerConfig` shapes, wraparound, boundary, compressible, and pseudo-random inputs. |

## CONVENTIONS

- Integration tests only — public `era_ingest` API surface, no internal paths.
- Async suites use `#[tokio::test]`; sync suites use plain `#[test]`.
- `directory_scanning_test.rs`, `ignore_support.rs`, and `acl_support.rs` create a `tempfile::TempDir` at test scope and let `Drop` tear it down. `test_streaming_chunker.rs` and `zerocopy_integration.rs` are in-memory `Cursor` tests and do not use `tempfile`.
- Ignore-file behavior is verified against freshly written `.gitignore` / `.ignore` / `.eraignore` files in a temp tree, not by mocking the ignore layer.

## PLATFORM NOTES

- `test_streaming_chunker.rs` reads `/dev/urandom` directly — Unix-like runtime required; it will fail to open the device on platforms without it.
- `acl_support.rs` is macOS-only via the `cfg!(target_os = "macos")` runtime guard plus `chmod +a`. The test compiles and runs (returning early) on every target but only asserts ACL capture on macOS.
- `directory_scanning_test.rs` and `ignore_support.rs` assume a real on-disk filesystem: `DirectoryScanner` walks actual paths and reads ignore files from them.
- `zerocopy_integration.rs` is fully in-memory and runs on every target.

## COMMANDS

```bash
cargo test -p era-ingest
cargo test -p era-ingest --test test_streaming_chunker
cargo test -p era-ingest --test acl_support
cargo test -p era-ingest --test zerocopy_integration
```

## TEST-SPECIFIC ANTI-PATTERNS

- Do not weaken `tempfile::TempDir` isolation in `directory_scanning_test.rs`, `ignore_support.rs`, or `acl_support.rs` — each test owns its temp root. Do not, however, force `tempfile` onto `test_streaming_chunker.rs` or `zerocopy_integration.rs`, which are intentionally in-memory via `Cursor`.
- Do not relax the `chunks.len() > 8 && chunks.len() < 25` assertion band in `test_streaming_chunker.rs` (or the analogous count assertions in `zerocopy_integration.rs`) without chunking-algorithm evidence.
- Do not replace the `/dev/urandom`-fed incompressible byte stream in `test_streaming_chunker.rs` with patterned bytes — that input is what the assertion band is calibrated against.
- Do not remove the `cfg!(target_os = "macos")` early-return guard in `acl_support.rs`; that guard is the contract that keeps the suite compiling everywhere while only asserting on macOS.
