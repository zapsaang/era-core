# CLI Source

CLI binary source tree. L5 — top of stack, delegates all archive work to era-engine. Crate-wide docs in parent AGENTS.md.

## FILES

| File | Lines | Purpose |
|------|------:|---------|
| `main.rs` | 600 | clap `Cli` struct + `Commands` enum (8 subcommands). `#[tokio::main]`, disables core dumps, delegates to `commands::*`. |
| `commands.rs` | 2056 | All 8 command implementations. dialoguer password prompts. Uses ArchiveWriter/ArchiveReader/RecoveryManager, repair/repack from era-engine. |
| `progress.rs` | 251 | Progress UI. |

## EXAMPLES

| File | Lines | Purpose |
|------|------:|---------|
| `examples/batch_files_demo.rs` | 116 | Batch file ingestion demo. |
| `examples/guard_pages_demo.rs` | 175 | Guard pages security demonstration. |

## WHEN CHANGING

- Any UX/CLI change starts in `commands.rs`.
- Auth-mode flags map to `era-engine/src/auth.rs` — engine owns the semantics.
- Keep `main.rs` thin: parsing and dispatch only.

## VALIDATION

```bash
cargo test --release -p era-cli
```
