# era-cli

CLI binary (`era` command) for encrypted archival storage. L5 — top of stack, delegates to era-engine.

## COMMANDS

| Command | Purpose |
|---------|---------|
| `create` | Create encrypted archive from files/directories |
| `extract` | Extract archive contents to directory |
| `list` | List archive contents with metadata |
| `info` | Show archive metadata (header, config, volumes) |
| `verify` | Verify archive integrity |
| `repair` | Repair damaged archive using Reed-Solomon recovery |
| `repack` | Repack archive with new parameters |
| `keygen` | Generate keypair — hybrid (X25519+ML-KEM-768) by default, legacy X25519 via `-t x25519` |

## ARCHITECTURE

- **clap** for argument parsing (8 subcommands)
- **tokio** async runtime for all I/O
- All archive operations delegate to `era_engine` — no direct crate access

## AUTH MODES

- Password-based (Argon2id + XChaCha20-Poly1305)
- Certificate-based (X25519 or hybrid X25519+ML-KEM-768)
- Threshold (T-of-N Shamir secret sharing)

## SURFACES

- `src/AGENTS.md` — source-tree map: main.rs, commands.rs, progress.rs, examples
- `tests/AGENTS.md` — CLI integration test surface (10 test files + harness)
- `examples/` — batch_files_demo, guard_pages_demo

## VALIDATION

```bash
cargo test --release -p era-cli  # matches CI
```

See root `AGENTS.md` for workspace rules and anti-patterns.