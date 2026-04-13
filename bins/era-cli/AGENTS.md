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

## ARCHITECTURE

- **clap** for argument parsing (7 subcommands)
- **tokio** async runtime for all I/O
- All archive operations delegate to `era_engine` — no direct crate access

## AUTH MODES

- Password-based (Argon2id + XChaCha20-Poly1305)
- Certificate-based (X25519 or hybrid X25519+Kyber-768)
- Threshold (T-of-N Shamir secret sharing)

## RUN

```bash
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help
cargo test -p era-cli
```

See root `AGENTS.md` for workspace rules and anti-patterns.