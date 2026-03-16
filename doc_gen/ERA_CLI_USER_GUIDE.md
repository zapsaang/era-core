# ERA CLI User Guide

## What is era-cli

`era-cli` is the command-line interface for ERA, an encrypted archival tool built for long-term storage. It handles:

- creating archives from files and directories,
- extracting archives,
- listing contents,
- showing archive metadata,
- verifying archive integrity,
- repairing damaged archives,
- repacking archives with new parameters.

The CLI exposes seven subcommands:

```
era create
era extract
era list
era info
era verify
era repair
era repack
```

Global flags:

```
era --help
era --version
era -v <command> ...    # verbose logging (most commands)
```

## Installation

From the repo:

```bash
cargo install --path bins/era-cli
```

Or run without installing:

```bash
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help
```

---

# 1. Quick Start

## Create an archive

```bash
era create --output archive.era --password "your-secret" /path/to/files
```

Omit `--password` and the CLI prompts you interactively with confirmation.

## Extract an archive

```bash
era extract --input archive.era --output ./restored --password "your-secret"
```

## List contents

```bash
era list archive.era --password "your-secret"
```

## Show metadata

```bash
era info archive.era --password "your-secret"
```

## Verify integrity

```bash
era verify archive.era --password "your-secret"
```

## Repair a damaged archive

```bash
era repair archive.era --password "your-secret"
```

## Repack with new parameters

```bash
era repack --input archive.era --output repacked.era --password "your-secret" --compact
```

---

# 2. Commands

## `era create`

Creates a new archive from one or more files or directories.

### Syntax

```
era create [OPTIONS] --output <OUTPUT> <INPUT>...
```

### Examples

Single file:

```bash
era create --output docs.era --password "secret" ./report.pdf
```

Directory (recursive):

```bash
era create --output backup.era --password "secret" ./my-folder
```

Multiple inputs:

```bash
era create --output bundle.era --password "secret" ./photos ./notes.txt ./archive
```

High compression preset:

```bash
era create --output archive.era --password "secret" --compact ./data
```

Certificate mode (key-based access, no password needed):

```bash
era create --output secure.era --certificate public.pem ./data
```

### Directory behavior

Directories are walked recursively. Stored paths are relative to the input base, so extracting recreates the original structure.

If you archive `./source` containing:

```
source/file1.txt
source/subdir/file2.txt
```

extraction recreates:

```
source/file1.txt
source/subdir/file2.txt
```

inside the output directory.

### All flags

| Flag | Description |
|------|-------------|
| `-o, --output <OUTPUT>` | Output archive path (required) |
| `-p, --password <PASSWORD>` | Encryption password (prompted if omitted) |
| `-c, --certificate <CERTIFICATE>` | Public key PEM for certificate mode |
| `-C, --config <CONFIG>` | TOML config file path |
| `-l, --level <LEVEL>` | Compression level 1-22 (default: 3) |
| `--no-compression` | Disable compression (store mode) |
| `-e, --erasure <ERASURE>` | Erasure coding as `data:parity` (default: `4:2`) |
| `--volumes <VOLUMES>` | Number of volumes to distribute shards across |
| `--max-volume-size <BYTES>` | Max bytes per volume (e.g., `4294967296` for 4 GB) |
| `--compact` | High compression preset (Zstd-19, 16 MB blocks, k=32) |
| `-v, --verbose` | Verbose logging |

Geek parameters (advanced tuning):

| Flag | Description |
|------|-------------|
| `--cdc-min <BYTES>` | CDC minimum chunk size |
| `--cdc-avg <BYTES>` | CDC average chunk size |
| `--cdc-max <BYTES>` | CDC maximum chunk size |
| `--packing-k <K>` | Packing k-factor (buffer slots) |
| `--flush-threshold <PCT>` | Packing flush threshold 0-100 |
| `--block-target-size <BYTES>` | Target block size |

### Typical create output

```
 INFO Erasure coding: disabled by CLI
 INFO Created VolumePool with 1 volumes (Strategy: RotatingOffset)
 INFO Creating archive: /tmp/guide_demo.era
 INFO Adding file: era_guide_demo/subdir/nested.txt
 INFO Adding file: era_guide_demo/report.txt
 INFO Adding file: era_guide_demo/hello.txt
 INFO Finalizing archive...
 INFO Packing 3 small files (49 bytes total)
 INFO Packed 3 files successfully
 INFO VolumePool finalized: 1 volumes, 267 total bytes, 1 blocks
 INFO Archive finalized: 3 files, 49 bytes, 2 blocks
 INFO
 INFO Archive created successfully!
 INFO   Archive ID: ff09eb11-25d4-4179-bf55-c7ffa304ff1e
 INFO   Files:      3
 INFO   Total size: 49 B
 INFO   Blocks:     2
```

---

## `era extract`

Extracts all files from an archive.

### Syntax

```
era extract [OPTIONS] --input <INPUT>
```

### Examples

Password mode:

```bash
era extract --input archive.era --output ./restored --password "secret"
```

Certificate/private-key mode:

```bash
era extract --input archive.era --output ./restored --key private.pem
```

Overwrite existing files:

```bash
era extract --input archive.era --output ./restored --password "secret" --force
```

### All flags

| Flag | Description |
|------|-------------|
| `-i, --input <INPUT>` | Input archive path (required) |
| `-o, --output <OUTPUT>` | Output directory (default: `.`) |
| `-p, --password <PASSWORD>` | Decryption password (prompted if omitted) |
| `-k, --key <KEY>` | Private key PEM for certificate mode |
| `-f, --force` | Overwrite existing files |
| `-v, --verbose` | Verbose logging |

### Typical extract output

```
 INFO Extraction complete in 1 second!
 INFO   Extracted: 3 files
 INFO   Skipped:   0 files
 INFO   Written:   49 B
```

---

## `era list`

Lists files stored in an archive.

### Syntax

```
era list [OPTIONS] <ARCHIVE>
```

### Examples

Short listing:

```bash
era list archive.era --password "secret"
```

Long listing with sizes and chunk IDs:

```bash
era list archive.era --password "secret" --long
```

Using a private key:

```bash
era list archive.era --key private.pem
```

### All flags

| Flag | Description |
|------|-------------|
| `-p, --password <PASSWORD>` | Decryption password (prompted if omitted) |
| `-k, --key <KEY>` | Private key PEM for certificate mode |
| `-l, --long` | Show detailed information |
| `-v, --verbose` | Verbose logging |

### Short listing output

```
 INFO era_guide_demo/subdir/nested.txt
 INFO era_guide_demo/report.txt
 INFO era_guide_demo/hello.txt
 INFO
 INFO Total: 3 files (49 B total)
```

### Long listing output

```
 INFO SIZE         CHUNK_ID             PATH
 INFO ------------------------------------------------------------
 INFO 12 B 4f3d3d8acff6c0c1     era_guide_demo/subdir/nested.txt
 INFO 25 B 4f3d3d8acff6c0c1     era_guide_demo/report.txt
 INFO 12 B 4f3d3d8acff6c0c1     era_guide_demo/hello.txt
 INFO
 INFO Total: 3 files (49 B total)
```

The `CHUNK_ID` column shows the first chunk identifier associated with each file entry. It is not a whole-file digest. Small files packed together may share the same `CHUNK_ID`, which is expected behavior.

---

## `era info`

Shows archive metadata and configuration.

### Syntax

```
era info [OPTIONS] <ARCHIVE>
```

### Examples

```bash
era info archive.era --password "secret"
era info archive.era --key private.pem
```

### All flags

| Flag | Description |
|------|-------------|
| `-p, --password <PASSWORD>` | Decryption password (prompted if omitted) |
| `-k, --key <KEY>` | Private key PEM for certificate mode |
| `-v, --verbose` | Enable verbose logging |

### Typical output

```
 INFO ERA Archive Information
 INFO =======================
 INFO
 INFO Archive ID:      ff09eb11-25d4-4179-bf55-c7ffa304ff1e
 INFO Volume ID:       cab433a6-3089-4db1-a6b3-235e7623e1bd
 INFO Volume Sequence: 0
 INFO ERA Version:     8.1
 INFO
 INFO Configuration:
 INFO   Max Volume Size:    1.00 GiB
 INFO   Compression Level:  3
 INFO   KDF Memory Cost:    65536 KB
 INFO   KDF Time Cost:      3
 INFO
 INFO Contents:
 INFO   Total Files:  3
 INFO   Total Size:   49 B
```

---

## `era verify`

Verifies archive integrity by checking all blocks and files.

### Syntax

```
era verify [OPTIONS] <ARCHIVE>
```

### Examples

```bash
era verify archive.era --password "secret"
era verify archive.era --key private.pem
era verify archive.era --password "secret" --verbose
```

### All flags

| Flag | Description |
|------|-------------|
| `-p, --password <PASSWORD>` | Decryption password (prompted if omitted) |
| `-k, --key <KEY>` | Private key PEM for certificate mode |
| `--verbose` | Show detailed error information |

Note: `verify` uses `--verbose` (long form only). The global `-v` flag is separate and controls log verbosity at the top level.

### Typical output

```
 INFO Verification Results
 INFO ====================
 INFO
 INFO Blocks verified:    2
 INFO Blocks failed:      0
 INFO Files verified:     3
 INFO Files incomplete:   0
 INFO Bytes verified:     461 B
 INFO Time taken:         1 second
 INFO
 INFO Archive integrity verified successfully!
```

If verification fails, the command exits non-zero and prints a summary. With `--verbose`, it includes detailed error messages per failed block.

---

## `era repair`

Analyzes an archive and attempts recovery where possible.

### Syntax

```
era repair [OPTIONS] <ARCHIVE>
```

### Examples

Analyze only (dry run):

```bash
era repair archive.era --password "secret"
```

Apply repairs or discard an interrupted-create checkpoint:

```bash
era repair archive.era --password "secret" --force
```

### All flags

| Flag | Description |
|------|-------------|
| `-p, --password <PASSWORD>` | Decryption password (prompted if omitted) |
| `-k, --key <KEY>` | Private key PEM for certificate mode |
| `-f, --force` | Apply repairs or discard checkpoint |
| `--verbose` | Show detailed information |

Note: like `verify`, `repair` uses `--verbose` (long form only).

### What repair does

Repair handles two situations:

**Interrupted archive creation.** If a recovery checkpoint exists from an incomplete `create` run:

- without `--force`: shows recovery info and suggests resuming the original `era create` command,
- with `--force`: discards the checkpoint so you can start fresh.

**Damaged archive.** If the archive exists and looks complete, repair runs verification first:

- if the archive is intact, it reports no repair is needed,
- if there are errors and the archive used erasure coding, it attempts Reed-Solomon repair,
- without `--force`: dry-run mode,
- with `--force`: applies repairs.

Archives created without erasure coding have limited repair options.

### Typical output (healthy archive)

```
 INFO Recovery Analysis
 INFO =================
 INFO
 INFO Checkpoint exists:  No
 INFO Archive exists:     Yes
 INFO Recovery needed:    No
 INFO Completed files:    0
 INFO In-progress file:   None
 INFO Chunks written:     0
 INFO Bytes written:      0
 INFO
 INFO Archive appears complete. Running verification...
 INFO ...
 INFO Archive is intact. No repair needed.
```

---

## `era repack`

Extracts an archive and re-creates it with new parameters. Useful for changing compression, erasure settings, or applying the compact preset to an existing archive.

### Syntax

```
era repack [OPTIONS] --input <INPUT> --output <OUTPUT>
```

### Examples

Repack with compact preset:

```bash
era repack --input old.era --output new.era --password "secret" --compact
```

Repack with custom settings:

```bash
era repack --input old.era --output new.era --password "secret" \
    --level 19 --erasure "6:3"
```

Repack without compression:

```bash
era repack --input old.era --output new.era --password "secret" --no-compression
```

### All flags

| Flag | Description |
|------|-------------|
| `-i, --input <INPUT>` | Input archive path (required) |
| `-o, --output <OUTPUT>` | Output archive path (required) |
| `-p, --password <PASSWORD>` | Decryption password (prompted if omitted) |
| `-k, --key <KEY>` | Private key PEM for certificate mode |
| `--compact` | High compression preset (Zstd-19, 16 MB blocks, k=32) |
| `-l, --level <LEVEL>` | Compression level 1-22 |
| `--no-compression` | Disable compression |
| `-e, --erasure <ERASURE>` | Erasure coding as `data:parity` |
| `-v, --verbose` | Verbose logging |

Geek parameters (same as `create`):

| Flag | Description |
|------|-------------|
| `--cdc-min <BYTES>` | CDC minimum chunk size |
| `--cdc-avg <BYTES>` | CDC average chunk size |
| `--cdc-max <BYTES>` | CDC maximum chunk size |
| `--packing-k <K>` | Packing k-factor |
| `--flush-threshold <PCT>` | Packing flush threshold 0-100 |
| `--block-target-size <BYTES>` | Target block size |

### Typical output

```
 INFO Repacking archive: source.era -> repacked.era
 INFO extracting source archive to temp dir
 INFO ...
 INFO Repack complete in 6 seconds!
 INFO   Files repacked: 3
 INFO   Extracted size:  49 B
 INFO   Repacked size:  49 B
 INFO   Blocks written: 2
```

---

# 3. Compression

ERA uses Zstd compression by default.

## Set compression level

```bash
era create --output archive.era --password "secret" --level 12 ./data
```

Valid range: `1` to `22`. Higher levels compress more but take longer.

## Disable compression

```bash
era create --output archive.era --password "secret" --no-compression ./data
```

Equivalent to `--level 0`. Use this for already-compressed content (video, images, zip files) where compression would waste CPU without saving space.

## Compact preset

```bash
era create --output archive.era --password "secret" --compact ./data
```

The `--compact` preset applies Zstd level 19, 16 MB blocks, and k=32 packing. It produces smaller archives at the cost of slower write speed. The CLI confirms the preset on startup:

```
 INFO Using compact preset (Zstd-19, 16MB blocks, k=32)
```

`--compact` is also available on `repack`.

## Defaults

| Setting | Default |
|---------|---------|
| Algorithm | Zstd |
| Level | 3 |

---

# 4. Erasure Coding

Erasure coding splits each block into data and parity shards using Reed-Solomon. If some shards are lost or corrupted, the block can be reconstructed from the remaining ones.

## Default behavior

Erasure coding is **on by default** with a `4:2` configuration (4 data shards, 2 parity shards). This means:

- archives produce 6 volume files by default,
- up to 2 shards per block can be lost and the data is still recoverable.

A small archive with default settings produces:

```
archive.era        (main volume)
archive.era.001
archive.era.002
archive.era.003
archive.era.004
archive.era.005
```

This is expected. Keep all volume files together.

## Custom erasure settings

```bash
era create --output archive.era --password "secret" --erasure 6:3 ./data
```

Format: `data:parity`. Both values must be at least `1`. Total shards cannot exceed `255`.

With `6:3`, you get 9 volume files and can tolerate losing any 3.

## Disable erasure coding

```bash
era create --output archive.era --password "secret" --erasure none ./data
```

Not recommended for important data. Without erasure coding, a single corrupted block cannot be recovered.

## Volume count

When erasure coding is enabled, `--volumes` must divide the total shard count for the selected erasure layout.
For `4:2`, accepted `--volumes` values include `1`, `2`, `3`, and `6`; `4` is rejected.

```bash
era create --output archive.era --password "secret" --erasure 4:2 --volumes 6 ./data
```

You can also set a maximum size per volume:

```bash
era create --output archive.era --password "secret" --max-volume-size 4294967296 ./data
```

When a volume hits the size limit, a new one is created automatically.

## Erasure coding with create output

```
 INFO Erasure coding:   4:2 (50% overhead, can recover 2 lost shards/block)
 INFO Using 6 volumes (will tolerate up to 2 volume failures)
 INFO Created VolumePool with 6 volumes (Strategy: RotatingOffset)
 ...
 INFO Archive created successfully!
 INFO   Archive ID: 74e38521-b2cc-494c-8ff9-12fbb7438a58
 INFO   Files:      3
 INFO   Total size: 49 B
 INFO   Blocks:     6
```

---

# 5. Certificate Mode

Certificate mode lets you create archives that can only be opened with a private key, without needing to share a password.

## Generate a keypair

Use `era-keygen` to generate a keypair and certificate:

```bash
era-keygen --output-dir ./keys
```

This produces `public.pem` and `private.pem`.

## Create a certificate-based archive

```bash
era create --output secure.era --certificate public.pem ./data
```

When you provide `--certificate` without `--password`, the CLI generates a random 32-byte password automatically. The archive is only decryptable with the matching private key.

## Hybrid mode (password + certificate)

```bash
era create --output secure.era --certificate public.pem --password "secret" ./data
```

In hybrid mode, either the password or the private key can decrypt the archive.

## Open a certificate-based archive

All read commands support `--key`:

```bash
era extract --input secure.era --output ./restored --key private.pem
era list secure.era --key private.pem
era info secure.era --key private.pem
era verify secure.era --key private.pem
era repair secure.era --key private.pem
```

## Supported PEM formats

Private keys:
- PKCS#8
- OpenSSH

Public input:
- SubjectPublicKeyInfo (SPKI)
- X.509 certificates

Note: encrypted PKCS#8 private keys are not yet supported.

---

# 6. Config Files

Config files let you define archive parameters in TOML and reuse them across runs.

## Precedence

```
CLI flags > config file > built-in defaults
```

You can define a base config and override individual settings from the command line.

## Using a config file

```bash
era create -C ./config.toml --output archive.era --password "secret" ./data
```

## Partial configs work

All config sections use `#[serde(default)]`, so you can write a sparse override file. A config with only a compression section is valid:

```toml
[compression]
level = 9
```

## Full config example

```toml
[compression]
algorithm = "Zstd"
level = 9

[encryption]
algorithm = "XChaCha20Poly1305"
kdf_memory_cost = 65536
kdf_time_cost = 3

[volume]
max_size = 1073741824
enable_padding = true
naming_template = "{archive_id}.vol{seq:03}.era"

[block]
target_size = 4194304

[chunking]
min_size = 4096
avg_size = 65536
max_size = 262144
normalization_level = "Level1"
rolling_hash_seed = 0

[packing]
k_factor = 8
flush_threshold = 95

[erasure]
data_shards = 4
parity_shards = 2

[distribution]
strategy = "RotatingOffset"
min_volumes = 3
target_volumes = 6
```

## Built-in defaults

| Setting | Default |
|---------|---------|
| Compression | Zstd level 3 |
| Encryption | XChaCha20-Poly1305 |
| KDF memory cost | 65536 KB |
| KDF time cost | 3 |
| Max volume size | 1 GiB |
| Block target size | 4 MiB |
| Erasure coding | 4:2 |
| CDC min | 4096 bytes |
| CDC avg | 65536 bytes |
| CDC max | 262144 bytes |
| Packing k-factor | 8 |
| Packing flush threshold | 95% |

---

# 7. Password Handling

## Interactive prompts

If you omit `--password` on any command, the CLI prompts you:

- on `create`: prompts and asks for confirmation,
- on all other commands: prompts once.

## Scripting

Pass `--password` explicitly to skip prompts:

```bash
era create --output archive.era --password "secret" ./data
era verify archive.era --password "secret"
```

## Wrong password

If you provide the wrong password, the CLI fails with:

```
Error: Failed to open archive

Caused by:
    Invalid key: No valid credentials found
```

---

# 8. Geek Parameters

These are available on `create` and `repack` for advanced tuning of the internal pipeline. Most users should leave them at defaults.

## Content-Defined Chunking (CDC)

CDC splits files into variable-size chunks based on content. The three size parameters control the chunk size distribution:

```bash
era create \
  --output archive.era \
  --password "secret" \
  --cdc-min 16384 \
  --cdc-avg 65536 \
  --cdc-max 262144 \
  ./data
```

Validation rules:

- all values must be greater than `0`,
- must satisfy `min <= avg <= max`.

## Packing

Small files are packed together into MacroBlocks to avoid wasting space on tiny chunks. The packing parameters control buffer behavior:

```bash
era create \
  --output archive.era \
  --password "secret" \
  --packing-k 16 \
  --flush-threshold 90 \
  ./data
```

## Block target size

Controls the target size for encrypted blocks:

```bash
era create --output archive.era --password "secret" --block-target-size 16777216 ./data
```

The compact preset sets this to 16 MB automatically.

---

# 9. Recommended Workflows

## Simple password-based backup

```bash
era create --output backup.era --password "secret" ./important-data
era verify backup.era --password "secret"
era list backup.era --password "secret"
era extract --input backup.era --output ./restore-test --password "secret"
```

## Space-saving archive

```bash
era create --output archive.era --password "secret" --compact ./data
```

## Fast archive without compression

```bash
era create --output archive.era --password "secret" --no-compression ./data
```

## Redundant archive with stronger erasure settings

```bash
era create --output archive.era --password "secret" --erasure 6:3 --volumes 9 ./data
```

## Config-driven archive creation

```bash
era create -C ./config.toml --output archive.era --password "secret" ./data
```

## Certificate-based archive (no shared password)

```bash
# Create
era create --output secure.era --certificate public.pem ./data

# Extract
era extract --input secure.era --output ./restored --key private.pem

# Verify
era verify secure.era --key private.pem
```

## Upgrade an existing archive to compact

```bash
era repack --input old.era --output compact.era --password "secret" --compact
```

## Safe repair: analyze first, then apply

```bash
era repair archive.era --password "secret"
era repair archive.era --password "secret" --force
```

---

# 10. Troubleshooting

## "Compression level must be between 0 and 22"

Use a value in that range, or use `--no-compression`.

## "Invalid erasure format"

Use `--erasure 4:2`, not `4,2` or `4`.

## "Invalid volume count for erasure layout"

With `--erasure 4:2`, the `--volumes` value must divide total shards (`6`).
Accepted examples: `1`, `2`, `3`, `6`. Rejected example: `4`.
Either omit `--volumes` (the CLI chooses a compatible value) or pass one of the compatible counts.

## Config file parse failure

Check that your TOML section names and field names are correct. Partial configs are fine, but field names must match exactly.

## Wrong password or wrong private key

The CLI fails to open the archive. That is expected. Double-check your credentials and try again.

## Interrupted archive creation

Run repair to inspect recovery state:

```bash
era repair archive.era --password "secret"
```

To discard the saved resume state and start over:

```bash
era repair archive.era --password "secret" --force
```

## Multiple volume files

If your archive produced `archive.era`, `archive.era.001`, etc., that is normal when erasure coding is enabled. Keep all volume files in the same directory. ERA finds them automatically.

## "Not enough shards for recovery"

Too many volume files are missing or corrupted. With `4:2` erasure coding, you can lose up to 2 volumes. Try `era repair` first. If more than 2 volumes are gone, the data cannot be recovered.
