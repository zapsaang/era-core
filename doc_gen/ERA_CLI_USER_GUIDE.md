# ERA CLI User Guide

## What era-cli is

`era-cli` is the command-line interface for ERA, an encrypted archival tool that can:

- create archives from files and directories,
- extract archives,
- list contents,
- show archive metadata,
- verify archive integrity,
- attempt repair or recovery.

The current CLI exposes these commands:

```bash
era create
era extract
era list
era info
era verify
era repair
```

Global help:

```bash
era --help
era --version
```

Global verbose logging:

```bash
era --verbose <command> ...
```

## Important reality check before you start

This project is still **pre-alpha**. The CLI works, but some behaviors are still rough or inconsistent.

A few things to know up front:

- Password-based workflows are the most consistently supported.
- `extract` and `list` support certificate/private-key access.
- `info`, `verify`, and `repair` are currently **password-only** in the CLI.
- Erasure coding is **enabled by default** for normal archive creation unless your config disables it.
- Matrix distribution is effectively always `RotatingOffset` in the current CLI.
- Config files must be complete enough to deserialize as `ArchiveConfig`; a partial TOML file can fail to parse.
- `list --long` shows a chunk hash column, **not a full-file digest**.

## Installation

From the repo:

```bash
cargo install --path bins/era-cli
```

Or run without installing:

```bash
cargo run --manifest-path bins/era-cli/Cargo.toml -- --help
```

# 1. Quick Start

## Create an archive with a password

```bash
era create --output archive.era --password "your-secret" /path/to/files
```

If you omit `--password`, the CLI will prompt you and ask for confirmation.

## Extract an archive

```bash
era extract --input archive.era --output ./restored --password "your-secret"
```

## List archive contents

```bash
era list archive.era --password "your-secret"
```

## Show archive metadata

```bash
era info archive.era --password "your-secret"
```

## Verify archive integrity

```bash
era verify archive.era --password "your-secret"
```

## Analyze or repair an archive

```bash
era repair archive.era --password "your-secret"
```

# 2. Command Overview

## `era create`

Creates a new archive from one or more files or directories.

### Basic syntax

```bash
era create [OPTIONS] --output <OUTPUT> <INPUT>...
```

### Common examples

Create from one file:

```bash
era create --output docs.era --password "secret" ./report.pdf
```

Create from a directory recursively:

```bash
era create --output backup.era --password "secret" ./my-folder
```

Create from multiple inputs:

```bash
era create --output bundle.era --password "secret" ./photos ./notes.txt ./archive
```

### What happens with directories

Directories are walked recursively. Stored paths are relative to the input base, so extracting a directory input recreates its directory structure.

For example, if you archive:

```bash
era create -o archive.era --password "secret" ./source
```

and `./source` contains:

```text
source/file1.txt
source/subdir/file2.txt
```

then extraction recreates:

```text
source/file1.txt
source/subdir/file2.txt
```

inside the output directory.

### Key options

#### Output path

```bash
-o, --output <OUTPUT>
```

Required.

#### Password

```bash
-p, --password <PASSWORD>
```

Optional. If omitted, you are prompted interactively.

#### Config file

```bash
-C, --config <CONFIG>
```

Loads a TOML config file.

Actual precedence is:

1. CLI flags
2. config file
3. built-in defaults

#### Certificate mode

```bash
-c, --certificate <CERTIFICATE>
```

Uses a public certificate / public key PEM file for certificate-based archive access.

Example:

```bash
era create --output secure.era --certificate public.pem ./data
```

### Important caveat: certificate mode today

In the current CLI, if you provide `--certificate` and do **not** provide `--password`, the create path does **not** do the normal interactive password confirmation flow. Internally it uses an empty password string unless one is explicitly passed.

So if you want password + certificate behavior, pass the password explicitly:

```bash
era create --output secure.era --certificate public.pem --password "secret" ./data
```

If you want pure certificate-style usage, the current CLI allows that, but this behavior is not polished yet.

## `era extract`

Extracts all files from an archive.

### Basic syntax

```bash
era extract [OPTIONS] --input <INPUT>
```

### Common examples

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

### Key options

#### Input archive

```bash
-i, --input <INPUT>
```

Required.

#### Output directory

```bash
-o, --output <OUTPUT>
```

Optional. Defaults to the current directory.

#### Password

```bash
-p, --password <PASSWORD>
```

If omitted, the CLI prompts:

```text
Enter decryption password:
```

#### Private key for certificate mode

```bash
-k, --key <KEY>
```

Loads a PEM private key and opens the archive using keypair-based access.

Supported private-key input formats currently come from the PEM loader in `era-crypto`, including:

- PKCS#8 private key
- OpenSSH private key

#### Force overwrite

```bash
-f, --force
```

Overwrites existing files on extraction.

## `era list`

Lists files stored in an archive.

### Basic syntax

```bash
era list [OPTIONS] <ARCHIVE>
```

### Common examples

Short listing:

```bash
era list archive.era --password "secret"
```

Long listing:

```bash
era list archive.era --password "secret" --long
```

List using private key:

```bash
era list archive.era --key private.pem
```

### Long listing output

`--long` prints columns like:

- size,
- hash,
- path.

Important: the current `HASH` column is derived from the **first chunk** associated with the file entry, not a canonical whole-file digest. Different files can therefore show the same value, especially in small-file packing cases.

So treat `list --long` as an inspection aid, not as a cryptographic manifest of file hashes.

## `era info`

Shows archive metadata and selected configuration values.

### Basic syntax

```bash
era info [OPTIONS] <ARCHIVE>
```

### Example

```bash
era info archive.era --password "secret"
```

### What it shows

Current output includes:

- Archive ID
- Volume ID
- Volume sequence
- ERA version
- Max volume size
- Compression level
- KDF memory cost
- KDF time cost
- Total file count
- Total content size

### Important caveat

`era info` currently supports **password mode only** in the CLI. It does **not** expose a `--key` option.

## `era verify`

Verifies archive integrity.

### Basic syntax

```bash
era verify [OPTIONS] <ARCHIVE>
```

### Example

```bash
era verify archive.era --password "secret"
```

Verbose mode:

```bash
era verify archive.era --password "secret" --verbose
```

or:

```bash
era verify -v archive.era --password "secret"
```

### What it checks

The verify path reports:

- blocks verified,
- blocks failed,
- files verified,
- incomplete files,
- bytes verified,
- elapsed time.

If verification succeeds, it exits successfully.

If verification fails, it exits non-zero and prints a summary. With `--verbose`, it prints detailed error messages.

### Important nuance about `-v`

On `verify`, `-v` is effectively tied into verbose behavior for that command. In practice, it also causes debug-style logging because there is a global verbose flag and a command-local verbose field sharing the same short flag. From a user perspective, this means:

- `era verify -v ...` gives you more detail,
- and you may also see lower-level debug logging.

That is how the current CLI behaves.

## `era repair`

Analyzes an archive and, where possible, attempts recovery or repair.

### Basic syntax

```bash
era repair [OPTIONS] <ARCHIVE>
```

### Example

Analyze only:

```bash
era repair archive.era --password "secret"
```

Apply repair actions or discard an interrupted-create checkpoint:

```bash
era repair archive.era --password "secret" --force
```

### What `repair` actually does today

`repair` handles two different situations:

#### A. Interrupted archive creation

If the CLI finds a recovery checkpoint from an incomplete `create` operation:

- without `--force`, it tells you to rerun the original `era create` command so creation can resume,
- with `--force`, it discards the checkpoint so you can start fresh.

So `--force` here does **not** mean “blindly fix everything”; it can also mean “throw away the saved resume state”.

#### B. Existing but damaged archive

If the archive exists and looks complete, `repair` runs verification first.

- If the archive is intact, it reports that no repair is needed.
- If there are errors and the archive used erasure coding, it attempts Reed–Solomon based repair logic.
- If you do **not** pass `--force`, repair runs in an effective dry-run mode.
- If you **do** pass `--force`, it can apply repairs.

If the archive was created **without** erasure coding, repair options are limited, and the CLI will suggest extracting what is still recoverable.

### Multi-volume detection

The repair flow tries to detect multi-volume archives heuristically. This is not a polished archive-discovery UX yet, so document it as best-effort, not magic.

# 3. Compression, Erasure Coding, and Volumes

## Compression

### Set compression level

```bash
era create --output archive.era --password "secret" --level 12 ./data
```

Rules enforced by the CLI:

- valid range is `0..22`
- `0` means no compression

### Disable compression completely

```bash
era create --output archive.era --password "secret" --no-compression ./data
```

Equivalent to:

```bash
era create --output archive.era --password "secret" --level 0 ./data
```

## Erasure coding

### Use custom erasure settings

```bash
era create --output archive.era --password "secret" --erasure 6:3 ./data
```

Current CLI rules:

- format must be `data:parity`
- both values must be at least `1`
- total shards must not exceed `255`

### Disable erasure coding

```bash
era create --output archive.era --password "secret" --erasure none ./data
```

### Default behavior

If you do not specify erasure settings and do not override them via config, the CLI currently starts from secure defaults equivalent to:

- data shards: `4`
- parity shards: `2`

That means normal archive creation may produce a multi-volume archive by default.

In a real run, creating a tiny directory with default settings produced:

- `demo.era`
- `demo.era.001`
- `demo.era.002`
- `demo.era.003`
- `demo.era.004`
- `demo.era.005`

So even small archives can fan out into multiple volume files when erasure coding is enabled.

## Volumes

### Set a maximum volume size

```bash
era create --output archive.era --password "secret" --max-volume-size 4294967296 ./data
```

### Set explicit volume count

```bash
era create --output archive.era --password "secret" --erasure 4:2 --volumes 6 ./data
```

If erasure coding is enabled, the CLI enforces:

```text
volume count >= total shards
```

So for `4:2`, `--volumes` must be at least `6`.

## Matrix distribution

The CLI exposes:

```bash
--matrix-distribution <true|false>
```

But the current implementation effectively forces the `RotatingOffset` strategy regardless. Passing `false` is deprecated and does not restore some alternate strategy.

For customers, the practical guidance is:

- you can treat matrix distribution as on/standardized in current builds,
- do not rely on this flag for meaningful strategy switching yet.

# 4. Advanced “Geek Parameters”

These are available on `create`:

```bash
--cdc-min <CDC_MIN>
--cdc-avg <CDC_AVG>
--cdc-max <CDC_MAX>
--packing-k <PACKING_K>
```

Example:

```bash
era create \
  --output archive.era \
  --password "secret" \
  --cdc-min 16384 \
  --cdc-avg 65536 \
  --cdc-max 262144 \
  --packing-k 8 \
  ./data
```

Current validation rules:

- all CDC sizes must be greater than `0`
- they must satisfy:

```text
min <= avg <= max
```

If not, the CLI fails before archive creation.

These options are useful for advanced tuning, but they are not beginner settings.

# 5. Config File Usage

## How config precedence works

Actual precedence is:

1. CLI flags
2. config file
3. built-in defaults

So you can define a base config and override parts of it from the command line.

## Important caveat: partial configs can fail

The current CLI deserializes the TOML directly into the full `ArchiveConfig` structure. That means a partial config file like:

```toml
[compression]
level = 9
```

can fail because required sibling fields are missing.

For example, a config with `[compression]` but no `algorithm` failed with:

```text
missing field `algorithm`
```

So for now, treat config files as **full structured configs**, not sparse overrides.

## Minimal working config example

This is a minimal config that worked in testing:

```toml
[compression]
algorithm = "Zstd"
level = 3

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
```

Use it like this:

```bash
era create \
  -C ./config.toml \
  --output archive.era \
  --password "secret" \
  ./data
```

## Fuller config example

If you want to define chunking, packing, erasure, and distribution explicitly too:

```toml
[compression]
algorithm = "Zstd"
level = 9

[encryption]
algorithm = "XChaCha20Poly1305"
kdf_memory_cost = 65536
kdf_time_cost = 3

[volume]
max_size = 1048576
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

# 6. Password and Key Handling

## Password workflows

### Create

- If `--password` is supplied: no interactive confirmation
- If `--password` is omitted: interactive prompt with confirmation

### Extract / List / Info / Verify / Repair

- If `--password` is supplied: non-interactive
- If omitted: interactive password prompt

This makes scripting easy, but it also means a typo in a scripted `create --password ...` is not caught by confirmation.

## Certificate / key workflows

### Create with a public certificate

```bash
era create --output archive.era --certificate public.pem ./data
```

### Extract with a private key

```bash
era extract --input archive.era --output ./restored --key private.pem
```

### List with a private key

```bash
era list archive.era --key private.pem
```

### Current limitations

- `info` does not support `--key`
- `verify` does not support `--key`
- `repair` does not support `--key`

So if you are building a customer workflow around certificate-based archives, call out that only some read paths currently expose key-based access in the CLI.

## Supported PEM/key input formats

Based on the current PEM loader, the CLI supports loading:

Private keys:
- PKCS#8
- OpenSSH

Public input:
- SubjectPublicKeyInfo (SPKI)
- X.509 certificates

One more important caveat: encrypted PKCS#8 private keys are **not yet supported** by the loader.

# 7. What Output Looks Like

## Create

A successful `create` run prints summary information such as:

- archive ID
- file count
- total size
- block count

With `--verbose`, you also see internal progress and debug logs, such as:

- small-file buffering,
- durable checkpoint commit,
- catalog write,
- embedded index finalization.

## Extract

Reports:

- extracted file count
- skipped file count
- total bytes written

## Verify

Reports:

- verified blocks
- failed blocks
- verified files
- incomplete files
- bytes verified
- time taken

## Repair

Reports recovery analysis first, including:

- whether checkpoint exists,
- whether archive exists,
- whether recovery is needed,
- in-progress file info,
- bytes/chunks written.

Then it either:

- says no repair is needed,
- suggests resume behavior,
- simulates repair,
- or applies repair when `--force` is used.

# 8. Known Rough Edges You Should Tell Customers About

These are worth documenting explicitly.

## 1. `list --long` hash is not a full file hash

It is a chunk-derived display value, not a canonical whole-file digest.

## 2. `info`, `verify`, and `repair` are password-only in the CLI

Even though key-based access exists in some read paths, those commands do not expose it yet.

## 3. Config files are not sparse patches

A partial TOML file may fail to parse because the CLI currently expects enough fields to deserialize the full config structure.

## 4. Certificate mode on create is not polished

If you use `--certificate` without `--password`, the create path skips the normal password confirmation flow and internally uses an empty password string.

## 5. `--matrix-distribution=false` does not really disable strategy use

The CLI still forces `RotatingOffset`.

## 6. Small archives may still produce multiple volume files

That is normal when erasure coding is enabled.

## 7. Verify on a healthy archive can still log degraded-mode warnings

In a real demo run, verification succeeded but logged embedded-index recovery warnings and continued successfully. Customers should treat those as implementation details unless the command exits non-zero.

# 9. Recommended Customer Workflows

## Simple password-based backup

```bash
era create --output backup.era --password "secret" ./important-data
era verify backup.era --password "secret"
era list backup.era --password "secret"
era extract --input backup.era --output ./restore-test --password "secret"
```

## Space-saving archive with stronger compression

```bash
era create --output archive.era --password "secret" --level 12 ./data
```

## Fast archive without compression

```bash
era create --output archive.era --password "secret" --no-compression ./data
```

## Redundant archive with explicit erasure settings

```bash
era create --output archive.era --password "secret" --erasure 6:3 --volumes 9 ./data
```

## Config-driven archive creation

```bash
era create -C ./config.toml --output archive.era --password "secret" ./data
```

## Certificate-based extraction

```bash
era extract --input archive.era --output ./restored --key private.pem
```

## Safe repair analysis first, then apply

```bash
era repair archive.era --password "secret"
era repair archive.era --password "secret" --force
```

# 10. Troubleshooting

## “Compression level must be between 0 and 22”

Use a value in that range, or use:

```bash
--no-compression
```

## “Invalid erasure format”

Use:

```bash
--erasure 4:2
```

not something like `4,2` or `4`.

## “Volume count must be >= total shards”

If you use:

```bash
--erasure 4:2
```

then volume count must be at least:

```text
6
```

## Config file parse failure

Your TOML is probably too incomplete. Start from a full working template rather than a partial override.

## Wrong password or wrong private key

The CLI will fail to open, verify, or extract. That is expected behavior.

## Interrupted archive creation

Run:

```bash
era repair archive.era --password "secret"
```

to inspect recovery state.

If you want to discard saved resume state and start over:

```bash
era repair archive.era --password "secret" --force
```
