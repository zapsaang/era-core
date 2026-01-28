# ERA (Encrypted Redundant Archiver) Core

**Architecture**: v0.1.0 (Pre-Release / Unstable)

A next-generation encrypted storage engine with content-defined chunking, erasure coding, and post-quantum cryptography support.

## Features

- **Content-Defined Chunking (CDC)**: FastCDC algorithm for deduplication
- **Erasure Coding**: Reed-Solomon with configurable data/parity shards (default: 4+1)
- **Encryption**: XChaCha20-Poly1305 AEAD with context-bound key derivation
- **Post-Quantum**: Hybrid KEM (X25519 + Kyber-768) for key encapsulation
- **Multi-Volume**: Distributed storage across multiple volume files with fault tolerance
- **Traffic Analysis Resistance**: CSPRNG padding to prevent size-channel attacks

## Build Status

| Component | Status |
|-----------|--------|
| `era-crypto` | ✅ |
| `era-codec` | ✅ |
| `era-storage` | ✅ |
| `era-volume` | ✅ |
| `era-packing` | ✅ |
| `era-ingest` | ✅ |
| `era-index` | ✅ |
| `era-engine` | ✅ |
| `era-cli` | ✅ |

## Quick Start

### Prerequisites
- Rust 1.75+ (2021 Edition)

### Running Tests

```bash
cargo test --workspace
```

### Installation

```bash
cargo install --path bins/era-cli
```

### Basic Usage

```bash
# Create an encrypted archive
era create archive.era --password "secret" /path/to/files

# Extract an archive
era extract archive.era --password "secret" --output /path/to/output

# List contents
era list archive.era --password "secret"
```

## Architecture

Layered architecture with strict dependency ordering:

```
L5: era-cli (Binary)
L4: era-engine (Orchestration)
L3: era-index, era-ingest (Features)
L2: era-packing, era-volume (Processing)
L1: era-codec, era-storage (I/O)
L0: era-crypto, era-common (Foundation)
```

## Known Limitations

- **Pre-release**: API is not stable. Breaking changes expected.
- **Index Persistence**: Physical index persistence layer is WIP. `zero_drift_append_tests` marked `#[ignore]`.

## License

MIT / Apache-2.0
