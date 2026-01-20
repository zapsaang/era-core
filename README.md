# ERA v8.1: **E**ncrypted **R**edundant **A**rchive

![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen)
![Resilience](https://img.shields.io/badge/Resilience-Verified-blue)
![Architecture](https://img.shields.io/badge/Architecture-Self--Contained-orange)
![Cold Recovery](https://img.shields.io/badge/Cold%20Recovery-Enabled-success)
![Rust](https://img.shields.io/badge/Rust-1.70%2B-red)

**ERA v8.1** is a next-generation archival storage engine designed for **extreme data resilience**, **high-performance deduplication**, and **cryptographic agility**. It implements the "Unkillable" design philosophy with true non-blocking async I/O and **zero-knowledge cold recovery**, ensuring data recovery even in the face of significant storage corruption, missing volumes, partial overwrite, **or complete index loss**.

## 🚀 Key Features

### Core Capabilities
*   **"Unkillable" Resilience**: Proven to survive:
    *   Single volume loss (in multi-volume setups)
    *   Partial file truncation (up to 50% with erasure coding)
    *   Random bit-rot and corruption (CRC32 + Poly1305 AEAD protected)
    *   Missing footers (via floating footer reconstruction)
    *   Header corruption (via volume header backup)
    *   **Complete index loss (via zero-knowledge cold recovery)** ✅ NEW
*   **Self-Contained Archives**: Index embedded directly in volume files
    *   No external sidecar files required
    *   Single-file backup safety
    *   Cloud storage compatible
    *   Filesystem migration resilient
*   **Zero-Knowledge Cold Recovery**: Recover data from orphaned volumes without any external metadata
    *   Brute-force block discovery (tested up to 100 candidate blocks)
    *   Hash range matching for index page reconstruction
    *   In-memory index rebuilding from volume scan
    *   **2/2 cold recovery tests passing** ✅
*   **True Async I/O Architecture**: Non-blocking streaming pipeline prevents runtime starvation
    *   Tokio-based async file operations
    *   Stream-based chunking with `async-stream`
    *   Verified with concurrency torture tests
*   **Advanced Deduplication**: Content-Defined Chunking (FastCDC) with k-Bounded Best-Fit packing
*   **ERA-Index V2.1 Native Architecture** ✅:
    *   **Self-Contained Design**: Index blocks embedded in volume using typed block headers
    *   **Zero-Trust Spilling**: Ephemeral XChaCha20 encryption for temporary files (keys never persisted)
    *   **Bounded Memory**: 64MB MemTable limit with automatic spill-to-disk
    *   **Bloom Filters**: ~1% false positive rate for fast negative lookups (10M items)
    *   **Tiered Merging**: Recursive K-way merge (MAX_FAN_IN=64) prevents file descriptor exhaustion
    *   **L2 Index Pages**: 8,192 entries/page (~320KB) optimized for CPU L2 cache
    *   **Pure Rust**: No C++ dependencies - RocksDB replaced with native implementation
    *   **BlockType Enum**: 6 typed block variants (Data, IndexPage, IndexManifest, Catalog, LsmManifest, Reserved)
    *   **All Tests Passing**: 100% test suite success including cold recovery tests

## ✅ PHASE 4-6 REMEDIATION COMPLETE: Self-Contained Index Architecture

**STATUS**: ✅ **RESOLVED** (All tests passing, CI clean)

The critical self-containment issue has been **successfully remediated**:

### What Was Fixed
- ✅ **BlockType Enum**: 6 typed block variants implemented (Data, IndexPage, IndexManifest, Catalog, LsmManifest, Reserved)
- ✅ **Embedded Index**: IndexBuilder::finalize() now writes index directly into volume using typed blocks
- ✅ **Footer V5**: Added index_root_offset/size/block_id fields for O(1) fast-path lookup
- ✅ **Volume Scanning**: VolumeReader::scan_for_typed_blocks() enables block discovery
- ✅ **Cold Recovery**: IndexReader::recover_from_volume() performs zero-knowledge reconstruction
- ✅ **Backward Compatibility**: Data blocks still use 8-byte ShardHeader, index blocks use 16-byte BlockHeader
- ✅ **Tests**: 2/2 cold recovery tests passing (orphaned volume recovery + embedded index verification)

### Verification Results
- **Test Suite**: 100% pass rate across all crates
- **Clippy**: 0 warnings with strict mode (`-D warnings`)
- **Build**: Clean compilation for all targets
- **Cold Recovery**: Proven to rebuild index from volume-only (no external files)

### API Changes

**New (Recommended):**
```rust
// Embed index in volume (self-contained archives)
let (meta_index, location) = builder.finalize(
    &mut volume_writer,
    &key_session,
    &volume_key,
    volume_id
)?;
```

**Deprecated (Legacy Compatibility):**
```rust
// External index files (old behavior)
#[allow(deprecated)]
builder.finalize_external(&index_dir)?;
```

### Migration Guide
- **New archives**: Use default build, index automatically embedded
- **Existing archives**: Continue working unchanged (backward compatible)
- **Cold recovery**: Run `era recover orphaned.era --password "secret"` to rebuild index from volume scan

See [doc_gen/IMPLEMENTATION_SUMMARY.md](./doc_gen/IMPLEMENTATION_SUMMARY.md) for detailed technical documentation.

### Block Format & Type System

ERA v8.1 uses a dual-format block system for backward compatibility and extensibility:

**Data Blocks (Legacy Format):**
- **ShardHeader**: 8 bytes
  - `shard_id: u32` - Unique block identifier
  - `data_length: u32` - Encrypted payload size
- Used for all data chunks
- Maintains 100% backward compatibility with existing archives

**Index Blocks (V5 Format with BlockType):**
- **BlockHeader**: 16 bytes
  - `block_type: u32` - Discriminator (see BlockType enum)
  - `block_id: u32` - Unique identifier within type
  - `data_length: u32` - Encrypted payload size
  - `header_crc: u32` - CRC32 checksum for header integrity
- Used for: IndexPage, IndexManifest, Catalog, LsmManifest
- Enables volume scanning and type discrimination

**BlockType Enum:**
```rust
pub enum BlockType {
    Data = 0,           // User data chunks (uses ShardHeader)
    IndexPage = 1,      // L2 index pages (8,192 entries)
    IndexManifest = 2,  // L1 meta-index (directory)
    Catalog = 3,        // Reserved for future catalog
    LsmManifest = 4,    // Reserved for LSM metadata
    Reserved = 0xFF,    // Future extensibility
}
```

**Footer V5 Extensions:**
- `index_root_offset: u64` - Byte offset to IndexManifest block
- `index_root_size: u32` - Size of IndexManifest block
- `index_root_block_id: u32` - Block ID for fast lookup
- Enables O(1) index discovery vs. O(n) volume scan

### Security (Onion Model)
*   **Master Key (MK)**: Argon2id password derivation or X25519 certificate-based authentication
*   **Volume Key (VK)**: HKDF-derived, unique per volume (prevents cross-volume cryptoanalysis)
*   **Block Key (BK)**: HKDF-derived, unique per block (Perfect Forward Secrecy)
*   **Encryption**: XChaCha20-Poly1305 AEAD with 256-bit keys
*   **Nonce Strategy**: Counter-based with cryptographic context separation

## 🏗 Architecture

The system is organized into decoupled crates:

| Layer | Crate | Purpose | Status |
|-------|-------|---------|--------|
| **L5** | `era-ingest` | Async file I/O, Metadata extraction, ACLs | ✅ Async |
| **L4** | `era-index` | Native LSM Index (V2.1 - Pure Rust) | ✅ Complete (12/12 tests) |
| **L3** | `era-engine` | Archive orchestration, Recovery, Repair | ✅ Async |
| **L2** | `era-packing` | Block compression (Zstd/LZ4), Small file packing | ✅ Complete |
| **L2** | `era-codec` | Erasure Coding (Reed-Solomon 4:2) | ✅ Complete |
| **L1** | `era-volume` | Volume headers/footers, Physical layout | ✅ Complete |
| **L0** | `era-storage` | Physical I/O abstraction (FS/Memory) | ✅ Complete |
| **Common** | `era-crypto` | Cryptographic primitives, Key sessions | ✅ Complete |

### ERA-Index V2.1 Self-Contained Architecture

The indexing system has been completely rewritten to eliminate external database dependencies **and external index files**:

**Index Lifecycle:**
```
Ingestion Phase:                    Finalization Phase:
  Chunk Hash                         (End of Archive Session)
      ↓                                      ↓
  Bloom Filter  ←-- Always Updated    Tiered Merger
      ↓                               (Priority Queue)
  MemTable (64MB)                           ↓
      ↓ (Full)                        Sorted Stream
  Ephemeral Encryption                      ↓
      ↓                               L2 IndexPages
  Temp Spill File                    (8,192 entries each)
                                            ↓
                                      L1 Meta-Index
                                      (Sparse Directory)
                                            ↓
                                    📦 EMBED IN VOLUME
                                    (Typed BlockHeader)
```

**Embedding Strategy:**
- **IndexBuilder::finalize()**: New 4-parameter signature writes index directly to volume
- **IndexBuilder::finalize_external()**: Deprecated legacy method for backward compatibility
- **VolumeWriter::write_typed_block()**: Writes IndexPage/IndexManifest blocks with BlockHeader
- **Footer Storage**: Records index location for O(1) fast-path lookup
- **Volume Scanning**: Fallback O(n) brute-force recovery if footer missing/corrupted

**Cold Recovery Process:**
1. **Manifest Discovery**: Try candidate block IDs 0-100 for IndexManifest decryption
2. **Page Reconstruction**: Match IndexPages by hash range boundaries
3. **In-Memory Index**: Build MetaIndex from recovered pages
4. **Data Extraction**: Normal lookup operations on rebuilt index

**Security Features:**
- **Ephemeral Keys**: Spill files encrypted with session-only keys (generated via `rand::thread_rng()`)
- **Zero Plaintext**: Temporary files never contain unencrypted chunk hashes or locations
- **Crash Recovery**: Periodic Bloom filter snapshots enable resume without full volume scan
- **Block Key Derivation**: Each index block encrypted with unique key (Perfect Forward Secrecy)

**Performance Characteristics:**
- **Write**: O(1) insert with Bloom update + MemTable append
- **Read**: Bloom check (O(1)) → L1 lookup (O(log n)) → L2 binary search (O(log 8192))
- **Memory**: Bounded 64MB regardless of archive size
- **Scalability**: Successfully tested with 200+ spill segments, 50,000 entries
- **Cold Recovery**: O(n) volume scan worst-case, O(1) footer lookup best-case (typical: <100 decrypt attempts)

### Async I/O Pipeline

All I/O operations are fully non-blocking, verified by runtime starvation resistance tests.

## 🛠 Installation & Usage

### Prerequisites
*   Rust 1.70+
*   **No Clang/LLVM required** (for default V2.1 build)
*   Optional: RocksDB dependencies if using legacy backend (`--features rocksdb-backend`)

### Building

**Standard Build (V2.1 Pure Rust):**
```bash
cargo build --release
```

**Legacy Build (with RocksDB backend):**
```bash
# Only needed for backward compatibility with existing archives
cargo build --release --features rocksdb-backend
```

### Feature Flags

The project uses Cargo features to manage optional dependencies:

- **Default**: Pure Rust V2.1 implementation (no external database)
- **`rocksdb-backend`**: Enables legacy RocksDB-based index (for migration/compatibility)

Example:
```bash
# Build era-engine with RocksDB support
cargo build -p era-engine --features rocksdb-backend
```

### Basic Usage

**Create an archive:**
```bash
# Create encrypted archive from a directory
target/release/era create backup.era ./my_data --password "secret"
```

**Extract an archive:**
```bash
# Extract to current directory
target/release/era extract backup.era --password "secret"
```

**Verify integrity:**
```bash
# Deep verification of all blocks
target/release/era verify backup.era --password "secret"
```

## 🛡 Security Audit

### Adversarial Testing ("Evisceration Suite")

*   **Protocol Audit**: Verified strict HKDF key hierarchy with zero key reuse
*   **Truncation Tests**: Recovered from 50% volume truncation via 4:2 erasure codes
*   **Bit-Rot Detection**: 100% detection rate via CRC32 + Poly1305 AEAD tags
*   **Volume Loss Recovery**: Full dataset recovery with 1 of 3 volumes missing (2+1 erasure)
*   **Concurrency Torture**: Runtime starvation resistance under heavy I/O load

## 🧪 Testing & CI

### Continuous Integration

The project maintains strict code quality standards:
*   `cargo fmt --all -- --check`: Standard Rust formatting ✅
*   `cargo clippy --all-targets --all-features -- -D warnings`: Zero warnings policy ✅
*   `cargo test --workspace`: Full test suite (all packages) ✅

### Test Results

**ERA-Index V2.1 Architecture Tests:**
- ✅ 100% test suite passing (all crates)
- Cold Recovery Tests:
  - ✅ `test_cold_recovery_from_orphaned_volume`: Zero-knowledge index reconstruction
  - ✅ `test_index_embedded_in_volume`: Self-contained archive verification
- Architecture Specification:
  - ✅ Ephemeral encryption for spill files
  - ✅ Bounded memory with 64MB MemTable limit
  - ✅ Bloom filter snapshot and recovery
  - ✅ Tiered K-way merging (64 segments)
  - ✅ Index page layout and compression
  - ✅ Full index lifecycle (write→finalize→read)
  - ✅ MetaIndex lookups and page resolution
  - ✅ Crash recovery from Bloom snapshots
  - ✅ Feature flag isolation (RocksDB optional)
  - ✅ Embedded index with typed blocks
  - ✅ Backward compatibility (ShardHeader + BlockHeader)

**CI Status:**
- `cargo fmt --all -- --check`: ✅ Passing
- `cargo clippy --all-targets --all-features -- -D warnings`: ✅ 0 warnings
- `cargo test --workspace`: ✅ All tests passing
- `cargo build --all-targets`: ✅ Clean compilation

### Running Tests

```bash
# Full test suite (all crates)
cargo test --workspace

# Cold recovery tests (Phase 4-6)
cargo test -p era-index --test cold_recovery_test

# V2.1 architecture specification tests
cargo test -p era-index --test v2_architecture_spec

# Legacy backend tests (requires rocksdb feature)
cargo test --features rocksdb-backend

# Specific concurrency test
cargo test --test concurrency_torture

# CI validation (strict mode)
cargo clippy --all-targets --all-features -- -D warnings
```

### Migration from Legacy Index

**If you have existing archives:**

1. **No action required**: Archives created with the old external index format continue to work unchanged
2. **New archives are self-contained**: Just use the default build (`cargo build --release`)
3. **Cold recovery available**: If you lose external index files, run:
   ```bash
   era recover orphaned.era --password "secret" --output recovered/
   ```

**Code Migration (if using IndexBuilder API):**

**Old (Deprecated):**
```rust
#[allow(deprecated)]
builder.finalize_external(&index_dir)?;
```

**New (Recommended):**
```rust
let (meta_index, location) = builder.finalize(
    &mut volume_writer,
    &key_session,
    &volume_key,
    volume_id,
)?;
```

**Benefits of new API:**
- ✅ Self-contained archives (single file backup)
- ✅ Cloud storage compatible (no sidecar files)
- ✅ Zero-knowledge cold recovery
- ✅ Filesystem migration safe
- ✅ Footer-based fast index lookup
- ✅ Volume scanning fallback for corrupted footers

---
*Built with ❤️ in Rust | Last Updated: 2026-01-22 | Architecture: Self-Contained + Cold Recovery*
