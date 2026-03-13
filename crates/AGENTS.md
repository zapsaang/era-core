# Crate Architecture and Navigation

9 library crates + 1 compact bundle crate forming a strict L0-L4 pipeline. Each layer only depends on layers below it.

## Crate Map

### Foundation (L0)
- **era-common**: EraError, Result, protobuf codegen, config types. Bottom of stack — everything depends on this.
- **era-crypto**: XChaCha20-Poly1305, Kyber-768, HKDF, Argon2id, SecureBuffer, Shamir. All key material lives here.

### Abstraction (L1)
- **era-storage**: `StorageBackend` trait + `LocalStorageBackend`, `MemoryStorageBackend`. All I/O is async.

### Transformation (L2)
- **era-codec**: `Compressor` trait (Zstd/LZ4/NoCompressor) + Reed-Solomon erasure coding.
- **era-volume**: Volume format v8.1. SuperHeader (4096B), Footer (128B), VolumeReader/Writer, MultiVolume, VolumePool.
- **era-compact**: Compact read-only bundle format (.erac). CompactBundleWriter/Reader, RS striping, multi-volume distribution. Sole consumer: era-engine.

### Logic (L3)
- **era-packing**: k-Bounded Best-Fit MacroBlock packing. StagingPool, resilient AEAD with 4-tier corruption detection.
- **era-ingest**: FastCDC chunking (16KB-64KB-256KB default), FileReader, DirectoryScanner, ACL handling.
- **era-index**: V2.1 embedded dedup index. Redb 2.1 ACID B-tree, Bloom filters, L1/L2 tiered pages, cold recovery.

### Orchestration (L4)
- **era-engine**: Async pipeline. ArchiveWriter, ArchiveReader, RecoveryManager, repair, 4 BlockIterator variants.

## Actual Dependency Graph

```
era-engine → era-{common,crypto,codec,storage,volume,packing,ingest,index,compact}
era-compact → era-{common,codec,volume}
era-index  → era-{common,crypto,codec,storage,volume}  # needs VolumeWriter for in-volume persistence
era-packing → era-{common,crypto,codec}
era-ingest → era-{common,crypto,codec}
era-volume → era-{common,storage}
era-codec  → era-common
era-storage → era-common
era-crypto → era-common
```

## Navigation Guide

### Changing the Disk Format
1. Update protobuf definitions in `era-common/proto/`.
2. Modify Header or Footer types in `era-volume/src/header.rs` or `footer.rs`.
3. Update era-engine writer/reader to handle the new format version.

### Modifying Security Patterns
1. Implement changes in era-crypto.
2. Update era-volume if key wrapping or AAD binding changes.
3. Verify with adversarial audit tests in `era-engine/tests/` (6 audit suites).

### Optimizing Throughput
- Compression: `era-codec/src/compression.rs`
- Chunking: `era-ingest/src/chunker*.rs` (3 implementations)
- Pipeline: `era-engine/src/writer.rs` (async orchestration)
- Erasure: `era-codec/src/erasure.rs`

See root `AGENTS.md` for workspace-wide rules and anti-patterns.
