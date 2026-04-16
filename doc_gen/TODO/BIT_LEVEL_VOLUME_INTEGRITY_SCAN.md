# Bit-Level Volume Integrity Scan

**Status:** Planned  
**Priority:** High  
**Area:** Archive Integrity, Verification, Repair  
**Created:** 2026-04-16

---

## Objective

Implement a comprehensive **bit-level integrity scan** across **all volumes** of an ERA archive. A great archival system must not only recover from corruption but also **detect, report, and surface every single bit-level anomaly** — whether it resides in data shards, parity shards, headers, footers, catalogs, embedded indexes, or any other structural block.

This capability elevates ERA from "best-effort recovery" to **defense-in-depth archival resilience**.

---

## Motivation

During the P0.3 repair investigation (2026-04-16), we discovered that a corruption at offset 5000 on volume 0 silently damaged the **catalog block**. While the archive remained logically recoverable (thanks to catalog replication across volumes), neither `verify` nor `repair` explicitly reported that **volume 0's catalog replica was corrupted**.

This gap means:
- Users are unaware of latent physical degradation on specific volumes.
- Silent bit-rot in non-data regions (headers, footers, catalog replicas, index pages) can accumulate undetected.
- The verification surface is currently **logical** (can we read all chunks?) rather than **physical** (is every byte on every volume exactly what it should be?).

A bit-level scan would close this gap and provide actionable intelligence for archive maintenance.

---

## Desired Behavior

### `era verify --physical` (or similar flag)

When invoked with a physical-scan mode, the CLI should:

1. **Scan every byte of every volume file** against the expected archive layout.
2. **Validate all structural regions:**
   - SuperHeader (magic, version, archive_id)
   - Backup/Primary Footers (checksums, offsets)
   - Backup Header
   - Data Region blocks (BlockHeader CRC, shard CRC)
   - Catalog blocks (all replicas across volumes)
   - Embedded index blocks (Bloom, L1 MetaIndex, L2 IndexPages)
   - Checkpoints / WAL blocks
3. **Report every anomaly with precise coordinates:**
   - Volume sequence / file path
   - Byte offset range
   - Expected vs. actual content (where applicable)
   - Severity: `critical` (unrecoverable), `degraded` (RS-recoverable), `cosmetic` (redundant replica damaged)
4. **Cross-check redundant replicas:**
   - Compare catalog replicas across volumes and flag mismatches.
   - Compare footer replicas (primary vs. backup) and flag discrepancies.
5. **Produce a machine-readable report** (optional JSON) suitable for monitoring integrations.

### Example Output

```
Physical integrity scan: 6 volumes, 1.2 GB total

[CRITICAL]  Vol 0  offset 0x1388  BlockHeader CRC mismatch
             Expected: 0xA3B4C5D6  Actual: 0x11223344
             Block: catalog_block_0  (recoverable via catalog replica on Vol 1)

[DEGRADED]  Vol 2  offset 0x50000  Shard CRC mismatch (data shard 1)
             Expected: 0xDEADBEEF  Actual: 0xCAFEBABE
             Block: 42  Shard: 1  (recoverable via RS with 4+2 config)

[COSMETIC]  Vol 4  offset 0x200000  Parity shard padding mismatch
             Expected: 0x00 padding  Actual: non-zero bytes detected
             Block: 128  Shard: 5  (does not affect data integrity)

Scan complete: 3 anomalies found, 0 unrecoverable.
```

---

## Technical Considerations

### Volume Layer Contract

The scan must deeply understand the v8.1 volume format:
- `era-volume/src/header.rs` — SuperHeader layout
- `era-volume/src/footer.rs` — Footer layout, checksum verification
- `era-volume/src/reader.rs` — `read_typed_block`, `read_erasure_shards`
- `era-engine/src/block_iter.rs` — Block iteration boundaries
- `era-engine/src/reader.rs` — Catalog loading, index recovery
- `era-engine/src/checkpoint.rs` — Checkpoint block types

### Catalog & Index Redundancy

- Catalog is replicated to all volumes via `VolumeStage::write_catalog_blocks_to_all()`.
- V2.1 embedded index may be present in the footer; its pages are also typed blocks within volumes.
- The scanner should hash/compare all readable catalog replicas and report mismatches.

### Performance

- For petabyte archives, a full byte-by-byte scan is expensive.
- Should support `--sample-rate N` to scan every Nth block, or `--regions headers|data|catalog|index` to limit scope.
- CPU-heavy hash/CRC verification should use `spawn_blocking`.

### Security

- Must never log key material.
- CRC mismatches must not trigger unbounded memory allocation.
- Maliciously crafted corruption should be reported, not panic.

---

## Acceptance Criteria

- [ ] A new CLI flag (e.g., `--physical` or a new subcommand `era scan`) triggers bit-level scanning.
- [ ] All volume files are opened and validated structurally.
- [ ] Every CRC mismatch, magic byte corruption, footer checksum failure, and replica mismatch is reported.
- [ ] Severity classification is accurate and actionable.
- [ ] The scan passes the adversarial audit suite with injected corruptions at known offsets.
- [ ] Machine-readable output format is supported.
- [ ] Documentation (`ERA_CLI_USER_GUIDE.md`) is updated.

---

## Related Work

- `REPAIR_CREDIBILITY_FIX_REPORT_2026-04-16_UPDATED.md` — P0.3 catalog corruption fix
- `era_volume_audit_master.md` — Volume format v8.1 specification
- `crates/era-engine/src/reader.rs` — `load_catalog()` fallback logic
- `crates/era-volume/src/reader.rs` — `read_typed_block`, footer validation
