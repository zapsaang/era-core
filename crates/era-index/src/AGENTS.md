# Index Source

V2.1 embedded deduplication index. L3. Depends on era-common, era-crypto, era-storage, era-volume. Pages hold `ENTRIES_PER_PAGE = 8192` entries.

## FILES

| File | LOC | Role |
|------|----:|------|
| `lib.rs` | 652 | Crate facade. Anomaly: inlines `IndexEntry`/`IndexPage`/`MetaIndex`/`PagePointer` type definitions instead of re-exporting from builder/reader. Flag if moving them. |
| `reader.rs` | 1282 | IndexReader — Bloom + L1 MetaIndex + L2 page lookup, legacy fallback, cold recovery from volume (`recover_from_volume`) |
| `store.rs` | 780 | Persists index as encrypted typed blocks in-volume |
| `builder.rs` | 596 | IndexBuilder — constructs index from chunk hashes |
| `chunk_index.rs` | 367 | ChunkIndex — redb-backed orchestrator across builder/reader/store |
| `bloom_serde.rs` | 238 | Bloom filter serialization (rkyv zero-copy) |
| `schema.rs` | 13 | Database schema (redb tables) |

## ARCHITECTURE

- **Bloom filter**: fast negative lookups, right-sized per archive
- **L1 MetaIndex**: compact page directory for range queries
- **L2 IndexPages**: full chunk hash → location mappings
- **Self-contained**: embedded in volume as typed encrypted blocks, no external state
- **Cold recovery**: reads footer index location when present (fast path); otherwise scans the data region for `BlockType::IndexManifest` then `BlockType::IndexPage` blocks, decrypting with candidate `block_id` values around the page count. See `reader.rs::recover_from_volume`.

## RULES

- **Bloom false-negative guarantee**: the Bloom filter NEVER produces false negatives; a negative answer must always short-circuit to "not present" (audit-verified).
- **Cold recovery is contract**: recovery from volume alone must work; it is not an optional optimization.

## KEY FEATURES

- **Redb 3.1.1**: ACID B-tree for durable index operations
- **Zero-copy**: rkyv serialization for `IndexEntry`, `IndexPage`, `MetaIndex`

## TEST

```bash
cargo test -p era-index
cargo test -p era-index --test index_persistence_audit
```
