# Index Source

V2.1 embedded deduplication index. L3 — depends on era-storage and era-volume for in-volume persistence.

## FILES

| File | Purpose |
|------|---------|
| `lib.rs` | Crate facade and public re-exports for builder / reader / schema types. |
| `chunk_index.rs` | Redb-backed index orchestrator. Coordinates build/finalize/lookup flows across `IndexBuilder` and `IndexReader`. |
| `builder.rs` | IndexBuilder — constructs index from chunk hashes |
| `reader.rs` | IndexReader — queries index for dedup decisions |
| `store.rs` | Storage layer — persists index as encrypted blocks in-volume |
| `bloom_serde.rs` | Bloom filter serialization (rkyv zero-copy) |
| `schema.rs` | Database schema (Redb 2.1 ACID B-tree) |

## ARCHITECTURE

- **Bloom filter**: Fast negative lookups (>99% accuracy), right-sized per archive
- **L1 MetaIndex**: Compact page directory for range queries
- **L2 IndexPages**: Full chunk hash → location mappings
- **Self-contained**: Embedded in volume as typed encrypted blocks (no external state)
- **Cold recovery**: Can rebuild index from volume headers alone

## KEY FEATURES

- **Redb 2.1**: ACID B-tree database for durable index operations
- **Zero-copy**: rkyv serialization for IndexEntry, IndexPage, MetaIndex
- **Bloom false negative guarantee**: Bloom filter NEVER produces false negatives (audit-verified)

## TEST

```bash
cargo test -p era-index
cargo test -p era-index --test index_persistence_audit  # 30 V2.1 audit tests
cargo test -p era-index --test adversarial_audit_v9     # behavioral security tests
```
