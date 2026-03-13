use era_common::BlockId;
use era_compact::{CompactDirectory, CompactDirectoryEntry, CompactRegionKind};

fn entry(block_id: u64, offset: u64, span: u64) -> CompactDirectoryEntry {
    CompactDirectoryEntry {
        block_id: BlockId::new(block_id),
        block_type: 1,
        region_kind: CompactRegionKind::ReplicatedTypedBlock,
        offset,
        span,
        stripe_ordinal: 0,
    }
}

#[test]
fn directory_rejects_duplicate_block_ids_and_overlaps() {
    let dup = CompactDirectory::new(vec![entry(100, 0, 64), entry(100, 64, 64)]);
    assert!(dup.is_err(), "duplicate block ids must be rejected");

    let overlap = CompactDirectory::new(vec![entry(101, 0, 64), entry(102, 32, 64)]);
    assert!(overlap.is_err(), "overlapping spans must be rejected");

    let ok = CompactDirectory::new(vec![entry(103, 0, 64), entry(104, 64, 64)])
        .expect("non-overlapping unique ids must pass");
    assert_eq!(ok.entries().len(), 2);
}
