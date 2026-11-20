use era_common::{ArchiveManifest, EraError};
use prost::Message;

#[derive(Clone, PartialEq, Message)]
struct HeaderDigestTable {
    #[prost(bytes = "vec", repeated, tag = "8")]
    digests: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct LegacyHeaderDigest {
    #[prost(bytes = "vec", optional, tag = "7")]
    digest: Option<Vec<u8>>,
}

#[test]
fn manifest_preserves_legacy_local_digest_and_sequence_order() {
    let manifest = ArchiveManifest::new(1, 5, 5000, [0xAA; 32], [0xBB; 32], vec![5000, 6000]);
    let table = [[2; 32], [1; 32]];

    let legacy = manifest.to_bytes_with_header_digest(table[1]);
    let (decoded, digests) = ArchiveManifest::from_bytes_with_header_digests(&legacy).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(digests.local, Some(table[1]));
    assert!(digests.by_sequence.is_empty());

    let extended = manifest.to_bytes_with_header_digests(1, &table).unwrap();
    let (decoded, digests) = ArchiveManifest::from_bytes_with_header_digests(&extended).unwrap();
    assert_eq!(decoded, manifest);
    assert_eq!(digests.local, Some(table[1]));
    assert_eq!(digests.by_sequence, table);
    assert_eq!(
        LegacyHeaderDigest::decode(extended.as_slice())
            .unwrap()
            .digest,
        Some(table[1].to_vec())
    );
    assert_eq!(extended.len() - legacy.len(), 34 * table.len());
}

#[test]
fn manifest_writer_rejects_incomplete_tables_and_unknown_replica_sequences() {
    for (ends, digests, sequence) in [(0, 0, 0), (2, 1, 0), (1, 2, 0), (1, 1, 1), (1025, 1025, 0)] {
        let manifest = ArchiveManifest::new(1, 5, 5000, [0xAA; 32], [0xBB; 32], vec![5000; ends]);
        assert!(matches!(
            manifest.to_bytes_with_header_digests(sequence, &vec![[1; 32]; digests]),
            Err(EraError::Serialization(_)),
        ));
    }
}

#[test]
fn manifest_rejects_malformed_header_digest_tables() {
    for (case, ends, digests) in [
        ("short digest", 2, vec![vec![1; 31], vec![2; 32]]),
        ("empty digest", 1, vec![vec![]]),
        ("long digest", 1, vec![vec![1; 33]]),
        ("missing entry", 2, vec![vec![1; 32]]),
        ("extra entry", 1, vec![vec![1; 32]; 2]),
        ("above the volume limit", 1, vec![vec![1; 32]; 1025]),
    ] {
        let manifest = ArchiveManifest::new(1, 5, 5000, [0xAA; 32], [0xBB; 32], vec![5000; ends]);
        let mut bytes = manifest.to_bytes_with_header_digest([1; 32]);
        HeaderDigestTable { digests }.encode(&mut bytes).unwrap();

        assert!(
            matches!(
                ArchiveManifest::from_bytes(&bytes),
                Err(EraError::Deserialization(_))
            ),
            "accepted {case}"
        );
    }
}
