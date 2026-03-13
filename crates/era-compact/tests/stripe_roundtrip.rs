use era_common::BlockId;
use era_compact::CompactShardRecordHeader;

#[test]
fn shard_record_roundtrip_and_crc_validation() {
    let payload = b"ciphertext-shard-bytes".to_vec();
    let header = CompactShardRecordHeader::new(
        BlockId::new(42),
        3,
        1,
        4,
        2,
        1024,
        payload.len() as u32,
        &payload,
    )
    .expect("valid shard header");

    let bytes = header.to_bytes().expect("serialize shard header");
    let parsed = CompactShardRecordHeader::from_bytes(&bytes).expect("parse shard header");

    parsed
        .validate_payload_crc(&payload)
        .expect("crc must validate for original payload");

    let mut tampered = payload.clone();
    tampered[0] ^= 0xFF;
    let err = parsed
        .validate_payload_crc(&tampered)
        .expect_err("crc must reject tampered payload");
    assert!(format!("{err}").contains("CRC"));
}
