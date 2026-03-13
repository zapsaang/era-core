use era_common::proto;

#[test]
fn compact_proto_exposes_explicit_threshold_field() {
    let header = proto::CompactSuperHeader {
        access_policy: proto::AccessPolicy::Threshold.into(),
        threshold: 2,
        ..Default::default()
    };

    assert_eq!(header.access_policy, proto::AccessPolicy::Threshold as i32);
    assert_eq!(header.threshold, 2);
}
