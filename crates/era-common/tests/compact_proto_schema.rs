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

#[test]
fn compact_proto_exposes_hybrid_kem_recipient_type_value() {
    // Lock the numeric value of the HybridKem recipient type so future
    // schema changes cannot accidentally renumber existing variants.
    assert_eq!(
        proto::recipient_slot::RecipientType::HybridKem as i32,
        3,
        "RECIPIENT_TYPE_HYBRID_KEM must remain 3 for backward compatibility"
    );
}
