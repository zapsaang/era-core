use era_common::{proto, ArchiveConfig, EraError, MatrixDistributionConfig};
use prost::Message;

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

#[test]
fn matrix_generation_width_survives_header_encoding() {
    for width in [1, 3, 6, usize::from(u16::MAX)] {
        let mut config = ArchiveConfig::default();
        config.distribution.target_volumes = width;
        let header = proto::SuperHeader {
            config: Some(config.into()),
            ..Default::default()
        };
        let encoded = header.encode_length_delimited_to_vec();
        let decoded = proto::SuperHeader::decode_length_delimited(encoded.as_slice()).unwrap();
        let config = ArchiveConfig::try_from(decoded.config.unwrap()).unwrap();

        assert_eq!(config.distribution.target_volumes, width);
    }
}

#[test]
fn legacy_matrix_config_uses_default_width_for_absent_or_zero_field() {
    for encoded in [&[][..], &[0x10, 0][..]] {
        let mut config = proto::ArchiveConfig::from(ArchiveConfig::default());
        config.distribution = Some(proto::MatrixDistributionConfig::decode(encoded).unwrap());
        let config = ArchiveConfig::try_from(config).unwrap();

        assert_eq!(
            config.distribution.target_volumes,
            MatrixDistributionConfig::default().target_volumes
        );
    }
}

#[test]
fn matrix_generation_width_outside_volume_count_range_is_rejected() {
    for encoded in [
        &[0x10, 0x80, 0x80, 0x04][..],
        &[0x10, 0x83, 0x80, 0x80, 0x80, 0x10][..],
    ] {
        let mut config = proto::ArchiveConfig::from(ArchiveConfig::default());
        config.distribution = Some(proto::MatrixDistributionConfig::decode(encoded).unwrap());

        assert!(matches!(
            ArchiveConfig::try_from(config),
            Err(EraError::CorruptedHeader(_))
        ));
    }
}
