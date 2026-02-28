//! Property-based tests for era-volume format invariants.
//!
//! Uses proptest to generate random valid inputs and verify roundtrip
//! invariants, postconditions, and domain constraints that hand-written
//! tests cannot exhaustively cover.

use era_common::{ArchiveId, VolumeId};
use era_volume::{
    AccessPolicy, EncryptedVolumeKey, Footer, KeyWrapAlgorithm, RecipientSlot, RecipientType,
    SuperHeader, FOOTER_MAGIC, FOOTER_SIZE, FOOTER_VERSION, HEADER_SIZE, HEADER_VERSION, MAGIC,
};
use proptest::prelude::*;

// ──────────────────── Strategies ────────────────────

/// Generate a valid `data_end_offset`: either 0 or ≥ HEADER_SIZE + FOOTER_SIZE.
fn arb_data_end_offset() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        // Minimum valid: header (4096) + footer (128) = 4224 up to a reasonable upper bound
        ((HEADER_SIZE + FOOTER_SIZE) as u64..=u64::MAX / 2),
    ]
}

/// Generate a valid `Footer` with consistent cross-field invariants.
fn arb_footer() -> impl Strategy<Value = Footer> {
    (
        arb_data_end_offset(),
        any::<u32>(), // block_count
        any::<u64>(), // sequence_number
        any::<u32>(), // catalog_block_id
        any::<u32>(), // last_checkpoint_block_id
        any::<u32>(), // index_block_id
    )
        .prop_flat_map(|(data_end, block_count, seq, cat_bid, ckpt_bid, idx_bid)| {
            // Constrain catalog and index regions to fit within data_end
            let max_offset = if data_end == 0 {
                0u64
            } else {
                data_end.saturating_sub(1)
            };

            let catalog_strat: BoxedStrategy<(u64, u32)> = if data_end == 0 {
                Just((0u64, 0u32)).boxed()
            } else {
                prop_oneof![
                    Just((0u64, 0u32)),
                    (HEADER_SIZE as u64..=max_offset).prop_flat_map(move |off| {
                        let max_size =
                            u32::try_from(data_end.saturating_sub(off)).unwrap_or(u32::MAX);
                        (Just(off), 0u32..=max_size)
                    }),
                ]
                .boxed()
            };

            let index_strat: BoxedStrategy<(u64, u32)> = if data_end == 0 {
                Just((0u64, 0u32)).boxed()
            } else {
                prop_oneof![
                    Just((0u64, 0u32)),
                    (HEADER_SIZE as u64..=max_offset).prop_flat_map(move |off| {
                        let max_size =
                            u32::try_from(data_end.saturating_sub(off)).unwrap_or(u32::MAX);
                        (Just(off), 0u32..=max_size)
                    }),
                ]
                .boxed()
            };

            // backup_header_offset: 0 or any value
            let backup_strat = prop_oneof![Just(0u64), any::<u64>(),];

            // checkpoint offset: any u64
            let ckpt_strat = any::<u64>();

            (
                Just(data_end),
                Just(block_count),
                Just(seq),
                catalog_strat,
                Just(cat_bid),
                ckpt_strat,
                Just(ckpt_bid),
                index_strat,
                Just(idx_bid),
                backup_strat,
            )
        })
        .prop_map(
            |(
                data_end,
                block_count,
                seq,
                (cat_off, cat_size),
                cat_bid,
                ckpt_off,
                ckpt_bid,
                (idx_off, idx_size),
                idx_bid,
                backup_off,
            )| {
                Footer::builder(data_end, block_count, seq)
                    .catalog(cat_off, cat_size, cat_bid)
                    .checkpoint(ckpt_off, ckpt_bid)
                    .index(idx_off, idx_size, idx_bid)
                    .backup_header(backup_off)
                    .build()
            },
        )
}

/// Generate a valid `EncryptedVolumeKey`.
fn arb_evk() -> impl Strategy<Value = EncryptedVolumeKey> {
    // nonce: fixed 24 bytes, ciphertext: 16..=256 bytes (min is Poly1305 tag)
    (
        proptest::array::uniform24(any::<u8>()),
        proptest::collection::vec(any::<u8>(), 16..=256),
    )
        .prop_map(|(nonce, ciphertext)| {
            EncryptedVolumeKey::new(KeyWrapAlgorithm::XChaCha20Poly1305, nonce, ciphertext)
        })
}

/// Generate a valid `RecipientSlot`.
fn arb_recipient_slot() -> impl Strategy<Value = RecipientSlot> {
    (
        prop_oneof![
            Just(RecipientType::Argon2idPassword),
            Just(RecipientType::X25519PubKey),
            Just(RecipientType::Fido2Hmac),
        ],
        prop_oneof![
            Just(None::<[u8; 8]>),
            proptest::array::uniform8(any::<u8>()).prop_map(Some),
        ],
        proptest::collection::vec(any::<u8>(), 0..=128), // params
        proptest::collection::vec(any::<u8>(), 24..=256), // encrypted_master_key (min 24)
    )
        .prop_map(|(r_type, key_id, params, encrypted_master_key)| {
            RecipientSlot::new(r_type, key_id, params, encrypted_master_key)
        })
}

/// Generate a valid `AccessPolicy` consistent with the given recipient count.
fn arb_access_policy_for(num_recipients: usize) -> BoxedStrategy<AccessPolicy> {
    if num_recipients >= 2 {
        prop_oneof![
            Just(AccessPolicy::AnyOfN),
            (2u32..=num_recipients as u32).prop_map(AccessPolicy::Threshold),
        ]
        .boxed()
    } else {
        Just(AccessPolicy::AnyOfN).boxed()
    }
}

// ──────────────────── Footer Properties ────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// P1: Footer roundtrip — to_bytes → from_bytes preserves all fields.
    #[test]
    fn footer_roundtrip(ref footer in arb_footer()) {
        let bytes = footer.to_bytes().expect("valid footer should serialize");
        let restored = Footer::from_bytes(&bytes).expect("valid bytes should deserialize");
        prop_assert_eq!(footer, &restored);
    }

    /// P2: Footer is always exactly FOOTER_SIZE bytes.
    #[test]
    fn footer_size_invariant(ref footer in arb_footer()) {
        let bytes = footer.to_bytes().expect("valid footer should serialize");
        prop_assert_eq!(bytes.len(), FOOTER_SIZE);
    }

    /// P3: Footer magic is always FOOTER_MAGIC.
    #[test]
    fn footer_magic_invariant(ref footer in arb_footer()) {
        prop_assert_eq!(footer.magic(), &FOOTER_MAGIC);
    }

    /// P4: Footer version is always FOOTER_VERSION.
    #[test]
    fn footer_version_invariant(ref footer in arb_footer()) {
        prop_assert_eq!(footer.version(), FOOTER_VERSION);
    }

    /// P5: Footer checksum verification always passes for freshly constructed footers.
    #[test]
    fn footer_checksum_valid(ref footer in arb_footer()) {
        prop_assert!(footer.verify_checksum(), "freshly built footer must have valid checksum");
    }

    /// P6: Any single-bit mutation in the serialized footer bytes causes checksum
    ///     failure (except mutations to the checksum field itself which trivially match).
    #[test]
    fn footer_checksum_detects_mutation(
        ref footer in arb_footer(),
        byte_idx in 0usize..96,  // only mutate pre-checksum fields (first 96 bytes)
        bit_idx in 0u8..8,
    ) {
        let mut bytes = footer.to_bytes().expect("valid footer should serialize");
        // Flip one bit
        bytes[byte_idx] ^= 1 << bit_idx;
        // Deserialization should fail (checksum mismatch or field validation)
        prop_assert!(
            Footer::from_bytes(&bytes).is_err(),
            "single-bit mutation at byte {} bit {} should be detected",
            byte_idx,
            bit_idx,
        );
    }

    /// P7: FooterBuilder always produces a footer with correct magic and version.
    #[test]
    fn footer_builder_postconditions(
        data_end in arb_data_end_offset(),
        block_count in any::<u32>(),
        seq in any::<u64>(),
    ) {
        let footer = Footer::builder(data_end, block_count, seq).build();
        prop_assert_eq!(footer.magic(), &FOOTER_MAGIC);
        prop_assert_eq!(footer.version(), FOOTER_VERSION);
        prop_assert!(footer.verify_checksum());
    }
}

// ──────────────────── EncryptedVolumeKey Properties ────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// P8: EVK protobuf roundtrip — Into<proto> → TryFrom<proto> preserves all fields.
    #[test]
    fn evk_protobuf_roundtrip(ref evk in arb_evk()) {
        let proto_evk: era_common::proto::EncryptedVolumeKey = evk.clone().into();
        let restored = EncryptedVolumeKey::try_from(proto_evk)
            .expect("valid proto EVK should convert back");
        prop_assert_eq!(evk, &restored);
    }

    /// P9: EVK nonce is always exactly 24 bytes after roundtrip.
    #[test]
    fn evk_nonce_length_invariant(ref evk in arb_evk()) {
        let proto_evk: era_common::proto::EncryptedVolumeKey = evk.clone().into();
        let restored = EncryptedVolumeKey::try_from(proto_evk).unwrap();
        prop_assert_eq!(restored.nonce().len(), 24);
    }
}

// ──────────────────── RecipientSlot Properties ────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// P10: RecipientSlot protobuf roundtrip preserves all fields.
    #[test]
    fn recipient_slot_protobuf_roundtrip(ref slot in arb_recipient_slot()) {
        let proto_slot: era_common::proto::RecipientSlot = slot.clone().into();
        let restored = RecipientSlot::try_from(proto_slot)
            .expect("valid proto RecipientSlot should convert back");
        prop_assert_eq!(slot, &restored);
    }

    /// P11: RecipientSlot key_id is preserved through roundtrip (None → empty → None).
    #[test]
    fn recipient_slot_key_id_roundtrip(ref slot in arb_recipient_slot()) {
        let proto_slot: era_common::proto::RecipientSlot = slot.clone().into();
        let restored = RecipientSlot::try_from(proto_slot).unwrap();
        prop_assert_eq!(slot.key_id(), restored.key_id());
    }
}

// ──────────────────── SuperHeader Properties ────────────────────

/// Helper: construct a SuperHeader with given components (bypasses ::new() which
/// uses SystemTime::now and VolumeId::new).
#[allow(clippy::too_many_arguments)]
fn make_super_header(
    archive_id: ArchiveId,
    volume_id: VolumeId,
    volume_sequence: u16,
    total_volumes: u16,
    creation_time: i64,
    feature_flags: u64,
    recipients: Vec<RecipientSlot>,
    salt: [u8; 16],
    epoch_id: u32,
    evk: EncryptedVolumeKey,
    access_policy: AccessPolicy,
) -> SuperHeader {
    SuperHeader::new_for_testing(
        archive_id,
        volume_id,
        volume_sequence,
        total_volumes,
        creation_time,
        feature_flags,
        recipients,
        salt,
        epoch_id,
        evk,
        access_policy,
    )
}
/// Strategy for generating a valid SuperHeader (deterministic fields, no SystemTime).
fn arb_super_header() -> impl Strategy<Value = SuperHeader> {
    // First generate recipients so we can derive a valid access_policy
    proptest::collection::vec(arb_recipient_slot(), 1..=8)
        .prop_flat_map(|recipients| {
            let num = recipients.len();
            (
                proptest::array::uniform16(any::<u8>()), // archive_id bytes
                proptest::array::uniform16(any::<u8>()), // volume_id bytes
                // IS31-02: generate valid volume_sequence/total_volumes pairs
                prop_oneof![
                    // total_volumes == 0: sequence can be anything
                    (any::<u16>(), Just(0u16)),
                    // total_volumes > 0: sequence must be < total_volumes
                    (1u16..=1000).prop_flat_map(|tv| (0..tv, Just(tv))),
                ],
                0i64..=i64::MAX, // creation_time (positive)
                Just(0u64),      // feature_flags (FC39-01: no flags currently defined)
                Just(recipients),
                proptest::array::uniform16(any::<u8>()), // salt
                any::<u32>(),                            // epoch_id
                arb_evk(),
                arb_access_policy_for(num), // IS31-01: policy consistent with recipients
            )
        })
        .prop_map(
            |(
                aid_bytes,
                vid_bytes,
                (vol_seq, total_vols),
                ctime,
                fflags,
                recipients,
                salt,
                epoch_id,
                evk,
                policy,
            )| {
                make_super_header(
                    ArchiveId(uuid::Uuid::from_bytes(aid_bytes)),
                    VolumeId(uuid::Uuid::from_bytes(vid_bytes)),
                    vol_seq,
                    total_vols,
                    ctime,
                    fflags,
                    recipients,
                    salt,
                    epoch_id,
                    evk,
                    policy,
                )
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// P12: SuperHeader roundtrip — to_bytes → from_bytes preserves all non-config fields.
    #[test]
    fn super_header_roundtrip(ref header in arb_super_header()) {
        let bytes = header.to_bytes().expect("valid header should serialize");
        prop_assert_eq!(bytes.len(), HEADER_SIZE);

        let restored = SuperHeader::from_bytes(&bytes).expect("valid bytes should deserialize");

        // Compare all fields individually (SuperHeader lacks PartialEq due to ArchiveConfig)
        prop_assert_eq!(restored.magic(), header.magic());
        prop_assert_eq!(restored.version(), header.version());
        prop_assert_eq!(restored.volume_id(), header.volume_id());
        prop_assert_eq!(restored.archive_id(), header.archive_id());
        prop_assert_eq!(restored.volume_sequence(), header.volume_sequence());
        prop_assert_eq!(restored.total_volumes(), header.total_volumes());
        prop_assert_eq!(restored.creation_time(), header.creation_time());
        prop_assert_eq!(restored.feature_flags(), header.feature_flags());
        prop_assert_eq!(restored.salt(), header.salt());
        prop_assert_eq!(restored.epoch_id(), header.epoch_id());
        prop_assert_eq!(restored.encrypted_volume_key(), header.encrypted_volume_key());
        prop_assert_eq!(restored.access_policy(), header.access_policy());
        prop_assert_eq!(restored.recipients().len(), header.recipients().len());
        for (orig, rest) in header.recipients().iter().zip(restored.recipients().iter()) {
            prop_assert_eq!(orig, rest);
        }
    }

    /// P13: SuperHeader always serializes to exactly HEADER_SIZE bytes.
    #[test]
    fn super_header_size_invariant(ref header in arb_super_header()) {
        let bytes = header.to_bytes().expect("valid header should serialize");
        prop_assert_eq!(bytes.len(), HEADER_SIZE);
    }

    /// P14: SuperHeader magic is always correct after roundtrip.
    #[test]
    fn super_header_magic_preserved(ref header in arb_super_header()) {
        let bytes = header.to_bytes().expect("valid header should serialize");
        let restored = SuperHeader::from_bytes(&bytes).unwrap();
        prop_assert_eq!(restored.magic(), &MAGIC);
        prop_assert_eq!(restored.version(), HEADER_VERSION);
    }

    /// P15: AccessPolicy roundtrip is lossless.
    #[test]
    fn access_policy_roundtrip(
        recipients in proptest::collection::vec(arb_recipient_slot(), 2..=8),
    ) {
        // Test both AnyOfN and max valid Threshold for this recipient count
        let policies = [AccessPolicy::AnyOfN, AccessPolicy::Threshold(recipients.len() as u32)];
        for policy in &policies {
            let header = make_super_header(
                ArchiveId(uuid::Uuid::from_bytes([0x11; 16])),
                VolumeId(uuid::Uuid::from_bytes([0x22; 16])),
                0, 1, 1000, 0,
                recipients.clone(),
                [0u8; 16], 0,
                EncryptedVolumeKey::new(
                    KeyWrapAlgorithm::XChaCha20Poly1305,
                    [0xAA; 24],
                    vec![0xBB; 48],
                ),
                *policy,
            );
            let bytes = header.to_bytes().expect("serialize");
            let restored = SuperHeader::from_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(restored.access_policy(), *policy);
        }
    }

    /// P16: Threshold(T < 2) is rejected on deserialization.
    #[test]
    fn threshold_below_2_rejected(t in 0u32..2) {
        use prost::Message;
        let header = make_super_header(
            ArchiveId(uuid::Uuid::from_bytes([0x11; 16])),
            VolumeId(uuid::Uuid::from_bytes([0x22; 16])),
            0, 1, 1000, 0,
            vec![RecipientSlot::new(
                RecipientType::Argon2idPassword,
                None,
                vec![0xAB; 16],
                vec![0xCD; 48],
            )],
            [0u8; 16], 0,
            EncryptedVolumeKey::new(
                KeyWrapAlgorithm::XChaCha20Poly1305,
                [0xAA; 24],
                vec![0xBB; 48],
            ),
            AccessPolicy::Threshold(3), // valid value first
        );
        // Serialize to proto, mutate threshold, re-encode
        let mut proto: era_common::proto::SuperHeader = header.into();
        proto.access_policy = era_common::proto::AccessPolicy::Threshold.into();
        proto.threshold = t;
        let mut data = Vec::new();
        proto.encode_length_delimited(&mut data).unwrap();
        data.resize(HEADER_SIZE, 0);
        let result = SuperHeader::from_bytes(&data);
        prop_assert!(result.is_err(), "Threshold({}) should be rejected", t);
    }
}

// ──────────────────── Cross-Field Validation Properties ────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// P17: Footer rejects data_end_offset in the dead zone (1..HEADER_SIZE+FOOTER_SIZE).
    #[test]
    fn footer_rejects_small_data_end(data_end in 1u64..(HEADER_SIZE + FOOTER_SIZE) as u64) {
        // Use Footer::with_catalog which calls update_checksum internally,
        // so the checksum check passes and field validation catches the bad offset.
        let bad_footer = Footer::with_catalog(
            data_end, 0, 0,
            0, 0, 0,
            0, 0,
            0, 0, 0,
            0,
        );
        let bytes = bad_footer.to_bytes().expect("serialize");
        let result = Footer::from_bytes(&bytes);
        prop_assert!(result.is_err(), "data_end_offset {} should be rejected", data_end);
    }

    /// P18: Footer rejects catalog_offset in the dead zone (1..HEADER_SIZE).
    #[test]
    fn footer_rejects_small_catalog_offset(
        cat_off in 1u64..HEADER_SIZE as u64,
    ) {
        let min_data_end = (HEADER_SIZE + FOOTER_SIZE) as u64;
        // data_end must be large enough to not be the rejection reason
        let bad_footer = Footer::with_catalog(
            min_data_end + 100_000, 0, 0,
            cat_off, 100, 0,
            0, 0,
            0, 0, 0,
            0,
        );
        let bytes = bad_footer.to_bytes().expect("serialize");
        let result = Footer::from_bytes(&bytes);
        prop_assert!(result.is_err(), "catalog_offset {} should be rejected", cat_off);
    }
}
