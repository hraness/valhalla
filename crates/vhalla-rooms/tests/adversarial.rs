//! Independent hostile-frame, signature-scope and legacy-isolation regressions.
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vhalla_core::RealmId;
use vhalla_rooms::{
    CreationIntent, Description, DirectoryId, Error, OwnerPermit, PolicyId, RoomRecordId,
    SignedRecord, Slug, MAX_RECORD_BYTES,
};
use vhalla_social::{AgentId, OwnerId, RecordId, Rights};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn intent() -> CreationIntent {
    CreationIntent {
        directory: DirectoryId::from_bytes([3; 32]),
        realm: RealmId(4),
        policy: PolicyId::from_bytes([5; 32]),
        initial_settings: PolicyId::from_bytes([6; 32]),
        owner: OwnerId::from_bytes([7; 32]),
        agent: AgentId::from_bytes([8; 32]),
        owner_key: key(1).verifying_key().to_bytes(),
        agent_key: key(2).verifying_key().to_bytes(),
        social_control: RecordId::from_bytes([9; 32]),
        room_control: RoomRecordId::from_bytes([10; 32]),
        grant: RoomRecordId::from_bytes([11; 32]),
        slug: Slug::new("rust-games").unwrap(),
        description: Description::new("Rust café simulations <script>inert text</script>").unwrap(),
        slot: 1,
        charge: 32,
        expires_at: 1000,
        nonce: [12; 32],
    }
}

fn proposal() -> SignedRecord {
    OwnerPermit::sign_with_key(intent(), &key(1))
        .unwrap()
        .verify()
        .unwrap()
        .propose_with_key(&key(2))
        .unwrap()
        .into_record()
}

#[test]
fn every_frame_byte_is_canonical_or_covered_by_strict_signatures() {
    let raw = proposal().encode();
    assert!(SignedRecord::decode(&raw).unwrap().verify().is_ok());
    for index in 0..raw.len() {
        let mut changed = raw.clone();
        changed[index] ^= 1;
        assert!(
            SignedRecord::decode(&changed)
                .and_then(SignedRecord::verify)
                .is_err(),
            "changed byte {index} was accepted"
        );
    }

    let permit = OwnerPermit::sign_with_key(intent(), &key(1))
        .unwrap()
        .encode();
    for index in 0..permit.len() {
        let mut changed = permit.clone();
        changed[index] ^= 1;
        assert!(
            OwnerPermit::decode(&changed)
                .and_then(OwnerPermit::verify)
                .is_err(),
            "changed permit byte {index} was accepted"
        );
    }
}

#[test]
fn all_truncations_trailing_data_and_cross_family_frames_are_rejected() {
    let raw = proposal().encode();
    let permit = OwnerPermit::sign_with_key(intent(), &key(1))
        .unwrap()
        .encode();
    for cut in 0..raw.len() {
        assert!(SignedRecord::decode(&raw[..cut]).is_err());
    }
    for cut in 0..permit.len() {
        assert!(OwnerPermit::decode(&permit[..cut]).is_err());
    }
    assert!(SignedRecord::decode(&permit).is_err());
    assert!(OwnerPermit::decode(&raw).is_err());
    for suffix in [vec![0], vec![1, 2, 3], raw.clone(), permit.clone()] {
        assert!(SignedRecord::decode(&[raw.as_slice(), &suffix].concat()).is_err());
        assert!(OwnerPermit::decode(&[permit.as_slice(), &suffix].concat()).is_err());
    }
    assert_eq!(
        SignedRecord::decode(&vec![0; MAX_RECORD_BYTES + 1]),
        Err(Error::Bounds)
    );
}

#[test]
fn social_v1_rights_and_decoder_do_not_adopt_room_authority() {
    assert_eq!(Rights::ALL.bits(), 63);
    for bits in [64, 65, 127, 255] {
        assert!(Rights::from_bits(bits).is_err());
    }
    assert!(vhalla_social::SignedRecord::decode(&proposal().encode()).is_err());
    let legacy = include_str!("../../vhalla-social/tests/vectors/legacy-post-v1.hex").trim();
    let legacy: Vec<_> = legacy
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert!(vhalla_social::SignedRecord::decode(&legacy)
        .unwrap()
        .verify()
        .is_ok());
    assert!(SignedRecord::decode(&legacy).is_err());
}

#[test]
fn a_sibling_key_cannot_issue_the_permit_or_countersign_it() {
    assert_eq!(
        OwnerPermit::sign_with_key(intent(), &key(2)).unwrap_err(),
        Error::SigningKey
    );
    let permit = OwnerPermit::sign_with_key(intent(), &key(1))
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(
        permit.propose_with_key(&key(3)).unwrap_err(),
        Error::SigningKey
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn bounded_foreign_frames_never_panic_or_normalize(
        raw in prop::collection::vec(any::<u8>(), 0..MAX_RECORD_BYTES + 2)
    ) {
        let first = SignedRecord::decode(&raw);
        let second = SignedRecord::decode(&raw);
        prop_assert_eq!(&first, &second);
        if let Ok(record) = first {
            prop_assert_eq!(record.encode(), raw.clone());
            let _ = record.verify();
        }
        if let Ok(permit) = OwnerPermit::decode(&raw) {
            prop_assert_eq!(permit.encode(), raw);
            let _ = permit.verify();
        }
    }
}
