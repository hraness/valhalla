//! Room schema, role-domain, boundary and canonical roundtrip regressions.
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vhalla_core::RealmId;
use vhalla_rooms::*;
use vhalla_social::{AgentId, OwnerId, RecordId};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn intent() -> CreationIntent {
    CreationIntent {
        directory: DirectoryId::from_bytes([1; 32]),
        realm: RealmId(7),
        policy: PolicyId::from_bytes([2; 32]),
        initial_settings: PolicyId::from_bytes([3; 32]),
        owner: OwnerId::from_bytes([4; 32]),
        agent: AgentId::from_bytes([5; 32]),
        owner_key: key(6).verifying_key().to_bytes(),
        agent_key: key(7).verifying_key().to_bytes(),
        social_control: RecordId::from_bytes([8; 32]),
        room_control: RoomRecordId::from_bytes([9; 32]),
        grant: RoomRecordId::from_bytes([10; 32]),
        slug: Slug::new("rust-tools").unwrap(),
        description: Description::new("A place for 程式 and tools").unwrap(),
        slot: 1,
        charge: 32,
        expires_at: 12345,
        nonce: [11; 32],
    }
}
fn control(action: CreateAction) -> RoomControl {
    RoomControl {
        directory: DirectoryId::from_bytes([1; 32]),
        realm: RealmId(7),
        owner: OwnerId::from_bytes([4; 32]),
        social_control: RecordId::from_bytes([8; 32]),
        controller_key: key(6).verifying_key().to_bytes(),
        previous: None,
        sequence: 0,
        action,
    }
}
fn grant() -> RoomControl {
    control(CreateAction::GrantCreate {
        agent: AgentId::from_bytes([5; 32]),
        agent_key: key(7).verifying_key().to_bytes(),
        expires_at: 12345,
        maximum_charge: 32,
        nonce: [11; 32],
    })
}
fn update(action: UpdateAction) -> RoomUpdate {
    RoomUpdate {
        directory: DirectoryId::from_bytes([1; 32]),
        realm: RealmId(7),
        genesis: RoomGenesisId::from_bytes([12; 32]),
        previous: RoomRecordId::from_bytes([13; 32]),
        owner: OwnerId::from_bytes([4; 32]),
        social_control: RecordId::from_bytes([8; 32]),
        controller_key: key(6).verifying_key().to_bytes(),
        expires_at: 12345,
        nonce: [14; 32],
        action,
    }
}

#[test]
fn every_control_and_update_variant_roundtrips() {
    let grant = grant().sign_with_key(&key(6)).unwrap();
    let mut revoke = control(CreateAction::RevokeGrant { grant: grant.id() });
    revoke.previous = Some(grant.id());
    revoke.sequence = 1;
    let records = [
        grant,
        revoke.sign_with_key(&key(6)).unwrap(),
        update(UpdateAction::Describe(
            Description::new("Revised 🦀 topic").unwrap(),
        ))
        .sign_with_key(&key(6))
        .unwrap(),
        update(UpdateAction::Archive)
            .sign_with_key(&key(6))
            .unwrap(),
    ];
    for record in records {
        let raw = record.encode();
        assert!(raw.len() <= MAX_RECORD_BYTES);
        let verified = SignedRecord::decode(&raw).unwrap().verify().unwrap();
        assert_eq!(record.id(), verified.id());
        assert_eq!(record.body(), verified.body());
        assert_eq!(verified.encode(), raw);
        assert_eq!(verified.genesis_id(), None);
        assert_eq!(AgentProposal::decode(&raw).unwrap_err(), Error::Encoding);
    }
}

#[test]
fn control_sequence_shape_and_signing_roles_are_checked() {
    let original = grant();
    assert_eq!(
        original.clone().sign_with_key(&key(7)).unwrap_err(),
        Error::SigningKey
    );
    let mut bad = original.clone();
    bad.sequence = 1;
    assert_eq!(bad.sign_with_key(&key(6)).unwrap_err(), Error::Encoding);
    let mut bad = original.clone();
    bad.previous = Some(RoomRecordId::from_bytes([1; 32]));
    assert_eq!(bad.sign_with_key(&key(6)).unwrap_err(), Error::Encoding);
    for field in 0..3 {
        let mut bad = original.clone();
        if let CreateAction::GrantCreate {
            expires_at,
            maximum_charge,
            nonce,
            ..
        } = &mut bad.action
        {
            match field {
                0 => *expires_at = 0,
                1 => *maximum_charge = 0,
                _ => *nonce = [0; 32],
            }
        }
        assert_eq!(bad.sign_with_key(&key(6)).unwrap_err(), Error::Bounds);
    }
    assert_eq!(
        update(UpdateAction::Archive)
            .sign_with_key(&key(7))
            .unwrap_err(),
        Error::SigningKey
    );
    let mut bad = update(UpdateAction::Archive);
    bad.expires_at = 0;
    assert_eq!(bad.sign_with_key(&key(6)).unwrap_err(), Error::Bounds);
    let mut bad = update(UpdateAction::Archive);
    bad.nonce = [0; 32];
    assert_eq!(bad.sign_with_key(&key(6)).unwrap_err(), Error::Bounds);
}

#[test]
fn swapped_controller_signature_domains_fail_even_for_same_key() {
    let control = grant().sign_with_key(&key(6)).unwrap();
    let update = update(UpdateAction::Archive)
        .sign_with_key(&key(6))
        .unwrap();
    let mut control_bytes = control.encode();
    let mut update_bytes = update.encode();
    let c_start = control_bytes.len() - 64;
    let u_start = update_bytes.len() - 64;
    let c_signature = control_bytes[c_start..].to_vec();
    control_bytes[c_start..].copy_from_slice(&update_bytes[u_start..]);
    update_bytes[u_start..].copy_from_slice(&c_signature);
    for raw in [control_bytes, update_bytes] {
        assert_eq!(
            SignedRecord::decode(&raw).unwrap().verify().unwrap_err(),
            Error::Signature
        );
    }
}

#[test]
fn swapping_owner_and_agent_signature_roles_fails_even_for_same_key() {
    let mut same_key = intent();
    same_key.agent_key = same_key.owner_key;
    let proposal = OwnerPermit::sign_with_key(same_key, &key(6))
        .unwrap()
        .verify()
        .unwrap()
        .propose_with_key(&key(6))
        .unwrap();
    let mut raw = proposal.encode();
    let start = raw.len() - 128;
    let owner_signature = raw[start..start + 64].to_vec();
    let agent_signature = raw[start + 64..].to_vec();
    raw[start..start + 64].copy_from_slice(&agent_signature);
    raw[start + 64..].copy_from_slice(&owner_signature);
    assert_eq!(
        SignedRecord::decode(&raw).unwrap().verify().unwrap_err(),
        Error::Signature
    );
}

#[test]
fn full_creation_commitments_bind_content_without_a_hash_cycle() {
    let original = OwnerPermit::sign_with_key(intent(), &key(6)).unwrap();
    let permit_id = original.id();
    let genesis = original.genesis_id();
    assert_ne!(permit_id.as_bytes(), genesis.as_bytes());
    let proposal = original
        .verify()
        .unwrap()
        .propose_with_key(&key(7))
        .unwrap();
    assert_eq!(proposal.genesis_id(), genesis);
    let record = proposal.into_record();
    assert_ne!(record.id().as_bytes(), genesis.as_bytes());
    assert_eq!(record.verify().unwrap().genesis_id(), Some(genesis));
    let mut changed = intent();
    changed.description = Description::new("A different subject").unwrap();
    let changed = OwnerPermit::sign_with_key(changed, &key(6)).unwrap();
    assert_ne!(changed.id(), permit_id);
    assert_ne!(changed.genesis_id(), genesis);
}

#[test]
fn textual_and_numeric_boundaries_are_closed() {
    for bad in [
        "",
        "Rust",
        "-rust",
        "rust-",
        "rust--tools",
        "rust_tools",
        "🦀",
        "rust%20tools",
    ] {
        assert!(Slug::new(bad).is_err());
    }
    assert!(Slug::new(&"a".repeat(MAX_SLUG_BYTES)).is_ok());
    assert!(Slug::new(&"a".repeat(MAX_SLUG_BYTES + 1)).is_err());
    for bad in ["", "line\nbreak", "\0", "\u{7f}"] {
        assert!(Description::new(bad).is_err());
    }
    assert!(Description::new(&"🦀".repeat(MAX_DESCRIPTION_BYTES / 4)).is_ok());
    assert!(Description::new(&"🦀".repeat(MAX_DESCRIPTION_BYTES / 4 + 1)).is_err());
    for field in 0..4 {
        let mut bad = intent();
        match field {
            0 => bad.slot = 0,
            1 => bad.charge = 0,
            2 => bad.expires_at = 0,
            _ => bad.nonce = [0; 32],
        }
        assert_eq!(
            OwnerPermit::sign_with_key(bad, &key(6)).unwrap_err(),
            Error::Bounds
        );
    }
    let mut maximal = intent();
    maximal.slug = Slug::new(&"a".repeat(MAX_SLUG_BYTES)).unwrap();
    maximal.description = Description::new(&"🦀".repeat(MAX_DESCRIPTION_BYTES / 4)).unwrap();
    maximal.slot = u32::MAX;
    maximal.charge = u64::MAX;
    maximal.expires_at = u64::MAX;
    let proposal = OwnerPermit::sign_with_key(maximal, &key(6))
        .unwrap()
        .verify()
        .unwrap()
        .propose_with_key(&key(7))
        .unwrap();
    assert!(proposal.encode().len() <= MAX_RECORD_BYTES);
    assert!(proposal.verify().is_ok());

    let mut maximal_control = grant();
    maximal_control.previous = Some(RoomRecordId::from_bytes([255; 32]));
    maximal_control.sequence = u64::MAX;
    let maximal_control = maximal_control.sign_with_key(&key(6)).unwrap();
    let maximal_update = update(UpdateAction::Describe(
        Description::new(&"🦀".repeat(MAX_DESCRIPTION_BYTES / 4)).unwrap(),
    ))
    .sign_with_key(&key(6))
    .unwrap();
    for record in [maximal_control, maximal_update] {
        let raw = record.encode();
        assert!(raw.len() <= MAX_RECORD_BYTES);
        assert_eq!(
            SignedRecord::decode(&raw)
                .unwrap()
                .verify()
                .unwrap()
                .encode(),
            raw
        );
    }
}

#[test]
fn weak_keys_are_rejected_in_every_claimed_signing_role() {
    let mut weak = [0; 32];
    weak[0] = 1; // Edwards identity, accepted as a point but cryptographically weak.
    let mut bad = intent();
    bad.owner_key = weak;
    assert_eq!(
        OwnerPermit::sign_with_key(bad, &key(6)).unwrap_err(),
        Error::Key
    );
    let mut bad = intent();
    bad.agent_key = weak;
    assert_eq!(
        OwnerPermit::sign_with_key(bad, &key(6)).unwrap_err(),
        Error::Key
    );
    let mut bad = grant();
    if let CreateAction::GrantCreate { agent_key, .. } = &mut bad.action {
        *agent_key = weak;
    }
    assert_eq!(bad.sign_with_key(&key(6)).unwrap_err(), Error::Key);
    let mut bad = update(UpdateAction::Archive);
    bad.controller_key = weak;
    assert_eq!(bad.sign_with_key(&key(6)).unwrap_err(), Error::Key);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn generated_valid_intents_roundtrip(
        slug in "[a-z][a-z0-9]{0,47}",
        description in "[a-zA-Z0-9 ]{1,256}",
        slot in 1u32..=u32::MAX,
        charge in 1u64..=u64::MAX,
        expiry in 1u64..=u64::MAX,
    ) {
        let mut value = intent();
        value.slug = Slug::new(&slug).unwrap();
        value.description = Description::new(&description).unwrap();
        value.slot = slot;
        value.charge = charge;
        value.expires_at = expiry;
        let permit = OwnerPermit::sign_with_key(value.clone(), &key(6)).unwrap();
        let raw = permit.encode();
        let decoded = OwnerPermit::decode(&raw).unwrap().verify().unwrap();
        prop_assert_eq!(decoded.intent(), &value);
        prop_assert_eq!(decoded.encode(), raw);
        let proposal = decoded.propose_with_key(&key(7)).unwrap();
        let raw = proposal.encode();
        let verified = AgentProposal::decode(&raw).unwrap().verify().unwrap();
        prop_assert_eq!(verified.body(), &Body::Create(value));
        prop_assert_eq!(verified.encode(), raw);
    }
}
