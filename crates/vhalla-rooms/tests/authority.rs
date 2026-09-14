//! Authority-assessment regressions over real social archives.
//!
//! These tests qualify basis-freshness, status and grant re-evaluation against
//! a borrowed `ControlView` plus the agreed room-control ledger. They do not
//! qualify slug uniqueness, allowance debit or consensus finality.
use ed25519_dalek::SigningKey;
use vhalla_core::RealmId;
use vhalla_rooms as rooms;
use vhalla_social as social;
use {
    rooms::{
        authority::RoomAuthority, CreateAction, CreationIntent, Denial, Description, DirectoryId,
        PolicyId, RoomControl, RoomRecordId, Slug,
    },
    social::{
        archive::{Archive, Budget, Limits},
        control::ControlView,
        AgentId, Body, ControlAction, OwnerId, RecordId, References, Rights, SignedRecord,
        UnsignedRecord, MAX_RECORD_BYTES,
    },
};

const DIRECTORY: DirectoryId = DirectoryId::from_bytes([7; 32]);
const POLICY: PolicyId = PolicyId::from_bytes([8; 32]);
const SETTINGS: PolicyId = PolicyId::from_bytes([9; 32]);

fn social_sign(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> SignedRecord {
    let primary = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    match ack {
        Some(k) => primary.countersign(k).unwrap(),
        None => primary.finish().unwrap(),
    }
}

fn ingest(archive: &mut Archive, record: &SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(2, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}

/// An owner with one affiliated agent and an open social grant; the returned
/// head is the owner's accepted social control head after ingestion.
struct Social {
    archive: Archive,
    owner_key: SigningKey,
    agent_key: SigningKey,
    owner: OwnerId,
    agent: AgentId,
    root: RecordId,
    head: RecordId,
}

fn social_fixture(realm: RealmId, seed: u8, agent_seed: u8) -> Social {
    let owner_key = SigningKey::from_bytes(&[seed; 32]);
    let agent_key = SigningKey::from_bytes(&[agent_seed; 32]);
    let root = social_sign(
        Body::OwnerGenesis {
            controller: owner_key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [seed; 32],
        },
        &owner_key,
        None,
    );
    let owner = OwnerId::from_bytes(*root.id().as_bytes());
    let agent_root = social_sign(
        Body::AgentGenesis {
            owner,
            control: root.id(),
            key: agent_key.verifying_key().to_bytes(),
            nonce: [agent_seed; 32],
        },
        &owner_key,
        Some(&agent_key),
    );
    let agent = AgentId::from_bytes(*agent_root.id().as_bytes());
    let grant = social_sign(
        Body::Control {
            owner,
            previous: root.id(),
            action: ControlAction::Grant {
                agent,
                realm,
                rights: Rights::ALL,
                expires_at: 10_000,
                nonce: [seed + 1; 32],
            },
        },
        &owner_key,
        None,
    );
    let limits = Limits {
        records: 64,
        control_reserve: 16,
        data_per_owner: 8,
        data_per_writer: 8,
        control_per_owner: 8,
        pending: 16,
        pending_per_signer: 4,
    };
    let mut archive = Archive::new(realm, limits).unwrap();
    for record in [&root, &agent_root, &grant] {
        ingest(&mut archive, record);
    }
    Social {
        archive,
        owner_key,
        agent_key,
        owner,
        agent,
        root: root.id(),
        head: grant.id(),
    }
}

/// Extend the social chain with one control record signed by the owner,
/// advancing the accepted head.
fn extend_social(social: &mut Social, action: ControlAction) {
    let record = social_sign(
        Body::Control {
            owner: social.owner,
            previous: social.head,
            action,
        },
        &social.owner_key,
        None,
    );
    social.head = record.id();
    ingest(&mut social.archive, &record);
}

fn room_control(
    social: &Social,
    realm: RealmId,
    previous: Option<RoomRecordId>,
    sequence: u64,
    action: CreateAction,
) -> rooms::VerifiedRecord {
    RoomControl {
        directory: DIRECTORY,
        realm,
        owner: social.owner,
        social_control: social.head,
        controller_key: social.owner_key.verifying_key().to_bytes(),
        previous,
        sequence,
        action,
    }
    .sign_with_key(&social.owner_key)
    .unwrap()
    .verify()
    .unwrap()
}

fn grant_create(social: &Social, realm: RealmId) -> rooms::VerifiedRecord {
    room_control(
        social,
        realm,
        None,
        0,
        CreateAction::GrantCreate {
            agent: social.agent,
            agent_key: social.agent_key.verifying_key().to_bytes(),
            expires_at: 5_000,
            maximum_charge: 100,
            nonce: [42; 32],
        },
    )
}

fn intent(
    social: &Social,
    realm: RealmId,
    room_head: RoomRecordId,
    grant: RoomRecordId,
) -> CreationIntent {
    CreationIntent {
        directory: DIRECTORY,
        realm,
        policy: POLICY,
        initial_settings: SETTINGS,
        owner: social.owner,
        agent: social.agent,
        owner_key: social.owner_key.verifying_key().to_bytes(),
        agent_key: social.agent_key.verifying_key().to_bytes(),
        social_control: social.head,
        room_control: room_head,
        grant,
        slug: Slug::new("rust-games").unwrap(),
        description: Description::new("inert").unwrap(),
        slot: 1,
        charge: 32,
        expires_at: 1_000,
        nonce: [13; 32],
    }
}

fn view(social: &Social) -> ControlView<'_> {
    ControlView::new(&social.archive, 500)
}

#[test]
fn grant_then_intent_is_assessed_and_snapshot_moves() {
    let realm = RealmId(61);
    let social = social_fixture(realm, 1, 2);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    let before = authority.snapshot(&view(&social));
    authority.admit(&grant, &view(&social), 500).unwrap();
    let after = authority.snapshot(&view(&social));
    assert_ne!(before, after, "admitting a grant must move the snapshot");
    let proposal = intent(&social, realm, grant.id(), grant.id());
    let assessed = authority
        .assess_creation(&proposal, &view(&social), 500)
        .unwrap();
    assert_eq!(assessed.grant(), &grant.id());
    assert_eq!(assessed.charge(), 32);
}

#[test]
fn stale_social_basis_is_denied_after_head_advances() {
    let realm = RealmId(62);
    let mut social = social_fixture(realm, 3, 4);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    let stale = intent(&social, realm, grant.id(), grant.id());
    // A later social control action advances the accepted head.
    extend_social(
        &mut social,
        ControlAction::Seal {
            realm,
            heads: References::default(),
        },
    );
    let result = authority.assess_creation(&stale, &view(&social), 500);
    assert_eq!(result, Err(Denial::StaleSocialBasis));
    // A permit re-signed at the new head assesses again: freshness is the basis.
    let fresh = intent(&social, realm, grant.id(), grant.id());
    authority
        .assess_creation(&fresh, &view(&social), 500)
        .unwrap();
}

#[test]
fn frozen_incomplete_and_forked_authority_is_denied() {
    let realm = RealmId(63);
    let mut social = social_fixture(realm, 5, 6);
    // A second valid control child of the genesis root forks the chain.
    let fork = social_sign(
        Body::Control {
            owner: social.owner,
            previous: social.root,
            action: ControlAction::Seal {
                realm,
                heads: References::default(),
            },
        },
        &social.owner_key,
        None,
    );
    ingest(&mut social.archive, &fork);
    assert!(view(&social).owner(social.owner).unwrap().frozen());
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    assert_eq!(
        authority.admit(&grant_create(&social, realm), &view(&social), 500),
        Err(Denial::Frozen)
    );
}

#[test]
fn retired_agent_cannot_be_granted_or_assessed() {
    let realm = RealmId(64);
    let mut social = social_fixture(realm, 7, 8);
    let agent = social.agent;
    extend_social(
        &mut social,
        ControlAction::Retire {
            agent,
            realm,
            accepted: References::default(),
        },
    );
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    assert_eq!(
        authority.admit(&grant_create(&social, realm), &view(&social), 500),
        Err(Denial::RetiredAgent)
    );
}

#[test]
fn revoked_grant_cannot_cover_an_intent() {
    let realm = RealmId(65);
    let social = social_fixture(realm, 9, 10);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    let revoke = room_control(
        &social,
        realm,
        Some(grant.id()),
        1,
        CreateAction::RevokeGrant { grant: grant.id() },
    );
    authority.admit(&revoke, &view(&social), 500).unwrap();
    // The intent names the current head but a grant that is now closed.
    assert_eq!(
        authority.assess_creation(
            &intent(&social, realm, revoke.id(), grant.id()),
            &view(&social),
            500
        ),
        Err(Denial::Grant)
    );
    // Re-assessing the pre-revoke intent also fails: no token survives a
    // state change inside atomic registration.
    assert_eq!(
        authority.assess_creation(
            &intent(&social, realm, grant.id(), grant.id()),
            &view(&social),
            500
        ),
        Err(Denial::StaleRoomBasis)
    );
}

#[test]
fn expired_grant_and_expired_intent_are_denied() {
    let realm = RealmId(66);
    let mut social = social_fixture(realm, 11, 12);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    // A grant already closed at the evaluation clock cannot be admitted.
    let dead = room_control(
        &social,
        realm,
        None,
        0,
        CreateAction::GrantCreate {
            agent: social.agent,
            agent_key: social.agent_key.verifying_key().to_bytes(),
            expires_at: 100,
            maximum_charge: 100,
            nonce: [43; 32],
        },
    );
    assert_eq!(
        authority.admit(&dead, &view(&social), 500),
        Err(Denial::Expired)
    );
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    // The grant outlives the clock but the intent does not.
    let mut expired = intent(&social, realm, grant.id(), grant.id());
    expired.expires_at = 400;
    assert_eq!(
        authority.assess_creation(&expired, &view(&social), 500),
        Err(Denial::Expired)
    );
    // And a grant whose deadline passes before assessment is stale too.
    extend_social(
        &mut social,
        ControlAction::Seal {
            realm,
            heads: References::default(),
        },
    );
    assert_eq!(
        authority.assess_creation(
            &intent(&social, realm, grant.id(), grant.id()),
            &view(&social),
            6_000
        ),
        Err(Denial::Expired)
    );
}

#[test]
fn charge_above_the_grant_maximum_is_denied() {
    let realm = RealmId(67);
    let social = social_fixture(realm, 13, 14);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    let mut over = intent(&social, realm, grant.id(), grant.id());
    over.charge = 101;
    assert_eq!(
        authority.assess_creation(&over, &view(&social), 500),
        Err(Denial::Charge)
    );
}

#[test]
fn chain_order_and_room_basis_are_enforced() {
    let realm = RealmId(68);
    let social = social_fixture(realm, 15, 16);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    // A well-formed record naming a wrong predecessor fails even with the
    // right sequence.
    let skip_previous = room_control(
        &social,
        realm,
        Some(RoomRecordId::from_bytes([77; 32])),
        1,
        CreateAction::RevokeGrant { grant: grant.id() },
    );
    assert_eq!(
        authority.admit(&skip_previous, &view(&social), 500),
        Err(Denial::Previous)
    );
    // The right predecessor with a jumped sequence fails too.
    let skip_sequence = room_control(
        &social,
        realm,
        Some(grant.id()),
        3,
        CreateAction::RevokeGrant { grant: grant.id() },
    );
    assert_eq!(
        authority.admit(&skip_sequence, &view(&social), 500),
        Err(Denial::Sequence)
    );
    // An intent naming an older room head after the chain moved is stale.
    let second = room_control(
        &social,
        realm,
        Some(grant.id()),
        1,
        CreateAction::RevokeGrant { grant: grant.id() },
    );
    authority.admit(&second, &view(&social), 500).unwrap();
    assert_eq!(
        authority.assess_creation(
            &intent(&social, realm, grant.id(), grant.id()),
            &view(&social),
            500
        ),
        Err(Denial::StaleRoomBasis)
    );
}

#[test]
fn a_grant_cannot_cover_another_agent_or_key() {
    let realm = RealmId(69);
    let social = social_fixture(realm, 17, 18);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    let mut other = intent(&social, realm, grant.id(), grant.id());
    other.agent = AgentId::from_bytes([99; 32]);
    assert_eq!(
        authority.assess_creation(&other, &view(&social), 500),
        Err(Denial::AgentAffiliation)
    );
    let mut wrong_key = intent(&social, realm, grant.id(), grant.id());
    wrong_key.agent_key = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
    assert_eq!(
        authority.assess_creation(&wrong_key, &view(&social), 500),
        Err(Denial::AgentKey)
    );
}

#[test]
fn scope_mismatch_is_denied_before_authority() {
    let realm = RealmId(70);
    let social = social_fixture(realm, 19, 20);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    let mut foreign = intent(&social, realm, grant.id(), grant.id());
    foreign.directory = DirectoryId::from_bytes([1; 32]);
    assert_eq!(
        authority.assess_creation(&foreign, &view(&social), 500),
        Err(Denial::Scope)
    );
    let mut foreign_realm = intent(&social, RealmId(71), grant.id(), grant.id());
    foreign_realm.realm = RealmId(71);
    assert_eq!(
        authority.assess_creation(&foreign_realm, &view(&social), 500),
        Err(Denial::Scope)
    );
}

#[test]
fn snapshot_binds_social_and_room_state() {
    let realm = RealmId(72);
    let mut social = social_fixture(realm, 21, 22);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let a = authority.snapshot(&view(&social));
    // A room grant changes the digest.
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    let b = authority.snapshot(&view(&social));
    assert_ne!(a, b);
    // A social rotation changes it again — an intervening rotation or grant
    // change requires a fresh proposal because the bound snapshot moved.
    let new_key = SigningKey::from_bytes(&[23; 32]);
    let rotate = Body::Control {
        owner: social.owner,
        previous: social.head,
        action: ControlAction::Rotate {
            new_key: new_key.verifying_key().to_bytes(),
        },
    };
    let record = {
        let primary = UnsignedRecord::new(social.owner_key.verifying_key().to_bytes(), rotate)
            .unwrap()
            .sign_with_key(&social.owner_key)
            .unwrap();
        primary.countersign(&new_key).unwrap()
    };
    social.head = record.id();
    ingest(&mut social.archive, &record);
    let c = authority.snapshot(&view(&social));
    assert_ne!(b, c);
    // The old controller key no longer assesses at the rotated head.
    assert_eq!(
        authority.assess_creation(
            &intent(&social, realm, grant.id(), grant.id()),
            &view(&social),
            500
        ),
        Err(Denial::ControllerKey)
    );
}

#[test]
fn updates_are_assessed_against_social_authority() {
    let realm = RealmId(73);
    let mut social = social_fixture(realm, 24, 25);
    let mut authority = RoomAuthority::new(DIRECTORY, realm);
    let grant = grant_create(&social, realm);
    authority.admit(&grant, &view(&social), 500).unwrap();
    let update = rooms::RoomUpdate {
        directory: DIRECTORY,
        realm,
        genesis: rooms::RoomGenesisId::from_bytes([31; 32]),
        previous: grant.id(),
        owner: social.owner,
        social_control: social.head,
        controller_key: social.owner_key.verifying_key().to_bytes(),
        expires_at: 1_000,
        nonce: [32; 32],
        action: rooms::UpdateAction::Archive,
    };
    authority
        .assess_update(&update, &view(&social), 500)
        .unwrap();
    // Advancing the social head makes the same claims stale.
    extend_social(
        &mut social,
        ControlAction::Seal {
            realm,
            heads: References::default(),
        },
    );
    assert_eq!(
        authority.assess_update(&update, &view(&social), 500),
        Err(Denial::StaleSocialBasis)
    );
}
