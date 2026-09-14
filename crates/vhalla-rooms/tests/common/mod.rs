//! Shared fixture for vhalla-rooms integration tests: real signed social
//! and room records, owners with enrolled agents and open grants, and the
//! registry helpers each test drives.
#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use vhalla_core::RealmId;
use vhalla_rooms::{
    registry::{Applied, DirectoryPolicy, Registry, RegistryError},
    CreateAction, CreationIntent, Description, DirectoryId, OwnerPermit, PolicyId, RoomControl,
    RoomRecordId, Slug,
};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    control::ControlView,
    Actor, AgentId, Body, ControlAction as SocialAction, Operation, OwnerId, Placement, Reaction,
    RecordId, References, Rights, Text, UnsignedRecord, MAX_RECORD_BYTES,
};

pub const REALM: RealmId = RealmId(77);
/// Shared record horizon: far enough out that multi-epoch simulations
/// never trip grant or intent expiry.
pub const EXPIRES: u64 = 1_000_000_000_000;
pub const DIRECTORY: DirectoryId = DirectoryId::from_bytes([5; 32]);
pub const EPOCH: u64 = 86_400;

pub fn policy() -> DirectoryPolicy {
    DirectoryPolicy {
        base_cost: 1,
        window_seconds: 86_400,
        max_in_window: 1,
        support_epoch_seconds: EPOCH,
        max_lifetime_rooms: 8,
    }
}

pub fn sign(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> vhalla_social::SignedRecord {
    let primary = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    match ack {
        Some(k) => primary.countersign(k).unwrap(),
        None => primary.finish().unwrap(),
    }
}

pub fn ingest(archive: &mut Archive, record: &vhalla_social::SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(2, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}

pub fn limits() -> Limits {
    Limits {
        records: 512,
        control_reserve: 64,
        data_per_owner: 16,
        data_per_writer: 8,
        control_per_owner: 16,
        pending: 64,
        pending_per_signer: 8,
    }
}

/// An owner, agent and open social grant in the shared archive.
pub struct Owner {
    pub key: SigningKey,
    pub agent_key: SigningKey,
    pub id: OwnerId,
    pub agent: AgentId,
    pub head: RecordId,
    pub grant: RecordId,
    /// Agent-actor social-chain state: next sequence and head for reacts.
    pub social_seq: u64,
    pub social_head: Option<RecordId>,
}

pub fn owner(archive: &mut Archive, seed: u8) -> Owner {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let agent_key = SigningKey::from_bytes(&[seed + 40; 32]);
    let root = sign(
        Body::OwnerGenesis {
            controller: key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [seed; 32],
        },
        &key,
        None,
    );
    let id = OwnerId::from_bytes(*root.id().as_bytes());
    let agent_root = sign(
        Body::AgentGenesis {
            owner: id,
            control: root.id(),
            key: agent_key.verifying_key().to_bytes(),
            nonce: [seed + 41; 32],
        },
        &key,
        Some(&agent_key),
    );
    let grant = sign(
        Body::Control {
            owner: id,
            previous: root.id(),
            action: SocialAction::Grant {
                agent: AgentId::from_bytes(*agent_root.id().as_bytes()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: EXPIRES,
                nonce: [seed + 42; 32],
            },
        },
        &key,
        None,
    );
    for record in [&root, &agent_root, &grant] {
        ingest(archive, record);
    }
    Owner {
        key,
        agent_key,
        id,
        agent: AgentId::from_bytes(*agent_root.id().as_bytes()),
        head: grant.id(),
        grant: grant.id(),
        social_seq: 0,
        social_head: None,
    }
}

/// Seal one writer-chain head, committing it and advancing the owner head.
pub fn seal(archive: &mut Archive, owner: &mut Owner, heads: &[RecordId]) {
    let record = sign(
        Body::Control {
            owner: owner.id,
            previous: owner.head,
            action: SocialAction::Seal {
                realm: REALM,
                heads: References::sorted(heads.to_vec()).unwrap(),
            },
        },
        &owner.key,
        None,
    );
    owner.head = record.id();
    ingest(archive, &record);
}

/// A beneficiary with one committed post.
pub fn beneficiary(archive: &mut Archive, seed: u8) -> Owner {
    let mut owner = owner(archive, seed);
    let post = sign(
        Body::Social {
            actor: Actor::Owner {
                owner: owner.id,
                control: owner.head,
            },
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: Operation::Post {
                placement: Placement::Profile,
                text: Text::new("beneficiary post").unwrap(),
                reply: None,
                quote: None,
            },
        },
        &owner.key,
        None,
    );
    ingest(archive, &post);
    seal(archive, &mut owner, &[post.id()]);
    owner
}

/// Build `count` source owners and a registry admitting them as eligible
/// award sources.
pub fn sources(archive: &mut Archive, start: u8, count: u8) -> (Vec<Owner>, Registry) {
    let sources: Vec<Owner> = (start..start + count).map(|s| owner(archive, s)).collect();
    let eligible: Vec<OwnerId> = sources.iter().map(|s| s.id).collect();
    (
        sources,
        Registry::new(DIRECTORY, REALM, policy(), &eligible).unwrap(),
    )
}

/// Emit and seal one up-reaction from `source` on `beneficiary`'s post,
/// returning the verified record for `Registry::award`.
pub fn react_to_post(
    archive: &mut Archive,
    source: &mut Owner,
    beneficiary: &Owner,
) -> vhalla_social::wire::VerifiedRecord {
    let post = archive
        .records()
        .find_map(|r| match r.body() {
            Body::Social {
                actor,
                operation: Operation::Post { .. },
                ..
            } if actor.owner() == beneficiary.id => Some(r.id()),
            _ => None,
        })
        .unwrap();
    let react = sign(
        Body::Social {
            actor: Actor::Agent {
                owner: source.id,
                agent: source.agent,
                grant: source.grant,
            },
            realm: REALM,
            sequence: source.social_seq,
            previous: source.social_head,
            operation: Operation::React {
                post,
                reaction: Reaction::Up(post),
                supersedes: References::default(),
            },
        },
        &source.agent_key,
        None,
    );
    source.social_seq += 1;
    source.social_head = Some(react.id());
    ingest(archive, &react);
    seal(archive, source, &[react.id()]);
    vhalla_social::SignedRecord::decode(&react.encode())
        .unwrap()
        .verify()
        .unwrap()
}

/// Give `beneficiary` one mature credit: a committed agent-signed up-reaction
/// from a fresh source owner, applied through the registry's award path.
pub fn award_one(
    registry: &mut Registry,
    archive: &mut Archive,
    source: &mut Owner,
    beneficiary: &Owner,
    now: u64,
) {
    let verified = react_to_post(archive, source, beneficiary);
    let view = ControlView::new(archive, now);
    assert_eq!(registry.award(&verified, &view, now), Ok(Applied::Awarded));
}

/// A room-control GrantCreate admitted through the registry.
pub fn grant_create(
    registry: &mut Registry,
    archive: &Archive,
    owner: &Owner,
    now: u64,
) -> RoomRecordId {
    let record = RoomControl {
        directory: DIRECTORY,
        realm: REALM,
        owner: owner.id,
        social_control: owner.head,
        controller_key: owner.key.verifying_key().to_bytes(),
        previous: None,
        sequence: 0,
        action: CreateAction::GrantCreate {
            agent: owner.agent,
            agent_key: owner.agent_key.verifying_key().to_bytes(),
            expires_at: EXPIRES,
            maximum_charge: 1_000,
            nonce: [9; 32],
        },
    }
    .sign_with_key(&owner.key)
    .unwrap()
    .verify()
    .unwrap();
    let id = record.id();
    let view = ControlView::new(archive, now);
    assert_eq!(registry.apply(&record, &view, now), Ok(Applied::Control));
    id
}

pub fn creation(
    owner: &Owner,
    room_head: RoomRecordId,
    grant: RoomRecordId,
    slug: &str,
    slot: u32,
    charge: u64,
    nonce: u8,
) -> vhalla_rooms::SignedRecord {
    creation_with_policy(
        owner,
        room_head,
        grant,
        slug,
        slot,
        charge,
        nonce,
        policy().id(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn creation_with_policy(
    owner: &Owner,
    room_head: RoomRecordId,
    grant: RoomRecordId,
    slug: &str,
    slot: u32,
    charge: u64,
    nonce: u8,
    policy: PolicyId,
) -> vhalla_rooms::SignedRecord {
    let intent = CreationIntent {
        directory: DIRECTORY,
        realm: REALM,
        policy,
        initial_settings: PolicyId::from_bytes([6; 32]),
        owner: owner.id,
        agent: owner.agent,
        owner_key: owner.key.verifying_key().to_bytes(),
        agent_key: owner.agent_key.verifying_key().to_bytes(),
        social_control: owner.head,
        room_control: room_head,
        grant,
        slug: Slug::new(slug).unwrap(),
        description: Description::new("a room").unwrap(),
        slot,
        charge,
        expires_at: EXPIRES,
        nonce: [nonce; 32],
    };
    OwnerPermit::sign_with_key(intent, &owner.key)
        .unwrap()
        .verify()
        .unwrap()
        .propose_with_key(&owner.agent_key)
        .unwrap()
        .into_record()
}

/// Verify a room record and apply it, returning the registry outcome.
pub fn apply(
    registry: &mut Registry,
    archive: &Archive,
    record: &vhalla_rooms::SignedRecord,
    now: u64,
) -> Result<Applied, RegistryError> {
    let verified = record.clone().verify().unwrap();
    registry.apply(&verified, &ControlView::new(archive, now), now)
}
