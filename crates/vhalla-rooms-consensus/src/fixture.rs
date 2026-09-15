//! Test-support fixture for the live adapter: builds real signed social
//! and room records and a deterministic per-height `Batch` plan. Engine
//! and adapter tests share it so every validator constructs — and
//! consensus-carries — the same canonical bytes.

use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use vhalla_core::RealmId;
use vhalla_rooms::registry::DirectoryPolicy;
use vhalla_rooms::{
    CreateAction, CreationIntent, Description, DirectoryId, OwnerPermit, RoomControl, RoomRecordId,
    Slug,
};
use vhalla_social::archive::{Archive, Budget, Limits};
use vhalla_social::{
    Actor, AgentId, Body, ControlAction, Operation, OwnerId, Placement, Reaction, RecordId,
    References, Rights, Text, UnsignedRecord,
};

use crate::{Application, Batch, Genesis};

/// Shared fixture realm.
pub const REALM: RealmId = RealmId(77);
/// Shared fixture directory identity.
pub const DIRECTORY: DirectoryId = DirectoryId::from_bytes([5; 32]);
/// Award-support epoch the policy carries.
pub const EPOCH: u64 = 86_400;

/// The fixture policy: unit base cost so slot `n` charges `n²`.
pub fn policy() -> DirectoryPolicy {
    DirectoryPolicy {
        base_cost: 1,
        window_seconds: 86_400,
        max_in_window: 8,
        support_epoch_seconds: EPOCH,
        max_lifetime_rooms: 16,
    }
}

/// Social store/archive bounds for the fixture.
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

fn sign(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> vhalla_social::SignedRecord {
    let primary = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    match ack {
        Some(k) => primary.countersign(k).unwrap(),
        None => primary.finish().unwrap(),
    }
}

fn ingest(archive: &mut Archive, record: &vhalla_social::SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(2, vhalla_social::MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}

/// An owner with an enrolled agent and an open social grant — the signing
/// bundle a batch plan signs with.
#[derive(Clone)]
pub struct Owner {
    /// Owner controller key.
    pub key: SigningKey,
    /// Agent signing key.
    pub agent_key: SigningKey,
    /// Owner identity.
    pub id: OwnerId,
    /// Agent identity.
    pub agent: AgentId,
    /// Current social control head (advanced by seals this plan emits).
    pub head: RecordId,
    /// The open social grant record id.
    pub grant: RecordId,
}

/// Enroll an owner, agent and open grant into `archive`.
pub fn owner(archive: &mut Archive, seed: u8) -> Owner {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let agent_key = SigningKey::from_bytes(&[seed.wrapping_add(40); 32]);
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
            nonce: [seed.wrapping_add(41); 32],
        },
        &key,
        Some(&agent_key),
    );
    let grant = sign(
        Body::Control {
            owner: id,
            previous: root.id(),
            action: ControlAction::Grant {
                agent: AgentId::from_bytes(*agent_root.id().as_bytes()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 1_000_000,
                nonce: [seed.wrapping_add(42); 32],
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
    }
}

/// A seal record committing `heads` and advancing `owner.head` — returned
/// for batch evidence rather than ingested directly.
pub fn seal_record(owner: &mut Owner, heads: &[RecordId]) -> vhalla_social::SignedRecord {
    let record = sign(
        Body::Control {
            owner: owner.id,
            previous: owner.head,
            action: ControlAction::Seal {
                realm: REALM,
                heads: References::sorted(heads.to_vec()).unwrap(),
            },
        },
        &owner.key,
        None,
    );
    owner.head = record.id();
    record
}

/// A beneficiary owner with one committed post (the react target).
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
    let seal = seal_record(&mut owner, &[post.id()]);
    ingest(archive, &seal);
    owner
}

/// The beneficiary's committed post record id.
pub fn beneficiary_post(archive: &Archive, owner: OwnerId) -> RecordId {
    archive
        .records()
        .find_map(|r| match r.body() {
            Body::Social {
                actor,
                operation: Operation::Post { .. },
                ..
            } if actor.owner() == owner => Some(r.id()),
            _ => None,
        })
        .unwrap()
}

/// An agent-signed up-reaction from `source` to `post` — batch evidence.
pub fn react_record(source: &Owner, post: RecordId) -> vhalla_social::SignedRecord {
    sign(
        Body::Social {
            actor: Actor::Agent {
                owner: source.id,
                agent: source.agent,
                grant: source.grant,
            },
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: Operation::React {
                post,
                reaction: Reaction::Up(post),
                supersedes: References::default(),
            },
        },
        &source.agent_key,
        None,
    )
}

/// A room-control GrantCreate record (chain genesis for `owner`), verified.
pub fn grant_create_record(owner: &Owner, nonce: u8) -> vhalla_rooms::VerifiedRecord {
    RoomControl {
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
            expires_at: 1_000_000,
            maximum_charge: 1_000,
            nonce: [nonce; 32],
        },
    }
    .sign_with_key(&owner.key)
    .unwrap()
    .verify()
    .unwrap()
}

/// A fully signed creation record (owner permit + agent proposal).
pub fn creation_record(
    owner: &Owner,
    room_head: RoomRecordId,
    grant: RoomRecordId,
    slug: &str,
    slot: u32,
    charge: u64,
    nonce: u8,
) -> vhalla_rooms::SignedRecord {
    let intent = CreationIntent {
        directory: DIRECTORY,
        realm: REALM,
        policy: policy().id(),
        initial_settings: vhalla_rooms::PolicyId::from_bytes([6; 32]),
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
        expires_at: 1_000_000,
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

/// A scenario: the genesis inputs plus the signing bundles tests drive
/// hand-built batches with.
pub struct Scenario {
    /// The shared genesis both stores seed from.
    pub genesis: Genesis,
    /// Beneficiary owners (post-genesis heads).
    pub owners: Vec<Owner>,
    /// Eligible award-source owners.
    pub sources: Vec<Owner>,
    /// A genesis application for preparing/validating batches.
    pub app: Application,
}

/// Wide bounds for long plans: dozens of reacts and seals per source
/// writer, ~1.5k retained records, and — the binding constraint — ~850
/// committed seals + grants must fit inside `control_reserve` before the
/// archive marks every owner capacity-blocked.
pub fn wide_limits() -> Limits {
    Limits {
        records: 4_096,
        control_reserve: 1_024,
        data_per_owner: 64,
        data_per_writer: 64,
        control_per_owner: 64,
        pending: 256,
        pending_per_signer: 8,
    }
}

/// Builds the genesis archive + registry, the owners and the sources.
pub fn scenario(owner_count: usize, source_count: u8) -> Scenario {
    scenario_with_limits(owner_count, source_count, limits())
}

/// `scenario` under caller-supplied archive bounds — long plans need wider
/// per-writer and total caps than the unit fixture's.
pub fn scenario_with_limits(owner_count: usize, source_count: u8, limits: Limits) -> Scenario {
    let mut archive = Archive::new(REALM, limits).unwrap();
    let owners: Vec<Owner> = (0..owner_count)
        .map(|i| beneficiary(&mut archive, 1 + i as u8))
        .collect();
    let sources: Vec<Owner> = (0..source_count)
        .map(|i| owner(&mut archive, 60 + i))
        .collect();
    let genesis = Genesis {
        directory: DIRECTORY,
        realm: REALM,
        policy: policy(),
        eligible: sources.iter().map(|s| s.id).collect(),
        limits,
        archive: archive.clone(),
    };
    let app = Application::genesis(archive, genesis.registry().unwrap());
    Scenario {
        genesis,
        owners,
        sources,
        app,
    }
}

/// `count` fresh award-evidence pairs (react + committing seal) for
/// `beneficiary`'s post, drawn from sources at `cursor` onward.
pub fn evidence_for(
    archive: &Archive,
    beneficiary: OwnerId,
    sources: &mut [Owner],
    cursor: &mut usize,
    count: usize,
) -> Vec<Vec<u8>> {
    let post = beneficiary_post(archive, beneficiary);
    let mut evidence = Vec::new();
    for _ in 0..count {
        let source = &mut sources[*cursor % sources.len()];
        *cursor += 1;
        let react = react_record(source, post);
        let react_id = react.id();
        evidence.push(react.encode());
        evidence.push(seal_record(source, &[react_id]).encode());
    }
    evidence
}

/// Batch body for `owner`'s first room: the GrantCreate chain genesis plus
/// the creation record, and the award evidence covering the charge. The
/// quoted slot/charge come from `app`'s registry.
pub fn first_create(
    app: &Application,
    owner: &Owner,
    sources: &mut [Owner],
    cursor: &mut usize,
    slug: &str,
    nonce: u8,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, RoomRecordId) {
    let (slot, charge) = app.registry().quote(owner.id).unwrap();
    let account = app.registry().account(owner.id);
    let needed = (charge - (account.earned - account.spent)) as usize;
    let evidence = evidence_for(app.social(), owner.id, sources, cursor, needed);
    let grant = grant_create_record(owner, nonce);
    let grant_id = grant.id();
    let create = creation_record(owner, grant_id, grant_id, slug, slot, charge, nonce);
    (evidence, vec![grant.encode(), create.encode()], grant_id)
}

/// Batch body for a follow-on room by `owner`: one creation record citing
/// the existing open `grant`, plus evidence covering the charge.
pub fn next_create(
    app: &Application,
    owner: &Owner,
    grant: RoomRecordId,
    sources: &mut [Owner],
    cursor: &mut usize,
    slug: &str,
    nonce: u8,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (slot, charge) = app.registry().quote(owner.id).unwrap();
    let account = app.registry().account(owner.id);
    let needed = (charge - (account.earned - account.spent)) as usize;
    let evidence = evidence_for(app.social(), owner.id, sources, cursor, needed);
    let create = creation_record(owner, grant, grant, slug, slot, charge, nonce);
    (evidence, vec![create.encode()])
}

/// A deterministic batch plan: `owners` beneficiaries, `sources` eligible
/// award sources, one room creation per height. Each batch carries the
/// award evidence (react + seal pairs) needed to fund that creation plus
/// the signed room records, prepared against the evolving application so
/// every cited head/slot/charge is exact.
pub struct Plan {
    /// The shared genesis both stores seed from.
    pub genesis: Genesis,
    /// Height → batch every node holds.
    pub batches: BTreeMap<u64, Batch>,
}

/// Builds the genesis archive + registry and the per-height batch plan.
pub fn plan(heights: u64, owner_count: usize, source_count: u8) -> Plan {
    plan_with_limits(heights, owner_count, source_count, limits())
}

/// `plan` under caller-supplied archive bounds; the returned `Genesis`
/// carries them so every node's stores open with the same caps.
pub fn plan_with_limits(
    heights: u64,
    owner_count: usize,
    source_count: u8,
    limits: Limits,
) -> Plan {
    let mut scenario = scenario_with_limits(owner_count, source_count, limits);
    let mut grants: BTreeMap<OwnerId, RoomRecordId> = BTreeMap::new();
    let mut cursors: BTreeMap<OwnerId, usize> = BTreeMap::new();

    let mut batches = BTreeMap::new();
    for h in 1..=heights {
        let owner_index = (h as usize - 1) % owner_count;
        let owner_id = scenario.owners[owner_index].id;
        let cursor = cursors.entry(owner_id).or_insert(0);
        let (evidence, records) = match grants.get(&owner_id) {
            Some(grant) => next_create(
                &scenario.app,
                &scenario.owners[owner_index],
                *grant,
                &mut scenario.sources,
                cursor,
                &format!("room-{h}"),
                h as u8,
            ),
            None => {
                let (evidence, records, grant_id) = first_create(
                    &scenario.app,
                    &scenario.owners[owner_index],
                    &mut scenario.sources,
                    cursor,
                    &format!("room-{h}"),
                    h as u8,
                );
                grants.insert(owner_id, grant_id);
                (evidence, records)
            }
        };
        let checked = scenario.app.prepare(h, evidence, records, None).unwrap();
        let batch = checked.batch().clone();
        scenario.app.apply_locally(checked);
        batches.insert(h, batch);
    }
    Plan {
        genesis: scenario.genesis,
        batches,
    }
}
