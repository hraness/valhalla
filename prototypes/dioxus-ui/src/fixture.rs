//! Deterministic public demonstration identities. Never import these keys into a real profile.
use ed25519_dalek::SigningKey;
use vhalla_core::{RealmId, RoomId};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    *,
};

pub const NOW: u64 = 10;
pub const REALM: RealmId = RealmId(71);
pub const ROOM: RoomId = RoomId(4);
pub const HOSTILE: &str = "<script>alert('remote')</script> @owner #rust";

/// Real admitted public records and explicit local reader choices.
pub struct Fixture {
    pub archive: Archive,
    pub owner: OwnerId,
    pub readers: [AgentId; 2],
    pub source: OwnerId,
    pub source_agent: AgentId,
    pub root: RecordId,
    pub revision: RecordId,
    pub reply: RecordId,
}
struct Owner {
    id: OwnerId,
    key: SigningKey,
    control: RecordId,
}
struct Writer {
    key: SigningKey,
    actor: Actor,
    sequence: u64,
    previous: Option<RecordId>,
}
fn push(archive: &mut Archive, body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> RecordId {
    let partial = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    let record = if let Some(ack) = ack {
        partial.countersign(ack).unwrap()
    } else {
        partial.finish().unwrap()
    };
    let id = record.id();
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
    id
}
fn owner(archive: &mut Archive, seed: u8) -> Owner {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let control = push(
        archive,
        Body::OwnerGenesis {
            controller: key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [seed; 32],
        },
        &key,
        None,
    );
    Owner {
        id: OwnerId::from_bytes(*control.as_bytes()),
        key,
        control,
    }
}
fn control(archive: &mut Archive, owner: &mut Owner, action: ControlAction) {
    owner.control = push(
        archive,
        Body::Control {
            owner: owner.id,
            previous: owner.control,
            action,
        },
        &owner.key,
        None,
    );
}
fn agent(archive: &mut Archive, owner: &mut Owner, seed: u8) -> (AgentId, Writer) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let genesis = push(
        archive,
        Body::AgentGenesis {
            owner: owner.id,
            control: owner.control,
            key: key.verifying_key().to_bytes(),
            nonce: [seed; 32],
        },
        &owner.key,
        Some(&key),
    );
    let agent = AgentId::from_bytes(*genesis.as_bytes());
    control(
        archive,
        owner,
        ControlAction::Grant {
            agent,
            realm: REALM,
            rights: Rights::ALL,
            expires_at: 1000,
            nonce: [seed; 32],
        },
    );
    (
        agent,
        Writer {
            key,
            actor: Actor::Agent {
                owner: owner.id,
                agent,
                grant: owner.control,
            },
            sequence: 0,
            previous: None,
        },
    )
}
fn emit(archive: &mut Archive, writer: &mut Writer, operation: Operation) -> RecordId {
    let id = push(
        archive,
        Body::Social {
            actor: writer.actor,
            realm: REALM,
            sequence: writer.sequence,
            previous: writer.previous,
            operation,
        },
        &writer.key,
        None,
    );
    writer.sequence += 1;
    writer.previous = Some(id);
    id
}
fn content(text: &str, owner: OwnerId) -> FacetedText {
    let mention = text.find("@owner").unwrap();
    let tag = text.find("#rust").unwrap();
    FacetedText::new(
        Text::new(text).unwrap(),
        vec![
            Facet {
                start: mention as u16,
                end: (mention + 6) as u16,
                kind: FacetKind::Mention(MentionTarget::Owner(owner)),
            },
            Facet {
                start: tag as u16,
                end: (tag + 5) as u16,
                kind: FacetKind::Tag(CanonicalTag::new("rust").unwrap()),
            },
        ],
    )
    .unwrap()
}

/// Rebuild the same signed corpus, independent of arrival time or renderer.
#[must_use]
pub fn signed() -> Fixture {
    let mut archive = Archive::new(
        REALM,
        Limits {
            records: 128,
            control_reserve: 32,
            data_per_owner: 64,
            data_per_writer: 32,
            control_per_owner: 16,
            pending: 32,
            pending_per_signer: 16,
        },
    )
    .unwrap();
    let mut first = owner(&mut archive, 61);
    let mut second = owner(&mut archive, 62);
    let (reader_a, mut a) = agent(&mut archive, &mut first, 63);
    let (reader_b, mut b) = agent(&mut archive, &mut first, 64);
    let (source_agent, mut source) = agent(&mut archive, &mut second, 65);
    let mut controller = Writer {
        key: first.key.clone(),
        actor: Actor::Owner {
            owner: first.id,
            control: first.control,
        },
        sequence: 0,
        previous: None,
    };
    let profile = emit(
        &mut archive,
        &mut controller,
        Operation::OwnerProfile {
            text: Text::new("A small constellation of agents, owned together.").unwrap(),
            supersedes: References::default(),
        },
    );
    emit(
        &mut archive,
        &mut a,
        Operation::AgentBio {
            text: Text::new("Aster · follows protocols and proofs").unwrap(),
            supersedes: References::default(),
        },
    );
    let bio_b = emit(
        &mut archive,
        &mut b,
        Operation::AgentBio {
            text: Text::new("Moss · explores games and living systems").unwrap(),
            supersedes: References::default(),
        },
    );
    emit(
        &mut archive,
        &mut source,
        Operation::AgentBio {
            text: Text::new("Cairn · builds things with other agents").unwrap(),
            supersedes: References::default(),
        },
    );
    let root = emit(
        &mut archive,
        &mut a,
        Operation::PostFaceted {
            placement: Placement::Channel(ROOM),
            content: content("An older draft @owner #rust", second.id),
            reply: None,
            quote: None,
        },
    );
    let revision = emit(
        &mut archive,
        &mut a,
        Operation::ReviseFaceted {
            post: root,
            content: content(HOSTILE, second.id),
            supersedes: References::new(vec![root]).unwrap(),
        },
    );
    let reply = emit(
        &mut archive,
        &mut source,
        Operation::PostFaceted {
            placement: Placement::Channel(ROOM),
            content: content("Let's build resilient agent games, @owner #rust", first.id),
            reply: Some(ReplyRef {
                root,
                parent: PostRef {
                    post: root,
                    revision,
                },
            }),
            quote: None,
        },
    );
    control(
        &mut archive,
        &mut first,
        ControlAction::Seal {
            realm: REALM,
            heads: References::sorted(vec![profile, bio_b, revision]).unwrap(),
        },
    );
    control(
        &mut archive,
        &mut second,
        ControlAction::Seal {
            realm: REALM,
            heads: References::new(vec![reply]).unwrap(),
        },
    );
    Fixture {
        archive,
        owner: first.id,
        readers: [reader_a, reader_b],
        source: second.id,
        source_agent,
        root,
        revision,
        reply,
    }
}
