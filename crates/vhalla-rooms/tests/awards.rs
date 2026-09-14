//! Mature-award derivation regressions over real committed social evidence.
//!
//! These tests qualify evidence authentication, owner attribution, epoch
//! binding and eligibility — not ledger deduplication, which the registry owns.
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use vhalla_core::RealmId;
use vhalla_rooms::awards::{assess_support, AwardDenial};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    control::ControlView,
    Actor, Body, ControlAction, Operation, OwnerId, Placement, Reaction, RecordId, References,
    Rights, SignedRecord, Text, UnsignedRecord, MAX_RECORD_BYTES,
};

const REALM: RealmId = RealmId(88);
const EPOCH: u64 = 86_400;

fn sign(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> SignedRecord {
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

/// One owner with one agent, one open social grant and the genesis root id.
struct Owner {
    key: SigningKey,
    agent_key: SigningKey,
    id: OwnerId,
    agent: vhalla_social::AgentId,
    head: RecordId,
    grant: RecordId,
}

fn owner(archive: &mut Archive, seed: u8) -> Owner {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let agent_key = SigningKey::from_bytes(&[seed + 1; 32]);
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
            nonce: [seed + 2; 32],
        },
        &key,
        Some(&agent_key),
    );
    let grant = sign(
        Body::Control {
            owner: id,
            previous: root.id(),
            action: ControlAction::Grant {
                agent: vhalla_social::AgentId::from_bytes(*agent_root.id().as_bytes()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: 100_000,
                nonce: [seed + 3; 32],
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
        agent: vhalla_social::AgentId::from_bytes(*agent_root.id().as_bytes()),
        head: grant.id(),
        grant: grant.id(),
    }
}

/// Owner-signed social record advancing no chain (sequence zero).
fn owner_social(owner: &Owner, operation: Operation) -> SignedRecord {
    sign(
        Body::Social {
            actor: Actor::Owner {
                owner: owner.id,
                control: owner.head,
            },
            realm: REALM,
            sequence: 0,
            previous: None,
            operation,
        },
        &owner.key,
        None,
    )
}

/// Agent-signed social record under the owner's open grant.
fn agent_social(owner: &Owner, operation: Operation) -> SignedRecord {
    sign(
        Body::Social {
            actor: Actor::Agent {
                owner: owner.id,
                agent: owner.agent,
                grant: owner.grant,
            },
            realm: REALM,
            sequence: 0,
            previous: None,
            operation,
        },
        &owner.agent_key,
        None,
    )
}

/// Seal exact writer-chain heads, committing them and advancing the head.
fn seal(archive: &mut Archive, owner: &mut Owner, heads: &[RecordId]) {
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
    ingest(archive, &record);
}

fn limits() -> Limits {
    Limits {
        records: 64,
        control_reserve: 16,
        data_per_owner: 16,
        data_per_writer: 8,
        control_per_owner: 8,
        pending: 16,
        pending_per_signer: 4,
    }
}

/// A beneficiary post and a committed agent-signed up-reaction to it.
struct Support {
    archive: Archive,
    source: OwnerId,
    beneficiary: OwnerId,
    post: RecordId,
    react: RecordId,
    react_record: SignedRecord,
}

fn support_fixture() -> Support {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let mut beneficiary = owner(&mut archive, 1);
    let post = owner_social(
        &beneficiary,
        Operation::Post {
            placement: Placement::Profile,
            text: Text::new("launch notes").unwrap(),
            reply: None,
            quote: None,
        },
    );
    ingest(&mut archive, &post);
    let post_id = post.id();
    seal(&mut archive, &mut beneficiary, &[post_id]);

    let mut source = owner(&mut archive, 10);
    let react = agent_social(
        &source,
        Operation::React {
            post: post_id,
            reaction: Reaction::Up(post_id),
            supersedes: References::default(),
        },
    );
    ingest(&mut archive, &react);
    let react_id = react.id();
    let react_id_record = react.clone();
    seal(&mut archive, &mut source, &[react_id]);
    let source_id = source.id;
    let beneficiary_id = beneficiary.id;
    Support {
        archive,
        source: source_id,
        beneficiary: beneficiary_id,
        post: post_id,
        react: react_id,
        react_record: react_id_record,
    }
}

fn verified(record: &SignedRecord) -> vhalla_social::VerifiedRecord {
    vhalla_social::SignedRecord::decode(&record.encode())
        .unwrap()
        .verify()
        .unwrap()
}

#[test]
fn committed_agent_upvote_derives_the_exact_award() {
    let fixture = support_fixture();
    let view = ControlView::new(&fixture.archive, 60_000);
    let eligible = BTreeSet::from([fixture.source]);
    let award = assess_support(
        &verified(&fixture.react_record),
        &view,
        &eligible,
        EPOCH,
        90_000,
        100_000,
    )
    .unwrap();
    // The agent-signed record attributes credit to its owner, not the agent.
    assert_eq!(award.source_owner, fixture.source);
    assert_eq!(award.beneficiary, fixture.beneficiary);
    assert_eq!(award.evidence_id, fixture.react);
    // The epoch is bound to the directory's own acceptance anchor.
    assert_eq!(award.activity_epoch, 90_000 / EPOCH);
}

#[test]
fn unsealed_or_conflicted_evidence_is_denied() {
    let mut fixture = support_fixture();
    let eligible = BTreeSet::from([fixture.source]);
    // A sealed non-reaction record is committed but is not support evidence.
    let view = ControlView::new(&fixture.archive, 60_000);
    let post_record = fixture
        .archive
        .records()
        .find(|r| r.id() == fixture.post)
        .unwrap()
        .clone();
    assert_eq!(
        assess_support(&post_record, &view, &eligible, EPOCH, 90_000, 100_000),
        Err(AwardDenial::NotSupport)
    );
    drop(view);
    // An up-reaction the owner never sealed is only provisional.
    let late = owner(&mut fixture.archive, 20);
    let unsealed = agent_social(
        &late,
        Operation::React {
            post: fixture.post,
            reaction: Reaction::Up(fixture.post),
            supersedes: References::default(),
        },
    );
    ingest(&mut fixture.archive, &unsealed);
    let view = ControlView::new(&fixture.archive, 60_000);
    let eligible_late = BTreeSet::from([late.id]);
    assert_eq!(
        assess_support(
            &verified(&unsealed),
            &view,
            &eligible_late,
            EPOCH,
            90_000,
            100_000
        ),
        Err(AwardDenial::NotCommitted)
    );
    drop(view);
    // A forked source owner's records become conflicted, never committed.
    let source_root = fixture
        .archive
        .records()
        .find_map(|r| match r.body() {
            Body::OwnerGenesis { .. }
                if OwnerId::from_bytes(*r.id().as_bytes()) == fixture.source =>
            {
                Some(r.id())
            }
            _ => None,
        })
        .unwrap();
    let fork = sign(
        Body::Control {
            owner: fixture.source,
            previous: source_root,
            action: ControlAction::Seal {
                realm: REALM,
                heads: References::default(),
            },
        },
        &SigningKey::from_bytes(&[10; 32]),
        None,
    );
    ingest(&mut fixture.archive, &fork);
    let view = ControlView::new(&fixture.archive, 60_000);
    assert_eq!(
        assess_support(
            &verified(&fixture.react_record),
            &view,
            &eligible,
            EPOCH,
            90_000,
            100_000
        ),
        Err(AwardDenial::NotCommitted)
    );
}

#[test]
fn downvotes_and_non_reactions_are_not_support() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let mut beneficiary = owner(&mut archive, 30);
    let post = owner_social(
        &beneficiary,
        Operation::Post {
            placement: Placement::Profile,
            text: Text::new("post").unwrap(),
            reply: None,
            quote: None,
        },
    );
    ingest(&mut archive, &post);
    let post_id = post.id();
    seal(&mut archive, &mut beneficiary, &[post_id]);
    let mut source = owner(&mut archive, 40);
    for reaction in [Reaction::Down(post_id), Reaction::Clear] {
        let down = agent_social(
            &source,
            Operation::React {
                post: post_id,
                reaction,
                supersedes: References::default(),
            },
        );
        ingest(&mut archive, &down);
        let id = down.id();
        seal(&mut archive, &mut source, &[id]);
        let view = ControlView::new(&archive, 60_000);
        let eligible = BTreeSet::from([source.id]);
        assert_eq!(
            assess_support(&verified(&down), &view, &eligible, EPOCH, 90_000, 100_000),
            Err(AwardDenial::NotSupport)
        );
    }
}

#[test]
fn post_resolution_self_support_and_eligibility_are_enforced() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let mut owner_a = owner(&mut archive, 50);
    // A committed reaction pointing at another reaction is not a post award.
    let post = owner_social(
        &owner_a,
        Operation::Post {
            placement: Placement::Profile,
            text: Text::new("p").unwrap(),
            reply: None,
            quote: None,
        },
    );
    ingest(&mut archive, &post);
    let first_react = agent_social(
        &owner_a,
        Operation::React {
            post: post.id(),
            reaction: Reaction::Up(post.id()),
            supersedes: References::default(),
        },
    );
    ingest(&mut archive, &first_react);
    // Reacting to the reaction record resolves to a non-post body.
    let meta = agent_social(
        &owner_a,
        Operation::React {
            post: first_react.id(),
            reaction: Reaction::Up(first_react.id()),
            supersedes: References::default(),
        },
    );
    ingest(&mut archive, &meta);
    seal(
        &mut archive,
        &mut owner_a,
        &[post.id(), first_react.id(), meta.id()],
    );
    let view = ControlView::new(&archive, 60_000);
    let eligible = BTreeSet::from([owner_a.id]);
    assert_eq!(
        assess_support(&verified(&meta), &view, &eligible, EPOCH, 90_000, 100_000),
        Err(AwardDenial::NotPost)
    );
    // Self-support and ineligible sources are denied even when committed.
    assert_eq!(
        assess_support(
            &verified(&first_react),
            &view,
            &eligible,
            EPOCH,
            90_000,
            100_000
        ),
        Err(AwardDenial::SelfSupport)
    );
    assert_eq!(
        assess_support(
            &verified(&first_react),
            &view,
            &BTreeSet::new(),
            EPOCH,
            90_000,
            100_000
        ),
        // Owner A reacting to owner A's post is self-support first.
        Err(AwardDenial::SelfSupport)
    );
    // An absent post target is unknown.
    let mut archive2 = Archive::new(REALM, limits()).unwrap();
    let mut source = owner(&mut archive2, 60);
    let ghost = agent_social(
        &source,
        Operation::React {
            post: RecordId::from_bytes([9; 32]),
            reaction: Reaction::Up(RecordId::from_bytes([9; 32])),
            supersedes: References::default(),
        },
    );
    ingest(&mut archive2, &ghost);
    let ghost_id = ghost.id();
    seal(&mut archive2, &mut source, &[ghost_id]);
    let view2 = ControlView::new(&archive2, 60_000);
    let eligible2 = BTreeSet::from([source.id]);
    assert_eq!(
        assess_support(
            &verified(&ghost),
            &view2,
            &eligible2,
            EPOCH,
            90_000,
            100_000
        ),
        Err(AwardDenial::UnknownPost)
    );
}

#[test]
fn the_epoch_binds_first_acceptance_not_the_record() {
    let fixture = support_fixture();
    let view = ControlView::new(&fixture.archive, 60_000);
    let eligible = BTreeSet::from([fixture.source]);
    let react = verified(&fixture.react_record);
    // The same committed record yields different epochs only through the
    // directory's own acceptance anchor — never through record timestamps.
    let early = assess_support(&react, &view, &eligible, EPOCH, 80_000, 100_000).unwrap();
    let late = assess_support(&react, &view, &eligible, EPOCH, 172_800, 200_000).unwrap();
    assert_eq!(early.activity_epoch, 0);
    assert_eq!(late.activity_epoch, 2);
    assert_eq!(early.evidence_id, late.evidence_id);
    // A future anchor and a zero epoch length are denied.
    assert_eq!(
        assess_support(&react, &view, &eligible, EPOCH, 200_000, 100_000),
        Err(AwardDenial::Epoch)
    );
    assert_eq!(
        assess_support(&react, &view, &eligible, 0, 90_000, 100_000),
        Err(AwardDenial::Epoch)
    );
}
