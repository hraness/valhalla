//! Signed adversarial projection fixtures; no fixture bypasses wire verification.
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use vhalla_core::{RealmId, RoomId};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    view::*,
    *,
};

const REALM: RealmId = RealmId(7);
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn refs(ids: &[RecordId]) -> References {
    References::sorted(ids.to_vec()).unwrap()
}
fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}
fn signed(body: Body, primary: &SigningKey, ack: Option<&SigningKey>) -> SignedRecord {
    let first = UnsignedRecord::new(primary.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(primary)
        .unwrap();
    match ack {
        Some(second) => first.countersign(second).unwrap(),
        None => first.finish().unwrap(),
    }
}
fn limits() -> Limits {
    Limits {
        records: 1024,
        control_reserve: 128,
        data_per_owner: 512,
        data_per_writer: 256,
        control_per_owner: 64,
        pending: 256,
        pending_per_signer: 128,
    }
}
struct Writer {
    actor: Actor,
    key: SigningKey,
    sequence: u64,
    previous: Option<RecordId>,
}
struct Fixture {
    archive: Archive,
    records: Vec<Vec<u8>>,
    owners: BTreeMap<OwnerId, (SigningKey, RecordId)>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            archive: Archive::new(REALM, limits()).unwrap(),
            records: Vec::new(),
            owners: BTreeMap::new(),
        }
    }
    fn push(&mut self, record: SignedRecord) -> RecordId {
        let id = record.id();
        let raw = record.encode();
        self.archive
            .ingest(&raw, &mut Budget::new(1, MAX_RECORD_BYTES).unwrap())
            .unwrap();
        self.records.push(raw);
        id
    }
    fn owner(&mut self, seed: u8) -> OwnerId {
        let secret = key(seed);
        let record = signed(
            Body::OwnerGenesis {
                controller: secret.verifying_key().to_bytes(),
                recovery: None,
                nonce: [seed; 32],
            },
            &secret,
            None,
        );
        let genesis = self.push(record);
        let owner = OwnerId::from_bytes(*genesis.as_bytes());
        self.owners.insert(owner, (secret, genesis));
        owner
    }
    fn control(&mut self, owner: OwnerId, action: ControlAction) -> RecordId {
        let (secret, previous) = self.owners[&owner].clone();
        let record = signed(
            Body::Control {
                owner,
                previous,
                action,
            },
            &secret,
            None,
        );
        let id = self.push(record);
        self.owners.get_mut(&owner).unwrap().1 = id;
        id
    }
    fn agent(&mut self, owner: OwnerId, seed: u8, rights: Rights) -> Writer {
        let (controller, control) = self.owners[&owner].clone();
        let secret = key(seed);
        let record = signed(
            Body::AgentGenesis {
                owner,
                control,
                key: secret.verifying_key().to_bytes(),
                nonce: [seed; 32],
            },
            &controller,
            Some(&secret),
        );
        let genesis = self.push(record);
        let agent = AgentId::from_bytes(*genesis.as_bytes());
        let grant = self.control(
            owner,
            ControlAction::Grant {
                agent,
                realm: REALM,
                rights,
                expires_at: 1000,
                nonce: [seed; 32],
            },
        );
        Writer {
            actor: Actor::Agent {
                owner,
                agent,
                grant,
            },
            key: secret,
            sequence: 0,
            previous: None,
        }
    }
    fn owner_writer(&self, owner: OwnerId) -> Writer {
        let (secret, control) = self.owners[&owner].clone();
        Writer {
            actor: Actor::Owner { owner, control },
            key: secret,
            sequence: 0,
            previous: None,
        }
    }
    fn emit(&mut self, writer: &mut Writer, operation: Operation) -> RecordId {
        let record = signed(
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
        let id = self.push(record);
        writer.previous = Some(id);
        writer.sequence += 1;
        id
    }
    fn seal(&mut self, owner: OwnerId, heads: &[RecordId]) {
        self.control(
            owner,
            ControlAction::Seal {
                realm: REALM,
                heads: refs(heads),
            },
        );
    }
}
fn post(placement: Placement, body: &str) -> Operation {
    Operation::Post {
        placement,
        text: text(body),
        reply: None,
        quote: None,
    }
}

#[test]
fn evaluation_basis_binds_all_limits_and_exposes_capacity_without_erasing_history() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let _agent = f.agent(owner, 2, Rights::ALL);
    let eligibility = Eligibility::default();
    let ordinary = View::new(&f.archive, 5, &eligibility);
    assert!(!ordinary.profile(owner).unwrap().capacity_blocked);
    let original = ordinary.basis();
    let snapshot = f.archive.snapshot();
    let baseline = limits();
    let mut variants = Vec::new();
    for field in 0..7 {
        let mut changed = baseline;
        match field {
            0 => changed.records += 1,
            1 => changed.control_reserve += 1,
            2 => changed.data_per_owner += 1,
            3 => changed.data_per_writer += 1,
            4 => changed.control_per_owner = 1,
            5 => changed.pending += 1,
            _ => changed.pending_per_signer += 1,
        }
        let archive = Archive::from_snapshot(REALM, changed, &snapshot).unwrap();
        let view = View::new(&archive, 5, &eligibility);
        assert_eq!(original.archive_root, view.basis().archive_root);
        assert_ne!(original.limits_digest, view.basis().limits_digest);
        assert_ne!(original.digest, view.basis().digest);
        assert_eq!(view.profile(owner).unwrap().capacity_blocked, field == 4);
        assert!(!view.profile(owner).unwrap().frozen);
        variants.push(view.basis().limits_digest);
    }
    assert_eq!(variants.iter().collect::<BTreeSet<_>>().len(), 7);
}
fn react(post: RecordId, reaction: Reaction, previous: &[RecordId]) -> Operation {
    Operation::React {
        post,
        reaction,
        supersedes: refs(previous),
    }
}
fn agent_id(writer: &Writer) -> AgentId {
    match writer.actor {
        Actor::Agent { agent, .. } => agent,
        _ => panic!("agent fixture"),
    }
}

#[test]
fn signed_profile_channel_threads_quotes_and_bios_preserve_attribution() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut alice = f.agent(a, 3, Rights::ALL);
    let mut bob = f.agent(b, 4, Rights::ALL);
    let mut controller = f.owner_writer(a);
    let owner_profile = f.emit(
        &mut controller,
        Operation::OwnerProfile {
            text: text("owner-written profile"),
            supersedes: refs(&[]),
        },
    );
    f.emit(
        &mut alice,
        Operation::AgentBio {
            text: text("<script>alert(1)</script> — plain foreign text"),
            supersedes: refs(&[]),
        },
    );
    let profile_root = f.emit(&mut alice, post(Placement::Profile, "profile conversation"));
    let channel = f.emit(
        &mut alice,
        post(Placement::Channel(RoomId(2)), "channel original"),
    );
    let response = f.emit(
        &mut bob,
        Operation::Post {
            placement: Placement::Profile,
            text: text("reply by another owner"),
            reply: Some(ReplyRef {
                root: profile_root,
                parent: PostRef {
                    post: profile_root,
                    revision: profile_root,
                },
            }),
            quote: None,
        },
    );
    let quote = f.emit(
        &mut bob,
        Operation::Post {
            placement: Placement::Profile,
            text: text("my commentary"),
            reply: None,
            quote: Some(PostRef {
                post: channel,
                revision: channel,
            }),
        },
    );
    let eligibility = Eligibility::default();
    assert_eq!(
        View::new(&f.archive, 10, &eligibility).state(channel),
        Some(RecordState::Provisional)
    );
    f.seal(a, &[owner_profile, channel]);
    f.seal(b, &[quote]);
    let view = View::new(&f.archive, 10, &eligibility);
    let profile = view.profile(a).unwrap();
    assert!(!profile.frozen);
    assert_eq!(profile.active_bios.known_total, 1);
    assert!(matches!(
        profile.profile.committed,
        Register::Resolved {
            value: "owner-written profile",
            ..
        }
    ));
    assert!(
        matches!(profile.active_bios.items[0].bio.committed, Register::Resolved { value, .. } if value.starts_with("<script>"))
    );
    assert_eq!(view.active_bios(a, 1, 1).unwrap().items.len(), 0);
    assert_eq!(view.active_bios(a, 0, 0), Err(Error::Bounds));
    assert_eq!(view.active_bios(a, 2, 1), Err(Error::Bounds));
    let thread = view.thread(profile_root).unwrap();
    assert_eq!(thread.len(), 2);
    let reply = view.post(response).unwrap();
    assert_eq!(reply.attribution.owner, b);
    assert_eq!(reply.profile_owner, Some(a));
    let quoted = view.post(quote).unwrap();
    assert_eq!(quoted.attribution.owner, b);
    assert_eq!(quoted.quote_attribution.unwrap().owner, a);
    assert_eq!(
        quoted.quote,
        Some(PostRef {
            post: channel,
            revision: channel
        })
    );
    assert_eq!(view.posts(Some(Placement::Channel(RoomId(2)))).len(), 1);
    assert_eq!(view.thread(response), Err(Error::Context));
}

#[test]
fn foreign_revision_parent_edit_and_grant_are_rejected_not_effective() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut alice = f.agent(a, 3, Rights::ALL);
    let mut bob = f.agent(b, 4, Rights::ALL);
    let original = f.emit(&mut alice, post(Placement::Profile, "original"));
    let unrelated = f.emit(&mut alice, post(Placement::Profile, "different original"));
    let wrong_revision = f.emit(&mut bob, react(original, Reaction::Up(unrelated), &[]));
    let unauthorized_edit = f.emit(
        &mut bob,
        Operation::Revise {
            post: original,
            text: text("stolen content"),
            supersedes: refs(&[original]),
        },
    );
    let wrong_parent = f.emit(
        &mut bob,
        Operation::Post {
            placement: Placement::Profile,
            text: text("forged ancestry"),
            reply: Some(ReplyRef {
                root: original,
                parent: PostRef {
                    post: unrelated,
                    revision: unrelated,
                },
            }),
            quote: None,
        },
    );
    let mut forged = f.owner_writer(b);
    let Actor::Agent { grant, .. } = alice.actor else {
        unreachable!()
    };
    forged.actor = Actor::Agent {
        owner: b,
        agent: agent_id(&bob),
        grant,
    };
    forged.key = bob.key.clone();
    let wrong_grant = f.emit(&mut forged, react(original, Reaction::Up(original), &[]));
    let policy = Eligibility::default();
    let view = View::new(&f.archive, 10, &policy);
    for id in [wrong_revision, unauthorized_edit, wrong_parent, wrong_grant] {
        assert_eq!(view.state(id), Some(RecordState::Rejected), "{id:?}");
    }
    assert!(matches!(
        view.reaction(b, original).unwrap().observed,
        Register::Empty
    ));
    assert_eq!(view.thread(original).unwrap().len(), 1);
}

#[test]
fn missing_admitted_heads_are_inert_but_unproved_owner_claims_cannot_poison_preferences() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut alice = f.agent(a, 3, Rights::ALL);
    let mut bob = f.agent(b, 4, Rights::ALL);
    let original = f.emit(&mut alice, post(Placement::Profile, "target"));
    let valid = f.emit(&mut bob, react(original, Reaction::Up(original), &[]));
    let mut stranger = Writer {
        actor: Actor::Agent {
            owner: b,
            agent: AgentId::from_bytes([77; 32]),
            grant: RecordId::from_bytes([78; 32]),
        },
        key: key(9),
        sequence: 0,
        previous: None,
    };
    let unproved = f.emit(
        &mut stranger,
        react(original, Reaction::Down(original), &[]),
    );
    let policy = Eligibility::default();
    let view = View::new(&f.archive, 10, &policy);
    assert_eq!(view.state(unproved), Some(RecordState::Pending));
    assert!(
        matches!(view.reaction(b, original).unwrap().observed, Register::Resolved { heads, value: Reaction::Up(_), .. } if heads == vec![valid])
    );
    let waiting = f.emit(
        &mut bob,
        react(original, Reaction::Clear, &[RecordId::from_bytes([90; 32])]),
    );
    let view = View::new(&f.archive, 10, &policy);
    assert_eq!(view.state(waiting), Some(RecordState::Pending));
    assert!(matches!(
        view.reaction(b, original).unwrap().observed,
        Register::Incomplete
    ));
}

#[test]
fn committed_dominance_crosses_provisional_context_without_committing_its_value() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut author = f.agent(a, 3, Rights::ALL);
    let mut one = f.agent(b, 4, Rights::REACT);
    let mut two = f.agent(b, 5, Rights::REACT);
    let mut three = f.agent(b, 6, Rights::REACT);
    let original = f.emit(&mut author, post(Placement::Profile, "target"));
    f.seal(a, &[original]);
    let first = f.emit(&mut one, react(original, Reaction::Up(original), &[]));
    let middle = f.emit(&mut two, react(original, Reaction::Up(original), &[first]));
    let last = f.emit(
        &mut three,
        react(original, Reaction::Down(original), &[middle]),
    );
    f.seal(b, &[first, last]);
    let policy = Eligibility::default();
    let view = View::new(&f.archive, 10, &policy);
    assert_eq!(view.state(middle), Some(RecordState::Provisional));
    assert!(
        matches!(view.reaction(b, original).unwrap().committed, Register::Resolved { heads, value: Reaction::Down(_), .. } if heads == vec![last])
    );
}

#[test]
fn committed_preferences_and_negative_history_survive_retraction_and_retirement() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut author = f.agent(a, 3, Rights::ALL);
    let mut voter = f.agent(b, 4, Rights::ALL);
    let positive = f.emit(&mut author, post(Placement::Profile, "liked"));
    let negative = f.emit(&mut author, post(Placement::Profile, "disliked"));
    f.seal(a, &[negative]);
    f.emit(&mut voter, react(positive, Reaction::Up(positive), &[]));
    f.emit(&mut voter, react(negative, Reaction::Down(negative), &[]));
    let followed = f.emit(
        &mut voter,
        Operation::Follow {
            target: a,
            following: true,
            supersedes: refs(&[]),
        },
    );
    f.seal(b, &[followed]);
    let policy = Eligibility::new(vec![b]).unwrap();
    assert_eq!(
        View::new(&f.archive, 10, &policy)
            .stats(a)
            .unwrap()
            .eligible_appreciation,
        Measured::Known(0)
    );
    f.emit(&mut author, Operation::Retract { post: negative });
    let edited = f.emit(
        &mut author,
        Operation::Revise {
            post: positive,
            text: text("replacement did not receive the earlier vote"),
            supersedes: refs(&[positive]),
        },
    );
    f.control(
        a,
        ControlAction::Retire {
            agent: agent_id(&author),
            realm: REALM,
            accepted: refs(&[edited]),
        },
    );
    f.control(
        b,
        ControlAction::Retire {
            agent: agent_id(&voter),
            realm: REALM,
            accepted: refs(&[followed]),
        },
    );
    let view = View::new(&f.archive, 10, &policy);
    assert_eq!(
        view.stats(a).unwrap().eligible_appreciation,
        Measured::Known(0)
    );
    assert!(matches!(
        view.post(negative).unwrap().observed,
        Content::Retracted { .. }
    ));
    assert_eq!(
        view.votes(PostRef {
            post: positive,
            revision: edited
        })
        .unwrap()
        .committed,
        Measured::Known(Tally { up: 0, down: 0 })
    );
    assert_eq!(
        view.votes(PostRef {
            post: positive,
            revision: positive
        })
        .unwrap()
        .committed,
        Measured::Known(Tally { up: 1, down: 0 })
    );
    assert!(matches!(
        view.follow(b, a).unwrap().committed,
        Register::Resolved { value: true, .. }
    ));
    assert_eq!(view.active_bios(a, 0, 1).unwrap().known_total, 0);
    let mut successor = f.agent(b, 5, Rights::FOLLOW);
    let removed = f.emit(
        &mut successor,
        Operation::Follow {
            target: a,
            following: false,
            supersedes: refs(&[followed]),
        },
    );
    f.seal(b, &[removed]);
    assert!(matches!(
        View::new(&f.archive, 10, &policy)
            .follow(b, a)
            .unwrap()
            .committed,
        Register::Resolved { value: false, .. }
    ));
}

#[test]
fn unknown_owners_have_no_ranking_weight_and_basis_covers_eligibility_and_time() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let c = f.owner(3);
    let mut author = f.owner_writer(a);
    let mut voter = f.owner_writer(b);
    let mut other = f.owner_writer(c);
    let original = f.emit(&mut author, post(Placement::Profile, "target"));
    f.seal(a, &[original]);
    let first = f.emit(&mut voter, react(original, Reaction::Up(original), &[]));
    f.seal(b, &[first]);
    let second = f.emit(&mut other, react(original, Reaction::Up(original), &[]));
    f.seal(c, &[second]);
    let empty = Eligibility::default();
    let one = Eligibility::new(vec![b]).unwrap();
    let unweighted = View::new(&f.archive, 10, &empty);
    let weighted = View::new(&f.archive, 10, &one);
    assert_eq!(
        unweighted.stats(a).unwrap().observed_appreciation,
        Measured::Known(2)
    );
    assert_eq!(
        unweighted.stats(a).unwrap().eligible_appreciation,
        Measured::Known(0)
    );
    assert_eq!(
        weighted.stats(a).unwrap().eligible_appreciation,
        Measured::Known(1)
    );
    assert_ne!(weighted.basis().digest, unweighted.basis().digest);
    assert_ne!(
        weighted.basis().digest,
        View::new(&f.archive, 11, &one).basis().digest
    );
    assert_eq!(
        weighted.basis().archive_root,
        unweighted.basis().archive_root
    );
    assert_eq!(Eligibility::new(vec![b, b]).err(), Some(Error::Bounds));
}

// Independent set oracle uses graph transitive closure, not the production
// register selection or value-reduction functions. It retains equal head IDs.
fn oracle(records: &[(RecordId, Reaction, Vec<RecordId>)]) -> (Vec<RecordId>, BTreeSet<Reaction>) {
    let index: BTreeMap<_, _> = records
        .iter()
        .map(|(id, value, parents)| (*id, (*value, parents)))
        .collect();
    let mut reach: BTreeSet<(RecordId, RecordId)> = records
        .iter()
        .flat_map(|(id, _, ps)| ps.iter().map(move |p| (*id, *p)))
        .collect();
    loop {
        let before = reach.len();
        let old: Vec<_> = reach.iter().copied().collect();
        for (a, b) in &old {
            for (c, d) in &old {
                if b == c {
                    reach.insert((*a, *d));
                }
            }
        }
        if reach.len() == before {
            break;
        }
    }
    let heads: Vec<_> = index
        .keys()
        .filter(|id| !reach.iter().any(|(_, ancestor)| ancestor == *id))
        .copied()
        .collect();
    let values = heads.iter().map(|id| index[id].0).collect();
    (heads, values)
}

#[test]
fn missing_sealed_history_is_scoped_unavailable_and_recovers_with_payload() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let writer = f.owner_writer(a);
    let delayed = signed(
        Body::Social {
            actor: writer.actor,
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: post(Placement::Profile, "delayed accepted post"),
        },
        &writer.key,
        None,
    );
    f.seal(a, &[delayed.id()]);
    let empty = Eligibility::default();
    let view = View::new(&f.archive, 10, &empty);
    assert_eq!(
        view.stats(a).unwrap().eligible_appreciation,
        Measured::Incomplete
    );
    assert!(!view.stats(a).unwrap().committed_history_complete);
    assert!(view.profile(a).unwrap().incomplete);
    assert_eq!(view.follow(a, b).unwrap().committed, Register::Incomplete);
    assert_eq!(
        view.stats(b).unwrap().eligible_appreciation,
        Measured::Known(0)
    );
    assert_eq!(view.profile(b).unwrap().profile.observed, Register::Empty);
    let explicit_unknown = Eligibility::new(vec![OwnerId::from_bytes([77; 32])]).unwrap();
    assert_eq!(
        View::new(&f.archive, 10, &explicit_unknown)
            .stats(b)
            .unwrap()
            .eligible_appreciation,
        Measured::Incomplete
    );
    f.push(delayed);
    let view = View::new(&f.archive, 10, &empty);
    assert_eq!(view.stats(a).unwrap().committed_posts, 1);
    assert!(view.stats(a).unwrap().committed_history_complete);
    assert_eq!(
        view.stats(a).unwrap().eligible_appreciation,
        Measured::Known(0)
    );
    assert_eq!(view.follow(a, b).unwrap().committed, Register::Empty);
}

#[test]
fn expired_external_context_disputes_sealed_cohort_without_erasing_negative() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let c = f.owner(3);
    let mut author = f.agent(a, 4, Rights::ALL);
    let mut parent_writer = f.agent(b, 5, Rights::ALL);
    let mut voter = f.agent(c, 6, Rights::ALL);
    let parent = f.emit(
        &mut parent_writer,
        post(Placement::Profile, "unsealed external context"),
    );
    let child = f.emit(
        &mut author,
        Operation::Post {
            placement: Placement::Profile,
            text: text("sealed quote"),
            reply: None,
            quote: Some(PostRef {
                post: parent,
                revision: parent,
            }),
        },
    );
    f.seal(a, &[child]);
    let down = f.emit(&mut voter, react(child, Reaction::Down(child), &[]));
    f.seal(c, &[down]);
    let eligible = Eligibility::new(vec![c]).unwrap();
    let before = View::new(&f.archive, 10, &eligible);
    assert_eq!(
        before.stats(a).unwrap().eligible_appreciation,
        Measured::Known(-1)
    );
    assert_eq!(before.stats(a).unwrap().committed_posts, 1);
    let after = View::new(&f.archive, 1001, &eligible);
    assert_eq!(after.state(parent), Some(RecordState::Rejected));
    assert_eq!(after.stats(a).unwrap().committed_posts, 1);
    assert_eq!(after.stats(a).unwrap().disputed_committed_posts, 1);
    assert!(!after.stats(a).unwrap().committed_history_complete);
    assert_eq!(
        after.stats(a).unwrap().eligible_appreciation,
        Measured::Incomplete
    );
}

#[test]
fn foreign_author_cannot_make_content_partial_with_missing_revision_heads() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut author = f.agent(a, 3, Rights::ALL);
    let mut foreign = f.agent(b, 4, Rights::ALL);
    let original = f.emit(&mut author, post(Placement::Profile, "authored"));
    f.seal(a, &[original]);
    let malicious = f.emit(
        &mut foreign,
        Operation::Revise {
            post: original,
            text: text("foreign"),
            supersedes: refs(&[RecordId::from_bytes([88; 32])]),
        },
    );
    f.seal(b, &[malicious]);
    let eligibility = Eligibility::default();
    let view = View::new(&f.archive, 10, &eligibility);
    assert_eq!(view.state(malicious), Some(RecordState::Rejected));
    assert!(
        matches!(view.post(original).unwrap().committed, Content::Present(Register::Resolved { value, .. }) if value.text == "authored")
    );
}

#[test]
fn controller_fork_disputes_but_preserves_owner_sealed_original_count() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut author = f.agent(owner, 2, Rights::ALL);
    let original = f.emit(
        &mut author,
        post(Placement::Profile, "durable sealed evidence"),
    );
    let (controller, previous) = f.owners[&owner].clone();
    f.seal(owner, &[original]);
    f.push(signed(
        Body::Control {
            owner,
            previous,
            action: ControlAction::Seal {
                realm: REALM,
                heads: refs(&[]),
            },
        },
        &controller,
        None,
    ));
    let eligibility = Eligibility::default();
    let view = View::new(&f.archive, 10, &eligibility);
    assert!(view.profile(owner).unwrap().frozen);
    assert_eq!(view.stats(owner).unwrap().committed_posts, 1);
    assert_eq!(view.stats(owner).unwrap().disputed_committed_posts, 1);
    assert_eq!(
        view.stats(owner).unwrap().eligible_appreciation,
        Measured::Incomplete
    );
}

#[test]
fn clear_unfollow_and_text_conflicts_have_explicit_concurrent_semantics() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut author = f.agent(a, 3, Rights::ALL);
    let mut one = f.agent(b, 4, Rights::ALL);
    let mut two = f.agent(b, 5, Rights::ALL);
    let original = f.emit(&mut author, post(Placement::Profile, "target"));
    f.seal(a, &[original]);
    f.emit(&mut one, react(original, Reaction::Up(original), &[]));
    f.emit(&mut two, react(original, Reaction::Clear, &[]));
    let follow = f.emit(
        &mut one,
        Operation::Follow {
            target: a,
            following: true,
            supersedes: refs(&[]),
        },
    );
    let unfollow = f.emit(
        &mut two,
        Operation::Follow {
            target: a,
            following: false,
            supersedes: refs(&[]),
        },
    );
    f.seal(b, &[follow, unfollow]);
    let mut profile_one = f.owner_writer(a);
    let text_one = f.emit(
        &mut profile_one,
        Operation::OwnerProfile {
            text: text("one"),
            supersedes: refs(&[]),
        },
    );
    f.seal(a, &[text_one]);
    let mut profile_two = f.owner_writer(a);
    let text_two = f.emit(
        &mut profile_two,
        Operation::OwnerProfile {
            text: text("two"),
            supersedes: refs(&[]),
        },
    );
    f.seal(a, &[text_two]);
    let eligible = Eligibility::new(vec![b]).unwrap();
    let view = View::new(&f.archive, 10, &eligible);
    assert!(
        matches!(view.reaction(b, original).unwrap().committed, Register::Resolved { heads, value: Reaction::Clear } if heads.len() == 2)
    );
    assert!(
        matches!(view.follow(b, a).unwrap().committed, Register::Resolved { heads, value: false } if heads.len() == 2)
    );
    assert!(
        matches!(view.profile(a).unwrap().profile.committed, Register::Conflict { heads, alternatives } if heads.len() == 2 && alternatives == vec!["one", "two"])
    );
    assert_eq!(
        view.stats(a).unwrap().eligible_appreciation,
        Measured::Known(0)
    );
}

#[test]
fn excess_heads_are_incomplete_until_explicit_causal_resolution() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut author = f.agent(a, 3, Rights::ALL);
    let original = f.emit(&mut author, post(Placement::Profile, "target"));
    f.seal(a, &[original]);
    let mut heads = Vec::new();
    let mut writers = Vec::new();
    for seed in 10..27 {
        let mut writer = f.agent(b, seed, Rights::REACT);
        heads.push(f.emit(&mut writer, react(original, Reaction::Up(original), &[])));
        writers.push(writer);
    }
    let eligible = Eligibility::new(vec![b]).unwrap();
    assert_eq!(
        View::new(&f.archive, 10, &eligible)
            .reaction(b, original)
            .unwrap()
            .observed,
        Register::Incomplete
    );
    let resolved = f.emit(
        &mut writers[0],
        react(original, Reaction::Up(original), &heads[..16]),
    );
    f.seal(b, &[resolved, heads[16]]);
    let view = View::new(&f.archive, 10, &eligible);
    assert!(
        matches!(view.reaction(b, original).unwrap().committed, Register::Resolved { heads, value: Reaction::Up(id) } if heads.len() == 2 && id == original)
    );
    assert_eq!(
        view.stats(a).unwrap().eligible_appreciation,
        Measured::Known(1)
    );
}

fn timeline_id(entry: &TimelineEntry<'_>) -> RecordId {
    match entry {
        TimelineEntry::Post(post) => post.id,
        TimelineEntry::Repost(repost) => repost.post,
    }
}

#[test]
fn timeline_discovers_profile_threads_and_exact_reposts_without_foreign_placement_leakage() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut alice = f.agent(a, 3, Rights::ALL);
    let mut bob = f.agent(b, 4, Rights::ALL);
    let own_profile = f.emit(&mut alice, post(Placement::Profile, "Alice profile"));
    let own_channel = f.emit(
        &mut alice,
        post(Placement::Channel(RoomId(9)), "not a profile post"),
    );
    let foreign_profile = f.emit(&mut bob, post(Placement::Profile, "Bob profile"));
    let source = f.emit(
        &mut bob,
        post(Placement::Channel(RoomId(8)), "reviewed source revision"),
    );
    let foreign_reply = f.emit(
        &mut bob,
        Operation::Post {
            placement: Placement::Profile,
            text: text("Bob replies on Alice's profile"),
            reply: Some(ReplyRef {
                root: own_profile,
                parent: PostRef {
                    post: own_profile,
                    revision: own_profile,
                },
            }),
            quote: None,
        },
    );
    let own_reply = f.emit(
        &mut alice,
        Operation::Post {
            placement: Placement::Profile,
            text: text("Alice replies on Bob's profile"),
            reply: Some(ReplyRef {
                root: foreign_profile,
                parent: PostRef {
                    post: foreign_profile,
                    revision: foreign_profile,
                },
            }),
            quote: None,
        },
    );
    f.seal(a, &[own_reply]);
    f.seal(b, &[foreign_reply]);
    let repost = f.emit(
        &mut alice,
        Operation::Repost {
            post: source,
            revision: Some(source),
            supersedes: refs(&[]),
        },
    );
    f.seal(a, &[repost]);
    let edit = f.emit(
        &mut bob,
        Operation::Revise {
            post: source,
            text: text("newer unendorsed text"),
            supersedes: refs(&[source]),
        },
    );
    f.seal(b, &[edit]);
    let policy = Eligibility::default();
    let view = View::new(&f.archive, 10, &policy);
    let complete = view.timeline(a, 0, 64).unwrap();
    assert_eq!(complete.known_total, 4);
    let ids = complete.items.iter().map(timeline_id).collect::<Vec<_>>();
    assert!(ids.windows(2).all(|ids| ids[0] < ids[1]));
    assert!(!ids.contains(&own_channel));
    assert!(!ids.contains(&foreign_profile));
    let foreign = complete
        .items
        .iter()
        .find(|v| timeline_id(v) == foreign_reply)
        .unwrap();
    assert!(
        matches!(foreign,TimelineEntry::Post(post) if post.attribution.owner==b && post.profile_owner==Some(a))
    );
    let reference = complete
        .items
        .iter()
        .find(|v| timeline_id(v) == source)
        .unwrap();
    assert!(
        matches!(reference,TimelineEntry::Repost(repost) if repost.owner==a && repost.attribution.unwrap().owner==b && !repost.source_incomplete && !repost.source_retracted && matches!(repost.preference.committed,Register::Resolved{value:Some(revision),..} if revision==source))
    );
    assert!(
        matches!(view.post(source).unwrap().observed,Content::Present(Register::Resolved{value,..}) if value.revision==edit)
    );
    let mut joined = Vec::new();
    let mut offset = 0;
    loop {
        let page = view.timeline(a, offset, 1).unwrap();
        assert_eq!(page.basis, complete.basis);
        joined.extend(page.items);
        let Some(next) = page.next_offset else { break };
        offset = next;
    }
    assert_eq!(joined, complete.items);
    assert!(view.timeline(a, 0, 0).is_err());
    assert!(view.timeline(a, 0, 65).is_err());
    assert!(view.timeline(a, 5, 1).is_err());
    assert!(view.timeline(OwnerId::from_bytes([99; 32]), 0, 1).is_err());
    assert!(view.timeline(a, 4, 1).unwrap().items.is_empty());
    let withdrawn = f.emit(&mut bob, Operation::Retract { post: source });
    f.seal(b, &[withdrawn]);
    let clear = f.emit(
        &mut alice,
        Operation::Repost {
            post: source,
            revision: None,
            supersedes: refs(&[repost]),
        },
    );
    let page = View::new(&f.archive, 10, &policy)
        .timeline(a, 0, 64)
        .unwrap();
    assert!(page.items.iter().any(|entry|matches!(entry,TimelineEntry::Repost(value) if value.post==source && value.source_retracted && matches!(value.preference.observed,Register::Resolved{value:None,..}) && matches!(value.preference.committed,Register::Resolved{value:Some(revision),..} if revision==source))));
    f.seal(a, &[clear]);
    assert!(!View::new(&f.archive, 10, &policy)
        .timeline(a, 0, 64)
        .unwrap()
        .items
        .iter()
        .any(|entry| matches!(entry, TimelineEntry::Repost(_))));
}

#[test]
fn timeline_keeps_missing_and_conflicting_sources_but_ignores_unproved_owner_claims() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let mut alice = f.agent(a, 3, Rights::ALL);
    let mut bob = f.agent(b, 4, Rights::ALL);
    let delayed = signed(
        Body::Social {
            actor: bob.actor,
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: post(Placement::Channel(RoomId(4)), "delayed source"),
        },
        &bob.key,
        None,
    );
    let source = delayed.id();
    f.emit(
        &mut alice,
        Operation::Repost {
            post: source,
            revision: Some(source),
            supersedes: refs(&[]),
        },
    );
    let stranger = key(90);
    f.push(signed(
        Body::Social {
            actor: Actor::Agent {
                owner: a,
                agent: AgentId::from_bytes([77; 32]),
                grant: RecordId::from_bytes([78; 32]),
            },
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: Operation::Repost {
                post: RecordId::from_bytes([79; 32]),
                revision: Some(RecordId::from_bytes([79; 32])),
                supersedes: refs(&[]),
            },
        },
        &stranger,
        None,
    ));
    let policy = Eligibility::default();
    let view = View::new(&f.archive, 10, &policy);
    let page = view.timeline(a, 0, 64).unwrap();
    assert_eq!(page.known_total, 1);
    assert!(
        matches!(&page.items[0],TimelineEntry::Repost(value) if value.post==source && value.attribution.is_none() && value.source_incomplete && value.preference.observed==Register::Incomplete)
    );
    f.push(delayed);
    bob.sequence = 1;
    bob.previous = Some(source);
    let view = View::new(&f.archive, 10, &policy);
    let page = view.timeline(a, 0, 64).unwrap();
    assert_eq!(page.known_total, 1);
    assert!(
        matches!(&page.items[0],TimelineEntry::Repost(value) if value.attribution.unwrap().owner==b && !value.source_incomplete && value.source_state==Some(RecordState::Provisional))
    );
    let revised = f.emit(
        &mut bob,
        Operation::Revise {
            post: source,
            text: text("another exact revision"),
            supersedes: refs(&[source]),
        },
    );
    let mut other = f.agent(a, 5, Rights::REPOST);
    f.emit(
        &mut other,
        Operation::Repost {
            post: source,
            revision: Some(revised),
            supersedes: refs(&[]),
        },
    );
    let view = View::new(&f.archive, 10, &policy);
    let page = view.timeline(a, 0, 64).unwrap();
    assert!(
        matches!(&page.items[0],TimelineEntry::Repost(value) if value.source_incomplete && matches!(&value.preference.observed,Register::Conflict{alternatives,..} if alternatives.len()==2 && alternatives.contains(&Some(source)) && alternatives.contains(&Some(revised))))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn signed_permutation_duplicates_and_equal_heads_match_independent_set_oracle(order in prop::collection::vec(any::<u8>(), 0..40)) {
        let mut f = Fixture::new(); let a = f.owner(1); let b = f.owner(2);
        let mut author = f.agent(a, 3, Rights::ALL); let mut one = f.agent(b, 4, Rights::REACT); let mut two = f.agent(b, 5, Rights::REACT);
        let original = f.emit(&mut author, post(Placement::Profile, "target")); f.seal(a, &[original]);
        let first = f.emit(&mut one, react(original, Reaction::Up(original), &[]));
        let equal = f.emit(&mut two, react(original, Reaction::Up(original), &[]));
        let policy = Eligibility::new(vec![b]).unwrap();
        let before = View::new(&f.archive, 10, &policy).reaction(b, original).unwrap();
        prop_assert!(matches!(before.observed, Register::Resolved { heads, .. } if heads.len() == 2), "equal values must retain both heads");
        let contrary = f.emit(&mut one, react(original, Reaction::Down(original), &[first]));
        f.seal(b, &[contrary, equal]);
        let expected = oracle(&[(first, Reaction::Up(original), vec![]), (equal, Reaction::Up(original), vec![]), (contrary, Reaction::Down(original), vec![first])]);
        let mut shuffled = Archive::new(REALM, limits()).unwrap();
        for index in order { let raw = &f.records[usize::from(index) % f.records.len()]; shuffled.ingest(raw, &mut Budget::new(1, MAX_RECORD_BYTES).unwrap()).unwrap(); }
        for raw in f.records.iter().rev() { shuffled.ingest(raw, &mut Budget::new(1, MAX_RECORD_BYTES).unwrap()).unwrap(); }
        let canonical = View::new(&f.archive, 10, &policy); let received = View::new(&shuffled, 10, &policy);
        prop_assert_eq!(canonical.basis(), received.basis());
        prop_assert_eq!(canonical.reaction(b, original).unwrap(), received.reaction(b, original).unwrap());
        match received.reaction(b, original).unwrap().committed {
            Register::Conflict { heads, alternatives } => { prop_assert_eq!(heads, expected.0); prop_assert_eq!(alternatives.into_iter().collect::<BTreeSet<_>>(), expected.1); },
            other => prop_assert!(false, "expected independent conflicting heads, got {other:?}"),
        }
        prop_assert_eq!(received.stats(a).unwrap().eligible_appreciation, Measured::Known(0));
    }
}
