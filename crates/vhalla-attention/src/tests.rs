//! Signed lifecycle and private attention regression fixtures.
use super::*;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use ed25519_dalek::SigningKey;
use hegel::generators as gs;
use hegel::TestCase;
use vhalla_social::{
    archive::{Budget, Limits},
    Actor, Body, ControlAction, Facet, FacetKind, FacetedText, MentionTarget, Operation, Placement,
    Reaction, References, ReplyRef, Rights, SignedRecord, Text, UnsignedRecord, MAX_RECORD_BYTES,
};

const REALM: RealmId = RealmId(23);
fn refs(ids: &[RecordId]) -> References {
    References::sorted(ids.to_vec()).unwrap()
}
fn sign(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> SignedRecord {
    let first = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    if let Some(ack) = ack {
        first.countersign(ack).unwrap()
    } else {
        first.finish().unwrap()
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
    owners: BTreeMap<OwnerId, (SigningKey, RecordId)>,
    raw: Vec<Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            archive: Archive::new(
                REALM,
                Limits {
                    records: 4096,
                    control_reserve: 256,
                    data_per_owner: 2048,
                    data_per_writer: 2048,
                    control_per_owner: 128,
                    pending: 1024,
                    pending_per_signer: 512,
                },
            )
            .unwrap(),
            owners: BTreeMap::new(),
            raw: Vec::new(),
        }
    }
    fn push(&mut self, record: SignedRecord) -> RecordId {
        let id = record.id();
        let raw = record.encode();
        self.archive
            .ingest(&raw, &mut Budget::new(1, MAX_RECORD_BYTES).unwrap())
            .unwrap();
        self.raw.push(raw);
        id
    }
    fn owner(&mut self, seed: u8) -> OwnerId {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let record = sign(
            Body::OwnerGenesis {
                controller: key.verifying_key().to_bytes(),
                recovery: None,
                nonce: [seed; 32],
            },
            &key,
            None,
        );
        let id = self.push(record);
        let owner = OwnerId::from_bytes(*id.as_bytes());
        self.owners.insert(owner, (key, id));
        owner
    }
    fn control(&mut self, owner: OwnerId, action: ControlAction) -> RecordId {
        let (key, previous) = self.owners[&owner].clone();
        let id = self.push(sign(
            Body::Control {
                owner,
                previous,
                action,
            },
            &key,
            None,
        ));
        self.owners.get_mut(&owner).unwrap().1 = id;
        id
    }
    fn agent(&mut self, owner: OwnerId, seed: u8) -> Writer {
        let (controller, control) = self.owners[&owner].clone();
        let key = SigningKey::from_bytes(&[seed; 32]);
        let id = self.push(sign(
            Body::AgentGenesis {
                owner,
                control,
                key: key.verifying_key().to_bytes(),
                nonce: [seed; 32],
            },
            &controller,
            Some(&key),
        ));
        let agent = AgentId::from_bytes(*id.as_bytes());
        let grant = self.control(
            owner,
            ControlAction::Grant {
                agent,
                realm: REALM,
                rights: Rights::ALL,
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
            key,
            sequence: 0,
            previous: None,
        }
    }
    fn emit(&mut self, writer: &mut Writer, operation: Operation) -> RecordId {
        let id = self.push(sign(
            Body::Social {
                actor: writer.actor,
                realm: REALM,
                sequence: writer.sequence,
                previous: writer.previous,
                operation,
            },
            &writer.key,
            None,
        ));
        writer.sequence += 1;
        writer.previous = Some(id);
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
    fn reader(&self, owner: OwnerId, agent: Option<AgentId>) -> ReaderScope {
        ReaderScope::new(&self.archive, 10, owner, agent, [0; 32], [0; 32]).unwrap()
    }
}
fn text(value: &str) -> Text {
    Text::new(value).unwrap()
}
fn mention(target: MentionTarget) -> FacetedText {
    FacetedText::new(
        text("@recipient hello"),
        vec![Facet {
            start: 0,
            end: 10,
            kind: FacetKind::Mention(target),
        }],
    )
    .unwrap()
}
fn post() -> Operation {
    Operation::Post {
        placement: Placement::Profile,
        text: text("base"),
        reply: None,
        quote: None,
    }
}
fn mentioned(target: MentionTarget) -> Operation {
    Operation::PostFaceted {
        placement: Placement::Profile,
        content: mention(target),
        reply: None,
        quote: None,
    }
}
fn selected(owners: Vec<OwnerId>) -> AttentionPolicy {
    let mut owners = owners;
    owners.sort();
    AttentionPolicy::new(owners, vec![], vec![], false).unwrap()
}
fn page(state: &Attention, f: &Fixture, policy: &AttentionPolicy) -> NotificationSnapshot {
    state.notifications(&f.archive, 10, policy, 0, 64).unwrap()
}

#[test]
fn all_reasons_are_derived_from_committed_signed_evidence_and_exact_attribution() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let source = f.owner(2);
    let mut rw = f.agent(recipient, 3);
    let mut sw = f.agent(source, 4);
    let root = f.emit(&mut rw, post());
    f.seal(recipient, &[root]);
    let target = PostRef {
        post: root,
        revision: root,
    };
    let reply = f.emit(
        &mut sw,
        Operation::PostFaceted {
            placement: Placement::Profile,
            content: mention(MentionTarget::Owner(recipient)),
            reply: Some(ReplyRef {
                root,
                parent: target,
            }),
            quote: Some(target),
        },
    );
    f.emit(
        &mut sw,
        Operation::Follow {
            target: recipient,
            following: true,
            supersedes: References::default(),
        },
    );
    f.emit(
        &mut sw,
        Operation::React {
            post: root,
            reaction: Reaction::Up(root),
            supersedes: References::default(),
        },
    );
    let repost = f.emit(
        &mut sw,
        Operation::Repost {
            post: root,
            revision: Some(root),
            supersedes: References::default(),
        },
    );
    f.seal(source, &[repost]);
    let state = Attention::new(f.reader(recipient, None));
    let policy = AttentionPolicy::new(vec![source], vec![], vec![root], false).unwrap();
    let shown = page(&state, &f, &policy);
    let reasons: BTreeSet<_> = shown
        .entries()
        .iter()
        .map(|entry| entry.update.group.reason)
        .collect();
    assert_eq!(
        reasons,
        BTreeSet::from([
            Reason::Mention,
            Reason::Reply,
            Reason::Follow,
            Reason::Reaction,
            Reason::Repost,
            Reason::Quote,
            Reason::WatchedThread
        ])
    );
    for entry in shown
        .entries()
        .iter()
        .filter(|entry| entry.source.owner == source)
    {
        assert_eq!(entry.source.actor, sw.actor);
        assert_eq!(entry.state, RecordState::Committed);
        assert!(f.archive.get(entry.update.event).is_some());
    }
    assert!(shown
        .entries()
        .iter()
        .any(|entry| entry.update.group.reason == Reason::Reply
            && entry.target == Some(target)
            && entry.source_post == Some(reply)));
    let read = state.acknowledge(&shown, &f.archive).unwrap();
    assert_eq!(page(&read, &f, &policy).counts(), Counts::default());
    assert_eq!(f.archive.snapshot(), f.archive.clone().snapshot());
}

#[test]
fn exact_read_and_group_priority_survive_edits_removal_readd_and_concurrent_revisions() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let source = f.owner(2);
    let mut writer = f.agent(source, 3);
    let root = f.emit(&mut writer, mentioned(MentionTarget::Owner(recipient)));
    f.seal(source, &[root]);
    let state = Attention::new(f.reader(recipient, None));
    let policy = selected(vec![source]);
    let first = page(&state, &f, &policy);
    let state = state.acknowledge(&first, &f.archive).unwrap();
    let removed = f.emit(
        &mut writer,
        Operation::ReviseFaceted {
            post: root,
            content: FacetedText::new(text("no mention"), vec![]).unwrap(),
            supersedes: refs(&[root]),
        },
    );
    f.seal(source, &[removed]);
    assert!(page(&state, &f, &policy).entries().is_empty());
    let readd = f.emit(
        &mut writer,
        Operation::ReviseFaceted {
            post: root,
            content: mention(MentionTarget::Owner(recipient)),
            supersedes: refs(&[removed]),
        },
    );
    let concurrent = f.emit(
        &mut writer,
        Operation::ReviseFaceted {
            post: root,
            content: mention(MentionTarget::Owner(recipient)),
            supersedes: refs(&[removed]),
        },
    );
    f.seal(source, &[concurrent]);
    let shown = page(&state, &f, &policy);
    assert_eq!(shown.entries().len(), 2);
    assert_eq!(shown.counts().unread_groups, 0);
    assert_eq!(shown.counts().unread_updates, 2);
    assert!(shown
        .entries()
        .iter()
        .all(|entry| entry.conflict && entry.priority.is_none()));
    assert_eq!(
        shown
            .entries()
            .iter()
            .map(|entry| entry.update.event)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([readd, concurrent])
    );
    assert!(shown.select(&[first.entries()[0].id()]).is_err());
    let read = state
        .acknowledge(
            &shown.select(&[shown.entries()[0].id()]).unwrap(),
            &f.archive,
        )
        .unwrap();
    assert_eq!(page(&read, &f, &policy).counts().unread_updates, 1);
    assert_eq!(read.generation(), 2);
    assert_eq!(
        read.acknowledge(
            &shown.select(&[shown.entries()[0].id()]).unwrap(),
            &f.archive
        )
        .unwrap()
        .generation(),
        2
    );
}

#[test]
fn live_provisional_promotion_and_terminal_lifecycle_do_not_duplicate_read_marks() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let source = f.owner(2);
    let mut writer = f.agent(source, 3);
    let event = f.emit(&mut writer, mentioned(MentionTarget::Owner(recipient)));
    let state = Attention::new(f.reader(recipient, None));
    let policy = selected(vec![source]);
    assert!(page(&state, &f, &policy).entries().is_empty());
    let live = AttentionPolicy::new(vec![source], vec![], vec![], true).unwrap();
    let shown = page(&state, &f, &live);
    assert_eq!(shown.entries()[0].state, RecordState::Provisional);
    let read = state.acknowledge(&shown, &f.archive).unwrap();
    f.seal(source, &[event]);
    let Actor::Agent { agent, grant, .. } = writer.actor else {
        unreachable!()
    };
    f.control(
        source,
        ControlAction::Revoke {
            grant,
            accepted: References::default(),
        },
    );
    f.control(
        source,
        ControlAction::Retire {
            agent,
            realm: REALM,
            accepted: References::default(),
        },
    );
    let later = read
        .notifications(&f.archive, 2000, &policy, 0, 64)
        .unwrap();
    assert_eq!(later.entries()[0].id(), shown.entries()[0].id());
    assert_eq!(later.counts(), Counts::default());
}

#[test]
fn owner_revision_mentions_report_actual_revision_signer_not_original_agent() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let source = f.owner(2);
    let mut agent = f.agent(source, 3);
    let root = f.emit(&mut agent, post());
    f.seal(source, &[root]);
    let (key, control) = f.owners[&source].clone();
    let actor = Actor::Owner {
        owner: source,
        control,
    };
    let mut writer = Writer {
        actor,
        key,
        sequence: 0,
        previous: None,
    };
    let revision = f.emit(
        &mut writer,
        Operation::ReviseFaceted {
            post: root,
            content: mention(MentionTarget::Owner(recipient)),
            supersedes: refs(&[root]),
        },
    );
    f.seal(source, &[revision]);
    let state = Attention::new(f.reader(recipient, None));
    let shown = page(&state, &f, &selected(vec![source]));
    assert_eq!(shown.entries().len(), 1);
    assert_eq!(shown.entries()[0].source.actor, actor);
    assert_ne!(shown.entries()[0].source.actor, agent.actor);
    assert_eq!(shown.entries()[0].source_post, Some(root));
    assert_eq!(shown.entries()[0].update.event, revision);
}

#[test]
fn typed_agent_mentions_route_to_historical_owner_and_siblings_keep_private_state() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let source = f.owner(2);
    let recipient_writer = f.agent(recipient, 3);
    let sibling_writer = f.agent(recipient, 4);
    let mut source_writer = f.agent(source, 5);
    let Actor::Agent { agent, .. } = recipient_writer.actor else {
        unreachable!()
    };
    let Actor::Agent { agent: sibling, .. } = sibling_writer.actor else {
        unreachable!()
    };
    f.control(
        recipient,
        ControlAction::Retire {
            agent,
            realm: REALM,
            accepted: References::default(),
        },
    );
    let event = f.emit(&mut source_writer, mentioned(MentionTarget::Agent(agent)));
    f.seal(source, &[event]);
    let first = Attention::new(f.reader(recipient, Some(agent)));
    let second = Attention::new(f.reader(recipient, Some(sibling)));
    let policy = selected(vec![source]);
    let shown = page(&first, &f, &policy);
    assert_eq!(shown.entries()[0].recipient_agents, vec![agent]);
    let read = first.acknowledge(&shown, &f.archive).unwrap();
    assert_eq!(page(&read, &f, &policy).counts().unread_updates, 0);
    assert_eq!(page(&second, &f, &policy).counts().unread_updates, 1);
    assert_eq!(
        Attention::decode(&read.encode(), second.reader()),
        Err(Error::Context)
    );
    assert!(ReaderScope::new(&f.archive, 10, source, Some(agent), [0; 32], [0; 32]).is_err());
}

#[test]
fn new_owner_recipient_gets_new_group_and_legacy_text_never_creates_identity_mentions() {
    let mut f = Fixture::new();
    let a = f.owner(1);
    let b = f.owner(2);
    let source = f.owner(3);
    let mut writer = f.agent(source, 4);
    let root = f.emit(&mut writer, mentioned(MentionTarget::Owner(a)));
    f.seal(source, &[root]);
    let state = Attention::new(f.reader(a, None));
    let policy = selected(vec![source]);
    let read = state
        .acknowledge(&page(&state, &f, &policy), &f.archive)
        .unwrap();
    let revision = f.emit(
        &mut writer,
        Operation::ReviseFaceted {
            post: root,
            content: mention(MentionTarget::Owner(b)),
            supersedes: refs(&[root]),
        },
    );
    let legacy = f.emit(
        &mut writer,
        Operation::Post {
            placement: Placement::Profile,
            text: text("@recipient hello"),
            reply: None,
            quote: None,
        },
    );
    f.seal(source, &[legacy]);
    assert!(page(&read, &f, &policy).entries().is_empty());
    let other = Attention::new(f.reader(b, None));
    let shown = page(&other, &f, &policy);
    assert_eq!(shown.entries().len(), 1);
    assert_eq!(shown.entries()[0].update.event, revision);
    assert_eq!(shown.counts().unread_groups, 1);
}

#[test]
fn clears_negative_activity_conflicts_and_muted_threads_never_create_priority() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let source = f.owner(2);
    let mut rw = f.agent(recipient, 3);
    let mut writer = f.agent(source, 4);
    let root = f.emit(&mut rw, post());
    f.seal(recipient, &[root]);
    let up = f.emit(
        &mut writer,
        Operation::React {
            post: root,
            reaction: Reaction::Up(root),
            supersedes: References::default(),
        },
    );
    let down = f.emit(
        &mut writer,
        Operation::React {
            post: root,
            reaction: Reaction::Down(root),
            supersedes: References::default(),
        },
    );
    f.seal(source, &[down]);
    let state = Attention::new(f.reader(recipient, None));
    let policy = selected(vec![source]);
    let conflicted = page(&state, &f, &policy);
    assert_eq!(conflicted.entries().len(), 2);
    assert!(conflicted
        .entries()
        .iter()
        .all(|entry| entry.conflict && entry.priority.is_none()));
    let clear = f.emit(
        &mut writer,
        Operation::React {
            post: root,
            reaction: Reaction::Clear,
            supersedes: refs(&[up, down]),
        },
    );
    f.seal(source, &[clear]);
    let shown = page(&state, &f, &policy);
    assert_eq!(shown.entries().len(), 1);
    assert!(!shown.entries()[0].positive);
    assert!(shown.entries()[0].priority.is_none());
    let muted = policy.with_muted_threads(vec![root]).unwrap();
    assert!(page(&state, &f, &muted).entries().is_empty());
}

#[test]
fn exact_selection_unread_filter_and_missing_source_ack_are_atomic() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let source = f.owner(2);
    let mut writer = f.agent(source, 3);
    for _ in 0..3 {
        f.emit(&mut writer, mentioned(MentionTarget::Owner(recipient)));
    }
    f.seal(source, &[writer.previous.unwrap()]);
    let state = Attention::new(f.reader(recipient, None));
    let policy = selected(vec![source]);
    let shown = page(&state, &f, &policy);
    let id = shown.entries()[0].id();
    assert!(shown.select(&[id, id]).is_err());
    assert!(shown.select(&[[0; 32]]).is_err());
    let selected = shown.select(&[id]).unwrap();
    let read = state.acknowledge(&selected, &f.archive).unwrap();
    let filtered = read
        .notifications_filtered(&f.archive, 10, &policy, true, 0, 1)
        .unwrap();
    assert_eq!(filtered.total(), 2);
    assert_eq!(filtered.entries().len(), 1);
    assert_ne!(filtered.entries()[0].id(), id);
    let empty = Archive::new(REALM, f.archive.limits()).unwrap();
    assert_eq!(
        state.acknowledge(&selected, &empty),
        Err(Error::MissingSource)
    );
    assert_eq!(read.unresolved_sources(&empty).unwrap(), 1);
    assert_eq!(
        Attention::decode(&read.encode(), read.reader()).unwrap(),
        read
    );
}

#[test]
fn per_owner_budget_does_not_consume_selected_lane_and_filters_keep_controls() {
    let mut f = Fixture::new();
    let recipient = f.owner(1);
    let known = f.owner(2);
    let unknown = f.owner(3);
    let mut noisy = f.agent(unknown, 4);
    let mut selected_writer = f.agent(known, 5);
    for _ in 0..40 {
        f.emit(&mut noisy, mentioned(MentionTarget::Owner(recipient)));
    }
    f.seal(unknown, &[noisy.previous.unwrap()]);
    let chosen = f.emit(
        &mut selected_writer,
        mentioned(MentionTarget::Owner(recipient)),
    );
    f.seal(known, &[chosen]);
    let state = Attention::new(f.reader(recipient, None));
    let shown = page(&state, &f, &selected(vec![known]));
    assert_eq!(shown.entries().len(), 33);
    assert!(shown.coverage().owner_limited);
    assert_eq!(shown.entries()[0].update.event, chosen);
    assert_eq!(shown.entries()[0].lane, Lane::Selected);
    let archive = f.archive.snapshot();
    let muted = AttentionPolicy::new(vec![known], vec![unknown], vec![], false).unwrap();
    assert_eq!(page(&state, &f, &muted).entries().len(), 1);
    assert_eq!(archive, f.archive.snapshot());
}

#[test]
fn bounded_private_marks_keep_group_witnesses_and_unknown_across_lane_changes() {
    // Private-state structural boundary fixture; source-derived admission is
    // independently exercised by signed fixtures above.
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let source = f.owner(2);
    let mut state = Attention::new(f.reader(owner, None));
    for n in 0..MAX_MARKS {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
        let event = RecordId::from_bytes(bytes);
        let group = Group {
            recipient: owner,
            source_owner: source,
            target: event,
            reason: Reason::Mention,
        };
        state.requests.groups.insert(group, event);
        state.requests.updates.insert(Update { group, event });
    }
    let before = state.required_sources();
    let forgotten = state.forget_exact_marks().unwrap();
    assert_eq!(forgotten.required_sources(), before);
    for (group, event) in &state.requests.groups {
        assert_eq!(
            forgotten.read(
                Update {
                    group: *group,
                    event: *event
                },
                Lane::Selected
            ),
            (ReadState::Read, ReadState::Unknown)
        );
    }
    assert_eq!(
        Attention::decode(&forgotten.encode(), forgotten.reader()).unwrap(),
        forgotten
    );
    assert!(forgotten.encode().len() <= MAX_STATE_BYTES);
    let mut newly_exact = forgotten.clone();
    newly_exact.requests.updates = state.requests.updates.clone();
    assert_eq!(newly_exact.required_sources(), forgotten.required_sources());
    assert_eq!(
        newly_exact.new_claim_sources(&forgotten).unwrap(),
        state.required_sources()
    );
    assert!(forgotten.new_claim_sources(&forgotten).unwrap().is_empty());
}

#[test]
fn unknown_precision_tracks_affected_source_owners_before_bounded_global_fallback() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let noisy = f.owner(2);
    let clean = f.owner(3);
    let mut state = Attention::new(f.reader(owner, None));
    let event = RecordId::from_bytes([9; 32]);
    let group = Group {
        recipient: owner,
        source_owner: noisy,
        target: event,
        reason: Reason::Mention,
    };
    state.requests.lose_group(noisy);
    state.requests.lose_update(noisy);
    assert_eq!(
        state.read(Update { group, event }, Lane::Selected),
        (ReadState::Unknown, ReadState::Unknown)
    );
    let clean_update = Update {
        group: Group {
            source_owner: clean,
            ..group
        },
        event,
    };
    assert_eq!(
        state.read(clean_update, Lane::Selected),
        (ReadState::Unread, ReadState::Unread)
    );
    for index in 0..=MAX_MARKS {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let source = OwnerId::from_bytes(bytes);
        state.requests.lose_group(source);
        state.requests.lose_update(source);
    }
    assert!(state.requests.groups_unknown && state.requests.updates_unknown);
    assert_eq!(state.requests.group_unknown_owners.len(), MAX_MARKS);
    assert_eq!(state.requests.update_unknown_owners.len(), MAX_MARKS);
    assert_eq!(
        state.read(clean_update, Lane::Selected),
        (ReadState::Unknown, ReadState::Unknown)
    );
    assert_eq!(
        Attention::decode(&state.encode(), state.reader()).unwrap(),
        state
    );
}

/// Reorder-and-replay ingest under Hegel's draw model: the generated order
/// permutes re-ingestion into a second archive, then a reversed replay
/// exercises dedup while the archive mutates across steps.
#[hegel::test(test_cases = 32)]
fn signed_archive_reordering_and_replay_produce_identical_notification_ids(tc: TestCase) {
    let order = tc.draw(gs::vecs(gs::integers::<u8>()).min_size(8).max_size(23));
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let source = f.owner(2);
    let mut writer = f.agent(source, 3);
    for _ in 0..4 {
        f.emit(&mut writer, mentioned(MentionTarget::Owner(owner)));
    }
    f.seal(source, &[writer.previous.unwrap()]);
    let state = Attention::new(f.reader(owner, None));
    let policy = selected(vec![source]);
    let expected = page(&state, &f, &policy);
    let mut records: Vec<_> = f.raw.iter().enumerate().collect();
    records.sort_by_key(|(index, _)| (order[*index % order.len()], core::cmp::Reverse(*index)));
    let mut other = Archive::new(REALM, f.archive.limits()).unwrap();
    for (_, raw) in records.iter().chain(records.iter().rev()) {
        other
            .ingest(raw, &mut Budget::new(1, MAX_RECORD_BYTES).unwrap())
            .unwrap();
    }
    let actual = state.notifications(&other, 10, &policy, 0, 64).unwrap();
    assert_eq!(expected.entries(), actual.entries());
    let read = state.acknowledge(&expected, &f.archive).unwrap();
    assert_eq!(
        read.notifications(&other, 10, &policy, 0, 64)
            .unwrap()
            .counts(),
        Counts::default()
    );
}

/// Private-state codec round-trip under a drawn mark count: each mark is
/// inserted inside a loop bounded by a generated occupancy.
#[hegel::test(test_cases = 32)]
fn private_roundtrip_unknown_and_decoder_damage_are_bounded(tc: TestCase) {
    let n = tc.draw(gs::integers::<usize>().max_value(MAX_MARKS - 1));
    let flip = tc.draw(gs::integers::<usize>().max_value(999));
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let source = f.owner(2);
    let mut state = Attention::new(f.reader(owner, None));
    for index in 0..n {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let event = RecordId::from_bytes(bytes);
        let group = Group {
            recipient: owner,
            source_owner: source,
            target: event,
            reason: Reason::Mention,
        };
        state.selected.groups.insert(group, event);
        state.selected.updates.insert(Update { group, event });
    }
    let bytes = state.encode();
    assert_eq!(&Attention::decode(&bytes, state.reader()).unwrap(), &state);
    let mut damaged = bytes.clone();
    let pos = flip % damaged.len();
    damaged[pos] ^= 1;
    assert!(Attention::decode(&damaged, state.reader()).is_err());
    let unknown = state.forget_exact_marks().unwrap();
    assert_eq!(unknown.required_sources(), state.required_sources());
}
