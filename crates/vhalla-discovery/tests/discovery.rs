//! Signed integration and generated private-state invariants.
use ed25519_dalek::SigningKey;
use hegel::generators as gs;
use hegel::TestCase;
use std::collections::{BTreeMap, BTreeSet};
use vhalla_core::{RealmId, RoomId};
use vhalla_discovery::{
    Budget, Change, DiscoverySnapshot, DiscoveryState, Error as DiscoveryError, FeedMode, Filters,
    Kind, Query, Subscription, Visibility,
};
use vhalla_social::{
    archive::{Archive, Budget as IngestBudget, Limits},
    view::{Eligibility, View},
    *,
};

const REALM: RealmId = RealmId(7);
struct Writer {
    key: SigningKey,
    actor: Actor,
    seq: u64,
    previous: Option<RecordId>,
}
struct Fixture {
    archive: Archive,
    owners: BTreeMap<OwnerId, (SigningKey, RecordId)>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            archive: Archive::new(
                REALM,
                Limits {
                    records: 1024,
                    control_reserve: 128,
                    data_per_owner: 512,
                    data_per_writer: 512,
                    control_per_owner: 64,
                    pending: 256,
                    pending_per_signer: 128,
                },
            )
            .unwrap(),
            owners: BTreeMap::new(),
        }
    }
    fn push(&mut self, body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> RecordId {
        let p = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
            .unwrap()
            .sign_with_key(key)
            .unwrap();
        let r = match ack {
            Some(k) => p.countersign(k).unwrap(),
            None => p.finish().unwrap(),
        };
        let id = r.id();
        self.archive
            .ingest(
                &r.encode(),
                &mut IngestBudget::new(1, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap();
        id
    }
    fn owner(&mut self, n: u8) -> OwnerId {
        let key = SigningKey::from_bytes(&[n; 32]);
        let id = self.push(
            Body::OwnerGenesis {
                controller: key.verifying_key().to_bytes(),
                recovery: None,
                nonce: [n; 32],
            },
            &key,
            None,
        );
        let owner = OwnerId::from_bytes(*id.as_bytes());
        self.owners.insert(owner, (key, id));
        owner
    }
    fn control(&mut self, owner: OwnerId, action: ControlAction) -> RecordId {
        let (key, previous) = self.owners[&owner].clone();
        let id = self.push(
            Body::Control {
                owner,
                previous,
                action,
            },
            &key,
            None,
        );
        self.owners.get_mut(&owner).unwrap().1 = id;
        id
    }
    fn writer(&self, owner: OwnerId) -> Writer {
        let (key, control) = self.owners[&owner].clone();
        Writer {
            key,
            actor: Actor::Owner { owner, control },
            seq: 0,
            previous: None,
        }
    }
    fn agent(&mut self, owner: OwnerId, n: u8, expiry: u64) -> Writer {
        let (controller, control) = self.owners[&owner].clone();
        let key = SigningKey::from_bytes(&[n; 32]);
        let id = self.push(
            Body::AgentGenesis {
                owner,
                control,
                key: key.verifying_key().to_bytes(),
                nonce: [n; 32],
            },
            &controller,
            Some(&key),
        );
        let agent = AgentId::from_bytes(*id.as_bytes());
        let grant = self.control(
            owner,
            ControlAction::Grant {
                agent,
                realm: REALM,
                rights: Rights::ALL,
                expires_at: expiry,
                nonce: [n; 32],
            },
        );
        Writer {
            key,
            actor: Actor::Agent {
                owner,
                agent,
                grant,
            },
            seq: 0,
            previous: None,
        }
    }
    fn emit(&mut self, w: &mut Writer, operation: Operation) -> RecordId {
        let id = self.push(
            Body::Social {
                actor: w.actor,
                realm: REALM,
                sequence: w.seq,
                previous: w.previous,
                operation,
            },
            &w.key,
            None,
        );
        w.seq += 1;
        w.previous = Some(id);
        id
    }
    fn seal(&mut self, owner: OwnerId, w: &Writer) {
        self.control(
            owner,
            ControlAction::Seal {
                realm: REALM,
                heads: References::new(vec![w.previous.unwrap()]).unwrap(),
            },
        );
    }
}
fn content(s: &str, target: Option<MentionTarget>) -> FacetedText {
    let mut facets = Vec::new();
    if let Some(target) = target {
        let start = s.find('@').unwrap();
        let end = s[start..].find(' ').map_or(s.len(), |n| start + n);
        facets.push(Facet {
            start: start as u16,
            end: end as u16,
            kind: FacetKind::Mention(target),
        });
    }
    for (i, _) in s.match_indices('#') {
        let end = s[i..].find(' ').map_or(s.len(), |n| i + n);
        facets.push(Facet {
            start: i as u16,
            end: end as u16,
            kind: FacetKind::Tag(CanonicalTag::new(&s[i + 1..end]).unwrap()),
        });
    }
    facets.sort();
    FacetedText::new(Text::new(s).unwrap(), facets).unwrap()
}
fn post(s: &str) -> Operation {
    Operation::PostFaceted {
        placement: Placement::Channel(RoomId(3)),
        content: content(s, None),
        reply: None,
        quote: None,
    }
}
fn reference(id: RecordId) -> PostRef {
    PostRef {
        post: id,
        revision: id,
    }
}

#[test]
fn signed_search_typed_facets_private_feedback_reposts_and_withdrawals() {
    let mut f = Fixture::new();
    let alice = f.owner(1);
    let bob = f.owner(2);
    let mut aw = f.writer(alice);
    let mut bw = f.writer(bob);
    let rust = f.emit(
        &mut aw,
        Operation::PostFaceted {
            placement: Placement::Channel(RoomId(3)),
            content: content("@b Rust WASM café #rust", Some(MentionTarget::Owner(bob))),
            reply: None,
            quote: None,
        },
    );
    let game = f.emit(&mut aw, post("Games #play"));
    f.seal(alice, &aw);
    f.emit(
        &mut bw,
        Operation::Repost {
            post: rust,
            revision: Some(rust),
            supersedes: References::default(),
        },
    );
    f.seal(bob, &bw);
    let e = Eligibility::default();
    let v = View::new(&f.archive, 10, &e);
    let mut state = DiscoveryState::new([8; 32]);
    state.observe(&v).unwrap();
    state.apply(Change::Wider(true)).unwrap();
    let snap = DiscoverySnapshot::new(&f.archive, &v, bob, &state, Visibility::Committed).unwrap();
    let filters = Filters {
        mention: Some(MentionTarget::Owner(bob)),
        tag: Some("rust".into()),
        ..Filters::default()
    };
    let result = snap
        .search(
            &Query::parse("wasm café").unwrap(),
            &filters,
            Budget::default(),
            64,
        )
        .unwrap();
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].owner, alice);
    assert_eq!(result.hits[0].reposted_by, vec![bob]);
    assert!(snap
        .search(
            &Query::parse("").unwrap(),
            &Filters {
                mention: Some(MentionTarget::Agent(AgentId::from_bytes(*bob.as_bytes()))),
                ..filters.clone()
            },
            Budget::default(),
            64
        )
        .unwrap()
        .hits
        .is_empty());
    assert!(snap
        .search(
            &Query::parse("CAFÉ").unwrap(),
            &Filters::default(),
            Budget::default(),
            64
        )
        .unwrap()
        .hits
        .is_empty());
    let before = state.encode();
    assert!(!state.seen(reference(rust)));
    assert_eq!(state.encode(), before);
    state.feedback(&v, reference(rust), 1).unwrap();
    let generation = state.generation();
    state.feedback(&v, reference(rust), 1).unwrap();
    assert_eq!(state.generation(), generation);
    let snap = DiscoverySnapshot::new(&f.archive, &v, bob, &state, Visibility::Committed).unwrap();
    assert_eq!(
        snap.feed(FeedMode::Discover, Budget::default(), 64)
            .unwrap()
            .hits[0]
            .reference,
        reference(rust)
    );
    state.feedback(&v, reference(rust), -1).unwrap();
    let snap = DiscoverySnapshot::new(&f.archive, &v, bob, &state, Visibility::Committed).unwrap();
    assert_eq!(
        snap.feed(FeedMode::Discover, Budget::default(), 64)
            .unwrap()
            .hits[0]
            .reference,
        reference(game)
    );
    state.mark_seen(&v, reference(rust)).unwrap();
    assert!(state.required_sources().contains(&rust));
    assert_eq!(
        DiscoveryState::decode(&state.encode(), [8; 32]).unwrap(),
        state
    );
    let ordinal = state.ordinal(rust);
    let mut aw = f.writer(alice);
    let revised = f.emit(
        &mut aw,
        Operation::ReviseFaceted {
            post: rust,
            content: content("Changed #other", None),
            supersedes: References::new(vec![rust]).unwrap(),
        },
    );
    f.seal(alice, &aw);
    let v = View::new(&f.archive, 11, &e);
    state.observe(&v).unwrap();
    assert_eq!(state.ordinal(rust), ordinal);
    let snap = DiscoverySnapshot::new(&f.archive, &v, bob, &state, Visibility::Committed).unwrap();
    assert!(snap
        .search(
            &Query::parse("WASM").unwrap(),
            &Filters::default(),
            Budget::default(),
            64
        )
        .unwrap()
        .hits
        .is_empty());
    let repost = snap
        .search(
            &Query::parse("WASM").unwrap(),
            &Filters {
                kind: Some(Kind::Repost),
                ..Filters::default()
            },
            Budget::default(),
            64,
        )
        .unwrap();
    assert_eq!(repost.hits[0].reference, reference(rust));
    assert_ne!(repost.hits[0].reference.revision, revised);
    let mut aw = f.writer(alice);
    f.emit(&mut aw, Operation::Retract { post: rust });
    f.seal(alice, &aw);
    let v = View::new(&f.archive, 12, &e);
    let snap = DiscoverySnapshot::new(&f.archive, &v, bob, &state, Visibility::Committed).unwrap();
    assert!(snap
        .search(
            &Query::parse("WASM").unwrap(),
            &Filters {
                kind: Some(Kind::Repost),
                ..Filters::default()
            },
            Budget::default(),
            64
        )
        .unwrap()
        .hits
        .is_empty());
    assert!(state.mark_seen(&v, reference(rust)).is_err());
}

#[test]
fn real_expiry_reclassifies_provisional_revision_and_cursor_returns_no_body() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.agent(owner, 2, 20);
    let original = f.emit(&mut w, post("old #rust"));
    f.seal(owner, &w);
    let revised = f.emit(
        &mut w,
        Operation::ReviseFaceted {
            post: original,
            content: content("temporary #rust", None),
            supersedes: References::new(vec![original]).unwrap(),
        },
    );
    let e = Eligibility::default();
    let v = View::new(&f.archive, 10, &e);
    let mut state = DiscoveryState::new([1; 32]);
    state.observe(&v).unwrap();
    let snap = DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Live).unwrap();
    let mut cursor = snap
        .cursor(
            Query::parse("").unwrap(),
            Filters::default(),
            None,
            Budget::default(),
        )
        .unwrap();
    assert_eq!(
        snap.search(
            &Query::parse("").unwrap(),
            &Filters::default(),
            Budget::default(),
            64
        )
        .unwrap()
        .hits[0]
            .reference
            .revision,
        revised
    );
    let later = View::new(&f.archive, 20, &e);
    let fresh =
        DiscoverySnapshot::new(&f.archive, &later, owner, &state, Visibility::Live).unwrap();
    assert_eq!(
        fresh
            .search(
                &Query::parse("").unwrap(),
                &Filters::default(),
                Budget::default(),
                64
            )
            .unwrap()
            .hits[0]
            .reference,
        reference(original)
    );
    assert!(matches!(
        cursor.page(&f.archive, &later, &state, 64),
        Err(DiscoveryError::Stale)
    ));
}

#[test]
fn more_than_sixty_four_results_cursor_and_partial_no_match_have_honest_coverage() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.writer(owner);
    for i in 0..90 {
        f.emit(&mut w, post(&format!("entry {i} #rust")));
    }
    f.seal(owner, &w);
    let e = Eligibility::default();
    let v = View::new(&f.archive, 10, &e);
    let mut state = DiscoveryState::new([1; 32]);
    state.observe(&v).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    let mut c = snap
        .cursor(
            Query::parse("").unwrap(),
            Filters::default(),
            None,
            Budget::default(),
        )
        .unwrap();
    assert_eq!(c.remaining(), 90);
    let first = c.page(&f.archive, &v, &state, 64).unwrap();
    let second = c.page(&f.archive, &v, &state, 64).unwrap();
    assert_eq!((first.hits.len(), second.hits.len()), (64, 26));
    assert_eq!((first.matches, second.matches, c.remaining()), (90, 90, 0));
    let ids: BTreeSet<_> = first
        .hits
        .iter()
        .chain(&second.hits)
        .map(|h| h.reference)
        .collect();
    assert_eq!(ids.len(), 90);
    let mut hinted: Vec<_> = second.hits.iter().map(|h| h.reference).collect();
    hinted.sort_unstable();
    let hydrated = snap
        .search_references(
            &Query::parse("").unwrap(),
            &Filters::default(),
            Budget::default(),
            &hinted,
        )
        .unwrap();
    assert_eq!(hydrated.matches, 26);
    assert_eq!(
        hydrated
            .hits
            .iter()
            .map(|h| h.reference)
            .collect::<Vec<_>>(),
        second.hits.iter().map(|h| h.reference).collect::<Vec<_>>()
    );
    assert!(hydrated.coverage.query_complete);
    let mut c = snap
        .cursor(
            Query::parse("").unwrap(),
            Filters::default(),
            None,
            Budget::default(),
        )
        .unwrap();
    c.skip(70);
    let skipped = c.page(&f.archive, &v, &state, 64).unwrap();
    assert_eq!((skipped.hits.len(), skipped.matches), (20, 90));
    let budget = Budget {
        documents: 3,
        ..Budget::default()
    };
    let none = snap
        .search(
            &Query::parse("absent").unwrap(),
            &Filters::default(),
            budget,
            64,
        )
        .unwrap();
    assert!(!none.coverage.query_complete);
    assert_eq!(none.coverage.examined, 3);
    assert_eq!(none.matches, 0);
    let partial = snap
        .search_references(
            &Query::parse("absent").unwrap(),
            &Filters::default(),
            budget,
            &hinted,
        )
        .unwrap();
    assert!(partial.hits.is_empty());
    assert!(!partial.coverage.query_complete);
    assert_eq!(partial.coverage.examined, 3);
    let fabricated = PostRef {
        post: RecordId::from_bytes([254; 32]),
        revision: RecordId::from_bytes([253; 32]),
    };
    assert!(snap
        .search_references(
            &Query::parse("").unwrap(),
            &Filters::default(),
            Budget::default(),
            &[fabricated]
        )
        .unwrap()
        .hits
        .is_empty());
    assert!(matches!(
        snap.search_references(
            &Query::parse("").unwrap(),
            &Filters::default(),
            Budget::default(),
            &[hinted[0], hinted[0]]
        ),
        Err(DiscoveryError::Bounds)
    ));
    let too_many: Vec<_> = ids.iter().take(65).copied().collect();
    assert!(matches!(
        snap.search_references(
            &Query::parse("").unwrap(),
            &Filters::default(),
            Budget::default(),
            &too_many
        ),
        Err(DiscoveryError::Bounds)
    ));
    let filtered = snap
        .search(
            &Query::parse("").unwrap(),
            &Filters {
                tag: Some("absent".into()),
                ..Filters::default()
            },
            budget,
            64,
        )
        .unwrap();
    assert!(!filtered.coverage.query_complete);
    assert_eq!(filtered.coverage.examined, 3);
    assert_eq!(snap.boards_page(0, 64).unwrap()[0].roots, 90);
    assert!(snap.boards_page(1, 64).unwrap().is_empty());
    assert_eq!(snap.directory_page(0, 1).unwrap(), vec![owner]);
    assert!(snap.directory_page(1, 1).unwrap().is_empty());
    let mut altered = state.clone();
    altered.apply(Change::MuteOwner(owner, true)).unwrap();
    assert!(matches!(
        c.page(&f.archive, &v, &altered, 64),
        Err(DiscoveryError::Stale)
    ));
}

#[test]
fn state_policy_mismatch_hidden_content_and_no_implicit_private_mutation() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.writer(owner);
    let p = f.emit(&mut w, post("hello #rust"));
    f.seal(owner, &w);
    let e = Eligibility::default();
    let v = View::new(&f.archive, 1, &e);
    let mut state = DiscoveryState::new([1; 32]);
    let snapshot = f.archive.snapshot();
    let mut limits = f.archive.limits();
    limits.pending_per_signer -= 1;
    let wrong = Archive::from_snapshot(REALM, limits, &snapshot).unwrap();
    assert!(matches!(
        DiscoverySnapshot::new(&wrong, &v, owner, &state, Visibility::Committed),
        Err(DiscoveryError::Evidence)
    ));
    state.observe(&v).unwrap();
    let bytes = state.encode();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    snap.search(
        &Query::parse("").unwrap(),
        &Filters::default(),
        Budget::default(),
        64,
    )
    .unwrap();
    assert_eq!(state.encode(), bytes);
    assert!(!state.seen(reference(p)));
    state.apply(Change::MuteOwner(owner, true)).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    assert!(snap
        .search(
            &Query::parse("").unwrap(),
            &Filters::default(),
            Budget::default(),
            64
        )
        .unwrap()
        .hits
        .is_empty());
    assert_eq!(f.archive.snapshot(), snapshot);
}

#[test]
fn cursor_requires_refresh_after_five_minutes_even_with_unchanged_evidence() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.writer(owner);
    f.emit(&mut w, post("stable #rust"));
    f.seal(owner, &w);
    let e = Eligibility::default();
    let initial = View::new(&f.archive, 10, &e);
    let state = DiscoveryState::new([1; 32]);
    let snap =
        DiscoverySnapshot::new(&f.archive, &initial, owner, &state, Visibility::Committed).unwrap();
    let freeze = || {
        snap.cursor(
            Query::parse("").unwrap(),
            Filters::default(),
            None,
            Budget::default(),
        )
        .unwrap()
    };
    let mut accepted = freeze();
    let mut expired = freeze();
    let boundary = View::new(
        &f.archive,
        10 + vhalla_discovery::MAX_CURSOR_AGE_SECONDS,
        &e,
    );
    assert_eq!(
        accepted
            .page(&f.archive, &boundary, &state, 64)
            .unwrap()
            .hits
            .len(),
        1
    );
    let late = View::new(
        &f.archive,
        11 + vhalla_discovery::MAX_CURSOR_AGE_SECONDS,
        &e,
    );
    assert!(matches!(
        expired.page(&f.archive, &late, &state, 64),
        Err(DiscoveryError::Stale)
    ));
    assert_eq!(expired.remaining(), 1);
    let past = View::new(&f.archive, 9, &e);
    assert!(matches!(
        accepted.page(&f.archive, &past, &state, 64),
        Err(DiscoveryError::Clock)
    ));
}

#[test]
fn bookmark_learning_reset_preserves_bookmarks_and_duplicate_facets_do_not_amplify() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.writer(owner);
    let one = f.emit(&mut w, post("one #rust"));
    let repeated = f.emit(&mut w, post("repeated #rust #rust #rust"));
    f.seal(owner, &w);
    let e = Eligibility::default();
    let v = View::new(&f.archive, 10, &e);
    let mut state = DiscoveryState::new([3; 32]);
    state.apply(Change::Bookmark(reference(one), true)).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    let feed = snap
        .feed(FeedMode::Discover, Budget::default(), 64)
        .unwrap();
    assert!(feed.hits.iter().all(|h| h.why[2] == 16));
    state.apply(Change::ClearInterests).unwrap();
    assert!(state.preferences().bookmarks().contains(&reference(one)));
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    assert!(snap
        .feed(FeedMode::Discover, Budget::default(), 64)
        .unwrap()
        .hits
        .iter()
        .all(|h| h.why[2] == 0));
    assert_eq!(
        DiscoveryState::decode(&state.encode(), [3; 32]).unwrap(),
        state
    );
    state.feedback(&v, reference(repeated), -1).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    assert!(snap
        .feed(FeedMode::Discover, Budget::default(), 64)
        .unwrap()
        .hits
        .iter()
        .all(|h| h.why[2] == -16));
    state
        .apply(Change::Interest {
            tag: "rust".into(),
            delta: -4,
        })
        .unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    assert!(snap
        .feed(FeedMode::Discover, Budget::default(), 64)
        .unwrap()
        .hits
        .iter()
        .all(|h| h.why[2] == -64));
}

#[test]
fn distinct_new_claim_requires_durable_source_even_when_an_old_observation_used_same_id() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.writer(owner);
    let post = f.emit(&mut w, post("hello #rust"));
    f.seal(owner, &w);
    let e = Eligibility::default();
    let view = View::new(&f.archive, 10, &e);
    let mut previous = DiscoveryState::new([1; 32]);
    previous.observe(&view).unwrap();
    assert!(previous.required_sources().contains(&post));
    let mut next = previous.clone();
    next.mark_seen(&view, reference(post)).unwrap();
    assert_eq!(next.required_sources(), previous.required_sources());
    assert_eq!(next.new_claim_sources(&previous).unwrap(), vec![post]);
    assert!(next.new_claim_sources(&next).unwrap().is_empty());
    let previous = next.clone();
    next.feedback(&view, reference(post), 1).unwrap();
    assert_eq!(next.new_claim_sources(&previous).unwrap(), vec![post]);
    let previous = next.clone();
    next.feedback(&view, reference(post), -1).unwrap();
    assert_eq!(next.new_claim_sources(&previous).unwrap(), vec![post]);
    assert!(next
        .new_claim_sources(&DiscoveryState::new([2; 32]))
        .is_err());
}

#[test]
fn committed_follow_selection_mute_repost_sources_and_page_diversity() {
    let mut f = Fixture::new();
    let alice = f.owner(1);
    let bob = f.owner(2);
    let reader = f.owner(3);
    let mut a = f.writer(alice);
    let mut b = f.writer(bob);
    let mut r = f.writer(reader);
    let source = f.emit(&mut a, post("source #rust"));
    for n in 0..4 {
        f.emit(&mut a, post(&format!("other {n} #rust")));
    }
    f.seal(alice, &a);
    f.emit(
        &mut b,
        Operation::Repost {
            post: source,
            revision: Some(source),
            supersedes: References::default(),
        },
    );
    f.seal(bob, &b);
    f.emit(
        &mut r,
        Operation::Follow {
            target: bob,
            following: true,
            supersedes: References::default(),
        },
    );
    let e = Eligibility::default();
    let provisional = View::new(&f.archive, 10, &e);
    let state = DiscoveryState::new([3; 32]);
    let snap = DiscoverySnapshot::new(
        &f.archive,
        &provisional,
        reader,
        &state,
        Visibility::Committed,
    )
    .unwrap();
    assert!(snap
        .feed(FeedMode::Following, Budget::default(), 64)
        .unwrap()
        .hits
        .is_empty());
    f.seal(reader, &r);
    let v = View::new(&f.archive, 10, &e);
    let mut state = state;
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, reader, &state, Visibility::Committed).unwrap();
    assert_eq!(
        snap.feed(FeedMode::Following, Budget::default(), 64)
            .unwrap()
            .hits
            .len(),
        1
    );
    state.apply(Change::MuteOwner(bob, true)).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, reader, &state, Visibility::Committed).unwrap();
    assert!(snap
        .feed(FeedMode::Following, Budget::default(), 64)
        .unwrap()
        .hits
        .is_empty());
    state.apply(Change::Wider(true)).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, reader, &state, Visibility::Committed).unwrap();
    assert_eq!(
        snap.feed(FeedMode::Discover, Budget::default(), 64)
            .unwrap()
            .hits
            .len(),
        2
    );
    let mut cursor = snap
        .cursor(
            Query::parse("").unwrap(),
            Filters::default(),
            Some(FeedMode::Discover),
            Budget::default(),
        )
        .unwrap();
    assert_eq!(
        cursor.page(&f.archive, &v, &state, 64).unwrap().hits.len(),
        2
    );
    assert_eq!(
        cursor.page(&f.archive, &v, &state, 64).unwrap().hits.len(),
        2
    );
    assert_eq!(
        cursor.page(&f.archive, &v, &state, 64).unwrap().hits.len(),
        1
    );
}

#[test]
fn discover_over_sixty_four_preserves_owner_and_root_diversity_on_every_page() {
    let mut f = Fixture::new();
    let reader = f.owner(40);
    for n in 1..=35 {
        let owner = f.owner(n);
        let mut w = f.writer(owner);
        let root = f.emit(&mut w, post("root #rust"));
        f.emit(&mut w, post("second root #rust"));
        f.emit(&mut w, post("third root #rust"));
        f.emit(
            &mut w,
            Operation::PostFaceted {
                placement: Placement::Channel(RoomId(3)),
                content: content("reply #rust", None),
                reply: Some(ReplyRef {
                    root,
                    parent: reference(root),
                }),
                quote: None,
            },
        );
        f.seal(owner, &w);
    }
    let e = Eligibility::default();
    let v = View::new(&f.archive, 10, &e);
    let mut state = DiscoveryState::new([40; 32]);
    state.observe(&v).unwrap();
    state.apply(Change::Wider(true)).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, reader, &state, Visibility::Committed).unwrap();
    let direct = snap
        .feed(FeedMode::Discover, Budget::default(), 64)
        .unwrap();
    let mut cursor = snap
        .cursor(
            Query::parse("").unwrap(),
            Filters::default(),
            Some(FeedMode::Discover),
            Budget::default(),
        )
        .unwrap();
    let mut all = BTreeSet::new();
    let mut pages = 0;
    while cursor.remaining() != 0 {
        let page = cursor.page(&f.archive, &v, &state, 64).unwrap();
        assert!(page.coverage.query_complete);
        assert_eq!(page.matches, 140);
        assert!(!page.hits.is_empty());
        assert!(page.hits.len() <= 64);
        if pages == 0 {
            assert_eq!(
                page.hits.iter().map(|h| h.reference).collect::<Vec<_>>(),
                direct.hits.iter().map(|h| h.reference).collect::<Vec<_>>(),
            );
        }
        let mut owners = BTreeMap::new();
        let mut roots = BTreeSet::new();
        for hit in &page.hits {
            let count = owners.entry(hit.owner).or_insert(0);
            *count += 1;
            assert!(*count <= 2);
            assert!(roots.insert(hit.root));
            assert!(all.insert(hit.reference));
        }
        pages += 1;
        assert!(pages <= 4);
    }
    assert!(pages > 2);
    assert_eq!(all.len(), 140);
}

#[test]
fn repost_source_metadata_is_charged_even_without_text_matching() {
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.writer(owner);
    let post = f.emit(&mut w, post("hello"));
    f.seal(owner, &w);
    for n in 2..=9 {
        let reposter = f.owner(n);
        let mut w = f.writer(reposter);
        f.emit(
            &mut w,
            Operation::Repost {
                post,
                revision: Some(post),
                supersedes: References::default(),
            },
        );
        f.seal(reposter, &w);
    }
    let e = Eligibility::default();
    let v = View::new(&f.archive, 10, &e);
    let state = DiscoveryState::new([1; 32]);
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    let budget = Budget {
        steps: 767,
        ..Budget::default()
    };
    let page = snap
        .search(&Query::parse("").unwrap(), &Filters::default(), budget, 64)
        .unwrap();
    assert!(!page.coverage.query_complete);
    assert_eq!((page.matches, page.coverage.examined), (0, 0));
    let budget = Budget {
        steps: 768,
        ..Budget::default()
    };
    let page = snap
        .search(&Query::parse("").unwrap(), &Filters::default(), budget, 64)
        .unwrap();
    assert!(page.coverage.query_complete);
    assert_eq!((page.matches, page.coverage.steps), (1, 768));
    assert_eq!(page.hits[0].reposted_by.len(), 8);
}

/// Signed search against an independent oracle under Hegel's interleaved draw
/// model: each post is drawn inside the loop while the archive and writer
/// mutate across steps.
#[hegel::test(test_cases = 32)]
fn signed_search_matches_an_exhaustive_literal_and_filter_oracle(tc: TestCase) {
    let texts = [
        "root café #rust",
        "RUST wasm #rust",
        "cafÉ root #play",
        "α root",
        "absent #play",
        "root café rust #play",
    ];
    let queries = ["rust", "café", "CAFÉ", "α", "\"root café\"", "root rust"];
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(19));
    let query = tc.draw(gs::integers::<usize>().max_value(5));
    let filter = tc.draw(gs::integers::<usize>().max_value(3));
    let terms: &[&str] = match query {
        0 => &["rust"],
        1 => &["café"],
        2 => &["CAFÉ"],
        3 => &["α"],
        4 => &["root café"],
        _ => &["root", "rust"],
    };
    let mut f = Fixture::new();
    let owner = f.owner(1);
    let mut w = f.writer(owner);
    let mut inputs = Vec::new();
    for _ in 0..steps {
        let which = tc.draw(gs::integers::<usize>().max_value(5));
        inputs.push((f.emit(&mut w, post(texts[which])), texts[which]));
    }
    f.seal(owner, &w);
    let e = Eligibility::default();
    let v = View::new(&f.archive, 10, &e);
    let mut state = DiscoveryState::new([1; 32]);
    state.observe(&v).unwrap();
    let snap =
        DiscoverySnapshot::new(&f.archive, &v, owner, &state, Visibility::Committed).unwrap();
    let filters = match filter {
        0 => Filters::default(),
        1 => Filters {
            tag: Some("rust".into()),
            ..Filters::default()
        },
        2 => Filters {
            reply: Some(true),
            ..Filters::default()
        },
        _ => Filters {
            channel: Some(RoomId(99)),
            ..Filters::default()
        },
    };
    // Independent std substring oracle with known fixture tag/placement data.
    // It does not call Query::matches, candidate matching or ranking helpers.
    let mut expected: Vec<_> = inputs
        .into_iter()
        .filter(|(_, text)| {
            let folded = text.to_ascii_lowercase();
            terms
                .iter()
                .all(|term| folded.contains(&term.to_ascii_lowercase()))
                && match filter {
                    0 => true,
                    1 => text.contains("#rust"),
                    _ => false,
                }
        })
        .map(|(id, _)| reference(id))
        .collect();
    expected.sort_by_key(|r| (core::cmp::Reverse(state.ordinal(r.post)), *r));
    let actual = snap
        .search(
            &Query::parse(queries[query]).unwrap(),
            &filters,
            Budget::default(),
            64,
        )
        .unwrap();
    assert!(actual.coverage.query_complete);
    assert_eq!(actual.matches, expected.len());
    assert_eq!(
        actual.hits.iter().map(|h| h.reference).collect::<Vec<_>>(),
        expected
    );
}

/// Private codec round-trip under a generated change sequence: each preference
/// change is drawn inside the loop while the state mutates across steps.
#[hegel::test(test_cases = 80)]
fn private_codec_idempotent_bounded_preferences_roundtrip(tc: TestCase) {
    let mut state = DiscoveryState::new([7; 32]);
    let steps = tc.draw(gs::integers::<usize>().max_value(99));
    for _ in 0..steps {
        let kind = tc.draw(gs::integers::<u8>().max_value(4));
        let n = tc.draw(gs::integers::<u8>().max_value(19));
        let yes = tc.draw(gs::booleans());
        let id = [n; 32];
        let change = match kind {
            0 => Change::Subscribe(Subscription::Owner(OwnerId::from_bytes(id)), yes),
            1 => Change::MuteOwner(OwnerId::from_bytes(id), yes),
            2 => Change::BlockOwner(OwnerId::from_bytes(id), yes),
            3 => Change::Subscribe(Subscription::Tag(format!("tag{n}")), yes),
            _ => Change::Wider(yes),
        };
        state.apply(change.clone()).unwrap();
        let gen = state.generation();
        state.apply(change).unwrap();
        assert_eq!(state.generation(), gen);
    }
    let raw = state.encode();
    assert_eq!(DiscoveryState::decode(&raw, [7; 32]).unwrap(), state);
    assert!(DiscoveryState::decode(&raw, [8; 32]).is_err());
    for n in [0, 1, 7, 8, 31, raw.len() - 1] {
        assert!(DiscoveryState::decode(&raw[..n], [7; 32]).is_err());
    }
    let mut trailing = raw;
    trailing.push(0);
    assert!(DiscoveryState::decode(&trailing, [7; 32]).is_err());
}
