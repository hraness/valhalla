use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use vhalla_social_attention_spike::*;

fn id(n: u8) -> Id {
    [n; 32]
}
fn reader() -> Reader {
    Reader {
        realm: id(1),
        owner: id(2),
        agent: Some(id(3)),
        profile: id(4),
        device: id(5),
    }
}
fn group(n: u8) -> Group {
    Group {
        recipient: reader().owner,
        source_owner: id(7),
        target: id(n),
        reason: Reason::Mention,
    }
}
fn fact(target: u8, revision: u8) -> Fact {
    Fact {
        update: Update {
            group: group(target),
            event: id(revision),
        },
        state: State::Committed,
        active: true,
        priority: true,
    }
}
fn durable(facts: &[Fact]) -> Durable {
    Durable::model_fixture(
        reader().realm,
        id(42),
        &facts.iter().map(|f| f.update.event).collect::<Vec<_>>(),
    )
    .unwrap()
}
fn state() -> Attention {
    Attention::new(reader(), 128).unwrap()
}
fn snapshot(state: &Attention, facts: &[Fact]) -> Snapshot {
    state
        .snapshot(&durable(facts), facts, false, 0, MAX_PAGE)
        .unwrap()
}
fn ack(state: &Attention, facts: &[Fact]) -> Attention {
    state
        .acknowledge(&snapshot(state, facts), &durable(facts))
        .unwrap()
}

#[test]
fn committed_default_and_provisional_promotion_have_one_exact_identity() {
    let committed = fact(10, 11);
    let provisional = Fact {
        state: State::Provisional,
        ..committed
    };
    let pending = Fact {
        state: State::Pending,
        ..committed
    };
    let state = state();
    assert!(snapshot(&state, &[provisional]).entries().is_empty());
    assert!(snapshot(&state, &[pending]).entries().is_empty());
    let live = state
        .snapshot(&durable(&[provisional]), &[provisional], true, 0, 64)
        .unwrap();
    let read = state.acknowledge(&live, &durable(&[provisional])).unwrap();
    let promoted = snapshot(&read, &[committed]);
    assert_eq!(live.entries()[0].update, promoted.entries()[0].update);
    assert_eq!(promoted.entries()[0].revision, Read::Read);
    assert_eq!(promoted.counts(), Counts::default());
}

#[test]
fn edits_remove_readd_and_concurrency_do_not_repeat_priority() {
    let first = fact(10, 11);
    let read = ack(&state(), &[first]);
    for update in [fact(10, 12), fact(10, 13)] {
        let current = snapshot(&read, &[update]);
        assert_eq!(current.counts().unread_groups, 0);
        assert_eq!(current.counts().unread_revisions, 1);
    }
    let removed = Fact {
        active: false,
        ..fact(10, 12)
    };
    assert!(snapshot(&read, &[removed]).entries().is_empty());
    let readded = snapshot(&read, &[fact(10, 13)]);
    assert_eq!(readded.entries()[0].priority, Some(Read::Read));
    let concurrent = snapshot(&read, &[fact(10, 14), fact(10, 15)]);
    assert_eq!(concurrent.counts().unread_revisions, 2);
    assert_eq!(concurrent.counts().unread_groups, 0);
    let fresh = snapshot(&state(), &[fact(10, 14), fact(10, 15)]);
    assert_eq!(fresh.counts().unread_groups, 1);
    assert_eq!(fresh.counts().unread_revisions, 2);
}

#[test]
fn genuine_new_recipient_has_independent_group_and_reader_state() {
    let source = fact(10, 11);
    let existing = ack(&state(), &[source]);
    let other = Reader {
        owner: id(8),
        ..reader()
    };
    let attention = Attention::new(other, 8).unwrap();
    let addressed = Fact {
        update: Update {
            group: Group {
                recipient: other.owner,
                ..source.update.group
            },
            ..source.update
        },
        ..source
    };
    let shown = attention
        .snapshot(
            &durable(&[source, addressed]),
            &[source, addressed],
            false,
            0,
            64,
        )
        .unwrap();
    assert_eq!(shown.entries().len(), 1);
    assert_eq!(shown.counts().unread_groups, 1);
    assert_eq!(
        snapshot(&existing, &[source, addressed])
            .counts()
            .unread_groups,
        0
    );
    assert_eq!(
        existing.acknowledge(&shown, &durable(&[source, addressed])),
        Err(Error::Namespace)
    );
}

#[test]
fn sibling_agents_share_owner_groups_but_never_private_acknowledgements() {
    let source = fact(10, 11);
    let first = ack(&state(), &[source]);
    let second_reader = Reader {
        agent: Some(id(9)),
        ..reader()
    };
    let second = Attention::new(second_reader, 8).unwrap();
    let shown = second
        .snapshot(&durable(&[source]), &[source], false, 0, 64)
        .unwrap();
    assert_eq!(shown.counts().unread_groups, 1);
    assert_eq!(snapshot(&first, &[source]).counts().unread_groups, 0);
    assert_eq!(
        Attention::decode(&first.encode(), second_reader),
        Err(Error::Namespace)
    );
    // Repeated routes to two agents are one owner-level semantic update supplied
    // by the adapter; exact duplicates cannot create additional owner priority.
    assert_eq!(
        snapshot(&state(), &[source, source]).counts().unread_groups,
        1
    );
}

#[test]
fn mark_all_acknowledges_exact_shown_set_not_later_or_offpage_revisions() {
    let old = fact(10, 11);
    let sibling_revision = fact(10, 12);
    let new_group = fact(20, 21);
    let state = state();
    let source = durable(&[old, sibling_revision, new_group]);
    let shown = state
        .snapshot(&source, &[old, sibling_revision, new_group], false, 0, 1)
        .unwrap();
    assert_eq!(shown.total(), 3);
    let read = state.acknowledge(&shown, &source).unwrap();
    let current = snapshot(&read, &[new_group, sibling_revision, old]);
    assert_eq!(current.entries()[0].revision, Read::Read);
    assert_eq!(current.entries()[1].revision, Read::Unread);
    assert_eq!(current.entries()[1].priority, Some(Read::Read));
    assert_eq!(current.entries()[2].priority, Some(Read::Unread));
    assert_eq!(current.counts().unread_revisions, 2);
    assert_eq!(current.counts().unread_groups, 1);
}

#[test]
fn control_recomputation_updates_visibility_without_changing_identity() {
    let committed = fact(10, 11);
    let read = ack(&state(), &[committed]);
    // Adapter fixture for grant expiry/revoke/retire invalidation. Accepted
    // historical sources normally remain committed through these transitions.
    for state in [State::Invalid, State::Pending] {
        assert!(snapshot(&read, &[Fact { state, ..committed }])
            .entries()
            .is_empty());
    }
    assert_eq!(
        snapshot(&read, &[committed]).entries()[0].revision,
        Read::Read
    );
    assert_eq!(snapshot(&read, &[committed]).counts().unread_groups, 0);
}

#[test]
fn negative_activity_and_unselected_sources_do_not_claim_priority() {
    let source = Fact {
        priority: false,
        ..fact(10, 11)
    };
    let current = snapshot(&state(), &[source]);
    assert_eq!(current.counts().unread_revisions, 1);
    assert_eq!(current.counts().unread_groups, 0);
    assert_eq!(current.entries()[0].priority, None);
}

#[test]
fn bounded_marks_never_invent_exact_zero_or_replay_old_unknown_as_unread() {
    let a = fact(10, 11);
    let b = fact(20, 21);
    let c = fact(30, 31);
    let small = Attention::new(reader(), 1).unwrap();
    let read = ack(&small, &[a, b]);
    assert_eq!(read.retained(), (1, 1));
    let current = snapshot(&read, &[a, b, c]);
    assert_eq!(current.counts().unread_groups, 0);
    assert_eq!(current.counts().unknown_groups, 2);
    assert_eq!(current.counts().unknown_revisions, 2);
    let mut compacted = read.clone();
    compacted.forget_exact_marks();
    assert_eq!(
        snapshot(&compacted, &[a]).entries()[0].revision,
        Read::Unknown
    );
    assert_eq!(
        snapshot(&compacted, &[a]).entries()[0].priority,
        Some(Read::Read)
    );
    assert_eq!(
        Attention::decode(&compacted.encode(), reader()).unwrap(),
        compacted
    );
}

#[test]
fn partial_source_restore_preserves_unresolved_marks_without_transplanting_them() {
    let a = fact(10, 11);
    let b = fact(10, 12);
    let initial = state();
    let read = ack(&initial, &[a]);
    let restored_sources = durable(&[b]);
    assert_eq!(read.unresolved_marks(&restored_sources), 1);
    let restored_state = Attention::decode(&read.encode(), reader()).unwrap();
    let current = restored_state
        .snapshot(&restored_sources, &[b], false, 0, 64)
        .unwrap();
    assert_eq!(current.entries()[0].revision, Read::Unread);
    assert_eq!(current.entries()[0].priority, Some(Read::Read));
    let old_receipt = snapshot(&initial, &[a]);
    assert_eq!(
        read.acknowledge(&old_receipt, &restored_sources),
        Err(Error::MissingDurableSource)
    );
    assert_eq!(
        snapshot(&restored_state, &[a]).entries()[0].revision,
        Read::Read
    );
}

#[test]
fn receipt_accepts_additive_source_growth_but_rejects_foreign_realm() {
    let initial = state();
    let a = fact(10, 11);
    let shown = snapshot(&initial, &[a]);
    let later = Durable::model_fixture(reader().realm, id(99), &[a.update.event, id(12)]).unwrap();
    let next = initial.acknowledge(&shown, &later).unwrap();
    assert_eq!(snapshot(&next, &[a]).entries()[0].revision, Read::Read);
    let wrong = Durable::model_fixture(id(90), id(99), &[a.update.event]).unwrap();
    assert_eq!(initial.acknowledge(&shown, &wrong), Err(Error::Namespace));
    assert_eq!(
        initial.snapshot(&wrong, &[a], false, 0, 1),
        Err(Error::Namespace)
    );
}

#[test]
fn journal_crash_model_distinguishes_durable_sources_from_private_read_success() {
    let old = state();
    let source = fact(10, 11);
    let absent = Durable::model_fixture(reader().realm, id(42), &[]).unwrap();
    assert_eq!(
        old.snapshot(&absent, &[source], false, 0, 1),
        Err(Error::MissingDurableSource)
    );
    let durable_source = durable(&[source]);
    let shown = old
        .snapshot(&durable_source, &[source], false, 0, 1)
        .unwrap();
    let next = old.acknowledge(&shown, &durable_source).unwrap();
    // Five abstract journal cut points: before intent, torn intent, complete
    // intent, publication, cleanup. This is not a native filesystem test.
    for cut in 0..5 {
        let intent = match cut {
            0 => None,
            1 => Some(next.encode()[..40].to_vec()),
            _ => Some(next.encode()),
        };
        let published = if cut >= 3 {
            next.encode()
        } else {
            old.encode()
        };
        let recovered = match intent {
            None => Attention::decode(&published, reader()),
            Some(bytes) => Attention::decode(&bytes, reader()),
        };
        match cut {
            0 => assert_eq!(
                snapshot(&recovered.unwrap(), &[source]).entries()[0].revision,
                Read::Unread
            ),
            1 => assert!(recovered.is_err()),
            _ => assert_eq!(
                snapshot(&recovered.unwrap(), &[source]).entries()[0].revision,
                Read::Read
            ),
        }
    }
    // Coherent rollback has a valid checksum and namespace. No local checksum
    // can distinguish old-but-valid state from never-acknowledged state.
    assert!(Attention::decode(&old.encode(), reader()).is_ok());
    assert_ne!(old.encode(), next.encode());
}

#[test]
fn strict_canonical_decoder_rejects_damage_trailing_bytes_and_forged_order() {
    let read = ack(&state(), &[fact(10, 11), fact(20, 21)]);
    let valid = read.encode();
    for end in 0..valid.len() {
        assert!(Attention::decode(&valid[..end], reader()).is_err());
    }
    let mut damaged = valid.clone();
    damaged[50] ^= 1;
    assert_eq!(Attention::decode(&damaged, reader()), Err(Error::Encoding));
    let mut trailing = valid[..valid.len() - 32].to_vec();
    trailing.push(0);
    trailing.extend_from_slice(&Sha256::digest(&trailing));
    assert_eq!(Attention::decode(&trailing, reader()), Err(Error::Encoding));
    // Header 8 + agent-present reader 161 + capacity 2 + flags 2 + count 2.
    let groups_start = 175;
    let mut unordered = valid[..valid.len() - 32].to_vec();
    let first = unordered[groups_start..groups_start + 97].to_vec();
    let second = unordered[groups_start + 97..groups_start + 194].to_vec();
    unordered[groups_start..groups_start + 97].copy_from_slice(&second);
    unordered[groups_start + 97..groups_start + 194].copy_from_slice(&first);
    unordered.extend_from_slice(&Sha256::digest(&unordered));
    assert_eq!(
        Attention::decode(&unordered, reader()),
        Err(Error::Encoding)
    );
}

#[test]
fn projection_bounds_and_contradictory_adapter_rows_are_explicit_errors() {
    let source = fact(10, 11);
    let changed = Fact {
        active: false,
        ..source
    };
    assert_eq!(
        state().snapshot(&durable(&[source]), &[source, changed], false, 0, 1),
        Err(Error::ConflictingInput)
    );
    assert_eq!(
        state().snapshot(&durable(&[]), &[], false, 0, 0),
        Err(Error::Bounds)
    );
    assert_eq!(
        state().snapshot(&durable(&[]), &[], false, 0, MAX_PAGE + 1),
        Err(Error::Bounds)
    );
    assert!(Attention::new(reader(), MAX_MARKS + 1).is_err());
    assert!(Attention::new(reader(), 0).is_err());
    assert_eq!(
        state().snapshot(
            &durable(&[source]),
            &vec![source; MAX_INPUTS + 1],
            false,
            0,
            1
        ),
        Err(Error::Bounds)
    );
}

#[test]
fn maximum_retained_state_has_exact_bounded_encoding_and_human_namespace_roundtrip() {
    let facts: Vec<_> = (0..=255).map(|n| fact(n, n)).collect();
    let source = durable(&facts);
    let mut attention = Attention::new(reader(), MAX_MARKS).unwrap();
    for offset in (0..MAX_INPUTS).step_by(MAX_PAGE) {
        let shown = attention
            .snapshot(&source, &facts, false, offset, MAX_PAGE)
            .unwrap();
        attention = attention.acknowledge(&shown, &source).unwrap();
    }
    assert_eq!(attention.retained(), (256, 256));
    let encoded = attention.encode();
    assert_eq!(encoded.len(), 58_065);
    assert!(encoded.len() < MAX_BYTES);
    assert_eq!(Attention::decode(&encoded, reader()).unwrap(), attention);
    let human = Reader {
        agent: None,
        ..reader()
    };
    let empty = Attention::new(human, 1).unwrap();
    assert_eq!(Attention::decode(&empty.encode(), human).unwrap(), empty);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn permutation_duplicate_and_ack_order_oracle_matches_exact_set(
        revisions in prop::collection::vec(0u8..60, 0..60),
        acknowledged in prop::collection::btree_set(0u8..60, 0..60),
    ) {
        // Independent declarative oracle: acknowledge exact intersection and
        // suppress priority iff any revision of that stable group was read.
        let all: Vec<_> = (0..60).map(|r| fact(r % 7 + 1, r)).collect();
        let source = durable(&all);
        let mut state = state();
        for revision in &acknowledged {
            let source_fact = fact(revision % 7 + 1, *revision);
            let receipt = state.snapshot(&source, &[source_fact], false, 0, 64).unwrap();
            state = state.acknowledge(&receipt, &source).unwrap();
        }
        let mut reverse = Attention::new(reader(), 128).unwrap();
        for revision in acknowledged.iter().rev() {
            let source_fact = fact(revision % 7 + 1, *revision);
            let receipt = reverse.snapshot(&source, &[source_fact], false, 0, 64).unwrap();
            reverse = reverse.acknowledge(&receipt, &source).unwrap();
            reverse = reverse.acknowledge(&receipt, &source).unwrap();
        }
        prop_assert_eq!(state.encode(), reverse.encode());
        let facts: Vec<_> = revisions.iter().map(|r| fact(r % 7 + 1, *r)).collect();
        let mut reordered = facts.clone();
        reordered.reverse();
        reordered.extend_from_slice(&facts);
        let current = state.snapshot(&source, &facts, false, 0, 64).unwrap();
        prop_assert_eq!(&current, &state.snapshot(&source, &reordered, false, 0, 64).unwrap());
        let expected: BTreeSet<_> = facts.iter().map(|f| f.update).collect();
        prop_assert_eq!(current.entries().iter().map(|e| e.update).collect::<BTreeSet<_>>(), expected);
        for entry in current.entries() {
            let revision = entry.update.event[0];
            let expected_revision = if acknowledged.contains(&revision) { Read::Read } else { Read::Unread };
            let expected_priority = if acknowledged.iter().any(|r| r % 7 == revision % 7) { Read::Read } else { Read::Unread };
            prop_assert_eq!(entry.revision, expected_revision);
            prop_assert_eq!(entry.priority, Some(expected_priority));
        }
    }

    #[test]
    fn generated_transition_trace_retains_ack_through_visibility_and_commit_changes(
        operations in prop::collection::vec((0u8..12, 0u8..6, any::<bool>()), 0..80)
    ) {
        let mut state = state();
        let mut oracle_read = BTreeSet::new();
        let mut oracle_groups = BTreeSet::new();
        for (revision, change, acknowledge) in operations {
            let mut source_fact = fact(revision % 3 + 1, revision);
            source_fact.state = match change { 0 => State::Invalid, 1 => State::Pending, 2 => State::Provisional, _ => State::Committed };
            source_fact.active = change != 3;
            let current = state.snapshot(&durable(&[source_fact]), &[source_fact], true, 0, 64).unwrap();
            let visible = source_fact.active && matches!(source_fact.state, State::Committed | State::Provisional);
            prop_assert_eq!(current.entries().len(), usize::from(visible));
            if let Some(entry) = current.entries().first() {
                prop_assert_eq!(entry.revision, if oracle_read.contains(&revision) { Read::Read } else { Read::Unread });
                prop_assert_eq!(entry.priority, Some(if oracle_groups.contains(&(revision % 3)) { Read::Read } else { Read::Unread }));
                if acknowledge {
                    oracle_read.insert(revision);
                    oracle_groups.insert(revision % 3);
                    state = state.acknowledge(&current, &durable(&[source_fact])).unwrap();
                }
            }
            let bytes = state.encode();
            prop_assert_eq!(&state, &Attention::decode(&bytes, reader()).unwrap());
        }
    }

    #[test]
    fn bounded_saturation_roundtrip_never_turns_a_read_item_unread(
        capacity in 1usize..16,
        revisions in prop::collection::vec(0u8..80, 0..80),
        compact in any::<bool>(),
    ) {
        let facts: Vec<_> = revisions.iter().map(|r| fact(*r, *r)).collect();
        let source = durable(&facts);
        let mut state = Attention::new(reader(), capacity).unwrap();
        let mut ever_read = BTreeSet::new();
        for fact in &facts {
            let receipt = state.snapshot(&source, &[*fact], false, 0, 64).unwrap();
            state = state.acknowledge(&receipt, &source).unwrap();
            if state.snapshot(&source, &[*fact], false, 0, 64).unwrap().entries()[0].revision == Read::Read { ever_read.insert(fact.update); }
        }
        if compact { state.forget_exact_marks(); }
        let copy = Attention::decode(&state.encode(), reader()).unwrap();
        prop_assert!(copy.retained().0 <= capacity && copy.retained().1 <= capacity);
        for fact in &facts {
            if ever_read.contains(&fact.update) {
                prop_assert_ne!(copy.snapshot(&source, &[*fact], false, 0, 64).unwrap().entries()[0].revision, Read::Unread);
            }
        }
    }

    #[test]
    fn arbitrary_decoder_bytes_never_panic_or_escape_bounds(bytes in prop::collection::vec(any::<u8>(), 0..1200)) {
        if let Ok(decoded) = Attention::decode(&bytes, reader()) {
            prop_assert_eq!(decoded.encode(), bytes);
            prop_assert!(decoded.retained().0 <= MAX_MARKS && decoded.retained().1 <= MAX_MARKS);
        }
    }
}
