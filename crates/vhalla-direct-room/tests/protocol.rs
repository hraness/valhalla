//! Adversarial protocol histories and stateful author replay.
use ed25519_dalek::SigningKey;
use vhalla_direct_room::*;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn writers(keys: &[&SigningKey]) -> Vec<[u8; 32]> {
    let mut keys: Vec<_> = keys
        .iter()
        .map(|key| key.verifying_key().to_bytes())
        .collect();
    keys.sort();
    keys
}
fn genesis() -> SignedGenesis {
    UnsignedGenesis::new(GenesisClaims {
        owner: key(1).verifying_key().to_bytes(),
        nonce: [9; 32],
        writers: writers(&[&key(1), &key(2)]),
    })
    .unwrap()
    .sign_with_key(&key(1))
    .unwrap()
}
fn policy() -> PolicyState {
    let genesis = genesis();
    let pin = genesis.id();
    PolicyState::new(genesis.verify_pin(pin).unwrap())
}
fn event(
    state: &PolicyState,
    author: u8,
    sequence: u64,
    previous: EventId,
    text: &str,
) -> VerifiedEvent {
    UnsignedEvent::new(EventClaims {
        room: state.room(),
        policy: state.head().id,
        author: key(author).verifying_key().to_bytes(),
        sequence,
        previous,
        created_at: 1234,
        text: Text::new(text).unwrap(),
    })
    .unwrap()
    .sign_with_key(&key(author))
    .unwrap()
    .verify()
    .unwrap()
}
fn update(state: &PolicyState, authors: &[u8], mut seals: Vec<SealHead>) -> SignedPolicy {
    let keys: Vec<_> = authors.iter().map(|n| key(*n)).collect();
    seals.sort_by_key(|head| head.author);
    UnsignedPolicy::new(PolicyClaims {
        room: state.room(),
        owner: state.owner(),
        revision: state.head().revision + 1,
        previous: state.head().id,
        writers: writers(&keys.iter().collect::<Vec<_>>()),
        sealed_heads: seals,
    })
    .unwrap()
    .sign_with_key(&key(1))
    .unwrap()
}
fn seal(event: &VerifiedEvent) -> SealHead {
    SealHead {
        author: event.claims().author,
        sequence: event.claims().sequence,
        event: event.id(),
    }
}
fn close(state: &mut PolicyState, authors: &[u8], seals: Vec<SealHead>) -> ClosedPolicy {
    assert!(
        seals.is_empty(),
        "use close_with_history for declared seals"
    );
    let pending = state.prepare_update(update(state, authors, seals)).unwrap();
    state.commit_after_persist(pending).unwrap()
}
fn close_with_history(
    state: &mut PolicyState,
    authors: &[u8],
    seals: Vec<SealHead>,
    frames: &[VerifiedEvent],
) -> ClosedPolicy {
    let update = update(state, authors, seals.clone());
    state
        .observe_after_persist(&update.clone().verify().unwrap())
        .unwrap();
    let mut pending = state.prepare_update(update).unwrap();
    for seal in seals {
        let prior = state.sealed_head(&seal.author).unwrap_or(AuthorHead::EMPTY);
        let frames: Vec<_> = frames
            .iter()
            .filter(|event| {
                event.claims().author == seal.author && event.claims().sequence > prior.sequence
            })
            .cloned()
            .collect();
        for page in frames.chunks(MAX_CHAIN_PAGE) {
            pending.push_seal(&seal.author, page).unwrap();
        }
    }
    assert!(pending.is_ready());
    state.commit_after_persist(pending).unwrap()
}
fn verifier(closed: &ClosedPolicy, event: VerifiedEvent) -> SealedHistoryVerifier {
    match closed.history_requirement(event).unwrap() {
        HistoryRequirement::Verify(proof) => *proof,
        HistoryRequirement::ContinuityOnly => panic!("expected owner-endorsed candidate"),
    }
}

#[test]
fn anchor_reconciliation_checks_exact_ancestry_without_advancing_the_head() {
    let mut state = policy();
    let author = key(2).verifying_key().to_bytes();
    let first = event(&state, 2, 1, EventId::ZERO, "sealed first");
    let second = event(&state, 2, 2, first.id(), "retained second");
    let third = event(&state, 2, 3, second.id(), "retained third");
    let mut chain = AuthorChain::new(state.room(), author).unwrap();
    for frame in [&first, &second, &third] {
        let step = chain.prepare_continuity(frame.clone(), &state).unwrap();
        chain.commit_continuity_after_persist(step, &state).unwrap();
    }
    close_with_history(
        &mut state,
        &[1, 2],
        vec![seal(&first)],
        std::slice::from_ref(&first),
    );
    assert_eq!(chain.authoring_head(&state), Err(Error::Gap));
    let original = chain.head();
    let mut proof = chain.prepare_anchor_reconciliation(&state).unwrap();
    assert_eq!(proof.progress().event, first.id());
    assert_eq!(proof.target(), original);
    assert_eq!(
        chain.clone().reconcile_anchor(proof.clone(), &state),
        Err(Error::Gap)
    );
    assert_eq!(proof.push(std::slice::from_ref(&third)), Err(Error::Gap));
    assert_eq!(proof.progress().event, first.id());
    let wrong_terminal = event(&policy(), 2, 3, second.id(), "forked third");
    assert_eq!(
        proof.push(&[second.clone(), wrong_terminal]),
        Err(Error::Fork)
    );
    assert_eq!(proof.progress().event, first.id());
    proof.push(&[second]).unwrap();
    proof.push(&[third]).unwrap();
    assert!(proof.is_ready());
    chain.reconcile_anchor(proof, &state).unwrap();
    assert_eq!(chain.head(), original);
    assert_eq!(chain.authoring_head(&state).unwrap(), original);
}

#[test]
fn anchor_reconciliation_rejects_scope_author_pages_and_stale_snapshots() {
    let mut state = policy();
    let author = key(2).verifying_key().to_bytes();
    let first = event(&state, 2, 1, EventId::ZERO, "first");
    let second = event(&state, 2, 2, first.id(), "second");
    let mut chain = AuthorChain::new(state.room(), author).unwrap();
    for frame in [&first, &second] {
        let step = chain.prepare_continuity(frame.clone(), &state).unwrap();
        chain.commit_continuity_after_persist(step, &state).unwrap();
    }
    close_with_history(
        &mut state,
        &[1, 2],
        vec![seal(&first)],
        std::slice::from_ref(&first),
    );
    let mut proof = chain.prepare_anchor_reconciliation(&state).unwrap();
    assert_eq!(proof.push(&[]), Err(Error::Bounds));
    assert_eq!(
        proof.push(&vec![second.clone(); MAX_CHAIN_PAGE + 1]),
        Err(Error::Bounds)
    );
    let wrong_author = event(&policy(), 1, 2, first.id(), "wrong author");
    assert_eq!(proof.push(&[wrong_author]), Err(Error::Author));
    let wrong_previous = event(
        &policy(),
        2,
        2,
        EventId::from_bytes([7; 32]),
        "wrong predecessor",
    );
    assert_eq!(proof.push(&[wrong_previous]), Err(Error::Fork));
    let mut other_claims = genesis().unverified_claims().clone();
    other_claims.nonce = [8; 32];
    let other = UnsignedGenesis::new(other_claims)
        .unwrap()
        .sign_with_key(&key(1))
        .unwrap();
    let other_pin = other.id();
    let other_state = PolicyState::new(other.verify_pin(other_pin).unwrap());
    let foreign = event(&other_state, 2, 2, first.id(), "foreign room");
    assert_eq!(proof.push(&[foreign]), Err(Error::Scope));
    assert_eq!(
        chain.prepare_anchor_reconciliation(&other_state),
        Err(Error::Scope)
    );
    proof.push(std::slice::from_ref(&second)).unwrap();
    let mut wrong_chain =
        AuthorChain::new(state.room(), key(1).verifying_key().to_bytes()).unwrap();
    assert_eq!(
        wrong_chain.reconcile_anchor(proof.clone(), &state),
        Err(Error::StaleBase)
    );
    assert_eq!(
        chain.clone().reconcile_anchor(proof.clone(), &other_state),
        Err(Error::StalePolicy)
    );
    let mut divergent_policy = policy();
    close_with_history(&mut divergent_policy, &[1], vec![seal(&first)], &[first]);
    assert_eq!(divergent_policy.head().revision, state.head().revision);
    assert_eq!(
        chain
            .clone()
            .reconcile_anchor(proof.clone(), &divergent_policy),
        Err(Error::StalePolicy)
    );
    let mut moved = chain.clone();
    moved.reconcile_anchor(proof.clone(), &state).unwrap();
    let third = event(&state, 2, 3, second.id(), "later");
    let step = moved.prepare_continuity(third, &state).unwrap();
    moved.commit_continuity_after_persist(step, &state).unwrap();
    assert_eq!(
        moved.reconcile_anchor(proof.clone(), &state),
        Err(Error::StaleBase)
    );
    close(&mut state, &[1, 2], vec![]);
    assert_eq!(
        chain.reconcile_anchor(proof, &state),
        Err(Error::StalePolicy)
    );
}

#[test]
fn anchor_reconciliation_cannot_connect_a_divergent_existing_branch() {
    let mut state = policy();
    let first = event(&state, 2, 1, EventId::ZERO, "owner branch");
    let fork_first = event(&state, 2, 1, EventId::ZERO, "other branch");
    let fork_second = event(&state, 2, 2, fork_first.id(), "other terminal");
    let mut chain = AuthorChain::new(state.room(), key(2).verifying_key().to_bytes()).unwrap();
    for frame in [fork_first, fork_second.clone()] {
        let step = chain.prepare_continuity(frame, &state).unwrap();
        chain.commit_continuity_after_persist(step, &state).unwrap();
    }
    close_with_history(&mut state, &[1, 2], vec![seal(&first)], &[first]);
    let mut proof = chain.prepare_anchor_reconciliation(&state).unwrap();
    assert_eq!(proof.push(&[fork_second]), Err(Error::Fork));
    assert_eq!(chain.reconcile_anchor(proof, &state), Err(Error::Gap));
    assert_eq!(chain.authoring_head(&state), Err(Error::Gap));
}

#[test]
fn records_preserve_bytes_and_require_signature_and_separate_room_pin() {
    let genesis = genesis();
    let raw = genesis.encode();
    assert_eq!(SignedGenesis::decode(&raw).unwrap().encode(), raw);
    assert_eq!(
        genesis.clone().verify_pin(RoomId::from_bytes([7; 32])),
        Err(Error::Scope)
    );
    let pin = genesis.id();
    assert_eq!(genesis.verify_pin(pin).unwrap().encode(), raw);
    let state = policy();
    let message = event(&state, 2, 1, EventId::ZERO, "hello\nworld\t✓");
    let raw = message.encode();
    assert_eq!(
        SignedEvent::decode(&raw).unwrap().verify().unwrap(),
        message
    );
    let mut corrupted = raw.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert_eq!(
        SignedEvent::decode(&corrupted).unwrap().verify(),
        Err(Error::Signature)
    );
    assert_eq!(SignedPolicy::decode(&raw), Err(Error::Protocol));
    for length in 0..raw.len() {
        assert!(SignedEvent::decode(&raw[..length])
            .and_then(SignedEvent::verify)
            .is_err());
    }
    let mut trailing = raw;
    trailing.push(0);
    assert!(SignedEvent::decode(&trailing).is_err());
}

#[test]
fn canonical_lists_weak_keys_lengths_and_text_are_rejected() {
    let owner = key(1).verifying_key().to_bytes();
    let mut claims = genesis().unverified_claims().clone();
    claims.writers.reverse();
    assert_eq!(UnsignedGenesis::new(claims.clone()), Err(Error::Encoding));
    claims.writers = vec![owner, owner];
    assert_eq!(UnsignedGenesis::new(claims.clone()), Err(Error::Encoding));
    claims.writers = vec![key(2).verifying_key().to_bytes()];
    assert_eq!(UnsignedGenesis::new(claims.clone()), Err(Error::Owner));
    claims.writers = vec![[0; 32]];
    assert_eq!(UnsignedGenesis::new(claims), Err(Error::Key));
    assert_eq!(Text::new(""), Err(Error::Bounds));
    assert_eq!(Text::new("not\0text"), Err(Error::Encoding));
    assert_eq!(
        Text::new(&"x".repeat(MAX_TEXT_BYTES + 1)),
        Err(Error::Bounds)
    );
    let unsigned = UnsignedGenesis::new(genesis().unverified_claims().clone()).unwrap();
    assert_eq!(unsigned.clone().sign_with_key(&key(2)), Err(Error::Signer));
    let mut huge = unsigned.encode();
    huge[69..71].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(UnsignedGenesis::decode(&huge), Err(Error::Bounds));
    let mut oversized_text = event(&policy(), 2, 1, EventId::ZERO, "message").encode();
    oversized_text[149..153].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(SignedEvent::decode(&oversized_text), Err(Error::Bounds));
}

#[test]
fn frozen_vectors_match_an_independent_ed25519_and_sha256_encoder() {
    fn vector(name: &str) -> Vec<u8> {
        let source = include_str!("../../../vectors/direct-room-v1.txt");
        let value = source
            .lines()
            .filter_map(|line| line.split_once('='))
            .find(|(key, _)| *key == name)
            .unwrap()
            .1;
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }
    let genesis = genesis();
    let state = policy();
    let event = event(&state, 2, 1, EventId::ZERO, "hello from a direct room");
    let update = update(&state, &[1], vec![seal(&event)]);
    assert_eq!(
        state.head().id.as_bytes().as_slice(),
        vector("initial_policy")
    );
    for (name, raw, id) in [
        ("genesis", genesis.encode(), *genesis.id().as_bytes()),
        ("event", event.encode(), *event.id().as_bytes()),
        ("policy", update.encode(), *update.id().as_bytes()),
    ] {
        assert_eq!(raw, vector(&format!("{name}_signed")));
        assert_eq!(&raw[..raw.len() - 64], vector(&format!("{name}_unsigned")));
        assert_eq!(&raw[raw.len() - 64..], vector(&format!("{name}_signature")));
        assert_eq!(id.as_slice(), vector(&format!("{name}_id")));
    }
}

#[test]
fn a_failed_seal_page_keeps_all_its_frames_unapplied() {
    let mut state = policy();
    let first = event(&state, 2, 1, EventId::ZERO, "first");
    let second = event(&state, 2, 2, first.id(), "second");
    let fork = event(&state, 2, 2, first.id(), "alternate second");
    let mut pending = state
        .prepare_update(update(&state, &[1, 2], vec![seal(&second)]))
        .unwrap();
    assert_eq!(
        pending.push_seal(&first.claims().author, &[first.clone(), fork]),
        Err(Error::Fork)
    );
    assert!(!pending.is_ready());
    pending
        .push_seal(&first.claims().author, &[first.clone(), second.clone()])
        .unwrap();
    state.commit_after_persist(pending).unwrap();
    assert_eq!(
        state.sealed_head(&first.claims().author).unwrap().event,
        second.id()
    );
}

#[test]
fn future_observation_stays_fenced_through_intermediate_replay_and_old_forks() {
    let mut state = policy();
    let first = update(&state, &[1, 2], vec![]);
    let mut advanced = state.clone();
    let pending = advanced.prepare_update(first.clone()).unwrap();
    advanced.commit_after_persist(pending).unwrap();
    let later = update(&advanced, &[1], vec![]);
    state
        .observe_after_persist(&later.clone().verify().unwrap())
        .unwrap();
    let pending = state.prepare_update(first.clone()).unwrap();
    state.commit_after_persist(pending).unwrap();
    assert!(state.pending().is_some());
    let pending = state.prepare_update(later).unwrap();
    state.commit_after_persist(pending).unwrap();
    assert_eq!(state.pending(), None);
    let mut alternate = first.unverified_claims().clone();
    alternate.writers = writers(&[&key(1)]);
    let alternate = UnsignedPolicy::new(alternate)
        .unwrap()
        .sign_with_key(&key(1))
        .unwrap();
    assert_eq!(
        state.observe_retained_after_persist(&first.verify().unwrap(), alternate),
        Err(Error::Fork)
    );
    assert!(state.is_forked());
    let chain = AuthorChain::new(state.room(), key(1).verifying_key().to_bytes()).unwrap();
    assert!(matches!(
        chain.prepare_next(
            event(&state, 1, 1, EventId::ZERO, "owner after fork"),
            &state
        ),
        Err(Error::Fork)
    ));
}

#[test]
fn author_candidates_recheck_policy_and_chain_without_advancing_on_failure() {
    let mut state = policy();
    let mut chain = AuthorChain::new(state.room(), key(2).verifying_key().to_bytes()).unwrap();
    let first = event(&state, 2, 1, EventId::ZERO, "first");
    let pending = chain.prepare_next(first.clone(), &state).unwrap();
    assert_eq!(chain.head(), AuthorHead::EMPTY);
    close(&mut state, &[1], vec![]);
    assert_eq!(
        chain.commit_after_persist(pending, &state),
        Err(Error::StalePolicy)
    );
    assert_eq!(chain.head(), AuthorHead::EMPTY);
    assert!(matches!(
        chain.prepare_next(first.clone(), &state),
        Err(Error::Policy)
    ));
    // An excluded old frame may be retained as an ancestor, never as fresh admission.
    let pending = chain.prepare_continuity(first.clone(), &state).unwrap();
    chain
        .commit_continuity_after_persist(pending, &state)
        .unwrap();
    assert!(matches!(
        chain.prepare_continuity(first.clone(), &state),
        Err(Error::Duplicate)
    ));
    let unauthorized = event(&state, 2, 2, first.id(), "removed author");
    assert!(matches!(
        chain.prepare_next(unauthorized, &state),
        Err(Error::Author)
    ));
    assert_eq!(chain.head().event, first.id());
}

#[test]
fn gaps_duplicates_forks_and_stale_candidates_are_distinct() {
    let state = policy();
    let mut chain = AuthorChain::new(state.room(), key(2).verifying_key().to_bytes()).unwrap();
    let first = event(&state, 2, 1, EventId::ZERO, "first");
    let alternative = event(&state, 2, 1, EventId::ZERO, "fork");
    let stale = chain.prepare_next(alternative.clone(), &state).unwrap();
    let pending = chain.prepare_next(first.clone(), &state).unwrap();
    chain.commit_after_persist(pending, &state).unwrap();
    assert_eq!(
        chain.commit_after_persist(stale, &state),
        Err(Error::StaleBase)
    );
    assert!(matches!(
        chain.prepare_next(first.clone(), &state),
        Err(Error::Duplicate)
    ));
    assert!(matches!(
        chain.prepare_next(alternative.clone(), &state),
        Err(Error::Fork)
    ));
    assert!(matches!(
        chain.prepare_next(event(&state, 2, 3, first.id(), "gap"), &state),
        Err(Error::Gap)
    ));
    assert!(matches!(
        chain.prepare_next(event(&state, 2, 2, alternative.id(), "fork child"), &state),
        Err(Error::Fork)
    ));
    assert_eq!(chain.head().event, first.id());
}

#[test]
fn owner_updates_pin_scope_owner_predecessor_and_sealed_writer() {
    let mut state = policy();
    let first = update(&state, &[1, 2], vec![]);
    let conflicting = update(&state, &[1], vec![]);
    let pending = state.prepare_update(first.clone()).unwrap();
    let stale = state.prepare_update(conflicting.clone()).unwrap();
    let closed = state.commit_after_persist(pending).unwrap();
    assert_eq!(closed.policy(), state.room().initial_policy());
    assert!(matches!(
        state.commit_after_persist(stale),
        Err(Error::StaleBase)
    ));
    assert!(matches!(
        state.prepare_update(first.clone()),
        Err(Error::Duplicate)
    ));
    assert!(matches!(
        state.prepare_update(conflicting.clone()),
        Err(Error::Fork)
    ));
    let retained = first.verify().unwrap();
    close(&mut state, &[1, 2], vec![]);
    assert!(matches!(
        state.prepare_update(conflicting.clone()),
        Err(Error::Replay)
    ));
    assert_eq!(
        state.compare_retained(&retained, conflicting),
        Err(Error::Fork)
    );
    let foreign = event(&state, 3, 1, EventId::ZERO, "unadmitted");
    assert!(matches!(
        state.prepare_update(update(&state, &[1, 2], vec![seal(&foreign)])),
        Err(Error::Author)
    ));
    let mut claims = update(&state, &[1, 2], vec![]).unverified_claims().clone();
    claims.owner = key(3).verifying_key().to_bytes();
    claims.writers = writers(&[&key(3)]);
    let attacker = UnsignedPolicy::new(claims)
        .unwrap()
        .sign_with_key(&key(3))
        .unwrap();
    assert!(matches!(state.prepare_update(attacker), Err(Error::Owner)));
    let mut claims = update(&state, &[1, 2], vec![]).unverified_claims().clone();
    claims.previous = PolicyId::from_bytes([5; 32]);
    let wrong_parent = UnsignedPolicy::new(claims)
        .unwrap()
        .sign_with_key(&key(1))
        .unwrap();
    assert!(matches!(
        state.prepare_update(wrong_parent),
        Err(Error::Fork)
    ));
}

#[test]
fn history_needs_exact_ancestry_not_only_a_numeric_cutoff() {
    let mut state = policy();
    let first = event(&state, 2, 1, EventId::ZERO, "first");
    let second = event(&state, 2, 2, first.id(), "second");
    let alternate_first = event(&state, 2, 1, EventId::ZERO, "forked first");
    let closed = close_with_history(
        &mut state,
        &[1],
        vec![seal(&second)],
        &[first.clone(), second.clone()],
    );
    let mut incomplete = verifier(&closed, first.clone());
    incomplete.push(std::slice::from_ref(&first)).unwrap();
    assert_eq!(incomplete.clone().finish(), Err(Error::Gap));
    incomplete.push(std::slice::from_ref(&second)).unwrap();
    assert_eq!(incomplete.finish().unwrap().event(), &first);
    let mut alternate = verifier(&closed, alternate_first.clone());
    assert_eq!(
        alternate.push(&[first.clone(), second.clone()]),
        Err(Error::Fork)
    );
    assert_eq!(alternate.head(), AuthorHead::EMPTY);
    // Even a signature-valid alternate prefix cannot connect to the endorsed terminal.
    assert_eq!(
        alternate.push(&[alternate_first, second.clone()]),
        Err(Error::Fork)
    );
    assert_eq!(alternate.head(), AuthorHead::EMPTY);
    let mut skipped = verifier(&closed, second.clone());
    assert_eq!(skipped.push(std::slice::from_ref(&second)), Err(Error::Gap));
    assert_eq!(skipped.head(), AuthorHead::EMPTY);
}

#[test]
fn later_seals_never_promote_excluded_old_policy_frames() {
    let mut state = policy();
    let accepted = event(&state, 2, 1, EventId::ZERO, "known at transition");
    let offline = event(&state, 2, 2, accepted.id(), "offline old-policy message");
    let old_boundary = close_with_history(
        &mut state,
        &[1, 2],
        vec![seal(&accepted)],
        std::slice::from_ref(&accepted),
    );
    assert!(matches!(
        old_boundary.history_requirement(offline.clone()).unwrap(),
        HistoryRequirement::ContinuityOnly
    ));
    let current = event(&state, 2, 3, offline.id(), "explicit new send");
    let new_boundary = close_with_history(
        &mut state,
        &[1, 2],
        vec![seal(&current)],
        &[offline.clone(), current.clone()],
    );
    let mut proof = verifier(&new_boundary, current.clone());
    proof
        .push(&[accepted, offline.clone(), current.clone()])
        .unwrap();
    assert_eq!(proof.finish().unwrap().event(), &current);
    assert!(matches!(
        new_boundary.history_requirement(offline.clone()),
        Err(Error::Policy)
    ));
    assert!(matches!(
        old_boundary.history_requirement(offline).unwrap(),
        HistoryRequirement::ContinuityOnly
    ));
}

#[test]
fn seals_cannot_name_a_terminal_from_another_policy() {
    let mut state = policy();
    let old = event(&state, 2, 1, EventId::ZERO, "old policy");
    close(&mut state, &[1, 2], vec![]);
    let update = update(&state, &[1, 2], vec![seal(&old)]);
    let mut pending = state.prepare_update(update).unwrap();
    assert_eq!(
        pending.push_seal(&old.claims().author, std::slice::from_ref(&old)),
        Err(Error::Policy)
    );
    assert!(!pending.is_ready());
    let before = state.clone();
    assert_eq!(state.commit_after_persist(pending), Err(Error::Gap));
    assert_eq!(state, before);
}

#[test]
fn later_policy_cannot_endorse_a_conflicting_lower_or_higher_author_branch() {
    let mut state = policy();
    let first = event(&state, 2, 1, EventId::ZERO, "original");
    close_with_history(
        &mut state,
        &[1, 2],
        vec![seal(&first)],
        std::slice::from_ref(&first),
    );
    let fork = event(&state, 2, 1, EventId::ZERO, "fork under newer policy");
    assert!(matches!(
        state.prepare_update(update(&state, &[1, 2], vec![seal(&fork)])),
        Err(Error::Fork)
    ));
    // Repeating the exact old terminal cannot pretend it names the new policy.
    assert!(matches!(
        state.prepare_update(update(&state, &[1, 2], vec![seal(&first)])),
        Err(Error::Policy)
    ));
    let higher_fork = event(
        &state,
        2,
        2,
        fork.id(),
        "larger number, conflicting ancestry",
    );
    let mut pending = state
        .prepare_update(update(&state, &[1, 2], vec![seal(&higher_fork)]))
        .unwrap();
    assert_eq!(
        pending.push_seal(
            &higher_fork.claims().author,
            std::slice::from_ref(&higher_fork)
        ),
        Err(Error::Fork)
    );
    assert!(!pending.is_ready());
    let before = state.clone();
    assert_eq!(state.commit_after_persist(pending), Err(Error::Gap));
    assert_eq!(state, before);
    let valid = event(&state, 2, 2, first.id(), "exact extension");
    close_with_history(
        &mut state,
        &[1, 2],
        vec![seal(&valid)],
        std::slice::from_ref(&valid),
    );
    assert_eq!(
        state.sealed_head(&valid.claims().author).unwrap().event,
        valid.id()
    );
}

#[test]
fn missing_seal_history_fences_old_policy_until_verified() {
    let mut state = policy();
    let first = event(&state, 2, 1, EventId::ZERO, "known to owner");
    let mut chain = AuthorChain::new(state.room(), first.claims().author).unwrap();
    let pre_observation = chain.prepare_next(first.clone(), &state).unwrap();
    let replacement = update(&state, &[1], vec![seal(&first)]);
    state
        .observe_after_persist(&replacement.clone().verify().unwrap())
        .unwrap();
    assert!(state.pending().is_some());
    assert_eq!(chain.authoring_head(&state), Err(Error::PolicyPending));
    assert!(matches!(
        chain.prepare_next(first.clone(), &state),
        Err(Error::PolicyPending)
    ));
    assert_eq!(
        chain.commit_after_persist(pre_observation, &state),
        Err(Error::PolicyPending)
    );
    let mut pending = state.prepare_update(replacement).unwrap();
    assert!(!pending.is_ready());
    pending
        .push_seal(&first.claims().author, std::slice::from_ref(&first))
        .unwrap();
    state.commit_after_persist(pending).unwrap();
    assert_eq!(state.pending(), None);
    assert!(!state.allows(&first.claims().author));
    assert_eq!(chain.head(), AuthorHead::EMPTY);
}

#[hegel::test(test_cases = 64)]
fn replay_and_exact_retries_preserve_the_model(tc: hegel::TestCase) {
    use hegel::generators as gs;
    let state = policy();
    let mut chain = AuthorChain::new(state.room(), key(2).verifying_key().to_bytes()).unwrap();
    let mut frames: Vec<VerifiedEvent> = vec![];
    let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(24));
    for _ in 0..steps {
        if !frames.is_empty() && tc.draw(gs::booleans()) {
            let index = tc.draw(gs::integers::<usize>().max_value(frames.len() - 1));
            let before = chain.clone();
            assert!(chain.prepare_next(frames[index].clone(), &state).is_err());
            assert_eq!(chain, before);
        } else {
            let text = format!("message {}", frames.len());
            let next = event(
                &state,
                2,
                chain.head().sequence + 1,
                chain.head().event,
                &text,
            );
            let pending = chain.prepare_next(next.clone(), &state).unwrap();
            chain.commit_after_persist(pending, &state).unwrap();
            frames.push(next);
        }
        let mut restored =
            AuthorChain::new(state.room(), key(2).verifying_key().to_bytes()).unwrap();
        for frame in &frames {
            let frame = SignedEvent::decode(&frame.encode())
                .unwrap()
                .verify()
                .unwrap();
            let pending = restored.prepare_continuity(frame, &state).unwrap();
            restored
                .commit_continuity_after_persist(pending, &state)
                .unwrap();
        }
        assert_eq!(restored, chain);
        assert_eq!(chain.head().sequence as usize, frames.len());
    }
}

#[test]
fn superseding_pending_revision_never_forgets_an_observed_owner_fork() {
    let mut state = policy();
    let a = update(&state, &[1], vec![]);
    let b = update(&state, &[1, 2], vec![]);
    let prepared_b = state.prepare_update(b.clone()).unwrap();
    let mut branch_b = state.clone();
    let step = branch_b.prepare_update(b.clone()).unwrap();
    branch_b.commit_after_persist(step).unwrap();
    let b2 = update(&branch_b, &[1, 2], vec![]);
    state.observe_after_persist(&a.verify().unwrap()).unwrap();
    state.observe_after_persist(&b2.verify().unwrap()).unwrap();
    assert_eq!(state.pending().unwrap().revision, 2);
    assert!(matches!(state.prepare_update(b.clone()), Err(Error::Fork)));
    assert!(matches!(
        state.commit_after_persist(prepared_b),
        Err(Error::Fork)
    ));
    assert_eq!(
        state.observe_after_persist(&b.verify().unwrap()),
        Err(Error::Fork)
    );
    assert!(state.is_forked());
    let chain = AuthorChain::new(state.room(), key(2).verifying_key().to_bytes()).unwrap();
    assert!(matches!(
        chain.prepare_next(event(&state, 2, 1, EventId::ZERO, "fenced"), &state),
        Err(Error::Fork)
    ));
}

#[test]
fn overflowed_observations_cannot_silently_unfence_after_partial_replay() {
    let mut state = policy();
    let mut owner = state.clone();
    let mut retained = vec![];
    for index in 0..=MAX_OBSERVED_POLICIES {
        let next = update(&owner, &[1, 2], vec![]);
        let verified = next.clone().verify().unwrap();
        assert_eq!(
            state.observe_after_persist(&verified),
            if index == MAX_OBSERVED_POLICIES {
                Err(Error::Capacity)
            } else {
                Ok(())
            }
        );
        let step = owner.prepare_update(next.clone()).unwrap();
        owner.commit_after_persist(step).unwrap();
        retained.push(next);
    }
    assert!(state.observation_overflow());
    for next in retained {
        let step = state.prepare_update(next).unwrap();
        state.commit_after_persist(step).unwrap();
    }
    assert_eq!(state.pending(), None);
    assert!(state.observation_overflow());
    let chain = AuthorChain::new(state.room(), key(2).verifying_key().to_bytes()).unwrap();
    assert!(matches!(
        chain.prepare_next(event(&state, 2, 1, EventId::ZERO, "fenced"), &state),
        Err(Error::Capacity)
    ));
}

#[test]
fn fresh_admission_requires_exact_sealed_ancestry_even_for_longer_chains() {
    let mut state = policy();
    let first = event(&state, 2, 1, EventId::ZERO, "sealed original");
    let second = event(&state, 2, 2, first.id(), "old-policy continuation");
    let fork = event(&state, 2, 1, EventId::ZERO, "conflicting first");
    let fork2 = event(&state, 2, 2, fork.id(), "longer conflicting branch");
    let empty = AuthorChain::new(state.room(), first.claims().author).unwrap();
    let mut conflicting = empty.clone();
    let mut longer = empty.clone();
    let mut valid_ahead = empty.clone();
    let step = conflicting
        .prepare_continuity(fork.clone(), &state)
        .unwrap();
    conflicting
        .commit_continuity_after_persist(step, &state)
        .unwrap();
    for (chain, frames) in [
        (&mut longer, vec![fork.clone(), fork2.clone()]),
        (&mut valid_ahead, vec![first.clone(), second.clone()]),
    ] {
        for frame in frames {
            let step = chain.prepare_continuity(frame, &state).unwrap();
            chain.commit_continuity_after_persist(step, &state).unwrap();
        }
    }
    // A candidate prepared under the old policy must also be rechecked on commit.
    let stale = empty.prepare_continuity(fork.clone(), &state).unwrap();
    close_with_history(
        &mut state,
        &[1, 2],
        vec![seal(&first)],
        std::slice::from_ref(&first),
    );
    assert!(matches!(
        empty.prepare_next(event(&state, 2, 1, EventId::ZERO, "reset"), &state),
        Err(Error::Gap)
    ));
    assert!(matches!(
        conflicting.prepare_next(event(&state, 2, 2, fork.id(), "fork continuation"), &state),
        Err(Error::Fork)
    ));
    assert!(matches!(
        longer.prepare_next(event(&state, 2, 3, fork2.id(), "longer fork"), &state),
        Err(Error::Gap)
    ));
    assert!(matches!(
        valid_ahead.prepare_next(
            event(&state, 2, 3, second.id(), "needs exact proof"),
            &state
        ),
        Err(Error::Gap)
    ));
    assert!(matches!(
        empty.prepare_continuity(fork, &state),
        Err(Error::Fork)
    ));
    assert_eq!(empty.authoring_head(&state), Err(Error::Gap));
    assert_eq!(conflicting.authoring_head(&state), Err(Error::Fork));
    assert_eq!(longer.authoring_head(&state), Err(Error::Gap));
    let mut rebuilt = empty;
    assert_eq!(
        rebuilt.commit_continuity_after_persist(stale, &state),
        Err(Error::Fork)
    );
    assert_eq!(rebuilt.head(), AuthorHead::EMPTY);
    for frame in [first, second.clone()] {
        let step = rebuilt.prepare_continuity(frame, &state).unwrap();
        rebuilt
            .commit_continuity_after_persist(step, &state)
            .unwrap();
    }
    let current = event(&state, 2, 3, second.id(), "exact known ancestry");
    let step = rebuilt.prepare_next(current.clone(), &state).unwrap();
    rebuilt.commit_after_persist(step, &state).unwrap();
    assert_eq!(rebuilt.head().event, current.id());
}
