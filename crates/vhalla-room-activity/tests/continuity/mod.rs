use super::*;
use vhalla_room_activity::continuity::{ContinuityPosition, EvidenceRole, MAX_HISTORY_SEGMENT};

fn next(scope: RoomScope, policy: RoomRecordId, seq: u64, previous: EventId) -> VerifiedEvent {
    let mut body = claims(scope, policy);
    body.sequence = seq;
    body.previous = previous;
    verified(body)
}

#[test]
fn continuity_more_than_one_page_survives_revocation_without_publishing_ancestors() {
    let mut f = Fixture::new();
    let old = f.policy(true);
    let mut ancestors = Vec::new();
    let mut previous = EventId::ZERO;
    for seq in 1..=65 {
        let event = next(f.scope, old, seq, previous);
        previous = event.id();
        ancestors.push(event);
    }
    f.policy(false);
    let current = f.policy(true);
    let mut chain = f.chain();
    let mut staging = ContinuityPosition::begin(&chain);
    for page in ancestors.chunks(MAX_HISTORY_SEGMENT) {
        let candidate = staging
            .prepare_segment(page.to_vec(), &f.context())
            .unwrap();
        let saved = staging
            .commit_segment_after_persist(candidate, &f.context())
            .unwrap();
        assert_eq!(saved.role(), EvidenceRole::HistoricalContinuity);
        assert_eq!(saved.events().len(), page.len());
        assert!(chain.position().is_none());
    }
    assert_eq!(staging.staged_tail().unwrap().sequence(), 65);
    let terminal = next(f.scope, current, 66, previous);
    let candidate = chain
        .prepare_continuity_terminal(staging, terminal.clone(), &f.context())
        .unwrap();
    assert!(chain.position().is_none());
    let admitted = chain
        .commit_continuity_terminal_after_persist(candidate, staging, &f.context())
        .unwrap();
    assert_eq!(admitted.event(), &terminal);
    assert_eq!(chain.position().unwrap().sequence(), 66);
}

#[test]
fn continuity_old_or_disabled_policy_can_never_become_a_fresh_terminal() {
    let mut f = Fixture::new();
    let old = f.policy(true);
    let ancestor = next(f.scope, old, 1, EventId::ZERO);
    let disabled = f.policy(false);
    let mut chain = f.chain();
    let mut staging = ContinuityPosition::begin(&chain);
    let candidate = staging
        .prepare_segment(vec![ancestor.clone()], &f.context())
        .unwrap();
    staging
        .commit_segment_after_persist(candidate, &f.context())
        .unwrap();
    let blocked = next(f.scope, disabled, 2, ancestor.id());
    assert_eq!(
        staging
            .prepare_segment(vec![blocked], &f.context())
            .unwrap_err(),
        Error::Policy
    );
    let old_terminal = next(f.scope, old, 2, ancestor.id());
    assert_eq!(
        chain
            .prepare_continuity_terminal(staging, old_terminal.clone(), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    let current = f.policy(true);
    assert_eq!(
        chain
            .prepare_continuity_terminal(staging, old_terminal.clone(), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    let candidate = staging
        .prepare_segment(vec![old_terminal.clone()], &f.context())
        .unwrap();
    staging
        .commit_segment_after_persist(candidate, &f.context())
        .unwrap();
    let terminal = next(f.scope, current, 3, old_terminal.id());
    let candidate = chain
        .prepare_continuity_terminal(staging, terminal, &f.context())
        .unwrap();
    chain
        .commit_continuity_terminal_after_persist(candidate, staging, &f.context())
        .unwrap();
    assert_eq!(chain.position().unwrap().sequence(), 3);
}

#[test]
fn continuity_segment_checks_full_scope_key_bounds_order_and_policy() {
    let mut f = Fixture::new();
    let policy = f.policy(true);
    let chain = f.chain();
    let staging = ContinuityPosition::begin(&chain);
    let first = next(f.scope, policy, 1, EventId::ZERO);
    let second = next(f.scope, policy, 2, first.id());
    assert_eq!(
        staging
            .prepare_segment(Vec::new(), &f.context())
            .unwrap_err(),
        Error::Bounds
    );
    assert_eq!(
        staging
            .prepare_segment(vec![first.clone(); MAX_HISTORY_SEGMENT + 1], &f.context())
            .unwrap_err(),
        Error::Bounds
    );
    assert_eq!(
        staging
            .prepare_segment(vec![second.clone(), first.clone()], &f.context())
            .unwrap_err(),
        Error::Gap
    );
    let fork = next(f.scope, policy, 2, EventId::from_bytes([3; 32]));
    assert_eq!(
        staging
            .prepare_segment(vec![first.clone(), fork], &f.context())
            .unwrap_err(),
        Error::Fork
    );
    let foreign = next(
        RoomScope {
            network: [33; 32],
            ..f.scope
        },
        policy,
        1,
        EventId::ZERO,
    );
    assert_eq!(
        staging
            .prepare_segment(vec![foreign], &f.context())
            .unwrap_err(),
        Error::Scope
    );
    let unknown = next(
        f.scope,
        RoomRecordId::from_bytes([88; 32]),
        1,
        EventId::ZERO,
    );
    assert_eq!(
        staging
            .prepare_segment(vec![unknown], &f.context())
            .unwrap_err(),
        Error::Policy
    );
    let other = SigningKey::from_bytes(&[44; 32]);
    let mut body = first.claims().clone();
    body.author = other.verifying_key().to_bytes();
    let foreign = UnsignedEvent::new(body)
        .unwrap()
        .sign_with_key(&other)
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(
        staging
            .prepare_segment(vec![foreign], &f.context())
            .unwrap_err(),
        Error::Author
    );
    assert!(chain.position().is_none());
}

#[test]
fn continuity_both_hidden_and_published_bases_and_current_policy_are_compared() {
    let mut f = Fixture::new();
    let policy = f.policy(true);
    let mut chain = f.chain();
    let empty = ContinuityPosition::begin(&chain);
    let mut staged = empty;
    let first = next(f.scope, policy, 1, EventId::ZERO);
    let candidate = staged
        .prepare_segment(vec![first.clone()], &f.context())
        .unwrap();
    let stale = staged
        .prepare_segment(vec![first.clone()], &f.context())
        .unwrap();
    staged
        .commit_segment_after_persist(candidate, &f.context())
        .unwrap();
    assert_eq!(
        staged
            .commit_segment_after_persist(stale, &f.context())
            .unwrap_err(),
        Error::StaleBase
    );
    let second = next(f.scope, policy, 2, first.id());
    let candidate = chain
        .prepare_continuity_terminal(staged, second.clone(), &f.context())
        .unwrap();
    assert_eq!(
        chain
            .commit_continuity_terminal_after_persist(candidate, empty, &f.context())
            .unwrap_err(),
        Error::StaleBase
    );
    let candidate = chain
        .prepare_continuity_terminal(staged, second.clone(), &f.context())
        .unwrap();
    let another = chain
        .prepare_continuity_terminal(staged, second.clone(), &f.context())
        .unwrap();
    chain
        .commit_continuity_terminal_after_persist(candidate, staged, &f.context())
        .unwrap();
    assert_eq!(
        chain
            .commit_continuity_terminal_after_persist(another, staged, &f.context())
            .unwrap_err(),
        Error::StaleBase
    );
    let staged = ContinuityPosition::begin(&chain);
    let third = next(f.scope, policy, 3, second.id());
    let candidate = chain
        .prepare_continuity_terminal(staged, third, &f.context())
        .unwrap();
    f.policy(false);
    assert_eq!(
        chain
            .commit_continuity_terminal_after_persist(candidate, staged, &f.context())
            .unwrap_err(),
        Error::StalePolicy
    );
    assert_eq!(chain.position().unwrap().sequence(), 2);
}

#[test]
fn continuity_local_staging_restore_never_manufactures_an_admission() {
    let mut f = Fixture::new();
    let policy = f.policy(true);
    let mut chain = f.chain();
    let first = next(f.scope, policy, 1, EventId::ZERO);
    let candidate = chain.prepare_next(first.clone(), &f.context()).unwrap();
    chain.commit_after_persist(candidate, &f.context()).unwrap();
    assert_eq!(
        ContinuityPosition::restore_local_staging(&chain, &first).unwrap_err(),
        Error::StaleBase
    );
    let second = next(f.scope, policy, 2, first.id());
    let staged = ContinuityPosition::restore_local_staging(&chain, &second).unwrap();
    assert_eq!(staged.published_base(), chain.position());
    assert_eq!(staged.staged_tail().unwrap().sequence(), 2);
    assert_eq!(chain.position().unwrap().sequence(), 1);
}

#[test]
fn continuity_staging_compares_registry_and_network_without_moving_tail() {
    let mut f = Fixture::new();
    let old = f.policy(true);
    let chain = f.chain();
    let mut staging = ContinuityPosition::begin(&chain);
    let before = staging;
    let first = next(f.scope, old, 1, EventId::ZERO);
    let candidate = staging
        .prepare_segment(vec![first.clone()], &f.context())
        .unwrap();
    let other_network = AdmissionContext::new([99; 32], &f.registry).unwrap();
    assert_eq!(
        staging
            .commit_segment_after_persist(candidate, &other_network)
            .unwrap_err(),
        Error::StalePolicy
    );
    assert_eq!(staging, before);
    let candidate = staging
        .prepare_segment(vec![first.clone()], &f.context())
        .unwrap();
    f.policy(false);
    assert_eq!(
        staging
            .commit_segment_after_persist(candidate, &f.context())
            .unwrap_err(),
        Error::StalePolicy
    );
    assert_eq!(staging, before);
    // Re-evaluation may retain the old enabled revision as historical evidence,
    // but still cannot authorize a fresh post under the disabled current view.
    let candidate = staging.prepare_segment(vec![first], &f.context()).unwrap();
    staging
        .commit_segment_after_persist(candidate, &f.context())
        .unwrap();
    assert_eq!(staging.staged_tail().unwrap().sequence(), 1);
    assert!(chain.position().is_none());
}

#[test]
fn continuity_archived_room_retains_history_without_current_admission() {
    let mut f = Fixture::new();
    let policy = f.policy(true);
    let first = next(f.scope, policy, 1, EventId::ZERO);
    let second = next(f.scope, policy, 2, first.id());
    f.update(UpdateAction::Archive);
    let chain = f.chain();
    let mut staging = ContinuityPosition::begin(&chain);
    let candidate = staging.prepare_segment(vec![first], &f.context()).unwrap();
    let historical = staging
        .commit_segment_after_persist(candidate, &f.context())
        .unwrap();
    assert_eq!(historical.role(), EvidenceRole::HistoricalContinuity);
    assert_eq!(
        chain
            .prepare_continuity_terminal(staging, second, &f.context())
            .unwrap_err(),
        Error::Policy
    );
    assert!(chain.position().is_none());
}

#[test]
fn continuity_local_restore_refuses_every_foreign_scope_and_author() {
    let mut f = Fixture::new();
    let policy = f.policy(true);
    let chain = f.chain();
    for scope in [
        RoomScope {
            network: [88; 32],
            ..f.scope
        },
        RoomScope {
            realm: RealmId(888),
            ..f.scope
        },
        RoomScope {
            directory: DirectoryId::from_bytes([88; 32]),
            ..f.scope
        },
        RoomScope {
            room: RoomGenesisId::from_bytes([88; 32]),
            ..f.scope
        },
    ] {
        let foreign = next(scope, policy, 1, EventId::ZERO);
        assert_eq!(
            ContinuityPosition::restore_local_staging(&chain, &foreign).unwrap_err(),
            Error::Scope
        );
    }
    let other = SigningKey::from_bytes(&[45; 32]);
    let mut body = claims(f.scope, policy);
    body.author = other.verifying_key().to_bytes();
    let foreign = UnsignedEvent::new(body)
        .unwrap()
        .sign_with_key(&other)
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(
        ContinuityPosition::restore_local_staging(&chain, &foreign).unwrap_err(),
        Error::Author
    );
    assert!(chain.position().is_none());
}

#[test]
fn continuity_inline_projection_prepares_terminal_without_claiming_persistence() {
    let mut f = Fixture::new();
    let policy = f.policy(true);
    let mut chain = f.chain();
    let mut staging = ContinuityPosition::begin(&chain);
    let before = staging;
    let first = next(f.scope, policy, 1, EventId::ZERO);
    let second = next(f.scope, policy, 2, first.id());
    let suffix = staging.prepare_segment(vec![first], &f.context()).unwrap();
    assert_eq!(suffix.before(), before);
    let projected = suffix.next_position();
    let terminal = chain
        .prepare_continuity_terminal(projected, second, &f.context())
        .unwrap();
    assert_eq!(staging, before);
    assert!(chain.position().is_none());
    assert_eq!(projected.staged_tail().unwrap().sequence(), 1);
    // The integration owner durably publishes suffix + terminal together here.
    // Installing the segment confirms the projected tail is exactly the one
    // subsequently used to advance the author head, with no extra admission.
    let historical = staging
        .commit_segment_after_persist(suffix, &f.context())
        .unwrap();
    assert_eq!(historical.role(), EvidenceRole::HistoricalContinuity);
    assert_eq!(staging, projected);
    let receipt = chain
        .commit_continuity_terminal_after_persist(terminal, staging, &f.context())
        .unwrap();
    assert_eq!(receipt.event().claims().sequence, 2);
    assert_eq!(chain.position().unwrap().sequence(), 2);
}

mod unsigned;
