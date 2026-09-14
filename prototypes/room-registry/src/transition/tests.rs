use super::*;
use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> Id {
    key(seed).verifying_key().to_bytes()
}
fn digest(bytes: &[u8]) -> Id {
    Sha256::digest(bytes).into()
}
fn hex_id(value: &str) -> Id {
    let bytes = value.as_bytes();
    assert_eq!(bytes.len(), 64);
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let nibble = |b: u8| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("invalid hex"),
        };
        out[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    out
}
fn policy() -> super::super::Policy {
    super::super::Policy {
        base_cost: 1,
        window_seconds: 100,
        max_in_window: 16,
        support_epoch_seconds: 1000,
        max_lifetime_rooms: 128,
    }
}
fn app() -> Application {
    let mut directory = Directory::new(
        [42; 32],
        policy(),
        &(10..30).map(public).collect::<Vec<_>>(),
    )
    .unwrap();
    for owner in 1..=8 {
        directory
            .apply_finalized_support(public(10 + owner), public(owner), 0, [owner; 32], 0)
            .unwrap();
    }
    Application::from_fixture(directory, [7; 32]).unwrap()
}
fn proposal(app: &Application, owner: u8, actor: u8, slug: &str) -> Proposal {
    let (slot, cost) = app.directory().quote(public(owner)).unwrap();
    Proposal::sign(
        super::super::Draft {
            directory: app.directory().id(),
            policy: app.directory().policy_id(),
            owner: public(owner),
            actor: public(actor),
            slug: super::super::Slug::new(slug).unwrap(),
            description: String::from("bounded room"),
            slot,
            cost,
            expires_at: 10_000,
            nonce: digest(slug.as_bytes()),
        },
        &key(owner),
        &key(actor),
    )
    .unwrap()
}

#[test]
fn failed_prefix_is_atomic_and_matching_root_validates_independently() {
    let first = app();
    let one = proposal(&first, 1, 21, "one");
    let two = proposal(&first, 1, 22, "two");
    let before = first.frontier();
    assert_eq!(
        first.prepare(1, &[one.clone(), two.clone()]).unwrap_err(),
        Error::Operation(super::super::Error::Slot)
    );
    assert_eq!(first.frontier(), before);
    assert_eq!(first.directory().room(&one.draft().slug), None);

    let checked = first.prepare(1, core::slice::from_ref(&one)).unwrap();
    let batch = checked.batch().clone();
    let mut second = app();
    let expected_next = checked.next();
    assert_eq!(second.validate(&batch).unwrap().next(), expected_next);
    assert_eq!(second.apply_locally(checked).unwrap(), Applied::New);
    assert_eq!(second.frontier(), expected_next);
}

#[test]
fn complete_parent_control_policy_and_root_mutations_fail_closed() {
    let source = app();
    let p = proposal(&source, 1, 21, "one");
    let checked = source.prepare(1, core::slice::from_ref(&p)).unwrap();
    let mut parent = checked.batch().parent();
    parent.height += 1;
    let mut altered = checked.batch().clone();
    altered.parent = parent;
    assert_eq!(source.validate(&altered).unwrap_err(), Error::Parent);
    altered = checked.batch().clone();
    altered.parent.control = [8; 32];
    assert_eq!(source.validate(&altered).unwrap_err(), Error::Parent);
    altered = checked.batch().clone();
    altered.parent.policy = [8; 32];
    assert_eq!(source.validate(&altered).unwrap_err(), Error::Parent);
    altered = checked.batch().clone();
    altered.result = [9; 32];
    assert_eq!(source.validate(&altered).unwrap_err(), Error::Root);
    for which in 0..4 {
        let mut candidate = checked.batch().clone();
        let mut frontier = candidate.parent;
        match which {
            0 => frontier.directory = [3; 32],
            1 => frontier.value = [4; 32],
            2 => frontier.state = [5; 32],
            _ => frontier.time += 1,
        }
        candidate.parent = frontier;
        assert_eq!(source.validate(&candidate).unwrap_err(), Error::Parent);
    }
}

#[test]
fn two_owner_slug_and_prepared_stale_writer_races_are_serialized() {
    let mut left = app();
    let right = app();
    let a = proposal(&left, 1, 21, "same");
    let b = proposal(&right, 2, 22, "same");
    let prepared_a = left.prepare(1, core::slice::from_ref(&a)).unwrap();
    let prepared_b = right.prepare(1, core::slice::from_ref(&b)).unwrap();
    left.apply_locally(prepared_a).unwrap();
    assert!(matches!(
        left.validate(prepared_b.batch()),
        Err(Error::Parent)
    ));
    assert_eq!(
        left.apply_locally(prepared_b.clone()).unwrap_err(),
        Error::Parent
    );
    let stale = right.prepare(1, core::slice::from_ref(&b)).unwrap();
    let mut winner = app();
    winner
        .apply_locally(winner.prepare(1, core::slice::from_ref(&a)).unwrap())
        .unwrap();
    assert!(matches!(winner.validate(stale.batch()), Err(Error::Parent)));
}

#[test]
fn exact_retry_does_not_double_debit_and_retry_only_root_keeps_clock_monotonic() {
    let mut state = app();
    let p = proposal(&state, 1, 21, "one");
    let checked = state.prepare(1, core::slice::from_ref(&p)).unwrap();
    let root = checked.next().state;
    state.apply_locally(checked.clone()).unwrap();
    let spent = state.directory().account(public(1)).spent;
    assert_eq!(state.apply_locally(checked), Ok(Applied::Existing));
    assert_eq!(state.directory().account(public(1)).spent, spent);
    let retry = state.prepare(2, core::slice::from_ref(&p)).unwrap();
    assert_eq!(retry.next().state, root);
    assert_eq!(retry.next().time, 2);
    state.apply_locally(retry).unwrap();
    assert_eq!(state.frontier().time, 2);
    assert_eq!(state.directory().account(public(1)).spent, spent);
    let stale_time = state.prepare(1, core::slice::from_ref(&p));
    assert_eq!(stale_time.unwrap_err(), Error::Clock);
}

#[test]
fn batch_bounds_accept_sixteen_and_reject_zero_and_seventeen() {
    let state = app();
    assert_eq!(
        Batch::new(state.frontier(), 1, &[], [1; 32]),
        Err(Error::Bounds)
    );
    let many = (0..17)
        .map(|i| proposal(&state, 1, 21, &format!("room-{i}")))
        .collect::<Vec<_>>();
    assert_eq!(
        Batch::new(state.frontier(), 1, &many, [1; 32]),
        Err(Error::Bounds)
    );
    let repeated = alloc::vec![many[0].clone(); MAX_BATCH];
    let checked = state.prepare(1, &repeated).unwrap();
    let single = state.prepare(1, &many[..1]).unwrap();
    assert_eq!(checked.next().state, single.next().state);
    assert_ne!(checked.next().value, single.next().value);
    assert_eq!(
        state.validate(checked.batch()).unwrap().next(),
        checked.next()
    );
}

#[test]
fn height_overflow_and_maximum_consensus_time_fail_or_remain_bounded() {
    let mut overflow = app();
    overflow.frontier.height = u64::MAX;
    let p = proposal(&overflow, 1, 21, "height");
    assert_eq!(
        overflow.prepare(1, core::slice::from_ref(&p)).unwrap_err(),
        Error::Height
    );

    let source = app();
    let mut draft = proposal(&source, 1, 21, "max-time").draft().clone();
    draft.expires_at = u64::MAX;
    draft.nonce = [8; 32];
    let max_time = Proposal::sign(draft, &key(1), &key(21)).unwrap();
    let checked = source
        .prepare(u64::MAX - 1, core::slice::from_ref(&max_time))
        .unwrap();
    assert_eq!(checked.next().time, u64::MAX - 1);
}

#[test]
fn canonical_state_and_fixture_genesis_match_independent_golden() {
    let directory = Directory::new([7; 32], super::super::Policy::default(), &[]).unwrap();
    assert_eq!(
        directory.policy_id(),
        hex_id("b18774959c6e312bde165fe0aa5df0cf23ba2aad9a4e8d385c8f8e9afe434f53")
    );
    assert_eq!(
        state_commitment(&directory),
        hex_id("1216a857b1b743b29ddae5797a9ca907eee80c0956a394c885765e4d8e95ab06")
    );
    let application = Application::from_fixture(directory, [9; 32]).unwrap();
    assert_eq!(
        application.frontier().value,
        hex_id("e899c5756bc457891435d0b8615c6577ecb5c2c6732117d47a5b50086f7c31ec")
    );
}

#[test]
fn state_root_covers_policy_signatures_evidence_and_tombstones() {
    let mut state = app();
    let p = proposal(&state, 1, 21, "one");
    state
        .apply_locally(state.prepare(1, core::slice::from_ref(&p)).unwrap())
        .unwrap();
    let original = state.frontier().state;
    let mut altered = state.directory().clone();
    altered
        .rooms
        .get_mut(&p.draft().slug)
        .unwrap()
        .proposal
        .owner_signature[0] ^= 1;
    assert_ne!(state_commitment(&altered), original);
    let mut tombstone = state.directory().clone();
    tombstone
        .archive_as_owner(&key(1), &p.draft().slug, 2)
        .unwrap();
    assert_ne!(state_commitment(&tombstone), original);
    let mut evidence = state.directory().clone();
    let old = evidence.support.iter().next().copied().unwrap();
    evidence.support.remove(&old);
    evidence.support.insert((old.0, old.1, old.2 + 1));
    assert_ne!(state_commitment(&evidence), original);
    let mut evidence_id = state.directory().clone();
    let (old_id, binding) = evidence_id
        .evidence
        .iter()
        .next()
        .map(|(id, b)| (*id, *b))
        .unwrap();
    evidence_id.evidence.remove(&old_id);
    evidence_id.evidence.insert([0xaa; 32], binding);
    assert_ne!(state_commitment(&evidence_id), original);
    let mut changed_policy = state.directory().clone();
    changed_policy.policy.base_cost += 1;
    assert_ne!(state_commitment(&changed_policy), original);
}

#[test]
fn equivalent_btree_insertion_order_has_one_canonical_root() {
    fn with_order(order: &[(u8, u8, u8)]) -> Directory {
        let mut d = Directory::new(
            [42; 32],
            policy(),
            &(10..30).map(public).collect::<Vec<_>>(),
        )
        .unwrap();
        for (source, owner, evidence) in order {
            d.apply_finalized_support(public(*source), public(*owner), 0, [*evidence; 32], 0)
                .unwrap();
        }
        d
    }
    let a = with_order(&[(10, 1, 1), (11, 2, 2), (12, 3, 3)]);
    let b = with_order(&[(12, 3, 3), (10, 1, 1), (11, 2, 2)]);
    assert_eq!(state_commitment(&a), state_commitment(&b));
}

proptest! {
    #[test]
    fn generated_schedule_replay_is_deterministic_and_idempotent(order in prop::collection::vec(0usize..4, 1..=8)) {
        let source = app();
        let proposals = (0..4).map(|i| proposal(&source, 1 + i as u8, 21 + i as u8, &format!("room-{i}"))).collect::<Vec<_>>();
        let mut unique = BTreeSet::new();
        let selected = order.into_iter().filter(|i| unique.insert(*i)).map(|i| proposals[i].clone()).collect::<Vec<_>>();
        prop_assume!(!selected.is_empty());
        let checked = source.prepare(1, &selected).unwrap();
        let batch = checked.batch().clone();
        let mut replay = app();
        let checked_again = replay.validate(&batch).unwrap();
        prop_assert_eq!(checked_again.next(), checked.next());
        replay.apply_locally(checked_again).unwrap();
        let before = replay.frontier();
        prop_assert_eq!(replay.apply_locally(checked), Ok(Applied::Existing));
        prop_assert_eq!(replay.frontier(), before);
    }
}
