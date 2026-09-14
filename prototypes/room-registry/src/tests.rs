use super::*;
use alloc::{format, vec};
use proptest::prelude::*;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> Id {
    key(seed).verifying_key().to_bytes()
}
fn policy() -> Policy {
    Policy {
        base_cost: 1,
        window_seconds: 100,
        max_in_window: 2,
        support_epoch_seconds: 1000,
        max_lifetime_rooms: 128,
    }
}
fn empty() -> Directory {
    Directory::new(
        [42; 32],
        policy(),
        &(10..110).map(public).collect::<Vec<_>>(),
    )
    .unwrap()
}
fn credit(d: &mut Directory, owner: u8, count: u8) {
    for source in 10..10 + count {
        d.apply_finalized_support(
            public(source),
            public(owner),
            0,
            digest(&[source, owner]),
            0,
        )
        .unwrap();
    }
}
fn propose(d: &Directory, owner: u8, actor: u8, slug: &str) -> Proposal {
    let (slot, cost) = d.quote(public(owner)).unwrap();
    Proposal::sign(
        Draft {
            directory: d.id(),
            policy: d.policy_id(),
            owner: public(owner),
            actor: public(actor),
            slug: Slug::new(slug).unwrap(),
            description: String::from("Rust café simulations"),
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
fn denial_unchanged(d: &mut Directory, p: &Proposal, now: u64, error: Error) {
    let before = d.clone();
    assert_eq!(d.finalize(p, now), Err(error));
    assert_eq!(*d, before);
}

#[test]
fn costs_are_marginal_squares_and_public_reputation_is_not_burned() {
    let p = Policy::default();
    assert_eq!(
        (1..=5).map(|n| p.cost(n).unwrap()).collect::<Vec<_>>(),
        vec![32, 128, 288, 512, 800]
    );
    assert_eq!(p.cost(0), Err(Error::Slot));
    assert_eq!(
        Policy {
            base_cost: u64::MAX,
            ..policy()
        }
        .cost(2),
        Err(Error::Cost)
    );
    let mut d = empty();
    let first = propose(&d, 1, 2, "first");
    denial_unchanged(&mut d, &first, 1, Error::InsufficientCredit);
    credit(&mut d, 1, 5);
    d.finalize(&first, 1).unwrap();
    let second = propose(&d, 1, 3, "second");
    d.finalize(&second, 2).unwrap();
    assert_eq!(
        d.account(public(1)),
        Account {
            earned: 5,
            spent: 5,
            lifetime_slots: 2
        }
    );
    let third = propose(&d, 1, 3, "third");
    denial_unchanged(&mut d, &third, 101, Error::InsufficientCredit);
}

#[test]
fn tentative_partition_claims_need_one_agreed_allocation_order() {
    let mut start = empty();
    credit(&mut start, 1, 1);
    credit(&mut start, 2, 1);
    let a = propose(&start, 1, 3, "rust");
    let b = propose(&start, 2, 4, "rust");
    assert_eq!(start.search("rust", 64, MAX_ROOMS).unwrap().rooms.len(), 0);
    // Counterexample: a map per partition cannot establish shared uniqueness.
    let mut left = start.clone();
    let mut right = start.clone();
    left.finalize(&a, 1).unwrap();
    right.finalize(&b, 1).unwrap();
    assert_ne!(
        left.room(&a.draft.slug).unwrap().id(),
        right.room(&b.draft.slug).unwrap().id()
    );
    // Once a SINGLE directory history is agreed, both possible orders are safe.
    for (winner, loser) in [(&a, &b), (&b, &a)] {
        let mut directory = start.clone();
        directory.finalize(winner, 1).unwrap();
        denial_unchanged(&mut directory, loser, 1, Error::Taken);
        assert_eq!(directory.account(loser.draft.owner).spent, 0);
        assert_eq!(directory.rooms.len(), 1);
    }
}

#[test]
fn sibling_agents_share_one_slot_and_exact_retry_is_idempotent() {
    let mut base = empty();
    credit(&mut base, 1, 20);
    let a = propose(&base, 1, 2, "agent-a");
    let b = propose(&base, 1, 3, "agent-b");
    for (first, second) in [(&a, &b), (&b, &a)] {
        let mut d = base.clone();
        assert_eq!(d.finalize(first, 1), Ok(Created::New(first.id())));
        let before = d.clone();
        assert_eq!(d.finalize(first, 2), Ok(Created::Existing(first.id())));
        assert_eq!(d, before);
        denial_unchanged(&mut d, second, 2, Error::Slot);
        assert_eq!(d.quote(public(1)), Ok((2, 4)));
    }
}

#[test]
fn permits_bind_owner_actor_directory_policy_text_and_expiry() {
    let mut d = empty();
    credit(&mut d, 1, 20);
    let good = propose(&d, 1, 2, "secure-room");
    let mut changed = good.clone();
    changed.draft.description.push('!');
    denial_unchanged(&mut d, &changed, 1, Error::Signature);
    changed = good.clone();
    changed.draft.actor = public(3);
    denial_unchanged(&mut d, &changed, 1, Error::Signature);
    changed = good.clone();
    changed.owner_signature = good.actor_signature;
    denial_unchanged(&mut d, &changed, 1, Error::Signature);
    let mut draft = good.draft.clone();
    draft.directory = [43; 32];
    changed = Proposal::sign(draft, &key(1), &key(2)).unwrap();
    denial_unchanged(&mut d, &changed, 1, Error::WrongDirectory);
    draft = good.draft.clone();
    draft.policy = [44; 32];
    changed = Proposal::sign(draft, &key(1), &key(2)).unwrap();
    denial_unchanged(&mut d, &changed, 1, Error::WrongPolicy);
    draft = good.draft.clone();
    draft.cost = 100;
    changed = Proposal::sign(draft, &key(1), &key(2)).unwrap();
    denial_unchanged(&mut d, &changed, 1, Error::Cost);
    denial_unchanged(&mut d, &good, 10_000, Error::Expired);
    assert_eq!(
        Proposal::sign(good.draft.clone(), &key(2), &key(2)),
        Err(Error::Owner)
    );
}

#[test]
fn exact_rolling_window_and_backwards_clock() {
    let mut d = empty();
    credit(&mut d, 1, 20);
    d.finalize(&propose(&d, 1, 2, "first"), 1).unwrap();
    d.finalize(&propose(&d, 1, 3, "second"), 99).unwrap();
    let third = propose(&d, 1, 4, "third");
    denial_unchanged(&mut d, &third, 100, Error::RateLimit);
    denial_unchanged(&mut d, &third, 98, Error::Clock);
    d.finalize(&third, 101).unwrap();
    assert_eq!(d.account(public(1)).lifetime_slots, 3);
}

#[test]
fn self_ineligible_and_rewrapped_support_do_not_mint_credits() {
    let mut d = empty();
    for source in [public(1), public(2)] {
        let before = d.clone();
        assert_eq!(
            d.apply_finalized_support(source, public(1), 0, [1; 32], 0),
            Err(Error::Owner)
        );
        assert_eq!(d, before);
    }
    assert_eq!(
        d.apply_finalized_support(public(10), public(1), 0, [1; 32], 0),
        Ok(true)
    );
    let before = d.clone();
    for _ in 0..10 {
        assert_eq!(
            d.apply_finalized_support(public(10), public(1), 0, [2; 32], 999),
            Ok(false)
        );
    }
    assert_eq!(d, before);
    assert_eq!(
        d.apply_finalized_support(public(10), public(1), 1, [2; 32], 1000),
        Ok(true)
    );
    assert_eq!(d.account(public(1)).earned, 2);
    let before = d.clone();
    assert_eq!(
        d.apply_finalized_support(public(11), public(1), 0, [3; 32], 1),
        Err(Error::Clock)
    );
    assert_eq!(d, before);
}

#[test]
fn old_support_cannot_earn_again_or_change_identity_across_arrival_epochs() {
    let mut d = empty();
    assert_eq!(
        d.apply_finalized_support(public(10), public(1), 0, [1; 32], 999),
        Ok(true)
    );
    let before = d.clone();
    for now in [1000, 2000, 1_000_000] {
        assert_eq!(
            d.apply_finalized_support(public(10), public(1), 0, [1; 32], now),
            Ok(false)
        );
        assert_eq!(d, before);
    }
    for (source, beneficiary, epoch, evidence) in [
        (public(10), public(1), 1, [1; 32]),
        (public(11), public(1), 0, [1; 32]),
        (public(10), public(2), 0, [1; 32]),
        (public(10), public(1), 2, [2; 32]),
        (public(10), public(1), 1, [0; 32]),
    ] {
        assert_eq!(
            d.apply_finalized_support(source, beneficiary, epoch, evidence, 1000),
            Err(Error::Evidence)
        );
        assert_eq!(d, before);
    }
    // A later arrival with a new envelope cannot duplicate the same contribution.
    assert_eq!(
        d.apply_finalized_support(public(10), public(1), 0, [2; 32], 1000),
        Ok(false)
    );
    assert_eq!(d, before);
    // Fresh authenticated activity is a distinct input, not inferred from arrival.
    assert_eq!(
        d.apply_finalized_support(public(10), public(1), 1, [2; 32], 1000),
        Ok(true)
    );
    assert_eq!(d.account(public(1)).earned, 2);
}

#[test]
fn archiving_keeps_slug_cost_and_rate_history_after_model_snapshot_copy() {
    let mut d = empty();
    credit(&mut d, 1, 20);
    credit(&mut d, 2, 2);
    let first = propose(&d, 1, 2, "rust");
    d.finalize(&first, 1).unwrap();
    let before = d.clone();
    assert_eq!(
        d.archive_as_owner(&key(2), &first.draft.slug, 2),
        Err(Error::Owner)
    );
    assert_eq!(d, before);
    d.archive_as_owner(&key(1), &first.draft.slug, 2).unwrap();
    // In-memory snapshot model only, not a filesystem restart or rollback proof.
    let mut restored = d.clone();
    assert_eq!(restored.quote(public(1)), Ok((2, 4)));
    assert!(restored
        .search("rust", 64, MAX_ROOMS)
        .unwrap()
        .rooms
        .is_empty());
    let thief = propose(&restored, 2, 2, "rust");
    denial_unchanged(&mut restored, &thief, 3, Error::Taken);
    let before = restored.clone();
    assert_eq!(
        restored.finalize(&first, 10_001),
        Ok(Created::Existing(first.id()))
    );
    assert_eq!(restored, before);
}

#[test]
fn slug_and_text_bounds_reject_ambiguous_or_unbounded_names() {
    for raw in [
        "", "Rust", "#rust", "a--b", "-a", "a-", "a/b", "rüst", "r%75st", "a b", "a\n",
    ] {
        assert_eq!(Slug::new(raw), Err(Error::Slug));
    }
    assert!(Slug::new(&"a".repeat(MAX_SLUG)).is_ok());
    assert_eq!(Slug::new(&"a".repeat(MAX_SLUG + 1)), Err(Error::Slug));
    let d = empty();
    let p = propose(&d, 1, 2, "safe");
    for text in [
        String::new(),
        "a".repeat(MAX_DESCRIPTION + 1),
        String::from("escape\u{1b}"),
    ] {
        let mut draft = p.draft.clone();
        draft.description = text;
        assert_eq!(Proposal::sign(draft, &key(1), &key(2)), Err(Error::Bounds));
    }
}

#[test]
fn search_is_literal_bounded_and_reports_partial_coverage() {
    let mut d = empty();
    credit(&mut d, 1, 5);
    let a = propose(&d, 1, 2, "rust");
    d.finalize(&a, 1).unwrap();
    let b = propose(&d, 1, 3, "wasm");
    d.finalize(&b, 2).unwrap();
    let r = d.search("RUST café", 64, MAX_ROOMS).unwrap();
    assert_eq!(r.rooms.len(), 2);
    assert!(!r.partial);
    assert_eq!(r.examined, 2);
    assert!(d.search("CAFÉ", 64, MAX_ROOMS).unwrap().rooms.is_empty());
    assert!(d
        .search("<script>", 64, MAX_ROOMS)
        .unwrap()
        .rooms
        .is_empty());
    let r = d.search("rust", 64, 0).unwrap();
    assert!(r.partial);
    assert_eq!(r.examined, 0);
    let r = d.search("", 1, MAX_ROOMS).unwrap();
    assert!(r.partial);
    assert_eq!(r.rooms.len(), 1);
    let r = d.search("absent", 64, 1).unwrap();
    assert!(r.partial);
    assert!(r.rooms.is_empty());
    assert_eq!(d.search("\u{1b}", 64, 1).unwrap_err(), Error::Bounds);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn generated_retries_and_sibling_races_cannot_overspend(order in prop::collection::vec(0usize..4, 0..24)) {
        let mut d = empty(); credit(&mut d, 1, 5);
        let proposals: Vec<_> = (0..4).map(|i| propose(&d, 1, 2+i, &format!("room-{i}"))).collect();
        for index in order {
            let before = d.clone();
            let result = d.finalize(&proposals[index], 1);
            if result.is_err() || matches!(result, Ok(Created::Existing(_))) { prop_assert_eq!(&d, &before); }
            prop_assert!(d.rooms.len() <= 1);
            prop_assert!(d.account(public(1)).spent <= d.account(public(1)).earned);
            prop_assert_eq!(d.rooms.len() as u32, d.account(public(1)).lifetime_slots);
        }
    }
    #[test]
    fn generated_text_queries_match_independent_ascii_fold_scan(query in "[a-zA-Z ]{0,50}", budget in 0usize..4, limit in 1usize..4) {
        let mut d = empty(); credit(&mut d, 1, 5);
        d.finalize(&propose(&d, 1, 2, "rust"), 1).unwrap();
        d.finalize(&propose(&d, 1, 3, "wasm"), 2).unwrap();
        let terms: Vec<_> = query.split_ascii_whitespace().collect();
        let result = d.search(&query, limit, budget);
        if terms.len() > 8 { prop_assert_eq!(result.unwrap_err(), Error::Bounds); }
        else {
            let result = result.unwrap();
            let expected: Vec<_> = d.rooms.values().take(budget).filter(|r| terms.iter().all(|t|
                r.draft().slug.as_str().to_ascii_lowercase().contains(&t.to_ascii_lowercase()) ||
                r.draft().description.to_ascii_lowercase().contains(&t.to_ascii_lowercase())
            )).take(limit).map(|r| r.id()).collect();
            prop_assert_eq!(result.rooms.iter().map(|r| r.id()).collect::<Vec<_>>(), expected);
            prop_assert!(result.examined <= budget);
        }
    }
}
