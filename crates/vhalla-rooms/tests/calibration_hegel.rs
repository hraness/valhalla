//! Generative Hegel counterparts of the deterministic economy measurements
//! in `calibration.rs`: the same proven bounds — quadratic cumulative cost,
//! per-account sybil linearization, the eligible-set funnel and the
//! window/lifetime demand caps — asserted under drawn policies, support
//! patterns, demand bursts and timing rather than one fixed scenario.
//!
//! Cases are pure-state but real evidence costs real signature work (~5 ms
//! per committed award), so the drawn policy keeps `max_lifetime_rooms`
//! small: reaching the `calibration.rs` cap of 8 rooms needs
//! `cumulative_cost(8)` = 204 credits — 204 committed award records, the
//! deterministic test's whole runtime for a single scenario. The invariants
//! themselves are policy-parametric — `base_cost·n(n+1)(2n+1)/6` spend,
//! `max_in_window` per rolling `window_seconds`, `max_lifetime_rooms`
//! lifetime — so drawing the policy exercises the identical bounds at a
//! reachable scale rather than at one constant.
mod common;

use std::collections::{BTreeSet, VecDeque};

use common::*;
use hegel::{generators as gs, TestCase};
use vhalla_rooms::{
    awards::AwardDenial,
    registry::{Applied, DirectoryPolicy, Registry, RegistryError},
    RoomRecordId,
};
use vhalla_social::{
    archive::{Archive, Limits},
    control::ControlView,
    Body, OwnerId,
};

/// Wider archive bounds for long-horizon simulations — identical to
/// `calibration.rs`: dozens of reactions per source across many epochs.
fn sim_limits() -> Limits {
    Limits {
        records: 4_096,
        control_reserve: 256,
        data_per_owner: 256,
        data_per_writer: 256,
        control_per_owner: 256,
        pending: 256,
        pending_per_signer: 8,
    }
}

/// Cumulative unit-base credit an account needs for `rooms` rooms: the
/// quadratic charge sums to rooms·(rooms+1)·(2·rooms+1)/6 — the bound
/// `calibration.rs` proves. `spend_bound` scales it by the policy base cost.
fn cumulative_cost(rooms: u64) -> u64 {
    rooms * (rooms + 1) * (2 * rooms + 1) / 6
}

/// Expected lifetime spend after `slots` rooms under `policy`.
fn spend_bound(policy: &DirectoryPolicy, slots: u64) -> u64 {
    policy.base_cost * cumulative_cost(slots)
}

/// A drawn directory policy around the shared fixture's shape: small unit
/// base cost, the fixture's whole-epoch support quantum, and bounded
/// window/lifetime limits in `cap_min..=cap_max` — small enough that a full
/// calibration stays cheap while every economic bound still bites.
fn draw_policy(tc: &TestCase, cap_min: u32, cap_max: u32) -> DirectoryPolicy {
    DirectoryPolicy {
        base_cost: tc.draw(gs::integers::<u64>().min_value(1).max_value(2)),
        window_seconds: EPOCH * tc.draw(gs::integers::<u64>().min_value(1).max_value(2)),
        max_in_window: tc.draw(gs::integers::<u16>().min_value(1).max_value(2)),
        support_epoch_seconds: EPOCH,
        max_lifetime_rooms: tc.draw(gs::integers::<u32>().min_value(cap_min).max_value(cap_max)),
    }
}

/// `sources()` with a caller-chosen policy: a drawn pool of source owners
/// admitted as the registry's eligible award set under `policy`.
fn sourced_registry(
    archive: &mut Archive,
    start: u8,
    count: u8,
    policy: DirectoryPolicy,
) -> (Vec<Owner>, Registry) {
    let pool: Vec<Owner> = (start..start + count).map(|s| owner(archive, s)).collect();
    let eligible: Vec<OwnerId> = pool.iter().map(|s| s.id).collect();
    (
        pool,
        Registry::new(DIRECTORY, REALM, policy, &eligible).unwrap(),
    )
}

/// One epoch of organic support — identical to `calibration.rs`: every
/// listed source awards `beneficiary` once; all reactions are emitted and
/// sealed first so a single committed `ControlView` serves the whole epoch.
/// Every listed award must be a fresh (source, beneficiary, epoch) triple —
/// callers pass each source at most once per whole-epoch step.
fn epoch_of_support(
    registry: &mut Registry,
    archive: &mut Archive,
    sources: &mut [Owner],
    beneficiary: &Owner,
    now: u64,
) {
    let evidence: Vec<_> = sources
        .iter_mut()
        .map(|source| react_to_post(archive, source, beneficiary))
        .collect();
    let view = ControlView::new(archive, now);
    for record in &evidence {
        assert_eq!(registry.award(record, &view, now), Ok(Applied::Awarded));
    }
}

/// One drawn creation attempt asserted against the exact registry ordering:
/// the policy quote is the only accepted `(slot, charge)` — slot `n` priced
/// at `base_cost·n²` — and a denial is `InsufficientCredit` when the charge
/// overruns the balance, else `RateLimit` when the rolling window is full;
/// credit is assessed before the window, matching `Registry::create`.
/// `in_window` counts this owner's creations still inside the current
/// `window_seconds`. Returns true when the room was created.
fn attempt_room(
    registry: &mut Registry,
    archive: &Archive,
    owner: &Owner,
    grant: RoomRecordId,
    slug_index: u32,
    in_window: u16,
    now: u64,
) -> bool {
    let policy = *registry.policy();
    let slots = u64::from(registry.account(owner.id).lifetime_slots);
    match registry.quote(owner.id) {
        Err(error) => {
            // The only quote denial reachable here is the lifetime cap.
            assert_eq!(error, RegistryError::Slot);
            assert_eq!(slots, u64::from(policy.max_lifetime_rooms));
            false
        }
        Ok((slot, charge)) => {
            assert_eq!(u64::from(slot), slots + 1);
            assert_eq!(charge, policy.base_cost * u64::from(slot) * u64::from(slot));
            let account = registry.account(owner.id);
            assert!(account.spent <= account.earned);
            let slug = format!("room-{slug_index}");
            let outcome = apply(
                registry,
                archive,
                &creation_with_policy(
                    owner,
                    grant,
                    grant,
                    &slug,
                    slot,
                    charge,
                    slug_index as u8,
                    policy.id(),
                ),
                now,
            );
            if account.spent + charge > account.earned {
                assert_eq!(outcome, Err(RegistryError::InsufficientCredit));
                false
            } else if in_window >= policy.max_in_window {
                assert_eq!(outcome, Err(RegistryError::RateLimit));
                false
            } else {
                assert!(
                    matches!(outcome, Ok(Applied::Created(_))),
                    "expected creation, got {outcome:?}"
                );
                true
            }
        }
    }
}

/// Mirror of the registry's per-owner rolling window: evict entries
/// `window_seconds` or older, then the window's occupancy bounds new
/// creations.
fn evict_window(window: &mut VecDeque<u64>, window_seconds: u64, now: u64) {
    while window
        .front()
        .is_some_and(|t| now.saturating_sub(*t) >= window_seconds)
    {
        window.pop_front();
    }
}

/// `honest_onboarding_pays_quadratic_cumulative_cost` generalized: the
/// policy, source-pool size, epoch count, per-epoch supporter counts and
/// per-epoch creation demand are all drawn. Whatever the pattern, each room
/// pays the quoted `base_cost·slot²` charge, cumulative spend is exactly
/// `spend_bound(slots)` and earned credit is never overspent.
#[hegel::test(test_cases = 64)]
fn onboarding_spend_is_quadratic_under_drawn_demand(tc: TestCase) {
    let mut archive = Archive::new(REALM, sim_limits()).unwrap();
    let creator = beneficiary(&mut archive, 1);
    let policy = draw_policy(&tc, 3, 6);
    let source_count = tc.draw(gs::integers::<u8>().min_value(1).max_value(6));
    let (mut pool, mut registry) = sourced_registry(&mut archive, 60, source_count, policy);
    let grant = grant_create(&mut registry, &archive, &creator, 100);
    let epochs = tc.draw(gs::integers::<u64>().min_value(1).max_value(4));
    let mut earned = 0u64;
    let mut slots = 0u64;
    let mut slug_index = 0u32;
    let mut window: VecDeque<u64> = VecDeque::new();
    for epoch in 1..=epochs {
        let now = epoch * EPOCH;
        let supporters = tc.draw(gs::integers::<usize>().max_value(usize::from(source_count)));
        if supporters > 0 {
            epoch_of_support(
                &mut registry,
                &mut archive,
                &mut pool[..supporters],
                &creator,
                now,
            );
            earned += supporters as u64;
        }
        evict_window(&mut window, policy.window_seconds, now);
        let attempts = tc.draw(gs::integers::<u32>().min_value(1).max_value(2));
        for _ in 0..attempts {
            slug_index += 1;
            if attempt_room(
                &mut registry,
                &archive,
                &creator,
                grant,
                slug_index,
                window.len() as u16,
                now,
            ) {
                slots += 1;
                window.push_back(now);
            }
        }
        let account = registry.account(creator.id);
        assert_eq!(account.earned, earned);
        assert_eq!(u64::from(account.lifetime_slots), slots);
        assert_eq!(account.spent, spend_bound(&policy, slots));
    }
}

/// `sybil_cluster_linearizes_pricing_and_windows` generalized: the policy,
/// cluster size, eligible-source count, round count, per-member per-round
/// support and demand bursts are all drawn. Each member still pays its own
/// quadratic schedule — the dedup triple `(source, beneficiary, epoch)` lets
/// one source credit every member once per epoch but never twice, and the
/// rolling window is per-owner so it never pools across the cluster.
/// Consolidated on one account the same rooms would cost
/// `base_cost·cumulative_cost(total) ≥ Σ base_cost·cumulative_cost(member)`
/// — the quadratic is superadditive, so the cluster's only gain is the
/// documented per-account linearization.
#[hegel::test(test_cases = 64)]
fn sybil_cluster_pays_per_account_quadratic_under_drawn_shapes(tc: TestCase) {
    let mut archive = Archive::new(REALM, sim_limits()).unwrap();
    let policy = draw_policy(&tc, 8, 8);
    let cluster_size = usize::from(tc.draw(gs::integers::<u8>().min_value(1).max_value(4)));
    let cluster: Vec<Owner> = (1..=cluster_size as u8)
        .map(|s| beneficiary(&mut archive, s))
        .collect();
    let source_count = tc.draw(gs::integers::<u8>().min_value(1).max_value(6));
    let (mut pool, mut registry) = sourced_registry(&mut archive, 60, source_count, policy);
    let grants: Vec<RoomRecordId> = cluster
        .iter()
        .map(|member| grant_create(&mut registry, &archive, member, 100))
        .collect();
    let rounds = tc.draw(gs::integers::<u64>().min_value(1).max_value(2));
    let mut earned = vec![0u64; cluster_size];
    let mut slots = vec![0u64; cluster_size];
    let mut windows = vec![VecDeque::new(); cluster_size];
    let mut slug_index = 0u32;
    for round in 1..=rounds {
        let now = round * EPOCH;
        // Drawn per-member support: one epoch of reactions from a drawn
        // prefix of the eligible pool.
        for (i, member) in cluster.iter().enumerate() {
            let supporters = tc.draw(gs::integers::<usize>().max_value(usize::from(source_count)));
            if supporters > 0 {
                epoch_of_support(
                    &mut registry,
                    &mut archive,
                    &mut pool[..supporters],
                    member,
                    now,
                );
                earned[i] += supporters as u64;
            }
        }
        // Same-`now` demand burst per member, against each member's own
        // rolling window.
        for (i, member) in cluster.iter().enumerate() {
            evict_window(&mut windows[i], policy.window_seconds, now);
            let attempts = tc.draw(gs::integers::<u32>().min_value(1).max_value(3));
            for _ in 0..attempts {
                slug_index += 1;
                if attempt_room(
                    &mut registry,
                    &archive,
                    member,
                    grants[i],
                    slug_index,
                    windows[i].len() as u16,
                    now,
                ) {
                    slots[i] += 1;
                    windows[i].push_back(now);
                }
            }
            // Per-owner windows never pool: a member can never carry more
            // than max_in_window open creations at once.
            assert!(windows[i].len() <= usize::from(policy.max_in_window));
        }
        for (i, member) in cluster.iter().enumerate() {
            let account = registry.account(member.id);
            assert_eq!(account.earned, earned[i]);
            assert_eq!(u64::from(account.lifetime_slots), slots[i]);
            assert_eq!(account.spent, spend_bound(&policy, slots[i]));
        }
    }
    // The cluster pays exactly the sum of the per-account schedules — never
    // less — and never more than one account would pay for the same rooms.
    let total_rooms: u64 = slots.iter().sum();
    let total_spent: u64 = cluster.iter().map(|m| registry.account(m.id).spent).sum();
    assert_eq!(
        total_spent,
        slots.iter().map(|&s| spend_bound(&policy, s)).sum::<u64>()
    );
    assert!(total_spent <= spend_bound(&policy, total_rooms));
}

/// `eligible_set_size_bounds_the_funnel_per_epoch` generalized: the eligible
/// set size, step count, sub/whole-epoch timing, per-step supporter counts,
/// resubmissions and outsider award attempts are all drawn. At most
/// `|eligible|` fresh credits land per activity epoch; a source re-awarding
/// inside the same epoch dedups to `DuplicateAward`, as does resubmitting
/// the same evidence record; committed outsider evidence is always
/// `Ineligible` and never credits.
#[hegel::test(test_cases = 64)]
fn eligible_set_bounds_per_epoch_funnel_under_drawn_support(tc: TestCase) {
    let mut archive = Archive::new(REALM, sim_limits()).unwrap();
    let creator = beneficiary(&mut archive, 1);
    let eligible_count = tc.draw(gs::integers::<u8>().min_value(1).max_value(5));
    let (mut pool, mut registry) = sources(&mut archive, 60, eligible_count);
    let outsider_count = tc.draw(gs::integers::<u8>().max_value(1));
    let mut outsiders: Vec<Owner> = (200..200 + outsider_count)
        .map(|s| owner(&mut archive, s))
        .collect();
    let steps = tc.draw(gs::integers::<u64>().min_value(1).max_value(5));
    // Dedup oracle: the credited (source, activity_epoch) set. `now` walks
    // sub- and whole-epoch steps, so consecutive steps can share an epoch.
    let mut credited: BTreeSet<(usize, u64)> = BTreeSet::new();
    let mut now = 0u64;
    for _ in 0..steps {
        now += match tc.draw(gs::integers::<u8>().max_value(2)) {
            0 => EPOCH / 2,
            1 => EPOCH,
            _ => 2 * EPOCH,
        };
        let activity_epoch = now / EPOCH;
        let supporters = tc.draw(gs::integers::<usize>().max_value(usize::from(eligible_count)));
        let repeats = tc.draw(gs::integers::<u8>().max_value(1));
        let outsider_attempts: Vec<u8> = (0..outsider_count)
            .map(|_| tc.draw(gs::integers::<u8>().max_value(1)))
            .collect();
        // Emit and seal all of this step's evidence first so one committed
        // view serves every award call, as in `epoch_of_support`.
        let mut records = Vec::new();
        for source in pool[..supporters].iter_mut() {
            records.push(react_to_post(&mut archive, source, &creator));
        }
        for _ in 0..repeats {
            // A repeat may hit a source already credited this epoch
            // (dedup), one credited in an earlier epoch (fresh triple —
            // credits again) or one that never awarded (credits).
            let index = tc.draw(gs::integers::<usize>().max_value(usize::from(eligible_count) - 1));
            records.push(react_to_post(&mut archive, &mut pool[index], &creator));
        }
        for (i, outsider) in outsiders.iter_mut().enumerate() {
            for _ in 0..=outsider_attempts[i] {
                let record = react_to_post(&mut archive, outsider, &creator);
                let view = ControlView::new(&archive, now);
                assert_eq!(
                    registry.award(&record, &view, now),
                    Err(RegistryError::Award(AwardDenial::Ineligible))
                );
            }
        }
        let view = ControlView::new(&archive, now);
        for record in &records {
            // The evidence attributes its source: walk the pool to recover
            // the index the dedup oracle needs.
            let Body::Social { actor, .. } = record.body() else {
                unreachable!()
            };
            let index = pool
                .iter()
                .position(|s| s.id == actor.owner())
                .expect("evidence source is a pool member");
            let expected = if credited.insert((index, activity_epoch)) {
                Applied::Awarded
            } else {
                Applied::DuplicateAward
            };
            assert_eq!(registry.award(record, &view, now), Ok(expected));
            // Resubmitting the same evidence record dedups on its id.
            assert_eq!(
                registry.award(record, &view, now),
                Ok(Applied::DuplicateAward)
            );
        }
        let account = registry.account(creator.id);
        assert_eq!(account.earned, credited.len() as u64);
        // The funnel bound: at most |eligible| distinct sources credit per
        // activity epoch.
        let epochs_seen: BTreeSet<u64> = credited.iter().map(|&(_, e)| e).collect();
        assert!(credited.len() <= usize::from(eligible_count) * epochs_seen.len());
    }
}

/// `many_room_demand_is_window_and_cap_bounded` generalized: the policy —
/// including a lifetime cap reachable in tens of credits — the funding
/// level, and a demand trace of drawn bursts at stay / partial-window /
/// whole-window advances. The rolling per-owner window never admits more
/// than `max_in_window` creations, lifetime slots never exceed
/// `max_lifetime_rooms`, spend stays exactly quadratic and credit is never
/// overspent — credit alone never buys throughput.
#[hegel::test(test_cases = 64)]
fn funded_demand_is_window_and_cap_bounded_under_drawn_timing(tc: TestCase) {
    let mut archive = Archive::new(REALM, sim_limits()).unwrap();
    let creator = beneficiary(&mut archive, 1);
    let policy = draw_policy(&tc, 2, 3);
    let source_count = tc.draw(gs::integers::<u8>().min_value(2).max_value(5));
    let (mut pool, mut registry) = sourced_registry(&mut archive, 60, source_count, policy);
    let grant = grant_create(&mut registry, &archive, &creator, 100);
    // Whole-epoch funding; whether the lifetime cap is affordable at all is
    // decided by the drawn `sources × epochs` against
    // `spend_bound(max_lifetime_rooms)`.
    let funding_epochs = tc.draw(gs::integers::<u64>().min_value(2).max_value(4));
    for epoch in 1..=funding_epochs {
        epoch_of_support(
            &mut registry,
            &mut archive,
            &mut pool,
            &creator,
            epoch * EPOCH,
        );
    }
    let earned = u64::from(source_count) * funding_epochs;
    assert_eq!(registry.account(creator.id).earned, earned);

    let mut now = funding_epochs * EPOCH;
    let mut window: VecDeque<u64> = VecDeque::new();
    let mut slots = 0u64;
    let mut slug_index = 0u32;
    let steps = tc.draw(gs::integers::<u32>().min_value(4).max_value(8));
    for _ in 0..steps {
        let advance = match tc.draw(gs::integers::<u8>().max_value(4)) {
            0 => 0,
            1 => EPOCH / 2,
            4 => 2 * EPOCH,
            _ => EPOCH,
        };
        now += advance;
        evict_window(&mut window, policy.window_seconds, now);
        let attempts = tc.draw(gs::integers::<u32>().max_value(2));
        for _ in 0..attempts {
            slug_index += 1;
            if attempt_room(
                &mut registry,
                &archive,
                &creator,
                grant,
                slug_index,
                window.len() as u16,
                now,
            ) {
                slots += 1;
                window.push_back(now);
            }
        }
        let account = registry.account(creator.id);
        assert_eq!(u64::from(account.lifetime_slots), slots);
        assert!(slots <= u64::from(policy.max_lifetime_rooms));
        assert_eq!(account.spent, spend_bound(&policy, slots));
        assert!(account.spent <= account.earned);
    }
    // Demand can never buy past the lifetime cap, however much credit or
    // however many windows remain — and short of it the quote is exactly the
    // next quadratic slot price.
    match registry.quote(creator.id) {
        Err(error) => {
            assert_eq!(error, RegistryError::Slot);
            assert_eq!(slots, u64::from(policy.max_lifetime_rooms));
        }
        Ok((slot, charge)) => {
            assert_eq!(u64::from(slot), slots + 1);
            assert_eq!(charge, policy.base_cost * u64::from(slot) * u64::from(slot));
        }
    }
}
