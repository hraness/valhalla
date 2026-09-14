//! Sybil/collusion calibration over real records: the award economy under
//! honest onboarding, colluding beneficiary clusters, funnel bounds and
//! many-room demand. These are deterministic economy measurements — the
//! numbers recorded in `kb/plans/valhalla-room-directory.md` come from
//! this suite, and the assertions pin the model's scaling laws.
mod common;
use common::*;
use vhalla_rooms::{
    awards::AwardDenial,
    registry::{Applied, Registry, RegistryError},
};
use vhalla_social::{
    archive::{Archive, Limits},
    control::ControlView,
    Actor, Body, Operation, Reaction, References,
};

/// Wider archive bounds for long-horizon simulations: the shared fixture
/// caps each writer at eight data records, while these scenarios emit
/// dozens of reactions per source agent across many epochs.
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

/// One epoch of organic support: every listed source awards `owner` once.
/// All reactions are emitted and sealed first so a single committed
/// `ControlView` serves the whole epoch — building a view per award
/// would rescan the archive for every source.
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

/// The full creation path for `owner`'s next quoted room.
fn create_next(
    registry: &mut Registry,
    archive: &Archive,
    owner: &Owner,
    grant: vhalla_rooms::RoomRecordId,
    slug: &str,
    nonce: u8,
    now: u64,
) -> Result<Applied, RegistryError> {
    let (slot, charge) = registry.quote(owner.id).unwrap();
    apply(
        registry,
        archive,
        &creation(owner, grant, grant, slug, slot, charge, nonce),
        now,
    )
}

/// Cumulative credit an account needs for `rooms` rooms at unit base cost:
/// the quadratic charge sums to rooms·(rooms+1)·(2·rooms+1)/6.
fn cumulative_cost(rooms: u64) -> u64 {
    rooms * (rooms + 1) * (2 * rooms + 1) / 6
}

/// An honest owner earns at the rate of their supporting sources: slot `n`
/// costs `n²`, so room `n` lands when cumulative earnings reach
/// `n(n+1)(2n+1)/6`. With four steady sources the fourth room arrives at
/// epoch 8 and has cost 30 credits — quadratic in rooms, linear in epochs
/// only in credit accumulation.
#[test]
fn honest_onboarding_pays_quadratic_cumulative_cost() {
    let mut archive = Archive::new(REALM, sim_limits()).unwrap();
    let creator = beneficiary(&mut archive, 1);
    let (mut pool, mut registry) = sources(&mut archive, 60, 4);
    let grant = grant_create(&mut registry, &archive, &creator, 100);

    let mut created_at = Vec::new();
    for epoch in 1..=10u64 {
        let now = epoch * EPOCH;
        epoch_of_support(&mut registry, &mut archive, &mut pool, &creator, now);
        if let Ok(Applied::Created(_)) = create_next(
            &mut registry,
            &archive,
            &creator,
            grant,
            &format!("honest-{}", created_at.len() + 1),
            10 + created_at.len() as u8,
            now,
        ) {
            created_at.push(epoch);
        }
    }
    // Slots 1..4 cost 1, 4, 9, 16 — cumulative 1, 5, 14, 30. Four sources
    // earn 4/epoch, so rooms land at epochs 1, 2, 4, 8.
    assert_eq!(created_at, vec![1, 2, 4, 8]);
    let account = registry.account(creator.id);
    assert_eq!(account.earned, 40);
    assert_eq!(account.spent, cumulative_cost(4));
    assert_eq!(account.lifetime_slots, 4);
}

/// The documented bypass: quadratic pricing is per-account, so `k`
/// colluding beneficiary owners each pay only the slot-1 charge. Four
/// colluders produce four rooms in one window for 4 credits total where a
/// single honest account's fourth room alone costs 16 — and the rate
/// window is per-owner, so the cluster's throughput is `k` rooms per
/// window against the honest owner's one.
#[test]
fn sybil_cluster_linearizes_pricing_and_windows() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let cluster: Vec<Owner> = (1..=4u8).map(|s| beneficiary(&mut archive, s)).collect();
    let (mut pool, mut registry) = sources(&mut archive, 60, 4);
    let grants: Vec<_> = cluster
        .iter()
        .map(|o| grant_create(&mut registry, &archive, o, 100))
        .collect();

    // Every source supports every colluder in the same epoch — dedup binds
    // (source, beneficiary, epoch), so distinct beneficiaries all credit.
    for member in &cluster {
        epoch_of_support(&mut registry, &mut archive, &mut pool, member, EPOCH);
    }
    for member in &cluster {
        assert_eq!(registry.account(member.id).earned, 4);
    }
    // One window, four rooms, four credits spent.
    let mut created = 0;
    for (i, member) in cluster.iter().enumerate() {
        assert!(matches!(
            create_next(
                &mut registry,
                &archive,
                member,
                grants[i],
                &format!("sybil-{i}"),
                20 + i as u8,
                EPOCH,
            ),
            Ok(Applied::Created(_))
        ));
        created += 1;
    }
    assert_eq!(created, 4);
    let total_spent: u64 = cluster.iter().map(|m| registry.account(m.id).spent).sum();
    assert_eq!(total_spent, 4);
    // The same four rooms on one account would have cost 30.
    assert_eq!(cumulative_cost(4), 30);
}

/// The funnel bound is the admitted eligible set: one beneficiary earns at
/// most `|eligible|` per epoch, sustained across epochs. Sources outside
/// the set are denied even with fully committed evidence — eligibility
/// admission is the actual Sybil gate, not the award rule.
#[test]
fn eligible_set_size_bounds_the_funnel_per_epoch() {
    let mut archive = Archive::new(REALM, limits()).unwrap();
    let creator = beneficiary(&mut archive, 1);
    let (mut pool, mut registry) = sources(&mut archive, 60, 4);
    // An owner outside the eligible set cannot award, whatever it seals.
    let mut outsider = owner(&mut archive, 200);
    let post = {
        let mut found = None;
        for r in archive.records() {
            if let Body::Social {
                actor,
                operation: Operation::Post { .. },
                ..
            } = r.body()
            {
                if actor.owner() == creator.id {
                    found = Some(r.id());
                }
            }
        }
        found.unwrap()
    };
    let react = sign(
        Body::Social {
            actor: Actor::Agent {
                owner: outsider.id,
                agent: outsider.agent,
                grant: outsider.grant,
            },
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: Operation::React {
                post,
                reaction: Reaction::Up(post),
                supersedes: References::default(),
            },
        },
        &outsider.agent_key,
        None,
    );
    ingest(&mut archive, &react);
    seal(&mut archive, &mut outsider, &[react.id()]);
    let verified = vhalla_social::SignedRecord::decode(&react.encode())
        .unwrap()
        .verify()
        .unwrap();
    let view = ControlView::new(&archive, EPOCH);
    assert_eq!(
        registry.award(&verified, &view, EPOCH),
        Err(RegistryError::Award(AwardDenial::Ineligible))
    );
    drop(view);

    // The admitted four earn exactly four per epoch, every epoch.
    epoch_of_support(&mut registry, &mut archive, &mut pool, &creator, EPOCH);
    assert_eq!(registry.account(creator.id).earned, 4);
    epoch_of_support(&mut registry, &mut archive, &mut pool, &creator, 2 * EPOCH);
    assert_eq!(registry.account(creator.id).earned, 8);
}

/// Many-room demand is bounded by the per-owner window and lifetime cap,
/// not by credit: a fully funded owner still creates at most
/// `max_in_window` rooms per `window_seconds` and stops at
/// `max_lifetime_rooms`. Credit alone never buys throughput.
#[test]
fn many_room_demand_is_window_and_cap_bounded() {
    let mut archive = Archive::new(REALM, sim_limits()).unwrap();
    let creator = beneficiary(&mut archive, 1);
    let (mut pool, mut registry) = sources(&mut archive, 60, 26);
    let grant = grant_create(&mut registry, &archive, &creator, 100);
    // Fund the lifetime maximum: cumulative_cost(8) = 204 credits, and
    // twenty-six admitted sources earn 208 in eight epochs.
    for epoch in 1..=8u64 {
        epoch_of_support(
            &mut registry,
            &mut archive,
            &mut pool,
            &creator,
            epoch * EPOCH,
        );
    }
    assert_eq!(registry.account(creator.id).earned, 208);

    // Window bound: a second creation inside the same rolling window is
    // denied even though the funded balance covers it.
    let now = 100 * EPOCH;
    assert!(matches!(
        create_next(
            &mut registry,
            &archive,
            &creator,
            grant,
            "demand-1",
            40,
            now
        ),
        Ok(Applied::Created(_))
    ));
    assert_eq!(
        create_next(
            &mut registry,
            &archive,
            &creator,
            grant,
            "demand-x",
            41,
            now
        ),
        Err(RegistryError::RateLimit)
    );

    // One creation per subsequent window fills the lifetime cap exactly.
    let mut created = 1u64;
    for window in 1..=7u64 {
        match create_next(
            &mut registry,
            &archive,
            &creator,
            grant,
            &format!("demand-{}", created + 1),
            41 + created as u8,
            now + window * EPOCH,
        ) {
            Ok(Applied::Created(_)) => created += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(created, 8);
    assert_eq!(registry.account(creator.id).spent, cumulative_cost(8));
    // Quoting past the lifetime cap fails: a ninth room cannot be priced.
    assert_eq!(registry.quote(creator.id), Err(RegistryError::Slot));
}
