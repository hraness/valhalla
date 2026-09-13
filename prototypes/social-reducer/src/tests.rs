extern crate std;
use super::observed_appreciation as appreciation;
use super::*;
use alloc::vec;
use proptest::prelude::*;

fn bindings() -> FixtureBindings {
    let mut b = FixtureBindings::default();
    for a in 1..=1000 {
        b.add(Agent(a), Owner(1)).unwrap();
    }
    b.add(Agent(2000), Owner(2)).unwrap();
    b
}
fn reaction(id: u32, agent: u32, vote: Reaction, parents: &[u32]) -> Operation {
    Operation {
        id: Event(id),
        realm: Realm(1),
        owner: Owner(1),
        agent: Agent(agent),
        body: Body::Reaction(Post(1), vote),
        supersedes: parents.iter().copied().map(Event).collect(),
    }
}
fn up(id: u32, agent: u32, parents: &[u32]) -> Operation {
    reaction(id, agent, Reaction::On(Revision(1), Vote::Up), parents)
}
fn key() -> Key {
    Key {
        realm: Realm(1),
        owner: Owner(1),
        target: Target::Reaction(Post(1)),
    }
}
fn load(ops: &[Operation]) -> Store {
    let mut s = Store::new(bindings());
    for o in ops {
        s.insert(o.clone()).unwrap();
    }
    s
}

// Independent operation-set oracle: recursively classify each complete ancestry,
// then compute maximal vertices from the graph. Does not use Store's accepted,
// pending, invalid, incremental head updates, or shared resolution function.
fn oracle(all: &BTreeMap<Event, Operation>, key: Key) -> View {
    fn status(id: Event, all: &BTreeMap<Event, Operation>, path: &mut BTreeSet<Event>) -> u8 {
        let Some(op) = all.get(&id) else {
            return 0;
        };
        if !path.insert(id) {
            return 0;
        }
        let mut answer = 1;
        for parent in &op.supersedes {
            if all.get(parent).is_some_and(|p| p.key() != op.key()) {
                answer = 2;
                break;
            }
            match status(*parent, all, path) {
                2 => {
                    answer = 2;
                    break;
                }
                0 => answer = 0,
                _ => {}
            }
        }
        path.remove(&id);
        answer
    }
    let states: BTreeMap<_, _> = all
        .keys()
        .map(|id| (*id, status(*id, all, &mut BTreeSet::new())))
        .collect();
    if all
        .values()
        .any(|op| op.key() == key && states[&op.id] == 0)
    {
        return View::Incomplete;
    }
    let candidates: BTreeSet<_> = all
        .values()
        .filter(|op| op.key() == key && states[&op.id] == 1)
        .map(|op| op.id)
        .collect();
    let referenced: BTreeSet<_> = candidates
        .iter()
        .flat_map(|id| all[id].supersedes.iter().copied())
        .collect();
    let heads: Vec<_> = candidates.difference(&referenced).copied().collect();
    if heads.len() > MAX_EFFECTIVE_HEADS {
        return View::Incomplete;
    }
    let bodies: Vec<_> = heads.iter().map(|id| all[id].body).collect();
    let value = if bodies.is_empty() {
        Value::Absent
    } else if matches!(bodies[0], Body::Follow(_, _)) {
        Value::Follow(bodies.iter().all(|b| matches!(b, Body::Follow(_, true))))
    } else if bodies
        .iter()
        .any(|b| matches!(b, Body::Reaction(_, Reaction::Clear)))
    {
        Value::Reaction(Reaction::Clear)
    } else if bodies.iter().all(|b| *b == bodies[0]) {
        match bodies[0] {
            Body::Reaction(_, r) => Value::Reaction(r),
            _ => unreachable!(),
        }
    } else {
        Value::ReactionConflict
    };
    View::Complete { heads, value }
}

#[test]
fn equal_heads_cannot_be_collapsed_before_future_supersession() {
    let a = up(1, 1, &[]);
    let b = up(2, 2, &[]);
    let c = reaction(3, 1, Reaction::On(Revision(1), Vote::Down), &[1]);
    let mut s = load(&[a.clone(), b.clone()]);
    assert_eq!(
        s.view(key()),
        View::Complete {
            heads: vec![Event(1), Event(2)],
            value: Value::Reaction(Reaction::On(Revision(1), Vote::Up))
        }
    );
    s.insert(c.clone()).unwrap();
    assert_eq!(
        s.view(key()),
        View::Complete {
            heads: vec![Event(2), Event(3)],
            value: Value::ReactionConflict
        }
    );
    let naive = load(&[a, c]); // Incorrectly forgetting equal-valued head B invents a downvote.
    assert_eq!(
        current_revision_vote(&naive.view(key()), Revision(1)),
        Some(-1)
    );
    assert_eq!(current_revision_vote(&s.view(key()), Revision(1)), Some(0));
}
#[test]
fn clear_unfollow_win_and_only_observed_resolution_restores() {
    let mut s = load(&[up(1, 1, &[]), reaction(2, 2, Reaction::Clear, &[])]);
    assert_eq!(current_revision_vote(&s.view(key()), Revision(1)), Some(0));
    s.insert(up(3, 1, &[1])).unwrap();
    assert_eq!(current_revision_vote(&s.view(key()), Revision(1)), Some(0));
    s.insert(up(4, 1, &[2, 3])).unwrap();
    assert_eq!(current_revision_vote(&s.view(key()), Revision(1)), Some(1));
    let mut a = up(5, 1, &[]);
    a.body = Body::Follow(Owner(2), true);
    let mut b = a.clone();
    b.id = Event(6);
    b.agent = Agent(2);
    b.body = Body::Follow(Owner(2), false);
    s.insert(a.clone()).unwrap();
    s.insert(b).unwrap();
    assert!(matches!(
        s.view(a.key()),
        View::Complete {
            value: Value::Follow(false),
            ..
        }
    ));
    let mut c = a.clone();
    c.id = Event(7);
    c.supersedes = vec![Event(5), Event(6)];
    s.insert(c).unwrap();
    s.insert(a.clone()).unwrap(); // A stale replay cannot undo the observed removal/resolution.
    assert!(matches!(
        s.view(a.key()),
        View::Complete {
            value: Value::Follow(true),
            ..
        }
    ));
}
#[test]
fn missing_foreign_and_cyclic_predecessors_never_become_effective() {
    let mut s = load(&[up(2, 2, &[1])]);
    assert_eq!(s.view(key()), View::Incomplete);
    s.insert(up(1, 1, &[])).unwrap();
    assert!(matches!(s.view(key()),View::Complete{heads,..} if heads==vec![Event(2)]));
    let mut foreign = up(3, 3, &[2]);
    foreign.realm = Realm(2);
    s.insert(foreign.clone()).unwrap();
    assert_eq!(
        s.view(foreign.key()),
        View::Complete {
            heads: vec![],
            value: Value::Absent
        }
    );
    let cycle = load(&[up(4, 4, &[5]), up(5, 5, &[4])]);
    assert_eq!(cycle.view(key()), View::Incomplete);
    assert_eq!(cycle.view(key()), oracle(&cycle.operations, key()));
}
#[test]
fn safety_bounds_and_immutable_fixture_bindings() {
    let mut b = bindings();
    assert_eq!(b.add(Agent(1), Owner(2)), Err(Error::Rebinding));
    let mut s = Store::new(b);
    let mut bad = up(1, 1, &[]);
    bad.owner = Owner(2);
    assert_eq!(s.insert(bad), Err(Error::UnknownBinding));
    assert_eq!(
        s.insert(up(1, 1, &[2, 3, 4, 5, 6])),
        Err(Error::ParentLimit)
    );
    assert_eq!(s.insert(up(1, 1, &[2, 2])), Err(Error::DuplicateParent));
    assert_eq!(s.insert(up(1, 1, &[1])), Err(Error::SelfParent));
    for id in 1..=9 {
        s.insert(up(id, id, &[])).unwrap();
    }
    assert_eq!(s.view(key()), View::Incomplete);
    assert_eq!(s.view(key()), oracle(&s.operations, key()));
    for id in 10..=MAX_OPERATIONS as u32 {
        s.insert(up(id, 1, &[])).unwrap();
    }
    assert_eq!(s.insert(up(1025, 1, &[])), Err(Error::Capacity));
    assert_eq!(s.retained_operations(), 1024);
    let mut s = load(&[up(1, 1, &[])]);
    assert_eq!(
        s.insert(reaction(1, 1, Reaction::Clear, &[])),
        Err(Error::IdConflict)
    );
    assert_eq!(s.view(key()), View::Incomplete);
}
#[test]
fn a_thousand_agents_still_cast_one_owner_vote_and_pair_cap() {
    let mut s = Store::new(bindings());
    for id in 1..=1000 {
        let previous = id - 1;
        s.insert(up(
            id,
            id,
            if id == 1 {
                &[]
            } else {
                core::slice::from_ref(&previous)
            },
        ))
        .unwrap();
    }
    assert_eq!(current_revision_vote(&s.view(key()), Revision(1)), Some(1));
    let mut cohort = Cohort::default();
    cohort
        .commit(Realm(1), Post(1), Owner(2), Revision(1))
        .unwrap();
    assert_eq!(appreciation(&s, &cohort, Realm(1), Owner(2)), Some(1));
    for id in 1001..=1010 {
        let mut op = up(id, 1, &[]);
        op.body = Body::Reaction(Post(id), Reaction::On(Revision(1), Vote::Up));
        s.insert(op).unwrap();
        cohort
            .commit(Realm(1), Post(id), Owner(2), Revision(1))
            .unwrap();
    }
    assert_eq!(appreciation(&s, &cohort, Realm(1), Owner(2)), Some(1));
    assert_eq!(appreciation(&s, &cohort, Realm(1), Owner(1)), Some(0));
}
#[test]
fn retraction_retirement_and_revision_do_not_launder_capital() {
    let mut positive = up(1, 1, &[]);
    positive.body = Body::Reaction(Post(1), Reaction::On(Revision(1), Vote::Up));
    let mut negative = up(2, 2, &[]);
    negative.body = Body::Reaction(Post(2), Reaction::On(Revision(1), Vote::Down));
    let s = load(&[positive, negative]);
    let mut cohort = Cohort::default();
    cohort
        .commit(Realm(1), Post(1), Owner(2), Revision(1))
        .unwrap();
    cohort
        .commit(Realm(1), Post(2), Owner(2), Revision(1))
        .unwrap();
    assert_eq!(appreciation(&s, &cohort, Realm(1), Owner(2)), Some(0));
    let mut naive_deleted = Cohort::default();
    naive_deleted
        .commit(Realm(1), Post(1), Owner(2), Revision(1))
        .unwrap();
    assert_eq!(
        appreciation(&s, &naive_deleted, Realm(1), Owner(2)),
        Some(1)
    ); // Demonstrated laundering.
       // UI deletion and author retirement have no input into immutable committed cohort.
    assert_eq!(appreciation(&s, &cohort, Realm(1), Owner(2)), Some(0));
    let old = s.view(key());
    assert_eq!(current_revision_vote(&old, Revision(1)), Some(1));
    assert_eq!(current_revision_vote(&old, Revision(2)), Some(0)); // Edited text cannot inherit endorsement.
    cohort
        .commit(Realm(1), Post(1), Owner(2), Revision(2))
        .unwrap();
    assert_eq!(appreciation(&s, &cohort, Realm(1), Owner(2)), Some(0));
    assert_eq!(
        cohort.commit(Realm(1), Post(1), Owner(3), Revision(1)),
        Err(Error::Rebinding)
    );
}
#[test]
fn incomplete_evidence_has_no_numeric_score_and_provisional_posts_are_separate() {
    let s = load(&[up(2, 2, &[1])]);
    let mut c = Cohort::default();
    assert_eq!(appreciation(&s, &c, Realm(1), Owner(2)), Some(0)); // Not a committed post yet.
    c.commit(Realm(1), Post(1), Owner(2), Revision(1)).unwrap();
    assert_eq!(appreciation(&s, &c, Realm(1), Owner(2)), None);
}
#[test]
fn visibility_is_independent_of_profile_channel_placement() {
    let public = Visibility::Public(Realm(1));
    let private = Visibility::Private {
        realm: Realm(1),
        audience: 7,
        epoch: 1,
    };
    assert!(repost_scope_allowed(
        public,
        public,
        Placement::Profile(Owner(2))
    ));
    assert!(repost_scope_allowed(public, public, Placement::Channel(8)));
    assert!(!repost_scope_allowed(
        private,
        public,
        Placement::Profile(Owner(2))
    ));
    assert!(!repost_scope_allowed(
        private,
        Visibility::Private {
            realm: Realm(1),
            audience: 7,
            epoch: 2
        },
        Placement::Channel(8)
    ));
}
#[test]
fn a_thousand_bound_unknown_owners_cannot_rank_without_explicit_local_eligibility() {
    let mut bindings = FixtureBindings::default();
    for n in 1..=1000 {
        bindings.add(Agent(n), Owner(n)).unwrap();
    }
    let mut store = Store::new(bindings);
    for n in 1..=1000 {
        let mut op = up(n, n, &[]);
        op.owner = Owner(n);
        store.insert(op).unwrap();
    }
    let mut cohort = Cohort::default();
    cohort
        .commit(Realm(1), Post(1), Owner(2000), Revision(1))
        .unwrap();
    assert_eq!(
        observed_appreciation(&store, &cohort, Realm(1), Owner(2000)),
        Some(1000)
    );
    let none = EligibleOwners::default();
    assert_eq!(
        eligible_appreciation(&store, &cohort, &none, Realm(1), Owner(2000)),
        Some(0)
    );
    let one = EligibleOwners::from_local_policy(&[Owner(42)]).unwrap();
    assert_eq!(
        eligible_appreciation(&store, &cohort, &one, Realm(1), Owner(2000)),
        Some(1)
    );
    let mut follow = up(1001, 42, &[]);
    follow.owner = Owner(42);
    follow.body = Body::Follow(Owner(2000), true);
    store.insert(follow).unwrap();
    assert_eq!(
        eligible_appreciation(&store, &cohort, &none, Realm(1), Owner(2000)),
        Some(0)
    );
}
#[test]
fn failed_union_receipt_does_not_mislabel_complete_retained_state_or_poison_it() {
    let mut limited = FixtureBindings::default();
    limited.add(Agent(1), Owner(1)).unwrap();
    let mut local = Store::new(limited);
    local.insert(up(1, 1, &[])).unwrap();
    let before = local.view(key());
    let mut broader = FixtureBindings::default();
    broader.add(Agent(1), Owner(1)).unwrap();
    broader.add(Agent(99), Owner(2)).unwrap();
    let mut remote = Store::new(broader);
    remote.insert(up(1, 1, &[])).unwrap();
    remote
        .insert(reaction(2, 1, Reaction::Clear, &[1]))
        .unwrap();
    let mut unknown = up(3, 99, &[]);
    unknown.owner = Owner(2);
    remote.insert(unknown).unwrap();
    assert_eq!(
        local.merge_with_receipt(&remote),
        MergeReceipt::Rejected {
            reason: Error::UnknownBinding,
            retained_operations: 1
        }
    );
    assert_eq!(local.view(key()), before);
    assert_eq!(local.retained_operations(), 1);
    // Complete means the retained graph is resolved, not that the attempted union succeeded.
    assert!(matches!(local.view(key()), View::Complete { .. }));
    let clean = load(&[up(1, 1, &[]), reaction(2, 1, Reaction::Clear, &[1])]);
    assert_eq!(
        local.merge_with_receipt(&clean),
        MergeReceipt::Applied {
            retained_operations: 2
        }
    );
    assert_eq!(
        current_revision_vote(&local.view(key()), Revision(1)),
        Some(0)
    );
}
#[test]
fn successor_agent_can_supersede_retained_owner_preferences() {
    let mut old = up(1, 1, &[]);
    old.body = Body::Follow(Owner(2), true);
    let mut store = load(&[old.clone()]);
    assert!(matches!(
        store.view(old.key()),
        View::Complete {
            value: Value::Follow(true),
            ..
        }
    ));
    // Retained admitted evidence is independent of a current-presence list. Actual
    // retirement/control admission is external; this fixture cannot certify it.
    let mut successor = old.clone();
    successor.id = Event(2);
    successor.agent = Agent(2);
    successor.body = Body::Follow(Owner(2), false);
    successor.supersedes = vec![Event(1)];
    store.insert(successor).unwrap();
    assert!(matches!(
        store.view(old.key()),
        View::Complete {
            value: Value::Follow(false),
            ..
        }
    ));
    assert_eq!(store.retained_operations(), 2);
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]
    #[test] fn arbitrary_order_duplicates_partition_and_set_oracle(order in prop::collection::vec(any::<u8>(),0..80), split in 0usize..7) {
        let ops=[up(1,1,&[]),up(2,2,&[]),reaction(3,3,Reaction::On(Revision(1),Vote::Down),&[1]),reaction(4,4,Reaction::Clear,&[2]),up(5,5,&[3,4]),reaction(6,6,Reaction::On(Revision(2),Vote::Up),&[5])];
        let mut streamed=Store::new(bindings());
        for n in order {streamed.insert(ops[usize::from(n)%ops.len()].clone()).unwrap();prop_assert_eq!(streamed.view(key()),oracle(&streamed.operations,key()));}
        for op in &ops {streamed.insert(op.clone()).unwrap();}
        prop_assert_eq!(streamed.view(key()),oracle(&streamed.operations,key()));
        let mut left=load(&ops[..split]);let mut right=load(&ops[split..]);let initial=left.clone();
        left.merge(&right).unwrap();right.merge(&initial).unwrap();prop_assert_eq!(left.view(key()),right.view(key()));
        let once=left.view(key());left.merge(&right).unwrap();prop_assert_eq!(left.view(key()),once);
        let a=load(&ops[..2]);let b=load(&ops[2..4]);let c=load(&ops[4..]);
        let mut ab=a.clone();ab.merge(&b).unwrap();ab.merge(&c).unwrap();
        let mut bc=b;bc.merge(&c).unwrap();let mut a_bc=a;a_bc.merge(&bc).unwrap();
        prop_assert_eq!(ab.view(key()),a_bc.view(key()));
    }
}
