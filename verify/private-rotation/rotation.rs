//! Verus pilot (2nd model): inductive proof of PrivateRotation's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`: the transition system
//! of `PrivateRotation.tla` under `normal.cfg` (all three mutant switches
//! false) is re-stated as a Verus spec, and the six checked invariants are
//! proved inductive. The three mutant configurations are proved to reach
//! violations of the invariants TLC found for them — `mutant-orphan`
//! breaks `NoOrphans`, `mutant-budget` breaks `PreservedSpend`,
//! `mutant-receipt` breaks `BoundReceipts` — and a completion witness shows
//! the safe model reaches the post-cutover state with both jobs retained.
//!
//! Encoding notes:
//!   * Jobs == {a,b} is the concrete set {1,2}; a/b map to 1/2.
//!   * `[Jobs -> 0..1]` functions become characteristic sets of the value 1:
//!     `job1 = {j : jobGeneration[j] = 1}` and `receipt1 = {j :
//!     receiptGeneration[j] = 1}`. Every invariant only compares these maps
//!     for equality with 0, 1 or each other, so the encoding is lossless.
//!   * The single TLA+ existential `\E j \in Jobs: Queue \/ Store \/ Retain`
//!     is split into three existentials, which is equivalent.
//!
//! Verify with:
//!   verus --crate-type=lib verify/private-rotation/rotation.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Jobs == {a, b} as {1, 2}.
pub open spec fn jobs() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

/// jobs_a == {a} as {1}.
pub open spec fn jobs_a() -> Set<int> {
    Set::empty().insert(1)
}

pub open spec fn is_job(j: int) -> bool {
    jobs().contains(j)
}

/// VARIABLES generation, fenced, created, pending, retained, jobGeneration,
/// receiptGeneration, spent, prepared, oldReadable, stored, frozenHead.
/// job1/receipt1 are the characteristic sets documented above.
pub struct State {
    pub generation: int,
    pub fenced: bool,
    pub created: Set<int>,
    pub pending: Set<int>,
    pub retained: Set<int>,
    pub job1: Set<int>,
    pub receipt1: Set<int>,
    pub spent: int,
    pub prepared: bool,
    pub old_readable: bool,
    pub stored: Set<int>,
    pub frozen_head: Set<int>,
}

/// Reachable(j) == jobGeneration[j] = generation
///                 \/ (jobGeneration[j] = 0 /\ oldReadable)
/// With the characteristic encoding, jobGeneration[j] = generation
/// (both 0..1-valued) is `job1.contains(j) == (generation == 1)`, and
/// jobGeneration[j] = 0 is `!job1.contains(j)`.
pub open spec fn reachable(s: State, j: int) -> bool {
    (s.job1.contains(j) == (s.generation == 1)) || (!s.job1.contains(j) && s.old_readable)
}

pub open spec fn init(s: State) -> bool {
    &&& s.generation == 0
    &&& !s.fenced
    &&& s.created =~= Set::empty()
    &&& s.pending =~= Set::empty()
    &&& s.retained =~= Set::empty()
    &&& s.job1 =~= Set::empty()
    &&& s.receipt1 =~= Set::empty()
    &&& s.spent == 0
    &&& !s.prepared
    &&& s.old_readable
    &&& s.stored =~= Set::empty()
    &&& s.frozen_head =~= Set::empty()
}

/// Queue(j) == /\ j \notin created /\ ~fenced /\ ~prepared
///             /\ created' = created \cup {j} /\ pending' = pending \cup {j}
///             /\ jobGeneration' = [jobGeneration EXCEPT ![j] = generation]
///             /\ spent' = spent + 1 /\ others unchanged
pub open spec fn queue(pre: State, post: State, j: int) -> bool {
    &&& !pre.created.contains(j)
    &&& !pre.fenced
    &&& !pre.prepared
    &&& post.created =~= pre.created.insert(j)
    &&& post.pending =~= pre.pending.insert(j)
    &&& post.job1 =~= if pre.generation == 1 {
        pre.job1.insert(j)
    } else {
        pre.job1.remove(j)
    }
    &&& post.spent == pre.spent + 1
    &&& post.generation == pre.generation
    &&& post.fenced == pre.fenced
    &&& post.retained =~= pre.retained
    &&& post.receipt1 =~= pre.receipt1
    &&& post.prepared == pre.prepared
    &&& post.old_readable == pre.old_readable
    &&& post.stored =~= pre.stored
    &&& post.frozen_head =~= pre.frozen_head
}

/// Store(j) == /\ j \in pending \ stored /\ ~fenced
///             /\ jobGeneration[j] = generation /\ stored' = stored \cup {j}
pub open spec fn store(pre: State, post: State, j: int) -> bool {
    &&& pre.pending.contains(j) && !pre.stored.contains(j)
    &&& !pre.fenced
    &&& pre.job1.contains(j) == (pre.generation == 1)
    &&& post.stored =~= pre.stored.insert(j)
    &&& post.generation == pre.generation
    &&& post.fenced == pre.fenced
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.retained =~= pre.retained
    &&& post.job1 =~= pre.job1
    &&& post.receipt1 =~= pre.receipt1
    &&& post.spent == pre.spent
    &&& post.prepared == pre.prepared
    &&& post.old_readable == pre.old_readable
    &&& post.frozen_head =~= pre.frozen_head
}

/// Retain(j) == /\ j \in pending \cap stored /\ Reachable(j)
///              /\ pending' = pending \ {j} /\ retained' = retained \cup {j}
///              /\ receiptGeneration' = [receiptGeneration EXCEPT ![j] = jobGeneration[j]]
pub open spec fn retain(pre: State, post: State, j: int) -> bool {
    &&& pre.pending.contains(j) && pre.stored.contains(j)
    &&& reachable(pre, j)
    &&& post.pending =~= pre.pending.remove(j)
    &&& post.retained =~= pre.retained.insert(j)
    &&& post.receipt1 =~= if pre.job1.contains(j) {
        pre.receipt1.insert(j)
    } else {
        pre.receipt1.remove(j)
    }
    &&& post.generation == pre.generation
    &&& post.fenced == pre.fenced
    &&& post.created =~= pre.created
    &&& post.job1 =~= pre.job1
    &&& post.spent == pre.spent
    &&& post.prepared == pre.prepared
    &&& post.old_readable == pre.old_readable
    &&& post.stored =~= pre.stored
    &&& post.frozen_head =~= pre.frozen_head
}

/// Fence == /\ generation = 0 /\ ~fenced /\ fenced' = TRUE /\ frozenHead' = stored
pub open spec fn fence(pre: State, post: State) -> bool {
    &&& pre.generation == 0
    &&& !pre.fenced
    &&& post.fenced
    &&& post.frozen_head =~= pre.stored
    &&& post.generation == pre.generation
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.retained =~= pre.retained
    &&& post.job1 =~= pre.job1
    &&& post.receipt1 =~= pre.receipt1
    &&& post.spent == pre.spent
    &&& post.prepared == pre.prepared
    &&& post.old_readable == pre.old_readable
    &&& post.stored =~= pre.stored
}

/// PrepareCutover == /\ generation = 0 /\ fenced /\ ~prepared
///                   /\ (pending = {} \/ UnsafeCutover) /\ prepared' = TRUE
pub open spec fn prepare_cutover(uc: bool, pre: State, post: State) -> bool {
    &&& pre.generation == 0
    &&& pre.fenced
    &&& !pre.prepared
    &&& (pre.pending =~= Set::empty() || uc)
    &&& post.prepared
    &&& post.generation == pre.generation
    &&& post.fenced == pre.fenced
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.retained =~= pre.retained
    &&& post.job1 =~= pre.job1
    &&& post.receipt1 =~= pre.receipt1
    &&& post.spent == pre.spent
    &&& post.old_readable == pre.old_readable
    &&& post.stored =~= pre.stored
    &&& post.frozen_head =~= pre.frozen_head
}

/// Crash == /\ prepared /\ prepared' = FALSE /\ others unchanged
pub open spec fn crash(pre: State, post: State) -> bool {
    &&& pre.prepared
    &&& !post.prepared
    &&& post.generation == pre.generation
    &&& post.fenced == pre.fenced
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.retained =~= pre.retained
    &&& post.job1 =~= pre.job1
    &&& post.receipt1 =~= pre.receipt1
    &&& post.spent == pre.spent
    &&& post.old_readable == pre.old_readable
    &&& post.stored =~= pre.stored
    &&& post.frozen_head =~= pre.frozen_head
}

/// Cutover == /\ prepared /\ generation = 0
///            /\ generation' = 1 /\ fenced' = FALSE /\ prepared' = FALSE
///            /\ oldReadable' = ~UnsafeCutover
///            /\ spent' = IF ResetSpent THEN 0 ELSE spent
///            /\ receiptGeneration' = IF RelabelReceipt
///                  THEN [j \in Jobs |-> IF j \in retained THEN 1 ELSE receiptGeneration[j]]
///                  ELSE receiptGeneration
/// In the characteristic encoding the relabeled map's 1-set is
/// `retained ∪ receipt1`: every retained job gets 1 and every
/// non-retained job keeps its value.
pub open spec fn cutover(uc: bool, rs: bool, rr: bool, pre: State, post: State) -> bool {
    &&& pre.prepared
    &&& pre.generation == 0
    &&& post.generation == 1
    &&& !post.fenced
    &&& !post.prepared
    &&& post.old_readable == !uc
    &&& post.spent == if rs {
        0
    } else {
        pre.spent
    }
    &&& post.receipt1 =~= if rr {
        pre.retained.union(pre.receipt1)
    } else {
        pre.receipt1
    }
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.retained =~= pre.retained
    &&& post.job1 =~= pre.job1
    &&& post.stored =~= pre.stored
    &&& post.frozen_head =~= pre.frozen_head
}

/// Next under arbitrary config constants.
pub open spec fn next_cfg(uc: bool, rs: bool, rr: bool, pre: State, post: State) -> bool {
    ||| fence(pre, post)
    ||| prepare_cutover(uc, pre, post)
    ||| crash(pre, post)
    ||| cutover(uc, rs, rr, pre, post)
    ||| exists|j: int| is_job(j) && #[trigger] queue(pre, post, j)
    ||| exists|j: int| is_job(j) && #[trigger] store(pre, post, j)
    ||| exists|j: int| is_job(j) && #[trigger] retain(pre, post, j)
}

/// normal.cfg: UnsafeCutover = ResetSpent = RelabelReceipt = FALSE.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, pre, post)
}

/// The three mutant configurations.
pub open spec fn next_mutant_orphan(pre: State, post: State) -> bool {
    next_cfg(true, false, false, pre, post)
}

pub open spec fn next_mutant_budget(pre: State, post: State) -> bool {
    next_cfg(false, true, false, pre, post)
}

pub open spec fn next_mutant_receipt(pre: State, post: State) -> bool {
    next_cfg(false, false, true, pre, post)
}

/// TypeOK: generation 0..1, all job sets inside Jobs, spent bounded by the
/// job count, and the stored/retained/frozen_head subset chain.
pub open spec fn type_ok(s: State) -> bool {
    &&& (s.generation == 0 || s.generation == 1)
    &&& s.created.subset_of(jobs())
    &&& s.pending.subset_of(jobs())
    &&& s.retained.subset_of(jobs())
    &&& s.job1.subset_of(jobs())
    &&& s.receipt1.subset_of(jobs())
    &&& s.stored.subset_of(jobs())
    &&& s.frozen_head.subset_of(jobs())
    &&& 0 <= s.spent <= 2
    &&& s.stored.subset_of(s.created)
    &&& s.retained.subset_of(s.stored)
    &&& s.frozen_head.subset_of(s.stored)
}

/// NoOrphans == \A j \in pending : Reachable(j)
pub open spec fn no_orphans(s: State) -> bool {
    forall|j: int| s.pending.contains(j) ==> reachable(s, j)
}

/// PreservedSpend == spent = Cardinality(created)
pub open spec fn preserved_spend(s: State) -> bool {
    s.spent == s.created.len()
}

/// BoundReceipts == \A j \in retained : receiptGeneration[j] = jobGeneration[j]
pub open spec fn bound_receipts(s: State) -> bool {
    forall|j: int| s.retained.contains(j) ==> (s.receipt1.contains(j) == s.job1.contains(j))
}

/// Conservation == pending \cup retained = created /\ disjoint
pub open spec fn conservation(s: State) -> bool {
    &&& s.pending.union(s.retained) =~= s.created
    &&& s.pending.intersect(s.retained) =~= Set::empty()
}

/// FrozenHead == (fenced \/ generation = 1) =>
///                  {j \in stored : jobGeneration[j] = 0} = frozenHead
/// jobGeneration[j] = 0 is !job1.contains(j), so the filtered set is
/// stored \ job1.
pub open spec fn frozen_head(s: State) -> bool {
    (s.fenced || s.generation == 1) ==> s.stored.difference(s.job1) =~= s.frozen_head
}

/// Auxiliary: preparation implies pending is empty (the safe configuration
/// only prepares when drained, and nothing refills while prepared).
pub open spec fn prepared_drained(s: State) -> bool {
    s.prepared ==> s.pending =~= Set::empty()
}

/// Auxiliary: a job's generation never exceeds the current generation —
/// before cutover every jobGeneration is 0, i.e. job1 is empty. This is
/// what makes the frozen head capture exactly the stored set at fence time.
pub open spec fn gen_bounded(s: State) -> bool {
    s.generation == 0 ==> s.job1 =~= Set::empty()
}

/// Auxiliary: preparation implies fenced (PrepareCutover is the only action
/// that sets prepared, and it requires fenced; nothing unfences until
/// cutover, which also unprepares).
pub open spec fn prepared_fenced(s: State) -> bool {
    s.prepared ==> s.fenced
}

/// The inductive invariant: TypeOK plus the five checked properties
/// strengthened by the three auxiliaries.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& no_orphans(s)
    &&& preserved_spend(s)
    &&& bound_receipts(s)
    &&& conservation(s)
    &&& frozen_head(s)
    &&& prepared_drained(s)
    &&& gen_bounded(s)
    &&& prepared_fenced(s)
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
}

proof fn queue_preserves(pre: State, post: State, j: int)
    requires
        inv(pre),
        is_job(j),
        queue(pre, post, j),
    ensures
        inv(post),
{
    // gen_bounded: in generation 0 the new member is removed from job1,
    // so job1 stays empty; in generation 1 the antecedent is false.
    if post.generation == 0 {
        assert(pre.job1 =~= Set::empty());
    }
    // no_orphans: the new member's job generation is the current one; other
    // pending members keep their membership answers (x != j).
    assert forall|x: int| post.pending.contains(x) implies reachable(post, x) by {
        if x == j {
            assert(post.job1.contains(j) == (post.generation == 1));
            assert(reachable(post, x));
        } else {
            assert(pre.pending.contains(x));
            assert(reachable(pre, x));
            assert(post.job1.contains(x) == pre.job1.contains(x));
            assert(reachable(post, x));
        }
    }
    // preserved_spend: created grows by one absent member.
    assert(post.created.len() == pre.created.len() + 1);
    // type_ok bounds: spent + 1 stays within the two-job capacity since
    // created' ⊆ jobs.
    assert(jobs().len() == 2);
    assert(post.created.subset_of(jobs())) by {
        assert forall|x: int| post.created.contains(x) implies jobs().contains(x) by {
            if x == j {
                assert(is_job(j));
            } else {
                assert(pre.created.contains(x));
            }
        }
    }
    assert(post.pending.subset_of(jobs())) by {
        assert forall|x: int| post.pending.contains(x) implies jobs().contains(x) by {
            if x == j {
                assert(is_job(j));
            } else {
                assert(pre.pending.contains(x));
            }
        }
    }
    vstd::set_lib::lemma_len_subset(post.created, jobs());
    assert(post.spent <= 2);
    // conservation: pending ∪ retained gains exactly j, disjoint since
    // j ∉ created ⊇ pending, retained.
    assert(post.pending.union(post.retained) =~= post.created) by {
        assert forall|x: int| post.pending.union(post.retained).contains(x)
            implies post.created.contains(x) by {
            if post.pending.contains(x) {
                if x == j {
                } else {
                    assert(pre.pending.contains(x));
                    assert(pre.pending.union(pre.retained).contains(x));
                }
            } else {
                assert(pre.retained.contains(x));
                assert(pre.pending.union(pre.retained).contains(x));
            }
        }
        assert forall|x: int| post.created.contains(x) implies post.pending.union(
            post.retained,
        ).contains(x) by {
            if x == j {
            } else {
                assert(pre.created.contains(x));
                assert(pre.pending.contains(x) || pre.retained.contains(x));
            }
        }
    }
    assert(post.pending.intersect(post.retained) =~= Set::empty()) by {
        assert forall|x: int| !(post.pending.contains(x) && post.retained.contains(x)) by {
            if post.pending.contains(x) && post.retained.contains(x) {
                assert(pre.retained.contains(x) || x == j);
                if x == j {
                    // retained ⊆ created and j ∉ created
                    assert(pre.retained.contains(x));
                    assert(pre.created.contains(x));
                } else {
                    assert(pre.pending.contains(x));
                    assert(pre.retained.contains(x));
                    assert(pre.pending.intersect(pre.retained).contains(x));
                }
            }
        }
    }
    // frozen_head: fenced and generation unchanged. In generation 1 the
    // zero-set is stored \ job1; job1 gains j but j ∉ stored (stored ⊆
    // created and j ∉ created), so the difference is unchanged.
    if post.fenced || post.generation == 1 {
        assert(pre.generation == 1);
        assert(frozen_head(pre));
        assert(post.stored.difference(post.job1) =~= post.frozen_head) by {
            assert forall|x: int| post.stored.difference(post.job1).contains(x)
                implies post.frozen_head.contains(x) by {
                assert(pre.stored.contains(x) && !pre.job1.contains(x));
            }
            assert forall|x: int| post.frozen_head.contains(x) implies post.stored.difference(
                post.job1,
            ).contains(x) by {
                assert(pre.stored.contains(x) && !pre.job1.contains(x));
                // x != j since j ∉ created ⊇ stored
                assert(x != j) by {
                    if x == j {
                        assert(pre.stored.contains(j));
                        assert(pre.created.contains(j));
                    }
                }
                assert(!post.job1.contains(x));
            }
        }
    }
    assert(type_ok(post));
    assert(no_orphans(post));
    assert(preserved_spend(post));
    assert(bound_receipts(post));
    assert(conservation(post));
    assert(frozen_head(post));
    assert(prepared_drained(post));
    assert(gen_bounded(post));
    assert(prepared_fenced(post));
}

proof fn store_preserves(pre: State, post: State, j: int)
    requires
        inv(pre),
        is_job(j),
        store(pre, post, j),
    ensures
        inv(post),
{
    // no_orphans: pending, job1, generation and old_readable are unchanged,
    // so reachability answers are identical.
    assert forall|x: int| post.pending.contains(x) implies reachable(post, x) by {
        assert(pre.pending.contains(x));
        assert(reachable(pre, x));
        assert(post.job1.contains(x) == pre.job1.contains(x));
        assert(reachable(post, x));
    }
    // frozen_head: only reachable when generation = 1 (fenced stays false
    // through this action since ~fenced is a guard). The added member has
    // job_gen = generation = 1, i.e. j ∈ job1, so stored \ job1 is
    // unchanged.
    if post.fenced || post.generation == 1 {
        assert(pre.generation == 1);
        assert(pre.job1.contains(j));
        assert(frozen_head(pre));
        assert(post.stored.difference(post.job1) =~= post.frozen_head) by {
            assert forall|x: int| post.stored.difference(post.job1).contains(x)
                implies post.frozen_head.contains(x) by {
                assert(pre.stored.contains(x) && !pre.job1.contains(x));
            }
            assert forall|x: int| post.frozen_head.contains(x) implies post.stored.difference(
                post.job1,
            ).contains(x) by {
                assert(pre.stored.contains(x) && !pre.job1.contains(x));
                assert(x != j) by {
                    if x == j {
                        assert(pre.job1.contains(j));
                        assert(!pre.job1.contains(j));
                    }
                }
                assert(post.stored.contains(x) && !post.job1.contains(x));
            }
        }
    }
    assert(post.created.len() == post.spent);
    assert(type_ok(post));
    assert(no_orphans(post));
    assert(preserved_spend(post));
    assert(bound_receipts(post));
    assert(conservation(post));
    assert(frozen_head(post));
    assert(prepared_drained(post));
    assert(gen_bounded(post));
    assert(prepared_fenced(post));
}

proof fn retain_preserves(pre: State, post: State, j: int)
    requires
        inv(pre),
        is_job(j),
        retain(pre, post, j),
    ensures
        inv(post),
{
    // bound_receipts: the new member's receipt1 membership is set to its
    // job1 membership exactly.
    assert forall|x: int| post.retained.contains(x) implies (post.receipt1.contains(x)
        == post.job1.contains(x)) by {
        if x == j {
            assert(post.receipt1.contains(x) == pre.job1.contains(x));
        } else {
            assert(pre.retained.contains(x));
            assert(pre.receipt1.contains(x) == pre.job1.contains(x));
            assert(post.receipt1.contains(x) == pre.receipt1.contains(x));
        }
    }
    // conservation: j moved from pending to retained.
    assert(post.pending.union(post.retained) =~= post.created) by {
        assert forall|x: int| post.pending.union(post.retained).contains(x)
            implies post.created.contains(x) by {
            if post.pending.contains(x) {
                assert(pre.pending.contains(x));
                assert(pre.pending.union(pre.retained).contains(x));
            } else {
                if x == j {
                    assert(pre.pending.contains(j));
                    assert(pre.pending.union(pre.retained).contains(j));
                } else {
                    assert(pre.retained.contains(x));
                    assert(pre.pending.union(pre.retained).contains(x));
                }
            }
        }
        assert forall|x: int| post.created.contains(x) implies post.pending.union(
            post.retained,
        ).contains(x) by {
            assert(pre.pending.union(pre.retained).contains(x));
            if pre.pending.contains(x) {
                if x == j {
                    assert(post.retained.contains(x));
                } else {
                    assert(post.pending.contains(x));
                }
            } else {
                assert(pre.retained.contains(x));
                assert(post.retained.contains(x));
            }
        }
    }
    assert(post.pending.intersect(post.retained) =~= Set::empty()) by {
        assert forall|x: int| !(post.pending.contains(x) && post.retained.contains(x)) by {
            if post.pending.contains(x) && post.retained.contains(x) {
                assert(pre.pending.contains(x) && x != j);
                assert(pre.retained.contains(x) || x == j);
                assert(pre.retained.contains(x));
                assert(pre.pending.intersect(pre.retained).contains(x));
            }
        }
    }
    // no_orphans: pending loses only j; other members' reachability is
    // unchanged (job1, generation, old_readable are the same).
    assert forall|x: int| post.pending.contains(x) implies reachable(post, x) by {
        assert(pre.pending.contains(x) && x != j);
        assert(reachable(pre, x));
        assert(post.job1.contains(x) == pre.job1.contains(x));
        assert(reachable(post, x));
    }
    // frozen_head: stored, job1, frozen_head, fenced, generation unchanged.
    if post.fenced || post.generation == 1 {
        assert(frozen_head(pre));
        assert(post.stored.difference(post.job1) =~= post.frozen_head) by {
            assert forall|x: int| post.stored.difference(post.job1).contains(x)
                implies post.frozen_head.contains(x) by {
                assert(pre.stored.contains(x) && !pre.job1.contains(x));
            }
            assert forall|x: int| post.frozen_head.contains(x) implies post.stored.difference(
                post.job1,
            ).contains(x) by {
                assert(pre.stored.contains(x) && !pre.job1.contains(x));
            }
        }
    }
    assert(type_ok(post));
    assert(no_orphans(post));
    assert(preserved_spend(post));
    assert(bound_receipts(post));
    assert(conservation(post));
    assert(frozen_head(post));
    assert(prepared_drained(post));
    assert(gen_bounded(post));
    assert(prepared_fenced(post));
}

proof fn fence_preserves(pre: State, post: State)
    requires
        inv(pre),
        fence(pre, post),
    ensures
        inv(post),
{
    // frozen_head: gen_bounded empties job1 at generation 0, so
    // stored \ job1 = stored = frozen_head'.
    assert(pre.job1 =~= Set::empty());
    assert(post.stored.difference(post.job1) =~= pre.stored);
    assert(type_ok(post));
    assert(no_orphans(post));
    assert(preserved_spend(post));
    assert(bound_receipts(post));
    assert(conservation(post));
    assert(frozen_head(post));
    assert(prepared_drained(post));
    assert(gen_bounded(post));
    assert(prepared_fenced(post));
}

proof fn prepare_preserves(pre: State, post: State)
    requires
        inv(pre),
        prepare_cutover(false, pre, post),
    ensures
        inv(post),
{
    assert(pre.pending =~= Set::empty());
    assert(frozen_head(pre));
    assert(type_ok(post));
    assert(no_orphans(post));
    assert(preserved_spend(post));
    assert(bound_receipts(post));
    assert(conservation(post));
    assert(frozen_head(post));
    assert(prepared_drained(post));
    assert(gen_bounded(post));
    assert(prepared_fenced(post));
}

proof fn crash_preserves(pre: State, post: State)
    requires
        inv(pre),
        crash(pre, post),
    ensures
        inv(post),
{
    if post.fenced || post.generation == 1 {
        assert(frozen_head(pre));
    }
    assert(type_ok(post));
    assert(no_orphans(post));
    assert(preserved_spend(post));
    assert(bound_receipts(post));
    assert(conservation(post));
    assert(frozen_head(post));
    assert(prepared_drained(post));
    assert(gen_bounded(post));
    assert(prepared_fenced(post));
}

proof fn cutover_preserves(pre: State, post: State)
    requires
        inv(pre),
        cutover(false, false, false, pre, post),
    ensures
        inv(post),
{
    // prepared_drained gives pending = {} at cutover, so no_orphans is
    // vacuous in generation 1.
    assert(pre.pending =~= Set::empty());
    // frozen_head: prepared_fenced gives fenced at pre, so
    // stored \ job1 =~= frozen_head held there; stored, job1 and
    // frozen_head are unchanged.
    assert(pre.fenced);
    assert(frozen_head(pre));
    assert(pre.stored.difference(pre.job1) =~= pre.frozen_head);
    assert(post.stored.difference(post.job1) =~= pre.stored.difference(pre.job1)) by {
        assert forall|x: int| post.stored.difference(post.job1).contains(x)
            implies pre.stored.difference(pre.job1).contains(x) by {
            assert(pre.stored.contains(x) && !pre.job1.contains(x));
        }
        assert forall|x: int| pre.stored.difference(pre.job1).contains(x)
            implies post.stored.difference(post.job1).contains(x) by {
            assert(post.stored.contains(x) && !post.job1.contains(x));
        }
    }
    assert(type_ok(post));
    assert(no_orphans(post));
    assert(preserved_spend(post));
    assert(bound_receipts(post));
    assert(conservation(post));
    assert(frozen_head(post));
    assert(prepared_drained(post));
    assert(gen_bounded(post));
    assert(prepared_fenced(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if fence(pre, post) {
        fence_preserves(pre, post);
    } else if prepare_cutover(false, pre, post) {
        prepare_preserves(pre, post);
    } else if crash(pre, post) {
        crash_preserves(pre, post);
    } else if cutover(false, false, false, pre, post) {
        cutover_preserves(pre, post);
    } else if exists|j: int| is_job(j) && queue(pre, post, j) {
        let j = choose|j: int| is_job(j) && queue(pre, post, j);
        queue_preserves(pre, post, j);
    } else if exists|j: int| is_job(j) && store(pre, post, j) {
        let j = choose|j: int| is_job(j) && store(pre, post, j);
        store_preserves(pre, post, j);
    } else {
        let j = choose|j: int| is_job(j) && retain(pre, post, j);
        retain_preserves(pre, post, j);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_orphan_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_orphan(t[i], t[i + 1])
}

pub open spec fn is_budget_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_budget(t[i], t[i + 1])
}

pub open spec fn is_receipt_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_receipt(t[i], t[i + 1])
}

proof fn trace_satisfies_inv(t: Seq<State>)
    requires
        is_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(t[i]),
    decreases t.len(),
{
    if t.len() > 1 {
        let prefix = t.drop_last();
        assert(is_trace(prefix)) by {
            assert forall|i: int| 0 <= i < prefix.len() - 1 implies #[trigger] next(
                prefix[i],
                prefix[i + 1],
            ) by {
                assert(prefix[i] == t[i]);
                assert(prefix[i + 1] == t[i + 1]);
                assert(next(t[i], t[i + 1]));
            }
        }
        trace_satisfies_inv(prefix);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            if i == t.len() - 1 {
                let k = i - 1;
                assert(prefix[k] == t[k]);
                assert(inv(prefix[k]));
                assert(next(t[k], t[k + 1]));
                assert(t[k + 1] == t[i]);
                step_inv(t[k], t[i]);
            } else {
                assert(prefix[i] == t[i]);
                assert(inv(prefix[i]));
            }
        }
    } else {
        init_inv(t[0]);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            assert(i == 0);
        }
    }
}

/// Constructing states concisely for the witness proofs.
pub open spec fn st(
    generation: int,
    fenced: bool,
    created: Set<int>,
    pending: Set<int>,
    retained: Set<int>,
    job1: Set<int>,
    receipt1: Set<int>,
    spent: int,
    prepared: bool,
    old_readable: bool,
    stored: Set<int>,
    frozen_head: Set<int>,
) -> State {
    State {
        generation,
        fenced,
        created,
        pending,
        retained,
        job1,
        receipt1,
        spent,
        prepared,
        old_readable,
        stored,
        frozen_head,
    }
}

/// mutant-orphan: Queue(a) -> Fence -> PrepareCutover (unsafe, pending # {})
/// -> Cutover leaves a pending job whose generation-0 record is unreadable.
proof fn mutant_orphan_violates()
    ensures
        exists|t: Seq<State>| is_orphan_trace(t) && !no_orphans(t.last()),
{
    let e = Set::empty();
    let s0 = st(0, false, e, e, e, e, e, 0, false, true, e, e);
    let s1 = st(0, false, jobs_a(), e.insert(1), e, e, e, 1, false, true, e, e);
    let s2 = st(0, true, jobs_a(), e.insert(1), e, e, e, 1, false, true, e, e);
    let s3 = st(0, true, jobs_a(), e.insert(1), e, e, e, 1, true, true, e, e);
    let s4 = st(1, false, jobs_a(), e.insert(1), e, e, e, 1, false, false, e, e);
    assert(init(s0));
    assert(next_mutant_orphan(s0, s1)) by { assert(queue(s0, s1, 1)); }
    assert(next_mutant_orphan(s1, s2)) by { assert(fence(s1, s2)); }
    assert(next_mutant_orphan(s2, s3)) by { assert(prepare_cutover(true, s2, s3)); }
    assert(next_mutant_orphan(s3, s4)) by { assert(cutover(true, false, false, s3, s4)); }
    assert(!no_orphans(s4)) by {
        assert(s4.pending.contains(1));
        assert(!reachable(s4, 1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_orphan_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_orphan(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_orphan_trace(t) && !no_orphans(t.last()));
}

/// mutant-budget: Queue(a) -> Store(a) -> Retain(a) -> Fence -> Prepare
/// -> Cutover with ResetSpent leaves spent = 0 while created = {a}.
proof fn mutant_budget_violates()
    ensures
        exists|t: Seq<State>| is_budget_trace(t) && !preserved_spend(t.last()),
{
    let e = Set::empty();
    let s0 = st(0, false, e, e, e, e, e, 0, false, true, e, e);
    let s1 = st(0, false, jobs_a(), e.insert(1), e, e, e, 1, false, true, e, e);
    let s2 = st(0, false, jobs_a(), e.insert(1), e, e, e, 1, false, true, jobs_a(), e);
    let s3 = st(0, false, jobs_a(), e, jobs_a(), e, e, 1, false, true, jobs_a(), e);
    let s4 = st(0, true, jobs_a(), e, jobs_a(), e, e, 1, false, true, jobs_a(), jobs_a());
    let s5 = st(0, true, jobs_a(), e, jobs_a(), e, e, 1, true, true, jobs_a(), jobs_a());
    let s6 = st(1, false, jobs_a(), e, jobs_a(), e, e, 0, false, true, jobs_a(), jobs_a());
    assert(init(s0));
    assert(next_mutant_budget(s0, s1)) by { assert(queue(s0, s1, 1)); }
    assert(next_mutant_budget(s1, s2)) by { assert(store(s1, s2, 1)); }
    assert(next_mutant_budget(s2, s3)) by { assert(retain(s2, s3, 1)); }
    assert(next_mutant_budget(s3, s4)) by { assert(fence(s3, s4)); }
    assert(next_mutant_budget(s4, s5)) by { assert(prepare_cutover(false, s4, s5)); }
    assert(next_mutant_budget(s5, s6)) by { assert(cutover(false, true, false, s5, s6)); }
    assert(!preserved_spend(s6)) by {
        assert(s6.spent == 0);
        assert(s6.created.len() == 1);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_budget_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_budget(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5);
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                    || t[i + 1] == s5 || t[i + 1] == s6
            );
        }
    }
    assert(t.last() == s6);
    assert(is_budget_trace(t) && !preserved_spend(t.last()));
}

/// mutant-receipt: Queue(a) -> Store(a) -> Retain(a) -> Fence -> Prepare
/// -> Cutover with RelabelReceipt leaves receiptGeneration[a] = 1 while
/// jobGeneration[a] = 0 for the retained job a.
proof fn mutant_receipt_violates()
    ensures
        exists|t: Seq<State>| is_receipt_trace(t) && !bound_receipts(t.last()),
{
    let e = Set::empty();
    let s0 = st(0, false, e, e, e, e, e, 0, false, true, e, e);
    let s1 = st(0, false, jobs_a(), e.insert(1), e, e, e, 1, false, true, e, e);
    let s2 = st(0, false, jobs_a(), e.insert(1), e, e, e, 1, false, true, jobs_a(), e);
    let s3 = st(0, false, jobs_a(), e, jobs_a(), e, e, 1, false, true, jobs_a(), e);
    let s4 = st(0, true, jobs_a(), e, jobs_a(), e, e, 1, false, true, jobs_a(), jobs_a());
    let s5 = st(0, true, jobs_a(), e, jobs_a(), e, e, 1, true, true, jobs_a(), jobs_a());
    let s6 = st(1, false, jobs_a(), e, jobs_a(), e, jobs_a(), 1, false, true, jobs_a(), jobs_a());
    assert(init(s0));
    assert(next_mutant_receipt(s0, s1)) by { assert(queue(s0, s1, 1)); }
    assert(next_mutant_receipt(s1, s2)) by { assert(store(s1, s2, 1)); }
    assert(next_mutant_receipt(s2, s3)) by { assert(retain(s2, s3, 1)); }
    assert(next_mutant_receipt(s3, s4)) by { assert(fence(s3, s4)); }
    assert(next_mutant_receipt(s4, s5)) by { assert(prepare_cutover(false, s4, s5)); }
    assert(next_mutant_receipt(s5, s6)) by { assert(cutover(false, false, true, s5, s6)); }
    assert(!bound_receipts(s6)) by {
        assert(s6.retained.contains(1));
        assert(s6.receipt1.contains(1));
        assert(!s6.job1.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_receipt_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_receipt(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5);
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                    || t[i + 1] == s5 || t[i + 1] == s6
            );
        }
    }
    assert(t.last() == s6);
    assert(is_receipt_trace(t) && !bound_receipts(t.last()));
}

/// Completion witness for the safe model: Queue(a) -> Store(a) -> Retain(a)
/// -> Fence -> Prepare -> Cutover -> Queue(b) -> Store(b) -> Retain(b)
/// reaches generation 1 with both jobs retained and receipts bound.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().generation == 1
            && t.last().retained =~= jobs(),
{
    let e = Set::empty();
    let j2 = Set::empty().insert(2);
    let s0 = st(0, false, e, e, e, e, e, 0, false, true, e, e);
    let s1 = st(0, false, jobs_a(), e.insert(1), e, e, e, 1, false, true, e, e);
    let s2 = st(0, false, jobs_a(), e.insert(1), e, e, e, 1, false, true, jobs_a(), e);
    let s3 = st(0, false, jobs_a(), e, jobs_a(), e, e, 1, false, true, jobs_a(), e);
    let s4 = st(0, true, jobs_a(), e, jobs_a(), e, e, 1, false, true, jobs_a(), jobs_a());
    let s5 = st(0, true, jobs_a(), e, jobs_a(), e, e, 1, true, true, jobs_a(), jobs_a());
    let s6 = st(1, false, jobs_a(), e, jobs_a(), e, e, 1, false, true, jobs_a(), jobs_a());
    let s7 = st(1, false, jobs(), j2, jobs_a(), j2, e, 2, false, true, jobs_a(), jobs_a());
    let s8 = st(1, false, jobs(), j2, jobs_a(), j2, e, 2, false, true, jobs(), jobs_a());
    let s9 = st(1, false, jobs(), e, jobs(), j2, j2, 2, false, true, jobs(), jobs_a());
    assert(init(s0));
    assert(next(s0, s1)) by { assert(queue(s0, s1, 1)); }
    assert(next(s1, s2)) by { assert(store(s1, s2, 1)); }
    assert(next(s2, s3)) by { assert(retain(s2, s3, 1)); }
    assert(next(s3, s4)) by { assert(fence(s3, s4)); }
    assert(next(s4, s5)) by { assert(prepare_cutover(false, s4, s5)); }
    assert(next(s5, s6)) by { assert(cutover(false, false, false, s5, s6)); }
    assert(next(s6, s7)) by { assert(queue(s6, s7, 2)); }
    assert(next(s7, s8)) by { assert(store(s7, s8, 2)); }
    assert(next(s8, s9)) by { assert(retain(s8, s9, 2)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7).push(
        s8,
    ).push(s9);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                    || t[i + 1] == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
                    || t[i + 1] == s9
            );
        }
    }
    assert(t.last() == s9);
    assert(s9.retained =~= jobs());
    assert(is_trace(t) && t.last().generation == 1 && t.last().retained =~= jobs());
}

}
