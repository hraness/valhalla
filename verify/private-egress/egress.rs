//! Verus pilot: inductive proof of the PrivateEgress safety invariant.
//!
//! This file translates `PrivateEgress.tla` under the normal configuration
//! (`TailFastPath = FALSE`) into a Verus transition system and proves that
//! the invariant TLC checks by enumeration — `OldBeforeControl` — is
//! inductive: it holds initially and every action preserves it. Two
//! auxiliary invariants are needed to make the induction go through, which
//! is the work a model checker does silently by enumeration.
//!
//! What this changes: the safety claim for this model no longer rests on
//! TLC's state enumeration or its fingerprint collision estimate; `init`,
//! `next` and `inv` are machine-checked, and `mutant_produces_counterexample`
//! proves that `mutant-tail.cfg`'s defect is reachable, not just observed.
//! What it does not change: the model's abstractions (atomic queue, retained
//! and control steps; the fixed item set 1..3 with old items {1,2}), the
//! production-correspondence tests, or the counterexample receipts. This is
//! a proof about the specification, not a refinement proof of the Rust
//! implementation.
//!
//! Encoding note: `Cardinality(queue) <= 1` is stated as pairwise equality
//! of queue members, which is equivalent for finite sets and avoids
//! cardinality lemmas. `queue = {}` versus `queue # {}` is stated as
//! emptiness versus membership, again equivalent.
//!
//! Verify with:
//!   verus --crate-type=lib verify/private-egress/egress.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Items == 1..3.
pub open spec fn max_item() -> int {
    3
}

pub open spec fn is_item(i: int) -> bool {
    1 <= i <= max_item()
}

/// Old == {1, 2}.
pub open spec fn is_old(i: int) -> bool {
    i == 1 || i == 2
}

pub open spec fn old_items() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

/// VARIABLES captured, queue, retained, control, admittedAtCutover.
pub struct State {
    pub captured: int,
    pub queue: Set<int>,
    pub retained: Set<int>,
    pub control: bool,
    pub admitted_at_cutover: Set<int>,
}

pub open spec fn init(s: State) -> bool {
    &&& s.captured == 1
    &&& s.queue =~= Set::empty().insert(1)
    &&& s.retained =~= Set::empty()
    &&& !s.control
    &&& s.admitted_at_cutover =~= Set::empty()
}

/// Capture == /\ captured < 3 /\ queue = {}
///            /\ captured' = captured + 1
///            /\ queue' = IF captured + 1 \in retained THEN {} ELSE {captured + 1}
///            /\ UNCHANGED <<retained, control, admittedAtCutover>>
pub open spec fn capture(pre: State, post: State) -> bool {
    &&& pre.captured < max_item()
    &&& pre.queue =~= Set::empty()
    &&& post.captured == pre.captured + 1
    &&& post.queue =~= if pre.retained.contains(pre.captured + 1) {
        Set::empty()
    } else {
        Set::empty().insert(pre.captured + 1)
    }
    &&& post.retained =~= pre.retained
    &&& post.control == pre.control
    &&& post.admitted_at_cutover =~= pre.admitted_at_cutover
}

/// ReceiptFastPath, parameterized by the TailFastPath config constant.
/// The normal model gates it with `false`; mutant-tail.cfg gates it with
/// `true` and produces the recorded counterexample.
pub open spec fn receipt_fast_path(tail_fast_path: bool, pre: State, post: State) -> bool {
    &&& tail_fast_path
    &&& pre.captured < max_item()
    &&& pre.queue =~= Set::empty()
    &&& !pre.retained.contains(max_item())
    &&& post.queue =~= Set::empty().insert(max_item())
    &&& post.captured == pre.captured
    &&& post.retained =~= pre.retained
    &&& post.control == pre.control
    &&& post.admitted_at_cutover =~= pre.admitted_at_cutover
}

/// SendItem(i) == /\ i \in queue /\ (i \in Old \/ control)
///                /\ queue' = {} /\ retained' = retained \cup {i}
///                /\ UNCHANGED <<captured, control, admittedAtCutover>>
pub open spec fn send_item(pre: State, post: State, i: int) -> bool {
    &&& pre.queue.contains(i)
    &&& (is_old(i) || pre.control)
    &&& post.queue =~= Set::empty()
    &&& post.retained =~= pre.retained.insert(i)
    &&& post.captured == pre.captured
    &&& post.control == pre.control
    &&& post.admitted_at_cutover =~= pre.admitted_at_cutover
}

/// SendControl == /\ ~control /\ (captured = 3 \/ queue # {})
///                /\ queue \intersect Old = {}
///                /\ control' = TRUE /\ admittedAtCutover' = retained
///                /\ UNCHANGED <<captured, queue, retained>>
pub open spec fn send_control(pre: State, post: State) -> bool {
    &&& !pre.control
    &&& (pre.captured == max_item() || !(pre.queue =~= Set::empty()))
    &&& pre.queue.intersect(old_items()) =~= Set::empty()
    &&& post.control
    &&& post.admitted_at_cutover =~= pre.retained
    &&& post.captured == pre.captured
    &&& post.queue =~= pre.queue
    &&& post.retained =~= pre.retained
}

/// Next under normal.cfg (TailFastPath = FALSE).
pub open spec fn next(pre: State, post: State) -> bool {
    ||| capture(pre, post)
    ||| receipt_fast_path(false, pre, post)
    ||| send_control(pre, post)
    ||| exists|i: int| is_item(i) && #[trigger] send_item(pre, post, i)
}

/// Next under mutant-tail.cfg (TailFastPath = TRUE).
pub open spec fn next_mutant(pre: State, post: State) -> bool {
    ||| capture(pre, post)
    ||| receipt_fast_path(true, pre, post)
    ||| send_control(pre, post)
    ||| exists|i: int| is_item(i) && #[trigger] send_item(pre, post, i)
}

/// TypeOK, with cardinality replaced by pairwise queue equality.
pub open spec fn type_ok(s: State) -> bool {
    &&& 1 <= s.captured <= max_item()
    &&& forall|i: int| s.queue.contains(i) ==> is_item(i)
    &&& forall|x: int, y: int| s.queue.contains(x) && s.queue.contains(y) ==> x == y
    &&& forall|i: int| s.retained.contains(i) ==> is_item(i)
    &&& s.admitted_at_cutover.subset_of(s.retained)
}

/// Auxiliary invariant: nothing staged or retained exceeds the capture
/// count. Needed so that `queue = {3}` implies `captured = 3`.
pub open spec fn staged_bounded(s: State) -> bool {
    &&& forall|i: int| s.queue.contains(i) ==> i <= s.captured
    &&& forall|i: int| s.retained.contains(i) ==> i <= s.captured
}

/// Auxiliary invariant: a captured item is never dropped; it is still
/// staged in the queue or already retained. Needed so that `captured = 3`
/// implies both old items are in `retained`.
pub open spec fn captured_kept(s: State) -> bool {
    forall|i: int| is_item(i) && i <= s.captured
        ==> s.queue.contains(i) || s.retained.contains(i)
}

/// OldBeforeControl == control => Old \subseteq admittedAtCutover.
pub open spec fn old_before_control(s: State) -> bool {
    s.control ==> old_items().subset_of(s.admitted_at_cutover)
}

/// The inductive invariant: the model's own TypeOK and OldBeforeControl,
/// strengthened by the two auxiliaries above.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& staged_bounded(s)
    &&& captured_kept(s)
    &&& old_before_control(s)
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
    assert forall|i: int| is_item(i) && i <= s.captured implies s.queue.contains(i)
        || s.retained.contains(i) by {
        assert(i == 1);
    }
}

proof fn capture_preserves(pre: State, post: State)
    requires
        inv(pre),
        capture(pre, post),
    ensures
        inv(post),
{
    let next_item = pre.captured + 1;
    assert(is_item(next_item));
    assert forall|i: int| is_item(i) && i <= post.captured implies post.queue.contains(i)
        || post.retained.contains(i) by {
        if i <= pre.captured {
            // queue(pre) is empty, so captured_kept(pre) gives retained.
            assert(pre.retained.contains(i));
        } else {
            // i == captured + 1: staged into queue' unless already retained.
            assert(i == next_item);
            assert(post.queue.contains(i) || post.retained.contains(i));
        }
    }
}

proof fn send_item_preserves(pre: State, post: State, i: int)
    requires
        inv(pre),
        is_item(i),
        send_item(pre, post, i),
    ensures
        inv(post),
{
    // The queue held at most one member and i was in it, so queue was {i}.
    assert forall|x: int| pre.queue.contains(x) implies x == i by {
        assert(x == i) by {
            assert(pre.queue.contains(x) && pre.queue.contains(i));
        }
    }
    assert(pre.queue =~= Set::empty().insert(i));
    assert forall|j: int| is_item(j) && j <= post.captured implies post.queue.contains(j)
        || post.retained.contains(j) by {
        // captured_kept(pre): j was in queue or retained; queue members all
        // equal i, and i moves to retained', so j is in retained'.
        assert(pre.queue.contains(j) || pre.retained.contains(j));
        if pre.queue.contains(j) {
            assert(j == i);
        }
        assert(post.retained.contains(j));
    }
    assert forall|j: int| post.retained.contains(j) implies j <= post.captured by {
        if j == i {
            assert(staged_bounded(pre));
            assert(pre.queue.contains(i));
        }
    }
}

proof fn send_control_preserves(pre: State, post: State)
    requires
        inv(pre),
        send_control(pre, post),
    ensures
        inv(post),
{
    // Establish captured = 3 from either guard disjunct.
    if pre.captured != max_item() {
        // queue # {}: pick its member; it is a non-old item, so it is 3,
        // and staged_bounded forces captured >= 3.
        let x = choose|x: int| pre.queue.contains(x);
        assert(!(pre.queue =~= Set::empty())) by {
            assert(pre.queue.contains(x));
        }
        assert(!is_old(x)) by {
            if is_old(x) {
                assert(pre.queue.intersect(old_items()).contains(x));
            }
        }
        assert(is_item(x));
        assert(x == max_item());
        assert(pre.captured == max_item());
    }
    // captured = 3, so captured_kept puts both old items in queue or
    // retained; the guard keeps them out of the queue, so both are retained.
    assert forall|j: int| is_old(j) implies pre.retained.contains(j) by {
        assert(is_item(j) && j <= pre.captured);
        if pre.queue.contains(j) {
            assert(pre.queue.intersect(old_items()).contains(j));
        }
    }
    assert(old_items().subset_of(pre.retained)) by {
        assert forall|j: int| old_items().contains(j) implies pre.retained.contains(j) by {
            assert(is_old(j));
        }
    }
    // post.admitted_at_cutover = pre.retained = post.retained, so both
    // subset_of(type_ok) and the safety invariant hold after the cutover.
    assert(post.admitted_at_cutover.subset_of(post.retained));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if capture(pre, post) {
        capture_preserves(pre, post);
    } else if receipt_fast_path(false, pre, post) {
        // Unreachable: the gate is `false`.
    } else if send_control(pre, post) {
        send_control_preserves(pre, post);
    } else {
        let i = choose|i: int| is_item(i) && send_item(pre, post, i);
        send_item_preserves(pre, post, i);
    }
}

/// Every state of every finite execution satisfies the invariant.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_mutant_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant(t[i], t[i + 1])
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

/// The recorded mutant-tail counterexample, checked rather than observed:
/// init -> SendItem(1) -> ReceiptFastPath -> SendControl ends with
/// control set while item 2 was never admitted.
proof fn mutant_produces_counterexample()
    ensures
        exists|t: Seq<State>| is_mutant_trace(t) && !old_before_control(t.last()),
{
    let s0 = State {
        captured: 1,
        queue: Set::empty().insert(1),
        retained: Set::empty(),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s1 = State {
        captured: 1,
        queue: Set::empty(),
        retained: Set::empty().insert(1),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s2 = State {
        captured: 1,
        queue: Set::empty().insert(3),
        retained: Set::empty().insert(1),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s3 = State {
        captured: 1,
        queue: Set::empty().insert(3),
        retained: Set::empty().insert(1),
        control: true,
        admitted_at_cutover: Set::empty().insert(1),
    };
    assert(init(s0));
    assert(send_item(s0, s1, 1));
    assert(next_mutant(s0, s1));
    assert(receipt_fast_path(true, s1, s2));
    assert(next_mutant(s1, s2));
    assert(send_control(s2, s3));
    assert(next_mutant(s2, s3));
    // control is set but admittedAtCutover = {1} does not contain item 2.
    assert(!old_before_control(s3)) by {
        assert(old_items().contains(2));
        assert(!s3.admitted_at_cutover.contains(2));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3);
    assert(is_mutant_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant(t[i], t[i + 1]) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3);
        }
    }
    assert(t.last() == s3);
    assert(is_mutant_trace(t) && !old_before_control(t.last()));
}

/// Non-vacuity witness for the safe model: init -> SendItem(1) -> Capture
/// -> SendItem(2) -> Capture -> SendControl -> SendItem(3) reaches the
/// completed cutover with both old items admitted. This is the proof-side
/// analogue of the reachability controls in the TLC suite.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().control
            && t.last().admitted_at_cutover =~= old_items(),
{
    let s0 = State {
        captured: 1,
        queue: Set::empty().insert(1),
        retained: Set::empty(),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s1 = State {
        captured: 1,
        queue: Set::empty(),
        retained: Set::empty().insert(1),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s2 = State {
        captured: 2,
        queue: Set::empty().insert(2),
        retained: Set::empty().insert(1),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s3 = State {
        captured: 2,
        queue: Set::empty(),
        retained: Set::empty().insert(1).insert(2),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s4 = State {
        captured: 3,
        queue: Set::empty().insert(3),
        retained: Set::empty().insert(1).insert(2),
        control: false,
        admitted_at_cutover: Set::empty(),
    };
    let s5 = State {
        captured: 3,
        queue: Set::empty().insert(3),
        retained: Set::empty().insert(1).insert(2),
        control: true,
        admitted_at_cutover: Set::empty().insert(1).insert(2),
    };
    let s6 = State {
        captured: 3,
        queue: Set::empty(),
        retained: Set::empty().insert(1).insert(2).insert(3),
        control: true,
        admitted_at_cutover: Set::empty().insert(1).insert(2),
    };
    assert(init(s0));
    assert(next(s0, s1)) by { assert(send_item(s0, s1, 1)); }
    assert(next(s1, s2)) by { assert(capture(s1, s2)); }
    assert(next(s2, s3)) by { assert(send_item(s2, s3, 2)); }
    assert(next(s3, s4)) by { assert(capture(s3, s4)); }
    assert(next(s4, s5)) by { assert(send_control(s4, s5)); }
    assert(next(s5, s6)) by { assert(send_item(s5, s6, 3)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5);
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1] == s5
                    || t[i + 1] == s6
            );
        }
    }
    assert(t.last() == s6);
    assert(old_items() =~= s6.admitted_at_cutover);
    assert(is_trace(t) && t.last().control && t.last().admitted_at_cutover =~= old_items());
}

}
