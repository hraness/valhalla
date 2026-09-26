//! Verus pilot (4th model): inductive proof of PrivateDelivery's
//! invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs` and
//! `verify/private-publication/publication.rs`: `PrivateDelivery.tla` under
//! `normal.cfg` is re-stated as a Verus transition system and the six
//! checked invariants (`TypeOK`, `NoLostWork`, `Bounded`, `ExactlyOnce`,
//! `ControlBeforeFuture`, `Disjoint`) are proved inductive. The three
//! mutant configurations are proved to reach violations of the invariants
//! TLC found for them — `mutant-skip` (DropFuture) and `mutant-crash`
//! (LosePending) break `NoLostWork`, `mutant-duplicate` (DoubleApply)
//! breaks `ExactlyOnce` — and a completion witness runs a client through
//! the full safe lifecycle. `EventuallyResolved` is a liveness property
//! and is out of scope: only the safety invariants are proved.
//!
//! Encoding notes:
//!   * Clients == {native, browser} is the concrete set {1, 2};
//!     native/browser map to 1/2. Items == 1..3, Capacity = 3,
//!     MaxCrashes = 1.
//!   * `cursor`, `staged` and `crashes` are `[Clients -> int]` read
//!     through `map_at` (0 off-domain). `effects` is
//!     `[Clients -> [Items -> 0..2]]` flattened to `Map<int,int>` keyed by
//!     `ekey(c, m) = c * 10 + m`; the all-zero init table is the empty
//!     map, read-equivalent under `map_at`.
//!   * `pending`/`applied` are `[Clients -> SUBSET Items]` encoded as
//!     `Map<int, Set<int>>` read through `set_at` (empty off-domain);
//!     `online` is the characteristic set of TRUE-valued clients.
//!   * The single TLA+ existential `\E c \in Clients` splits into six,
//!     one per action — equivalent.
//!   * mutant-*.cfg shrink Clients to a singleton to bound TLC's state
//!     space; the proved witnesses replay the same recorded action
//!     sequences inside the two-client instance, where they stay enabled
//!     and reach the same violated invariant.
//!
//! Verify with:
//!   verus --crate-type=lib verify/private-delivery/delivery.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Clients == {native, browser} as {1, 2}.
pub open spec fn clients() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

/// Items == 1..3.
pub open spec fn items() -> Set<int> {
    Set::empty().insert(1).insert(2).insert(3)
}

pub open spec fn is_client(c: int) -> bool {
    clients().contains(c)
}

pub open spec fn is_item(m: int) -> bool {
    items().contains(m)
}

/// Capacity = 3.
pub open spec fn capacity() -> nat {
    3
}

/// MaxCrashes = 1.
pub open spec fn max_crashes() -> int {
    1
}

/// Flat key for `effects[c][m]`; injective since m < 10.
pub open spec fn ekey(c: int, m: int) -> int {
    c * 10 + m
}

/// Total scalar map read at int keys (0 off-domain).
pub open spec fn map_at(m: Map<int, int>, j: int) -> int {
    if m.dom().contains(j) {
        m[j]
    } else {
        0
    }
}

/// Total map-of-sets read at int keys (empty off-domain).
pub open spec fn set_at(m: Map<int, Set<int>>, j: int) -> Set<int> {
    if m.dom().contains(j) {
        m[j]
    } else {
        Set::empty()
    }
}

/// The all-zero client map at init.
pub open spec fn zmap() -> Map<int, int> {
    Map::new(clients(), |c: int| 0)
}

/// The all-empty client-to-set map at init.
pub open spec fn zset() -> Map<int, Set<int>> {
    Map::new(clients(), |c: int| Set::empty())
}

/// VARIABLES cursor, pending, applied, staged, online, crashes, effects.
pub struct State {
    pub cursor: Map<int, int>,
    pub pending: Map<int, Set<int>>,
    pub applied: Map<int, Set<int>>,
    pub staged: Map<int, int>,
    pub online: Set<int>,
    pub crashes: Map<int, int>,
    pub effects: Map<int, int>,
}

/// Ready(c, m) == m # 1 \/ 3 \in applied[c]
pub open spec fn ready(s: State, c: int, m: int) -> bool {
    m != 1 || set_at(s.applied, c).contains(3)
}

pub open spec fn init(s: State) -> bool {
    &&& s.cursor =~= zmap()
    &&& s.pending =~= zset()
    &&& s.applied =~= zset()
    &&& s.staged =~= zmap()
    &&& s.online =~= clients()
    &&& s.crashes =~= zmap()
    &&& s.effects =~= Map::empty()
}

/// Fetch(c): online, nothing staged, cursor not exhausted, pending under
/// capacity; stages cursor[c] + 1.
pub open spec fn fetch(pre: State, post: State, c: int) -> bool {
    &&& pre.online.contains(c)
    &&& map_at(pre.staged, c) == 0
    &&& map_at(pre.cursor, c) < 3
    &&& set_at(pre.pending, c).len() < capacity()
    &&& post.staged =~= pre.staged.insert(c, map_at(pre.cursor, c) + 1)
    &&& post.cursor =~= pre.cursor
    &&& post.pending =~= pre.pending
    &&& post.applied =~= pre.applied
    &&& post.online =~= pre.online
    &&& post.crashes =~= pre.crashes
    &&& post.effects =~= pre.effects
}

/// PublishFetch(c): online with a staged item; commits cursor to it and,
/// unless DropFuture drops a not-ready staged item, adds it to pending.
/// The mutant-skip configuration sets df.
pub open spec fn publish_fetch(pre: State, post: State, df: bool, c: int) -> bool {
    &&& pre.online.contains(c)
    &&& map_at(pre.staged, c) != 0
    &&& post.cursor =~= pre.cursor.insert(c, map_at(pre.staged, c))
    &&& post.pending =~= if df && !ready(pre, c, map_at(pre.staged, c)) {
        pre.pending
    } else {
        pre.pending.insert(c, set_at(pre.pending, c).insert(map_at(pre.staged, c)))
    }
    &&& post.staged =~= pre.staged.insert(c, 0)
    &&& post.applied =~= pre.applied
    &&& post.online =~= pre.online
    &&& post.crashes =~= pre.crashes
    &&& post.effects =~= pre.effects
}

/// Apply(c, m): online, m pending and ready; moves it to applied and
/// records one application effect.
pub open spec fn apply(pre: State, post: State, c: int, m: int) -> bool {
    &&& pre.online.contains(c)
    &&& set_at(pre.pending, c).contains(m)
    &&& ready(pre, c, m)
    &&& post.pending =~= pre.pending.insert(c, set_at(pre.pending, c).remove(m))
    &&& post.applied =~= pre.applied.insert(c, set_at(pre.applied, c).insert(m))
    &&& post.effects =~= pre.effects.insert(ekey(c, m), map_at(pre.effects, ekey(c, m)) + 1)
    &&& post.cursor =~= pre.cursor
    &&& post.staged =~= pre.staged
    &&& post.online =~= pre.online
    &&& post.crashes =~= pre.crashes
}

/// Replay(c, m): an exact retained retry of an applied item. Under
/// DoubleApply it records the effect again (the mutant-duplicate defect).
pub open spec fn replay(pre: State, post: State, da: bool, c: int, m: int) -> bool {
    &&& pre.online.contains(c)
    &&& set_at(pre.applied, c).contains(m)
    &&& map_at(pre.effects, ekey(c, m)) < 2
    &&& post.effects =~= if da {
        pre.effects.insert(ekey(c, m), map_at(pre.effects, ekey(c, m)) + 1)
    } else {
        pre.effects
    }
    &&& post.cursor =~= pre.cursor
    &&& post.pending =~= pre.pending
    &&& post.applied =~= pre.applied
    &&& post.staged =~= pre.staged
    &&& post.online =~= pre.online
    &&& post.crashes =~= pre.crashes
}

/// Crash(c): goes offline within the crash budget, dropping any staged
/// fetch. Under LosePending it also drops the pending mailbox (the
/// mutant-crash defect).
pub open spec fn crash(pre: State, post: State, lp: bool, c: int) -> bool {
    &&& pre.online.contains(c)
    &&& map_at(pre.crashes, c) < max_crashes()
    &&& post.online =~= pre.online.remove(c)
    &&& post.crashes =~= pre.crashes.insert(c, map_at(pre.crashes, c) + 1)
    &&& post.staged =~= pre.staged.insert(c, 0)
    &&& post.pending =~= if lp {
        pre.pending.insert(c, Set::empty())
    } else {
        pre.pending
    }
    &&& post.cursor =~= pre.cursor
    &&& post.applied =~= pre.applied
    &&& post.effects =~= pre.effects
}

/// Recover(c): offline -> online.
pub open spec fn recover(pre: State, post: State, c: int) -> bool {
    &&& !pre.online.contains(c)
    &&& post.online =~= pre.online.insert(c)
    &&& post.cursor =~= pre.cursor
    &&& post.pending =~= pre.pending
    &&& post.applied =~= pre.applied
    &&& post.staged =~= pre.staged
    &&& post.crashes =~= pre.crashes
    &&& post.effects =~= pre.effects
}

/// Next under arbitrary config constants (DropFuture, LosePending,
/// DoubleApply).
pub open spec fn next_cfg(df: bool, lp: bool, da: bool, pre: State, post: State) -> bool {
    ||| exists|c: int| is_client(c) && #[trigger] fetch(pre, post, c)
    ||| exists|c: int| is_client(c) && #[trigger] publish_fetch(pre, post, df, c)
    ||| exists|c: int| is_client(c) && #[trigger] crash(pre, post, lp, c)
    ||| exists|c: int| is_client(c) && #[trigger] recover(pre, post, c)
    ||| exists|c: int, m: int| is_client(c) && is_item(m) && #[trigger] apply(pre, post, c, m)
    ||| exists|c: int, m: int| is_client(c) && is_item(m) && #[trigger] replay(pre, post, da, c, m)
}

/// normal.cfg: DropFuture = LosePending = DoubleApply = FALSE.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, pre, post)
}

/// mutant-skip.cfg: DropFuture = TRUE.
pub open spec fn next_mutant_skip(pre: State, post: State) -> bool {
    next_cfg(true, false, false, pre, post)
}

/// mutant-crash.cfg: LosePending = TRUE.
pub open spec fn next_mutant_crash(pre: State, post: State) -> bool {
    next_cfg(false, true, false, pre, post)
}

/// mutant-duplicate.cfg: DoubleApply = TRUE.
pub open spec fn next_mutant_duplicate(pre: State, post: State) -> bool {
    next_cfg(false, false, true, pre, post)
}

/// TypeOK.
pub open spec fn type_ok(s: State) -> bool {
    &&& forall|c: int| is_client(c) ==> 0 <= map_at(s.cursor, c) <= 3
    &&& forall|c: int| is_client(c) ==> set_at(s.pending, c).subset_of(items())
    &&& forall|c: int| is_client(c) ==> set_at(s.applied, c).subset_of(items())
    &&& forall|c: int| is_client(c) ==> 0 <= map_at(s.staged, c) <= 3
    &&& s.online.subset_of(clients())
    &&& forall|c: int| is_client(c) ==> 0 <= map_at(s.crashes, c) <= max_crashes()
    &&& forall|c: int, m: int| is_client(c) && is_item(m) ==> 0 <= map_at(
        s.effects,
        ekey(c, m),
    ) <= 2
}

/// NoLostWork == (1..cursor[c]) \subseteq pending[c] \cup applied[c]
pub open spec fn no_lost_work(s: State) -> bool {
    forall|c: int, m: int| is_client(c) && 1 <= m <= map_at(s.cursor, c) ==> set_at(
        s.pending,
        c,
    ).contains(m) || set_at(s.applied, c).contains(m)
}

/// Bounded == Cardinality(pending[c]) <= Capacity
pub open spec fn bounded(s: State) -> bool {
    forall|c: int| is_client(c) ==> set_at(s.pending, c).len() <= capacity()
}

/// ExactlyOnce == effects[c][m] <= 1
pub open spec fn exactly_once(s: State) -> bool {
    forall|c: int, m: int| is_client(c) && is_item(m) ==> map_at(s.effects, ekey(c, m)) <= 1
}

/// ControlBeforeFuture == 1 \in applied[c] => 3 \in applied[c]
pub open spec fn control_before_future(s: State) -> bool {
    forall|c: int| is_client(c) && set_at(s.applied, c).contains(1) ==> set_at(
        s.applied,
        c,
    ).contains(3)
}

/// Disjoint == pending[c] \intersect applied[c] = {}
pub open spec fn disjoint(s: State) -> bool {
    forall|c: int| is_client(c) ==> set_at(s.pending, c).intersect(set_at(s.applied, c))
        =~= Set::empty()
}

/// Auxiliary: a nonzero staged value is exactly the next cursor — Fetch
/// stages cursor[c]+1 and no action leaves a nonzero staged value behind
/// a moved cursor. This is what makes PublishFetch cover the new cursor
/// position (staged = cursor + 1) and stay clear of applied
/// (staged > cursor).
pub open spec fn staged_is_next(s: State) -> bool {
    forall|c: int| is_client(c) && map_at(s.staged, c) != 0 ==> map_at(s.staged, c)
        == map_at(s.cursor, c) + 1
}

/// Auxiliary: pending members never exceed the durable cursor — items
/// enter pending only as the committed staged value. Needed so an applied
/// member drawn from pending stays within the cursor.
pub open spec fn pending_le_cursor(s: State) -> bool {
    forall|c: int, m: int| is_client(c) && set_at(s.pending, c).contains(m) ==> m <= map_at(
        s.cursor,
        c,
    )
}

/// Auxiliary: applied members never exceed the durable cursor. With
/// staged_is_next this keeps the newly published staged value out of
/// applied, which is what preserves Disjoint through PublishFetch.
pub open spec fn applied_le_cursor(s: State) -> bool {
    forall|c: int, m: int| is_client(c) && set_at(s.applied, c).contains(m) ==> m <= map_at(
        s.cursor,
        c,
    )
}

/// Auxiliary: a nonzero effect count implies the item was applied — Apply
/// is the only safe-config action that records an effect and it adds the
/// item to applied atomically. With Disjoint this forces a pending item's
/// effect count to zero, which is what makes Apply preserve ExactlyOnce.
pub open spec fn effect_applied(s: State) -> bool {
    forall|c: int, m: int| is_client(c) && is_item(m) && map_at(s.effects, ekey(c, m)) >= 1
        ==> set_at(s.applied, c).contains(m)
}

/// The inductive invariant: the six checked invariants strengthened by
/// the four auxiliaries.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& no_lost_work(s)
    &&& bounded(s)
    &&& exactly_once(s)
    &&& control_before_future(s)
    &&& disjoint(s)
    &&& staged_is_next(s)
    &&& pending_le_cursor(s)
    &&& applied_le_cursor(s)
    &&& effect_applied(s)
}

/// Map insert propagation (scalar values).
proof fn map_insert_at(m: Map<int, int>, k: int, v: int, x: int)
    ensures
        map_at(m.insert(k, v), x) == if x == k {
            v
        } else {
            map_at(m, x)
        },
{
}

/// Map insert propagation (set values).
proof fn set_map_insert_at(m: Map<int, Set<int>>, k: int, v: Set<int>, x: int)
    ensures
        set_at(m.insert(k, v), x) =~= if x == k {
            v
        } else {
            set_at(m, x)
        },
{
}

/// Concrete membership bounds, used to discharge finite-set contains.
proof fn client_bounds(c: int)
    requires
        is_client(c),
    ensures
        c == 1 || c == 2,
{
}

proof fn item_bounds(m: int)
    requires
        is_item(m),
    ensures
        1 <= m <= 3,
{
}

/// ekey injectivity over single-digit items.
proof fn ekey_inj(c1: int, m1: int, c2: int, m2: int)
    requires
        0 <= m1 < 10,
        0 <= m2 < 10,
        ekey(c1, m1) == ekey(c2, m2),
    ensures
        c1 == c2 && m1 == m2,
{
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
    assert forall|c: int| is_client(c) implies 0 <= map_at(s.cursor, c) <= 3 by {
        assert(s.cursor.dom().contains(c));
    }
    assert forall|c: int| is_client(c) implies 0 <= map_at(s.staged, c) <= 3 by {
        assert(s.staged.dom().contains(c));
    }
    assert forall|c: int| is_client(c) implies 0 <= map_at(s.crashes, c) <= max_crashes() by {
        assert(s.crashes.dom().contains(c));
    }
    assert forall|c: int| is_client(c) implies set_at(s.pending, c).subset_of(items()) by {
        assert(s.pending.dom().contains(c));
        assert(set_at(s.pending, c) =~= Set::empty());
    }
    assert forall|c: int| is_client(c) implies set_at(s.applied, c).subset_of(items()) by {
        assert(s.applied.dom().contains(c));
        assert(set_at(s.applied, c) =~= Set::empty());
    }
    assert forall|c: int| is_client(c) implies set_at(s.pending, c).len() <= capacity() by {
        assert(set_at(s.pending, c) =~= Set::empty());
    }
    assert forall|c: int, m: int| is_client(c) && is_item(m) implies 0 <= map_at(
        s.effects,
        ekey(c, m),
    ) <= 2 by {
        assert(!s.effects.dom().contains(ekey(c, m)));
    }
    assert forall|c: int| is_client(c) implies set_at(s.pending, c).intersect(set_at(
        s.applied,
        c,
    )) =~= Set::empty() by {
        assert(set_at(s.pending, c) =~= Set::empty());
        assert(set_at(s.applied, c) =~= Set::empty());
    }
    assert(type_ok(s));
    assert(no_lost_work(s));
    assert(bounded(s));
    assert(exactly_once(s));
    assert(control_before_future(s));
    assert(disjoint(s));
    assert(staged_is_next(s));
    assert(pending_le_cursor(s));
    assert(applied_le_cursor(s));
    assert(effect_applied(s));
}

proof fn fetch_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_client(c),
        fetch(pre, post, c),
    ensures
        inv(post),
{
    let nv = map_at(pre.cursor, c) + 1;
    assert(0 <= map_at(pre.cursor, c));
    // staged bound: nv = cursor + 1 <= 3 by the fetch guard.
    assert forall|x: int| is_client(x) implies 0 <= map_at(post.staged, x) <= 3 by {
        map_insert_at(pre.staged, c, nv, x);
    }
    // staged_is_next: c stages exactly cursor + 1; other clients unchanged.
    assert forall|x: int| is_client(x) && map_at(post.staged, x) != 0 implies map_at(
        post.staged,
        x,
    ) == map_at(post.cursor, x) + 1 by {
        map_insert_at(pre.staged, c, nv, x);
        assert(map_at(post.cursor, x) == map_at(pre.cursor, x));
        if x == c {
            assert(map_at(post.staged, c) == nv);
        }
    }
    assert(type_ok(post));
    assert(no_lost_work(post));
    assert(bounded(post));
    assert(exactly_once(post));
    assert(control_before_future(post));
    assert(disjoint(post));
    assert(staged_is_next(post));
    assert(pending_le_cursor(post));
    assert(applied_le_cursor(post));
    assert(effect_applied(post));
}

proof fn publish_fetch_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_client(c),
        publish_fetch(pre, post, false, c),
    ensures
        inv(post),
{
    let sv = map_at(pre.staged, c);
    // Safe configuration commits the staged item to pending.
    assert(post.pending =~= pre.pending.insert(c, set_at(pre.pending, c).insert(sv)));
    // staged_is_next + TypeOK pin sv to cursor + 1 in 1..3.
    assert(sv == map_at(pre.cursor, c) + 1);
    assert(1 <= sv <= 3);
    assert(is_item(sv));
    // type_ok: cursor' = sv is in range; staged' = 0; pending stays inside
    // items since sv is an item.
    assert forall|x: int| is_client(x) implies 0 <= map_at(post.cursor, x) <= 3 by {
        map_insert_at(pre.cursor, c, sv, x);
    }
    assert forall|x: int| is_client(x) implies 0 <= map_at(post.staged, x) <= 3 by {
        map_insert_at(pre.staged, c, 0, x);
    }
    assert forall|x: int| is_client(x) implies set_at(post.pending, x).subset_of(items()) by {
        set_map_insert_at(pre.pending, c, set_at(pre.pending, c).insert(sv), x);
        if x == c {
            assert forall|m: int| set_at(post.pending, c).contains(m) implies items().contains(
                m,
            ) by {
                if m == sv {
                    assert(items().contains(sv));
                } else {
                    assert(set_at(pre.pending, c).contains(m));
                    assert(items().contains(m));
                }
            }
        } else {
            assert(set_at(post.pending, x) =~= set_at(pre.pending, x));
        }
    }
    // staged_is_next(post): the acting client's staged is 0.
    assert forall|x: int| is_client(x) && map_at(post.staged, x) != 0 implies map_at(
        post.staged,
        x,
    ) == map_at(post.cursor, x) + 1 by {
        map_insert_at(pre.staged, c, 0, x);
        map_insert_at(pre.cursor, c, sv, x);
    }
    // bounded: pending'[x] ⊆ items hence within capacity 3.
    assert forall|x: int| is_client(x) implies set_at(post.pending, x).len() <= capacity() by {
        assert(set_at(post.pending, x).subset_of(items()));
        assert(items().len() == 3);
        vstd::set_lib::lemma_len_subset(set_at(post.pending, x), items());
    }
    // no_lost_work: positions below the old cursor stay covered; the new
    // position sv = cursor + 1 enters pending.
    assert forall|x: int, m: int| is_client(x) && 1 <= m <= map_at(post.cursor, x)
        implies set_at(post.pending, x).contains(m) || set_at(post.applied, x).contains(m) by {
        map_insert_at(pre.cursor, c, sv, x);
        set_map_insert_at(pre.pending, c, set_at(pre.pending, c).insert(sv), x);
        assert(set_at(post.applied, x) =~= set_at(pre.applied, x));
        if x == c {
            if m <= map_at(pre.cursor, c) {
                assert(set_at(pre.pending, c).contains(m) || set_at(pre.applied, c).contains(m));
                if set_at(pre.pending, c).contains(m) {
                    assert(set_at(pre.pending, c).insert(sv).contains(m));
                }
            } else {
                assert(m == sv);
                assert(set_at(post.pending, c).contains(sv));
            }
        } else {
            assert(1 <= m <= map_at(pre.cursor, x));
            assert(set_at(pre.pending, x).contains(m) || set_at(pre.applied, x).contains(m));
        }
    }
    // pending_le_cursor: old members stay below sv = cursor'; sv itself
    // equals cursor'.
    assert forall|x: int, m: int| is_client(x) && set_at(post.pending, x).contains(m)
        implies m <= map_at(post.cursor, x) by {
        map_insert_at(pre.cursor, c, sv, x);
        set_map_insert_at(pre.pending, c, set_at(pre.pending, c).insert(sv), x);
        if x == c {
            if m == sv {
            } else {
                assert(set_at(pre.pending, c).contains(m));
                assert(m <= map_at(pre.cursor, c));
            }
        } else {
            assert(set_at(pre.pending, x).contains(m));
            assert(m <= map_at(pre.cursor, x));
        }
    }
    // applied_le_cursor: applied unchanged and c's cursor grew.
    assert forall|x: int, m: int| is_client(x) && set_at(post.applied, x).contains(m)
        implies m <= map_at(post.cursor, x) by {
        map_insert_at(pre.cursor, c, sv, x);
        assert(set_at(pre.applied, x).contains(m));
        assert(m <= map_at(pre.cursor, x));
    }
    // disjoint: the new pending member sv is above the old cursor, hence
    // not applied; other members keep the pre disjointness.
    assert forall|x: int| is_client(x) implies set_at(post.pending, x).intersect(set_at(
        post.applied,
        x,
    )) =~= Set::empty() by {
        set_map_insert_at(pre.pending, c, set_at(pre.pending, c).insert(sv), x);
        assert(set_at(post.applied, x) =~= set_at(pre.applied, x));
        if x == c {
            assert forall|m: int| !(set_at(post.pending, c).contains(m) && set_at(
                post.applied,
                c,
            ).contains(m)) by {
                if m == sv {
                    if set_at(pre.applied, c).contains(m) {
                        assert(m <= map_at(pre.cursor, c));
                    }
                } else if set_at(pre.pending, c).contains(m) && set_at(pre.applied, c).contains(
                    m,
                ) {
                    assert(set_at(pre.pending, c).intersect(set_at(pre.applied, c)).contains(m));
                }
            }
        } else {
            assert(set_at(post.pending, x) =~= set_at(pre.pending, x));
        }
    }
    assert(type_ok(post));
    assert(no_lost_work(post));
    assert(bounded(post));
    assert(exactly_once(post));
    assert(control_before_future(post));
    assert(disjoint(post));
    assert(staged_is_next(post));
    assert(pending_le_cursor(post));
    assert(applied_le_cursor(post));
    assert(effect_applied(post));
}

proof fn apply_preserves(pre: State, post: State, c: int, m: int)
    requires
        inv(pre),
        is_client(c),
        is_item(m),
        apply(pre, post, c, m),
    ensures
        inv(post),
{
    let ek = ekey(c, m);
    let new_pend = set_at(pre.pending, c).remove(m);
    let new_appl = set_at(pre.applied, c).insert(m);
    // A pending member is inside the cursor and, by Disjoint, not applied.
    assert(m <= map_at(pre.cursor, c));
    assert(!set_at(pre.applied, c).contains(m)) by {
        if set_at(pre.applied, c).contains(m) {
            assert(set_at(pre.pending, c).intersect(set_at(pre.applied, c)).contains(m));
        }
    }
    // Its effect count is therefore 0 (effect_applied contrapositive), so
    // Apply brings it to exactly 1.
    assert(map_at(pre.effects, ek) == 0) by {
        if map_at(pre.effects, ek) >= 1 {
            assert(set_at(pre.applied, c).contains(m));
        }
    }
    item_bounds(m);
    // type_ok: pending shrinks, applied gains the item m, effects' = 1.
    assert forall|x: int| is_client(x) implies set_at(post.pending, x).subset_of(items()) by {
        set_map_insert_at(pre.pending, c, new_pend, x);
        if x == c {
            assert forall|n: int| new_pend.contains(n) implies items().contains(n) by {
                assert(set_at(pre.pending, c).contains(n));
                assert(items().contains(n));
            }
        }
    }
    assert forall|x: int| is_client(x) implies set_at(post.applied, x).subset_of(items()) by {
        set_map_insert_at(pre.applied, c, new_appl, x);
        if x == c {
            assert forall|n: int| new_appl.contains(n) implies items().contains(n) by {
                if n == m {
                    assert(items().contains(m));
                } else {
                    assert(set_at(pre.applied, c).contains(n));
                    assert(items().contains(n));
                }
            }
        }
    }
    assert forall|x: int, n: int| is_client(x) && is_item(n) implies 0 <= map_at(
        post.effects,
        ekey(x, n),
    ) <= 2 by {
        map_insert_at(pre.effects, ek, map_at(pre.effects, ek) + 1, ekey(x, n));
    }
    // bounded: pending only shrinks.
    assert forall|x: int| is_client(x) implies set_at(post.pending, x).len() <= capacity() by {
        assert(set_at(post.pending, x).subset_of(items()));
        assert(items().len() == 3);
        vstd::set_lib::lemma_len_subset(set_at(post.pending, x), items());
    }
    // no_lost_work: the pending ∪ applied coverage is elementwise
    // unchanged — m moves between the two sets.
    assert forall|x: int, n: int| is_client(x) && 1 <= n <= map_at(post.cursor, x)
        implies set_at(post.pending, x).contains(n) || set_at(post.applied, x).contains(n) by {
        set_map_insert_at(pre.pending, c, new_pend, x);
        set_map_insert_at(pre.applied, c, new_appl, x);
        assert(map_at(post.cursor, x) == map_at(pre.cursor, x));
        assert(set_at(pre.pending, x).contains(n) || set_at(pre.applied, x).contains(n));
        if x == c {
            if set_at(pre.pending, c).contains(n) {
                if n == m {
                    assert(new_appl.contains(n));
                } else {
                    assert(new_pend.contains(n));
                }
            } else {
                assert(new_appl.contains(n));
            }
        }
    }
    // disjoint: m left pending as it entered applied; other members keep
    // the pre disjointness.
    assert forall|x: int| is_client(x) implies set_at(post.pending, x).intersect(set_at(
        post.applied,
        x,
    )) =~= Set::empty() by {
        set_map_insert_at(pre.pending, c, new_pend, x);
        set_map_insert_at(pre.applied, c, new_appl, x);
        if x == c {
            assert forall|n: int| !(new_pend.contains(n) && new_appl.contains(n)) by {
                if new_pend.contains(n) {
                    assert(set_at(pre.pending, c).contains(n) && n != m);
                    if new_appl.contains(n) {
                        assert(set_at(pre.applied, c).contains(n));
                        assert(set_at(pre.pending, c).intersect(set_at(pre.applied, c)).contains(
                            n,
                        ));
                    }
                }
            }
        } else {
            assert(set_at(post.pending, x) =~= set_at(pre.pending, x));
            assert(set_at(post.applied, x) =~= set_at(pre.applied, x));
        }
    }
    // pending_le_cursor: pending only shrinks, cursor unchanged.
    assert forall|x: int, n: int| is_client(x) && set_at(post.pending, x).contains(n)
        implies n <= map_at(post.cursor, x) by {
        set_map_insert_at(pre.pending, c, new_pend, x);
        assert(map_at(post.cursor, x) == map_at(pre.cursor, x));
        if x == c {
            assert(set_at(pre.pending, c).contains(n));
        } else {
            assert(set_at(pre.pending, x).contains(n));
        }
    }
    // applied_le_cursor: the new member came from pending, hence <= cursor.
    assert forall|x: int, n: int| is_client(x) && set_at(post.applied, x).contains(n)
        implies n <= map_at(post.cursor, x) by {
        set_map_insert_at(pre.applied, c, new_appl, x);
        assert(map_at(post.cursor, x) == map_at(pre.cursor, x));
        if x == c && n == m {
        } else {
            assert(set_at(pre.applied, x).contains(n));
        }
    }
    // exactly_once: the only changed cell goes 0 -> 1.
    assert forall|x: int, n: int| is_client(x) && is_item(n) implies map_at(
        post.effects,
        ekey(x, n),
    ) <= 1 by {
        map_insert_at(pre.effects, ek, map_at(pre.effects, ek) + 1, ekey(x, n));
    }
    // effect_applied: the newly nonzero cell's item is in applied'; other
    // cells keep their witness since applied only grows.
    assert forall|x: int, n: int| is_client(x) && is_item(n) && map_at(
        post.effects,
        ekey(x, n),
    ) >= 1 implies set_at(post.applied, x).contains(n) by {
        map_insert_at(pre.effects, ek, map_at(pre.effects, ek) + 1, ekey(x, n));
        set_map_insert_at(pre.applied, c, new_appl, x);
        if ekey(x, n) == ek {
            item_bounds(n);
            ekey_inj(x, n, c, m);
            assert(x == c && n == m);
            assert(new_appl.contains(n));
        } else {
            if map_at(pre.effects, ekey(x, n)) >= 1 {
                assert(set_at(pre.applied, x).contains(n));
                if x == c {
                    assert(new_appl.contains(n));
                }
            }
        }
    }
    // control_before_future: applying 1 required 3 already applied.
    assert forall|x: int| is_client(x) && set_at(post.applied, x).contains(1) implies set_at(
        post.applied,
        x,
    ).contains(3) by {
        set_map_insert_at(pre.applied, c, new_appl, x);
        if x == c {
            if m == 1 {
                assert(ready(pre, c, m));
                assert(set_at(pre.applied, c).contains(3));
                assert(new_appl.contains(3));
            } else if new_appl.contains(1) {
                assert(set_at(pre.applied, c).contains(1));
                assert(set_at(pre.applied, c).contains(3));
                assert(new_appl.contains(3));
            }
        }
    }
    assert(type_ok(post));
    assert(no_lost_work(post));
    assert(bounded(post));
    assert(exactly_once(post));
    assert(control_before_future(post));
    assert(disjoint(post));
    assert(staged_is_next(post));
    assert(pending_le_cursor(post));
    assert(applied_le_cursor(post));
    assert(effect_applied(post));
}

proof fn replay_preserves(pre: State, post: State, c: int, m: int)
    requires
        inv(pre),
        is_client(c),
        is_item(m),
        replay(pre, post, false, c, m),
    ensures
        inv(post),
{
    // Safe configuration: effects is unchanged, so every conjunct
    // transfers verbatim.
    assert(type_ok(post));
    assert(no_lost_work(post));
    assert(bounded(post));
    assert(exactly_once(post));
    assert(control_before_future(post));
    assert(disjoint(post));
    assert(staged_is_next(post));
    assert(pending_le_cursor(post));
    assert(applied_le_cursor(post));
    assert(effect_applied(post));
}

proof fn crash_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_client(c),
        crash(pre, post, false, c),
    ensures
        inv(post),
{
    // Safe configuration: pending kept; staged resets to 0; crashes < 1
    // becomes 1; online loses c.
    assert(post.pending =~= pre.pending);
    assert forall|x: int| is_client(x) implies 0 <= map_at(post.crashes, x) <= max_crashes()
        by {
        map_insert_at(pre.crashes, c, map_at(pre.crashes, c) + 1, x);
    }
    assert forall|x: int| is_client(x) implies 0 <= map_at(post.staged, x) <= 3 by {
        map_insert_at(pre.staged, c, 0, x);
    }
    assert forall|x: int| is_client(x) && map_at(post.staged, x) != 0 implies map_at(
        post.staged,
        x,
    ) == map_at(post.cursor, x) + 1 by {
        map_insert_at(pre.staged, c, 0, x);
        assert(map_at(post.cursor, x) == map_at(pre.cursor, x));
        if x == c {
            assert(map_at(post.staged, c) == 0);
        }
    }
    assert(post.online.subset_of(clients())) by {
        assert forall|x: int| post.online.contains(x) implies clients().contains(x) by {
            assert(pre.online.contains(x));
        }
    }
    assert(type_ok(post));
    assert(no_lost_work(post));
    assert(bounded(post));
    assert(exactly_once(post));
    assert(control_before_future(post));
    assert(disjoint(post));
    assert(staged_is_next(post));
    assert(pending_le_cursor(post));
    assert(applied_le_cursor(post));
    assert(effect_applied(post));
}

proof fn recover_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_client(c),
        recover(pre, post, c),
    ensures
        inv(post),
{
    assert(post.online.subset_of(clients())) by {
        assert forall|x: int| post.online.contains(x) implies clients().contains(x) by {
            if x == c {
                assert(is_client(c));
            } else {
                assert(pre.online.contains(x));
            }
        }
    }
    assert(type_ok(post));
    assert(no_lost_work(post));
    assert(bounded(post));
    assert(exactly_once(post));
    assert(control_before_future(post));
    assert(disjoint(post));
    assert(staged_is_next(post));
    assert(pending_le_cursor(post));
    assert(applied_le_cursor(post));
    assert(effect_applied(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if exists|c: int| is_client(c) && fetch(pre, post, c) {
        let c = choose|c: int| is_client(c) && fetch(pre, post, c);
        fetch_preserves(pre, post, c);
    } else if exists|c: int| is_client(c) && publish_fetch(pre, post, false, c) {
        let c = choose|c: int| is_client(c) && publish_fetch(pre, post, false, c);
        publish_fetch_preserves(pre, post, c);
    } else if exists|c: int| is_client(c) && crash(pre, post, false, c) {
        let c = choose|c: int| is_client(c) && crash(pre, post, false, c);
        crash_preserves(pre, post, c);
    } else if exists|c: int| is_client(c) && recover(pre, post, c) {
        let c = choose|c: int| is_client(c) && recover(pre, post, c);
        recover_preserves(pre, post, c);
    } else if exists|c: int, m: int| is_client(c) && is_item(m) && apply(pre, post, c, m) {
        let cm = choose|c: int, m: int| is_client(c) && is_item(m) && apply(pre, post, c, m);
        apply_preserves(pre, post, cm.0, cm.1);
    } else {
        let cm = choose|c: int, m: int| is_client(c) && is_item(m) && replay(
            pre,
            post,
            false,
            c,
            m,
        );
        replay_preserves(pre, post, cm.0, cm.1);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_skip_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_skip(t[i], t[i + 1])
}

pub open spec fn is_crash_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_crash(t[i], t[i + 1])
}

pub open spec fn is_duplicate_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_duplicate(t[i], t[i + 1])
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
    cursor: Map<int, int>,
    pending: Map<int, Set<int>>,
    applied: Map<int, Set<int>>,
    staged: Map<int, int>,
    online: Set<int>,
    crashes: Map<int, int>,
    effects: Map<int, int>,
) -> State {
    State { cursor, pending, applied, staged, online, crashes, effects }
}

/// mutant-skip (DropFuture): Fetch(browser) -> PublishFetch(browser) drops
/// the future-epoch item 1 because its enabling control 3 is not applied —
/// cursor advances past an item that is nowhere.
proof fn mutant_skip_violates()
    ensures
        exists|t: Seq<State>| is_skip_trace(t) && !no_lost_work(t.last()),
{
    let e: Set<int> = Set::empty();
    let s0 = st(zmap(), zset(), zset(), zmap(), clients(), zmap(), Map::empty());
    let s1 = st(zmap(), zset(), zset(), zmap().insert(2, 1), clients(), zmap(), Map::empty());
    let s2 = st(
        zmap().insert(2, 1),
        zset(),
        zset(),
        zmap().insert(2, 0),
        clients(),
        zmap(),
        Map::empty(),
    );
    assert(init(s0));
    assert(next_mutant_skip(s0, s1)) by {
        assert(is_client(2));
        assert(fetch(s0, s1, 2));
    }
    assert(next_mutant_skip(s1, s2)) by {
        assert(is_client(2));
        assert(map_at(s1.staged, 2) == 1);
        assert(!ready(s1, 2, 1));
        assert(publish_fetch(s1, s2, true, 2));
    }
    assert(!no_lost_work(s2)) by {
        assert(map_at(s2.cursor, 2) == 1);
        assert(!set_at(s2.pending, 2).contains(1));
        assert(!set_at(s2.applied, 2).contains(1));
        assert(!(set_at(s2.pending, 2).contains(1) || set_at(s2.applied, 2).contains(1)));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_skip_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_skip(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_skip_trace(t) && !no_lost_work(t.last()));
}

/// mutant-crash (LosePending): Fetch(browser) -> PublishFetch(browser) ->
/// Crash(browser) empties pending while cursor stays at 1 — the committed
/// item is lost.
proof fn mutant_crash_violates()
    ensures
        exists|t: Seq<State>| is_crash_trace(t) && !no_lost_work(t.last()),
{
    let e: Set<int> = Set::empty();
    let s0 = st(zmap(), zset(), zset(), zmap(), clients(), zmap(), Map::empty());
    let s1 = st(zmap(), zset(), zset(), zmap().insert(2, 1), clients(), zmap(), Map::empty());
    let s2 = st(
        zmap().insert(2, 1),
        zset().insert(2, e.insert(1)),
        zset(),
        zmap().insert(2, 0),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s3 = st(
        zmap().insert(2, 1),
        s2.pending.insert(2, e),
        zset(),
        zmap().insert(2, 0),
        clients().remove(2),
        zmap().insert(2, 1),
        Map::empty(),
    );
    assert(init(s0));
    assert(next_mutant_crash(s0, s1)) by {
        assert(is_client(2));
        assert(fetch(s0, s1, 2));
    }
    assert(next_mutant_crash(s1, s2)) by {
        assert(is_client(2));
        assert(map_at(s1.staged, 2) == 1);
        assert(publish_fetch(s1, s2, false, 2));
    }
    assert(next_mutant_crash(s2, s3)) by {
        assert(is_client(2));
        assert(crash(s2, s3, true, 2));
    }
    assert(!no_lost_work(s3)) by {
        assert(map_at(s3.cursor, 2) == 1);
        assert(set_at(s3.pending, 2) =~= e);
        assert(!set_at(s3.applied, 2).contains(1));
        assert(!(set_at(s3.pending, 2).contains(1) || set_at(s3.applied, 2).contains(1)));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3);
    assert(is_crash_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_crash(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3);
        }
    }
    assert(t.last() == s3);
    assert(is_crash_trace(t) && !no_lost_work(t.last()));
}

/// mutant-duplicate (DoubleApply): fetch and publish items 1, 2, then
/// Apply(native, 2) and Replay(native, 2) records a second effect for the
/// same retained item.
proof fn mutant_duplicate_violates()
    ensures
        exists|t: Seq<State>| is_duplicate_trace(t) && !exactly_once(t.last()),
{
    let e: Set<int> = Set::empty();
    let s0 = st(zmap(), zset(), zset(), zmap(), clients(), zmap(), Map::empty());
    let s1 = st(zmap(), zset(), zset(), zmap().insert(1, 1), clients(), zmap(), Map::empty());
    let s2 = st(
        zmap().insert(1, 1),
        zset().insert(1, e.insert(1)),
        zset(),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s3 = st(
        zmap().insert(1, 1),
        zset().insert(1, e.insert(1)),
        zset(),
        zmap().insert(1, 2),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s4 = st(
        zmap().insert(1, 2),
        zset().insert(1, e.insert(1).insert(2)),
        zset(),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s5 = st(
        zmap().insert(1, 2),
        s4.pending.insert(1, set_at(s4.pending, 1).remove(2)),
        s4.applied.insert(1, set_at(s4.applied, 1).insert(2)),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        s4.effects.insert(ekey(1, 2), map_at(s4.effects, ekey(1, 2)) + 1),
    );
    let s6 = st(
        zmap().insert(1, 2),
        s5.pending,
        s5.applied,
        zmap().insert(1, 0),
        clients(),
        zmap(),
        s5.effects.insert(ekey(1, 2), 2),
    );
    assert(init(s0));
    assert(next_mutant_duplicate(s0, s1)) by {
        assert(is_client(1));
        assert(fetch(s0, s1, 1));
    }
    assert(next_mutant_duplicate(s1, s2)) by {
        assert(is_client(1));
        assert(map_at(s1.staged, 1) == 1);
        assert(publish_fetch(s1, s2, false, 1));
    }
    assert(next_mutant_duplicate(s2, s3)) by {
        assert(is_client(1));
        assert(map_at(s2.cursor, 1) == 1);
        assert(set_at(s2.pending, 1).len() == 1);
        assert(fetch(s2, s3, 1));
    }
    assert(next_mutant_duplicate(s3, s4)) by {
        assert(is_client(1));
        assert(map_at(s3.staged, 1) == 2);
        assert(publish_fetch(s3, s4, false, 1));
    }
    assert(next_mutant_duplicate(s4, s5)) by {
        assert(is_client(1));
        assert(is_item(2));
        assert(set_at(s4.pending, 1).contains(2));
        assert(apply(s4, s5, 1, 2));
    }
    assert(next_mutant_duplicate(s5, s6)) by {
        assert(is_client(1));
        assert(is_item(2));
        assert(map_at(s5.effects, ekey(1, 2)) == 1);
        assert(replay(s5, s6, true, 1, 2));
    }
    assert(!exactly_once(s6)) by {
        assert(is_client(1) && is_item(2));
        assert(map_at(s6.effects, ekey(1, 2)) == 2);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_duplicate_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_duplicate(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i]
                == s5);
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6
            );
        }
    }
    assert(t.last() == s6);
    assert(is_duplicate_trace(t) && !exactly_once(t.last()));
}

/// Completion witness for the safe model: native fetches, publishes and
/// applies all three items in dependency order (control 3 before the
/// future item 1), survives a retained Replay, a Crash and a Recover, and
/// ends with applied = Items.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && set_at(t.last().applied, 1) =~= items()
            && t.last().online =~= clients(),
{
    let e: Set<int> = Set::empty();
    let s0 = st(zmap(), zset(), zset(), zmap(), clients(), zmap(), Map::empty());
    let s1 = st(zmap(), zset(), zset(), zmap().insert(1, 1), clients(), zmap(), Map::empty());
    let s2 = st(
        zmap().insert(1, 1),
        zset().insert(1, e.insert(1)),
        zset(),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s3 = st(
        zmap().insert(1, 1),
        zset().insert(1, e.insert(1)),
        zset(),
        zmap().insert(1, 2),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s4 = st(
        zmap().insert(1, 2),
        zset().insert(1, e.insert(1).insert(2)),
        zset(),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s5 = st(
        zmap().insert(1, 2),
        zset().insert(1, e.insert(1).insert(2)),
        zset(),
        zmap().insert(1, 3),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s6 = st(
        zmap().insert(1, 3),
        zset().insert(1, e.insert(1).insert(2).insert(3)),
        zset(),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        Map::empty(),
    );
    let s7 = st(
        zmap().insert(1, 3),
        s6.pending.insert(1, set_at(s6.pending, 1).remove(3)),
        s6.applied.insert(1, set_at(s6.applied, 1).insert(3)),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        s6.effects.insert(ekey(1, 3), map_at(s6.effects, ekey(1, 3)) + 1),
    );
    let s8 = st(
        zmap().insert(1, 3),
        s7.pending.insert(1, set_at(s7.pending, 1).remove(2)),
        s7.applied.insert(1, set_at(s7.applied, 1).insert(2)),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        s7.effects.insert(ekey(1, 2), map_at(s7.effects, ekey(1, 2)) + 1),
    );
    let s9 = st(
        zmap().insert(1, 3),
        s8.pending.insert(1, set_at(s8.pending, 1).remove(1)),
        s8.applied.insert(1, set_at(s8.applied, 1).insert(1)),
        zmap().insert(1, 0),
        clients(),
        zmap(),
        s8.effects.insert(ekey(1, 1), map_at(s8.effects, ekey(1, 1)) + 1),
    );
    // Replay(1, 1) is a safe-config no-op: effects unchanged.
    let s10 = st(
        s9.cursor,
        s9.pending,
        s9.applied,
        s9.staged,
        s9.online,
        s9.crashes,
        s9.effects,
    );
    let s11 = st(
        s10.cursor,
        s10.pending,
        s10.applied,
        s10.staged.insert(1, 0),
        s10.online.remove(1),
        s10.crashes.insert(1, map_at(s10.crashes, 1) + 1),
        s10.effects,
    );
    let s12 = st(
        s11.cursor,
        s11.pending,
        s11.applied,
        s11.staged,
        s11.online.insert(1),
        s11.crashes,
        s11.effects,
    );
    assert(init(s0));
    assert(next(s0, s1)) by {
        assert(is_client(1));
        assert(fetch(s0, s1, 1));
    }
    assert(next(s1, s2)) by {
        assert(is_client(1));
        assert(publish_fetch(s1, s2, false, 1));
    }
    assert(next(s2, s3)) by {
        assert(is_client(1));
        assert(fetch(s2, s3, 1));
    }
    assert(next(s3, s4)) by {
        assert(is_client(1));
        assert(publish_fetch(s3, s4, false, 1));
    }
    assert(next(s4, s5)) by {
        assert(is_client(1));
        assert(fetch(s4, s5, 1));
    }
    assert(next(s5, s6)) by {
        assert(is_client(1));
        assert(publish_fetch(s5, s6, false, 1));
    }
    assert(next(s6, s7)) by {
        assert(is_client(1) && is_item(3));
        assert(apply(s6, s7, 1, 3));
    }
    assert(next(s7, s8)) by {
        assert(is_client(1) && is_item(2));
        assert(apply(s7, s8, 1, 2));
    }
    assert(next(s8, s9)) by {
        assert(is_client(1) && is_item(1));
        assert(ready(s8, 1, 1));
        assert(set_at(s8.applied, 1).contains(3));
        assert(apply(s8, s9, 1, 1));
    }
    assert(next(s9, s10)) by {
        assert(is_client(1) && is_item(1));
        assert(map_at(s9.effects, ekey(1, 1)) == 1);
        assert(replay(s9, s10, false, 1, 1));
    }
    assert(next(s10, s11)) by {
        assert(is_client(1));
        assert(map_at(s10.crashes, 1) == 0);
        assert(crash(s10, s11, false, 1));
    }
    assert(next(s11, s12)) by {
        assert(is_client(1));
        assert(!s11.online.contains(1));
        assert(recover(s11, s12, 1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(
        s7,
    ).push(s8).push(s9).push(s10).push(s11).push(s12);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9 || t[i] == s10
                    || t[i] == s11
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8 || t[i + 1] == s9
                    || t[i + 1] == s10 || t[i + 1] == s11 || t[i + 1] == s12
            );
        }
    }
    assert(t.last() == s12);
    assert(set_at(s12.applied, 1) =~= items()) by {
        assert(set_at(s12.applied, 1) =~= e.insert(1).insert(2).insert(3));
    }
    assert(s12.online =~= clients());
    assert(is_trace(t) && set_at(t.last().applied, 1) =~= items() && t.last().online =~= clients());
}


// ---------------------------------------------------------------------
// Liveness: EventuallyResolved under the spec's declared weak fairness.
//
// `Fair == WF(Fetch) /\ WF(PublishFetch) /\ WF(Recover) /\ WF(Apply)`.
// Verus proves the WF1-style content: (1) at every reachable non-goal
// state a covered action is enabled, so a fair behavior cannot stutter
// forever below the goal; (2) every covered step strictly decreases a
// bounded well-founded measure; and (3) measure 0 implies the goal.
// Together every fair execution reaches the goal within measure(init)
// covered steps. The only non-covered steps are Crash (which itself
// decreases the measure by consuming the crash budget) and Replay
// (which is a no-op: post =~= pre).
// ---------------------------------------------------------------------

/// Non-stuttering: at least one field changed (safe-Replay is a no-op,
/// so it is the only covered-by-Next step that is not real).
pub open spec fn real_step(a: State, b: State) -> bool {
    !(b.cursor =~= a.cursor && b.pending =~= a.pending && b.applied =~= a.applied
        && b.staged =~= a.staged && b.online =~= a.online && b.crashes =~= a.crashes
        && b.effects =~= a.effects)
}

/// The body of EventuallyResolved: every client has applied all items.
pub open spec fn goal(s: State) -> bool {
    &&& set_at(s.applied, 1) =~= items()
    &&& set_at(s.applied, 2) =~= items()
}

/// A covered (WF-guarded) step under the safe configuration.
pub open spec fn wf_step(pre: State, post: State) -> bool {
    ||| exists|c: int| is_client(c) && #[trigger] fetch(pre, post, c)
    ||| exists|c: int| is_client(c) && #[trigger] publish_fetch(pre, post, false, c)
    ||| exists|c: int| is_client(c) && #[trigger] recover(pre, post, c)
    ||| exists|c: int, m: int| is_client(c) && is_item(m) && #[trigger] apply(pre, post, c, m)
}

/// Guard-level covered availability body: a Fetch / PublishFetch /
/// Recover / Apply guard holds for (c, m).
pub open spec fn covered_guard(s: State, c: int, m: int) -> bool {
    ||| (is_client(c) && s.online.contains(c) && map_at(s.staged, c) == 0
        && map_at(s.cursor, c) < 3 && set_at(s.pending, c).len() < capacity())
    ||| (is_client(c) && s.online.contains(c) && map_at(s.staged, c) != 0)
    ||| (is_client(c) && !s.online.contains(c))
    ||| (is_client(c) && is_item(m) && s.online.contains(c)
        && set_at(s.pending, c).contains(m) && ready(s, c, m))
}

/// Guard-level covered availability (the enabledness half of WF).
pub open spec fn covered_enabled(s: State) -> bool {
    exists|c: int, m: int| #[trigger] covered_guard(s, c, m)
}

/// Pipeline distance of one item for one client: applied = 0,
/// pending = 1, staged = 2, unseen = 3.
pub open spec fn idist(s: State, c: int, i: int) -> int {
    if set_at(s.applied, c).contains(i) {
        0
    } else if set_at(s.pending, c).contains(i) {
        1
    } else if map_at(s.staged, c) == i {
        2
    } else {
        3
    }
}

/// Per-client progress measure: crash budget dominates (a crash costs
/// 4 but can add back at most 2), then the offline bit, then the sum of
/// per-item pipeline distances.
pub open spec fn measure_c(s: State, c: int) -> int {
    4 * (max_crashes() - map_at(s.crashes, c))
        + (if s.online.contains(c) { 0int } else { 1int })
        + idist(s, c, 1) + idist(s, c, 2) + idist(s, c, 3)
}

pub open spec fn measure(s: State) -> int {
    measure_c(s, 1) + measure_c(s, 2)
}

proof fn measure_nonneg(s: State)
    requires
        inv(s),
    ensures
        measure(s) >= 0,
{
    assert(type_ok(s));
    assert(is_client(1) && is_client(2));
    assert(0 <= map_at(s.crashes, 1) <= max_crashes());
    assert(0 <= map_at(s.crashes, 2) <= max_crashes());
}

proof fn measure_zero_is_goal(s: State)
    requires
        inv(s),
        measure(s) == 0,
    ensures
        goal(s),
{
    assert(type_ok(s));
    assert(is_client(1) && is_client(2));
    assert(0 <= map_at(s.crashes, 1) <= max_crashes());
    assert(0 <= map_at(s.crashes, 2) <= max_crashes());
    assert(measure_c(s, 1) >= 0 && measure_c(s, 2) >= 0);
    assert(measure_c(s, 1) == 0 && measure_c(s, 2) == 0);
    assert(idist(s, 1, 1) >= 0 && idist(s, 1, 2) >= 0 && idist(s, 1, 3) >= 0);
    assert(idist(s, 2, 1) >= 0 && idist(s, 2, 2) >= 0 && idist(s, 2, 3) >= 0);
    assert(idist(s, 1, 1) == 0 && idist(s, 1, 2) == 0 && idist(s, 1, 3) == 0);
    assert(idist(s, 2, 1) == 0 && idist(s, 2, 2) == 0 && idist(s, 2, 3) == 0);
    assert forall|c: int| c == 1 || c == 2 implies set_at(s.applied, c).contains(1)
        && set_at(s.applied, c).contains(2) && set_at(s.applied, c).contains(3) by {
        assert(idist(s, c, 1) == 0);
        assert(idist(s, c, 2) == 0);
        assert(idist(s, c, 3) == 0);
    }
    assert(set_at(s.applied, 1).contains(1) && set_at(s.applied, 1).contains(2)
        && set_at(s.applied, 1).contains(3));
    assert(set_at(s.applied, 2).contains(1) && set_at(s.applied, 2).contains(2)
        && set_at(s.applied, 2).contains(3));
    assert(set_at(s.applied, 1).subset_of(items()));
    assert(set_at(s.applied, 2).subset_of(items()));
    assert(set_at(s.applied, 1) =~= items()) by {
        assert forall|i: int| set_at(s.applied, 1).contains(i) implies items().contains(i) by {
        }
        assert forall|i: int| items().contains(i) implies set_at(s.applied, 1).contains(i) by {
        }
    }
    assert(set_at(s.applied, 2) =~= items()) by {
        assert forall|i: int| set_at(s.applied, 2).contains(i) implies items().contains(i) by {
        }
        assert forall|i: int| items().contains(i) implies set_at(s.applied, 2).contains(i) by {
        }
    }
}

/// A covered step strictly decreases the measure.
proof fn covered_decreases(pre: State, post: State)
    requires
        inv(pre),
        wf_step(pre, post),
    ensures
        measure(post) < measure(pre),
{
    if exists|c: int| is_client(c) && #[trigger] fetch(pre, post, c) {
        let c = choose|c: int| is_client(c) && fetch(pre, post, c);
        let j = map_at(pre.cursor, c) + 1;
        assert(1 <= j <= 3);
        assert(j > map_at(pre.cursor, c));
        assert(!set_at(pre.pending, c).contains(j)) by {
            assert(pending_le_cursor(pre));
        }
        assert(!set_at(pre.applied, c).contains(j)) by {
            assert(applied_le_cursor(pre));
        }
        assert(idist(pre, c, j) == 3);
        assert(map_at(post.staged, c) == j);
        assert(post.pending =~= pre.pending);
        assert(post.applied =~= pre.applied);
        assert(set_at(post.pending, c) =~= set_at(pre.pending, c));
        assert(idist(post, c, j) == 2);
        assert forall|i: int| is_item(i) && i != j implies idist(post, c, i) == idist(pre, c, i) by {
            assert(map_at(post.staged, c) == j); assert(j != i);
        }
        assert(post.online =~= pre.online && post.crashes =~= pre.crashes);
        let d = if c == 1 { 2int } else { 1int };
        assert(post.staged =~= pre.staged.insert(c, j));
        assert forall|i: int| is_item(i) implies idist(post, d, i) == idist(pre, d, i) by {
            assert(map_at(post.staged, d) == map_at(pre.staged, d)) by {
                map_insert_at(pre.staged, c, j, d);
            }
            assert(set_at(post.pending, d) =~= set_at(pre.pending, d)) by {
                assert(post.pending =~= pre.pending);
            }
            assert(set_at(post.applied, d) =~= set_at(pre.applied, d));
        }
        assert(measure_c(post, d) == measure_c(pre, d)) by {
            assert(map_at(post.crashes, d) == map_at(pre.crashes, d)) by {
                map_insert_at(pre.crashes, c, map_at(pre.crashes, c), d);
            }
            assert(post.online.contains(d) == pre.online.contains(d));
        }
    } else if exists|c: int| is_client(c) && #[trigger] publish_fetch(pre, post, false, c) {
        let c = choose|c: int| is_client(c) && publish_fetch(pre, post, false, c);
        let i = map_at(pre.staged, c);
        assert(i != 0);
        assert(type_ok(pre));
        assert(1 <= i <= 3);
        assert(staged_is_next(pre));
        assert(i == map_at(pre.cursor, c) + 1);
        assert(!set_at(pre.pending, c).contains(i)) by {
            assert(pending_le_cursor(pre));
        }
        assert(!set_at(pre.applied, c).contains(i)) by {
            assert(applied_le_cursor(pre));
        }
        assert(idist(pre, c, i) == 2);
        assert(post.pending =~= pre.pending.insert(c, set_at(pre.pending, c).insert(i)));
        set_map_insert_at(pre.pending, c, set_at(pre.pending, c).insert(i), c);
        assert(set_at(post.pending, c) =~= set_at(pre.pending, c).insert(i));
        assert(idist(post, c, i) == 1);
        assert forall|j: int| is_item(j) && j != i implies idist(post, c, j) == idist(pre, c, j) by {
            assert(set_at(post.pending, c).contains(j) == set_at(pre.pending, c).contains(j));
            assert(set_at(post.applied, c).contains(j) == set_at(pre.applied, c).contains(j));
            assert(map_at(post.staged, c) == 0) by {
                map_insert_at(pre.staged, c, 0, c);
            }
        }
        let d = if c == 1 { 2int } else { 1int };
        assert forall|j: int| is_item(j) implies idist(post, d, j) == idist(pre, d, j) by {
            set_map_insert_at(pre.pending, c, set_at(pre.pending, c).insert(i), d);
            map_insert_at(pre.staged, c, 0, d);
        }
        assert(measure_c(post, d) == measure_c(pre, d)) by {
            map_insert_at(pre.crashes, c, map_at(pre.crashes, c), d);
            assert(post.online =~= pre.online);
        }
    } else if exists|c: int, m: int| is_client(c) && is_item(m) && #[trigger] apply(pre, post, c, m) {
        let cm = choose|c: int, m: int| is_client(c) && is_item(m) && apply(pre, post, c, m);
        let c = cm.0;
        let m = cm.1;
        assert(set_at(pre.pending, c).contains(m));
        assert(disjoint(pre));
        assert(!set_at(pre.applied, c).contains(m));
        assert(idist(pre, c, m) == 1);
        set_map_insert_at(pre.applied, c, set_at(pre.applied, c).insert(m), c);
        set_map_insert_at(pre.pending, c, set_at(pre.pending, c).remove(m), c);
        assert(set_at(post.applied, c) =~= set_at(pre.applied, c).insert(m));
        assert(idist(post, c, m) == 0);
        assert forall|j: int| is_item(j) && j != m implies idist(post, c, j) == idist(pre, c, j) by {
            assert(set_at(post.pending, c).contains(j) == set_at(pre.pending, c).contains(j));
            assert(set_at(post.applied, c).contains(j) == set_at(pre.applied, c).contains(j));
            assert(post.staged =~= pre.staged);
        }
        let d = if c == 1 { 2int } else { 1int };
        assert(measure_c(post, d) == measure_c(pre, d)) by {
            set_map_insert_at(pre.applied, c, set_at(pre.applied, c).insert(m), d);
            set_map_insert_at(pre.pending, c, set_at(pre.pending, c).remove(m), d);
            map_insert_at(pre.crashes, c, map_at(pre.crashes, c), d);
            assert(post.online =~= pre.online);
        }
    } else {
        let c = choose|c: int| is_client(c) && recover(pre, post, c);
        assert(!pre.online.contains(c));
        assert(post.online =~= pre.online.insert(c));
        assert forall|i: int| is_item(i) implies idist(post, c, i) == idist(pre, c, i) by {
            assert(post.staged =~= pre.staged && post.pending =~= pre.pending && post.applied =~= pre.applied);
            assert(set_at(post.pending, c) =~= set_at(pre.pending, c));
            assert(set_at(post.applied, c) =~= set_at(pre.applied, c));
            assert(map_at(post.staged, c) == map_at(pre.staged, c));
        }
        let d = if c == 1 { 2int } else { 1int };
        assert(measure_c(post, d) == measure_c(pre, d)) by {
            assert(post.online.contains(d) == pre.online.contains(d));
            assert(post.crashes =~= pre.crashes && post.staged =~= pre.staged
                && post.pending =~= pre.pending && post.applied =~= pre.applied);
        }
        assert(measure_c(post, c) == measure_c(pre, c) - 1);
    }
}

/// Every non-stuttering step of the safe configuration decreases the
/// measure — even Crash, which spends the crash budget (4) while adding
/// at most 2 back (offline bit plus un-staging one item).
proof fn real_step_decreases(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
        real_step(pre, post),
    ensures
        measure(post) < measure(pre),
{
    if exists|c: int| is_client(c) && #[trigger] crash(pre, post, false, c) {
        let c = choose|c: int| is_client(c) && crash(pre, post, false, c);
        assert(map_at(pre.crashes, c) < max_crashes());
        assert(map_at(post.crashes, c) == map_at(pre.crashes, c) + 1) by {
            map_insert_at(pre.crashes, c, map_at(pre.crashes, c) + 1, c);
        }
        assert(post.online =~= pre.online.remove(c));
        let i = map_at(pre.staged, c);
        assert(map_at(post.staged, c) == 0) by {
            map_insert_at(pre.staged, c, 0, c);
        }
        if i != 0 {
            assert(staged_is_next(pre));
            assert(i == map_at(pre.cursor, c) + 1);
            assert(!set_at(pre.pending, c).contains(i)) by {
                assert(pending_le_cursor(pre));
            }
            assert(!set_at(pre.applied, c).contains(i)) by {
                assert(applied_le_cursor(pre));
            }
            assert(idist(pre, c, i) == 2);
            assert(post.pending =~= pre.pending);
            assert(set_at(post.pending, c) =~= set_at(pre.pending, c));
            assert(idist(post, c, i) == 3);
        }
        assert forall|j: int| is_item(j) && j != i implies idist(post, c, j) == idist(pre, c, j) by {
            assert(set_at(post.pending, c).contains(j) == set_at(pre.pending, c).contains(j));
            assert(set_at(post.applied, c).contains(j) == set_at(pre.applied, c).contains(j));
        }
        let d = if c == 1 { 2int } else { 1int };
        assert(measure_c(post, d) == measure_c(pre, d)) by {
            map_insert_at(pre.crashes, c, map_at(pre.crashes, c) + 1, d);
            map_insert_at(pre.staged, c, 0, d);
            assert(post.online.contains(d) == pre.online.contains(d));
            assert(post.pending =~= pre.pending && post.applied =~= pre.applied);
        }
        assert(measure_c(post, c) <= measure_c(pre, c) - 2);
    } else if exists|c: int, m: int| is_client(c) && is_item(m) && #[trigger] replay(pre, post, false, c, m) {
        let cm = choose|c: int, m: int| is_client(c) && is_item(m) && replay(pre, post, false, c, m);
        assert(post.cursor =~= pre.cursor && post.pending =~= pre.pending
            && post.applied =~= pre.applied && post.staged =~= pre.staged
            && post.online =~= pre.online && post.crashes =~= pre.crashes
            && post.effects =~= pre.effects);
        assert(false);
    } else {
        assert(wf_step(pre, post)) by {
            assert(next_cfg(false, false, false, pre, post));
        }
        covered_decreases(pre, post);
    }
}

/// At every reachable non-goal state some covered action's guard holds.
/// Under weak fairness a fair behavior therefore cannot stall below the
/// goal: the covered action stays enabled until it fires.
proof fn covered_available(s: State)
    requires
        inv(s),
        !goal(s),
    ensures
        covered_enabled(s),
{
    if !s.online.contains(1) {
        assert(covered_guard(s, 1, 1));
        return;
    }
    if !s.online.contains(2) {
        assert(covered_guard(s, 2, 1));
        return;
    }
    // Both online. !goal gives a client whose applied set is short.
    let c = if set_at(s.applied, 1) =~= items() { 2int } else { 1int };
    if c == 2 {
        assert(set_at(s.applied, 1) =~= items());
        if set_at(s.applied, 2) =~= items() {
            assert(goal(s));
        }
    }
    assert(!(set_at(s.applied, c) =~= items()));
    assert(c == 1 || c == 2);
    assert(is_client(c));
    assert(set_at(s.applied, c).subset_of(items()));
    // some item is missing from applied[c]
    let i0 = if !set_at(s.applied, c).contains(1) {
        1int
    } else if !set_at(s.applied, c).contains(2) {
        2int
    } else {
        3int
    };
    assert(is_item(i0) && !set_at(s.applied, c).contains(i0)) by {
        if set_at(s.applied, c).contains(1) && set_at(s.applied, c).contains(2)
            && set_at(s.applied, c).contains(3) {
            assert forall|i: int| items().contains(i) implies set_at(s.applied, c).contains(i) by {
            }
            assert(set_at(s.applied, c) =~= items());
            assert(false);
        }
        assert(i0 == 1 || i0 == 2 || i0 == 3);
    }
    let p = set_at(s.pending, c);
    assert(is_client(c) && s.online.contains(c));
    if p.contains(2) {
        assert(ready(s, c, 2));
        assert(covered_guard(s, c, 2));
        return;
    }
    if p.contains(3) {
        assert(ready(s, c, 3));
        assert(covered_guard(s, c, 3));
        return;
    }
    if map_at(s.staged, c) != 0 {
        assert(covered_guard(s, c, 1));
        return;
    }
    if map_at(s.cursor, c) < 3 && p.len() < capacity() {
        assert(covered_guard(s, c, 1));
        return;
    }
    // Remaining: staged == 0, and (cursor == 3 or pending is full).
    assert(p.len() <= capacity());
    if p.len() >= 3 {
        // pending subset items with 3 members contains 2 (else it is a
        // subset of {1,3} with len <= 2), so Apply was enabled.
        let small = Set::empty().insert(1int).insert(3int);
        assert(p.subset_of(small)) by {
            assert(p.subset_of(items()));
            assert forall|x: int| p.contains(x) implies small.contains(x) by {
                assert(!p.contains(2));
            }
        }
        vstd::set_lib::lemma_len_subset(p, small);
        assert(small.len() == 2);
        assert(false);
    }
    // cursor must be 3 (cursor < 3 would have enabled Fetch since pending
    // is now known below capacity).
    assert(map_at(s.cursor, c) == 3) by {
        assert(0 <= map_at(s.cursor, c) <= 3);
        if map_at(s.cursor, c) < 3 {
            assert(p.len() < capacity());
            assert(false);
        }
    }
    assert(no_lost_work(s));
    // 1..3 subset pending union applied; the missing item is in pending.
    let i = i0;
    assert(p.contains(i)) by {
        assert(1 <= i <= 3);
    }
    if i == 1 {
        // 2 and 3 are applied (not in pending, which is a subset of {1});
        // so 1 is ready and Apply fires.
        assert(set_at(s.applied, c).contains(3)) by {
            if !set_at(s.applied, c).contains(3) {
                assert(p.contains(3));
                assert(false);
            }
        }
        assert(ready(s, c, 1));
    } else {
        assert(ready(s, c, i)) by {
            assert(i != 1);
        }
    }
    assert(is_client(c) && is_item(i) && s.online.contains(c) && set_at(s.pending, c).contains(i)
        && ready(s, c, i));
    assert(covered_guard(s, c, i));
}

/// Along any trace of distinct consecutive states the measure strictly
/// decreases — so a fair execution reaches the goal within
/// measure(init) = 28 real steps.
proof fn measure_decreases_along(t: Seq<State>)
    requires
        is_trace(t),
        forall|j: int| 0 <= j && j + 1 < t.len() ==> #[trigger] real_step(t[j], t[j + 1]),
    ensures
        forall|i: int| 0 <= i < t.len() ==> #[trigger] measure(t[i]) <= measure(t[0]) - i,
    decreases t.len(),
{
    trace_satisfies_inv(t);
    if t.len() > 1 {
        let prefix = t.drop_last();
        assert(is_trace(prefix)) by {
            assert forall|i: int| 0 <= i < prefix.len() - 1 implies #[trigger] next(
                prefix[i],
                prefix[i + 1],
            ) by {
                assert(prefix[i] == t[i]);
                assert(prefix[i + 1] == t[i + 1]);
            }
        }
        assert(forall|j: int| 0 <= j && j + 1 < prefix.len() ==> #[trigger] real_step(prefix[j], prefix[j + 1])) by {
            assert forall|j: int| 0 <= j && j + 1 < prefix.len() implies #[trigger] real_step(prefix[j], prefix[j + 1]) by {
                assert(prefix[j] == t[j]);
                assert(prefix[j + 1] == t[j + 1]);
            }
        }
        measure_decreases_along(prefix);
        let n = t.len() - 1;
        assert(is_trace(t));
        assert(0 <= n - 1 && n - 1 + 1 < t.len());
        assert(next(t[n - 1], t[n]));
        assert(real_step(t[n - 1], t[n]));
        assert(inv(t[n - 1]));
        assert(measure(prefix[n - 1]) <= measure(prefix[0]) - (n - 1));
        assert(prefix[n - 1] == t[n - 1] && prefix[0] == t[0]);
        real_step_decreases(t[n - 1], t[n]);
        assert(measure(t[n]) <= measure(t[0]) - n);
        assert forall|i: int| 0 <= i < t.len() implies #[trigger] measure(t[i]) <= measure(t[0]) - i by {
            if i == n {
            } else {
                assert(prefix[i] == t[i]);
                assert(measure(prefix[i]) <= measure(prefix[0]) - i);
            }
        }
    } else {
    }
}

/// Termination: an all-real trace (no stuttering steps) reaches the goal
/// by index measure(t[0]). In TLA+ terms the same holds for every fair
/// behavior: a non-goal state has a covered action enabled, which weak
/// fairness eventually fires, and covered steps strictly decrease the
/// bounded measure.
proof fn eventually_resolved(t: Seq<State>)
    requires
        is_trace(t),
        t.len() > measure(t[0]),
        forall|j: int| 0 <= j && j + 1 < t.len() ==> #[trigger] real_step(t[j], t[j + 1]),
    ensures
        goal(t[measure(t[0])]),
{
    measure_decreases_along(t);
    let i = measure(t[0]);
    trace_satisfies_inv(t);
    assert(measure(t[i]) <= 0);
    assert(inv(t[i]));
    measure_nonneg(t[i]);
    assert(measure(t[i]) == 0);
    measure_zero_is_goal(t[i]);
}

}
