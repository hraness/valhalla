//! Verus pilot (4th model): inductive proof of RoomsHeldReply's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs` and
//! `verify/private-publication/publication.rs`: `RoomsHeldReply.tla` under
//! `normal.cfg` (all five mutant switches false) is re-stated as a Verus
//! transition system and the six safety invariants TLC checks there —
//! `TypeOK`, `ReplyCustody`, `DurableBeforeReply`, `TombstonesStayLocal`,
//! `MetadataBound` and `AdmittedBeforeReply` — are proved inductive, with the
//! auxiliary invariants the inductive step needs. Four mutants are proved to
//! reach the violations TLC recorded for them: `mutant-drop` breaks
//! `ReplyCustody`, `mutant-early` breaks `DurableBeforeReply`,
//! `mutant-tombstone` breaks `TombstonesStayLocal` and `mutant-unadmitted`
//! breaks `AdmittedBeforeReply`. `mutant-deadline` violates the *temporal*
//! property `AllRequestsAnswered`, which is outside the safety scope of this
//! proof; `mutant_deadline_violates` instead shows that the recorded
//! counterexample's finite prefix is reachable and that deadline resolution
//! and reply are both disabled in its final state — the safety content of
//! the stuttering violation. The conditional liveness claim itself is not
//! re-proved. A completion witness runs request 1 through arrival, live
//! selection, admission, reply and publication, then request 2 through the
//! full-budget tombstone fallback.
//!
//! Encoding notes:
//!   * RequestCount = 2 and MetadataCapacity = 1 as in every cfg file.
//!   * `phase` and `kind` strings become int constants
//!     (idle/held/selected/prepared/publishing/lost, none/live/tombstone).
//!   * `replyKind` in `[Requests -> Kinds]` becomes `Map<int, int>` read
//!     through `map_at` (0 = "none" off-domain; the model only reads
//!     Requests). `EXCEPT ![r] = k` is `insert(r, k)`.
//!   * `Cardinality(seen) <= MetadataCapacity` becomes `seen.len() <= 1`.
//!   * `Next` has no existential: all seven actions are parameter-free, so
//!     `step_inv` needs no `choose` for witnesses.
//!   * TLA stuttering (`[Next]_vars`) is not modeled: Verus traces step only
//!     on `Next`. Stuttering preserves every safety invariant, and the
//!     deadline counterexample's stuttering loop is represented by its
//!     reachable final state with resolution disabled.
//!
//! Verify with:
//!   verus --crate-type=lib verify/rooms-held-reply/held.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Requests == 1..RequestCount for RequestCount = 2.
pub open spec fn request_count() -> int {
    2
}

/// MetadataCapacity = 1.
pub open spec fn metadata_cap() -> int {
    1
}

pub open spec fn requests() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

pub open spec fn is_request(r: int) -> bool {
    requests().contains(r)
}

/// Phases == {"idle","held","selected","prepared","publishing","lost"}.
pub open spec fn ph_idle() -> int {
    0
}

pub open spec fn ph_held() -> int {
    1
}

pub open spec fn ph_selected() -> int {
    2
}

pub open spec fn ph_prepared() -> int {
    3
}

pub open spec fn ph_publishing() -> int {
    4
}

pub open spec fn ph_lost() -> int {
    5
}

/// Kinds == {"none","live","tombstone"}.
pub open spec fn k_none() -> int {
    0
}

pub open spec fn k_live() -> int {
    1
}

pub open spec fn k_tombstone() -> int {
    2
}

/// Total map read at int keys (0 == "none" off-domain; the model only reads
/// Requests, which are always in-domain).
pub open spec fn map_at(m: Map<int, int>, r: int) -> int {
    if m.dom().contains(r) {
        m[r]
    } else {
        0
    }
}

/// VARIABLES current, phase, arrived, expired, issued, seen, admitted, kind,
/// replied, replyKind, published.
pub struct State {
    pub current: int,
    pub phase: int,
    pub arrived: bool,
    pub expired: bool,
    pub issued: Set<int>,
    pub seen: Set<int>,
    pub admitted: Set<int>,
    pub kind: int,
    pub replied: Set<int>,
    pub reply_kind: Map<int, int>,
    pub published: Set<int>,
}

/// replyKind = [r \in Requests |-> "none"].
pub open spec fn rk0() -> Map<int, int> {
    Map::new(requests(), |r: int| k_none())
}

pub open spec fn init(s: State) -> bool {
    &&& s.current == 0
    &&& s.phase == ph_idle()
    &&& !s.arrived
    &&& !s.expired
    &&& s.issued =~= Set::empty()
    &&& s.seen =~= Set::empty()
    &&& s.admitted =~= Set::empty()
    &&& s.kind == k_none()
    &&& s.replied =~= Set::empty()
    &&& s.reply_kind =~= rk0()
    &&& s.published =~= Set::empty()
}

/// Request == /\ phase = "idle" /\ current < RequestCount
///            /\ current' = current + 1 /\ issued' = issued \cup {current + 1}
///            /\ phase' = IF DropEmpty /\ ~arrived THEN "lost" ELSE "held"
///            /\ expired' = FALSE /\ kind' = "none"
///            /\ UNCHANGED <<arrived, seen, admitted, replied, replyKind,
///                           published>>
pub open spec fn request(drop_empty: bool, pre: State, post: State) -> bool {
    &&& pre.phase == ph_idle()
    &&& pre.current < request_count()
    &&& post.current == pre.current + 1
    &&& post.issued =~= pre.issued.insert(pre.current + 1)
    &&& post.phase == if drop_empty && !pre.arrived {
        ph_lost()
    } else {
        ph_held()
    }
    &&& !post.expired
    &&& post.kind == k_none()
    &&& post.arrived == pre.arrived
    &&& post.seen =~= pre.seen
    &&& post.admitted =~= pre.admitted
    &&& post.replied =~= pre.replied
    &&& post.reply_kind =~= pre.reply_kind
    &&& post.published =~= pre.published
}

/// Arrival == /\ ~arrived /\ arrived' = TRUE /\ others unchanged.
pub open spec fn arrival(pre: State, post: State) -> bool {
    &&& !pre.arrived
    &&& post.arrived
    &&& post.current == pre.current
    &&& post.phase == pre.phase
    &&& post.expired == pre.expired
    &&& post.issued =~= pre.issued
    &&& post.seen =~= pre.seen
    &&& post.admitted =~= pre.admitted
    &&& post.kind == pre.kind
    &&& post.replied =~= pre.replied
    &&& post.reply_kind =~= pre.reply_kind
    &&& post.published =~= pre.published
}

/// Expire == /\ phase = "held" /\ ~expired /\ expired' = TRUE.
pub open spec fn expire(pre: State, post: State) -> bool {
    &&& pre.phase == ph_held()
    &&& !pre.expired
    &&& post.expired
    &&& post.current == pre.current
    &&& post.phase == pre.phase
    &&& post.arrived == pre.arrived
    &&& post.issued =~= pre.issued
    &&& post.seen =~= pre.seen
    &&& post.admitted =~= pre.admitted
    &&& post.kind == pre.kind
    &&& post.replied =~= pre.replied
    &&& post.reply_kind =~= pre.reply_kind
    &&& post.published =~= pre.published
}

/// Resolve == /\ phase = "held" /\ (arrived \/ (expired /\ ~ForgetDeadline))
///            /\ kind' = IF arrived THEN "live" ELSE "tombstone"
///            /\ phase' = "selected" /\ others unchanged.
pub open spec fn resolve(forget_deadline: bool, pre: State, post: State) -> bool {
    &&& pre.phase == ph_held()
    &&& (pre.arrived || (pre.expired && !forget_deadline))
    &&& post.kind == if pre.arrived {
        k_live()
    } else {
        k_tombstone()
    }
    &&& post.phase == ph_selected()
    &&& post.current == pre.current
    &&& post.arrived == pre.arrived
    &&& post.expired == pre.expired
    &&& post.issued =~= pre.issued
    &&& post.seen =~= pre.seen
    &&& post.admitted =~= pre.admitted
    &&& post.replied =~= pre.replied
    &&& post.reply_kind =~= pre.reply_kind
    &&& post.published =~= pre.published
}

/// Prepare == /\ phase = "selected"
///            /\ LET admit == kind = "live" /\ |seen| < MetadataCapacity
///               IN /\ seen' = IF admit THEN seen \cup {current} ELSE seen
///                  /\ admitted' = IF admit /\ ~ForgetAdmission
///                                 THEN admitted \cup {current} ELSE admitted
///                  /\ kind' = IF kind = "live" /\ ~admit
///                             THEN "tombstone" ELSE kind
///            /\ phase' = "prepared" /\ others unchanged.
pub open spec fn prepare(forget_admission: bool, pre: State, post: State) -> bool {
    &&& pre.phase == ph_selected()
    &&& post.seen =~= if pre.kind == k_live() && pre.seen.len() < metadata_cap() {
        pre.seen.insert(pre.current)
    } else {
        pre.seen
    }
    &&& post.admitted =~= if pre.kind == k_live() && pre.seen.len() < metadata_cap()
        && !forget_admission {
        pre.admitted.insert(pre.current)
    } else {
        pre.admitted
    }
    &&& post.kind == if pre.kind == k_live() && !(pre.seen.len() < metadata_cap()) {
        k_tombstone()
    } else {
        pre.kind
    }
    &&& post.phase == ph_prepared()
    &&& post.current == pre.current
    &&& post.arrived == pre.arrived
    &&& post.expired == pre.expired
    &&& post.issued =~= pre.issued
    &&& post.replied =~= pre.replied
    &&& post.reply_kind =~= pre.reply_kind
    &&& post.published =~= pre.published
}

/// Reply == /\ (phase = "prepared"
///              \/ (EarlyLiveReply /\ phase = "selected" /\ kind = "live"))
///          /\ replied' = replied \cup {current}
///          /\ replyKind' = [replyKind EXCEPT ![current] = kind]
///          /\ phase' = IF kind = "live" \/ PublishTombstone
///                       THEN "publishing" ELSE "idle"
///          /\ others unchanged.
pub open spec fn reply(early_live: bool, publish_tombstone: bool, pre: State, post: State) -> bool {
    &&& (pre.phase == ph_prepared() || (early_live && pre.phase == ph_selected()
        && pre.kind == k_live()))
    &&& post.replied =~= pre.replied.insert(pre.current)
    &&& post.reply_kind =~= pre.reply_kind.insert(pre.current, pre.kind)
    &&& post.phase == if pre.kind == k_live() || publish_tombstone {
        ph_publishing()
    } else {
        ph_idle()
    }
    &&& post.current == pre.current
    &&& post.arrived == pre.arrived
    &&& post.expired == pre.expired
    &&& post.issued =~= pre.issued
    &&& post.seen =~= pre.seen
    &&& post.admitted =~= pre.admitted
    &&& post.kind == pre.kind
    &&& post.published =~= pre.published
}

/// Publish == /\ phase = "publishing" /\ published' = published \cup {current}
///            /\ phase' = "idle" /\ others unchanged.
pub open spec fn publish(pre: State, post: State) -> bool {
    &&& pre.phase == ph_publishing()
    &&& post.published =~= pre.published.insert(pre.current)
    &&& post.phase == ph_idle()
    &&& post.current == pre.current
    &&& post.arrived == pre.arrived
    &&& post.expired == pre.expired
    &&& post.issued =~= pre.issued
    &&& post.seen =~= pre.seen
    &&& post.admitted =~= pre.admitted
    &&& post.kind == pre.kind
    &&& post.replied =~= pre.replied
    &&& post.reply_kind =~= pre.reply_kind
}

/// Next under arbitrary config constants (DropEmpty, EarlyLiveReply,
/// PublishTombstone, ForgetDeadline, ForgetAdmission).
pub open spec fn next_cfg(
    drop_empty: bool,
    early_live: bool,
    publish_tombstone: bool,
    forget_deadline: bool,
    forget_admission: bool,
    pre: State,
    post: State,
) -> bool {
    ||| request(drop_empty, pre, post)
    ||| arrival(pre, post)
    ||| expire(pre, post)
    ||| resolve(forget_deadline, pre, post)
    ||| prepare(forget_admission, pre, post)
    ||| reply(early_live, publish_tombstone, pre, post)
    ||| publish(pre, post)
}

/// normal.cfg: all five mutant switches false.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, pre, post)
}

pub open spec fn next_mutant_drop(pre: State, post: State) -> bool {
    next_cfg(true, false, false, false, false, pre, post)
}

pub open spec fn next_mutant_early(pre: State, post: State) -> bool {
    next_cfg(false, true, false, false, false, pre, post)
}

pub open spec fn next_mutant_tombstone(pre: State, post: State) -> bool {
    next_cfg(false, false, true, false, false, pre, post)
}

pub open spec fn next_mutant_deadline(pre: State, post: State) -> bool {
    next_cfg(false, false, false, true, false, pre, post)
}

pub open spec fn next_mutant_unadmitted(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, true, pre, post)
}

/// OwnedReply == IF phase \in {"held","selected","prepared"} THEN {current}
///               ELSE {}.
pub open spec fn owned_reply(s: State) -> Set<int> {
    if s.phase == ph_held() || s.phase == ph_selected() || s.phase == ph_prepared() {
        Set::empty().insert(s.current)
    } else {
        Set::empty()
    }
}

/// TypeOK.
pub open spec fn type_ok(s: State) -> bool {
    &&& 0 <= s.current <= request_count()
    &&& 0 <= s.phase <= ph_lost()
    &&& s.issued.subset_of(requests())
    &&& s.seen.subset_of(s.issued)
    &&& s.admitted.subset_of(s.seen)
    &&& 0 <= s.kind <= k_tombstone()
    &&& s.replied.subset_of(s.issued)
    &&& s.reply_kind.dom() =~= requests()
    &&& forall|r: int| is_request(r) ==> 0 <= map_at(s.reply_kind, r) <= k_tombstone()
    &&& s.published.subset_of(s.replied)
}

/// ReplyCustody == issued = replied \cup OwnedReply, disjointly.
pub open spec fn reply_custody(s: State) -> bool {
    &&& s.issued =~= s.replied.union(owned_reply(s))
    &&& s.replied.intersect(owned_reply(s)) =~= Set::empty()
}

/// DurableBeforeReply == \A r \in replied : replyKind[r] = "live" =>
/// (arrived /\ r \in seen).
pub open spec fn durable_before_reply(s: State) -> bool {
    forall|r: int| s.replied.contains(r) && map_at(s.reply_kind, r) == k_live()
        ==> (s.arrived && s.seen.contains(r))
}

/// AdmittedBeforeReply == \A r \in replied : replyKind[r] = "live" =>
/// r \in admitted.
pub open spec fn admitted_before_reply(s: State) -> bool {
    forall|r: int| s.replied.contains(r) && map_at(s.reply_kind, r) == k_live()
        ==> s.admitted.contains(r)
}

/// TombstonesStayLocal == \A r \in published : replyKind[r] = "live".
pub open spec fn tombstones_stay_local(s: State) -> bool {
    forall|r: int| s.published.contains(r) ==> map_at(s.reply_kind, r) == k_live()
}

/// MetadataBound == Cardinality(seen) <= MetadataCapacity.
pub open spec fn metadata_bound(s: State) -> bool {
    s.seen.len() <= metadata_cap()
}

/// Auxiliary: issued is exactly the frontier 1..=current. This makes
/// issued \subseteq Requests, current \in issued for owned phases, and
/// current + 1 \notin replied at Request time all immediate.
pub open spec fn issued_frontier(s: State) -> bool {
    forall|r: int| s.issued.contains(r) <==> (1 <= r <= s.current)
}

/// Auxiliary: every non-idle phase carries a real request number — only
/// Request leaves idle, and it raises current first.
pub open spec fn active_current(s: State) -> bool {
    s.phase != ph_idle() ==> 1 <= s.current
}

/// Auxiliary: kind = "live" is only produced by Resolve on the arrived
/// branch, and arrived never resets.
pub open spec fn live_arrived(s: State) -> bool {
    s.kind == k_live() ==> s.arrived
}

/// Auxiliary: a live kind that survives Prepare into prepared/publishing was
/// admitted: its request is in seen and admitted. This is what a live reply
/// needs for DurableBeforeReply and AdmittedBeforeReply.
pub open spec fn live_ready(s: State) -> bool {
    s.kind == k_live() && (s.phase == ph_prepared() || s.phase == ph_publishing())
        ==> (s.seen.contains(s.current) && s.admitted.contains(s.current))
}

/// Auxiliary: a publishing phase has already replied with a live kind for
/// the current request — Publish can then safely add it to published.
pub open spec fn publishing_replied(s: State) -> bool {
    s.phase == ph_publishing() ==> (s.replied.contains(s.current) && map_at(
        s.reply_kind,
        s.current,
    ) == k_live())
}

/// The inductive invariant: the six checked invariants plus five
/// auxiliaries.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& reply_custody(s)
    &&& durable_before_reply(s)
    &&& admitted_before_reply(s)
    &&& tombstones_stay_local(s)
    &&& metadata_bound(s)
    &&& issued_frontier(s)
    &&& active_current(s)
    &&& live_arrived(s)
    &&& live_ready(s)
    &&& publishing_replied(s)
}

/// Map insert propagation used everywhere below.
proof fn map_insert_at(m: Map<int, int>, k: int, v: int, x: int)
    ensures
        map_at(m.insert(k, v), x) == if x == k {
            v
        } else {
            map_at(m, x)
        },
{
}

/// len() == 0 means empty (subset-length argument).
proof fn len0_empty(s: Set<int>)
    requires
        s.len() == 0,
    ensures
        s =~= Set::empty(),
{
    if !s.is_empty() {
        let x = choose|x: int| s.contains(x);
        assert(Set::empty().insert(x).subset_of(s));
        vstd::set_lib::lemma_len_subset(Set::empty().insert(x), s);
        assert(Set::empty().insert(x).len() == 1);
    }
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
    assert(s.reply_kind.dom() =~= requests());
    assert forall|r: int| is_request(r) implies 0 <= map_at(s.reply_kind, r) <= k_tombstone() by {
        assert(s.reply_kind.dom().contains(r));
    }
    assert forall|r: int| s.issued.contains(r) == (1 <= r <= s.current) by {
        assert(!(1 <= r <= s.current));
    }
    assert(s.seen.len() == 0);
    assert(owned_reply(s) =~= Set::empty());
    assert(type_ok(s));
    assert(reply_custody(s));
    assert(durable_before_reply(s));
    assert(admitted_before_reply(s));
    assert(tombstones_stay_local(s));
    assert(metadata_bound(s));
    assert(issued_frontier(s));
    assert(active_current(s));
    assert(live_arrived(s));
    assert(live_ready(s));
    assert(publishing_replied(s));
}

proof fn request_preserves(pre: State, post: State)
    requires
        inv(pre),
        request(false, pre, post),
    ensures
        inv(post),
{
    let c = post.current;
    assert(c == pre.current + 1 && 1 <= c <= request_count());
    // owned(pre) = {} since pre.phase == idle, so issued = replied.
    assert(owned_reply(pre) =~= Set::empty());
    assert(pre.issued =~= pre.replied);
    // issued_frontier: the frontier gains exactly c.
    assert forall|r: int| post.issued.contains(r) == (1 <= r <= c) by {
        if post.issued.contains(r) {
            if r == c {
            } else {
                assert(pre.issued.contains(r));
            }
        } else {
            if 1 <= r <= c {
                if r == c {
                    assert(post.issued.contains(r));
                } else {
                    assert(1 <= r <= pre.current);
                    assert(pre.issued.contains(r));
                    assert(post.issued.contains(r));
                }
            }
        }
    }
    // custody: owned(post) = {c} (phase held under the safe switch).
    assert(post.phase == ph_held());
    assert(owned_reply(post) =~= Set::empty().insert(c));
    assert(post.issued =~= post.replied.union(owned_reply(post))) by {
        assert forall|x: int| post.issued.contains(x) implies post.replied.union(
            owned_reply(post),
        ).contains(x) by {
            if x == c {
            } else {
                assert(pre.issued.contains(x));
                assert(pre.replied.contains(x));
            }
        }
        assert forall|x: int| post.replied.union(owned_reply(post)).contains(x)
            implies post.issued.contains(x) by {
            if post.replied.contains(x) {
                assert(pre.replied.contains(x));
                assert(pre.issued.contains(x));
            } else {
                assert(x == c);
            }
        }
    }
    assert(post.replied.intersect(owned_reply(post)) =~= Set::empty()) by {
        assert forall|x: int| !(post.replied.contains(x) && owned_reply(post).contains(x)) by {
            if post.replied.contains(x) && owned_reply(post).contains(x) {
                assert(x == c);
                assert(pre.replied.contains(x));
                assert(pre.issued.contains(x));
                assert(1 <= x <= pre.current);
            }
        }
    }
    // issued ⊆ requests.
    assert forall|x: int| post.issued.contains(x) implies requests().contains(x) by {
        assert(1 <= x <= c);
        assert(x == 1 || x == 2);
    }
    assert forall|x: int| post.replied.contains(x) implies post.issued.contains(x) by {
        assert(pre.replied.contains(x));
        assert(pre.issued.contains(x));
    }
    assert(type_ok(post));
    assert(reply_custody(post));
    assert(durable_before_reply(post));
    assert(admitted_before_reply(post));
    assert(tombstones_stay_local(post));
    assert(metadata_bound(post));
    assert(issued_frontier(post));
    assert(active_current(post));
    assert(live_arrived(post));
    assert(live_ready(post));
    assert(publishing_replied(post));
}

proof fn arrival_preserves(pre: State, post: State)
    requires
        inv(pre),
        arrival(pre, post),
    ensures
        inv(post),
{
    // Nothing but arrived changed; a live kind was impossible before arrival.
    assert(post.kind != k_live());
    assert(type_ok(post));
    assert(reply_custody(post));
    assert(durable_before_reply(post));
    assert(admitted_before_reply(post));
    assert(tombstones_stay_local(post));
    assert(metadata_bound(post));
    assert(issued_frontier(post));
    assert(active_current(post));
    assert(live_arrived(post));
    assert(live_ready(post));
    assert(publishing_replied(post));
}

proof fn expire_preserves(pre: State, post: State)
    requires
        inv(pre),
        expire(pre, post),
    ensures
        inv(post),
{
    // Only expired changed; owned stays {current} (held -> held).
    assert(type_ok(post));
    assert(reply_custody(post));
    assert(durable_before_reply(post));
    assert(admitted_before_reply(post));
    assert(tombstones_stay_local(post));
    assert(metadata_bound(post));
    assert(issued_frontier(post));
    assert(active_current(post));
    assert(live_arrived(post));
    assert(live_ready(post));
    assert(publishing_replied(post));
}

proof fn resolve_preserves(pre: State, post: State)
    requires
        inv(pre),
        resolve(false, pre, post),
    ensures
        inv(post),
{
    // owned stays {current} (held -> selected). live_arrived: a live kind
    // came from the arrived branch.
    assert(owned_reply(pre) =~= owned_reply(post));
    assert(type_ok(post));
    assert(reply_custody(post));
    assert(durable_before_reply(post));
    assert(admitted_before_reply(post));
    assert(tombstones_stay_local(post));
    assert(metadata_bound(post));
    assert(issued_frontier(post));
    assert(active_current(post));
    assert(live_arrived(post));
    assert(live_ready(post));
    assert(publishing_replied(post));
}

proof fn prepare_preserves(pre: State, post: State)
    requires
        inv(pre),
        prepare(false, pre, post),
    ensures
        inv(post),
{
    let admit = pre.kind == k_live() && pre.seen.len() < metadata_cap();
    // current \in issued: phase is selected so current >= 1.
    assert(1 <= pre.current <= request_count());
    assert(pre.issued.contains(pre.current));
    // MetadataBound + subsets for the admit branch.
    if admit {
        assert(pre.seen.len() == 0);
        len0_empty(pre.seen);
        assert(post.seen =~= Set::empty().insert(pre.current));
        assert(post.seen.len() == 1);
        assert(post.admitted =~= pre.admitted.insert(pre.current));
    }
    assert forall|x: int| post.seen.contains(x) implies post.issued.contains(x) by {
        if admit && x == pre.current {
        } else {
            if admit {
                assert(pre.seen.contains(x));
            } else {
                assert(pre.seen.contains(x));
            }
            assert(pre.issued.contains(x));
        }
    }
    assert forall|x: int| post.admitted.contains(x) implies post.seen.contains(x) by {
        if x == pre.current && admit {
        } else {
            assert(pre.admitted.contains(x));
            assert(pre.seen.contains(x));
        }
    }
    // live_ready: a live kind at prepared means admit held, so current was
    // inserted into both seen and admitted.
    if post.kind == k_live() && post.phase == ph_prepared() {
        assert(pre.kind == k_live() && admit);
        assert(post.seen.contains(pre.current));
        assert(post.admitted.contains(pre.current));
    }
    // live_arrived: a surviving live kind was live before, hence arrived.
    if post.kind == k_live() {
        assert(pre.kind == k_live());
        assert(pre.arrived);
    }
    assert(owned_reply(pre) =~= owned_reply(post));
    assert(type_ok(post));
    assert(reply_custody(post));
    assert(durable_before_reply(post));
    assert(admitted_before_reply(post));
    assert(tombstones_stay_local(post));
    assert(metadata_bound(post));
    assert(issued_frontier(post));
    assert(active_current(post));
    assert(live_ready(post));
    assert(publishing_replied(post));
}

proof fn reply_preserves(pre: State, post: State)
    requires
        inv(pre),
        reply(false, false, pre, post),
    ensures
        inv(post),
{
    // Safe switch values force phase = prepared.
    assert(pre.phase == ph_prepared());
    assert(1 <= pre.current <= request_count());
    assert(pre.issued.contains(pre.current));
    // current \in owned(pre) and disjoint from replied.
    assert(owned_reply(pre) =~= Set::empty().insert(pre.current));
    assert(!pre.replied.contains(pre.current)) by {
        if pre.replied.contains(pre.current) {
            assert(pre.replied.intersect(owned_reply(pre)).contains(pre.current));
        }
    }
    assert(pre.issued =~= pre.replied.insert(pre.current));
    // owned(post) = {} since post.phase is publishing or idle.
    assert(owned_reply(post) =~= Set::empty());
    assert(post.issued =~= post.replied);
    assert(post.issued =~= post.replied.union(owned_reply(post)));
    // The new reply's kind record.
    map_insert_at(pre.reply_kind, pre.current, pre.kind, pre.current);
    assert(map_at(post.reply_kind, pre.current) == pre.kind);
    // Durable/admitted obligations for the new reply when it is live.
    if pre.kind == k_live() {
        assert(live_ready(pre) && live_arrived(pre));
        assert(pre.arrived && pre.seen.contains(pre.current) && pre.admitted.contains(pre.current));
    }
    assert forall|x: int| post.replied.contains(x) && map_at(post.reply_kind, x) == k_live()
        implies post.arrived && post.seen.contains(x) by {
        if x == pre.current {
        } else {
            map_insert_at(pre.reply_kind, pre.current, pre.kind, x);
            assert(pre.replied.contains(x));
            assert(map_at(pre.reply_kind, x) == k_live());
        }
    }
    assert forall|x: int| post.replied.contains(x) && map_at(post.reply_kind, x) == k_live()
        implies post.admitted.contains(x) by {
        if x == pre.current {
        } else {
            map_insert_at(pre.reply_kind, pre.current, pre.kind, x);
            assert(pre.replied.contains(x));
            assert(map_at(pre.reply_kind, x) == k_live());
        }
    }
    // TypeOK: replied ⊆ issued gains current (in issued); the replyKind
    // domain is unchanged since current is a request.
    assert forall|x: int| post.replied.contains(x) implies post.issued.contains(x) by {
        if x == pre.current {
        } else {
            assert(pre.replied.contains(x));
            assert(pre.issued.contains(x));
        }
    }
    assert(post.reply_kind.dom() =~= requests());
    assert forall|x: int| is_request(x) implies 0 <= map_at(post.reply_kind, x)
        <= k_tombstone() by {
        map_insert_at(pre.reply_kind, pre.current, pre.kind, x);
        if x == pre.current {
            assert(0 <= pre.kind <= k_tombstone());
        } else {
            assert(0 <= map_at(pre.reply_kind, x) <= k_tombstone());
        }
    }
    // TombstonesStayLocal: published members were replied before, so none is
    // the newly recorded current; their kinds are unchanged.
    assert forall|x: int| post.published.contains(x) implies map_at(post.reply_kind, x)
        == k_live() by {
        assert(pre.published.contains(x));
        assert(pre.replied.contains(x));
        assert(x != pre.current);
        map_insert_at(pre.reply_kind, pre.current, pre.kind, x);
        assert(map_at(pre.reply_kind, x) == k_live());
    }
    // live_ready at post: publishing with a live kind inherits the prepared
    // obligation.
    if post.kind == k_live() && post.phase == ph_publishing() {
        assert(pre.seen.contains(pre.current) && pre.admitted.contains(pre.current));
    }
    // publishing_replied at post.
    if post.phase == ph_publishing() {
        assert(pre.kind == k_live());
        assert(post.replied.contains(pre.current));
        assert(map_at(post.reply_kind, post.current) == k_live());
    }
    assert(type_ok(post));
    assert(reply_custody(post));
    assert(durable_before_reply(post));
    assert(admitted_before_reply(post));
    assert(tombstones_stay_local(post));
    assert(metadata_bound(post));
    assert(issued_frontier(post));
    assert(active_current(post));
    assert(live_arrived(post));
    assert(live_ready(post));
    assert(publishing_replied(post));
}

proof fn publish_preserves(pre: State, post: State)
    requires
        inv(pre),
        publish(pre, post),
    ensures
        inv(post),
{
    // publishing_replied: the published request is replied and live.
    assert(pre.replied.contains(pre.current));
    assert(map_at(pre.reply_kind, pre.current) == k_live());
    assert(owned_reply(post) =~= Set::empty());
    assert forall|x: int| post.published.contains(x) implies map_at(post.reply_kind, x)
        == k_live() by {
        if x == pre.current {
        } else {
            assert(pre.published.contains(x));
        }
    }
    assert forall|x: int| post.published.contains(x) implies post.replied.contains(x) by {
        if x == pre.current {
        } else {
            assert(pre.published.contains(x));
            assert(pre.replied.contains(x));
        }
    }
    assert(type_ok(post));
    assert(reply_custody(post));
    assert(durable_before_reply(post));
    assert(admitted_before_reply(post));
    assert(tombstones_stay_local(post));
    assert(metadata_bound(post));
    assert(issued_frontier(post));
    assert(active_current(post));
    assert(live_arrived(post));
    assert(live_ready(post));
    assert(publishing_replied(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if request(false, pre, post) {
        request_preserves(pre, post);
    } else if arrival(pre, post) {
        arrival_preserves(pre, post);
    } else if expire(pre, post) {
        expire_preserves(pre, post);
    } else if resolve(false, pre, post) {
        resolve_preserves(pre, post);
    } else if prepare(false, pre, post) {
        prepare_preserves(pre, post);
    } else if reply(false, false, pre, post) {
        reply_preserves(pre, post);
    } else {
        assert(publish(pre, post));
        publish_preserves(pre, post);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_drop_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_drop(t[i], t[i + 1])
}

pub open spec fn is_early_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_early(t[i], t[i + 1])
}

pub open spec fn is_tombstone_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_tombstone(t[i], t[i + 1])
}

pub open spec fn is_deadline_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_deadline(t[i], t[i + 1])
}

pub open spec fn is_unadmitted_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_unadmitted(t[i], t[i + 1])
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
    current: int,
    phase: int,
    arrived: bool,
    expired: bool,
    issued: Set<int>,
    seen: Set<int>,
    admitted: Set<int>,
    kind: int,
    replied: Set<int>,
    reply_kind: Map<int, int>,
    published: Set<int>,
) -> State {
    State {
        current,
        phase,
        arrived,
        expired,
        issued,
        seen,
        admitted,
        kind,
        replied,
        reply_kind,
        published,
    }
}

/// mutant-drop: Request with DropEmpty on an empty queue moves to "lost"
/// while the issued request was never replied — issued = {1} but replied
/// and OwnedReply are both empty.
proof fn mutant_drop_violates()
    ensures
        exists|t: Seq<State>| is_drop_trace(t) && !reply_custody(t.last()),
{
    let e = Set::empty();
    let s0 = st(0, ph_idle(), false, false, e, e, e, k_none(), e, rk0(), e);
    let s1 = st(1, ph_lost(), false, false, e.insert(1), e, e, k_none(), e, rk0(), e);
    assert(init(s0));
    assert(next_mutant_drop(s0, s1)) by { assert(request(true, s0, s1)); }
    assert(!reply_custody(s1)) by {
        assert(owned_reply(s1) =~= Set::empty());
        assert(!s1.replied.union(owned_reply(s1)).contains(1));
        assert(s1.issued.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1);
    assert(is_drop_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_drop(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0);
            assert(t[i + 1] == s1);
        }
    }
    assert(t.last() == s1);
    assert(is_drop_trace(t) && !reply_custody(t.last()));
}

/// mutant-early: Request -> Arrival -> Resolve -> Reply with EarlyLiveReply
/// replies "live" while the request's metadata was never prepared —
/// 1 \in replied with replyKind[1] = "live" but 1 \notin seen.
proof fn mutant_early_violates()
    ensures
        exists|t: Seq<State>| is_early_trace(t) && !durable_before_reply(t.last()),
{
    let e = Set::empty();
    let e1 = e.insert(1);
    let rkl = rk0().insert(1, k_live());
    let s0 = st(0, ph_idle(), false, false, e, e, e, k_none(), e, rk0(), e);
    let s1 = st(1, ph_held(), false, false, e1, e, e, k_none(), e, rk0(), e);
    let s2 = st(1, ph_held(), true, false, e1, e, e, k_none(), e, rk0(), e);
    let s3 = st(1, ph_selected(), true, false, e1, e, e, k_live(), e, rk0(), e);
    let s4 = st(1, ph_publishing(), true, false, e1, e, e, k_live(), e1, rkl, e);
    assert(init(s0));
    assert(next_mutant_early(s0, s1)) by { assert(request(false, s0, s1)); }
    assert(next_mutant_early(s1, s2)) by { assert(arrival(s1, s2)); }
    assert(next_mutant_early(s2, s3)) by { assert(resolve(false, s2, s3)); }
    assert(next_mutant_early(s3, s4)) by { assert(reply(true, false, s3, s4)); }
    assert(!durable_before_reply(s4)) by {
        assert(s4.replied.contains(1));
        map_insert_at(rk0(), 1, k_live(), 1);
        assert(map_at(s4.reply_kind, 1) == k_live());
        assert(!s4.seen.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_early_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_early(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_early_trace(t) && !durable_before_reply(t.last()));
}

/// mutant-tombstone: Request -> Expire -> Resolve -> Prepare -> Reply ->
/// Publish with PublishTombstone publishes a tombstone's parts —
/// 1 \in published with replyKind[1] = "tombstone".
proof fn mutant_tombstone_violates()
    ensures
        exists|t: Seq<State>| is_tombstone_trace(t) && !tombstones_stay_local(t.last()),
{
    let e = Set::empty();
    let e1 = e.insert(1);
    let rkt = rk0().insert(1, k_tombstone());
    let s0 = st(0, ph_idle(), false, false, e, e, e, k_none(), e, rk0(), e);
    let s1 = st(1, ph_held(), false, false, e1, e, e, k_none(), e, rk0(), e);
    let s2 = st(1, ph_held(), false, true, e1, e, e, k_none(), e, rk0(), e);
    let s3 = st(1, ph_selected(), false, true, e1, e, e, k_tombstone(), e, rk0(), e);
    let s4 = st(1, ph_prepared(), false, true, e1, e, e, k_tombstone(), e, rk0(), e);
    let s5 = st(1, ph_publishing(), false, true, e1, e, e, k_tombstone(), e1, rkt, e);
    let s6 = st(1, ph_idle(), false, true, e1, e, e, k_tombstone(), e1, rkt, e1);
    assert(init(s0));
    assert(next_mutant_tombstone(s0, s1)) by { assert(request(false, s0, s1)); }
    assert(next_mutant_tombstone(s1, s2)) by { assert(expire(s1, s2)); }
    assert(next_mutant_tombstone(s2, s3)) by { assert(resolve(false, s2, s3)); }
    assert(next_mutant_tombstone(s3, s4)) by { assert(prepare(false, s3, s4)); }
    assert(next_mutant_tombstone(s4, s5)) by { assert(reply(false, true, s4, s5)); }
    assert(next_mutant_tombstone(s5, s6)) by { assert(publish(s5, s6)); }
    assert(!tombstones_stay_local(s6)) by {
        assert(s6.published.contains(1));
        map_insert_at(rk0(), 1, k_tombstone(), 1);
        assert(map_at(s6.reply_kind, 1) == k_tombstone());
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_tombstone_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_tombstone(
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                    || t[i + 1] == s5 || t[i + 1] == s6
            );
        }
    }
    assert(t.last() == s6);
    assert(is_tombstone_trace(t) && !tombstones_stay_local(t.last()));
}

/// mutant-deadline: the recorded counterexample is *temporal* — an issued,
/// expired, unanswered request stutters forever under ForgetDeadline. The
/// safety content provable here: the stuck state is reachable, and in it
/// neither deadline resolution nor any reply step can fire (only an Arrival
/// that fairness never requires could unblock it).
pub open spec fn deadline_stuck(s: State) -> bool {
    &&& s.phase == ph_held()
    &&& s.expired
    &&& !s.arrived
    &&& s.issued.contains(s.current)
    &&& !s.replied.contains(s.current)
    &&& forall|post: State| !resolve(true, s, post)
    &&& forall|post: State| !reply(true, true, s, post)
}

proof fn mutant_deadline_violates()
    ensures
        exists|t: Seq<State>| is_deadline_trace(t) && deadline_stuck(t.last()),
{
    let e = Set::empty();
    let e1 = e.insert(1);
    let s0 = st(0, ph_idle(), false, false, e, e, e, k_none(), e, rk0(), e);
    let s1 = st(1, ph_held(), false, false, e1, e, e, k_none(), e, rk0(), e);
    let s2 = st(1, ph_held(), false, true, e1, e, e, k_none(), e, rk0(), e);
    assert(init(s0));
    assert(next_mutant_deadline(s0, s1)) by { assert(request(false, s0, s1)); }
    assert(next_mutant_deadline(s1, s2)) by { assert(expire(s1, s2)); }
    // resolve needs arrived or (expired and not ForgetDeadline); reply needs
    // prepared or selected+live. Neither is possible at held+expired+!arrived.
    assert(deadline_stuck(s2)) by {
        assert forall|post: State| !resolve(true, s2, post) by {
            assert(!(s2.arrived || (s2.expired && !true)));
        }
        assert forall|post: State| !reply(true, true, s2, post) by {
            assert(s2.phase != ph_prepared());
            assert(!(true && s2.phase == ph_selected() && s2.kind == k_live()));
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_deadline_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_deadline(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_deadline_trace(t) && deadline_stuck(t.last()));
}

/// mutant-unadmitted: Request -> Arrival -> Resolve -> Prepare -> Reply with
/// ForgetAdmission records durable metadata but skips the adapter hold —
/// 1 \in replied with replyKind[1] = "live" but 1 \notin admitted.
proof fn mutant_unadmitted_violates()
    ensures
        exists|t: Seq<State>| is_unadmitted_trace(t) && !admitted_before_reply(t.last()),
{
    let e = Set::empty();
    let e1 = e.insert(1);
    let rkl = rk0().insert(1, k_live());
    let s0 = st(0, ph_idle(), false, false, e, e, e, k_none(), e, rk0(), e);
    let s1 = st(1, ph_held(), false, false, e1, e, e, k_none(), e, rk0(), e);
    let s2 = st(1, ph_held(), true, false, e1, e, e, k_none(), e, rk0(), e);
    let s3 = st(1, ph_selected(), true, false, e1, e, e, k_live(), e, rk0(), e);
    let s4 = st(1, ph_prepared(), true, false, e1, e1, e, k_live(), e, rk0(), e);
    let s5 = st(1, ph_publishing(), true, false, e1, e1, e, k_live(), e1, rkl, e);
    assert(init(s0));
    assert(next_mutant_unadmitted(s0, s1)) by { assert(request(false, s0, s1)); }
    assert(next_mutant_unadmitted(s1, s2)) by { assert(arrival(s1, s2)); }
    assert(next_mutant_unadmitted(s2, s3)) by { assert(resolve(false, s2, s3)); }
    assert(next_mutant_unadmitted(s3, s4)) by { assert(prepare(true, s3, s4)); }
    assert(next_mutant_unadmitted(s4, s5)) by { assert(reply(false, false, s4, s5)); }
    assert(!admitted_before_reply(s5)) by {
        assert(s5.replied.contains(1));
        map_insert_at(rk0(), 1, k_live(), 1);
        assert(map_at(s5.reply_kind, 1) == k_live());
        assert(!s5.admitted.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5);
    assert(is_unadmitted_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_unadmitted(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                || t[i + 1] == s5);
        }
    }
    assert(t.last() == s5);
    assert(is_unadmitted_trace(t) && !admitted_before_reply(t.last()));
}

/// Completion witness for the safe model: Request -> Arrival -> Resolve ->
/// Prepare -> Reply -> Publish answers request 1 live and publishes it, then
/// Request -> Resolve -> Prepare -> Reply answers request 2 with a
/// reply-only tombstone under the full metadata budget. Reaches
/// replied = Requests with only the live value published.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().replied =~= requests()
            && t.last().published =~= Set::empty().insert(1),
{
    let e = Set::empty();
    let e1 = e.insert(1);
    let e12 = e1.insert(2);
    let rkl = rk0().insert(1, k_live());
    let rklt = rkl.insert(2, k_tombstone());
    let s0 = st(0, ph_idle(), false, false, e, e, e, k_none(), e, rk0(), e);
    let s1 = st(1, ph_held(), false, false, e1, e, e, k_none(), e, rk0(), e);
    let s2 = st(1, ph_held(), true, false, e1, e, e, k_none(), e, rk0(), e);
    let s3 = st(1, ph_selected(), true, false, e1, e, e, k_live(), e, rk0(), e);
    let s4 = st(1, ph_prepared(), true, false, e1, e1, e1, k_live(), e, rk0(), e);
    let s5 = st(1, ph_publishing(), true, false, e1, e1, e1, k_live(), e1, rkl, e);
    let s6 = st(1, ph_idle(), true, false, e1, e1, e1, k_live(), e1, rkl, e1);
    let s7 = st(2, ph_held(), true, false, e12, e1, e1, k_none(), e1, rkl, e1);
    let s8 = st(2, ph_selected(), true, false, e12, e1, e1, k_live(), e1, rkl, e1);
    let s9 = st(2, ph_prepared(), true, false, e12, e1, e1, k_tombstone(), e1, rkl, e1);
    let s10 = st(2, ph_idle(), true, false, e12, e1, e1, k_tombstone(), e12, rklt, e1);
    assert(init(s0));
    assert(next(s0, s1)) by { assert(request(false, s0, s1)); }
    assert(next(s1, s2)) by { assert(arrival(s1, s2)); }
    assert(next(s2, s3)) by { assert(resolve(false, s2, s3)); }
    assert(next(s3, s4)) by { assert(prepare(false, s3, s4)); }
    assert(next(s4, s5)) by { assert(reply(false, false, s4, s5)); }
    assert(next(s5, s6)) by { assert(publish(s5, s6)); }
    assert(next(s6, s7)) by { assert(request(false, s6, s7)); }
    assert(next(s7, s8)) by { assert(resolve(false, s7, s8)); }
    assert(next(s8, s9)) by { assert(prepare(false, s8, s9)); }
    assert(next(s9, s10)) by { assert(reply(false, false, s9, s10)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7).push(
        s8,
    ).push(s9).push(s10);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                    || t[i + 1] == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
                    || t[i + 1] == s9 || t[i + 1] == s10
            );
        }
    }
    assert(t.last() == s10);
    assert(s10.replied =~= requests());
    assert(s10.published =~= Set::empty().insert(1));
    assert(is_trace(t) && t.last().replied =~= requests() && t.last().published =~= Set::empty()
        .insert(1));
}

}
