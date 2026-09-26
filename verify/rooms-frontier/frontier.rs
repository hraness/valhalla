//! Verus pilot (5th model): inductive proof of RoomsFrontier's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs`,
//! `verify/private-publication/publication.rs` and
//! `verify/host-recovery/recovery.rs`: `RoomsFrontier.tla` is re-stated as a
//! Verus transition system and the nine checked safety invariants are proved
//! inductive. The proof is generic over the two root-change schedules
//! `SocialChanges`/`RoomsChanges`, so `normal.cfg`, `root-preserving.cfg`,
//! `social-only.cfg` and `two-changing.cfg` are all covered by one argument —
//! matching their four positive TLC results. Each of the seven mutant
//! configurations is proved to reach a violation of the invariant TLC found
//! for it, and a completion witness runs a decision through finalization and
//! one interruption through recovery to a reopened frontier.
//!
//! Encoding notes:
//!   * `Root(h, changes)` picks the maximal element of `changes \cup {0}` that
//!     is `<= h`. With `Heights = 2` the only elements that can win are 1 and
//!     2, so `root_at` below is a closed form: `2` iff `2 in changes` and
//!     `h >= 2`, else `1` iff `1 in changes` and `h >= 1`, else `0`. This is
//!     exact for every `h <= 2` and arbitrary `changes`; heights above the
//!     bound are never reached. `LatestMatch` gets the same closed form.
//!   * The value alphabet {"none","a","b","genesis"} is {0,1,2,3}, the phase
//!     alphabet is int constants, and Evidence == {vote,lock} is {1,2}.
//!   * `journal`/`original` are `Map<int,int>` on the fixed domain {1,2}
//!     (read through `map_at`); `acks`, `starts` and `reopened` are `Set` of
//!     record structs and `wal` is `Set<int>`.
//!   * The mutant/variant switches become parameters of `next_cfg`, exactly
//!     like the prior pilots; `next`/`is_trace` take the concrete change sets
//!     so one induction covers all four positive configurations.
//!   * Safety only: no liveness claim is made, matching the model's own
//!     scoping (`HonestRecovery` is a safety invariant about not refusing or
//!     stalling a recoverable cut, not a fairness statement).
//!
//! Verify with:
//!   verus --crate-type=lib verify/rooms-frontier/frontier.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Heights = 2.
pub open spec fn heights() -> int {
    2
}

/// CrashBudget = 2.
pub open spec fn crash_budget() -> int {
    2
}

/// Values \cup {"none","genesis"}: none=0, a=1, b=2, genesis=3.
pub open spec fn v_none() -> int {
    0
}

pub open spec fn v_a() -> int {
    1
}

pub open spec fn v_genesis() -> int {
    3
}

/// Values == {"a","b"}.
pub open spec fn is_value(v: int) -> bool {
    v == 1 || v == 2
}

/// Journal entries range over Values \cup {"none"}.
pub open spec fn is_jval(v: int) -> bool {
    v == 0 || v == 1 || v == 2
}

/// Evidence == {"vote","lock"} as {1,2}.
pub open spec fn evidence() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

/// Phases: "idle","journal","social","rooms","social-after-rooms","apply",
/// "ack","respond","engine-restart","recover","recovery-check","blocked".
pub open spec fn ph_idle() -> int {
    0
}

pub open spec fn ph_journal() -> int {
    1
}

pub open spec fn ph_social() -> int {
    2
}

pub open spec fn ph_rooms() -> int {
    3
}

pub open spec fn ph_sar() -> int {
    4
}

pub open spec fn ph_apply() -> int {
    5
}

pub open spec fn ph_ack() -> int {
    6
}

pub open spec fn ph_respond() -> int {
    7
}

pub open spec fn ph_er() -> int {
    8
}

pub open spec fn ph_recover() -> int {
    9
}

pub open spec fn ph_rcc() -> int {
    10
}

pub open spec fn ph_blocked() -> int {
    11
}

pub open spec fn is_phase(p: int) -> bool {
    0 <= p <= 11
}

/// Outcome alphabet {"none","Acked","Rejected","Withheld"}.
pub open spec fn o_none() -> int {
    0
}

pub open spec fn o_acked() -> int {
    1
}

pub open spec fn o_rejected() -> int {
    2
}

pub open spec fn o_withheld() -> int {
    3
}

/// Roster alphabet: "old"=0, "new"=1; Roster(h) == IF h = 1 THEN "old" ELSE "new".
pub open spec fn roster(h: int) -> int {
    if h == 1 {
        0
    } else {
        1
    }
}

/// The checked change-set schedules.
pub open spec fn ch_none() -> Set<int> {
    Set::empty()
}

pub open spec fn ch_1() -> Set<int> {
    Set::empty().insert(1)
}

pub open spec fn ch_12() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

// ---------------------------------------------------------------------------
// Root arithmetic
// ---------------------------------------------------------------------------

/// Total map read at int keys (0 off-domain; the model only reads the
/// {1,2} domain and the guarded genesis case).
pub open spec fn map_at(m: Map<int, int>, j: int) -> int {
    if m.dom().contains(j) {
        m[j]
    } else {
        0
    }
}

/// The fixed journal domain 1..Heights.
pub open spec fn dom12() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

/// Root(h, changes): maximal k in changes \cup {0} with k <= h, in closed
/// form for h <= 2 (see header note).
pub open spec fn root_at(h: int, changes: Set<int>) -> int {
    if h >= 2 && changes.contains(2) {
        2
    } else if h >= 1 && changes.contains(1) {
        1
    } else {
        0
    }
}

/// LatestMatch(root, changes) over 0..journalHead, in closed form:
/// the largest p <= head whose root equals `root`. When no prefix matches,
/// TLA's CHOOSE is unspecified; the value 0 is a deterministic stand-in and
/// the only checked configuration that consults it always has a match.
pub open spec fn latest_match(root: int, changes: Set<int>, head: int) -> int {
    if head >= 2 && root == root_at(2, changes) {
        2
    } else if head >= 1 && root == root_at(1, changes) {
        1
    } else {
        0
    }
}

/// Social(h) == Root(h, SocialChanges) for schedule sc.
pub open spec fn social_root(sc: Set<int>, h: int) -> int {
    root_at(h, sc)
}

/// Rooms(h) == Root(h, RoomsChanges) for schedule rc.
pub open spec fn rooms_root(rc: Set<int>, h: int) -> int {
    root_at(h, rc)
}

proof fn root_at_mono(a: int, b: int, c: Set<int>)
    requires
        a <= b,
    ensures
        root_at(a, c) <= root_at(b, c),
{
}

proof fn root_at_range(h: int, c: Set<int>)
    ensures
        0 <= root_at(h, c) <= 2,
{
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

// ---------------------------------------------------------------------------
// Records and state
// ---------------------------------------------------------------------------

/// The full application frontier record
/// [height, value, social, registry, control, time].
pub struct Frontier {
    pub height: int,
    pub value: int,
    pub social: int,
    pub registry: int,
    pub control: int,
    pub time: int,
}

/// Frontier(h, value).
pub open spec fn frontier(sc: Set<int>, rc: Set<int>, h: int, value: int) -> Frontier {
    Frontier {
        height: h,
        value: if h == 0 {
            v_genesis()
        } else {
            value
        },
        social: root_at(h, sc),
        registry: root_at(h, rc),
        control: h,
        time: h,
    }
}

/// Genesis == Frontier(0, "genesis"); every field is a constant because
/// root_at(0, _) = 0.
pub open spec fn genesis_frontier() -> Frontier {
    Frontier { height: 0, value: v_genesis(), social: 0, registry: 0, control: 0, time: 0 }
}

/// At(h) == IF h = 0 THEN Genesis ELSE Frontier(h, s.journal[h]).
/// `frontier` already maps h = 0 to the genesis value and zero roots, so the
/// unconditional form is equivalent.
pub open spec fn at(s: State, sc: Set<int>, rc: Set<int>, h: int) -> Frontier {
    frontier(sc, rc, h, map_at(s.journal, h))
}

/// The acks element: [height, value, journalHead, committedValue, app,
/// appliedValue, social, rooms, appSocial, appRooms].
pub struct Ack {
    pub height: int,
    pub value: int,
    pub journal_head: int,
    pub committed_value: int,
    pub app: Frontier,
    pub applied_value: int,
    pub social: int,
    pub rooms: int,
    pub app_social: int,
    pub app_rooms: int,
}

/// The starts element: [decided, height, roster].
pub struct Start {
    pub decided: int,
    pub height: int,
    pub roster: int,
}

/// The reopened element: [frontier, head, value, social, rooms].
pub struct Reopened {
    pub frontier: Frontier,
    pub head: int,
    pub value: int,
    pub social: int,
    pub rooms: int,
}

/// VARIABLE s: fields in the TLA record's order.
pub struct State {
    pub pc: int,
    pub journal_head: int,
    pub journal: Map<int, int>,
    pub original: Map<int, int>,
    pub social: int,
    pub rooms: int,
    pub app: Frontier,
    pub app_social: int,
    pub app_rooms: int,
    pub target: int,
    pub value: int,
    pub outcome: int,
    pub recovering: bool,
    pub crashes: int,
    pub acks: Set<Ack>,
    pub starts: Set<Start>,
    pub reopened: Set<Reopened>,
    pub wal: Set<int>,
    pub released_wal: bool,
}

/// CompatiblePrefix(p).
pub open spec fn compatible_prefix(s: State, sc: Set<int>, rc: Set<int>, p: int) -> bool {
    &&& s.rooms == rooms_root(rc, p)
        &&& (s.social == social_root(sc, p) || (p < s.journal_head && s.social == social_root(
            sc,
            p + 1,
        )))
}

/// IndependentSkewInvalid.
pub open spec fn independent_skew_invalid(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    let rooms_height = latest_match(s.rooms, rc, s.journal_head);
    let social_height = latest_match(s.social, sc, s.journal_head);
    social_height < rooms_height || social_height > rooms_height + 1
}

/// Init.
pub open spec fn init(s: State) -> bool {
    &&& s.pc == ph_idle()
    &&& s.journal_head == 0
    &&& s.journal =~= Map::new(dom12(), |_h: int| v_none())
    &&& s.original =~= Map::new(dom12(), |_h: int| v_none())
    &&& s.social == 0
    &&& s.rooms == 0
    &&& s.app == genesis_frontier()
    &&& s.app_social == 0
    &&& s.app_rooms == 0
    &&& s.target == 1
    &&& s.value == v_a()
    &&& s.outcome == o_none()
    &&& !s.recovering
    &&& s.crashes == 0
    &&& s.acks =~= Set::empty()
    &&& s.starts =~= Set::empty()
    &&& s.reopened =~= Set::empty()
    &&& s.wal =~= evidence()
    &&& !s.released_wal
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// NewDecision(v).
pub open spec fn new_decision(pre: State, post: State, v: int) -> bool {
    &&& pre.pc == ph_idle()
    &&& pre.journal_head < heights()
    &&& pre.app.height == pre.journal_head
    &&& post.pc == ph_journal()
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.journal_head + 1
    &&& post.value == v
    &&& post.outcome == o_none()
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// Redeliver(h, v), parameterized by OverwriteIdentity (oi) and RootsOnlyAck
/// (roa). `h <= journalHead` is the action guard; the `h in 1..Heights`
/// bound comes from the next-state existential, mirrored below.
pub open spec fn redeliver(
    pre: State,
    post: State,
    sc: Set<int>,
    rc: Set<int>,
    oi: bool,
    roa: bool,
    h: int,
    v: int,
) -> bool {
    &&& pre.pc == ph_idle()
    &&& 1 <= h <= pre.journal_head
    &&& post.pc == if v != map_at(pre.journal, h) {
        ph_respond()
    } else if h <= pre.app.height {
        ph_ack()
    } else if roa && pre.app_social == social_root(sc, h) && pre.app_rooms == rooms_root(rc, h) {
        ph_ack()
    } else {
        ph_social()
    }
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= if oi && v != map_at(pre.journal, h) {
        pre.journal.insert(h, v)
    } else {
        pre.journal
    }
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == h
    &&& post.value == v
    &&& post.outcome == if v != map_at(pre.journal, h) {
        o_rejected()
    } else {
        o_none()
    }
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// JournalCommit.
pub open spec fn journal_commit(pre: State, post: State) -> bool {
    &&& pre.pc == ph_journal()
    &&& post.pc == ph_social()
    &&& post.journal_head == pre.target
    &&& post.journal =~= pre.journal.insert(pre.target, pre.value)
    &&& post.original =~= pre.original.insert(pre.target, pre.value)
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// PublishSocial.
pub open spec fn publish_social(pre: State, post: State, sc: Set<int>) -> bool {
    &&& (pre.pc == ph_social() || pre.pc == ph_sar())
    &&& post.pc == if pre.pc == ph_social() {
        ph_rooms()
    } else {
        ph_apply()
    }
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == social_root(sc, pre.target)
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// PublishRooms, parameterized by RoomsBeforeSocial (rbs).
pub open spec fn publish_rooms(pre: State, post: State, rc: Set<int>, rbs: bool) -> bool {
    &&& (pre.pc == ph_rooms() || (rbs && pre.pc == ph_social()))
    &&& post.pc == if pre.pc == ph_rooms() {
        ph_apply()
    } else {
        ph_sar()
    }
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == rooms_root(rc, pre.target)
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// Apply.
pub open spec fn apply_step(pre: State, post: State, sc: Set<int>, rc: Set<int>) -> bool {
    &&& pre.pc == ph_apply()
    &&& post.app == at(pre, sc, rc, pre.target)
    &&& post.app_social == social_root(sc, pre.target)
    &&& post.app_rooms == rooms_root(rc, pre.target)
    &&& post.target == if pre.recovering && pre.target < pre.journal_head {
        pre.target + 1
    } else {
        pre.target
    }
    &&& post.value == if pre.recovering && pre.target < pre.journal_head {
        map_at(pre.journal, pre.target + 1)
    } else {
        pre.value
    }
    &&& post.pc == if !pre.recovering {
        ph_ack()
    } else if pre.target < pre.journal_head {
        ph_social()
    } else {
        ph_rcc()
    }
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.outcome == pre.outcome
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
    &&& post.recovering == pre.recovering
}

/// Acknowledge, parameterized by EarlyAck (ea). The recorded ack captures the
/// observations at the boundary, as in the model.
pub open spec fn acknowledge(pre: State, post: State, ea: bool) -> bool {
    &&& (pre.pc == ph_ack() || (ea && pre.pc == ph_journal()))
    &&& post.outcome == o_acked()
    &&& post.pc == ph_respond()
    &&& post.acks =~= pre.acks.insert(Ack {
        height: pre.target,
        value: pre.value,
        journal_head: pre.journal_head,
        committed_value: map_at(pre.journal, pre.target),
        app: pre.app,
        applied_value: if pre.app.height == 0 {
            v_genesis()
        } else {
            map_at(pre.journal, pre.app.height)
        },
        social: pre.social,
        rooms: pre.rooms,
        app_social: pre.app_social,
        app_rooms: pre.app_rooms,
    })
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// Fail.
pub open spec fn fail(pre: State, post: State) -> bool {
    &&& (pre.pc == ph_journal() || pre.pc == ph_social() || pre.pc == ph_rooms() || pre.pc
        == ph_sar())
    &&& !pre.recovering
    &&& post.pc == ph_respond()
    &&& post.outcome == o_withheld()
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// HostSuccess, parameterized by WrongNextRoster (wnr).
pub open spec fn host_success(pre: State, post: State, wnr: bool) -> bool {
    &&& pre.pc == ph_respond()
    &&& pre.outcome == o_acked()
    &&& post.pc == ph_idle()
    &&& post.starts =~= pre.starts.insert(Start {
        decided: pre.target,
        height: pre.target + 1,
        roster: roster(
            if wnr {
                pre.target
            } else {
                pre.target + 1
            },
        ),
    })
    &&& post.wal =~= if pre.target == 1 {
        Set::empty()
    } else {
        pre.wal
    }
    &&& post.released_wal == (pre.released_wal || pre.target == 1)
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.reopened =~= pre.reopened
}

/// HostFailure, parameterized by RestartOnFailure (rof).
pub open spec fn host_failure(pre: State, post: State, rof: bool) -> bool {
    &&& pre.pc == ph_respond()
    &&& (pre.outcome == o_withheld() || pre.outcome == o_rejected())
    &&& post.pc == if rof {
        ph_er()
    } else {
        ph_idle()
    }
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// EngineRestart.
pub open spec fn engine_restart(pre: State, post: State) -> bool {
    &&& pre.pc == ph_er()
    &&& post.pc == ph_idle()
    &&& post.wal =~= if pre.target == 1 {
        Set::empty()
    } else {
        pre.wal
    }
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.released_wal == pre.released_wal
}

/// Interrupt.
pub open spec fn interrupt(pre: State, post: State) -> bool {
    &&& pre.pc != ph_recover()
    &&& pre.pc != ph_blocked()
    &&& pre.crashes < crash_budget()
    &&& post.pc == ph_recover()
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == genesis_frontier()
    &&& post.app_social == 0
    &&& post.app_rooms == 0
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering
    &&& post.crashes == pre.crashes + 1
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// LoadPrefix(p), parameterized by IndependentRoots (ir).
pub open spec fn load_prefix(
    pre: State,
    post: State,
    sc: Set<int>,
    rc: Set<int>,
    ir: bool,
    p: int,
) -> bool {
    &&& pre.pc == ph_recover()
    &&& 0 <= p <= pre.journal_head
    &&& compatible_prefix(pre, sc, rc, p)
    &&& (!ir || (!independent_skew_invalid(pre, sc, rc) && p == latest_match(
        pre.rooms,
        rc,
        pre.journal_head,
    )))
    &&& post.app == at(pre, sc, rc, p)
    &&& post.app_social == pre.social
    &&& post.app_rooms == pre.rooms
    &&& post.target == if p < pre.journal_head {
        p + 1
    } else if p == 0 {
        1
    } else {
        p
    }
    &&& post.value == if p < pre.journal_head {
        map_at(pre.journal, p + 1)
    } else if p == 0 {
        v_a()
    } else {
        map_at(pre.journal, p)
    }
    &&& post.pc == if p < pre.journal_head {
        ph_social()
    } else {
        ph_rcc()
    }
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// RecoveryRefuse, parameterized by IndependentRoots (ir).
pub open spec fn recovery_refuse(pre: State, post: State, sc: Set<int>, rc: Set<int>, ir: bool) -> bool {
    &&& pre.pc == ph_recover()
    &&& (!(exists|p: int| 0 <= p <= pre.journal_head && #[trigger] compatible_prefix(
        pre,
        sc,
        rc,
        p,
    )) || (ir && independent_skew_invalid(pre, sc, rc)))
    &&& post.pc == ph_blocked()
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.recovering == pre.recovering
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.reopened =~= pre.reopened
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

/// RecoveryReady.
pub open spec fn recovery_ready(pre: State, post: State, sc: Set<int>, rc: Set<int>) -> bool {
    &&& pre.pc == ph_rcc()
    &&& pre.app == at(pre, sc, rc, pre.journal_head)
    &&& pre.app_social == pre.social
    &&& pre.app_rooms == pre.rooms
    &&& post.pc == ph_idle()
    &&& !post.recovering
    &&& post.reopened =~= pre.reopened.insert(Reopened {
        frontier: pre.app,
        head: pre.journal_head,
        value: if pre.journal_head == 0 {
            v_genesis()
        } else {
            map_at(pre.journal, pre.journal_head)
        },
        social: pre.social,
        rooms: pre.rooms,
    })
    &&& post.journal_head == pre.journal_head
    &&& post.journal =~= pre.journal
    &&& post.original =~= pre.original
    &&& post.social == pre.social
    &&& post.rooms == pre.rooms
    &&& post.app == pre.app
    &&& post.app_social == pre.app_social
    &&& post.app_rooms == pre.app_rooms
    &&& post.target == pre.target
    &&& post.value == pre.value
    &&& post.outcome == pre.outcome
    &&& post.crashes == pre.crashes
    &&& post.acks =~= pre.acks
    &&& post.starts =~= pre.starts
    &&& post.wal =~= pre.wal
    &&& post.released_wal == pre.released_wal
}

// ---------------------------------------------------------------------------
// Next under arbitrary config constants
// ---------------------------------------------------------------------------

/// Next parameterized by the schedules and the seven switches
/// (RootsOnlyAck, EarlyAck, OverwriteIdentity, RestartOnFailure,
/// WrongNextRoster, RoomsBeforeSocial, IndependentRoots).
pub open spec fn next_cfg(
    sc: Set<int>,
    rc: Set<int>,
    roa: bool,
    ea: bool,
    oi: bool,
    rof: bool,
    wnr: bool,
    rbs: bool,
    ir: bool,
    pre: State,
    post: State,
) -> bool {
    ||| journal_commit(pre, post)
    ||| publish_social(pre, post, sc)
    ||| publish_rooms(pre, post, rc, rbs)
    ||| apply_step(pre, post, sc, rc)
    ||| acknowledge(pre, post, ea)
    ||| fail(pre, post)
    ||| host_success(pre, post, wnr)
    ||| host_failure(pre, post, rof)
    ||| engine_restart(pre, post)
    ||| interrupt(pre, post)
    ||| recovery_refuse(pre, post, sc, rc, ir)
    ||| recovery_ready(pre, post, sc, rc)
    ||| exists|v: int| is_value(v) && #[trigger] new_decision(pre, post, v)
    ||| exists|h: int, v: int|
        (1 <= h <= heights() && is_value(v) && #[trigger] redeliver(
            pre,
            post,
            sc,
            rc,
            oi,
            roa,
            h,
            v,
        ))
    ||| exists|p: int|
        (0 <= p <= heights() && #[trigger] load_prefix(pre, post, sc, rc, ir, p))
}

/// The all-switches-false next relation shared by the four positive
/// configurations; the schedules stay free.
pub open spec fn next_safe(sc: Set<int>, rc: Set<int>, pre: State, post: State) -> bool {
    next_cfg(sc, rc, false, false, false, false, false, false, false, pre, post)
}

/// normal.cfg: SocialChanges = {1}, RoomsChanges = {1}.
pub open spec fn next_normal(pre: State, post: State) -> bool {
    next_safe(ch_1(), ch_1(), pre, post)
}

/// root-preserving.cfg: both schedules empty.
pub open spec fn next_root_preserving(pre: State, post: State) -> bool {
    next_safe(ch_none(), ch_none(), pre, post)
}

/// social-only.cfg: SocialChanges = {1}, RoomsChanges = {}.
pub open spec fn next_social_only(pre: State, post: State) -> bool {
    next_safe(ch_1(), ch_none(), pre, post)
}

/// two-changing.cfg: both schedules {1,2}.
pub open spec fn next_two_changing(pre: State, post: State) -> bool {
    next_safe(ch_12(), ch_12(), pre, post)
}

/// mutant-early-ack.cfg: EarlyAck.
pub open spec fn next_mutant_early_ack(pre: State, post: State) -> bool {
    next_cfg(ch_1(), ch_1(), false, true, false, false, false, false, false, pre, post)
}

/// mutant-failed-restart.cfg: RestartOnFailure.
pub open spec fn next_mutant_failed_restart(pre: State, post: State) -> bool {
    next_cfg(ch_1(), ch_1(), false, false, false, true, false, false, false, pre, post)
}

/// mutant-identity.cfg: OverwriteIdentity.
pub open spec fn next_mutant_identity(pre: State, post: State) -> bool {
    next_cfg(ch_1(), ch_1(), false, false, true, false, false, false, false, pre, post)
}

/// mutant-independent-roots.cfg: IndependentRoots over RoomsChanges = {}.
pub open spec fn next_mutant_independent_roots(pre: State, post: State) -> bool {
    next_cfg(ch_1(), ch_none(), false, false, false, false, false, false, true, pre, post)
}

/// mutant-next-roster.cfg: WrongNextRoster.
pub open spec fn next_mutant_next_roster(pre: State, post: State) -> bool {
    next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, pre, post)
}

/// mutant-publication-order.cfg: RoomsBeforeSocial.
pub open spec fn next_mutant_publication_order(pre: State, post: State) -> bool {
    next_cfg(ch_1(), ch_1(), false, false, false, false, false, true, false, pre, post)
}

/// mutant-roots-only.cfg: RootsOnlyAck over empty schedules.
pub open spec fn next_mutant_roots_only(pre: State, post: State) -> bool {
    next_cfg(ch_none(), ch_none(), true, false, false, false, false, false, false, pre, post)
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// TypeOK.
pub open spec fn type_ok(s: State) -> bool {
    &&& is_phase(s.pc)
    &&& 0 <= s.journal_head <= heights()
    &&& s.journal.dom() =~= dom12()
    &&& forall|h: int| dom12().contains(h) ==> is_jval(map_at(s.journal, h))
    &&& s.original.dom() =~= dom12()
    &&& forall|h: int| dom12().contains(h) ==> is_jval(map_at(s.original, h))
    &&& 0 <= s.social <= heights()
    &&& 0 <= s.rooms <= heights()
    &&& 0 <= s.app.height <= heights()
    &&& 1 <= s.target <= heights()
    &&& is_value(s.value)
    &&& 0 <= s.app_social <= heights()
    &&& 0 <= s.app_rooms <= heights()
    &&& (s.outcome == o_none() || s.outcome == o_acked() || s.outcome == o_rejected() || s.outcome
        == o_withheld())
    &&& 0 <= s.crashes <= crash_budget()
    &&& s.wal.subset_of(evidence())
}

/// CommittedIdentity.
pub open spec fn committed_identity(s: State) -> bool {
    s.journal =~= s.original
}

/// PublicationOrder == \E p in 0..journalHead : CompatiblePrefix(p).
pub open spec fn publication_order(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    exists|p: int| 0 <= p <= s.journal_head && #[trigger] compatible_prefix(s, sc, rc, p)
}

/// AckAfterDurability.
pub open spec fn ack_after_durability(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    forall|a: Ack| s.acks.contains(a) ==> (a.height <= a.journal_head && a.value
        == a.committed_value && a.social >= social_root(sc, a.height) && a.rooms >= rooms_root(
        rc,
        a.height,
    ))
}

/// AckHasFullFrontier.
pub open spec fn ack_has_full_frontier(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    forall|a: Ack| s.acks.contains(a) ==> (a.app.height >= a.height && a.app == frontier(
        sc,
        rc,
        a.app.height,
        a.applied_value,
    ) && a.app_social == a.app.social && a.app_rooms == a.app.registry)
}

/// FailedFinalizationKeepsWal.
pub open spec fn failed_finalization_keeps_wal(s: State) -> bool {
    !s.released_wal ==> s.wal =~= evidence()
}

/// NextRoster.
pub open spec fn next_roster_inv(s: State) -> bool {
    forall|n: Start| s.starts.contains(n) ==> (n.height == n.decided + 1 && n.roster == roster(
        n.height,
    ))
}

/// RecoveredFrontier.
pub open spec fn recovered_frontier(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    forall|r: Reopened| s.reopened.contains(r) ==> (r.frontier == frontier(
        sc,
        rc,
        r.head,
        r.value,
    ) && r.social == social_root(sc, r.head) && r.rooms == rooms_root(rc, r.head))
}

/// HonestRecovery.
pub open spec fn honest_recovery(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    &&& s.pc != ph_blocked()
    &&& (s.pc == ph_rcc() ==> (s.app == at(s, sc, rc, s.journal_head) && s.app_social == s.social
        && s.app_rooms == s.rooms && s.social == social_root(sc, s.journal_head) && s.rooms
        == rooms_root(rc, s.journal_head)))
}

// ---- Auxiliary invariants -------------------------------------------------

/// Auxiliary: journal[h] holds a committed value exactly for h <= head;
/// entries above head are still "none".
pub open spec fn aux_journal_shape(s: State) -> bool {
    forall|h: int| dom12().contains(h) ==> if h <= s.journal_head {
        is_value(map_at(s.journal, h))
    } else {
        map_at(s.journal, h) == v_none()
    }
}

/// Auxiliary: the recorded original is a journal value on the whole domain.
pub open spec fn aux_original_shape(s: State) -> bool {
    forall|h: int| dom12().contains(h) ==> is_jval(map_at(s.original, h))
}

/// Auxiliary: the journal phase only ever follows NewDecision on a caught-up
/// application, so its target is fresh and both roots sit at head.
pub open spec fn aux_journal_state(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    s.pc == ph_journal() ==> (s.target == s.journal_head + 1 && s.app.height == s.journal_head
        && s.social == social_root(sc, s.journal_head) && s.rooms == rooms_root(
        rc,
        s.journal_head,
    ))
}

/// Auxiliary: the application frontier is exactly the At-record of its own
/// height — nothing else constructs app.
pub open spec fn aux_app_wf(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    s.app == at(s, sc, rc, s.app.height)
}

/// Auxiliary: the applied height never leads the durable head.
pub open spec fn aux_app_le_head(s: State) -> bool {
    0 <= s.app.height <= s.journal_head
}

/// Auxiliary: inside a publish/apply/ack flow the target is committed.
pub open spec fn aux_target_le(s: State) -> bool {
    (s.pc == ph_social() || s.pc == ph_rooms() || s.pc == ph_sar() || s.pc == ph_apply() || s.pc
        == ph_ack()) ==> s.target <= s.journal_head
}

/// Auxiliary: those same phases only exist above genesis.
pub open spec fn aux_head_pos(s: State) -> bool {
    (s.pc == ph_social() || s.pc == ph_rooms() || s.pc == ph_sar() || s.pc == ph_apply() || s.pc
        == ph_ack()) ==> s.journal_head >= 1
}

/// Auxiliary: in the flow phases the working value is the committed one.
pub open spec fn aux_value_journal(s: State) -> bool {
    (s.pc == ph_social() || s.pc == ph_rooms() || s.pc == ph_sar() || s.pc == ph_apply() || s.pc
        == ph_ack()) ==> s.value == map_at(s.journal, s.target)
}

/// Auxiliary: the rooms phase is only entered by publishing social first.
pub open spec fn aux_rooms_social(s: State, sc: Set<int>) -> bool {
    s.pc == ph_rooms() ==> s.social == social_root(sc, s.target)
}

/// Auxiliary: the apply phase only follows a complete publication pair.
pub open spec fn aux_apply(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    s.pc == ph_apply() ==> (s.social == social_root(sc, s.target) && s.rooms == rooms_root(
        rc,
        s.target,
    ))
}

/// Auxiliary: while replaying after a crash, the rooms root still trails the
/// social root by one step and the journal target stays below head.
pub open spec fn aux_social_rec(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    (s.recovering && s.pc == ph_social()) ==> (s.rooms == rooms_root(rc, s.target - 1)
        && s.target - 1 < s.journal_head && (s.social == social_root(sc, s.target - 1)
        || s.social == social_root(sc, s.target)))
}

/// Auxiliary: the same trailing-rooms fact inside the recovering rooms phase.
pub open spec fn aux_rooms_rec(s: State, rc: Set<int>) -> bool {
    (s.recovering && s.pc == ph_rooms()) ==> (s.rooms == rooms_root(rc, s.target - 1)
        && s.target <= s.journal_head)
}

/// Auxiliary: wherever an ack or a fresh decision can be recorded, the
/// captured app roots match the applied frontier and the durable roots have
/// covered it.
pub open spec fn aux_roots_cover(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    (s.pc == ph_idle() || s.pc == ph_respond() || (!s.recovering && (s.pc == ph_journal()
        || s.pc == ph_social() || s.pc == ph_rooms() || s.pc == ph_sar()))) ==> (s.app_social
        == social_root(sc, s.app.height) && s.app_rooms == rooms_root(rc, s.app.height)
        && s.social >= social_root(sc, s.app.height) && s.rooms >= rooms_root(rc, s.app.height))
}

/// Auxiliary: outside recovery the durable roots sit at head or one step
/// behind it — the publish pair is the only mover.
pub open spec fn aux_window(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    (!s.recovering && (s.pc == ph_idle() || s.pc == ph_journal() || s.pc == ph_social() || s.pc
        == ph_rooms() || s.pc == ph_sar() || s.pc == ph_apply() || s.pc == ph_ack() || s.pc
        == ph_respond())) ==> ((s.social == social_root(sc, s.journal_head) || s.social
        == social_root(sc, s.journal_head - 1)) && (s.rooms == rooms_root(rc, s.journal_head)
        || s.rooms == rooms_root(rc, s.journal_head - 1)))
}

/// Auxiliary: a rooms root strictly ahead of head-1 outside the flow means
/// the apply already happened — a stale redelivery can only re-ack, not
/// re-publish.
pub open spec fn aux_strict_app(s: State, rc: Set<int>) -> bool {
    (!s.recovering && (s.pc == ph_idle() || s.pc == ph_ack() || s.pc == ph_respond()) && s.rooms
        == rooms_root(rc, s.journal_head) && s.rooms != rooms_root(rc, s.journal_head - 1))
        ==> s.app.height == s.journal_head
}

/// Auxiliary: inside the publish phases the rooms root is never strictly at
/// head — it leads at most the social publish, which keeps the one-behind
/// compatible prefix available.
pub open spec fn aux_strict_social(s: State, rc: Set<int>) -> bool {
    (!s.recovering && (s.pc == ph_social() || s.pc == ph_rooms() || s.pc == ph_sar()) && s.rooms
        == rooms_root(rc, s.journal_head)) ==> s.rooms == rooms_root(rc, s.journal_head - 1)
}

/// Auxiliary: a non-recovery publish flow only runs while the application
/// still trails the durable head.
pub open spec fn aux_app_lt_head(s: State) -> bool {
    (!s.recovering && (s.pc == ph_social() || s.pc == ph_rooms() || s.pc == ph_sar()))
        ==> s.app.height < s.journal_head
}

/// Auxiliary: a caught-up idle or respond state has both roots at head —
/// nothing outside recovery can lower them once the apply has landed.
pub open spec fn aux_head_roots(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    ((s.pc == ph_idle() || s.pc == ph_respond()) && s.app.height == s.journal_head)
        ==> (s.social == social_root(sc, s.journal_head) && s.rooms == rooms_root(
        rc,
        s.journal_head,
    ))
}

/// Auxiliary: what an ack boundary can record — every conjunct TLC gets for
/// free by enumerating the reachable ack states.
pub open spec fn aux_ack(s: State, sc: Set<int>, rc: Set<int>) -> bool {
    (s.pc == ph_ack() || (s.pc == ph_respond() && s.outcome == o_acked())) ==> (s.value == map_at(
        s.journal,
        s.target,
    ) && s.app.height >= s.target && s.app_social == social_root(sc, s.app.height)
        && s.app_rooms == rooms_root(rc, s.app.height) && s.social >= social_root(sc, s.target)
        && s.rooms >= rooms_root(rc, s.target) && s.social >= social_root(sc, s.app.height)
        && s.rooms >= rooms_root(rc, s.app.height))
}

/// Auxiliary: the recovery phase only exists inside a crash.
pub open spec fn aux_recover_flag(s: State) -> bool {
    s.pc == ph_recover() ==> s.recovering
}

/// Auxiliary: the named phases are always outside a recovery pass.
pub open spec fn aux_not_rec(s: State) -> bool {
    (s.pc == ph_idle() || s.pc == ph_journal() || s.pc == ph_ack() || s.pc == ph_respond()
        || s.pc == ph_er()) ==> !s.recovering
}

/// Auxiliary: under the safe configuration nothing ever enters the modeled
/// engine restart (HostFailure always goes idle).
pub open spec fn aux_no_er(s: State) -> bool {
    s.pc != ph_er()
}

/// Auxiliary: "social-after-rooms" is equally unreachable — only the
/// RoomsBeforeSocial mutant produces it.
pub open spec fn aux_no_sar(s: State) -> bool {
    s.pc != ph_sar()
}

/// The inductive invariant: TypeOK plus the nine checked safety invariants,
/// strengthened by the auxiliaries.
pub open spec fn inv(sc: Set<int>, rc: Set<int>, s: State) -> bool {
    &&& type_ok(s)
    &&& committed_identity(s)
    &&& publication_order(s, sc, rc)
    &&& ack_after_durability(s, sc, rc)
    &&& ack_has_full_frontier(s, sc, rc)
    &&& failed_finalization_keeps_wal(s)
    &&& next_roster_inv(s)
    &&& recovered_frontier(s, sc, rc)
    &&& honest_recovery(s, sc, rc)
    &&& aux_journal_shape(s)
    &&& aux_original_shape(s)
    &&& aux_journal_state(s, sc, rc)
    &&& aux_app_wf(s, sc, rc)
    &&& aux_app_le_head(s)
    &&& aux_target_le(s)
    &&& aux_head_pos(s)
    &&& aux_value_journal(s)
    &&& aux_rooms_social(s, sc)
    &&& aux_apply(s, sc, rc)
    &&& aux_social_rec(s, sc, rc)
    &&& aux_rooms_rec(s, rc)
    &&& aux_roots_cover(s, sc, rc)
    &&& aux_window(s, sc, rc)
    &&& aux_strict_app(s, rc)
    &&& aux_strict_social(s, rc)
    &&& aux_app_lt_head(s)
    &&& aux_head_roots(s, sc, rc)
    &&& aux_ack(s, sc, rc)
    &&& aux_recover_flag(s)
    &&& aux_not_rec(s)
    &&& aux_no_er(s)
    &&& aux_no_sar(s)
}

// ---------------------------------------------------------------------------
// Base case and step
// ---------------------------------------------------------------------------

proof fn init_inv(sc: Set<int>, rc: Set<int>, s: State)
    requires
        init(s),
    ensures
        inv(sc, rc, s),
{
    assert(compatible_prefix(s, sc, rc, 0));
    assert forall|h: int| dom12().contains(h) implies is_jval(map_at(s.original, h)) by {
        assert(s.original.dom().contains(h));
    }
}

proof fn new_decision_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State, v: int)
    requires
        inv(sc, rc, pre),
        is_value(v),
        new_decision(pre, post, v),
    ensures
        inv(sc, rc, post),
{
    // aux_head_roots at the idle pre-state gives both roots at head; the
    // journal bundle at post follows directly.
    assert(pre.social == social_root(sc, pre.journal_head));
    assert(pre.rooms == rooms_root(rc, pre.journal_head));
    assert(post.social == social_root(sc, post.journal_head));
    assert(post.rooms == rooms_root(rc, post.journal_head));
    // PublicationOrder: roots and head unchanged, the old witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn redeliver_preserves(
    sc: Set<int>,
    rc: Set<int>,
    pre: State,
    post: State,
    h: int,
    v: int,
)
    requires
        inv(sc, rc, pre),
        1 <= h <= heights(),
        is_value(v),
        redeliver(pre, post, sc, rc, false, false, h, v),
    ensures
        inv(sc, rc, post),
{
    // pc branches under oi = false and roa = false:
    // v != journal[h] -> respond (Rejected); h <= app.height -> ack;
    // otherwise social.
    if v != map_at(pre.journal, h) {
        assert(post.pc == ph_respond());
    } else if h <= pre.app.height {
        // Redeliver -> ack: the bundle is inherited from the idle state.
        assert(post.pc == ph_ack());
        assert(post.value == map_at(post.journal, post.target));
        assert(post.app.height >= post.target);
        assert(post.app_social == social_root(sc, post.app.height));
        assert(post.app_rooms == rooms_root(rc, post.app.height));
        // social >= Social(app.height) >= Social(h); h <= app.height <= head.
        root_at_mono(h, pre.app.height, sc);
        root_at_mono(h, pre.app.height, rc);
        assert(post.social >= social_root(sc, post.target));
        assert(post.rooms >= rooms_root(rc, post.target));
    } else {
        assert(post.pc == ph_social());
        // h > app.height and h <= head give app.height < head and head >= 1.
        assert(pre.app.height < pre.journal_head);
        assert(pre.journal_head >= 1);
        // aux_strict_social: rooms = R(head) forces rooms = R(head-1),
        // because the strict case would have made the app caught up and the
        // ack branch would have been taken instead.
        if post.rooms == rooms_root(rc, post.journal_head) {
            if post.rooms == rooms_root(rc, post.journal_head - 1) {
            } else {
                // strict: rooms = R(head) != R(head-1) at idle implies
                // app.height = head (aux_strict_app), contradicting
                // app.height < h <= head.
                assert(pre.rooms == rooms_root(rc, pre.journal_head));
                assert(pre.rooms != rooms_root(rc, pre.journal_head - 1));
                assert(!pre.recovering);
                assert(pre.pc == ph_idle());
                assert(pre.app.height == pre.journal_head);
                assert(false);
            }
        }
        assert(post.value == map_at(post.journal, post.target));
        assert(post.app.height < post.journal_head);
        assert(post.social == social_root(sc, post.journal_head) || post.social == social_root(
            sc,
            post.journal_head - 1,
        ));
        assert(post.rooms == rooms_root(rc, post.journal_head) || post.rooms == rooms_root(
            rc,
            post.journal_head - 1,
        ));
        assert(post.social >= social_root(sc, post.app.height));
        assert(post.rooms >= rooms_root(rc, post.app.height));
    }
    // PublicationOrder: roots and head unchanged, the old witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn journal_commit_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        journal_commit(pre, post),
    ensures
        inv(sc, rc, post),
{
    // aux_journal_state: target = head + 1, app.height = head, roots at head.
    assert(pre.target == pre.journal_head + 1);
    assert(pre.app.height == pre.journal_head);
    assert(pre.social == social_root(sc, pre.journal_head));
    assert(pre.rooms == rooms_root(rc, pre.journal_head));

    // CommittedIdentity: the same entry goes to both maps.
    assert(post.journal =~= post.original) by {
        assert(post.journal =~= pre.journal.insert(pre.target, pre.value));
        assert(post.original =~= pre.original.insert(pre.target, pre.value));
        assert(pre.journal =~= pre.original);
    }

    // journal_shape / original_shape at the new head.
    assert forall|h: int| dom12().contains(h) implies is_jval(map_at(post.original, h)) by {
        map_insert_at(pre.original, pre.target, pre.value, h);
    }
    assert forall|h: int| dom12().contains(h) implies if h <= post.journal_head {
        is_value(map_at(post.journal, h))
    } else {
        map_at(post.journal, h) == v_none()
    } by {
        map_insert_at(pre.journal, pre.target, pre.value, h);
        if h <= post.journal_head {
            if h == post.journal_head {
            } else {
                assert(h <= pre.journal_head);
            }
        } else {
            assert(h > pre.journal_head);
        }
    }
    assert forall|h: int| dom12().contains(h) implies is_jval(map_at(post.journal, h)) by {
        map_insert_at(pre.journal, pre.target, pre.value, h);
    }

    // app_wf: app.height < target, so the insert does not touch its entry.
    assert(post.app == at(post, sc, rc, post.app.height)) by {
        map_insert_at(pre.journal, pre.target, pre.value, pre.app.height);
        assert(pre.app.height != pre.target);
    }

    // roots_cover at the new social state (unchanged app fields).
    root_at_mono(pre.app.height, pre.journal_head, sc);
    root_at_mono(pre.app.height, pre.journal_head, rc);

    // window at the new social state: roots sit one step behind the new head.
    assert(post.social == social_root(sc, post.journal_head - 1));
    assert(post.rooms == rooms_root(rc, post.journal_head - 1));

    // PublicationOrder with the new head: p = old head, since rooms = R(head-1)
    // and social = S(head-1) == S(p).
    assert(compatible_prefix(post, sc, rc, pre.journal_head)) by {
        assert(post.rooms == rooms_root(rc, pre.journal_head));
        assert(post.social == social_root(sc, pre.journal_head));
    }
}

proof fn publish_social_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        publish_social(pre, post, sc),
    ensures
        inv(sc, rc, post),
{
    // The recovering case replays toward head; otherwise the normal flow.
    // aux_no_sar rules out the sar disjunct under the safe configuration.
    assert(pre.pc != ph_sar());
    if pre.recovering {
        // social_rec gives rooms = R(target-1), target-1 < head, and the
        // social disjunction; post.pc = rooms and rec still holds.
        assert(pre.pc == ph_social());
        assert(pre.rooms == rooms_root(rc, pre.target - 1));
        assert(pre.target - 1 < pre.journal_head);
        assert(post.rooms == rooms_root(rc, post.target - 1));
        assert(post.target <= post.journal_head);
        // PublicationOrder: p = target - 1.
        assert(compatible_prefix(post, sc, rc, pre.target - 1)) by {
            assert(post.rooms == rooms_root(rc, pre.target - 1));
            assert(post.social == social_root(sc, pre.target));
            assert(pre.target - 1 < post.journal_head);
            assert(post.social == social_root(sc, pre.target - 1 + 1));
        }
    } else {
        // Non-recovering publish from the social phase.
        assert(pre.pc == ph_social());
        // window + strict_social: rooms = R(head-1).
        assert(pre.rooms == rooms_root(rc, pre.journal_head) || pre.rooms == rooms_root(
            rc,
            pre.journal_head - 1,
        ));
        if pre.rooms == rooms_root(rc, pre.journal_head) {
            assert(pre.rooms == rooms_root(rc, pre.journal_head - 1));
        }
        assert(pre.rooms == rooms_root(rc, pre.journal_head - 1));
        // head >= 1, target in {head-1, head}.
        assert(pre.journal_head >= 1);
        assert(pre.target <= pre.journal_head);
        assert(pre.target == pre.journal_head || pre.target == pre.journal_head - 1);
        // PublicationOrder witness p = head - 1: rooms = R(head-1), and
        // social' = S(target) = S(p) or S(p+1).
        assert(compatible_prefix(post, sc, rc, pre.journal_head - 1)) by {
            assert(post.rooms == rooms_root(rc, pre.journal_head - 1));
            if pre.target == pre.journal_head - 1 {
                assert(post.social == social_root(sc, pre.journal_head - 1));
            } else {
                assert(post.social == social_root(sc, pre.journal_head));
                assert(post.social == social_root(sc, pre.journal_head - 1 + 1));
            }
        }
        // window: social' = S(target) with target in {head, head-1}.
        assert(post.social == social_root(sc, post.journal_head) || post.social == social_root(
            sc,
            post.journal_head - 1,
        ));
        // rooms stays within the window; strict_social is inherited.
        assert(post.rooms == rooms_root(rc, post.journal_head - 1));
        // roots_cover: social' = S(target) >= S(app.height); app.height < head
        // and target >= head - 1 give app.height <= target.
        assert(pre.app.height < pre.journal_head);
        assert(pre.app.height <= pre.target);
        root_at_mono(pre.app.height, pre.target, sc);
        root_at_mono(pre.app.height, pre.target, rc);
        assert(post.social >= social_root(sc, post.app.height));
        assert(post.rooms >= rooms_root(rc, post.app.height));
        // aux_rooms_social at the new rooms state.
        assert(post.social == social_root(sc, post.target));
    }
}

proof fn publish_rooms_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        publish_rooms(pre, post, rc, false),
    ensures
        inv(sc, rc, post),
{
    // rbs = false: only the rooms phase can fire, so post.pc = apply.
    assert(pre.pc == ph_rooms());
    assert(post.pc == ph_apply());
    // aux_rooms_social gives social = S(target); aux_apply follows.
    assert(post.social == social_root(sc, post.target));
    assert(post.rooms == rooms_root(rc, post.target));
    // PublicationOrder: p = target is now fully compatible.
    assert(pre.target <= pre.journal_head);
    assert(compatible_prefix(post, sc, rc, pre.target));
    // window at apply: social = S(target), rooms = R(target), target in
    // {head, head-1} because 1 <= target <= head <= 2.
    assert(pre.target == pre.journal_head || pre.target == pre.journal_head - 1);
    assert(post.social == social_root(sc, post.journal_head) || post.social == social_root(
        sc,
        post.journal_head - 1,
    ));
    assert(post.rooms == rooms_root(rc, post.journal_head) || post.rooms == rooms_root(
        rc,
        post.journal_head - 1,
    ));
}

proof fn apply_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        apply_step(pre, post, sc, rc),
    ensures
        inv(sc, rc, post),
{
    // aux_apply: social = S(target), rooms = R(target); aux_target_le: target <= head.
    assert(pre.social == social_root(sc, pre.target));
    assert(pre.rooms == rooms_root(rc, pre.target));
    assert(pre.target <= pre.journal_head);
    assert(pre.value == map_at(pre.journal, pre.target));
    assert(pre.target == pre.journal_head || pre.target == pre.journal_head - 1);
    if !pre.recovering {
        // post.pc = ack: every aux_ack conjunct follows from the apply bundle.
        assert(post.pc == ph_ack());
        assert(post.value == map_at(post.journal, post.target));
        assert(post.app.height == pre.target);
        assert(post.app_social == social_root(sc, post.app.height));
        assert(post.app_rooms == rooms_root(rc, post.app.height));
        assert(post.social >= social_root(sc, post.target));
        assert(post.rooms >= rooms_root(rc, post.target));
        // app_wf and window at the new ack state.
        assert(post.app == at(post, sc, rc, post.app.height));
        assert(post.social == social_root(sc, post.journal_head) || post.social == social_root(
            sc,
            post.journal_head - 1,
        ));
        assert(post.rooms == rooms_root(rc, post.journal_head) || post.rooms == rooms_root(
            rc,
            post.journal_head - 1,
        ));
        // strict_app at ack: rooms = R(head) strict means target = head.
        if post.rooms == rooms_root(rc, post.journal_head) && post.rooms != rooms_root(
            rc,
            post.journal_head - 1,
        ) {
            // rooms = R(target): strict means target != head - 1.
            root_at_mono(pre.target, pre.journal_head, rc);
            if pre.target == pre.journal_head - 1 {
                assert(false);
            }
            assert(pre.target == pre.journal_head);
            assert(post.app.height == post.journal_head);
        }
    } else if pre.target < pre.journal_head {
        // Replay continues: post.pc = social, target' = target + 1.
        assert(post.pc == ph_social());
        assert(post.rooms == rooms_root(rc, pre.target));
        assert(post.rooms == rooms_root(rc, post.target - 1));
        assert(post.target - 1 < post.journal_head);
        assert(post.social == social_root(sc, post.target - 1));
        assert(post.value == map_at(post.journal, post.target));
        assert(post.app == at(post, sc, rc, post.app.height));
    } else {
        // Replay done: post.pc = recovery-check with the honest bundle.
        assert(post.pc == ph_rcc());
        assert(pre.target == pre.journal_head);
        assert(post.app == at(post, sc, rc, post.journal_head));
        assert(post.app_social == post.social);
        assert(post.app_rooms == post.rooms);
        assert(post.social == social_root(sc, post.journal_head));
        assert(post.rooms == rooms_root(rc, post.journal_head));
        assert(post.app == at(post, sc, rc, post.app.height));
    }
    // PublicationOrder: roots unchanged, the old witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn acknowledge_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        acknowledge(pre, post, false),
    ensures
        inv(sc, rc, post),
{
    // ea = false: only pc = ack fires.
    assert(pre.pc == ph_ack());
    let na = Ack {
        height: pre.target,
        value: pre.value,
        journal_head: pre.journal_head,
        committed_value: map_at(pre.journal, pre.target),
        app: pre.app,
        applied_value: if pre.app.height == 0 {
            v_genesis()
        } else {
            map_at(pre.journal, pre.app.height)
        },
        social: pre.social,
        rooms: pre.rooms,
        app_social: pre.app_social,
        app_rooms: pre.app_rooms,
    };
    assert(post.acks =~= pre.acks.insert(na));
    // The new ack satisfies both ack invariants via aux_ack and app_wf.
    assert(na.height <= na.journal_head);
    assert(na.value == na.committed_value);
    assert(na.social >= social_root(sc, na.height));
    assert(na.rooms >= rooms_root(rc, na.height));
    assert(na.app.height >= na.height);
    assert(na.app_social == na.app.social) by {
        assert(pre.app_social == social_root(sc, pre.app.height));
        assert(na.app == frontier(sc, rc, na.app.height, na.applied_value)) by {
            assert(pre.app == at(pre, sc, rc, pre.app.height));
        }
    }
    assert(na.app == frontier(sc, rc, na.app.height, na.applied_value));
    assert forall|a: Ack| post.acks.contains(a) implies (a.height <= a.journal_head && a.value
        == a.committed_value && a.social >= social_root(sc, a.height) && a.rooms >= rooms_root(
        rc,
        a.height,
    )) by {
        if a != na {
            assert(pre.acks.contains(a));
        }
    }
    assert forall|a: Ack| post.acks.contains(a) implies (a.app.height >= a.height && a.app
        == frontier(sc, rc, a.app.height, a.applied_value) && a.app_social == a.app.social
        && a.app_rooms == a.app.registry) by {
        if a != na {
            assert(pre.acks.contains(a));
        } else {
            assert(na.app_rooms == na.app.registry);
        }
    }
    // aux_ack carries over to the new respond state, and roots_cover picks up
    // the app-cover facts too.
    assert(post.value == map_at(post.journal, post.target));
    assert(post.app.height >= post.target);
    assert(post.social >= social_root(sc, post.target));
    assert(post.rooms >= rooms_root(rc, post.target));
    assert(post.app_social == social_root(sc, post.app.height));
    assert(post.app_rooms == rooms_root(rc, post.app.height));
    assert(post.social >= social_root(sc, post.app.height));
    assert(post.rooms >= rooms_root(rc, post.app.height));
    // window, strict_app and head_roots transfer unchanged through respond.
    assert(post.social == social_root(sc, post.journal_head) || post.social == social_root(
        sc,
        post.journal_head - 1,
    ));
    assert(post.rooms == rooms_root(rc, post.journal_head) || post.rooms == rooms_root(
        rc,
        post.journal_head - 1,
    ));
    if post.app.height == post.journal_head {
        // head_roots at respond: social >= S(app.height) = S(head) and the
        // window pin social to S(head).
        assert(post.social >= social_root(sc, post.app.height));
        root_at_mono(post.journal_head - 1, post.journal_head, sc);
        root_at_mono(post.journal_head - 1, post.journal_head, rc);
        assert(post.social == social_root(sc, post.journal_head));
        assert(post.rooms == rooms_root(rc, post.journal_head));
    }
    // PublicationOrder: unchanged roots, witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn fail_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        fail(pre, post),
    ensures
        inv(sc, rc, post),
{
    // respond keeps every field; the auxiliaries are re-established from the
    // corresponding facts at the flow phase.
    if pre.pc == ph_journal() {
        // journal_state: app.height = head, roots at head.
        assert(pre.rooms == rooms_root(rc, pre.journal_head));
        assert(pre.social == social_root(sc, pre.journal_head));
        assert(pre.app.height == pre.journal_head);
    } else {
        // social/rooms/sar: app.height < head (aux_app_lt_head) and the
        // strict case for rooms is excluded (aux_strict_social), so
        // rooms = R(head-1) and app.height <= head-1.
        assert(pre.app.height < pre.journal_head);
        assert(pre.rooms == rooms_root(rc, pre.journal_head) || pre.rooms == rooms_root(
            rc,
            pre.journal_head - 1,
        ));
        if pre.rooms == rooms_root(rc, pre.journal_head) {
            assert(pre.rooms == rooms_root(rc, pre.journal_head - 1));
        }
        assert(pre.rooms == rooms_root(rc, pre.journal_head - 1));
        root_at_mono(pre.app.height, pre.journal_head - 1, rc);
        // social covers S(app.height): social is S(head) or S(head-1), both
        // >= S(head-1) >= S(app.height) since app.height <= head-1.
        assert(pre.social == social_root(sc, pre.journal_head) || pre.social == social_root(
            sc,
            pre.journal_head - 1,
        ));
        root_at_mono(pre.app.height, pre.journal_head - 1, sc);
        root_at_mono(pre.journal_head - 1, pre.journal_head, sc);
        assert(pre.social >= social_root(sc, pre.journal_head - 1));
        assert(pre.social >= social_root(sc, pre.app.height));
        assert(pre.rooms >= rooms_root(rc, pre.app.height));
    }
    // PublicationOrder: unchanged roots, witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn host_success_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        host_success(pre, post, false),
    ensures
        inv(sc, rc, post),
{
    let ns = Start { decided: pre.target, height: pre.target + 1, roster: roster(pre.target + 1) };
    assert(post.starts =~= pre.starts.insert(ns));
    assert(ns.height == ns.decided + 1);
    assert(ns.roster == roster(ns.height));
    assert forall|n: Start| post.starts.contains(n) implies (n.height == n.decided + 1
        && n.roster == roster(n.height)) by {
        if n != ns {
            assert(pre.starts.contains(n));
        }
    }
    // wal: ¬released_wal' implies ¬released_wal and target != 1, so wal' = wal.
    if !post.released_wal {
        assert(!pre.released_wal);
        assert(pre.target != 1);
        assert(post.wal =~= pre.wal);
    }
    // The idle auxiliaries are inherited from the respond state.
    assert(post.app_social == social_root(sc, post.app.height));
    assert(post.app_rooms == rooms_root(rc, post.app.height));
    assert(post.social >= social_root(sc, post.app.height));
    assert(post.rooms >= rooms_root(rc, post.app.height));
    assert(post.social == social_root(sc, post.journal_head) || post.social == social_root(
        sc,
        post.journal_head - 1,
    ));
    assert(post.rooms == rooms_root(rc, post.journal_head) || post.rooms == rooms_root(
        rc,
        post.journal_head - 1,
    ));
    if post.app.height == post.journal_head {
        assert(post.social == social_root(sc, post.journal_head));
        assert(post.rooms == rooms_root(rc, post.journal_head));
    }
    // PublicationOrder: unchanged roots, witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn host_failure_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        host_failure(pre, post, false),
    ensures
        inv(sc, rc, post),
{
    // rof = false: post.pc = idle; everything else is unchanged, and the
    // respond auxiliaries carry over verbatim.
    assert(post.app_social == social_root(sc, post.app.height));
    assert(post.app_rooms == rooms_root(rc, post.app.height));
    assert(post.social >= social_root(sc, post.app.height));
    assert(post.rooms >= rooms_root(rc, post.app.height));
    assert(post.social == social_root(sc, post.journal_head) || post.social == social_root(
        sc,
        post.journal_head - 1,
    ));
    assert(post.rooms == rooms_root(rc, post.journal_head) || post.rooms == rooms_root(
        rc,
        post.journal_head - 1,
    ));
    if post.app.height == post.journal_head {
        assert(post.social == social_root(sc, post.journal_head));
        assert(post.rooms == rooms_root(rc, post.journal_head));
    }
    // PublicationOrder: unchanged roots, witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn engine_restart_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        engine_restart(pre, post),
    ensures
        inv(sc, rc, post),
{
    // aux_no_er makes the guard unsatisfiable under inv(pre).
    assert(false);
}

proof fn interrupt_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        interrupt(pre, post),
    ensures
        inv(sc, rc, post),
{
    // PublicationOrder: roots and head unchanged, witness persists.
    let w = choose|p: int| 0 <= p <= pre.journal_head && compatible_prefix(pre, sc, rc, p);
    assert(compatible_prefix(post, sc, rc, w));
    // app_wf at genesis.
    assert(post.app == at(post, sc, rc, post.app.height));
}

proof fn load_prefix_preserves(
    sc: Set<int>,
    rc: Set<int>,
    pre: State,
    post: State,
    p: int,
)
    requires
        inv(sc, rc, pre),
        0 <= p <= heights(),
        load_prefix(pre, post, sc, rc, false, p),
    ensures
        inv(sc, rc, post),
{
    // ir = false. pre.pc = recover implies recovering (aux_recover_flag).
    assert(pre.recovering);
    assert(pre.rooms == rooms_root(rc, p));
    if p < pre.journal_head {
        // post.pc = social with the recovering bundle.
        assert(post.pc == ph_social());
        assert(post.target == p + 1);
        assert(post.rooms == rooms_root(rc, post.target - 1));
        assert(post.target - 1 < post.journal_head);
        // CompatiblePrefix gives the social disjunction at p.
        assert(pre.social == social_root(sc, p) || pre.social == social_root(sc, p + 1));
        assert(post.social == social_root(sc, post.target - 1) || post.social == social_root(
            sc,
            post.target,
        ));
        assert(post.value == map_at(post.journal, post.target));
        assert(post.app == at(post, sc, rc, post.app.height));
    } else {
        // p = head: post.pc = recovery-check; CompatiblePrefix(head) forces
        // the unsplit roots, giving the whole honest bundle.
        assert(post.pc == ph_rcc());
        assert(p == pre.journal_head);
        assert(pre.social == social_root(sc, p));
        assert(post.app == at(post, sc, rc, post.journal_head));
        assert(post.social == social_root(sc, post.journal_head));
        assert(post.rooms == rooms_root(rc, post.journal_head));
        assert(post.app_social == post.social);
        assert(post.app_rooms == post.rooms);
        assert(post.app == at(post, sc, rc, post.app.height));
        if p == 0 {
            assert(post.target == 1);
            assert(post.value == v_a());
        } else {
            assert(post.target == p);
            assert(post.value == map_at(pre.journal, p));
            assert(is_value(map_at(pre.journal, p)));
        }
    }
    // PublicationOrder: roots and head unchanged, witness persists.
    let w = choose|q: int| 0 <= q <= pre.journal_head && compatible_prefix(pre, sc, rc, q);
    assert(compatible_prefix(post, sc, rc, w));
}

proof fn recovery_refuse_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        recovery_refuse(pre, post, sc, rc, false),
    ensures
        inv(sc, rc, post),
{
    // publication_order gives a compatible prefix, so the refuse guard's
    // first disjunct fails; ir = false kills the second.
    assert(false);
}

proof fn recovery_ready_preserves(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        recovery_ready(pre, post, sc, rc),
    ensures
        inv(sc, rc, post),
{
    // honest_recovery at the pre state supplies the whole bundle.
    assert(pre.app == at(pre, sc, rc, pre.journal_head));
    assert(pre.app_social == pre.social);
    assert(pre.app_rooms == pre.rooms);
    assert(pre.social == social_root(sc, pre.journal_head));
    assert(pre.rooms == rooms_root(rc, pre.journal_head));
    assert(pre.app.height == pre.journal_head);
    let nr = Reopened {
        frontier: pre.app,
        head: pre.journal_head,
        value: if pre.journal_head == 0 {
            v_genesis()
        } else {
            map_at(pre.journal, pre.journal_head)
        },
        social: pre.social,
        rooms: pre.rooms,
    };
    assert(nr.frontier == frontier(sc, rc, nr.head, nr.value)) by {
        assert(pre.app == at(pre, sc, rc, pre.app.height));
    }
    assert(nr.social == social_root(sc, nr.head));
    assert(nr.rooms == rooms_root(rc, nr.head));
    assert forall|r: Reopened| post.reopened.contains(r) implies (r.frontier == frontier(
        sc,
        rc,
        r.head,
        r.value,
    ) && r.social == social_root(sc, r.head) && r.rooms == rooms_root(rc, r.head)) by {
        if r != nr {
            assert(pre.reopened.contains(r));
        }
    }
    // roots_cover / window / head_roots at the new idle state all follow the
    // bundle; app.height = head makes the strict and head cases immediate.
    assert(pre.app.height == pre.journal_head);
    assert(post.app_social == social_root(sc, post.app.height));
    assert(post.app_rooms == rooms_root(rc, post.app.height));
    assert(post.social >= social_root(sc, post.app.height));
    assert(post.rooms >= rooms_root(rc, post.app.height));
    assert(post.social == social_root(sc, post.journal_head));
    assert(post.rooms == rooms_root(rc, post.journal_head));
    // PublicationOrder: p = head is compatible since social = S(head) and
    // rooms = R(head).
    assert(compatible_prefix(post, sc, rc, post.journal_head)) by {
        assert(post.rooms == rooms_root(rc, post.journal_head));
        assert(post.social == social_root(sc, post.journal_head));
    }
}

proof fn step_inv(sc: Set<int>, rc: Set<int>, pre: State, post: State)
    requires
        inv(sc, rc, pre),
        next_safe(sc, rc, pre, post),
    ensures
        inv(sc, rc, post),
{
    if journal_commit(pre, post) {
        journal_commit_preserves(sc, rc, pre, post);
    } else if publish_social(pre, post, sc) {
        publish_social_preserves(sc, rc, pre, post);
    } else if publish_rooms(pre, post, rc, false) {
        publish_rooms_preserves(sc, rc, pre, post);
    } else if apply_step(pre, post, sc, rc) {
        apply_preserves(sc, rc, pre, post);
    } else if acknowledge(pre, post, false) {
        acknowledge_preserves(sc, rc, pre, post);
    } else if fail(pre, post) {
        fail_preserves(sc, rc, pre, post);
    } else if host_success(pre, post, false) {
        host_success_preserves(sc, rc, pre, post);
    } else if host_failure(pre, post, false) {
        host_failure_preserves(sc, rc, pre, post);
    } else if engine_restart(pre, post) {
        engine_restart_preserves(sc, rc, pre, post);
    } else if recovery_refuse(pre, post, sc, rc, false) {
        recovery_refuse_preserves(sc, rc, pre, post);
    } else if recovery_ready(pre, post, sc, rc) {
        recovery_ready_preserves(sc, rc, pre, post);
    } else if interrupt(pre, post) {
        interrupt_preserves(sc, rc, pre, post);
    } else if exists|v: int| is_value(v) && new_decision(pre, post, v) {
        let v = choose|v: int| is_value(v) && new_decision(pre, post, v);
        new_decision_preserves(sc, rc, pre, post, v);
    } else if exists|h: int, v: int|
        1 <= h <= heights() && is_value(v) && redeliver(pre, post, sc, rc, false, false, h, v) {
        let hv = choose|h: int, v: int|
            1 <= h <= heights() && is_value(v) && redeliver(pre, post, sc, rc, false, false, h, v);
        redeliver_preserves(sc, rc, pre, post, hv.0, hv.1);
    } else {
        let p = choose|p: int|
            0 <= p <= heights() && load_prefix(pre, post, sc, rc, false, p);
        load_prefix_preserves(sc, rc, pre, post, p);
    }
}

// ---------------------------------------------------------------------------
// Traces
// ---------------------------------------------------------------------------

/// Every finite execution under arbitrary safe schedules satisfies inv.
/// Covers normal.cfg, root-preserving.cfg, social-only.cfg and
/// two-changing.cfg by instantiation.
pub open spec fn is_trace(sc: Set<int>, rc: Set<int>, t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_safe(sc, rc, t[i], t[i + 1])
}

pub open spec fn is_cfg_trace(
    sc: Set<int>,
    rc: Set<int>,
    roa: bool,
    ea: bool,
    oi: bool,
    rof: bool,
    wnr: bool,
    rbs: bool,
    ir: bool,
    t: Seq<State>,
) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int|
        0 <= i < t.len() - 1 ==> #[trigger] next_cfg(
            sc,
            rc,
            roa,
            ea,
            oi,
            rof,
            wnr,
            rbs,
            ir,
            t[i],
            t[i + 1],
        )
}

pub open spec fn is_early_ack_trace(t: Seq<State>) -> bool {
    is_cfg_trace(ch_1(), ch_1(), false, true, false, false, false, false, false, t)
}

pub open spec fn is_failed_restart_trace(t: Seq<State>) -> bool {
    is_cfg_trace(ch_1(), ch_1(), false, false, false, true, false, false, false, t)
}

pub open spec fn is_identity_trace(t: Seq<State>) -> bool {
    is_cfg_trace(ch_1(), ch_1(), false, false, true, false, false, false, false, t)
}

pub open spec fn is_independent_roots_trace(t: Seq<State>) -> bool {
    is_cfg_trace(ch_1(), ch_none(), false, false, false, false, false, false, true, t)
}

pub open spec fn is_next_roster_trace(t: Seq<State>) -> bool {
    is_cfg_trace(ch_1(), ch_1(), false, false, false, false, true, false, false, t)
}

pub open spec fn is_publication_order_trace(t: Seq<State>) -> bool {
    is_cfg_trace(ch_1(), ch_1(), false, false, false, false, false, true, false, t)
}

pub open spec fn is_roots_only_trace(t: Seq<State>) -> bool {
    is_cfg_trace(ch_none(), ch_none(), true, false, false, false, false, false, false, t)
}

proof fn trace_satisfies_inv(sc: Set<int>, rc: Set<int>, t: Seq<State>)
    requires
        is_trace(sc, rc, t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(sc, rc, t[i]),
    decreases t.len(),
{
    if t.len() > 1 {
        let prefix = t.drop_last();
        assert(is_trace(sc, rc, prefix)) by {
            assert forall|i: int| 0 <= i < prefix.len() - 1 implies #[trigger] next_safe(
                sc,
                rc,
                prefix[i],
                prefix[i + 1],
            ) by {
                assert(prefix[i] == t[i]);
                assert(prefix[i + 1] == t[i + 1]);
                assert(next_safe(sc, rc, t[i], t[i + 1]));
            }
        }
        trace_satisfies_inv(sc, rc, prefix);
        assert forall|i: int| 0 <= i < t.len() implies inv(sc, rc, t[i]) by {
            if i == t.len() - 1 {
                let k = i - 1;
                assert(prefix[k] == t[k]);
                assert(inv(sc, rc, prefix[k]));
                assert(next_safe(sc, rc, t[k], t[k + 1]));
                assert(t[k + 1] == t[i]);
                step_inv(sc, rc, t[k], t[i]);
            } else {
                assert(prefix[i] == t[i]);
                assert(inv(sc, rc, prefix[i]));
            }
        }
    } else {
        init_inv(sc, rc, t[0]);
        assert forall|i: int| 0 <= i < t.len() implies inv(sc, rc, t[i]) by {
            assert(i == 0);
        }
    }
}

/// The four positive configurations, named for the record.
pub open spec fn is_normal_trace(t: Seq<State>) -> bool {
    is_trace(ch_1(), ch_1(), t)
}

pub open spec fn is_root_preserving_trace(t: Seq<State>) -> bool {
    is_trace(ch_none(), ch_none(), t)
}

pub open spec fn is_social_only_trace(t: Seq<State>) -> bool {
    is_trace(ch_1(), ch_none(), t)
}

pub open spec fn is_two_changing_trace(t: Seq<State>) -> bool {
    is_trace(ch_12(), ch_12(), t)
}

proof fn normal_trace_satisfies_inv(t: Seq<State>)
    requires
        is_normal_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(ch_1(), ch_1(), t[i]),
{
    trace_satisfies_inv(ch_1(), ch_1(), t);
}

proof fn root_preserving_trace_satisfies_inv(t: Seq<State>)
    requires
        is_root_preserving_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(ch_none(), ch_none(), t[i]),
{
    trace_satisfies_inv(ch_none(), ch_none(), t);
}

proof fn social_only_trace_satisfies_inv(t: Seq<State>)
    requires
        is_social_only_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(ch_1(), ch_none(), t[i]),
{
    trace_satisfies_inv(ch_1(), ch_none(), t);
}

proof fn two_changing_trace_satisfies_inv(t: Seq<State>)
    requires
        is_two_changing_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(ch_12(), ch_12(), t[i]),
{
    trace_satisfies_inv(ch_12(), ch_12(), t);
}

// ---------------------------------------------------------------------------
// Mutant counterexample proofs
// ---------------------------------------------------------------------------

/// The concrete initial state.
pub open spec fn init_state() -> State {
    State {
        pc: ph_idle(),
        journal_head: 0,
        journal: Map::new(dom12(), |_h: int| v_none()),
        original: Map::new(dom12(), |_h: int| v_none()),
        social: 0,
        rooms: 0,
        app: genesis_frontier(),
        app_social: 0,
        app_rooms: 0,
        target: 1,
        value: v_a(),
        outcome: o_none(),
        recovering: false,
        crashes: 0,
        acks: Set::empty(),
        starts: Set::empty(),
        reopened: Set::empty(),
        wal: evidence(),
        released_wal: false,
    }
}

/// mutant-early-ack: NewDecision -> Acknowledge before the journal write
/// lands an ack whose height leads its own journalHead.
proof fn mutant_early_ack_violates()
    ensures
        exists|t: Seq<State>| is_early_ack_trace(t) && !ack_after_durability(
            t.last(),
            ch_1(),
            ch_1(),
        ),
{
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let na = Ack {
        height: 1,
        value: v_a(),
        journal_head: 0,
        committed_value: v_none(),
        app: genesis_frontier(),
        applied_value: v_genesis(),
        social: 0,
        rooms: 0,
        app_social: 0,
        app_rooms: 0,
    };
    let s2 = State { pc: ph_respond(), outcome: o_acked(), acks: Set::empty().insert(na), ..s1 };
    assert(init(s0));
    assert(next_cfg(ch_1(), ch_1(), false, true, false, false, false, false, false, s0, s1)) by {
        assert(new_decision(s0, s1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, true, false, false, false, false, false, s1, s2)) by {
        assert(acknowledge(s1, s2, true));
        assert(s2.acks =~= s1.acks.insert(na));
    }
    assert(!ack_after_durability(s2, ch_1(), ch_1())) by {
        assert(s2.acks.contains(na));
        assert(na.height == 1 && na.journal_head == 0);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_early_ack_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_cfg(
            ch_1(),
            ch_1(),
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_early_ack_trace(t) && !ack_after_durability(t.last(), ch_1(), ch_1()));
}

/// mutant-failed-restart: NewDecision -> Fail -> HostFailure (RestartOnFailure)
/// -> EngineRestart drops the height-1 WAL while releasedWal stays false.
proof fn mutant_failed_restart_violates()
    ensures
        exists|t: Seq<State>| is_failed_restart_trace(t) && !failed_finalization_keeps_wal(
            t.last(),
        ),
{
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let s2 = State { pc: ph_respond(), outcome: o_withheld(), ..s1 };
    let s3 = State { pc: ph_er(), ..s2 };
    let s4 = State { pc: ph_idle(), wal: Set::empty(), ..s3 };
    assert(init(s0));
    assert(next_cfg(ch_1(), ch_1(), false, false, false, true, false, false, false, s0, s1)) by {
        assert(new_decision(s0, s1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, true, false, false, false, s1, s2)) by {
        assert(fail(s1, s2));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, true, false, false, false, s2, s3)) by {
        assert(host_failure(s2, s3, true));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, true, false, false, false, s3, s4)) by {
        assert(engine_restart(s3, s4));
    }
    assert(!failed_finalization_keeps_wal(s4)) by {
        assert(!s4.released_wal);
        assert(!(s4.wal =~= evidence())) by {
            assert(evidence().contains(1));
            assert(!s4.wal.contains(1));
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_failed_restart_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_cfg(
            ch_1(),
            ch_1(),
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_failed_restart_trace(t) && !failed_finalization_keeps_wal(t.last()));
}

/// mutant-identity: commit "a" at height 1, withhold, then redeliver "b";
/// OverwriteIdentity rewrites the durable journal without touching original.
proof fn mutant_identity_violates()
    ensures
        exists|t: Seq<State>| is_identity_trace(t) && !committed_identity(t.last()),
{
    let j_n = Map::new(dom12(), |_h: int| v_none());
    let j_a = j_n.insert(1, v_a());
    let j_b = j_n.insert(1, 2);
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let s2 = State {
        pc: ph_social(),
        journal_head: 1,
        journal: j_a,
        original: j_a,
        ..s1
    };
    let s3 = State { pc: ph_respond(), outcome: o_withheld(), ..s2 };
    let s4 = State { pc: ph_idle(), ..s3 };
    let s5 = State {
        pc: ph_respond(),
        journal: j_b,
        value: 2,
        outcome: o_rejected(),
        ..s4
    };
    assert(init(s0));
    assert(next_cfg(ch_1(), ch_1(), false, false, true, false, false, false, false, s0, s1)) by {
        assert(new_decision(s0, s1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, true, false, false, false, false, s1, s2)) by {
        assert(journal_commit(s1, s2));
        assert(s2.journal =~= s1.journal.insert(1, v_a()));
        assert(s2.original =~= s1.original.insert(1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, true, false, false, false, false, s2, s3)) by {
        assert(fail(s2, s3));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, true, false, false, false, false, s3, s4)) by {
        assert(host_failure(s3, s4, false));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, true, false, false, false, false, s4, s5)) by {
        assert(redeliver(s4, s5, ch_1(), ch_1(), true, false, 1, 2)) by {
            assert(map_at(s4.journal, 1) == v_a());
        }
        assert(s5.journal =~= s4.journal.insert(1, 2));
    }
    assert(!committed_identity(s5)) by {
        assert(!(s5.journal =~= s5.original)) by {
            assert(s5.journal[1] == 2);
            assert(s5.original[1] == v_a());
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5);
    assert(is_identity_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_cfg(
            ch_1(),
            ch_1(),
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4);
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5
            );
        }
    }
    assert(t.last() == s5);
    assert(is_identity_trace(t) && !committed_identity(t.last()));
}

/// mutant-independent-roots: after a social-changing commit and a crash,
/// RoomsChanges = {} makes the rooms root match height 1 while social still
/// matches 0; the skew check refuses the honest cut into "blocked".
proof fn mutant_independent_roots_violates()
    ensures
        exists|t: Seq<State>| is_independent_roots_trace(t) && !honest_recovery(
            t.last(),
            ch_1(),
            ch_none(),
        ),
{
    let j_n = Map::new(dom12(), |_h: int| v_none());
    let j_a = j_n.insert(1, v_a());
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let s2 = State {
        pc: ph_social(),
        journal_head: 1,
        journal: j_a,
        original: j_a,
        ..s1
    };
    let s3 = State {
        pc: ph_recover(),
        app: genesis_frontier(),
        app_social: 0,
        app_rooms: 0,
        recovering: true,
        crashes: 1,
        ..s2
    };
    let s4 = State { pc: ph_blocked(), ..s3 };
    assert(init(s0));
    assert(next_cfg(ch_1(), ch_none(), false, false, false, false, false, false, true, s0, s1)) by {
        assert(new_decision(s0, s1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_none(), false, false, false, false, false, false, true, s1, s2)) by {
        assert(journal_commit(s1, s2));
        assert(s2.journal =~= s1.journal.insert(1, v_a()));
        assert(s2.original =~= s1.original.insert(1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_none(), false, false, false, false, false, false, true, s2, s3)) by {
        assert(interrupt(s2, s3));
    }
    assert(next_cfg(ch_1(), ch_none(), false, false, false, false, false, false, true, s3, s4)) by {
        assert(recovery_refuse(s3, s4, ch_1(), ch_none(), true)) by {
            // rooms = 0 matches every rooms root (RoomsChanges = {}), so its
            // latest match is 1; social = 0 only matches Social(0), latest 0.
            assert(latest_match(s3.rooms, ch_none(), s3.journal_head) == 1) by {
                assert(root_at(1, ch_none()) == 0);
                assert(s3.rooms == 0);
            }
            assert(latest_match(s3.social, ch_1(), s3.journal_head) == 0) by {
                assert(root_at(1, ch_1()) == 1);
                assert(s3.social == 0);
            }
            assert(independent_skew_invalid(s3, ch_1(), ch_none()));
        }
    }
    assert(!honest_recovery(s4, ch_1(), ch_none())) by {
        assert(s4.pc == ph_blocked());
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_independent_roots_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_cfg(
            ch_1(),
            ch_none(),
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_independent_roots_trace(t) && !honest_recovery(t.last(), ch_1(), ch_none()));
}

/// mutant-next-roster: a complete height-1 flow ends in HostSuccess starting
/// height 2 with height 1's roster.
proof fn mutant_next_roster_violates()
    ensures
        exists|t: Seq<State>| is_next_roster_trace(t) && !next_roster_inv(t.last()),
{
    let j_n = Map::new(dom12(), |_h: int| v_none());
    let j_a = j_n.insert(1, v_a());
    let f1 = frontier(ch_1(), ch_1(), 1, v_a());
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let s2 = State {
        pc: ph_social(),
        journal_head: 1,
        journal: j_a,
        original: j_a,
        ..s1
    };
    let s3 = State { pc: ph_rooms(), social: 1, ..s2 };
    let s4 = State { pc: ph_apply(), rooms: 1, ..s3 };
    let s5 = State { pc: ph_ack(), app: f1, app_social: 1, app_rooms: 1, ..s4 };
    let na = Ack {
        height: 1,
        value: v_a(),
        journal_head: 1,
        committed_value: v_a(),
        app: f1,
        applied_value: v_a(),
        social: 1,
        rooms: 1,
        app_social: 1,
        app_rooms: 1,
    };
    let s6 = State {
        pc: ph_respond(),
        outcome: o_acked(),
        acks: Set::empty().insert(na),
        ..s5
    };
    let ns = Start { decided: 1, height: 2, roster: roster(1) };
    let s7 = State {
        pc: ph_idle(),
        starts: Set::empty().insert(ns),
        wal: Set::empty(),
        released_wal: true,
        ..s6
    };
    assert(init(s0));
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, s0, s1)) by {
        assert(new_decision(s0, s1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, s1, s2)) by {
        assert(journal_commit(s1, s2));
        assert(s2.journal =~= s1.journal.insert(1, v_a()));
        assert(s2.original =~= s1.original.insert(1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, s2, s3)) by {
        assert(publish_social(s2, s3, ch_1()));
        assert(s3.social == root_at(1, ch_1()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, s3, s4)) by {
        assert(publish_rooms(s3, s4, ch_1(), false));
        assert(s4.rooms == root_at(1, ch_1()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, s4, s5)) by {
        assert(apply_step(s4, s5, ch_1(), ch_1()));
        assert(s5.app == at(s4, ch_1(), ch_1(), 1));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, s5, s6)) by {
        assert(acknowledge(s5, s6, false));
        assert(s6.acks =~= s5.acks.insert(na));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, true, false, false, s6, s7)) by {
        assert(host_success(s6, s7, true));
        assert(s7.starts =~= s6.starts.insert(ns));
    }
    assert(!next_roster_inv(s7)) by {
        assert(s7.starts.contains(ns));
        assert(ns.height == ns.decided + 1);
        assert(ns.roster == roster(1));
        assert(ns.roster != roster(ns.height));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7);
    assert(is_next_roster_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_cfg(
            ch_1(),
            ch_1(),
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7
            );
        }
    }
    assert(t.last() == s7);
    assert(is_next_roster_trace(t) && !next_roster_inv(t.last()));
}

/// mutant-publication-order: RoomsBeforeSocial publishes the rooms root ahead
/// of social, leaving no jointly compatible prefix.
proof fn mutant_publication_order_violates()
    ensures
        exists|t: Seq<State>| is_publication_order_trace(t) && !publication_order(
            t.last(),
            ch_1(),
            ch_1(),
        ),
{
    let j_n = Map::new(dom12(), |_h: int| v_none());
    let j_a = j_n.insert(1, v_a());
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let s2 = State {
        pc: ph_social(),
        journal_head: 1,
        journal: j_a,
        original: j_a,
        ..s1
    };
    let s3 = State { pc: ph_sar(), rooms: 1, ..s2 };
    assert(init(s0));
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, false, true, false, s0, s1)) by {
        assert(new_decision(s0, s1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, false, true, false, s1, s2)) by {
        assert(journal_commit(s1, s2));
        assert(s2.journal =~= s1.journal.insert(1, v_a()));
        assert(s2.original =~= s1.original.insert(1, v_a()));
    }
    assert(next_cfg(ch_1(), ch_1(), false, false, false, false, false, true, false, s2, s3)) by {
        assert(publish_rooms(s2, s3, ch_1(), true));
        assert(s3.rooms == root_at(1, ch_1()));
    }
    assert(!publication_order(s3, ch_1(), ch_1())) by {
        // p in 0..1: p = 0 needs rooms = 0; p = 1 needs social = S(1) = 1
        // (the skew disjunct needs 1 < 1).
        assert forall|p: int| 0 <= p <= s3.journal_head implies !compatible_prefix(
            s3,
            ch_1(),
            ch_1(),
            p,
        ) by {
            assert(p == 0 || p == 1);
            assert(root_at(0, ch_1()) == 0);
            assert(root_at(1, ch_1()) == 1);
            if p == 0 {
                assert(s3.rooms != rooms_root(ch_1(), 0));
            } else {
                assert(s3.social != social_root(ch_1(), 1));
                assert(!(p < s3.journal_head));
            }
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3);
    assert(is_publication_order_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_cfg(
            ch_1(),
            ch_1(),
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3);
        }
    }
    assert(t.last() == s3);
    assert(is_publication_order_trace(t) && !publication_order(t.last(), ch_1(), ch_1()));
}

/// mutant-roots-only: with both schedules empty the roots stay at 0, so a
/// redelivered but never-applied decision is acked on roots alone while the
/// full frontier is still genesis.
proof fn mutant_roots_only_violates()
    ensures
        exists|t: Seq<State>| is_roots_only_trace(t) && !ack_has_full_frontier(
            t.last(),
            ch_none(),
            ch_none(),
        ),
{
    let j_n = Map::new(dom12(), |_h: int| v_none());
    let j_a = j_n.insert(1, v_a());
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let s2 = State {
        pc: ph_social(),
        journal_head: 1,
        journal: j_a,
        original: j_a,
        ..s1
    };
    let s3 = State { pc: ph_respond(), outcome: o_withheld(), ..s2 };
    let s4 = State { pc: ph_idle(), ..s3 };
    let s5 = State { pc: ph_ack(), target: 1, value: v_a(), outcome: o_none(), ..s4 };
    let na = Ack {
        height: 1,
        value: v_a(),
        journal_head: 1,
        committed_value: v_a(),
        app: genesis_frontier(),
        applied_value: v_genesis(),
        social: 0,
        rooms: 0,
        app_social: 0,
        app_rooms: 0,
    };
    let s6 = State { pc: ph_respond(), outcome: o_acked(), acks: Set::empty().insert(na), ..s5 };
    assert(init(s0));
    assert(next_cfg(ch_none(), ch_none(), true, false, false, false, false, false, false, s0, s1)) by {
        assert(new_decision(s0, s1, v_a()));
    }
    assert(next_cfg(ch_none(), ch_none(), true, false, false, false, false, false, false, s1, s2)) by {
        assert(journal_commit(s1, s2));
        assert(s2.journal =~= s1.journal.insert(1, v_a()));
        assert(s2.original =~= s1.original.insert(1, v_a()));
    }
    assert(next_cfg(ch_none(), ch_none(), true, false, false, false, false, false, false, s2, s3)) by {
        assert(fail(s2, s3));
    }
    assert(next_cfg(ch_none(), ch_none(), true, false, false, false, false, false, false, s3, s4)) by {
        assert(host_failure(s3, s4, false));
    }
    assert(next_cfg(ch_none(), ch_none(), true, false, false, false, false, false, false, s4, s5)) by {
        assert(redeliver(s4, s5, ch_none(), ch_none(), false, true, 1, v_a())) by {
            assert(map_at(s4.journal, 1) == v_a());
            // RootsOnlyAck branch: appSocial = 0 = Social(1), appRooms = 0 = Rooms(1).
            assert(s4.app_social == social_root(ch_none(), 1));
            assert(s4.app_rooms == rooms_root(ch_none(), 1));
        }
    }
    assert(next_cfg(ch_none(), ch_none(), true, false, false, false, false, false, false, s5, s6)) by {
        assert(acknowledge(s5, s6, false));
        assert(s6.acks =~= s5.acks.insert(na));
    }
    assert(!ack_has_full_frontier(s6, ch_none(), ch_none())) by {
        assert(s6.acks.contains(na));
        assert(na.app.height == 0 && na.height == 1);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_roots_only_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_cfg(
            ch_none(),
            ch_none(),
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6
            );
        }
    }
    assert(t.last() == s6);
    assert(is_roots_only_trace(t) && !ack_has_full_frontier(t.last(), ch_none(), ch_none()));
}

/// Completion witness for the safe model: a height-1 decision runs through
/// finalization, then one interruption recovers through LoadPrefix(head) and
/// RecoveryReady records the reopened frontier.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>|
            is_normal_trace(t) && t.last().pc == ph_idle() && !(t.last().starts =~= Set::empty())
                && !(t.last().reopened =~= Set::empty()),
{
    let j_n = Map::new(dom12(), |_h: int| v_none());
    let j_a = j_n.insert(1, v_a());
    let f1 = frontier(ch_1(), ch_1(), 1, v_a());
    let s0 = init_state();
    let s1 = State { pc: ph_journal(), target: 1, value: v_a(), outcome: o_none(), ..s0 };
    let s2 = State {
        pc: ph_social(),
        journal_head: 1,
        journal: j_a,
        original: j_a,
        ..s1
    };
    let s3 = State { pc: ph_rooms(), social: 1, ..s2 };
    let s4 = State { pc: ph_apply(), rooms: 1, ..s3 };
    let s5 = State { pc: ph_ack(), app: f1, app_social: 1, app_rooms: 1, ..s4 };
    let na = Ack {
        height: 1,
        value: v_a(),
        journal_head: 1,
        committed_value: v_a(),
        app: f1,
        applied_value: v_a(),
        social: 1,
        rooms: 1,
        app_social: 1,
        app_rooms: 1,
    };
    let s6 = State { pc: ph_respond(), outcome: o_acked(), acks: Set::empty().insert(na), ..s5 };
    let ns = Start { decided: 1, height: 2, roster: roster(2) };
    let s7 = State {
        pc: ph_idle(),
        starts: Set::empty().insert(ns),
        wal: Set::empty(),
        released_wal: true,
        ..s6
    };
    let s8 = State {
        pc: ph_recover(),
        app: genesis_frontier(),
        app_social: 0,
        app_rooms: 0,
        recovering: true,
        crashes: 1,
        ..s7
    };
    let s9 = State {
        pc: ph_rcc(),
        app: f1,
        app_social: 1,
        app_rooms: 1,
        ..s8
    };
    let nr = Reopened {
        frontier: f1,
        head: 1,
        value: v_a(),
        social: 1,
        rooms: 1,
    };
    let s10 = State {
        pc: ph_idle(),
        recovering: false,
        reopened: Set::empty().insert(nr),
        ..s9
    };
    assert(init(s0));
    assert(next_normal(s0, s1)) by { assert(new_decision(s0, s1, v_a())); }
    assert(next_normal(s1, s2)) by {
        assert(journal_commit(s1, s2));
        assert(s2.journal =~= s1.journal.insert(1, v_a()));
        assert(s2.original =~= s1.original.insert(1, v_a()));
    }
    assert(next_normal(s2, s3)) by {
        assert(publish_social(s2, s3, ch_1()));
        assert(s3.social == root_at(1, ch_1()));
    }
    assert(next_normal(s3, s4)) by {
        assert(publish_rooms(s3, s4, ch_1(), false));
        assert(s4.rooms == root_at(1, ch_1()));
    }
    assert(next_normal(s4, s5)) by {
        assert(apply_step(s4, s5, ch_1(), ch_1()));
        assert(s5.app == at(s4, ch_1(), ch_1(), 1));
    }
    assert(next_normal(s5, s6)) by {
        assert(acknowledge(s5, s6, false));
        assert(s6.acks =~= s5.acks.insert(na));
    }
    assert(next_normal(s6, s7)) by {
        assert(host_success(s6, s7, false));
        assert(s7.starts =~= s6.starts.insert(ns));
        assert(s7.wal =~= Set::empty());
    }
    assert(next_normal(s7, s8)) by { assert(interrupt(s7, s8)); }
    assert(next_normal(s8, s9)) by {
        assert(load_prefix(s8, s9, ch_1(), ch_1(), false, 1)) by {
            assert(compatible_prefix(s8, ch_1(), ch_1(), 1)) by {
                assert(s8.rooms == rooms_root(ch_1(), 1));
                assert(s8.social == social_root(ch_1(), 1));
            }
        }
        assert(s9.app == at(s8, ch_1(), ch_1(), 1));
    }
    assert(next_normal(s9, s10)) by {
        assert(recovery_ready(s9, s10, ch_1(), ch_1())) by {
            assert(s9.app == at(s9, ch_1(), ch_1(), s9.journal_head));
            assert(s9.app_social == s9.social);
            assert(s9.app_rooms == s9.rooms);
        }
        assert(s10.reopened =~= s9.reopened.insert(nr));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8).push(s9).push(s10);
    assert(is_normal_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_normal(t[i], t[i + 1]) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8 || t[i + 1] == s9
                    || t[i + 1] == s10
            );
        }
    }
    assert(t.last() == s10);
    assert(s10.starts.contains(ns));
    assert(s10.reopened.contains(nr));
    assert(!(s10.starts =~= Set::empty()));
    assert(!(s10.reopened =~= Set::empty()));
    assert(is_normal_trace(t) && t.last().pc == ph_idle() && !(t.last().starts =~= Set::empty())
        && !(t.last().reopened =~= Set::empty()));
}

}
