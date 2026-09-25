//! Verus pilot (3rd model): inductive proof of PrivatePublication's
//! invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs` and
//! `verify/private-rotation/rotation.rs`: `PrivatePublication.tla` under
//! `normal.cfg` is re-stated as a Verus transition system and the three
//! checked invariants are proved inductive. The three mutant
//! configurations are proved to reach violations of the invariants TLC
//! found for them — `mutant-early` breaks `ConfirmedOutput`,
//! `mutant-retarget` breaks `DraftBinding`, `mutant-revoked` breaks
//! `AuthorizedOutput` — and a completion witness runs a session through
//! the full safe lifecycle.
//!
//! Encoding notes:
//!   * Sessions == {a,b} is the concrete set {1,2}; a/b map to 1/2.
//!   * `phase` and `expected` are `[Sessions -> int]` and become
//!     `Map<int,int>` read through `map_at` (0 off-domain; the model never
//!     reads them elsewhere). Phase strings are the constants IDLE..DONE.
//!   * `{0,1}`-valued `draftRoster`/`storedRoster` and `BOOLEAN`-valued
//!     `authorizedAtRelease` become characteristic sets `dr1`, `sr1`,
//!     `auth_ok`; equality of two such maps is membership agreement.
//!   * `Publish` bumps `revision`; the bound `revision <= Sessions + 1`
//!     is proved through the auxiliary `revision = |stored| + roster`.
//!
//! Verify with:
//!   verus --crate-type=lib verify/private-publication/publication.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Sessions == {a, b} as {1, 2}.
pub open spec fn sessions() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

pub open spec fn sessions_a() -> Set<int> {
    Set::empty().insert(1)
}

pub open spec fn is_session(s: int) -> bool {
    sessions().contains(s)
}

/// Phase encoding for the `{"idle","draft","waiting","readback","ready",
/// "latched","done"}` alphabet.
pub open spec fn ph_idle() -> int {
    0
}

pub open spec fn ph_draft() -> int {
    1
}

pub open spec fn ph_waiting() -> int {
    2
}

pub open spec fn ph_readback() -> int {
    3
}

pub open spec fn ph_ready() -> int {
    4
}

pub open spec fn ph_latched() -> int {
    5
}

pub open spec fn ph_done() -> int {
    6
}

/// Total map read at int keys (see header note).
pub open spec fn map_at(m: Map<int, int>, j: int) -> int {
    if m.dom().contains(j) {
        m[j]
    } else {
        0
    }
}

/// VARIABLES roster, revision, revoked, phase, expected, draftRoster,
/// stored, storedRoster, confirmed, released, authorizedAtRelease.
pub struct State {
    pub roster: int,
    pub revision: int,
    pub revoked: bool,
    pub phase: Map<int, int>,
    pub expected: Map<int, int>,
    pub dr1: Set<int>,
    pub stored: Set<int>,
    pub sr1: Set<int>,
    pub confirmed: Set<int>,
    pub released: Set<int>,
    pub auth_ok: Set<int>,
}

/// Authority == ~revoked /\ roster = 0
pub open spec fn authority(s: State) -> bool {
    !s.revoked && s.roster == 0
}

/// The all-zero / all-true session maps at init.
pub open spec fn zmap() -> Map<int, int> {
    Map::new(sessions(), |s: int| 0)
}

pub open spec fn init(s: State) -> bool {
    &&& s.roster == 0
    &&& s.revision == 0
    &&& !s.revoked
    &&& s.phase =~= zmap()
    &&& s.expected =~= zmap()
    &&& s.dr1 =~= Set::empty()
    &&& s.stored =~= Set::empty()
    &&& s.sr1 =~= Set::empty()
    &&& s.confirmed =~= Set::empty()
    &&& s.released =~= Set::empty()
    &&& s.auth_ok =~= sessions()
}

/// Prepare(s): idle + Authority -> draft; snapshot expected/draftRoster.
pub open spec fn prepare(pre: State, post: State, s: int) -> bool {
    &&& map_at(pre.phase, s) == ph_idle()
    &&& authority(pre)
    &&& post.phase =~= pre.phase.insert(s, ph_draft())
    &&& post.expected =~= pre.expected.insert(s, pre.revision)
    &&& post.dr1 =~= if pre.roster == 1 {
        pre.dr1.insert(s)
    } else {
        pre.dr1.remove(s)
    }
    &&& post.roster == pre.roster
    &&& post.revision == pre.revision
    &&& post.revoked == pre.revoked
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.confirmed =~= pre.confirmed
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// Start(s): draft + Authority -> waiting.
pub open spec fn start(pre: State, post: State, s: int) -> bool {
    &&& map_at(pre.phase, s) == ph_draft()
    &&& authority(pre)
    &&& post.phase =~= pre.phase.insert(s, ph_waiting())
    &&& post.roster == pre.roster
    &&& post.revision == pre.revision
    &&& post.revoked == pre.revoked
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.confirmed =~= pre.confirmed
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// Publish(s): waiting, s not yet stored, and the draft still matches the
/// current roster/revision unless RetargetDraft bypasses it. Stores s at
/// the current roster, bumps revision, moves to readback.
pub open spec fn publish(pre: State, post: State, rd: bool, s: int) -> bool {
    &&& map_at(pre.phase, s) == ph_waiting()
    &&& !pre.stored.contains(s)
    &&& ((map_at(pre.expected, s) == pre.revision && (pre.dr1.contains(s)
        == (pre.roster == 1))) || rd)
    &&& post.stored =~= pre.stored.insert(s)
    &&& post.sr1 =~= if pre.roster == 1 {
        pre.sr1.insert(s)
    } else {
        pre.sr1.remove(s)
    }
    &&& post.revision == pre.revision + 1
    &&& post.phase =~= pre.phase.insert(s, ph_readback())
    &&& post.roster == pre.roster
    &&& post.revoked == pre.revoked
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.confirmed =~= pre.confirmed
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// Readback(s): readback + stored -> ready; confirm.
pub open spec fn readback(pre: State, post: State, s: int) -> bool {
    &&& map_at(pre.phase, s) == ph_readback()
    &&& pre.stored.contains(s)
    &&& post.confirmed =~= pre.confirmed.insert(s)
    &&& post.phase =~= pre.phase.insert(s, ph_ready())
    &&& post.roster == pre.roster
    &&& post.revision == pre.revision
    &&& post.revoked == pre.revoked
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// Interrupt(s): waiting/readback/ready -> latched.
pub open spec fn interrupt(pre: State, post: State, s: int) -> bool {
    &&& (map_at(pre.phase, s) == ph_waiting() || map_at(pre.phase, s) == ph_readback()
        || map_at(pre.phase, s) == ph_ready())
    &&& post.phase =~= pre.phase.insert(s, ph_latched())
    &&& post.roster == pre.roster
    &&& post.revision == pre.revision
    &&& post.revoked == pre.revoked
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.confirmed =~= pre.confirmed
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// Recover(s): latched + stored -> readback.
pub open spec fn recover(pre: State, post: State, s: int) -> bool {
    &&& map_at(pre.phase, s) == ph_latched()
    &&& pre.stored.contains(s)
    &&& post.phase =~= pre.phase.insert(s, ph_readback())
    &&& post.roster == pre.roster
    &&& post.revision == pre.revision
    &&& post.revoked == pre.revoked
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.confirmed =~= pre.confirmed
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// Release(s): ready (or waiting under EarlyOutput), Authority (or
/// IgnoreRevocation); records whether authority held at release time.
pub open spec fn release(pre: State, post: State, eo: bool, ir: bool, s: int) -> bool {
    &&& (map_at(pre.phase, s) == ph_ready() || (eo && map_at(pre.phase, s) == ph_waiting()))
    &&& (authority(pre) || ir)
    &&& post.released =~= pre.released.insert(s)
    &&& post.auth_ok =~= if authority(pre) {
        pre.auth_ok.insert(s)
    } else {
        pre.auth_ok.remove(s)
    }
    &&& post.phase =~= pre.phase.insert(s, ph_done())
    &&& post.roster == pre.roster
    &&& post.revision == pre.revision
    &&& post.revoked == pre.revoked
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.confirmed =~= pre.confirmed
}

/// Revoke == ~revoked -> revoked' = TRUE.
pub open spec fn revoke(pre: State, post: State) -> bool {
    &&& !pre.revoked
    &&& post.revoked
    &&& post.roster == pre.roster
    &&& post.revision == pre.revision
    &&& post.phase =~= pre.phase
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.confirmed =~= pre.confirmed
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// ChangeRoster == roster = 0 -> roster' = 1, revision + 1.
pub open spec fn change_roster(pre: State, post: State) -> bool {
    &&& pre.roster == 0
    &&& post.roster == 1
    &&& post.revision == pre.revision + 1
    &&& post.revoked == pre.revoked
    &&& post.phase =~= pre.phase
    &&& post.expected =~= pre.expected
    &&& post.dr1 =~= pre.dr1
    &&& post.stored =~= pre.stored
    &&& post.sr1 =~= pre.sr1
    &&& post.confirmed =~= pre.confirmed
    &&& post.released =~= pre.released
    &&& post.auth_ok =~= pre.auth_ok
}

/// Next under arbitrary config constants.
pub open spec fn next_cfg(eo: bool, rd: bool, ir: bool, pre: State, post: State) -> bool {
    ||| revoke(pre, post)
    ||| change_roster(pre, post)
    ||| exists|s: int| is_session(s) && #[trigger] prepare(pre, post, s)
    ||| exists|s: int| is_session(s) && #[trigger] start(pre, post, s)
    ||| exists|s: int| is_session(s) && #[trigger] publish(pre, post, rd, s)
    ||| exists|s: int| is_session(s) && #[trigger] readback(pre, post, s)
    ||| exists|s: int| is_session(s) && #[trigger] interrupt(pre, post, s)
    ||| exists|s: int| is_session(s) && #[trigger] recover(pre, post, s)
    ||| exists|s: int| is_session(s) && #[trigger] release(pre, post, eo, ir, s)
}

/// normal.cfg: all three mutant switches false.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, pre, post)
}

pub open spec fn next_mutant_early(pre: State, post: State) -> bool {
    next_cfg(true, false, false, pre, post)
}

pub open spec fn next_mutant_retarget(pre: State, post: State) -> bool {
    next_cfg(false, true, false, pre, post)
}

pub open spec fn next_mutant_revoked(pre: State, post: State) -> bool {
    next_cfg(false, false, true, pre, post)
}

/// TypeOK.
pub open spec fn type_ok(s: State) -> bool {
    &&& (s.roster == 0 || s.roster == 1)
    &&& 0 <= s.revision <= 3
    &&& forall|x: int| is_session(x) ==> 0 <= map_at(s.phase, x) <= 6
    &&& forall|x: int| is_session(x) ==> 0 <= map_at(s.expected, x) <= 3
    &&& s.dr1.subset_of(sessions())
    &&& s.sr1.subset_of(sessions())
    &&& s.stored.subset_of(sessions())
    &&& s.confirmed.subset_of(s.stored)
    &&& s.released.subset_of(sessions())
    &&& s.auth_ok.subset_of(sessions())
}

/// ConfirmedOutput == released \subseteq confirmed
pub open spec fn confirmed_output(s: State) -> bool {
    s.released.subset_of(s.confirmed)
}

/// DraftBinding == \A s \in stored : storedRoster[s] = draftRoster[s]
pub open spec fn draft_binding(s: State) -> bool {
    forall|x: int| s.stored.contains(x) ==> (s.sr1.contains(x) == s.dr1.contains(x))
}

/// AuthorizedOutput == \A s \in released : authorizedAtRelease[s]
pub open spec fn authorized_output(s: State) -> bool {
    s.released.subset_of(s.auth_ok)
}

/// Auxiliary: ready or done implies confirmed (ready is only entered via
/// Readback, which confirms; done is only entered via Release from ready).
pub open spec fn ready_done_confirmed(s: State) -> bool {
    forall|x: int| is_session(x) && (map_at(s.phase, x) == ph_ready() || map_at(s.phase, x)
        == ph_done()) ==> s.confirmed.contains(x)
}

/// Auxiliary: released implies done (Release sets done atomically and done
/// is terminal — no action leaves it).
pub open spec fn released_done(s: State) -> bool {
    forall|x: int| s.released.contains(x) ==> map_at(s.phase, x) == ph_done()
}

/// Auxiliary: revision accounting — every publish stores one item and every
/// roster change moves roster 0 -> 1, so revision = |stored| + roster.
/// This is what bounds revision at 3 in TypeOK.
pub open spec fn rev_accounting(s: State) -> bool {
    s.revision == s.stored.len() + s.roster
}

/// Auxiliary: a stored session has already left the pre-publication phases —
/// Publish moves waiting -> readback atomically and no action moves a phase
/// back into {idle, draft, waiting}. This is what makes the `s \notin
/// stored`-style reasoning hold where Prepare/Start move phases.
pub open spec fn stored_phase(s: State) -> bool {
    forall|x: int| s.stored.contains(x) ==> (map_at(s.phase, x) == ph_readback() || map_at(
        s.phase,
        x,
    ) == ph_ready() || map_at(s.phase, x) == ph_latched() || map_at(s.phase, x) == ph_done())
}

/// The inductive invariant.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& confirmed_output(s)
    &&& draft_binding(s)
    &&& authorized_output(s)
    &&& ready_done_confirmed(s)
    &&& released_done(s)
    &&& rev_accounting(s)
    &&& stored_phase(s)
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
    assert forall|x: int| is_session(x) implies 0 <= map_at(s.phase, x) <= 6 by {
        assert(s.phase.dom().contains(x));
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(s.expected, x) <= 3 by {
        assert(s.expected.dom().contains(x));
    }
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

proof fn prepare_preserves(pre: State, post: State, s: int)
    requires
        inv(pre),
        is_session(s),
        prepare(pre, post, s),
    ensures
        inv(post),
{
    vstd::set_lib::lemma_len_subset(pre.stored, sessions());
    assert(pre.revision <= 3);
    // stored_phase: the acting session was idle, hence not stored.
    if pre.stored.contains(s) {
        assert(0 <= map_at(pre.phase, s) && map_at(pre.phase, s) <= 6);
        assert(map_at(pre.phase, s) != ph_idle());
    }
    assert(!pre.stored.contains(s));
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.phase, x) <= 6 by {
        map_insert_at(pre.phase, s, ph_draft(), x);
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.expected, x) <= 3 by {
        map_insert_at(pre.expected, s, pre.revision, x);
        if x == s {
            assert(pre.revision <= 3);
        }
    }
    // ready_done_confirmed / released_done: phase moves idle->draft only.
    assert forall|x: int| is_session(x) && (map_at(post.phase, x) == ph_ready() || map_at(
        post.phase,
        x,
    ) == ph_done()) implies post.confirmed.contains(x) by {
        map_insert_at(pre.phase, s, ph_draft(), x);
    }
    assert forall|x: int| post.released.contains(x) implies map_at(post.phase, x)
        == ph_done() by {
        map_insert_at(pre.phase, s, ph_draft(), x);
    }
    assert forall|x: int| post.stored.contains(x) implies (post.sr1.contains(x)
        == post.dr1.contains(x)) by {
        assert(pre.stored.contains(x));
        assert(pre.sr1.contains(x) == pre.dr1.contains(x));
        // dr1 changed only at s; stored members satisfy the binding already
        // and s ∉ stored.
        if x == s {
            assert(false);
        }
        assert(post.dr1.contains(x) == pre.dr1.contains(x));
    }
    assert(post.dr1.subset_of(sessions()));
    assert forall|x: int| post.stored.contains(x) implies (map_at(post.phase, x)
        == ph_readback() || map_at(post.phase, x) == ph_ready() || map_at(post.phase, x)
        == ph_latched() || map_at(post.phase, x) == ph_done()) by {
        assert(pre.stored.contains(x) && x != s);
        map_insert_at(pre.phase, s, ph_draft(), x);
    }
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
    assert(stored_phase(post));
}

proof fn start_preserves(pre: State, post: State, s: int)
    requires
        inv(pre),
        is_session(s),
        start(pre, post, s),
    ensures
        inv(post),
{
    assert forall|x: int| is_session(x) && (map_at(post.phase, x) == ph_ready() || map_at(
        post.phase,
        x,
    ) == ph_done()) implies post.confirmed.contains(x) by {
        map_insert_at(pre.phase, s, ph_waiting(), x);
        if x == s {
            assert(map_at(pre.phase, s) == ph_draft());
        }
    }
    assert forall|x: int| post.released.contains(x) implies map_at(post.phase, x)
        == ph_done() by {
        map_insert_at(pre.phase, s, ph_waiting(), x);
        if x == s {
            assert(map_at(post.phase, s) == ph_waiting());
        }
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.phase, x) <= 6 by {
        map_insert_at(pre.phase, s, ph_waiting(), x);
    }
    if pre.stored.contains(s) {
        assert(map_at(pre.phase, s) != ph_draft());
        assert(false);
    }
    assert forall|x: int| post.stored.contains(x) implies (map_at(post.phase, x)
        == ph_readback() || map_at(post.phase, x) == ph_ready() || map_at(post.phase, x)
        == ph_latched() || map_at(post.phase, x) == ph_done()) by {
        assert(pre.stored.contains(x) && x != s);
        map_insert_at(pre.phase, s, ph_waiting(), x);
    }
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
    assert(stored_phase(post));
}

proof fn publish_preserves(pre: State, post: State, s: int)
    requires
        inv(pre),
        is_session(s),
        publish(pre, post, false, s),
    ensures
        inv(post),
{
    // draft_binding: the safe gate gives dr1(s) == roster and the write
    // stores sr1'(s) = roster, so the new member binds.
    assert forall|x: int| post.stored.contains(x) implies (post.sr1.contains(x)
        == post.dr1.contains(x)) by {
        if x == s {
            assert(pre.dr1.contains(s) == (pre.roster == 1));
            assert(post.sr1.contains(s) == (pre.roster == 1));
            assert(post.dr1.contains(s) == pre.dr1.contains(s));
        } else {
            assert(pre.stored.contains(x));
            assert(post.sr1.contains(x) == pre.sr1.contains(x));
            assert(post.dr1.contains(x) == pre.dr1.contains(x));
        }
    }
    // rev_accounting: stored and revision both grow by one.
    assert(post.stored.len() == pre.stored.len() + 1);
    // ready_done_confirmed / released_done: s moves waiting->readback.
    assert forall|x: int| is_session(x) && (map_at(post.phase, x) == ph_ready() || map_at(
        post.phase,
        x,
    ) == ph_done()) implies post.confirmed.contains(x) by {
        map_insert_at(pre.phase, s, ph_readback(), x);
        if x == s {
        }
    }
    assert forall|x: int| post.released.contains(x) implies map_at(post.phase, x)
        == ph_done() by {
        map_insert_at(pre.phase, s, ph_readback(), x);
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.phase, x) <= 6 by {
        map_insert_at(pre.phase, s, ph_readback(), x);
    }
    // type_ok: revision bound via rev_accounting + stored ⊆ sessions.
    vstd::set_lib::lemma_len_subset(post.stored, sessions());
    assert(post.stored.subset_of(sessions())) by {
        assert forall|x: int| post.stored.contains(x) implies sessions().contains(x) by {
            if x == s {
                assert(is_session(s));
            } else {
                assert(pre.stored.contains(x));
            }
        }
    }
    vstd::set_lib::lemma_len_subset(post.stored, sessions());
    assert forall|x: int| post.stored.contains(x) implies (map_at(post.phase, x)
        == ph_readback() || map_at(post.phase, x) == ph_ready() || map_at(post.phase, x)
        == ph_latched() || map_at(post.phase, x) == ph_done()) by {
        if x == s {
            map_insert_at(pre.phase, s, ph_readback(), x);
            assert(map_at(post.phase, s) == ph_readback());
        } else {
            assert(pre.stored.contains(x));
            map_insert_at(pre.phase, s, ph_readback(), x);
        }
    }
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
    assert(stored_phase(post));
}

proof fn readback_preserves(pre: State, post: State, s: int)
    requires
        inv(pre),
        is_session(s),
        readback(pre, post, s),
    ensures
        inv(post),
{
    assert forall|x: int| is_session(x) && (map_at(post.phase, x) == ph_ready() || map_at(
        post.phase,
        x,
    ) == ph_done()) implies post.confirmed.contains(x) by {
        map_insert_at(pre.phase, s, ph_ready(), x);
        if x == s {
            assert(post.confirmed.contains(s));
        } else {
            assert(pre.confirmed.contains(x));
        }
    }
    assert forall|x: int| post.released.contains(x) implies map_at(post.phase, x)
        == ph_done() by {
        map_insert_at(pre.phase, s, ph_ready(), x);
        if x == s {
        }
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.phase, x) <= 6 by {
        map_insert_at(pre.phase, s, ph_ready(), x);
    }
    assert forall|x: int| post.stored.contains(x) implies (map_at(post.phase, x)
        == ph_readback() || map_at(post.phase, x) == ph_ready() || map_at(post.phase, x)
        == ph_latched() || map_at(post.phase, x) == ph_done()) by {
        assert(pre.stored.contains(x));
        if x == s {
            map_insert_at(pre.phase, s, ph_ready(), x);
            assert(map_at(post.phase, s) == ph_ready());
        } else {
            map_insert_at(pre.phase, s, ph_ready(), x);
        }
    }
    assert(post.confirmed.subset_of(post.stored)) by {
        assert forall|x: int| post.confirmed.contains(x) implies post.stored.contains(x) by {
            if x == s {
            } else {
                assert(pre.confirmed.contains(x));
            }
        }
    }
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
}

proof fn interrupt_preserves(pre: State, post: State, s: int)
    requires
        inv(pre),
        is_session(s),
        interrupt(pre, post, s),
    ensures
        inv(post),
{
    assert forall|x: int| is_session(x) && (map_at(post.phase, x) == ph_ready() || map_at(
        post.phase,
        x,
    ) == ph_done()) implies post.confirmed.contains(x) by {
        map_insert_at(pre.phase, s, ph_latched(), x);
        if x == s {
            // pre phase was waiting/readback/ready; if ready it was confirmed
            assert(map_at(post.phase, s) == ph_latched());
        } else {
            assert(pre.confirmed.contains(x));
        }
    }
    assert forall|x: int| post.released.contains(x) implies map_at(post.phase, x)
        == ph_done() by {
        map_insert_at(pre.phase, s, ph_latched(), x);
        if x == s {
        }
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.phase, x) <= 6 by {
        map_insert_at(pre.phase, s, ph_latched(), x);
    }
    assert forall|x: int| post.stored.contains(x) implies (map_at(post.phase, x)
        == ph_readback() || map_at(post.phase, x) == ph_ready() || map_at(post.phase, x)
        == ph_latched() || map_at(post.phase, x) == ph_done()) by {
        assert(pre.stored.contains(x));
        if x == s {
            map_insert_at(pre.phase, s, ph_latched(), x);
            assert(map_at(post.phase, s) == ph_latched());
        } else {
            map_insert_at(pre.phase, s, ph_latched(), x);
        }
    }
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
    assert(stored_phase(post));
}

proof fn recover_preserves(pre: State, post: State, s: int)
    requires
        inv(pre),
        is_session(s),
        recover(pre, post, s),
    ensures
        inv(post),
{
    assert forall|x: int| is_session(x) && (map_at(post.phase, x) == ph_ready() || map_at(
        post.phase,
        x,
    ) == ph_done()) implies post.confirmed.contains(x) by {
        map_insert_at(pre.phase, s, ph_readback(), x);
        if x == s {
        } else {
            assert(pre.confirmed.contains(x));
        }
    }
    assert forall|x: int| post.released.contains(x) implies map_at(post.phase, x)
        == ph_done() by {
        map_insert_at(pre.phase, s, ph_readback(), x);
        if x == s {
        }
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.phase, x) <= 6 by {
        map_insert_at(pre.phase, s, ph_readback(), x);
    }
    assert forall|x: int| post.stored.contains(x) implies (map_at(post.phase, x)
        == ph_readback() || map_at(post.phase, x) == ph_ready() || map_at(post.phase, x)
        == ph_latched() || map_at(post.phase, x) == ph_done()) by {
        assert(pre.stored.contains(x));
        if x == s {
            map_insert_at(pre.phase, s, ph_readback(), x);
            assert(map_at(post.phase, s) == ph_readback());
        } else {
            map_insert_at(pre.phase, s, ph_readback(), x);
        }
    }
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
    assert(stored_phase(post));
}

proof fn release_preserves(pre: State, post: State, s: int)
    requires
        inv(pre),
        is_session(s),
        release(pre, post, false, false, s),
    ensures
        inv(post),
{
    // In the safe configuration the release gate is phase = ready and
    // Authority holds, so the new member is confirmed and authorized.
    assert(authority(pre));
    assert(map_at(pre.phase, s) == ph_ready());
    // confirmed_output: released ⊆ confirmed — new member was ready hence
    // confirmed; released members already confirmed.
    assert forall|x: int| post.released.contains(x) implies post.confirmed.contains(x) by {
        if x == s {
            assert(pre.confirmed.contains(x));
        } else {
            assert(pre.released.contains(x));
            assert(pre.confirmed.contains(x));
        }
    }
    // authorized_output: released ⊆ auth_ok — authority held, so s joined.
    assert forall|x: int| post.released.contains(x) implies post.auth_ok.contains(x) by {
        if x == s {
            assert(post.auth_ok.contains(s));
        } else {
            assert(pre.released.contains(x));
            assert(pre.auth_ok.contains(x));
        }
    }
    assert forall|x: int| is_session(x) && (map_at(post.phase, x) == ph_ready() || map_at(
        post.phase,
        x,
    ) == ph_done()) implies post.confirmed.contains(x) by {
        map_insert_at(pre.phase, s, ph_done(), x);
        if x == s {
            assert(pre.confirmed.contains(s));
        } else {
            assert(pre.confirmed.contains(x));
        }
    }
    assert forall|x: int| post.released.contains(x) implies map_at(post.phase, x)
        == ph_done() by {
        map_insert_at(pre.phase, s, ph_done(), x);
        if x == s {
        }
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.phase, x) <= 6 by {
        map_insert_at(pre.phase, s, ph_done(), x);
    }
    assert(post.released.subset_of(sessions())) by {
        assert forall|x: int| post.released.contains(x) implies sessions().contains(x) by {
            if x == s {
                assert(is_session(s));
            } else {
                assert(pre.released.contains(x));
            }
        }
    }
    assert forall|x: int| post.stored.contains(x) implies (map_at(post.phase, x)
        == ph_readback() || map_at(post.phase, x) == ph_ready() || map_at(post.phase, x)
        == ph_latched() || map_at(post.phase, x) == ph_done()) by {
        assert(pre.stored.contains(x));
        if x == s {
            map_insert_at(pre.phase, s, ph_done(), x);
            assert(map_at(post.phase, s) == ph_done());
        } else {
            map_insert_at(pre.phase, s, ph_done(), x);
        }
    }
    assert forall|x: int| is_session(x) implies 0 <= map_at(post.expected, x) <= 3 by {
        assert(map_at(post.expected, x) == map_at(pre.expected, x));
    }
    assert(post.roster == 0 || post.roster == 1);
    assert(0 <= post.revision <= 3);
    assert(post.dr1.subset_of(sessions()));
    assert(post.sr1.subset_of(sessions()));
    assert(post.stored.subset_of(sessions()));
    assert(post.confirmed.subset_of(post.stored));
    assert(post.released.subset_of(sessions()));
    assert(post.auth_ok.subset_of(sessions())) by {
        assert forall|x: int| post.auth_ok.contains(x) implies sessions().contains(x) by {
            if x == s {
                assert(is_session(s));
            } else {
                assert(pre.auth_ok.contains(x));
            }
        }
    }
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
    assert(stored_phase(post));
}

proof fn revoke_preserves(pre: State, post: State)
    requires
        inv(pre),
        revoke(pre, post),
    ensures
        inv(post),
{
}

proof fn change_roster_preserves(pre: State, post: State)
    requires
        inv(pre),
        change_roster(pre, post),
    ensures
        inv(post),
{
    // rev_accounting: revision + 1 and roster 0 -> 1 both add one.
    // The revision bound needs |stored| <= 2 for revision <= 3.
    vstd::set_lib::lemma_len_subset(pre.stored, sessions());
    assert(pre.revision <= 2);
    assert(post.revision <= 3);
    // draft_binding is unaffected: the maps and stored are unchanged.
    assert(type_ok(post));
    assert(confirmed_output(post));
    assert(draft_binding(post));
    assert(authorized_output(post));
    assert(ready_done_confirmed(post));
    assert(released_done(post));
    assert(rev_accounting(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if revoke(pre, post) {
        revoke_preserves(pre, post);
    } else if change_roster(pre, post) {
        change_roster_preserves(pre, post);
    } else if exists|s: int| is_session(s) && prepare(pre, post, s) {
        let s = choose|s: int| is_session(s) && prepare(pre, post, s);
        prepare_preserves(pre, post, s);
    } else if exists|s: int| is_session(s) && start(pre, post, s) {
        let s = choose|s: int| is_session(s) && start(pre, post, s);
        start_preserves(pre, post, s);
    } else if exists|s: int| is_session(s) && publish(pre, post, false, s) {
        let s = choose|s: int| is_session(s) && publish(pre, post, false, s);
        publish_preserves(pre, post, s);
    } else if exists|s: int| is_session(s) && readback(pre, post, s) {
        let s = choose|s: int| is_session(s) && readback(pre, post, s);
        readback_preserves(pre, post, s);
    } else if exists|s: int| is_session(s) && interrupt(pre, post, s) {
        let s = choose|s: int| is_session(s) && interrupt(pre, post, s);
        interrupt_preserves(pre, post, s);
    } else if exists|s: int| is_session(s) && recover(pre, post, s) {
        let s = choose|s: int| is_session(s) && recover(pre, post, s);
        recover_preserves(pre, post, s);
    } else {
        let s = choose|s: int| is_session(s) && release(pre, post, false, false, s);
        release_preserves(pre, post, s);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_early_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_early(t[i], t[i + 1])
}

pub open spec fn is_retarget_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_retarget(t[i], t[i + 1])
}

pub open spec fn is_revoked_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_revoked(t[i], t[i + 1])
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
    roster: int,
    revision: int,
    revoked: bool,
    phase: Map<int, int>,
    expected: Map<int, int>,
    dr1: Set<int>,
    stored: Set<int>,
    sr1: Set<int>,
    confirmed: Set<int>,
    released: Set<int>,
    auth_ok: Set<int>,
) -> State {
    State {
        roster,
        revision,
        revoked,
        phase,
        expected,
        dr1,
        stored,
        sr1,
        confirmed,
        released,
        auth_ok,
    }
}

/// Phase map with a's phase set to p and b's to idle.
pub open spec fn phmap(p: int) -> Map<int, int> {
    zmap().insert(1, p)
}

/// mutant-early: Prepare(a) -> Start(a) -> Release(a) with EarlyOutput lets
/// a waiting session release without readback — released = {a} while
/// confirmed = {}.
proof fn mutant_early_violates()
    ensures
        exists|t: Seq<State>| is_early_trace(t) && !confirmed_output(t.last()),
{
    let e = Set::empty();
    let s0 = st(0, 0, false, zmap(), zmap(), e, e, e, e, e, sessions());
    let s1 = st(0, 0, false, phmap(ph_draft()), zmap(), e, e, e, e, e, sessions());
    let s2 = st(0, 0, false, phmap(ph_waiting()), zmap(), e, e, e, e, e, sessions());
    let s3 = st(0, 0, false, phmap(ph_done()), zmap(), e, e, e, e, e.insert(1), sessions());
    assert(init(s0));
    assert(next_mutant_early(s0, s1)) by { assert(prepare(s0, s1, 1)); }
    assert(next_mutant_early(s1, s2)) by { assert(start(s1, s2, 1)); }
    assert(next_mutant_early(s2, s3)) by { assert(release(s2, s3, true, false, 1)); }
    assert(!confirmed_output(s3)) by {
        assert(s3.released.contains(1));
        assert(!s3.confirmed.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3);
    assert(is_early_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_early(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3);
        }
    }
    assert(t.last() == s3);
    assert(is_early_trace(t) && !confirmed_output(t.last()));
}

/// mutant-retarget: Prepare(a) -> Start(a) -> ChangeRoster -> Publish(a)
/// with RetargetDraft stores a under roster 1 while its draft binds roster
/// 0 — storedRoster[a] != draftRoster[a].
proof fn mutant_retarget_violates()
    ensures
        exists|t: Seq<State>| is_retarget_trace(t) && !draft_binding(t.last()),
{
    let e = Set::empty();
    let s0 = st(0, 0, false, zmap(), zmap(), e, e, e, e, e, sessions());
    let s1 = st(0, 0, false, phmap(ph_draft()), zmap(), e, e, e, e, e, sessions());
    let s2 = st(0, 0, false, phmap(ph_waiting()), zmap(), e, e, e, e, e, sessions());
    let s3 = st(1, 1, false, phmap(ph_waiting()), zmap(), e, e, e, e, e, sessions());
    let s4 = st(1, 2, false, phmap(ph_readback()), zmap(), e, sessions_a(), sessions_a(), e, e, sessions());
    assert(init(s0));
    assert(next_mutant_retarget(s0, s1)) by { assert(prepare(s0, s1, 1)); }
    assert(next_mutant_retarget(s1, s2)) by { assert(start(s1, s2, 1)); }
    assert(next_mutant_retarget(s2, s3)) by { assert(change_roster(s2, s3)); }
    assert(next_mutant_retarget(s3, s4)) by { assert(publish(s3, s4, true, 1)); }
    assert(!draft_binding(s4)) by {
        assert(s4.stored.contains(1));
        assert(s4.sr1.contains(1));
        assert(!s4.dr1.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_retarget_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_retarget(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_retarget_trace(t) && !draft_binding(t.last()));
}

/// mutant-revoked: Prepare(a) -> Start(a) -> Publish(a) -> Readback(a) ->
/// Revoke -> Release(a) with IgnoreRevocation records
/// authorizedAtRelease[a] = FALSE.
proof fn mutant_revoked_violates()
    ensures
        exists|t: Seq<State>| is_revoked_trace(t) && !authorized_output(t.last()),
{
    let e = Set::empty();
    let ea = e.insert(1);
    let s0 = st(0, 0, false, zmap(), zmap(), e, e, e, e, e, sessions());
    let s1 = st(0, 0, false, phmap(ph_draft()), zmap(), e, e, e, e, e, sessions());
    let s2 = st(0, 0, false, phmap(ph_waiting()), zmap(), e, e, e, e, e, sessions());
    let s3 = st(0, 1, false, phmap(ph_readback()), zmap(), e, ea, e, e, e, sessions());
    let s4 = st(0, 1, false, phmap(ph_ready()), zmap(), e, ea, e, ea, e, sessions());
    let s5 = st(0, 1, true, phmap(ph_ready()), zmap(), e, ea, e, ea, e, sessions());
    let s6 = st(0, 1, true, phmap(ph_done()), zmap(), e, ea, e, ea, ea, sessions().remove(1));
    assert(init(s0));
    assert(next_mutant_revoked(s0, s1)) by { assert(prepare(s0, s1, 1)); }
    assert(next_mutant_revoked(s1, s2)) by { assert(start(s1, s2, 1)); }
    assert(next_mutant_revoked(s2, s3)) by { assert(publish(s2, s3, false, 1)); }
    assert(next_mutant_revoked(s3, s4)) by { assert(readback(s3, s4, 1)); }
    assert(next_mutant_revoked(s4, s5)) by { assert(revoke(s4, s5)); }
    assert(next_mutant_revoked(s5, s6)) by { assert(release(s5, s6, false, true, 1)); }
    assert(!authorized_output(s6)) by {
        assert(s6.released.contains(1));
        assert(!s6.auth_ok.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_revoked_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_revoked(
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
    assert(is_revoked_trace(t) && !authorized_output(t.last()));
}

/// Completion witness for the safe model: Prepare(a) -> Start(a) ->
/// Publish(a) -> Readback(a) -> Release(a) -> Revoke reaches done with a
/// confirmed, authorized release.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().released =~= sessions_a()
            && t.last().confirmed =~= sessions_a() && t.last().auth_ok =~= sessions(),
{
    let e = Set::empty();
    let ea = e.insert(1);
    let s0 = st(0, 0, false, zmap(), zmap(), e, e, e, e, e, sessions());
    let s1 = st(0, 0, false, phmap(ph_draft()), zmap(), e, e, e, e, e, sessions());
    let s2 = st(0, 0, false, phmap(ph_waiting()), zmap(), e, e, e, e, e, sessions());
    let s3 = st(0, 1, false, phmap(ph_readback()), zmap(), e, ea, e, e, e, sessions());
    let s4 = st(0, 1, false, phmap(ph_ready()), zmap(), e, ea, e, ea, e, sessions());
    let s5 = st(0, 1, false, phmap(ph_done()), zmap(), e, ea, e, ea, ea, sessions());
    assert(init(s0));
    assert(next(s0, s1)) by { assert(prepare(s0, s1, 1)); }
    assert(next(s1, s2)) by { assert(start(s1, s2, 1)); }
    assert(next(s2, s3)) by { assert(publish(s2, s3, false, 1)); }
    assert(next(s3, s4)) by { assert(readback(s3, s4, 1)); }
    assert(next(s4, s5)) by { assert(release(s4, s5, false, false, 1)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4);
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                    || t[i + 1] == s5
            );
        }
    }
    assert(t.last() == s5);
    assert(s5.released =~= sessions_a());
    assert(s5.confirmed =~= sessions_a());
    assert(s5.auth_ok =~= sessions());
    assert(is_trace(t) && t.last().released =~= sessions_a() && t.last().confirmed =~= sessions_a()
        && t.last().auth_ok =~= sessions());
}

}
