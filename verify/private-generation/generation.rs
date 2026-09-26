//! Verus pilot (5th model): inductive proof of PrivateGeneration's
//! invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs`,
//! `verify/private-publication/publication.rs` and
//! `verify/host-recovery/recovery.rs`: `PrivateGeneration.tla` under
//! `normal.cfg` (all six switches false) is re-stated as a Verus
//! transition system and the eight checked safety invariants are proved
//! inductive. Each of the six mutant configurations is proved to reach a
//! violation of the invariant TLC found for it —
//! `mutant-missing-controller` breaks `CompleteInventory`,
//! `mutant-changed-head` breaks `ConditionalHead`,
//! `mutant-automatic-output` breaks `AutomaticOutputDrained`,
//! `mutant-missing-intent` breaks `IntentBeforeSelection`,
//! `mutant-reset-spend` breaks `PreservedSpend` and `mutant-lost-archive`
//! breaks `PreservedArchive` — and a completion witness runs both
//! controllers through a fenced generation-1 selection.
//!
//! Encoding notes:
//!   * Controllers == {a, b} is the concrete set {1, 2}; a/b map to 1/2.
//!   * A job `<<"application", c>>` or `<<"acceptance", c>>` is the pair
//!     `(0, c)` / `(1, c)` and `j[2]` is `j.1`; Foreign is `(2, 0)`, the
//!     only non-job value `stored` ever holds. Applications, Acceptances
//!     and Jobs are the literal member sets TLC computes for this
//!     instance.
//!   * `Owned(c, js)` is `js.filter(|j| j.1 == c)` and `Incoming(c)` is
//!     `stored ∩ Applications \ {App(c)}`.
//!   * `{0,1}`-valued `intent`/`selected` become the characteristic sets
//!     `intent1`/`selected1` of the controllers mapped to TRUE/1;
//!     `fenced` stays a bool.
//!   * `[Controllers -> SUBSET _]` maps (`applied`, `observed`, `archive`)
//!     become `Map<int, Set<(int,int)>>` read through `map_at_s` (empty
//!     off-domain) and `spent` becomes `Map<int,int>` read through
//!     `map_at` (0 off-domain); the model only reads them at Controllers.
//!     `[m EXCEPT ![c] = v]` is `m.insert(c, v)`, which keeps the
//!     constant Controllers domain because c ∈ Controllers.
//!   * Required's `CHOOSE c ∈ Controllers` under SkipController is the
//!     singleton {a} — the choice TLC's recorded witness exhibits.
//!   * `Cardinality(Owned(c, created))` is `owned(c, created).len()`;
//!     finiteness follows from `owned ⊆ created ⊆ Jobs`.
//!   * The TLA+ existentials `\E j \in Jobs : Store \/ Receipt` and
//!     `\E c \in Controllers : Queue \/ Apply \/ ...` become one
//!     existential per action, which is equivalent.
//!
//! Verify with:
//!   verus --crate-type=lib verify/private-generation/generation.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Controllers == {a, b} as {1, 2}.
pub open spec fn controllers() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

/// The other controller of this two-member instance.
pub open spec fn other(c: int) -> int {
    if c == 1 {
        2
    } else {
        1
    }
}

pub open spec fn is_controller(c: int) -> bool {
    controllers().contains(c)
}

/// Required == IF SkipController THEN {CHOOSE c ∈ Controllers} ELSE
/// Controllers. TLC's recorded witness exercises the {a} choice.
pub open spec fn required(skip_controller: bool) -> Set<int> {
    if skip_controller {
        Set::empty().insert(1)
    } else {
        controllers()
    }
}

/// App(c) == <<"application", c>> as (0, c).
pub open spec fn app(c: int) -> (int, int) {
    (0, c)
}

/// Ack(c) == <<"acceptance", c>> as (1, c).
pub open spec fn ack(c: int) -> (int, int) {
    (1, c)
}

/// Foreign == <<"concurrent", "old-writer">> as (2, 0).
pub open spec fn foreign() -> (int, int) {
    (2, 0)
}

/// Applications == {App(c) : c ∈ Controllers} for Controllers = {1, 2}.
pub open spec fn applications() -> Set<(int, int)> {
    Set::empty().insert(app(1)).insert(app(2))
}

/// Acceptances == {Ack(c) : c ∈ Controllers} for Controllers = {1, 2}.
pub open spec fn acceptances() -> Set<(int, int)> {
    Set::empty().insert(ack(1)).insert(ack(2))
}

/// Jobs == Applications ∪ Acceptances.
pub open spec fn jobs() -> Set<(int, int)> {
    applications().union(acceptances())
}

/// Jobs ∪ {Foreign}: the stored/observed/archive alphabet.
pub open spec fn job_atoms() -> Set<(int, int)> {
    jobs().insert(foreign())
}

pub open spec fn is_job(j: (int, int)) -> bool {
    jobs().contains(j)
}

/// Owned(c, js) == {j ∈ js : j[2] = c}.
pub open spec fn owned(c: int, js: Set<(int, int)>) -> Set<(int, int)> {
    js.filter(|j: (int, int)| j.1 == c)
}

/// VARIABLES created, pending, stored, applied, observed, paused, fenced,
/// terminal, intent, selected, archive, spent, online. `intent1` and
/// `selected1` are the characteristic sets documented in the header.
pub struct State {
    pub created: Set<(int, int)>,
    pub pending: Set<(int, int)>,
    pub stored: Set<(int, int)>,
    pub applied: Map<int, Set<(int, int)>>,
    pub observed: Map<int, Set<(int, int)>>,
    pub paused: Set<int>,
    pub fenced: bool,
    pub terminal: Set<(int, int)>,
    pub intent1: Set<int>,
    pub selected1: Set<int>,
    pub archive: Map<int, Set<(int, int)>>,
    pub spent: Map<int, int>,
    pub online: Set<int>,
}

/// Incoming(c) == (stored ∩ Applications) \ {App(c)}.
pub open spec fn incoming(s: State, c: int) -> Set<(int, int)> {
    s.stored.intersect(applications()).remove(app(c))
}

/// Total map reads at int keys (see header note).
pub open spec fn map_at(m: Map<int, int>, j: int) -> int {
    if m.dom().contains(j) {
        m[j]
    } else {
        0
    }
}

/// Total map reads at set-valued entries.
pub open spec fn map_at_s(m: Map<int, Set<(int, int)>>, j: int) -> Set<(int, int)> {
    if m.dom().contains(j) {
        m[j]
    } else {
        Set::empty()
    }
}

/// The all-empty-set controller map at init.
pub open spec fn zmap_s() -> Map<int, Set<(int, int)>> {
    Map::new(controllers(), |c: int| Set::empty())
}

/// The all-zero controller map at init.
pub open spec fn zmap_i() -> Map<int, int> {
    Map::new(controllers(), |c: int| 0)
}

pub open spec fn init(s: State) -> bool {
    &&& s.created =~= Set::empty()
    &&& s.pending =~= Set::empty()
    &&& s.stored =~= Set::empty()
    &&& s.applied =~= zmap_s()
    &&& s.observed =~= zmap_s()
    &&& s.paused =~= Set::empty()
    &&& !s.fenced
    &&& s.terminal =~= Set::empty()
    &&& s.intent1 =~= Set::empty()
    &&& s.selected1 =~= Set::empty()
    &&& s.archive =~= zmap_s()
    &&& s.spent =~= zmap_i()
    &&& s.online =~= controllers()
}

/// Queue(c) == /\ c ∈ online \ paused /\ ~fenced /\ selected[c] = 0
///             /\ App(c) ∉ created
///             /\ created' = created ∪ {App(c)}
///             /\ pending' = pending ∪ {App(c)}
///             /\ spent' = [spent EXCEPT ![c] = @ + 1]
pub open spec fn queue(pre: State, post: State, c: int) -> bool {
    &&& pre.online.contains(c) && !pre.paused.contains(c)
    &&& !pre.fenced
    &&& !pre.selected1.contains(c)
    &&& !pre.created.contains(app(c))
    &&& post.created =~= pre.created.insert(app(c))
    &&& post.pending =~= pre.pending.insert(app(c))
    &&& post.spent =~= pre.spent.insert(c, map_at(pre.spent, c) + 1)
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.online =~= pre.online
}

/// Store(j) == /\ j ∈ pending \ stored /\ ~fenced
///             /\ stored' = stored ∪ {j}
pub open spec fn store(pre: State, post: State, j: (int, int)) -> bool {
    &&& pre.pending.contains(j) && !pre.stored.contains(j)
    &&& !pre.fenced
    &&& post.stored =~= pre.stored.insert(j)
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
    &&& post.online =~= pre.online
}

/// Receipt(j) == /\ j ∈ pending ∩ stored
///               /\ pending' = pending \ {j}
/// A lost PUT completion leaves pending evidence; this exact retry may
/// still obtain its original receipt after a fence.
pub open spec fn receipt(pre: State, post: State, j: (int, int)) -> bool {
    &&& pre.pending.contains(j) && pre.stored.contains(j)
    &&& post.pending =~= pre.pending.remove(j)
    &&& post.created =~= pre.created
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
    &&& post.online =~= pre.online
}

/// Apply(c) == /\ c ∈ online \ paused /\ selected[c] = 0 /\ ~fenced
///             /\ Incoming(c) \ applied[c] ≠ {}
///             /\ applied' = [applied EXCEPT ![c] = Incoming(c)]
///             /\ created' = created ∪ {Ack(c)}
///             /\ pending' = pending ∪ {Ack(c)}
///             /\ spent' = [spent EXCEPT ![c] = @ + 1]
pub open spec fn apply(pre: State, post: State, c: int) -> bool {
    &&& pre.online.contains(c) && !pre.paused.contains(c)
    &&& !pre.selected1.contains(c)
    &&& !pre.fenced
    &&& !(incoming(pre, c).difference(map_at_s(pre.applied, c)) =~= Set::empty())
    &&& post.applied =~= pre.applied.insert(c, incoming(pre, c))
    &&& post.created =~= pre.created.insert(ack(c))
    &&& post.pending =~= pre.pending.insert(ack(c))
    &&& post.spent =~= pre.spent.insert(c, map_at(pre.spent, c) + 1)
    &&& post.stored =~= pre.stored
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.online =~= pre.online
}

/// Observe(c) == /\ c ∈ online \ paused /\ selected[c] = 0 /\ ~fenced
///               /\ (Incoming(c) ⊆ applied[c] \/ SkipAutomatic)
///               /\ observed' = [observed EXCEPT ![c] = stored]
pub open spec fn observe(pre: State, post: State, sa: bool, c: int) -> bool {
    &&& pre.online.contains(c) && !pre.paused.contains(c)
    &&& !pre.selected1.contains(c)
    &&& !pre.fenced
    &&& (incoming(pre, c).subset_of(map_at_s(pre.applied, c)) || sa)
    &&& post.observed =~= pre.observed.insert(c, pre.stored)
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
    &&& post.online =~= pre.online
}

/// Pause(c) == /\ c ∈ online \ paused /\ selected[c] = 0 /\ ~fenced
///             /\ Owned(c, pending) = {} /\ observed[c] = stored
///             /\ (Incoming(c) ⊆ applied[c] \/ SkipAutomatic)
///             /\ paused' = paused ∪ {c}
pub open spec fn pause(pre: State, post: State, sa: bool, c: int) -> bool {
    &&& pre.online.contains(c) && !pre.paused.contains(c)
    &&& !pre.selected1.contains(c)
    &&& !pre.fenced
    &&& owned(c, pre.pending) =~= Set::empty()
    &&& map_at_s(pre.observed, c) =~= pre.stored
    &&& (incoming(pre, c).subset_of(map_at_s(pre.applied, c)) || sa)
    &&& post.paused =~= pre.paused.insert(c)
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
    &&& post.online =~= pre.online
}

/// RaceWrite == /\ ~fenced /\ paused ≠ {} /\ Foreign ∉ stored
///              /\ stored' = stored ∪ {Foreign}
/// Another admitted writer can finish after the controller's last
/// observation; expected-head comparison must detect the change.
pub open spec fn race_write(pre: State, post: State) -> bool {
    &&& !pre.fenced
    &&& !(pre.paused =~= Set::empty())
    &&& !pre.stored.contains(foreign())
    &&& post.stored =~= pre.stored.insert(foreign())
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
    &&& post.online =~= pre.online
}

/// Fence == /\ ~fenced /\ Required ⊆ paused
///          /\ ((∀ c ∈ Required : observed[c] = stored) \/ IgnoreHead)
///          /\ fenced' = TRUE /\ terminal' = stored
pub open spec fn fence(pre: State, post: State, sc: bool, ih: bool) -> bool {
    &&& !pre.fenced
    &&& required(sc).subset_of(pre.paused)
    &&& ((forall|c: int| required(sc).contains(c) ==> map_at_s(pre.observed, c)
        =~= pre.stored) || ih)
    &&& post.fenced
    &&& post.terminal =~= pre.stored
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
    &&& post.online =~= pre.online
}

/// Prepare(c) == /\ c ∈ online /\ fenced /\ c ∈ paused
///               /\ observed[c] = terminal /\ Owned(c, pending) = {}
///               /\ Incoming(c) ⊆ applied[c] /\ ~intent[c]
///               /\ intent' = [intent EXCEPT ![c] = TRUE]
pub open spec fn prepare(pre: State, post: State, c: int) -> bool {
    &&& pre.online.contains(c)
    &&& pre.fenced
    &&& pre.paused.contains(c)
    &&& map_at_s(pre.observed, c) =~= pre.terminal
    &&& owned(c, pre.pending) =~= Set::empty()
    &&& incoming(pre, c).subset_of(map_at_s(pre.applied, c))
    &&& !pre.intent1.contains(c)
    &&& post.intent1 =~= pre.intent1.insert(c)
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
    &&& post.online =~= pre.online
}

/// Select(c) == /\ c ∈ online /\ fenced /\ selected[c] = 0
///              /\ (intent[c] \/ SkipIntent)
///              /\ selected' = [selected EXCEPT ![c] = 1]
///              /\ archive' = [archive EXCEPT ![c] = IF DropArchive THEN {}
///                                                    ELSE terminal]
///              /\ spent' = [spent EXCEPT ![c] = IF ResetSpent THEN 0 ELSE @]
/// The intent and predecessor remain durable through crash/reopen;
/// selecting generation 1 is one atomic publication including archive and
/// spent basis.
pub open spec fn select(pre: State, post: State, si: bool, rs: bool, da: bool, c: int) -> bool {
    &&& pre.online.contains(c)
    &&& pre.fenced
    &&& !pre.selected1.contains(c)
    &&& (pre.intent1.contains(c) || si)
    &&& post.selected1 =~= pre.selected1.insert(c)
    &&& post.archive =~= pre.archive.insert(
        c,
        if da {
            Set::empty()
        } else {
            pre.terminal
        },
    )
    &&& post.spent =~= pre.spent.insert(
        c,
        if rs {
            0
        } else {
            map_at(pre.spent, c)
        },
    )
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.online =~= pre.online
}

/// Crash(c) == /\ c ∈ online /\ online' = online \ {c}
pub open spec fn crash(pre: State, post: State, c: int) -> bool {
    &&& pre.online.contains(c)
    &&& post.online =~= pre.online.remove(c)
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
}

/// Reopen(c) == /\ c ∉ online /\ online' = online ∪ {c}
pub open spec fn reopen(pre: State, post: State, c: int) -> bool {
    &&& !pre.online.contains(c)
    &&& post.online =~= pre.online.insert(c)
    &&& post.created =~= pre.created
    &&& post.pending =~= pre.pending
    &&& post.stored =~= pre.stored
    &&& post.applied =~= pre.applied
    &&& post.observed =~= pre.observed
    &&& post.paused =~= pre.paused
    &&& post.fenced == pre.fenced
    &&& post.terminal =~= pre.terminal
    &&& post.intent1 =~= pre.intent1
    &&& post.selected1 =~= pre.selected1
    &&& post.archive =~= pre.archive
    &&& post.spent =~= pre.spent
}

/// Next under arbitrary config constants SkipController, IgnoreHead,
/// SkipAutomatic, SkipIntent, ResetSpent, DropArchive.
pub open spec fn next_cfg(
    sc: bool,
    ih: bool,
    sa: bool,
    si: bool,
    rs: bool,
    da: bool,
    pre: State,
    post: State
) -> bool {
    ||| fence(pre, post, sc, ih)
    ||| race_write(pre, post)
    ||| exists|j: (int, int)| is_job(j) && #[trigger] store(pre, post, j)
    ||| exists|j: (int, int)| is_job(j) && #[trigger] receipt(pre, post, j)
    ||| exists|c: int| is_controller(c) && #[trigger] queue(pre, post, c)
    ||| exists|c: int| is_controller(c) && #[trigger] apply(pre, post, c)
    ||| exists|c: int| is_controller(c) && #[trigger] observe(pre, post, sa, c)
    ||| exists|c: int| is_controller(c) && #[trigger] pause(pre, post, sa, c)
    ||| exists|c: int| is_controller(c) && #[trigger] prepare(pre, post, c)
    ||| exists|c: int| is_controller(c) && #[trigger] select(pre, post, si, rs, da, c)
    ||| exists|c: int| is_controller(c) && #[trigger] crash(pre, post, c)
    ||| exists|c: int| is_controller(c) && #[trigger] reopen(pre, post, c)
}

/// normal.cfg: every mutant switch false.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, false, pre, post)
}

/// mutant-missing-controller.cfg: SkipController = TRUE.
pub open spec fn next_mutant_missing_controller(pre: State, post: State) -> bool {
    next_cfg(true, false, false, false, false, false, pre, post)
}

/// mutant-changed-head.cfg: IgnoreHead = TRUE.
pub open spec fn next_mutant_changed_head(pre: State, post: State) -> bool {
    next_cfg(false, true, false, false, false, false, pre, post)
}

/// mutant-automatic-output.cfg: SkipAutomatic = TRUE.
pub open spec fn next_mutant_automatic(pre: State, post: State) -> bool {
    next_cfg(false, false, true, false, false, false, pre, post)
}

/// mutant-missing-intent.cfg: SkipIntent = TRUE.
pub open spec fn next_mutant_missing_intent(pre: State, post: State) -> bool {
    next_cfg(false, false, false, true, false, false, pre, post)
}

/// mutant-reset-spend.cfg: ResetSpent = TRUE.
pub open spec fn next_mutant_reset_spend(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, true, false, pre, post)
}

/// mutant-lost-archive.cfg: DropArchive = TRUE.
pub open spec fn next_mutant_lost_archive(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, true, pre, post)
}

/// TypeOK.
pub open spec fn type_ok(s: State) -> bool {
    &&& s.created.subset_of(jobs())
    &&& s.pending.subset_of(s.created)
    &&& s.stored.subset_of(s.created.insert(foreign()))
    &&& s.applied.dom() =~= controllers()
    &&& forall|c: int| is_controller(c) ==> map_at_s(s.applied, c).subset_of(
        applications(),
    )
    &&& s.observed.dom() =~= controllers()
    &&& forall|c: int| is_controller(c) ==> map_at_s(s.observed, c).subset_of(
        job_atoms(),
    )
    &&& s.paused.subset_of(controllers())
    &&& s.online.subset_of(controllers())
    &&& s.terminal.subset_of(s.stored)
    &&& s.intent1.subset_of(controllers())
    &&& s.selected1.subset_of(controllers())
    &&& s.archive.dom() =~= controllers()
    &&& forall|c: int| is_controller(c) ==> map_at_s(s.archive, c).subset_of(
        job_atoms(),
    )
    &&& s.spent.dom() =~= controllers()
    &&& forall|c: int| is_controller(c) ==> 0 <= map_at(s.spent, c) <= 2
}

/// CompleteInventory == fenced => paused = Controllers
pub open spec fn complete_inventory(s: State) -> bool {
    s.fenced ==> s.paused =~= controllers()
}

/// ConditionalHead == fenced => ∀ c ∈ Controllers : observed[c] = terminal
pub open spec fn conditional_head(s: State) -> bool {
    s.fenced ==> forall|c: int| is_controller(c) ==> map_at_s(s.observed, c)
        =~= s.terminal
}

/// AutomaticOutputDrained == fenced =>
///     pending = {} /\ ∀ c ∈ Controllers : Incoming(c) ⊆ applied[c]
pub open spec fn automatic_output_drained(s: State) -> bool {
    s.fenced ==> (s.pending =~= Set::empty() && forall|c: int| is_controller(c)
        ==> incoming(s, c).subset_of(map_at_s(s.applied, c)))
}

/// IntentBeforeSelection == ∀ c : selected[c] = 1 => intent[c]
pub open spec fn intent_before_selection(s: State) -> bool {
    forall|c: int| is_controller(c) ==> (s.selected1.contains(c) ==> s.intent1.contains(c))
}

/// PreservedSpend == ∀ c : spent[c] = Cardinality(Owned(c, created))
pub open spec fn preserved_spend(s: State) -> bool {
    forall|c: int| is_controller(c) ==> map_at(s.spent, c) == owned(c, s.created).len()
}

/// PreservedArchive == ∀ c : selected[c] = 1 => archive[c] = terminal
pub open spec fn preserved_archive(s: State) -> bool {
    forall|c: int| is_controller(c) ==> (s.selected1.contains(c) ==> map_at_s(
        s.archive,
        c,
    ) =~= s.terminal)
}

/// FrozenPredecessor == fenced => stored = terminal
pub open spec fn frozen_predecessor(s: State) -> bool {
    s.fenced ==> s.stored =~= s.terminal
}

/// Auxiliary: applied[c] only ever holds a past Incoming(c), and Incoming
/// is monotone in stored — so applied[c] ⊆ Incoming(c). With two
/// controllers Incoming(c) ⊆ {App(other c)}, which is what makes Apply
/// fire at most once.
pub open spec fn aux_applied_incoming(s: State) -> bool {
    forall|c: int| is_controller(c) ==> map_at_s(s.applied, c).subset_of(
        incoming(s, c),
    )
}

/// Auxiliary: a created acceptance means the creating Apply ran, which set
/// applied[c] to a nonempty Incoming — and applied is only rewritten by
/// another Apply, which needs a strictly larger Incoming first.
pub open spec fn aux_ack_applied(s: State) -> bool {
    forall|c: int| is_controller(c) && s.created.contains(ack(c)) ==> !(map_at_s(
        s.applied,
        c,
    ) =~= Set::empty())
}

/// Auxiliary: every observation is a past stored snapshot and stored only
/// grows, so observed[c] ⊆ stored.
pub open spec fn aux_observed_stored(s: State) -> bool {
    forall|c: int| is_controller(c) ==> map_at_s(s.observed, c).subset_of(s.stored)
}

/// Auxiliary: a paused controller stays drained — Queue/Apply need the
/// owner unpaused, Receipt only removes, and pending jobs are always
/// owned by their creator.
pub open spec fn aux_paused_drained(s: State) -> bool {
    forall|c: int| s.paused.contains(c) ==> owned(c, s.pending) =~= Set::empty()
}

/// Auxiliary: a paused controller whose recorded observation still equals
/// the current stored has already applied all of its incoming work. The
/// Pause guard establishes it; while paused, observed/applied are frozen
/// and any stored growth breaks the observation equality instead.
pub open spec fn aux_paused_applied(s: State) -> bool {
    forall|c: int| is_controller(c) && s.paused.contains(c) && map_at_s(s.observed, c)
        =~= s.stored ==> incoming(s, c).subset_of(map_at_s(s.applied, c))
}

/// Auxiliary: selection only happens after the fence, so an unfenced
/// state has no selected controller.
pub open spec fn aux_selected_fenced(s: State) -> bool {
    forall|c: int| s.selected1.contains(c) ==> s.fenced
}

/// The inductive invariant: TypeOK plus the seven checked safety
/// invariants, strengthened by the six auxiliaries.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& complete_inventory(s)
    &&& conditional_head(s)
    &&& automatic_output_drained(s)
    &&& intent_before_selection(s)
    &&& preserved_spend(s)
    &&& preserved_archive(s)
    &&& frozen_predecessor(s)
    &&& aux_applied_incoming(s)
    &&& aux_ack_applied(s)
    &&& aux_observed_stored(s)
    &&& aux_paused_drained(s)
    &&& aux_paused_applied(s)
    &&& aux_selected_fenced(s)
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

/// The same for set-valued maps.
proof fn map_insert_at_s(m: Map<int, Set<(int, int)>>, k: int, v: Set<(int, int)>, x: int)
    ensures
        map_at_s(m.insert(k, v), x) =~= if x == k {
            v
        } else {
            map_at_s(m, x)
        },
{
}

/// Membership in Owned(c, js).
proof fn owned_mem(c: int, js: Set<(int, int)>, j: (int, int))
    ensures
        owned(c, js).contains(j) == (js.contains(j) && j.1 == c),
{
}

/// Owned distributes over insert.
proof fn owned_insert(c: int, js: Set<(int, int)>, j: (int, int))
    ensures
        owned(c, js.insert(j)) =~= if j.1 == c {
            owned(c, js).insert(j)
        } else {
            owned(c, js)
        },
{
    if j.1 == c {
        assert(owned(c, js.insert(j)) =~= owned(c, js).insert(j)) by {
            assert forall|x: (int, int)| owned(c, js.insert(j)).contains(x)
                implies owned(c, js).insert(j).contains(x) by {
                owned_mem(c, js.insert(j), x);
            }
            assert forall|x: (int, int)| owned(c, js).insert(j).contains(x)
                implies owned(c, js.insert(j)).contains(x) by {
                owned_mem(c, js.insert(j), x);
            }
        }
    } else {
        assert(owned(c, js.insert(j)) =~= owned(c, js)) by {
            assert forall|x: (int, int)| owned(c, js.insert(j)).contains(x)
                implies owned(c, js).contains(x) by {
                owned_mem(c, js.insert(j), x);
            }
            assert forall|x: (int, int)| owned(c, js).contains(x) implies owned(
                c,
                js.insert(j),
            ).contains(x) by {
                owned_mem(c, js.insert(j), x);
            }
        }
    }
}

/// Owned distributes over remove.
proof fn owned_remove(c: int, js: Set<(int, int)>, j: (int, int))
    ensures
        owned(c, js.remove(j)) =~= owned(c, js).remove(j),
{
    assert(owned(c, js.remove(j)) =~= owned(c, js).remove(j)) by {
        assert forall|x: (int, int)| owned(c, js.remove(j)).contains(x) implies owned(
            c,
            js,
        ).remove(j).contains(x) by {
            owned_mem(c, js.remove(j), x);
        }
        assert forall|x: (int, int)| owned(c, js).remove(j).contains(x) implies owned(
            c,
            js.remove(j),
        ).contains(x) by {
            owned_mem(c, js.remove(j), x);
        }
    }
}

/// Over Jobs the owned jobs of c are exactly {App(c), Ack(c)}.
proof fn owned_jobs_bound(c: int, js: Set<(int, int)>)
    requires
        is_controller(c),
        js.subset_of(jobs()),
    ensures
        owned(c, js).subset_of(Set::empty().insert(app(c)).insert(ack(c))),
{
    assert forall|j: (int, int)| owned(c, js).contains(j) implies Set::empty()
        .insert(app(c))
        .insert(ack(c))
        .contains(j) by {
        owned_mem(c, js, j);
        assert(js.contains(j));
        assert(jobs().contains(j));
        assert(j == app(1) || j == app(2) || j == ack(1) || j == ack(2)) by {
            if applications().contains(j) {
                assert(j == app(1) || j == app(2));
            } else {
                assert(acceptances().contains(j));
                assert(j == ack(1) || j == ack(2));
            }
        }
        assert(j.1 == c);
        assert(c == 1 || c == 2);
    }
}

/// Incoming(c) is bounded by the single other controller's application:
/// Incoming(c) ⊆ Applications \ {App(c)} = {App(other c)}.
proof fn incoming_singleton(s: State, c: int)
    requires
        is_controller(c),
    ensures
        incoming(s, c).subset_of(Set::empty().insert(app(other(c)))),
{
    assert forall|j: (int, int)| incoming(s, c).contains(j) implies Set::empty()
        .insert(app(other(c)))
        .contains(j) by {
        assert(applications().contains(j));
        assert(j == app(1) || j == app(2));
        assert(j != app(c));
        assert(c == 1 || c == 2);
        assert(j == app(other(c)));
    }
}

/// Storing a job grows Incoming(c) by at most that job.
proof fn incoming_store(pre: State, post: State, j: (int, int), c: int)
    requires
        post.stored =~= pre.stored.insert(j),
    ensures
        incoming(post, c) =~= if applications().contains(j) && j != app(c) {
            incoming(pre, c).insert(j)
        } else {
            incoming(pre, c)
        },
{
    assert(incoming(post, c) =~= if applications().contains(j) && j != app(c) {
        incoming(pre, c).insert(j)
    } else {
        incoming(pre, c)
    }) by {
        assert forall|x: (int, int)| incoming(post, c).contains(x) implies (if applications()
            .contains(j) && j != app(c) {
            incoming(pre, c).insert(j)
        } else {
            incoming(pre, c)
        }).contains(x) by {
            if x != j {
                assert(pre.stored.intersect(applications()).contains(x));
            }
        }
        assert forall|x: (int, int)| (if applications().contains(j) && j != app(c) {
            incoming(pre, c).insert(j)
        } else {
            incoming(pre, c)
        }).contains(x) implies incoming(post, c).contains(x) by {
            if x == j {
            } else {
                assert(pre.stored.intersect(applications()).contains(x));
            }
        }
    }
}

/// A RaceWrite cannot change Incoming(c): Foreign is not an application.
proof fn incoming_race(pre: State, post: State, c: int)
    requires
        post.stored =~= pre.stored.insert(foreign()),
    ensures
        incoming(post, c) =~= incoming(pre, c),
{
    assert(incoming(post, c) =~= incoming(pre, c)) by {
        assert forall|x: (int, int)| incoming(post, c).contains(x)
            implies incoming(pre, c).contains(x) by {
            assert(applications().contains(x));
            assert(x != foreign());
            assert(pre.stored.contains(x));
        }
        assert forall|x: (int, int)| incoming(pre, c).contains(x)
            implies incoming(post, c).contains(x) by {
        }
    }
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
    assert(s.applied.dom() =~= controllers());
    assert(s.observed.dom() =~= controllers());
    assert(s.archive.dom() =~= controllers());
    assert(s.spent.dom() =~= controllers());
    assert forall|c: int| is_controller(c) implies map_at_s(s.applied, c).subset_of(
        applications(),
    ) by {
        assert(s.applied.dom().contains(c));
    }
    assert forall|c: int| is_controller(c) implies map_at_s(s.observed, c).subset_of(
        job_atoms(),
    ) by {
        assert(s.observed.dom().contains(c));
    }
    assert forall|c: int| is_controller(c) implies map_at_s(s.archive, c).subset_of(
        job_atoms(),
    ) by {
        assert(s.archive.dom().contains(c));
    }
    assert forall|c: int| is_controller(c) implies 0 <= map_at(s.spent, c) <= 2 by {
        assert(s.spent.dom().contains(c));
    }
    assert forall|c: int| is_controller(c) implies map_at(s.spent, c) == owned(
        c,
        s.created,
    ).len() by {
        assert(owned(c, s.created) =~= Set::empty()) by {
            assert forall|j: (int, int)| !owned(c, s.created).contains(j) by {
                owned_mem(c, s.created, j);
            }
        }
    }
    assert forall|c: int| s.paused.contains(c) implies owned(c, s.pending)
        =~= Set::empty() by {
    }
    assert(type_ok(s));
    assert(complete_inventory(s));
    assert(conditional_head(s));
    assert(automatic_output_drained(s));
    assert(intent_before_selection(s));
    assert(preserved_spend(s));
    assert(preserved_archive(s));
    assert(frozen_predecessor(s));
    assert(aux_applied_incoming(s));
    assert(aux_ack_applied(s));
    assert(aux_observed_stored(s));
    assert(aux_paused_drained(s));
    assert(aux_paused_applied(s));
    assert(aux_selected_fenced(s));
}

proof fn queue_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        queue(pre, post, c),
    ensures
        inv(post),
{
    // PreservedSpend / TypeOK spent bound: app(c) ∉ created keeps
    // Owned(c, created) ⊆ {Ack(c)}, so spent[c] ≤ 1 before the bump.
    assert(!owned(c, pre.created).contains(app(c))) by {
        owned_mem(c, pre.created, app(c));
    }
    assert(owned(c, pre.created).subset_of(Set::empty().insert(ack(c)))) by {
        owned_jobs_bound(c, pre.created);
        assert forall|j: (int, int)| owned(c, pre.created).contains(j)
            implies Set::empty().insert(ack(c)).contains(j) by {
            assert(j == app(c) || j == ack(c));
            if j == app(c) {
                assert(pre.created.contains(app(c)));
            }
        }
    }
    vstd::set_lib::lemma_len_subset(
        owned(c, pre.created),
        Set::empty().insert(ack(c)),
    );
    assert(owned(c, pre.created).len() <= 1);
    assert(map_at(pre.spent, c) <= 1);
    owned_insert(c, pre.created, app(c));
    assert(owned(c, post.created) =~= owned(c, pre.created).insert(app(c)));
    assert(!owned(c, pre.created).contains(app(c)));
    assert(owned(c, post.created).len() == owned(c, pre.created).len() + 1);
    map_insert_at(pre.spent, c, map_at(pre.spent, c) + 1, c);
    assert forall|x: int| is_controller(x) implies map_at(post.spent, x) == owned(
        x,
        post.created,
    ).len() by {
        map_insert_at(pre.spent, c, map_at(pre.spent, c) + 1, x);
        if x == c {
        } else {
            owned_insert(x, pre.created, app(c));
            assert(app(c).1 == c && c != x);
            assert(owned(x, post.created) =~= owned(x, pre.created));
        }
    }
    assert forall|x: int| is_controller(x) implies 0 <= map_at(post.spent, x) <= 2 by {
        map_insert_at(pre.spent, c, map_at(pre.spent, c) + 1, x);
    }
    assert(post.spent.dom() =~= controllers()) by {
        assert(post.spent.dom() =~= pre.spent.dom().insert(c));
        assert(pre.spent.dom().insert(c) =~= controllers());
    }
    assert(post.created.subset_of(jobs())) by {
        assert forall|j: (int, int)| post.created.contains(j) implies jobs().contains(j) by {
            if j == app(c) {
                assert(applications().contains(j));
            } else {
                assert(pre.created.contains(j));
            }
        }
    }
    assert(post.pending.subset_of(post.created)) by {
        assert forall|j: (int, int)| post.pending.contains(j) implies post.created.contains(
            j,
        ) by {
            if j == app(c) {
            } else {
                assert(pre.pending.contains(j));
                assert(pre.created.contains(j));
            }
        }
    }
    assert(post.stored.subset_of(post.created.insert(foreign()))) by {
        assert forall|j: (int, int)| post.stored.contains(j) implies post.created
            .insert(foreign())
            .contains(j) by {
            assert(pre.stored.contains(j));
            if j == foreign() {
            } else {
                assert(pre.created.contains(j));
            }
        }
    }
    // aux_paused_drained: only c gains an owned pending member; paused
    // members d ≠ c keep their empty owned sets.
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(x));
        assert(x != c);
        owned_insert(x, pre.pending, app(c));
        assert(owned(x, post.pending) =~= owned(x, pre.pending));
    }
    // aux_paused_applied: paused members kept their frozen observation, so
    // the implication is carried unchanged.
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        assert(pre.paused.contains(x));
        assert(map_at_s(pre.observed, x) =~= pre.stored);
    }
    // aux_ack_applied: the new member is an application, not an acceptance.
    assert forall|x: int| is_controller(x) && post.created.contains(ack(x))
        implies !(map_at_s(post.applied, x) =~= Set::empty()) by {
        assert(ack(x) != app(c));
        assert(pre.created.contains(ack(x)));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn store_preserves(pre: State, post: State, j: (int, int))
    requires
        inv(pre),
        is_job(j),
        store(pre, post, j),
    ensures
        inv(post),
{
    assert(pre.created.contains(j));
    assert(post.stored.subset_of(post.created.insert(foreign()))) by {
        assert forall|x: (int, int)| post.stored.contains(x) implies post.created
            .insert(foreign())
            .contains(x) by {
            if x == j {
            } else {
                assert(pre.stored.contains(x));
                assert(pre.created.insert(foreign()).contains(x));
            }
        }
    }
    // aux_applied_incoming: Incoming only grows when stored does.
    assert forall|c: int| is_controller(c) implies map_at_s(post.applied, c).subset_of(
        incoming(post, c),
    ) by {
        incoming_store(pre, post, j, c);
        assert(map_at_s(pre.applied, c).subset_of(incoming(pre, c)));
    }
    // aux_observed_stored: a past observation stays inside the grown set.
    assert forall|c: int| is_controller(c) implies map_at_s(post.observed, c).subset_of(
        post.stored,
    ) by {
        assert(map_at_s(pre.observed, c).subset_of(pre.stored));
    }
    // aux_paused_applied: a paused controller cannot satisfy the
    // antecedent at post — its frozen observation misses the new member.
    assert forall|c: int| is_controller(c) && post.paused.contains(c) && map_at_s(
        post.observed,
        c,
    ) =~= post.stored implies incoming(post, c).subset_of(map_at_s(post.applied, c)) by {
        assert(pre.paused.contains(c));
        assert(map_at_s(pre.observed, c).subset_of(pre.stored));
        if map_at_s(pre.observed, c) =~= post.stored {
            assert(pre.stored.insert(j).contains(j));
            assert(pre.stored.contains(j));
            assert(false);
        }
    }
    // aux_paused_drained: pending is unchanged.
    assert forall|c: int| post.paused.contains(c) implies owned(c, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(c));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn receipt_preserves(pre: State, post: State, j: (int, int))
    requires
        inv(pre),
        is_job(j),
        receipt(pre, post, j),
    ensures
        inv(post),
{
    assert(post.pending.subset_of(post.created)) by {
        assert forall|x: (int, int)| post.pending.contains(x) implies post.created.contains(
            x,
        ) by {
            assert(pre.pending.contains(x));
            assert(pre.created.contains(x));
        }
    }
    // aux_paused_drained: removing a pending job cannot grow Owned.
    assert forall|c: int| post.paused.contains(c) implies owned(c, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(c));
        owned_remove(c, pre.pending, j);
        assert(owned(c, post.pending) =~= owned(c, pre.pending).remove(j));
    }
    // AutomaticOutputDrained: fenced keeps pending = {} through removal.
    if post.fenced {
        assert(pre.fenced);
        assert(pre.pending =~= Set::empty());
        assert(post.pending =~= Set::empty()) by {
            assert forall|x: (int, int)| !post.pending.contains(x) by {
                if post.pending.contains(x) {
                    assert(pre.pending.contains(x));
                }
            }
        }
    }
    // aux_paused_applied: stored, observed, applied, incoming unchanged.
    assert forall|c: int| is_controller(c) && post.paused.contains(c) && map_at_s(
        post.observed,
        c,
    ) =~= post.stored implies incoming(post, c).subset_of(map_at_s(post.applied, c)) by {
        assert(pre.paused.contains(c));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn apply_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        apply(pre, post, c),
    ensures
        inv(post),
{
    // Apply cannot fire twice: if Ack(c) were already created then
    // applied[c] ≠ {} (aux_ack_applied); with applied[c] ⊆ Incoming(c)
    // ⊆ {App(other)} that forces applied[c] = {App(other)} ⊇ Incoming(c),
    // contradicting the nonempty-difference guard.
    if pre.created.contains(ack(c)) {
        assert(!(map_at_s(pre.applied, c) =~= Set::empty()));
        incoming_singleton(pre, c);
        assert(incoming(pre, c).subset_of(Set::empty().insert(app(other(c)))));
        assert(map_at_s(pre.applied, c).subset_of(incoming(pre, c)));
        assert(map_at_s(pre.applied, c) =~= Set::empty().insert(app(other(c)))) by {
            let w = choose|w: (int, int)| map_at_s(pre.applied, c).contains(w);
            assert(incoming(pre, c).contains(w));
            assert(w == app(other(c)));
            assert forall|x: (int, int)| map_at_s(pre.applied, c).contains(x)
                implies Set::empty().insert(app(other(c))).contains(x) by {
                assert(incoming(pre, c).contains(x));
            }
            assert forall|x: (int, int)| Set::empty().insert(app(other(c))).contains(x)
                implies map_at_s(pre.applied, c).contains(x) by {
                assert(x == app(other(c)));
                assert(x == w);
            }
        }
        assert(incoming(pre, c).subset_of(map_at_s(pre.applied, c)));
        assert(incoming(pre, c).difference(map_at_s(pre.applied, c)) =~= Set::empty()) by {
            assert forall|x: (int, int)| !incoming(pre, c)
                .difference(map_at_s(pre.applied, c))
                .contains(x) by {
                if incoming(pre, c).contains(x) {
                    assert(map_at_s(pre.applied, c).contains(x));
                }
            }
        }
        assert(false);
    }
    assert(!pre.created.contains(ack(c)));
    // spent bound: Owned(c, created) ⊆ {App(c)} since Ack(c) ∉ created.
    assert(!owned(c, pre.created).contains(ack(c))) by {
        owned_mem(c, pre.created, ack(c));
    }
    assert(owned(c, pre.created).subset_of(Set::empty().insert(app(c)))) by {
        owned_jobs_bound(c, pre.created);
        assert forall|j: (int, int)| owned(c, pre.created).contains(j)
            implies Set::empty().insert(app(c)).contains(j) by {
            assert(j == app(c) || j == ack(c));
        }
    }
    vstd::set_lib::lemma_len_subset(owned(c, pre.created), Set::empty().insert(app(c)));
    assert(map_at(pre.spent, c) <= 1);
    // PreservedSpend: Ack(c) joins Owned(c, created).
    owned_insert(c, pre.created, ack(c));
    assert(owned(c, post.created) =~= owned(c, pre.created).insert(ack(c)));
    assert(owned(c, post.created).len() == owned(c, pre.created).len() + 1);
    map_insert_at(pre.spent, c, map_at(pre.spent, c) + 1, c);
    assert forall|x: int| is_controller(x) implies map_at(post.spent, x) == owned(
        x,
        post.created,
    ).len() by {
        map_insert_at(pre.spent, c, map_at(pre.spent, c) + 1, x);
        if x == c {
        } else {
            owned_insert(x, pre.created, ack(c));
            assert(ack(c).1 == c && c != x);
            assert(owned(x, post.created) =~= owned(x, pre.created));
        }
    }
    assert forall|x: int| is_controller(x) implies 0 <= map_at(post.spent, x) <= 2 by {
        map_insert_at(pre.spent, c, map_at(pre.spent, c) + 1, x);
    }
    assert(post.spent.dom() =~= controllers()) by {
        assert(post.spent.dom() =~= pre.spent.dom().insert(c));
        assert(pre.spent.dom().insert(c) =~= controllers());
    }
    assert(post.applied.dom() =~= controllers()) by {
        assert(post.applied.dom() =~= pre.applied.dom().insert(c));
        assert(pre.applied.dom().insert(c) =~= controllers());
    }
    assert forall|x: int| is_controller(x) implies map_at_s(post.applied, x).subset_of(
        applications(),
    ) by {
        map_insert_at_s(pre.applied, c, incoming(pre, c), x);
        if x == c {
            assert(incoming(pre, c).subset_of(applications())) by {
                assert forall|j: (int, int)| incoming(pre, c).contains(j)
                    implies applications().contains(j) by {
                }
            }
        }
    }
    assert(post.created.subset_of(jobs())) by {
        assert forall|j: (int, int)| post.created.contains(j) implies jobs().contains(j) by {
            if j == ack(c) {
                assert(acceptances().contains(j));
            } else {
                assert(pre.created.contains(j));
            }
        }
    }
    assert(post.pending.subset_of(post.created)) by {
        assert forall|j: (int, int)| post.pending.contains(j) implies post.created.contains(
            j,
        ) by {
            if j == ack(c) {
            } else {
                assert(pre.pending.contains(j));
                assert(pre.created.contains(j));
            }
        }
    }
    assert(post.stored.subset_of(post.created.insert(foreign()))) by {
        assert forall|j: (int, int)| post.stored.contains(j) implies post.created
            .insert(foreign())
            .contains(j) by {
            assert(pre.stored.contains(j));
            if j == foreign() {
            } else {
                assert(pre.created.contains(j));
            }
        }
    }
    // aux_applied_incoming: applied'[c] = Incoming(c); the incoming set is
    // unchanged, and for x ≠ c both sides are carried.
    assert forall|x: int| is_controller(x) implies map_at_s(post.applied, x).subset_of(
        incoming(post, x),
    ) by {
        map_insert_at_s(pre.applied, c, incoming(pre, c), x);
        if x == c {
            assert(incoming(post, x) =~= incoming(pre, x));
        } else {
            assert(incoming(post, x) =~= incoming(pre, x));
        }
    }
    // aux_ack_applied: applied'[c] = Incoming(c) is nonempty because the
    // guard's difference is nonempty; other controllers are carried.
    assert(incoming(pre, c).contains(choose|j: (int, int)| incoming(pre, c)
        .difference(map_at_s(pre.applied, c))
        .contains(j)));
    assert forall|x: int| is_controller(x) && post.created.contains(ack(x))
        implies !(map_at_s(post.applied, x) =~= Set::empty()) by {
        if x == c {
            map_insert_at_s(pre.applied, c, incoming(pre, c), x);
            assert(map_at_s(post.applied, x) =~= incoming(pre, x));
        } else {
            assert(ack(x) != ack(c));
            assert(pre.created.contains(ack(x)));
            map_insert_at_s(pre.applied, c, incoming(pre, c), x);
            assert(map_at_s(post.applied, x) =~= map_at_s(pre.applied, x));
        }
    }
    // aux_paused_drained: the new pending member is owned by c, which is
    // not paused.
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(x));
        assert(x != c);
        owned_insert(x, pre.pending, ack(c));
        assert(owned(x, post.pending) =~= owned(x, pre.pending));
    }
    // aux_paused_applied: stored, observed and incoming are unchanged;
    // applied changes only at the unpaused c.
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        assert(pre.paused.contains(x));
        assert(x != c);
        map_insert_at_s(pre.applied, c, incoming(pre, c), x);
        assert(map_at_s(post.applied, x) =~= map_at_s(pre.applied, x));
        assert(incoming(post, x) =~= incoming(pre, x));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn observe_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        observe(pre, post, false, c),
    ensures
        inv(post),
{
    assert(post.observed.dom() =~= controllers()) by {
        assert(post.observed.dom() =~= pre.observed.dom().insert(c));
        assert(pre.observed.dom().insert(c) =~= controllers());
    }
    assert forall|x: int| is_controller(x) implies map_at_s(post.observed, x).subset_of(
        job_atoms(),
    ) by {
        map_insert_at_s(pre.observed, c, pre.stored, x);
        if x == c {
            assert(pre.stored.subset_of(job_atoms())) by {
                assert forall|j: (int, int)| pre.stored.contains(j)
                    implies job_atoms().contains(j) by {
                    assert(pre.created.insert(foreign()).contains(j));
                    if j != foreign() {
                        assert(pre.created.contains(j));
                        assert(jobs().contains(j));
                    }
                }
            }
        }
    }
    // aux_observed_stored: the new observation equals the current stored.
    assert forall|x: int| is_controller(x) implies map_at_s(post.observed, x).subset_of(
        post.stored,
    ) by {
        map_insert_at_s(pre.observed, c, pre.stored, x);
        if x == c {
            assert(map_at_s(post.observed, x) =~= pre.stored);
        } else {
            assert(map_at_s(post.observed, x) =~= map_at_s(pre.observed, x));
            assert(map_at_s(pre.observed, x).subset_of(pre.stored));
        }
    }
    // aux_paused_applied: the acting controller is not paused; others keep
    // their observation, stored and applied answers.
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        assert(pre.paused.contains(x));
        assert(x != c);
        map_insert_at_s(pre.observed, c, pre.stored, x);
        assert(map_at_s(post.observed, x) =~= map_at_s(pre.observed, x));
        assert(incoming(post, x) =~= incoming(pre, x));
    }
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(x));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn pause_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        pause(pre, post, false, c),
    ensures
        inv(post),
{
    assert(post.paused.subset_of(controllers())) by {
        assert forall|x: int| post.paused.contains(x) implies controllers().contains(x) by {
            if x == c {
                assert(is_controller(c));
            } else {
                assert(pre.paused.contains(x));
            }
        }
    }
    // aux_paused_drained: the Pause guard supplies c's empty owned set.
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        if x == c {
            assert(owned(c, pre.pending) =~= Set::empty());
        } else {
            assert(pre.paused.contains(x));
        }
    }
    // aux_paused_applied: the Pause guard supplies observed[c] = stored
    // and (with SkipAutomatic false) Incoming(c) ⊆ applied[c].
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        if x == c {
            assert(incoming(pre, c).subset_of(map_at_s(pre.applied, c)));
        } else {
            assert(pre.paused.contains(x));
        }
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn race_write_preserves(pre: State, post: State)
    requires
        inv(pre),
        race_write(pre, post),
    ensures
        inv(post),
{
    assert(post.stored.subset_of(post.created.insert(foreign()))) by {
        assert forall|x: (int, int)| post.stored.contains(x) implies post.created
            .insert(foreign())
            .contains(x) by {
            if x == foreign() {
            } else {
                assert(pre.stored.contains(x));
            }
        }
    }
    // aux_applied_incoming: Foreign is not an application, so Incoming is
    // unchanged.
    assert forall|c: int| is_controller(c) implies map_at_s(post.applied, c).subset_of(
        incoming(post, c),
    ) by {
        incoming_race(pre, post, c);
        assert(incoming(post, c) =~= incoming(pre, c));
    }
    // aux_observed_stored: a past observation stays inside the grown set.
    assert forall|c: int| is_controller(c) implies map_at_s(post.observed, c).subset_of(
        post.stored,
    ) by {
        assert(map_at_s(pre.observed, c).subset_of(pre.stored));
    }
    // aux_paused_applied: as in Store, the antecedent is impossible — a
    // paused controller's frozen observation cannot contain Foreign.
    assert forall|c: int| is_controller(c) && post.paused.contains(c) && map_at_s(
        post.observed,
        c,
    ) =~= post.stored implies incoming(post, c).subset_of(map_at_s(post.applied, c)) by {
        assert(pre.paused.contains(c));
        assert(map_at_s(pre.observed, c).subset_of(pre.stored));
        if map_at_s(pre.observed, c) =~= post.stored {
            assert(post.stored.contains(foreign()));
            assert(pre.stored.contains(foreign()));
            assert(false);
        }
    }
    assert forall|c: int| post.paused.contains(c) implies owned(c, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(c));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn fence_preserves(pre: State, post: State)
    requires
        inv(pre),
        fence(pre, post, false, false),
    ensures
        inv(post),
{
    // Required = Controllers: the fence guard gives paused ⊇ Controllers,
    // and TypeOK gives ⊆, so paused = Controllers.
    assert(pre.paused =~= controllers()) by {
        assert(controllers().subset_of(pre.paused));
        assert(pre.paused.subset_of(controllers()));
    }
    assert(post.paused =~= controllers());
    // AutomaticOutputDrained, pending = {}: every pending member is a job,
    // hence owned by a controller, and every controller is paused and
    // therefore drained.
    assert(post.pending =~= Set::empty()) by {
        assert forall|x: (int, int)| !post.pending.contains(x) by {
            if post.pending.contains(x) {
                assert(pre.pending.contains(x));
                assert(pre.created.contains(x));
                assert(jobs().contains(x));
                assert(is_controller(x.1));
                assert(pre.paused.contains(x.1));
                owned_mem(x.1, pre.pending, x);
                assert(owned(x.1, pre.pending).contains(x));
                assert(owned(x.1, pre.pending) =~= Set::empty());
            }
        }
    }
    // AutomaticOutputDrained, Incoming ⊆ applied: paused + observed-head
    // equality is exactly the aux_paused_applied antecedent.
    assert forall|c: int| is_controller(c) implies incoming(post, c).subset_of(
        map_at_s(post.applied, c),
    ) by {
        assert(pre.paused.contains(c));
        assert(controllers().contains(c));
        assert(map_at_s(pre.observed, c) =~= pre.stored);
        assert(incoming(pre, c).subset_of(map_at_s(pre.applied, c)));
        assert(incoming(post, c) =~= incoming(pre, c));
    }
    // PreservedArchive: no controller could be selected before the fence.
    assert(post.selected1 =~= Set::empty()) by {
        assert forall|x: int| !post.selected1.contains(x) by {
            if post.selected1.contains(x) {
                assert(pre.selected1.contains(x));
                assert(pre.fenced);
            }
        }
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn prepare_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        prepare(pre, post, c),
    ensures
        inv(post),
{
    assert(post.intent1.subset_of(controllers())) by {
        assert forall|x: int| post.intent1.contains(x) implies controllers().contains(x) by {
            if x == c {
                assert(is_controller(c));
            } else {
                assert(pre.intent1.contains(x));
            }
        }
    }
    // IntentBeforeSelection: the intent set only grows.
    assert forall|x: int| is_controller(x) && post.selected1.contains(x)
        implies post.intent1.contains(x) by {
        assert(pre.selected1.contains(x));
        assert(pre.intent1.contains(x));
    }
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(x));
    }
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        assert(pre.paused.contains(x));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn select_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        select(pre, post, false, false, false, c),
    ensures
        inv(post),
{
    assert(post.selected1.subset_of(controllers())) by {
        assert forall|x: int| post.selected1.contains(x) implies controllers().contains(
            x,
        ) by {
            if x == c {
                assert(is_controller(c));
            } else {
                assert(pre.selected1.contains(x));
            }
        }
    }
    assert(post.archive.dom() =~= controllers()) by {
        assert(post.archive.dom() =~= pre.archive.dom().insert(c));
        assert(pre.archive.dom().insert(c) =~= controllers());
    }
    assert forall|x: int| is_controller(x) implies map_at_s(post.archive, x).subset_of(
        job_atoms(),
    ) by {
        map_insert_at_s(pre.archive, c, pre.terminal, x);
        if x == c {
            assert(pre.terminal.subset_of(job_atoms())) by {
                assert forall|j: (int, int)| pre.terminal.contains(j)
                    implies job_atoms().contains(j) by {
                    assert(pre.stored.contains(j));
                    assert(pre.created.insert(foreign()).contains(j));
                    if j != foreign() {
                        assert(pre.created.contains(j));
                        assert(jobs().contains(j));
                    }
                }
            }
        }
    }
    // IntentBeforeSelection: the guard supplies intent[c].
    assert forall|x: int| is_controller(x) && post.selected1.contains(x)
        implies post.intent1.contains(x) by {
        if x == c {
            assert(pre.intent1.contains(c));
        } else {
            assert(pre.selected1.contains(x));
            assert(pre.intent1.contains(x));
        }
    }
    // PreservedArchive: archive'[c] = terminal and terminal is unchanged.
    assert forall|x: int| is_controller(x) && post.selected1.contains(x)
        implies map_at_s(post.archive, x) =~= post.terminal by {
        if x == c {
            map_insert_at_s(pre.archive, c, pre.terminal, x);
            assert(map_at_s(post.archive, c) =~= pre.terminal);
        } else {
            assert(pre.selected1.contains(x));
            map_insert_at_s(pre.archive, c, pre.terminal, x);
            assert(map_at_s(post.archive, x) =~= map_at_s(pre.archive, x));
        }
    }
    // PreservedSpend: ResetSpent is false, so spent is unchanged.
    assert forall|x: int| is_controller(x) implies map_at(post.spent, x) == owned(
        x,
        post.created,
    ).len() by {
        map_insert_at(pre.spent, c, map_at(pre.spent, c), x);
        if x == c {
        }
    }
    assert forall|x: int| is_controller(x) implies 0 <= map_at(post.spent, x) <= 2 by {
        map_insert_at(pre.spent, c, map_at(pre.spent, c), x);
    }
    assert(post.spent.dom() =~= controllers()) by {
        assert(post.spent.dom() =~= pre.spent.dom().insert(c));
        assert(pre.spent.dom().insert(c) =~= controllers());
    }
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(x));
    }
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        assert(pre.paused.contains(x));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn crash_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        crash(pre, post, c),
    ensures
        inv(post),
{
    assert(post.online.subset_of(controllers())) by {
        assert forall|x: int| post.online.contains(x) implies controllers().contains(x) by {
            assert(pre.online.contains(x));
        }
    }
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(x));
    }
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        assert(pre.paused.contains(x));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn reopen_preserves(pre: State, post: State, c: int)
    requires
        inv(pre),
        is_controller(c),
        reopen(pre, post, c),
    ensures
        inv(post),
{
    assert(post.online.subset_of(controllers())) by {
        assert forall|x: int| post.online.contains(x) implies controllers().contains(x) by {
            if x == c {
                assert(is_controller(c));
            } else {
                assert(pre.online.contains(x));
            }
        }
    }
    assert forall|x: int| post.paused.contains(x) implies owned(x, post.pending)
        =~= Set::empty() by {
        assert(pre.paused.contains(x));
    }
    assert forall|x: int| is_controller(x) && post.paused.contains(x) && map_at_s(
        post.observed,
        x,
    ) =~= post.stored implies incoming(post, x).subset_of(map_at_s(post.applied, x)) by {
        assert(pre.paused.contains(x));
    }
    assert(type_ok(post));
    assert(complete_inventory(post));
    assert(conditional_head(post));
    assert(automatic_output_drained(post));
    assert(intent_before_selection(post));
    assert(preserved_spend(post));
    assert(preserved_archive(post));
    assert(frozen_predecessor(post));
    assert(aux_applied_incoming(post));
    assert(aux_ack_applied(post));
    assert(aux_observed_stored(post));
    assert(aux_paused_drained(post));
    assert(aux_paused_applied(post));
    assert(aux_selected_fenced(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if fence(pre, post, false, false) {
        fence_preserves(pre, post);
    } else if race_write(pre, post) {
        race_write_preserves(pre, post);
    } else if exists|j: (int, int)| is_job(j) && store(pre, post, j) {
        let j = choose|j: (int, int)| is_job(j) && store(pre, post, j);
        store_preserves(pre, post, j);
    } else if exists|j: (int, int)| is_job(j) && receipt(pre, post, j) {
        let j = choose|j: (int, int)| is_job(j) && receipt(pre, post, j);
        receipt_preserves(pre, post, j);
    } else if exists|c: int| is_controller(c) && queue(pre, post, c) {
        let c = choose|c: int| is_controller(c) && queue(pre, post, c);
        queue_preserves(pre, post, c);
    } else if exists|c: int| is_controller(c) && apply(pre, post, c) {
        let c = choose|c: int| is_controller(c) && apply(pre, post, c);
        apply_preserves(pre, post, c);
    } else if exists|c: int| is_controller(c) && observe(pre, post, false, c) {
        let c = choose|c: int| is_controller(c) && observe(pre, post, false, c);
        observe_preserves(pre, post, c);
    } else if exists|c: int| is_controller(c) && pause(pre, post, false, c) {
        let c = choose|c: int| is_controller(c) && pause(pre, post, false, c);
        pause_preserves(pre, post, c);
    } else if exists|c: int| is_controller(c) && prepare(pre, post, c) {
        let c = choose|c: int| is_controller(c) && prepare(pre, post, c);
        prepare_preserves(pre, post, c);
    } else if exists|c: int| is_controller(c) && select(pre, post, false, false, false, c) {
        let c = choose|c: int| is_controller(c) && select(pre, post, false, false, false, c);
        select_preserves(pre, post, c);
    } else if exists|c: int| is_controller(c) && crash(pre, post, c) {
        let c = choose|c: int| is_controller(c) && crash(pre, post, c);
        crash_preserves(pre, post, c);
    } else {
        let c = choose|c: int| is_controller(c) && reopen(pre, post, c);
        reopen_preserves(pre, post, c);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_missing_controller_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_missing_controller(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_changed_head_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_changed_head(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_automatic_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_automatic(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_missing_intent_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_missing_intent(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_reset_spend_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_reset_spend(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_lost_archive_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_lost_archive(
        t[i],
        t[i + 1],
    )
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

/// Constructing states concisely for the witness proofs. Field order
/// follows the TLA+ vars tuple.
pub open spec fn st(
    created: Set<(int, int)>,
    pending: Set<(int, int)>,
    stored: Set<(int, int)>,
    applied: Map<int, Set<(int, int)>>,
    observed: Map<int, Set<(int, int)>>,
    paused: Set<int>,
    fenced: bool,
    terminal: Set<(int, int)>,
    intent1: Set<int>,
    selected1: Set<int>,
    archive: Map<int, Set<(int, int)>>,
    spent: Map<int, int>,
    online: Set<int>
) -> State {
    State {
        created,
        pending,
        stored,
        applied,
        observed,
        paused,
        fenced,
        terminal,
        intent1,
        selected1,
        archive,
        spent,
        online,
    }
}

/// The init state, spelled out once for the witnesses.
pub open spec fn s_init() -> State {
    st(
        Set::empty(),
        Set::empty(),
        Set::empty(),
        zmap_s(),
        zmap_s(),
        Set::empty(),
        false,
        Set::empty(),
        Set::empty(),
        Set::empty(),
        zmap_s(),
        zmap_i(),
        controllers(),
    )
}

/// mutant-missing-controller: with SkipController the Required set is the
/// singleton {a}; pausing a alone lets Fence fire with b never paused —
/// paused ≠ Controllers at a fenced state.
proof fn mutant_missing_controller_violates()
    ensures
        exists|t: Seq<State>| is_missing_controller_trace(t) && !complete_inventory(
            t.last(),
        ),
{
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let s0 = s_init();
    let s1 = st(
        ej,
        ej,
        ej,
        zmap_s(),
        zmap_s(),
        ei.insert(1),
        false,
        ej,
        ei,
        ei,
        zmap_s(),
        zmap_i(),
        controllers(),
    );
    let s2 = st(
        ej,
        ej,
        ej,
        zmap_s(),
        zmap_s(),
        ei.insert(1),
        true,
        ej,
        ei,
        ei,
        zmap_s(),
        zmap_i(),
        controllers(),
    );
    assert(init(s0));
    assert(next_mutant_missing_controller(s0, s1)) by {
        assert(is_controller(1));
        assert(pause(s0, s1, false, 1));
    }
    assert(next_mutant_missing_controller(s1, s2)) by {
        assert(required(true).subset_of(s1.paused)) by {
            assert(required(true) =~= ei.insert(1));
        }
        assert forall|c: int| required(true).contains(c) implies map_at_s(s1.observed, c)
            =~= s1.stored by {
            assert(c == 1);
        }
        assert(fence(s1, s2, true, false));
    }
    assert(!complete_inventory(s2)) by {
        assert(s2.fenced);
        assert(!(s2.paused =~= controllers())) by {
            assert(controllers().contains(2));
            assert(!s2.paused.contains(2));
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_missing_controller_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1
            implies #[trigger] next_mutant_missing_controller(t[i], t[i + 1]) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_missing_controller_trace(t) && !complete_inventory(t.last()));
}

/// mutant-changed-head: both controllers pause on an empty stored head,
/// then the admitted old writer lands and IgnoreHead lets Fence commit
/// terminal = {Foreign} — observed[c] ≠ terminal for both.
proof fn mutant_changed_head_violates()
    ensures
        exists|t: Seq<State>| is_changed_head_trace(t) && !conditional_head(t.last()),
{
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let f1 = ej.insert(foreign());
    let p1 = ei.insert(1);
    let p12 = ei.insert(1).insert(2);
    let s0 = s_init();
    let s1 = st(ej, ej, ej, zmap_s(), zmap_s(), p1, false, ej, ei, ei, zmap_s(), zmap_i(), controllers());
    let s2 = st(ej, ej, ej, zmap_s(), zmap_s(), p12, false, ej, ei, ei, zmap_s(), zmap_i(), controllers());
    let s3 = st(ej, ej, f1, zmap_s(), zmap_s(), p12, false, ej, ei, ei, zmap_s(), zmap_i(), controllers());
    let s4 = st(ej, ej, f1, zmap_s(), zmap_s(), p12, true, f1, ei, ei, zmap_s(), zmap_i(), controllers());
    assert(init(s0));
    assert(next_mutant_changed_head(s0, s1)) by {
        assert(is_controller(1));
        assert(pause(s0, s1, false, 1));
    }
    assert(next_mutant_changed_head(s1, s2)) by {
        assert(is_controller(2));
        assert(pause(s1, s2, false, 2));
    }
    assert(next_mutant_changed_head(s2, s3)) by {
        assert(!(s2.paused =~= ei)) by {
            assert(s2.paused.contains(1));
        }
        assert(race_write(s2, s3));
    }
    assert(next_mutant_changed_head(s3, s4)) by {
        assert(required(false).subset_of(s3.paused)) by {
            assert(required(false) =~= controllers());
        }
        assert(fence(s3, s4, false, true));
    }
    assert(!conditional_head(s4)) by {
        assert(s4.fenced);
        assert(is_controller(1));
        assert(!(map_at_s(s4.observed, 1) =~= s4.terminal)) by {
            assert(s4.observed.dom().contains(1));
            assert(!(s4.terminal =~= ej)) by {
                assert(s4.terminal.contains(foreign()));
            }
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_changed_head_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_changed_head(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_changed_head_trace(t) && !conditional_head(t.last()));
}

/// mutant-automatic-output: a's application is stored and both
/// controllers observe and pause, but b's Pause skips the Incoming ⊆
/// applied check, so at the fence b still owes applied output —
/// Incoming(b) ⊄ applied[b].
proof fn mutant_automatic_violates()
    ensures
        exists|t: Seq<State>| is_automatic_trace(t) && !automatic_output_drained(
            t.last(),
        ),
{
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let a1 = app(1);
    let st1 = ej.insert(a1);
    let p1 = ei.insert(1);
    let p12 = ei.insert(1).insert(2);
    let ob1 = zmap_s().insert(1, st1);
    let ob12 = ob1.insert(2, st1);
    let spent1 = zmap_i().insert(1, 1);
    let s0 = s_init();
    // Queue(a)
    let s1 = st(st1, st1, ej, zmap_s(), zmap_s(), ei, false, ej, ei, ei, zmap_s(), spent1, controllers());
    // Store(App a)
    let s2 = st(st1, st1, st1, zmap_s(), zmap_s(), ei, false, ej, ei, ei, zmap_s(), spent1, controllers());
    // Receipt(App a)
    let s3 = st(st1, ej, st1, zmap_s(), zmap_s(), ei, false, ej, ei, ei, zmap_s(), spent1, controllers());
    // Observe(a)
    let s4 = st(st1, ej, st1, zmap_s(), ob1, ei, false, ej, ei, ei, zmap_s(), spent1, controllers());
    // Pause(a)
    let s5 = st(st1, ej, st1, zmap_s(), ob1, p1, false, ej, ei, ei, zmap_s(), spent1, controllers());
    // Observe(b)
    let s6 = st(st1, ej, st1, zmap_s(), ob12, p1, false, ej, ei, ei, zmap_s(), spent1, controllers());
    // Pause(b)
    let s7 = st(st1, ej, st1, zmap_s(), ob12, p12, false, ej, ei, ei, zmap_s(), spent1, controllers());
    // Fence
    let s8 = st(st1, ej, st1, zmap_s(), ob12, p12, true, st1, ei, ei, zmap_s(), spent1, controllers());
    assert(init(s0));
    assert(next_mutant_automatic(s0, s1)) by {
        assert(is_controller(1));
        assert(queue(s0, s1, 1));
    }
    assert(next_mutant_automatic(s1, s2)) by {
        assert(is_job(a1));
        assert(store(s1, s2, a1));
    }
    assert(next_mutant_automatic(s2, s3)) by {
        assert(is_job(a1));
        assert(receipt(s2, s3, a1));
    }
    assert(next_mutant_automatic(s3, s4)) by {
        assert(is_controller(1));
        assert(observe(s3, s4, true, 1)) by {
            assert(incoming(s3, 1).subset_of(map_at_s(s3.applied, 1)) || true);
        }
    }
    assert(next_mutant_automatic(s4, s5)) by {
        assert(is_controller(1));
        assert(pause(s4, s5, true, 1)) by {
            assert(owned(1, s4.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(1, s4.pending).contains(j) by {
                    owned_mem(1, s4.pending, j);
                }
            }
            assert(map_at_s(s4.observed, 1) =~= s4.stored) by {
                map_insert_at_s(zmap_s(), 1, st1, 1);
            }
        }
    }
    assert(next_mutant_automatic(s5, s6)) by {
        assert(is_controller(2));
        assert(observe(s5, s6, true, 2));
    }
    assert(next_mutant_automatic(s6, s7)) by {
        assert(is_controller(2));
        assert(pause(s6, s7, true, 2)) by {
            assert(owned(2, s6.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(2, s6.pending).contains(j) by {
                    owned_mem(2, s6.pending, j);
                }
            }
            assert(map_at_s(s6.observed, 2) =~= s6.stored) by {
                map_insert_at_s(zmap_s(), 1, st1, 2);
                map_insert_at_s(ob1, 2, st1, 2);
            }
        }
    }
    assert(next_mutant_automatic(s7, s8)) by {
        assert(required(false).subset_of(s7.paused)) by {
            assert(required(false) =~= controllers());
        }
        assert forall|c: int| required(false).contains(c) implies map_at_s(s7.observed, c)
            =~= s7.stored by {
            map_insert_at_s(zmap_s(), 1, st1, c);
            map_insert_at_s(ob1, 2, st1, c);
        }
        assert(fence(s7, s8, false, false));
    }
    assert(!automatic_output_drained(s8)) by {
        assert(s8.fenced);
        assert(is_controller(2));
        assert(incoming(s8, 2).contains(a1)) by {
            assert(applications().contains(a1));
            assert(a1 != app(2));
        }
        assert(!map_at_s(s8.applied, 2).contains(a1)) by {
            assert(s8.applied.dom().contains(2));
        }
        assert(!incoming(s8, 2).subset_of(map_at_s(s8.applied, 2)));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8);
    assert(is_automatic_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_automatic(
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
            );
        }
    }
    assert(t.last() == s8);
    assert(is_automatic_trace(t) && !automatic_output_drained(t.last()));
}

/// mutant-missing-intent: both controllers pause, the fence commits, then
/// Select(a) with SkipIntent selects generation 1 without a durable
/// intent.
proof fn mutant_missing_intent_violates()
    ensures
        exists|t: Seq<State>| is_missing_intent_trace(t) && !intent_before_selection(
            t.last(),
        ),
{
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let p1 = ei.insert(1);
    let p12 = ei.insert(1).insert(2);
    let sel1 = ei.insert(1);
    let s0 = s_init();
    let s1 = st(ej, ej, ej, zmap_s(), zmap_s(), p1, false, ej, ei, ei, zmap_s(), zmap_i(), controllers());
    let s2 = st(ej, ej, ej, zmap_s(), zmap_s(), p12, false, ej, ei, ei, zmap_s(), zmap_i(), controllers());
    let s3 = st(ej, ej, ej, zmap_s(), zmap_s(), p12, true, ej, ei, ei, zmap_s(), zmap_i(), controllers());
    let s4 = st(
        ej,
        ej,
        ej,
        zmap_s(),
        zmap_s(),
        p12,
        true,
        ej,
        ei,
        sel1,
        zmap_s().insert(1, ej),
        zmap_i().insert(1, 0),
        controllers(),
    );
    assert(init(s0));
    assert(next_mutant_missing_intent(s0, s1)) by {
        assert(is_controller(1));
        assert(pause(s0, s1, false, 1));
    }
    assert(next_mutant_missing_intent(s1, s2)) by {
        assert(is_controller(2));
        assert(pause(s1, s2, false, 2));
    }
    assert(next_mutant_missing_intent(s2, s3)) by {
        assert(required(false).subset_of(s2.paused)) by {
            assert(required(false) =~= controllers());
        }
        assert forall|c: int| required(false).contains(c) implies map_at_s(s2.observed, c)
            =~= s2.stored by {
            assert(s2.observed.dom().contains(c));
        }
        assert(fence(s2, s3, false, false));
    }
    assert(next_mutant_missing_intent(s3, s4)) by {
        assert(is_controller(1));
        assert(select(s3, s4, true, false, false, 1)) by {
            assert(s3.online.contains(1));
            assert(s3.fenced);
            assert(!s3.selected1.contains(1));
            assert(s3.intent1.contains(1) || true);
        }
    }
    assert(!intent_before_selection(s4)) by {
        assert(is_controller(1));
        assert(s4.selected1.contains(1));
        assert(!s4.intent1.contains(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_missing_intent_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1
            implies #[trigger] next_mutant_missing_intent(t[i], t[i + 1]) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_missing_intent_trace(t) && !intent_before_selection(t.last()));
}

/// The concrete action predicates used by the drained prefix below, in
/// step order. Each is a flag-free action, or a flag-affected action whose
/// flag arguments match the safe configuration — and `observe`/`pause`
/// only weaken under `sa = true`, so every disjunct also fires under the
/// `mutant-reset-spend` and `mutant-lost-archive` instantiations, whose
/// switches touch only `select`.
pub open spec fn prefix_step(s1: State, s2: State) -> bool {
    ||| queue(s1, s2, 1)
    ||| store(s1, s2, app(1))
    ||| receipt(s1, s2, app(1))
    ||| apply(s1, s2, 2)
    ||| store(s1, s2, ack(2))
    ||| receipt(s1, s2, ack(2))
    ||| observe(s1, s2, false, 1)
    ||| pause(s1, s2, false, 1)
    ||| observe(s1, s2, false, 2)
    ||| pause(s1, s2, false, 2)
    ||| fence(s1, s2, false, false)
}

/// The common drained-mailbox prefix for the spend/archive mutants: a's
/// application is queued, stored and received; b applies it, generating
/// its acceptance; both controllers observe and pause; the fence commits.
/// Returns the fenced state.
pub open spec fn drained_states() -> Seq<State> {
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let a1 = app(1);
    let k2 = ack(2);
    let st1 = ej.insert(a1);
    let st2 = st1.insert(k2);
    let p1 = ei.insert(1);
    let p12 = ei.insert(1).insert(2);
    let app_b = zmap_s().insert(2, st1);
    let ob1 = zmap_s().insert(1, st2);
    let ob12 = ob1.insert(2, st2);
    let spent11 = zmap_i().insert(1, 1).insert(2, 1);
    let s0 = s_init();
    let s1 = st(st1, st1, ej, zmap_s(), zmap_s(), ei, false, ej, ei, ei, zmap_s(), zmap_i().insert(1, 1), controllers());
    let s2 = st(st1, st1, st1, zmap_s(), zmap_s(), ei, false, ej, ei, ei, zmap_s(), zmap_i().insert(1, 1), controllers());
    let s3 = st(st1, ej, st1, zmap_s(), zmap_s(), ei, false, ej, ei, ei, zmap_s(), zmap_i().insert(1, 1), controllers());
    let s4 = st(st2, ej.insert(k2), st1, app_b, zmap_s(), ei, false, ej, ei, ei, zmap_s(), spent11, controllers());
    let s5 = st(st2, ej.insert(k2), st2, app_b, zmap_s(), ei, false, ej, ei, ei, zmap_s(), spent11, controllers());
    let s6 = st(st2, ej, st2, app_b, zmap_s(), ei, false, ej, ei, ei, zmap_s(), spent11, controllers());
    let s7 = st(st2, ej, st2, app_b, ob1, ei, false, ej, ei, ei, zmap_s(), spent11, controllers());
    let s8 = st(st2, ej, st2, app_b, ob1, p1, false, ej, ei, ei, zmap_s(), spent11, controllers());
    let s9 = st(st2, ej, st2, app_b, ob12, p1, false, ej, ei, ei, zmap_s(), spent11, controllers());
    let s10 = st(st2, ej, st2, app_b, ob12, p12, false, ej, ei, ei, zmap_s(), spent11, controllers());
    let s11 = st(st2, ej, st2, app_b, ob12, p12, true, st2, ei, ei, zmap_s(), spent11, controllers());
    Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7).push(
        s8,
    ).push(s9).push(s10).push(s11)
}

/// Steps 0..11 of the drained prefix satisfy the concrete `prefix_step`
/// disjunction.
proof fn drained_prefix_steps(i: int)
    requires
        0 <= i < drained_states().len() - 1,
    ensures
        prefix_step(drained_states()[i], drained_states()[i + 1]),
{
    let ej = Set::<(int, int)>::empty();
    let a1 = app(1);
    let k2 = ack(2);
    let st1 = ej.insert(a1);
    let st2 = st1.insert(k2);
    let t = drained_states();
    let s0 = t[0];
    let s1 = t[1];
    let s2 = t[2];
    let s3 = t[3];
    let s4 = t[4];
    let s5 = t[5];
    let s6 = t[6];
    let s7 = t[7];
    let s8 = t[8];
    let s9 = t[9];
    let s10 = t[10];
    let s11 = t[11];
    assert(init(s0));
    assert(queue(s0, s1, 1));
    assert(store(s1, s2, a1));
    assert(receipt(s2, s3, a1));
    assert(apply(s3, s4, 2)) by {
        assert(s3.online.contains(2));
        assert(incoming(s3, 2) =~= st1) by {
            assert forall|j: (int, int)| incoming(s3, 2).contains(j)
                implies st1.contains(j) by {
                assert(applications().contains(j));
                assert(j == a1 || j == app(2));
                assert(j != app(2));
            }
            assert forall|j: (int, int)| st1.contains(j) implies incoming(s3, 2).contains(j) by {
                assert(j == a1);
                assert(applications().contains(j));
                assert(j != app(2));
            }
        }
        assert(!(incoming(s3, 2).difference(map_at_s(s3.applied, 2)) =~= Set::empty()))
            by {
            assert(!map_at_s(s3.applied, 2).contains(a1)) by {
                assert(s3.applied.dom().contains(2));
            }
        }
        assert(s4.applied =~= s3.applied.insert(2, incoming(s3, 2))) by {
            assert(s4.applied =~= s3.applied.insert(2, st1));
        }
        assert(s4.spent =~= s3.spent.insert(2, map_at(s3.spent, 2) + 1)) by {
            assert(map_at(s3.spent, 2) == 0) by {
                assert(s3.spent.dom().contains(2));
            }
            assert(s4.spent =~= s3.spent.insert(2, 1));
        }
    }
    assert(store(s4, s5, k2));
    assert(receipt(s5, s6, k2));
    assert(observe(s6, s7, false, 1)) by {
        // Incoming(a) = {} ⊆ applied[a]
        assert(incoming(s6, 1).subset_of(map_at_s(s6.applied, 1))) by {
            assert forall|j: (int, int)| !incoming(s6, 1).contains(j) by {
                assert(applications().contains(j) == (j == a1 || j == app(2)));
                assert(!s6.stored.contains(app(2)));
            }
        }
    }
    assert(pause(s7, s8, false, 1)) by {
        assert(owned(1, s7.pending) =~= Set::empty()) by {
            assert forall|j: (int, int)| !owned(1, s7.pending).contains(j) by {
                owned_mem(1, s7.pending, j);
            }
        }
        assert(map_at_s(s7.observed, 1) =~= s7.stored) by {
            map_insert_at_s(zmap_s(), 1, st2, 1);
        }
        assert(incoming(s7, 1).subset_of(map_at_s(s7.applied, 1))) by {
            assert forall|j: (int, int)| !incoming(s7, 1).contains(j) by {
                assert(applications().contains(j) == (j == a1 || j == app(2)));
                assert(!s7.stored.contains(app(2)));
            }
        }
    }
    assert(observe(s8, s9, false, 2)) by {
        assert(incoming(s8, 2).subset_of(map_at_s(s8.applied, 2))) by {
            assert forall|j: (int, int)| incoming(s8, 2).contains(j)
                implies map_at_s(s8.applied, 2).contains(j) by {
                assert(j == a1) by {
                    assert(applications().contains(j));
                    assert(j == a1 || j == app(2));
                    assert(j != app(2));
                }
                map_insert_at_s(zmap_s(), 2, st1, 2);
            }
        }
    }
    assert(pause(s9, s10, false, 2)) by {
        assert(owned(2, s9.pending) =~= Set::empty()) by {
            assert forall|j: (int, int)| !owned(2, s9.pending).contains(j) by {
                owned_mem(2, s9.pending, j);
            }
        }
        assert(map_at_s(s9.observed, 2) =~= s9.stored) by {
            map_insert_at_s(zmap_s(), 1, st2, 2);
            map_insert_at_s(zmap_s().insert(1, st2), 2, st2, 2);
        }
        assert(incoming(s9, 2).subset_of(map_at_s(s9.applied, 2))) by {
            assert forall|j: (int, int)| incoming(s9, 2).contains(j)
                implies map_at_s(s9.applied, 2).contains(j) by {
                assert(j == a1) by {
                    assert(applications().contains(j));
                    assert(j == a1 || j == app(2));
                    assert(j != app(2));
                }
                map_insert_at_s(zmap_s(), 2, st1, 2);
            }
        }
    }
    assert(fence(s10, s11, false, false)) by {
        assert(required(false).subset_of(s10.paused)) by {
            assert(required(false) =~= controllers());
        }
        assert forall|c: int| required(false).contains(c) implies map_at_s(s10.observed, c)
            =~= s10.stored by {
            map_insert_at_s(zmap_s(), 1, st2, c);
            map_insert_at_s(zmap_s().insert(1, st2), 2, st2, c);
        }
    }
    if i == 0 {
        assert(t[0] == s0 && t[1] == s1);
    } else if i == 1 {
        assert(t[1] == s1 && t[2] == s2);
    } else if i == 2 {
        assert(t[2] == s2 && t[3] == s3);
    } else if i == 3 {
        assert(t[3] == s3 && t[4] == s4);
    } else if i == 4 {
        assert(t[4] == s4 && t[5] == s5);
    } else if i == 5 {
        assert(t[5] == s5 && t[6] == s6);
    } else if i == 6 {
        assert(t[6] == s6 && t[7] == s7);
    } else if i == 7 {
        assert(t[7] == s7 && t[8] == s8);
    } else if i == 8 {
        assert(t[8] == s8 && t[9] == s9);
    } else if i == 9 {
        assert(t[9] == s9 && t[10] == s10);
    } else {
        assert(i == 10);
        assert(t[10] == s10 && t[11] == s11);
    }
}

/// A `prefix_step` is a step of the safe model and of the
/// `mutant-reset-spend` / `mutant-lost-archive` configurations: those
/// switches touch only `select`, which the prefix never uses, and every
/// other disjunct is a `next_cfg` disjunct at matching flag values.
proof fn prefix_step_nexts(s1: State, s2: State)
    requires
        prefix_step(s1, s2),
    ensures
        next(s1, s2) && next_mutant_reset_spend(s1, s2) && next_mutant_lost_archive(
            s1,
            s2,
        ),
{
    assert(is_controller(1));
    assert(is_controller(2));
    assert(is_job(app(1)));
    assert(is_job(ack(2)));
}

/// mutant-reset-spend: after the drained prefix, Prepare(a) then
/// Select(a) with ResetSpent zeroes a's spend while Owned(a, created)
/// still holds the created application.
proof fn mutant_reset_spend_violates()
    ensures
        exists|t: Seq<State>| is_reset_spend_trace(t) && !preserved_spend(t.last()),
{
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let a1 = app(1);
    let k2 = ack(2);
    let st1 = ej.insert(a1);
    let st2 = st1.insert(k2);
    let p12 = ei.insert(1).insert(2);
    let app_b = zmap_s().insert(2, st1);
    let ob1 = zmap_s().insert(1, st2);
    let ob12 = ob1.insert(2, st2);
    let spent11 = zmap_i().insert(1, 1).insert(2, 1);
    let prefix = drained_states();
    let s11 = prefix[11];
    // Prepare(a)
    let s12 = st(
        st2,
        ej,
        st2,
        app_b,
        ob12,
        p12,
        true,
        st2,
        ei.insert(1),
        ei,
        zmap_s(),
        spent11,
        controllers(),
    );
    // Select(a) with ResetSpent
    let s13 = st(
        st2,
        ej,
        st2,
        app_b,
        ob12,
        p12,
        true,
        st2,
        ei.insert(1),
        ei.insert(1),
        zmap_s().insert(1, st2),
        spent11.insert(1, 0),
        controllers(),
    );
    assert(next_mutant_reset_spend(s11, s12)) by {
        assert(is_controller(1));
        assert(prepare(s11, s12, 1)) by {
            assert(s11.online.contains(1));
            assert(s11.fenced);
            assert(s11.paused.contains(1));
            assert(map_at_s(s11.observed, 1) =~= s11.terminal) by {
                map_insert_at_s(zmap_s(), 1, st2, 1);
                map_insert_at_s(ob1, 2, st2, 1);
            }
            assert(owned(1, s11.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(1, s11.pending).contains(j) by {
                    owned_mem(1, s11.pending, j);
                }
            }
            assert(incoming(s11, 1).subset_of(map_at_s(s11.applied, 1))) by {
                assert forall|j: (int, int)| !incoming(s11, 1).contains(j) by {
                    assert(applications().contains(j) == (j == a1 || j == app(2)));
                    assert(!s11.stored.contains(app(2)));
                }
            }
        }
    }
    assert(next_mutant_reset_spend(s12, s13)) by {
        assert(is_controller(1));
        assert(select(s12, s13, false, true, false, 1)) by {
            assert(s12.online.contains(1));
            assert(s12.fenced);
            assert(!s12.selected1.contains(1));
            assert(s12.intent1.contains(1));
            assert(s13.spent =~= s12.spent.insert(1, 0));
        }
    }
    assert(!preserved_spend(s13)) by {
        assert(is_controller(1));
        assert(map_at(s13.spent, 1) == 0) by {
            map_insert_at(spent11, 1, 0, 1);
        }
        assert(owned(1, s13.created).len() == 1) by {
            assert(owned(1, s13.created) =~= Set::empty().insert(a1)) by {
                assert forall|j: (int, int)| owned(1, s13.created).contains(j)
                    implies Set::empty().insert(a1).contains(j) by {
                    owned_mem(1, s13.created, j);
                    assert(s13.created.contains(j));
                    assert(j == a1 || j == k2);
                    assert(j.1 == 1);
                    assert(j == a1);
                }
                assert forall|j: (int, int)| Set::empty().insert(a1).contains(j)
                    implies owned(1, s13.created).contains(j) by {
                    owned_mem(1, s13.created, j);
                    assert(s13.created.contains(j));
                }
            }
        }
    }
    let t = prefix.push(s12).push(s13);
    assert(is_reset_spend_trace(t)) by {
        assert(init(t[0]));
        assert forall|i: int| 0 <= i < t.len() - 1
            implies #[trigger] next_mutant_reset_spend(t[i], t[i + 1]) by {
            if i < prefix.len() - 1 {
                assert(t[i] == prefix[i]);
                assert(t[i + 1] == prefix[i + 1]);
                drained_prefix_steps(i);
                prefix_step_nexts(t[i], t[i + 1]);
            } else {
                assert(i == prefix.len() - 1 || i == prefix.len());
                if i == prefix.len() - 1 {
                    assert(t[i] == s11);
                    assert(t[i + 1] == s12);
                } else {
                    assert(t[i] == s12);
                    assert(t[i + 1] == s13);
                }
            }
        }
    }
    assert(t.last() == s13);
    assert(is_reset_spend_trace(t) && !preserved_spend(t.last()));
}

/// mutant-lost-archive: the same drained prefix and Prepare, then
/// Select(a) with DropArchive records an empty archive instead of the
/// predecessor head.
proof fn mutant_lost_archive_violates()
    ensures
        exists|t: Seq<State>| is_lost_archive_trace(t) && !preserved_archive(t.last()),
{
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let a1 = app(1);
    let k2 = ack(2);
    let st1 = ej.insert(a1);
    let st2 = st1.insert(k2);
    let p12 = ei.insert(1).insert(2);
    let app_b = zmap_s().insert(2, st1);
    let ob1 = zmap_s().insert(1, st2);
    let ob12 = ob1.insert(2, st2);
    let spent11 = zmap_i().insert(1, 1).insert(2, 1);
    let prefix = drained_states();
    let s11 = prefix[11];
    let s12 = st(
        st2,
        ej,
        st2,
        app_b,
        ob12,
        p12,
        true,
        st2,
        ei.insert(1),
        ei,
        zmap_s(),
        spent11,
        controllers(),
    );
    // Select(a) with DropArchive
    let s13 = st(
        st2,
        ej,
        st2,
        app_b,
        ob12,
        p12,
        true,
        st2,
        ei.insert(1),
        ei.insert(1),
        zmap_s().insert(1, ej),
        spent11.insert(1, 1),
        controllers(),
    );
    assert(next_mutant_lost_archive(s11, s12)) by {
        assert(is_controller(1));
        assert(prepare(s11, s12, 1)) by {
            assert(s11.online.contains(1));
            assert(s11.fenced);
            assert(s11.paused.contains(1));
            assert(map_at_s(s11.observed, 1) =~= s11.terminal) by {
                map_insert_at_s(zmap_s(), 1, st2, 1);
                map_insert_at_s(ob1, 2, st2, 1);
            }
            assert(owned(1, s11.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(1, s11.pending).contains(j) by {
                    owned_mem(1, s11.pending, j);
                }
            }
            assert(incoming(s11, 1).subset_of(map_at_s(s11.applied, 1))) by {
                assert forall|j: (int, int)| !incoming(s11, 1).contains(j) by {
                    assert(applications().contains(j) == (j == a1 || j == app(2)));
                    assert(!s11.stored.contains(app(2)));
                }
            }
        }
    }
    assert(next_mutant_lost_archive(s12, s13)) by {
        assert(is_controller(1));
        assert(select(s12, s13, false, false, true, 1)) by {
            assert(s12.online.contains(1));
            assert(s12.fenced);
            assert(!s12.selected1.contains(1));
            assert(s12.intent1.contains(1));
            assert(s13.archive =~= s12.archive.insert(1, ej));
            assert(s13.spent =~= s12.spent.insert(1, map_at(s12.spent, 1))) by {
                assert(map_at(s12.spent, 1) == 1) by {
                    assert(s12.spent.dom().contains(1));
                }
                assert(spent11.insert(1, 1) =~= s12.spent.insert(1, 1));
            }
        }
    }
    assert(!preserved_archive(s13)) by {
        assert(is_controller(1));
        assert(s13.selected1.contains(1));
        assert(!(map_at_s(s13.archive, 1) =~= s13.terminal)) by {
            map_insert_at_s(zmap_s(), 1, ej, 1);
            assert(map_at_s(s13.archive, 1) =~= ej);
            assert(s13.terminal.contains(a1));
        }
    }
    let t = prefix.push(s12).push(s13);
    assert(is_lost_archive_trace(t)) by {
        assert(init(t[0]));
        assert forall|i: int| 0 <= i < t.len() - 1
            implies #[trigger] next_mutant_lost_archive(t[i], t[i + 1]) by {
            if i < prefix.len() - 1 {
                assert(t[i] == prefix[i]);
                assert(t[i + 1] == prefix[i + 1]);
                drained_prefix_steps(i);
                prefix_step_nexts(t[i], t[i + 1]);
            } else {
                assert(i == prefix.len() - 1 || i == prefix.len());
                if i == prefix.len() - 1 {
                    assert(t[i] == s11);
                    assert(t[i + 1] == s12);
                } else {
                    assert(t[i] == s12);
                    assert(t[i + 1] == s13);
                }
            }
        }
    }
    assert(t.last() == s13);
    assert(is_lost_archive_trace(t) && !preserved_archive(t.last()));
}

/// Completion witness for the safe model: both controllers queue, store
/// and receive their applications, each applies the other's incoming
/// work, both observe, pause (with a crash/reopen of a exercised),
/// fence, prepare and select generation 1 — ending fully selected with
/// the predecessor head archived and cumulative spend preserved.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().fenced && t.last().selected1
            =~= controllers() && t.last().intent1 =~= controllers() && forall|c: int|
            is_controller(c) ==> map_at_s(t.last().archive, c) =~= t.last().terminal
            && map_at(t.last().spent, c) == 2,
{
    let ej = Set::<(int, int)>::empty();
    let ei = Set::<int>::empty();
    let a1 = app(1);
    let a2 = app(2);
    let k1 = ack(1);
    let k2 = ack(2);
    // stored snapshots
    let sa12 = ej.insert(a1).insert(a2);
    let s1234 = sa12.insert(k1).insert(k2);
    let p1 = ei.insert(1);
    let p12 = ei.insert(1).insert(2);
    let i1 = ei.insert(1);
    let i12 = ei.insert(1).insert(2);
    let sel12 = ei.insert(1).insert(2);
    let on2 = ei.insert(2);
    // per-controller maps
    let zm = zmap_s();
    let zi = zmap_i();
    let ap1 = zm.insert(1, ej.insert(a2));
    let ap12 = ap1.insert(2, ej.insert(a1));
    let ob1 = zm.insert(1, s1234);
    let ob12 = ob1.insert(2, s1234);
    let ar1 = zm.insert(1, s1234);
    let ar12 = ar1.insert(2, s1234);
    let sp10 = zi.insert(1, 1);
    let sp11 = zi.insert(1, 1).insert(2, 1);
    let sp21 = zi.insert(1, 2).insert(2, 1);
    let sp22 = zi.insert(1, 2).insert(2, 2);
    let s0 = s_init();
    // Queue(a)
    let s1 = st(
        ej.insert(a1),
        ej.insert(a1),
        ej,
        zm,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp10,
        controllers(),
    );
    // Queue(b)
    let s2 = st(
        sa12,
        sa12,
        ej,
        zm,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp11,
        controllers(),
    );
    // Store(App a)
    let s3 = st(
        sa12,
        sa12,
        ej.insert(a1),
        zm,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp11,
        controllers(),
    );
    // Store(App b)
    let s4 = st(sa12, sa12, sa12, zm, zm, ei, false, ej, ei, ei, zm, sp11, controllers());
    // Receipt(App a)
    let s5 = st(
        sa12,
        ej.insert(a2),
        sa12,
        zm,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp11,
        controllers(),
    );
    // Receipt(App b)
    let s6 = st(sa12, ej, sa12, zm, zm, ei, false, ej, ei, ei, zm, sp11, controllers());
    // Apply(a): incoming = {App b}
    let s7 = st(
        sa12.insert(k1),
        ej.insert(k1),
        sa12,
        ap1,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp21,
        controllers(),
    );
    // Apply(b): incoming = {App a}
    let s8 = st(
        s1234,
        ej.insert(k1).insert(k2),
        sa12,
        ap12,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp22,
        controllers(),
    );
    // Store(Ack a)
    let s9 = st(
        s1234,
        ej.insert(k1).insert(k2),
        sa12.insert(k1),
        ap12,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp22,
        controllers(),
    );
    // Store(Ack b)
    let s10 = st(
        s1234,
        ej.insert(k1).insert(k2),
        s1234,
        ap12,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp22,
        controllers(),
    );
    // Receipt(Ack a)
    let s11 = st(
        s1234,
        ej.insert(k2),
        s1234,
        ap12,
        zm,
        ei,
        false,
        ej,
        ei,
        ei,
        zm,
        sp22,
        controllers(),
    );
    // Receipt(Ack b)
    let s12 = st(s1234, ej, s1234, ap12, zm, ei, false, ej, ei, ei, zm, sp22, controllers());
    // Observe(a)
    let s13 = st(s1234, ej, s1234, ap12, ob1, ei, false, ej, ei, ei, zm, sp22, controllers());
    // Pause(a)
    let s14 = st(s1234, ej, s1234, ap12, ob1, p1, false, ej, ei, ei, zm, sp22, controllers());
    // Observe(b)
    let s15 = st(s1234, ej, s1234, ap12, ob12, p1, false, ej, ei, ei, zm, sp22, controllers());
    // Pause(b)
    let s16 = st(s1234, ej, s1234, ap12, ob12, p12, false, ej, ei, ei, zm, sp22, controllers());
    // Crash(a) then Reopen(a): the durable record is unaffected.
    let s17 = st(s1234, ej, s1234, ap12, ob12, p12, false, ej, ei, ei, zm, sp22, on2);
    let s18 = st(
        s1234,
        ej,
        s1234,
        ap12,
        ob12,
        p12,
        false,
        ej,
        ei,
        ei,
        zm,
        sp22,
        controllers(),
    );
    // Fence
    let s19 = st(
        s1234,
        ej,
        s1234,
        ap12,
        ob12,
        p12,
        true,
        s1234,
        ei,
        ei,
        zm,
        sp22,
        controllers(),
    );
    // Prepare(a), Prepare(b)
    let s20 = st(
        s1234,
        ej,
        s1234,
        ap12,
        ob12,
        p12,
        true,
        s1234,
        i1,
        ei,
        zm,
        sp22,
        controllers(),
    );
    let s21 = st(
        s1234,
        ej,
        s1234,
        ap12,
        ob12,
        p12,
        true,
        s1234,
        i12,
        ei,
        zm,
        sp22,
        controllers(),
    );
    // Select(a), Select(b)
    let s22 = st(
        s1234,
        ej,
        s1234,
        ap12,
        ob12,
        p12,
        true,
        s1234,
        i12,
        ei.insert(1),
        ar1,
        sp22,
        controllers(),
    );
    let s23 = st(
        s1234,
        ej,
        s1234,
        ap12,
        ob12,
        p12,
        true,
        s1234,
        i12,
        sel12,
        ar12,
        sp22,
        controllers(),
    );
    assert(init(s0));
    assert(next(s0, s1)) by {
        assert(is_controller(1));
        assert(queue(s0, s1, 1));
    }
    assert(next(s1, s2)) by {
        assert(is_controller(2));
        assert(queue(s1, s2, 2));
    }
    assert(next(s2, s3)) by {
        assert(is_job(a1));
        assert(store(s2, s3, a1));
    }
    assert(next(s3, s4)) by {
        assert(is_job(a2));
        assert(store(s3, s4, a2));
    }
    assert(next(s4, s5)) by {
        assert(is_job(a1));
        assert(receipt(s4, s5, a1));
    }
    assert(next(s5, s6)) by {
        assert(is_job(a2));
        assert(receipt(s5, s6, a2));
    }
    assert(next(s6, s7)) by {
        assert(is_controller(1));
        assert(apply(s6, s7, 1)) by {
            assert(!(incoming(s6, 1).difference(map_at_s(s6.applied, 1)) =~= Set::empty()))
                by {
                assert(incoming(s6, 1).contains(a2)) by {
                    assert(applications().contains(a2));
                    assert(a2 != a1);
                }
                assert(!map_at_s(s6.applied, 1).contains(a2)) by {
                    assert(s6.applied.dom().contains(1));
                }
            }
            assert(s7.applied =~= s6.applied.insert(1, incoming(s6, 1))) by {
                assert(incoming(s6, 1) =~= ej.insert(a2)) by {
                    assert forall|j: (int, int)| incoming(s6, 1).contains(j)
                        implies ej.insert(a2).contains(j) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a1);
                    }
                    assert forall|j: (int, int)| ej.insert(a2).contains(j)
                        implies incoming(s6, 1).contains(j) by {
                        assert(j == a2);
                        assert(applications().contains(j));
                        assert(s6.stored.contains(j));
                        assert(j != a1);
                    }
                }
            }
            assert(s7.spent =~= s6.spent.insert(1, 2)) by {
                assert(map_at(s6.spent, 1) == 1) by {
                    assert(s6.spent.dom().contains(1));
                }
                assert(sp21.insert(2, 1) =~= sp11.insert(1, 2));
            }
            assert(s7.pending =~= s6.pending.insert(k1));
            assert(s7.created =~= s6.created.insert(k1));
        }
    }
    assert(next(s7, s8)) by {
        assert(is_controller(2));
        assert(apply(s7, s8, 2)) by {
            assert(!(incoming(s7, 2).difference(map_at_s(s7.applied, 2)) =~= Set::empty()))
                by {
                assert(incoming(s7, 2).contains(a1)) by {
                    assert(applications().contains(a1));
                    assert(a1 != a2);
                }
                assert(!map_at_s(s7.applied, 2).contains(a1)) by {
                    assert(s7.applied.dom().contains(2));
                }
            }
            assert(s8.applied =~= s7.applied.insert(2, incoming(s7, 2))) by {
                assert(incoming(s7, 2) =~= ej.insert(a1)) by {
                    assert forall|j: (int, int)| incoming(s7, 2).contains(j)
                        implies ej.insert(a1).contains(j) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a2);
                    }
                    assert forall|j: (int, int)| ej.insert(a1).contains(j)
                        implies incoming(s7, 2).contains(j) by {
                        assert(j == a1);
                        assert(applications().contains(j));
                        assert(s7.stored.contains(j));
                        assert(j != a2);
                    }
                }
                assert(ap12 =~= ap1.insert(2, ej.insert(a1)));
            }
            assert(s8.spent =~= s7.spent.insert(2, 2)) by {
                assert(map_at(s7.spent, 2) == 1) by {
                    assert(s7.spent.dom().contains(2));
                }
                assert(sp22 =~= sp21.insert(2, 1).insert(2, 2));
            }
            assert(s8.pending =~= s7.pending.insert(k2));
            assert(s8.created =~= s7.created.insert(k2));
        }
    }
    assert(next(s8, s9)) by {
        assert(is_job(k1));
        assert(store(s8, s9, k1));
    }
    assert(next(s9, s10)) by {
        assert(is_job(k2));
        assert(store(s9, s10, k2));
    }
    assert(next(s10, s11)) by {
        assert(is_job(k1));
        assert(receipt(s10, s11, k1));
    }
    assert(next(s11, s12)) by {
        assert(is_job(k2));
        assert(receipt(s11, s12, k2));
    }
    assert(next(s12, s13)) by {
        assert(is_controller(1));
        assert(observe(s12, s13, false, 1)) by {
            assert(incoming(s12, 1).subset_of(map_at_s(s12.applied, 1))) by {
                assert forall|j: (int, int)| incoming(s12, 1).contains(j)
                    implies map_at_s(s12.applied, 1).contains(j) by {
                    assert(j == a2) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a1);
                    }
                    map_insert_at_s(zm, 1, ej.insert(a2), 1);
                }
            }
            assert(s13.observed =~= s12.observed.insert(1, s12.stored)) by {
                assert(ob1 =~= zm.insert(1, s1234));
            }
        }
    }
    assert(next(s13, s14)) by {
        assert(is_controller(1));
        assert(pause(s13, s14, false, 1)) by {
            assert(owned(1, s13.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(1, s13.pending).contains(j) by {
                    owned_mem(1, s13.pending, j);
                }
            }
            assert(map_at_s(s13.observed, 1) =~= s13.stored) by {
                map_insert_at_s(zm, 1, s1234, 1);
            }
            assert(incoming(s13, 1).subset_of(map_at_s(s13.applied, 1))) by {
                assert forall|j: (int, int)| incoming(s13, 1).contains(j)
                    implies map_at_s(s13.applied, 1).contains(j) by {
                    assert(j == a2) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a1);
                    }
                    map_insert_at_s(zm, 1, ej.insert(a2), 1);
                }
            }
        }
    }
    assert(next(s14, s15)) by {
        assert(is_controller(2));
        assert(observe(s14, s15, false, 2)) by {
            assert(incoming(s14, 2).subset_of(map_at_s(s14.applied, 2))) by {
                assert forall|j: (int, int)| incoming(s14, 2).contains(j)
                    implies map_at_s(s14.applied, 2).contains(j) by {
                    assert(j == a1) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a2);
                    }
                    map_insert_at_s(ap1, 2, ej.insert(a1), 2);
                }
            }
            assert(s15.observed =~= s14.observed.insert(2, s14.stored)) by {
                assert(ob12 =~= ob1.insert(2, s1234));
            }
        }
    }
    assert(next(s15, s16)) by {
        assert(is_controller(2));
        assert(pause(s15, s16, false, 2)) by {
            assert(owned(2, s15.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(2, s15.pending).contains(j) by {
                    owned_mem(2, s15.pending, j);
                }
            }
            assert(map_at_s(s15.observed, 2) =~= s15.stored) by {
                map_insert_at_s(ob1, 2, s1234, 2);
            }
            assert(incoming(s15, 2).subset_of(map_at_s(s15.applied, 2))) by {
                assert forall|j: (int, int)| incoming(s15, 2).contains(j)
                    implies map_at_s(s15.applied, 2).contains(j) by {
                    assert(j == a1) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a2);
                    }
                    map_insert_at_s(ap1, 2, ej.insert(a1), 2);
                }
            }
        }
    }
    assert(next(s16, s17)) by {
        assert(is_controller(1));
        assert(crash(s16, s17, 1)) by {
            assert(s16.online.contains(1));
            assert(s17.online =~= s16.online.remove(1)) by {
                assert(on2 =~= controllers().remove(1)) by {
                    assert forall|x: int| on2.contains(x)
                        implies controllers().remove(1).contains(x) by {
                        assert(x == 2);
                    }
                    assert forall|x: int| controllers().remove(1).contains(x)
                        implies on2.contains(x) by {
                        assert(x == 2);
                    }
                }
            }
        }
    }
    assert(next(s17, s18)) by {
        assert(is_controller(1));
        assert(reopen(s17, s18, 1)) by {
            assert(!s17.online.contains(1));
            assert(s18.online =~= s17.online.insert(1)) by {
                assert(controllers() =~= on2.insert(1)) by {
                    assert forall|x: int| controllers().contains(x)
                        implies on2.insert(1).contains(x) by {
                        assert(x == 1 || x == 2);
                    }
                }
            }
        }
    }
    assert(next(s18, s19)) by {
        assert(required(false).subset_of(s18.paused)) by {
            assert(required(false) =~= controllers());
        }
        assert forall|c: int| required(false).contains(c) implies map_at_s(s18.observed, c)
            =~= s18.stored by {
            if c == 1 {
                map_insert_at_s(zm, 1, s1234, 1);
            } else {
                assert(c == 2);
                map_insert_at_s(zm, 1, s1234, 2);
                map_insert_at_s(ob1, 2, s1234, 2);
            }
        }
        assert(fence(s18, s19, false, false));
    }
    assert(next(s19, s20)) by {
        assert(is_controller(1));
        assert(prepare(s19, s20, 1)) by {
            assert(s19.online.contains(1));
            assert(s19.fenced);
            assert(s19.paused.contains(1));
            assert(map_at_s(s19.observed, 1) =~= s19.terminal) by {
                map_insert_at_s(zm, 1, s1234, 1);
            }
            assert(owned(1, s19.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(1, s19.pending).contains(j) by {
                    owned_mem(1, s19.pending, j);
                }
            }
            assert(incoming(s19, 1).subset_of(map_at_s(s19.applied, 1))) by {
                assert forall|j: (int, int)| incoming(s19, 1).contains(j)
                    implies map_at_s(s19.applied, 1).contains(j) by {
                    assert(j == a2) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a1);
                    }
                    map_insert_at_s(zm, 1, ej.insert(a2), 1);
                }
            }
        }
    }
    assert(next(s20, s21)) by {
        assert(is_controller(2));
        assert(prepare(s20, s21, 2)) by {
            assert(s20.online.contains(2));
            assert(s20.fenced);
            assert(s20.paused.contains(2));
            assert(map_at_s(s20.observed, 2) =~= s20.terminal) by {
                map_insert_at_s(zm, 1, s1234, 2);
                map_insert_at_s(ob1, 2, s1234, 2);
            }
            assert(owned(2, s20.pending) =~= Set::empty()) by {
                assert forall|j: (int, int)| !owned(2, s20.pending).contains(j) by {
                    owned_mem(2, s20.pending, j);
                }
            }
            assert(incoming(s20, 2).subset_of(map_at_s(s20.applied, 2))) by {
                assert forall|j: (int, int)| incoming(s20, 2).contains(j)
                    implies map_at_s(s20.applied, 2).contains(j) by {
                    assert(j == a1) by {
                        assert(applications().contains(j));
                        assert(j == a1 || j == a2);
                        assert(j != a2);
                    }
                    map_insert_at_s(ap1, 2, ej.insert(a1), 2);
                }
            }
        }
    }
    assert(next(s21, s22)) by {
        assert(is_controller(1));
        assert(select(s21, s22, false, false, false, 1)) by {
            assert(s21.online.contains(1));
            assert(s21.fenced);
            assert(!s21.selected1.contains(1));
            assert(s21.intent1.contains(1));
            assert(s22.archive =~= s21.archive.insert(1, s21.terminal)) by {
                assert(ar1 =~= zm.insert(1, s1234));
            }
            assert(s22.spent =~= s21.spent.insert(1, map_at(s21.spent, 1))) by {
                assert(map_at(s21.spent, 1) == 2) by {
                    assert(s21.spent.dom().contains(1));
                }
                assert(sp22 =~= sp22.insert(1, 2));
            }
        }
    }
    assert(next(s22, s23)) by {
        assert(is_controller(2));
        assert(select(s22, s23, false, false, false, 2)) by {
            assert(s22.online.contains(2));
            assert(s22.fenced);
            assert(!s22.selected1.contains(2));
            assert(s22.intent1.contains(2));
            assert(s23.archive =~= s22.archive.insert(2, s22.terminal)) by {
                assert(ar12 =~= ar1.insert(2, s1234));
            }
            assert(s23.spent =~= s22.spent.insert(2, map_at(s22.spent, 2))) by {
                assert(map_at(s22.spent, 2) == 2) by {
                    assert(s22.spent.dom().contains(2));
                }
                assert(sp22 =~= sp22.insert(2, 2));
            }
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8).push(s9).push(s10).push(s11).push(s12).push(s13).push(s14).push(s15).push(s16)
        .push(s17).push(s18).push(s19).push(s20).push(s21).push(s22).push(s23);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9 || t[i] == s10
                    || t[i] == s11 || t[i] == s12 || t[i] == s13 || t[i] == s14 || t[i] == s15
                    || t[i] == s16 || t[i] == s17 || t[i] == s18 || t[i] == s19 || t[i] == s20
                    || t[i] == s21 || t[i] == s22
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8 || t[i + 1]
                    == s9 || t[i + 1] == s10 || t[i + 1] == s11 || t[i + 1] == s12 || t[i + 1]
                    == s13 || t[i + 1] == s14 || t[i + 1] == s15 || t[i + 1] == s16 || t[i + 1]
                    == s17 || t[i + 1] == s18 || t[i + 1] == s19 || t[i + 1] == s20 || t[i + 1]
                    == s21 || t[i + 1] == s22 || t[i + 1] == s23
            );
        }
    }
    assert(t.last() == s23);
    assert(s23.fenced);
    assert(s23.selected1 =~= controllers());
    assert(s23.intent1 =~= controllers());
    assert forall|c: int| is_controller(c) implies map_at_s(s23.archive, c) =~= s23.terminal
        && map_at(s23.spent, c) == 2 by {
        map_insert_at_s(ar1, 2, s1234, c);
        if c == 1 {
            map_insert_at_s(zm, 1, s1234, 1);
            assert(s23.spent.dom().contains(1));
        } else {
            assert(c == 2);
            assert(s23.spent.dom().contains(2));
        }
    }
    assert(is_trace(t) && t.last().fenced && t.last().selected1 =~= controllers()
        && t.last().intent1 =~= controllers() && forall|c: int| is_controller(c)
        ==> map_at_s(t.last().archive, c) =~= t.last().terminal && map_at(t.last().spent, c)
        == 2);
}

}
