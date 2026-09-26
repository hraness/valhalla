//! Verus pilot (5th model): inductive proof of PrivateControl's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs`,
//! `verify/private-publication/publication.rs` and
//! `verify/host-recovery/recovery.rs`: `PrivateControl.tla` under
//! `normal.cfg` (LateJoin = FALSE, all six mutant switches false) is
//! re-stated as a Verus transition system and the eight checked safety
//! invariants are proved inductive. The same inductive invariant is also
//! proved for `late-join.cfg` (LateJoin = TRUE), matching its positive
//! TLC result. Each of the six mutant configurations is proved to reach
//! a violation of the invariant TLC found for it:
//! `mutant-current-owner` breaks `HistoricalAuthority`,
//! `mutant-stale-grant` breaks `PinnedHandoff`,
//! `mutant-future-observation` breaks `ObservationOnly`,
//! `mutant-precheckpoint` breaks `KnownHistoryFault`,
//! `mutant-uncertainty` breaks `UncertainCustody`, and
//! `mutant-clear-quarantine` breaks `PersistentQuarantine`. A completion
//! witness carries an A→B handoff plus a conflicting-claim quarantine
//! through a lost completion and a process reopen, and a second witness
//! quarantines a fork over the retained late-join checkpoint chain.
//!
//! Encoding notes:
//!   * Devices == {"A","B"} is {1,2}; Signers adds "foreign" as 3;
//!     "none" is 0. `pc`, `kind`, `variant` and `result` strings are int
//!     constants.
//!   * `signers`/`changes` : [1..MaxControls -> _] become `Map<int,int>`
//!     with `dom() = 1..4`, read through `map_at` (0 off-domain, which is
//!     also "none"). `usedGrants` is a `Set<UsedGrant>` of int records.
//!   * `OwnerAt(changes, seq)` (the change at the greatest h < seq with
//!     h in 1..4 and changes[h] # "none", else "A") is unrolled over the
//!     fixed domain 1..4 as a descending if-chain on h = 4,3,2,1.
//!   * `Cardinality(Handoffs) < 2` is the unrolled count of non-"none"
//!     `changes` entries on 1..4; the auxiliary `changes[h] # "none" =>
//!     h <= floor` makes it agree with `Cardinality` on reachable states.
//!   * `Initial` is literal: under `late_join` the maps are
//!     signers = [A,A,B,none] / changes[2] = B, which is exactly the
//!     OwnerAt-computed initial image (proved inside `init_inv` when the
//!     invariant is established).
//!   * TLA `s' = [s EXCEPT ...]` is written as `post == State{..pre}`
//!     functional updates, which is the same fieldwise rebinding.
//!   * The TLA existential `\E sequence \in 1..MaxControls+1, signer \in
//!     Signers, variant \in {"exact","conflict"} : Observe(...)` is one
//!     multi-binder existential, which is equivalent.
//!   * Stutter steps of `[][Next]_vars` are not modeled; they preserve
//!     every state predicate trivially.
//!
//! Verify with:
//!   verus --crate-type=lib verify/private-control/control.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// MaxControls = 4 from the checked configurations.
pub open spec fn max_controls() -> int {
    4
}

/// ReopenBudget = 2 from the checked configurations.
pub open spec fn reopen_budget() -> int {
    2
}

/// The control sequence domain 1..MaxControls.
pub open spec fn seqs() -> Set<int> {
    Set::empty().insert(1).insert(2).insert(3).insert(4)
}

pub open spec fn is_seq(h: int) -> bool {
    1 <= h <= max_controls()
}

/// Devices == {"A", "B"} as {1, 2}.
pub open spec fn dev_a() -> int {
    1
}

pub open spec fn dev_b() -> int {
    2
}

/// "foreign" as 3.
pub open spec fn foreign() -> int {
    3
}

/// "none" as 0.
pub open spec fn none() -> int {
    0
}

pub open spec fn is_device(d: int) -> bool {
    d == dev_a() || d == dev_b()
}

/// Signers == Devices \cup {"foreign"}.
pub open spec fn is_signer(d: int) -> bool {
    is_device(d) || d == foreign()
}

/// Other(device) == IF device = "A" THEN "B" ELSE "A".
pub open spec fn other(d: int) -> int {
    if d == dev_a() {
        dev_b()
    } else {
        dev_a()
    }
}

/// pc alphabet {"idle","publishing","readback"}.
pub open spec fn pc_idle() -> int {
    0
}

pub open spec fn pc_publishing() -> int {
    1
}

pub open spec fn pc_readback() -> int {
    2
}

pub open spec fn is_pc(p: int) -> bool {
    0 <= p <= 2
}

/// kind alphabet {"none","handoff","fork"}.
pub open spec fn k_none() -> int {
    0
}

pub open spec fn k_handoff() -> int {
    1
}

pub open spec fn k_fork() -> int {
    2
}

pub open spec fn is_kind(k: int) -> bool {
    0 <= k <= 2
}

/// variant alphabet {"exact","conflict"}.
pub open spec fn v_exact() -> int {
    0
}

pub open spec fn v_conflict() -> int {
    1
}

pub open spec fn is_variant(v: int) -> bool {
    v == v_exact() || v == v_conflict()
}

/// result alphabet {"Policy","Missing","Exact","Fork"}.
pub open spec fn r_policy() -> int {
    0
}

pub open spec fn r_missing() -> int {
    1
}

pub open spec fn r_exact() -> int {
    2
}

pub open spec fn r_fork() -> int {
    3
}

/// Base == IF LateJoin THEN 2 ELSE 0.
pub open spec fn base(lj: bool) -> int {
    if lj {
        2
    } else {
        0
    }
}

/// InitialFloor == IF LateJoin THEN 3 ELSE 1.
pub open spec fn ifloor(lj: bool) -> int {
    if lj {
        3
    } else {
        1
    }
}

/// Initial.owner == IF LateJoin THEN "B" ELSE "A".
pub open spec fn iowner(lj: bool) -> int {
    if lj {
        dev_b()
    } else {
        dev_a()
    }
}

/// Total map read at int keys: 0 off-domain, which is also "none".
pub open spec fn map_at(m: Map<int, int>, j: int) -> int {
    if m.dom().contains(j) {
        m[j]
    } else {
        0
    }
}

/// OwnerAt(changes, sequence): the change at the greatest h < sequence in
/// 1..MaxControls with changes[h] # "none", else "A". Unrolled over the
/// fixed domain; the descending branch order picks the greatest such h.
pub open spec fn owner_at(changes: Map<int, int>, sequence: int) -> int {
    if sequence > 4 && map_at(changes, 4) != none() {
        map_at(changes, 4)
    } else if sequence > 3 && map_at(changes, 3) != none() {
        map_at(changes, 3)
    } else if sequence > 2 && map_at(changes, 2) != none() {
        map_at(changes, 2)
    } else if sequence > 1 && map_at(changes, 1) != none() {
        map_at(changes, 1)
    } else {
        dev_a()
    }
}

/// Cardinality(Handoffs): the count of non-"none" changes entries in
/// 1..MaxControls. The aux `changes[h] # "none" => h <= floor` keeps this
/// equal to |{h \in 1..floor : changes[h] # "none"}| on reachable states.
pub open spec fn handoff_count(d: Disk) -> int {
    let c = |h: int| if map_at(d.changes, h) != none() {
        1int
    } else {
        0int
    };
    c(1) + c(2) + c(3) + c(4)
}

/// The [floor, owner, signers, changes, fault] image record shared by
/// `disk` and `cached`.
pub struct Disk {
    pub floor: int,
    pub owner: int,
    pub signers: Map<int, int>,
    pub changes: Map<int, int>,
    pub fault: int,
}

/// The prepared grant record [present, sequence, predecessor, successor].
pub struct Grant {
    pub present: bool,
    pub sequence: int,
    pub predecessor: int,
    pub successor: int,
}

/// A usedGrants member [carriedAt, grantedAt, predecessor, signer,
/// successor].
pub struct UsedGrant {
    pub carried_at: int,
    pub granted_at: int,
    pub predecessor: int,
    pub signer: int,
    pub successor: int,
}

/// The observation record [present, sequence, signer, expectedOwner,
/// variant, result, base, beforeFloor, afterFloor, beforeOwner,
/// afterOwner].
pub struct Observation {
    pub present: bool,
    pub sequence: int,
    pub signer: int,
    pub expected_owner: int,
    pub variant: int,
    pub result: int,
    pub base: int,
    pub before_floor: int,
    pub after_floor: int,
    pub before_owner: int,
    pub after_owner: int,
}

/// VARIABLE s.
pub struct State {
    pub disk: Disk,
    pub cached: Disk,
    pub pc: int,
    pub needs_reopen: bool,
    pub uncertain: bool,
    pub kind: int,
    pub pending_fork: int,
    pub ever_fault: bool,
    pub grant: Grant,
    pub used_grants: Set<UsedGrant>,
    pub observation: Observation,
    pub reopens: int,
}

/// The all-"none" map on 1..MaxControls.
pub open spec fn nmap() -> Map<int, int> {
    Map::new(seqs(), |h: int| 0)
}

/// InitialChanges == [h |-> IF LateJoin /\ h = 2 THEN "B" ELSE "none"].
/// Literal form of the same function.
pub open spec fn ichanges(lj: bool) -> Map<int, int> {
    if lj {
        nmap().insert(2, dev_b())
    } else {
        nmap()
    }
}

/// Initial.signers == [h |-> IF h > InitialFloor THEN "none" ELSE
/// OwnerAt(InitialChanges, h)], evaluated: [A,none..] normally and
/// [A,A,B,none] under LateJoin (OwnerAt over changes[2] = B gives A at
/// 1-2 and B at 3).
pub open spec fn isigners(lj: bool) -> Map<int, int> {
    if lj {
        nmap().insert(1, dev_a()).insert(2, dev_a()).insert(3, dev_b())
    } else {
        nmap().insert(1, dev_a())
    }
}

/// The Initial disk/cached image.
pub open spec fn idisk(lj: bool) -> Disk {
    Disk { floor: ifloor(lj), owner: iowner(lj), signers: isigners(lj), changes: ichanges(lj), fault: 0 }
}

/// NoGrant.
pub open spec fn no_grant() -> Grant {
    Grant { present: false, sequence: 0, predecessor: dev_a(), successor: dev_b() }
}

/// NoObservation (base/floor/owner fields follow LateJoin).
pub open spec fn no_observation(lj: bool) -> Observation {
    Observation {
        present: false,
        sequence: 1,
        signer: dev_a(),
        expected_owner: dev_a(),
        variant: v_exact(),
        result: r_exact(),
        base: base(lj),
        before_floor: ifloor(lj),
        after_floor: ifloor(lj),
        before_owner: iowner(lj),
        after_owner: iowner(lj),
    }
}

/// Init under a LateJoin flag.
pub open spec fn init_cfg(lj: bool, s: State) -> bool {
    &&& s.disk == idisk(lj)
    &&& s.cached == idisk(lj)
    &&& s.pc == pc_idle()
    &&& !s.needs_reopen
    &&& !s.uncertain
    &&& s.kind == k_none()
    &&& s.pending_fork == 0
    &&& !s.ever_fault
    &&& s.grant == no_grant()
    &&& s.used_grants =~= Set::empty()
    &&& s.observation == no_observation(lj)
    &&& s.reopens == 0
}

/// normal.cfg init (LateJoin = FALSE).
pub open spec fn init(s: State) -> bool {
    init_cfg(false, s)
}

/// late-join.cfg init (LateJoin = TRUE).
pub open spec fn init_late_join(s: State) -> bool {
    init_cfg(true, s)
}

/// Live == s.pc = "idle" /\ ~s.needsReopen /\ s.cached.fault = 0.
pub open spec fn live(s: State) -> bool {
    &&& s.pc == pc_idle()
    &&& !s.needs_reopen
    &&& s.cached.fault == 0
}

/// PrepareGrant == /\ Live /\ s.disk.floor < MaxControls
///                 /\ Cardinality(Handoffs) < 2
///                 /\ s' = [s EXCEPT !.grant = [present |-> TRUE, ...]]
pub open spec fn prepare_grant(pre: State, post: State) -> bool {
    &&& live(pre)
    &&& pre.disk.floor < max_controls()
    &&& handoff_count(pre.disk) < 2
    &&& post == State {
        grant: Grant {
            present: true,
            sequence: pre.disk.floor + 1,
            predecessor: pre.disk.owner,
            successor: other(pre.disk.owner),
        },
        ..pre
    }
}

/// AdvanceControl == /\ Live /\ s.disk.floor < MaxControls
///                   /\ s' = [s EXCEPT !.disk = next, !.cached = next]
/// where next advances floor and records the current owner as signer.
pub open spec fn advance_control(pre: State, post: State) -> bool {
    let h = pre.disk.floor + 1;
    let next_disk = Disk {
        floor: h,
        signers: pre.disk.signers.insert(h, pre.disk.owner),
        ..pre.disk
    };
    &&& live(pre)
    &&& pre.disk.floor < max_controls()
    &&& post == State { disk: next_disk, cached: next_disk, ..pre }
}

/// BeginHandoff == /\ Live /\ s.grant.present /\ s.disk.floor < MaxControls
///                 /\ Cardinality(Handoffs) < 2
///                 /\ s.grant.predecessor = s.disk.owner
///                 /\ RebindGrant \/ s.grant.sequence = s.disk.floor + 1
///                 /\ s' = [s EXCEPT !.pc = "publishing", !.kind = "handoff",
///                                    !.needsReopen = TRUE, !.uncertain = TRUE]
pub open spec fn begin_handoff(pre: State, post: State, rg: bool) -> bool {
    &&& live(pre)
    &&& pre.grant.present
    &&& pre.disk.floor < max_controls()
    &&& handoff_count(pre.disk) < 2
    &&& pre.grant.predecessor == pre.disk.owner
    &&& (rg || pre.grant.sequence == pre.disk.floor + 1)
    &&& post == State {
        pc: pc_publishing(),
        kind: k_handoff(),
        needs_reopen: true,
        uncertain: true,
        ..pre
    }
}

/// Observe(sequence, signer, variant) — see the TLA+ LET chain. `base` is
/// the LateJoin-dependent checkpoint base; `cos` is CurrentOwnerShortcut,
/// `ao` is AdmitObservation, `fbc` is FaultBeforeCheckpoint.
pub open spec fn observe(
    pre: State,
    post: State,
    lj: bool,
    cos: bool,
    ao: bool,
    fbc: bool,
    seq: int,
    signer: int,
    variant: int,
) -> bool {
    let b = base(lj);
    let expected_owner = owner_at(pre.disk.changes, seq);
    let checked_owner = if cos {
        pre.disk.owner
    } else {
        expected_owner
    };
    let result = if signer != checked_owner {
        r_policy()
    } else if seq > pre.disk.floor {
        r_missing()
    } else if seq < b && !fbc {
        r_missing()
    } else if variant == v_exact() {
        r_exact()
    } else {
        r_fork()
    };
    let admit = ao && signer == checked_owner && seq > pre.disk.floor && seq <= max_controls();
    let next_disk = if admit {
        Disk { floor: seq, signers: pre.disk.signers.insert(seq, signer), ..pre.disk }
    } else {
        pre.disk
    };
    &&& live(pre)
    &&& post == State {
        disk: next_disk,
        cached: next_disk,
        observation: Observation {
            present: true,
            sequence: seq,
            signer: signer,
            expected_owner: expected_owner,
            variant: variant,
            result: result,
            base: b,
            before_floor: pre.disk.floor,
            after_floor: next_disk.floor,
            before_owner: pre.disk.owner,
            after_owner: next_disk.owner,
        },
        pc: if result == r_fork() {
            pc_publishing()
        } else {
            pre.pc
        },
        kind: if result == r_fork() {
            k_fork()
        } else {
            pre.kind
        },
        pending_fork: if result == r_fork() {
            seq
        } else {
            pre.pending_fork
        },
        needs_reopen: result == r_fork(),
        uncertain: result == r_fork(),
        ..pre
    }
}

/// RefuseBefore == /\ s.pc = "publishing"
///                 /\ s' = [s EXCEPT !.pc = "idle",
///                                    !.needsReopen = ~UnlatchUncertainty]
pub open spec fn refuse_before(pre: State, post: State, uu: bool) -> bool {
    &&& pre.pc == pc_publishing()
    &&& post == State { pc: pc_idle(), needs_reopen: !uu, ..pre }
}

/// Publish == /\ s.pc = "publishing" /\ LET h == s.disk.floor + 1 ...
/// Fork quarantine writes only the fault; a handoff advances floor, owner,
/// signers and the change chain and records the used grant.
pub open spec fn publish(pre: State, post: State) -> bool {
    let h = pre.disk.floor + 1;
    let next_disk = if pre.kind == k_fork() {
        Disk { fault: pre.pending_fork, ..pre.disk }
    } else {
        Disk {
            floor: h,
            owner: pre.grant.successor,
            signers: pre.disk.signers.insert(h, pre.disk.owner),
            changes: pre.disk.changes.insert(h, pre.grant.successor),
            ..pre.disk
        }
    };
    &&& pre.pc == pc_publishing()
    &&& post == State {
        disk: next_disk,
        pc: pc_readback(),
        ever_fault: pre.ever_fault || pre.kind == k_fork(),
        used_grants: if pre.kind == k_handoff() {
            pre.used_grants.insert(UsedGrant {
                carried_at: h,
                granted_at: pre.grant.sequence,
                predecessor: pre.grant.predecessor,
                signer: pre.disk.owner,
                successor: pre.grant.successor,
            })
        } else {
            pre.used_grants
        },
        ..pre
    }
}

/// LoseCompletion == /\ s.pc = "readback"
///                   /\ s' = [s EXCEPT !.pc = "idle",
///                                      !.needsReopen = ~UnlatchUncertainty]
pub open spec fn lose_completion(pre: State, post: State, uu: bool) -> bool {
    &&& pre.pc == pc_readback()
    &&& post == State { pc: pc_idle(), needs_reopen: !uu, ..pre }
}

/// Confirm == /\ s.pc = "readback" /\ s' = [s EXCEPT !.cached = s.disk,
///   !.pc = "idle", !.needsReopen = FALSE, !.uncertain = FALSE,
///   !.kind = "none", !.pendingFork = 0]
pub open spec fn confirm(pre: State, post: State) -> bool {
    &&& pre.pc == pc_readback()
    &&& post == State {
        cached: pre.disk,
        pc: pc_idle(),
        needs_reopen: false,
        uncertain: false,
        kind: k_none(),
        pending_fork: 0,
        ..pre
    }
}

/// Reopen == /\ s.reopens < ReopenBudget
///           /\ s' = [s EXCEPT !.cached = IF ClearQuarantine THEN
///                  [s.disk EXCEPT !.fault = 0] ELSE s.disk, ...]
pub open spec fn reopen(pre: State, post: State, cq: bool) -> bool {
    &&& pre.reopens < reopen_budget()
    &&& post == State {
        cached: if cq {
            Disk { fault: 0, ..pre.disk }
        } else {
            pre.disk
        },
        pc: pc_idle(),
        needs_reopen: false,
        uncertain: false,
        kind: k_none(),
        pending_fork: 0,
        reopens: pre.reopens + 1,
        ..pre
    }
}

/// Next under arbitrary config constants, in the declaration order
/// (LateJoin, CurrentOwnerShortcut, RebindGrant, AdmitObservation,
/// FaultBeforeCheckpoint, UnlatchUncertainty, ClearQuarantine).
pub open spec fn next_cfg(
    lj: bool,
    cos: bool,
    rg: bool,
    ao: bool,
    fbc: bool,
    uu: bool,
    cq: bool,
    pre: State,
    post: State,
) -> bool {
    ||| prepare_grant(pre, post)
    ||| advance_control(pre, post)
    ||| begin_handoff(pre, post, rg)
    ||| refuse_before(pre, post, uu)
    ||| publish(pre, post)
    ||| lose_completion(pre, post, uu)
    ||| confirm(pre, post)
    ||| reopen(pre, post, cq)
    ||| exists|seq: int, signer: int, variant: int|
        1 <= seq <= max_controls() + 1 && is_signer(signer) && is_variant(variant)
            && #[trigger] observe(pre, post, lj, cos, ao, fbc, seq, signer, variant)
}

/// normal.cfg: every switch false.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, false, false, pre, post)
}

/// late-join.cfg: LateJoin = TRUE, every switch false.
pub open spec fn next_late_join(pre: State, post: State) -> bool {
    next_cfg(true, false, false, false, false, false, false, pre, post)
}

/// mutant-current-owner.cfg: CurrentOwnerShortcut = TRUE.
pub open spec fn next_mutant_current_owner(pre: State, post: State) -> bool {
    next_cfg(false, true, false, false, false, false, false, pre, post)
}

/// mutant-stale-grant.cfg: RebindGrant = TRUE.
pub open spec fn next_mutant_stale_grant(pre: State, post: State) -> bool {
    next_cfg(false, false, true, false, false, false, false, pre, post)
}

/// mutant-future-observation.cfg: AdmitObservation = TRUE.
pub open spec fn next_mutant_future_observation(pre: State, post: State) -> bool {
    next_cfg(false, false, false, true, false, false, false, pre, post)
}

/// mutant-precheckpoint.cfg: LateJoin = TRUE, FaultBeforeCheckpoint = TRUE.
pub open spec fn next_mutant_precheckpoint(pre: State, post: State) -> bool {
    next_cfg(true, false, false, false, true, false, false, pre, post)
}

/// mutant-uncertainty.cfg: UnlatchUncertainty = TRUE.
pub open spec fn next_mutant_uncertainty(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, true, false, pre, post)
}

/// mutant-clear-quarantine.cfg: ClearQuarantine = TRUE.
pub open spec fn next_mutant_clear_quarantine(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, false, true, pre, post)
}

/// TypeOK. `signers`/`changes` are functions on exactly 1..MaxControls
/// with codomains Signers ∪ {"none"} and Devices ∪ {"none"}; TLA leaves
/// the cached maps untyped and this encoding does the same.
pub open spec fn type_ok(s: State) -> bool {
    &&& is_pc(s.pc)
    &&& 1 <= s.disk.floor <= max_controls()
    &&& is_device(s.disk.owner)
    &&& 1 <= s.cached.floor <= max_controls()
    &&& is_device(s.cached.owner)
    &&& s.disk.signers.dom() =~= seqs()
    &&& forall|h: int| is_seq(h) ==> 0 <= #[trigger] map_at(s.disk.signers, h) <= 3
    &&& s.disk.changes.dom() =~= seqs()
    &&& forall|h: int| is_seq(h) ==> 0 <= #[trigger] map_at(s.disk.changes, h) <= 2
    &&& 0 <= s.disk.fault <= max_controls()
    &&& 0 <= s.cached.fault <= max_controls()
    &&& is_kind(s.kind)
    &&& 0 <= s.pending_fork <= max_controls()
    &&& 0 <= s.reopens <= reopen_budget()
}

/// HistoricalSigners == s.disk.owner = OwnerAt(changes, floor + 1) /\
///   \A h \in 1..floor : signers[h] = OwnerAt(changes, h).
pub open spec fn historical_signers(s: State) -> bool {
    &&& s.disk.owner == owner_at(s.disk.changes, s.disk.floor + 1)
    &&& forall|h: int| 1 <= h <= s.disk.floor ==> map_at(s.disk.signers, h) == owner_at(
        s.disk.changes,
        h,
    )
}

/// HistoricalAuthority == ~observation.present \/
///   ((signer = expectedOwner) <=> (result # "Policy")).
pub open spec fn historical_authority(s: State) -> bool {
    !s.observation.present || ((s.observation.signer == s.observation.expected_owner)
        == (s.observation.result != r_policy()))
}

/// PinnedHandoff == \A grant \in usedGrants : carriedAt = grantedAt /\
///   predecessor = signer /\ successor # predecessor.
pub open spec fn pinned_handoff(s: State) -> bool {
    forall|g: UsedGrant| #[trigger] s.used_grants.contains(g) ==> (g.carried_at
        == g.granted_at && g.predecessor == g.signer && g.successor != g.predecessor)
}

/// ObservationOnly == beforeFloor = afterFloor /\ beforeOwner = afterOwner.
pub open spec fn observation_only(s: State) -> bool {
    &&& s.observation.before_floor == s.observation.after_floor
    &&& s.observation.before_owner == s.observation.after_owner
}

/// KnownHistoryFault == result = "Fork" => sequence >= base /\
///   sequence <= beforeFloor /\ signer = expectedOwner /\
///   variant = "conflict".
pub open spec fn known_history_fault(s: State) -> bool {
    s.observation.result == r_fork() ==> (s.observation.sequence >= s.observation.base
        && s.observation.sequence <= s.observation.before_floor && s.observation.signer
        == s.observation.expected_owner && s.observation.variant == v_conflict())
}

/// UncertainCustody == uncertain => needsReopen /\
///   (kind = "fork" => pendingFork # 0).
pub open spec fn uncertain_custody(s: State) -> bool {
    s.uncertain ==> (s.needs_reopen && (s.kind == k_fork() ==> s.pending_fork != 0))
}

/// PersistentQuarantine == everFault /\ ~needsReopen =>
///   disk.fault # 0 /\ cached.fault # 0.
pub open spec fn persistent_quarantine(s: State) -> bool {
    (s.ever_fault && !s.needs_reopen) ==> (s.disk.fault != 0 && s.cached.fault != 0)
}

/// Auxiliary: accepted handoff entries only exist at or below the floor —
/// the only writer (Publish) writes changes at the new floor.
pub open spec fn aux_changes_floor(s: State) -> bool {
    forall|h: int| #[trigger] map_at(s.disk.changes, h) != none() ==> h <= s.disk.floor
}

/// Auxiliary: a non-"none" kind always carries the reopen latch — both
/// entries into "publishing" set needsReopen, and the only clears also
/// clear kind.
pub open spec fn aux_kind_needs_reopen(s: State) -> bool {
    s.kind != k_none() ==> s.needs_reopen
}

/// Auxiliary: a fork kind always carries its nonzero pending sequence —
/// Observe sets both together and the only clears also clear kind.
pub open spec fn aux_kind_pending(s: State) -> bool {
    s.kind == k_fork() ==> s.pending_fork != 0
}

/// Auxiliary: once a fork quarantine is committed the durable fault mark
/// is never cleared — everFault is only set at a fork Publish, which
/// writes pendingFork # 0, and no action touches disk.fault afterwards.
pub open spec fn aux_everfault_disk(s: State) -> bool {
    s.ever_fault ==> s.disk.fault != 0
}

/// Auxiliary: while a handoff publication is in flight the grant stays
/// pinned to the carrying sequence and the current owner — between
/// BeginHandoff and Publish no action can touch disk or grant.
pub open spec fn aux_handoff_grant(s: State) -> bool {
    (s.pc == pc_publishing() && s.kind == k_handoff()) ==> (s.grant.present
        && s.grant.sequence == s.disk.floor + 1 && s.grant.predecessor == s.disk.owner
        && s.grant.successor == other(s.disk.owner) && s.disk.floor < max_controls())
}

/// Auxiliary: a present grant always has the PrepareGrant shape — a device
/// predecessor and its "other" successor.
pub open spec fn aux_grant_shape(s: State) -> bool {
    s.grant.present ==> (is_device(s.grant.predecessor) && s.grant.successor == other(
        s.grant.predecessor,
    ))
}

/// Auxiliary: "publishing" is only entered by BeginHandoff or a Fork
/// observation, so the kind there is never "none".
pub open spec fn aux_publishing_kind(s: State) -> bool {
    s.pc == pc_publishing() ==> s.kind != k_none()
}

/// The inductive invariant: TypeOK plus the seven checked safety
/// invariants, strengthened by the seven auxiliaries.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& historical_signers(s)
    &&& historical_authority(s)
    &&& pinned_handoff(s)
    &&& observation_only(s)
    &&& known_history_fault(s)
    &&& uncertain_custody(s)
    &&& persistent_quarantine(s)
    &&& aux_changes_floor(s)
    &&& aux_kind_needs_reopen(s)
    &&& aux_kind_pending(s)
    &&& aux_everfault_disk(s)
    &&& aux_handoff_grant(s)
    &&& aux_grant_shape(s)
    &&& aux_publishing_kind(s)
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

proof fn init_inv(lj: bool, s: State)
    requires
        init_cfg(lj, s),
    ensures
        inv(s),
{
    // HistoricalSigners at init, for both LateJoin values: signers equals
    // the OwnerAt-computed image and owner equals OwnerAt(changes, floor+1).
    if lj {
        assert(owner_at(s.disk.changes, 1) == dev_a());
        assert(owner_at(s.disk.changes, 2) == dev_a());
        assert(owner_at(s.disk.changes, 3) == dev_b());
        assert(owner_at(s.disk.changes, 4) == dev_b());
    } else {
        assert(owner_at(s.disk.changes, 1) == dev_a());
        assert(owner_at(s.disk.changes, 2) == dev_a());
    }
    assert forall|h: int| 1 <= h <= s.disk.floor implies map_at(s.disk.signers, h)
        == owner_at(s.disk.changes, h) by {
        if lj {
            if h == 1 {
            } else if h == 2 {
            } else {
                assert(h == 3);
            }
        } else {
            assert(h == 1);
        }
    }
    assert forall|h: int| is_seq(h) implies 0 <= #[trigger] map_at(s.disk.signers, h)
        <= 3 by {
    }
    assert forall|h: int| is_seq(h) implies 0 <= #[trigger] map_at(s.disk.changes, h)
        <= 2 by {
    }
    assert(type_ok(s));
    assert(historical_signers(s));
    assert(historical_authority(s));
    assert(pinned_handoff(s));
    assert(observation_only(s));
    assert(known_history_fault(s));
    assert(uncertain_custody(s));
    assert(persistent_quarantine(s));
    assert(aux_changes_floor(s));
    assert(aux_kind_needs_reopen(s));
    assert(aux_kind_pending(s));
    assert(aux_everfault_disk(s));
    assert(aux_handoff_grant(s));
    assert(aux_grant_shape(s));
    assert(aux_publishing_kind(s));
}

proof fn prepare_grant_preserves(pre: State, post: State)
    requires
        inv(pre),
        prepare_grant(pre, post),
    ensures
        inv(post),
{
    // Live gives ~needsReopen and cached.fault = 0; the latter with
    // persistent_quarantine(pre) and ~ever_fault makes the post-state
    // quarantine conjunct vacuous, and ~needsReopen makes ~uncertain.
    assert(!pre.ever_fault);
    assert(!pre.uncertain);
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn advance_control_preserves(pre: State, post: State)
    requires
        inv(pre),
        advance_control(pre, post),
    ensures
        inv(post),
{
    let h = pre.disk.floor + 1;
    assert(2 <= h <= max_controls());
    // The new floor's changes entry is still "none" (aux_changes_floor),
    // so OwnerAt(changes, h + 1) = OwnerAt(changes, h) = pre.disk.owner.
    assert(map_at(pre.disk.changes, h) == none());
    assert(owner_at(pre.disk.changes, h) == pre.disk.owner);
    assert(owner_at(pre.disk.changes, h + 1) == pre.disk.owner) by {
        // owner_at reads only entries < h + 1; the entry at h is "none".
        assert(map_at(pre.disk.changes, h) == none());
    }
    let sg2 = post.disk.signers;
    assert(sg2.dom() =~= seqs()) by {
        assert(sg2.dom() =~= pre.disk.signers.dom().insert(h));
        assert(seqs().insert(h) =~= seqs());
    }
    assert forall|x: int| is_seq(x) implies 0 <= #[trigger] map_at(sg2, x) <= 3 by {
        map_insert_at(pre.disk.signers, h, pre.disk.owner, x);
    }
    assert forall|q: int| 1 <= q <= post.disk.floor implies map_at(sg2, q) == owner_at(
        post.disk.changes,
        q,
    ) by {
        map_insert_at(pre.disk.signers, h, pre.disk.owner, q);
        if q == h {
        } else {
            assert(q <= pre.disk.floor);
        }
    }
    assert(historical_signers(post));
    assert(!pre.ever_fault);
    assert(!pre.uncertain);
    assert(type_ok(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn begin_handoff_preserves(pre: State, post: State)
    requires
        inv(pre),
        begin_handoff(pre, post, false),
    ensures
        inv(post),
{
    // aux_handoff_grant: the guards pin sequence/predecessor; the shape aux
    // turns successor = other(predecessor) into other(owner).
    assert(pre.grant.successor == other(pre.grant.predecessor));
    assert(pre.grant.successor == other(pre.disk.owner));
    assert(aux_handoff_grant(post));
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn observe_preserves(pre: State, post: State, lj: bool, seq: int, signer: int, variant: int)
    requires
        inv(pre),
        1 <= seq <= max_controls() + 1,
        is_signer(signer),
        is_variant(variant),
        observe(pre, post, lj, false, false, false, seq, signer, variant),
    ensures
        inv(post),
{
    let b = base(lj);
    let expected_owner = owner_at(pre.disk.changes, seq);
    let checked_owner = expected_owner;
    let result = if signer != checked_owner {
        r_policy()
    } else if seq > pre.disk.floor {
        r_missing()
    } else if seq < b {
        r_missing()
    } else if variant == v_exact() {
        r_exact()
    } else {
        r_fork()
    };
    // admit is false under AdmitObservation = FALSE, so disk/cached are
    // unchanged images of pre.disk.
    assert(post.disk == pre.disk);
    assert(post.observation.result == result);
    assert(post.observation.signer == signer);
    assert(post.observation.expected_owner == expected_owner);
    assert(post.observation.base == b);
    assert(post.observation.before_floor == pre.disk.floor);
    assert(post.observation.after_floor == pre.disk.floor);
    assert(post.observation.before_owner == pre.disk.owner);
    assert(post.observation.after_owner == pre.disk.owner);
    assert(post.observation.present);
    // Live forces kind = "none" and ~ever_fault, ~uncertain through the
    // auxiliaries (kind # none => needsReopen; everFault with ~needsReopen
    // would contradict cached.fault = 0).
    assert(pre.kind == k_none());
    assert(!pre.ever_fault);
    assert(!pre.uncertain);
    // Result-chain facts needed below.
    if result == r_fork() {
        assert(signer == checked_owner);
        assert(seq <= pre.disk.floor);
        assert(seq >= b);
        assert(variant == v_conflict());
        assert(post.kind == k_fork());
        assert(post.pending_fork == seq);
        assert(post.needs_reopen && post.uncertain);
    } else {
        assert(post.kind == k_none());
        assert(!post.needs_reopen && !post.uncertain);
    }
    assert(historical_authority(post)) by {
        // (signer == expected_owner) == (result != Policy): the first
        // branch of the result chain makes the two sides agree.
        assert((signer == expected_owner) == (result != r_policy()));
    }
    assert(known_history_fault(post)) by {
        if post.observation.result == r_fork() {
            assert(post.observation.sequence >= post.observation.base);
            assert(post.observation.sequence <= post.observation.before_floor);
            assert(post.observation.signer == post.observation.expected_owner);
            assert(post.observation.variant == v_conflict());
        }
    }
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn refuse_before_preserves(pre: State, post: State)
    requires
        inv(pre),
        refuse_before(pre, post, false),
    ensures
        inv(post),
{
    assert(post.needs_reopen);
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn publish_preserves(pre: State, post: State)
    requires
        inv(pre),
        publish(pre, post),
    ensures
        inv(post),
{
    let h = pre.disk.floor + 1;
    if pre.kind == k_fork() {
        // Fork publish: fault' = pendingFork # 0 (aux_kind_pending), so
        // ever_fault ==> disk.fault # 0 is established for post.
        assert(pre.pending_fork != 0);
        assert(post.disk.fault != 0);
    } else {
        // Handoff branch (kind = "handoff"; "none" is excluded by
        // aux_publishing_kind): the in-flight grant is pinned.
        assert(pre.kind == k_handoff());
        assert(pre.grant.sequence == h);
        assert(pre.grant.predecessor == pre.disk.owner);
        assert(pre.grant.successor == other(pre.disk.owner));
        assert(pre.disk.floor < max_controls());
        let ch2 = post.disk.changes;
        let sg2 = post.disk.signers;
        // owner_at over changes' at h reads only entries < h, unchanged.
        assert forall|k: int| k != h implies #[trigger] map_at(ch2, k) == map_at(
            pre.disk.changes,
            k,
        ) by {
            map_insert_at(pre.disk.changes, h, pre.grant.successor, k);
        }
        assert(map_at(ch2, h) == pre.grant.successor);
        assert(pre.grant.successor != none());
        // HistoricalSigners part 1: owner' = successor = changes'[h] =
        // OwnerAt(changes', h + 1).
        assert(owner_at(ch2, h) == owner_at(pre.disk.changes, h));
        assert(owner_at(pre.disk.changes, h) == pre.disk.owner);
        assert(owner_at(ch2, h) == pre.disk.owner);
        assert(owner_at(ch2, h + 1) == pre.grant.successor);
        // HistoricalSigners part 2.
        assert forall|q: int| 1 <= q <= post.disk.floor implies map_at(sg2, q) == owner_at(
            ch2,
            q,
        ) by {
            map_insert_at(pre.disk.signers, h, pre.disk.owner, q);
            if q == h {
                // signers'[h] = pre owner = OwnerAt(changes, h) = OwnerAt(changes', h).
            } else {
                assert(1 <= q <= pre.disk.floor);
                assert(owner_at(ch2, q) == owner_at(pre.disk.changes, q));
            }
        }
        assert(historical_signers(post));
        // aux_changes_floor: the new entry is at h = post.floor.
        assert forall|k: int| #[trigger] map_at(ch2, k) != none() implies k
            <= post.disk.floor by {
            map_insert_at(pre.disk.changes, h, pre.grant.successor, k);
            if k == h {
            } else {
                assert(k <= pre.disk.floor);
            }
        }
        assert(ch2.dom() =~= seqs()) by {
            assert(ch2.dom() =~= pre.disk.changes.dom().insert(h));
            assert(seqs().insert(h) =~= seqs());
        }
        assert(sg2.dom() =~= seqs()) by {
            assert(sg2.dom() =~= pre.disk.signers.dom().insert(h));
            assert(seqs().insert(h) =~= seqs());
        }
        assert forall|x: int| is_seq(x) implies 0 <= #[trigger] map_at(sg2, x) <= 3 by {
            map_insert_at(pre.disk.signers, h, pre.disk.owner, x);
        }
        assert forall|x: int| is_seq(x) implies 0 <= #[trigger] map_at(ch2, x) <= 2 by {
            map_insert_at(pre.disk.changes, h, pre.grant.successor, x);
        }
        // PinnedHandoff: the new member has carriedAt = h = grant.sequence,
        // signer = predecessor = disk.owner, successor = other(owner).
        assert forall|g: UsedGrant| #[trigger] post.used_grants.contains(g) implies (g.carried_at
            == g.granted_at && g.predecessor == g.signer && g.successor
            != g.predecessor) by {
            if pre.used_grants.contains(g) {
            } else {
                assert(g == UsedGrant {
                    carried_at: h,
                    granted_at: pre.grant.sequence,
                    predecessor: pre.grant.predecessor,
                    signer: pre.disk.owner,
                    successor: pre.grant.successor,
                });
            }
        }
        assert(pinned_handoff(post));
    }
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn lose_completion_preserves(pre: State, post: State)
    requires
        inv(pre),
        lose_completion(pre, post, false),
    ensures
        inv(post),
{
    assert(post.needs_reopen);
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn confirm_preserves(pre: State, post: State)
    requires
        inv(pre),
        confirm(pre, post),
    ensures
        inv(post),
{
    // cached' = disk; if ever_fault held at pre then disk.fault # 0, which
    // carries into both halves of persistent_quarantine.
    if post.ever_fault {
        assert(pre.ever_fault);
        assert(pre.disk.fault != 0);
        assert(post.disk.fault != 0);
        assert(post.cached.fault != 0);
    }
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

proof fn reopen_preserves(pre: State, post: State)
    requires
        inv(pre),
        reopen(pre, post, false),
    ensures
        inv(post),
{
    // cached' = disk under ClearQuarantine = FALSE; same reasoning as
    // confirm for the quarantine conjuncts.
    assert(post.cached.fault == pre.disk.fault);
    if post.ever_fault {
        assert(pre.ever_fault);
        assert(pre.disk.fault != 0);
        assert(post.disk.fault != 0);
        assert(post.cached.fault != 0);
    }
    assert(post.reopens <= reopen_budget());
    assert(type_ok(post));
    assert(historical_signers(post));
    assert(historical_authority(post));
    assert(pinned_handoff(post));
    assert(observation_only(post));
    assert(known_history_fault(post));
    assert(uncertain_custody(post));
    assert(persistent_quarantine(post));
    assert(aux_changes_floor(post));
    assert(aux_kind_needs_reopen(post));
    assert(aux_kind_pending(post));
    assert(aux_everfault_disk(post));
    assert(aux_handoff_grant(post));
    assert(aux_grant_shape(post));
    assert(aux_publishing_kind(post));
}

/// The safe next relation shared by normal.cfg and late-join.cfg — the
/// only difference is the LateJoin constant, which enters Next through
/// Observe's checkpoint base.
proof fn step_inv_cfg(lj: bool, pre: State, post: State)
    requires
        inv(pre),
        next_cfg(lj, false, false, false, false, false, false, pre, post),
    ensures
        inv(post),
{
    if prepare_grant(pre, post) {
        prepare_grant_preserves(pre, post);
    } else if advance_control(pre, post) {
        advance_control_preserves(pre, post);
    } else if begin_handoff(pre, post, false) {
        begin_handoff_preserves(pre, post);
    } else if refuse_before(pre, post, false) {
        refuse_before_preserves(pre, post);
    } else if publish(pre, post) {
        publish_preserves(pre, post);
    } else if lose_completion(pre, post, false) {
        lose_completion_preserves(pre, post);
    } else if confirm(pre, post) {
        confirm_preserves(pre, post);
    } else if reopen(pre, post, false) {
        reopen_preserves(pre, post);
    } else {
        let (seq, signer, variant) = choose|seq: int, signer: int, variant: int|
            1 <= seq <= max_controls() + 1 && is_signer(signer) && is_variant(variant)
                && observe(pre, post, lj, false, false, false, seq, signer, variant);
        observe_preserves(pre, post, lj, seq, signer, variant);
    }
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    step_inv_cfg(false, pre, post);
}

proof fn step_inv_late_join(pre: State, post: State)
    requires
        inv(pre),
        next_late_join(pre, post),
    ensures
        inv(post),
{
    step_inv_cfg(true, pre, post);
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

/// Every finite execution of the late-join.cfg model.
pub open spec fn is_late_join_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init_late_join(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_late_join(t[i], t[i + 1])
}

pub open spec fn is_current_owner_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_current_owner(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_stale_grant_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_stale_grant(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_future_observation_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_future_observation(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_precheckpoint_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init_late_join(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_precheckpoint(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_uncertainty_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_uncertainty(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_clear_quarantine_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_clear_quarantine(
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
        assert(init_cfg(false, t[0]));
        init_inv(false, t[0]);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            assert(i == 0);
        }
    }
}

proof fn late_join_trace_satisfies_inv(t: Seq<State>)
    requires
        is_late_join_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(t[i]),
    decreases t.len(),
{
    if t.len() > 1 {
        let prefix = t.drop_last();
        assert(is_late_join_trace(prefix)) by {
            assert forall|i: int| 0 <= i < prefix.len() - 1 implies #[trigger] next_late_join(
                prefix[i],
                prefix[i + 1],
            ) by {
                assert(prefix[i] == t[i]);
                assert(prefix[i + 1] == t[i + 1]);
                assert(next_late_join(t[i], t[i + 1]));
            }
        }
        late_join_trace_satisfies_inv(prefix);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            if i == t.len() - 1 {
                let k = i - 1;
                assert(prefix[k] == t[k]);
                assert(inv(prefix[k]));
                assert(next_late_join(t[k], t[k + 1]));
                assert(t[k + 1] == t[i]);
                step_inv_late_join(t[k], t[i]);
            } else {
                assert(prefix[i] == t[i]);
                assert(inv(prefix[i]));
            }
        }
    } else {
        assert(init_cfg(true, t[0]));
        init_inv(true, t[0]);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            assert(i == 0);
        }
    }
}

/// Constructing states concisely for the witness proofs.
pub open spec fn st(
    disk: Disk,
    cached: Disk,
    pc: int,
    needs_reopen: bool,
    uncertain: bool,
    kind: int,
    pending_fork: int,
    ever_fault: bool,
    grant: Grant,
    used_grants: Set<UsedGrant>,
    observation: Observation,
    reopens: int,
) -> State {
    State {
        disk,
        cached,
        pc,
        needs_reopen,
        uncertain,
        kind,
        pending_fork,
        ever_fault,
        grant,
        used_grants,
        observation,
        reopens,
    }
}

/// mutant-current-owner: a confirmed A->B handoff moves ownership to B at
/// sequence 2; then Observe(1, "A", "exact") checks the current owner B
/// instead of the historical A and records a Policy refusal even though
/// signer = expectedOwner — HistoricalAuthority fails.
proof fn mutant_current_owner_violates()
    ensures
        exists|t: Seq<State>| is_current_owner_trace(t) && !historical_authority(t.last()),
{
    let e = Set::empty();
    let d0 = idisk(false);
    let o0 = no_observation(false);
    let g1 = Grant { present: true, sequence: 2, predecessor: dev_a(), successor: dev_b() };
    let d1 = Disk {
        floor: 2,
        owner: dev_b(),
        signers: nmap().insert(1, dev_a()).insert(2, dev_a()),
        changes: nmap().insert(2, dev_b()),
        fault: 0,
    };
    let ug1 = UsedGrant {
        carried_at: 2,
        granted_at: 2,
        predecessor: dev_a(),
        signer: dev_a(),
        successor: dev_b(),
    };
    let o1 = Observation {
        present: true,
        sequence: 1,
        signer: dev_a(),
        expected_owner: dev_a(),
        variant: v_exact(),
        result: r_policy(),
        base: 0,
        before_floor: 2,
        after_floor: 2,
        before_owner: dev_b(),
        after_owner: dev_b(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, g1, e, o0, 0);
    let s2 = st(d0, d0, pc_publishing(), true, true, k_handoff(), 0, false, g1, e, o0, 0);
    let s3 = st(d1, d0, pc_readback(), true, true, k_handoff(), 0, false, g1, e.insert(ug1), o0, 0);
    let s4 = st(d1, d1, pc_idle(), false, false, k_none(), 0, false, g1, e.insert(ug1), o0, 0);
    let s5 = st(d1, d1, pc_idle(), false, false, k_none(), 0, false, g1, e.insert(ug1), o1, 0);
    assert(init(s0));
    assert(next_mutant_current_owner(s0, s1)) by { assert(prepare_grant(s0, s1)); }
    assert(next_mutant_current_owner(s1, s2)) by { assert(begin_handoff(s1, s2, false)); }
    assert(next_mutant_current_owner(s2, s3)) by { assert(publish(s2, s3)); }
    assert(next_mutant_current_owner(s3, s4)) by { assert(confirm(s3, s4)); }
    assert(next_mutant_current_owner(s4, s5)) by {
        assert(owner_at(s4.disk.changes, 1) == dev_a());
        assert(observe(s4, s5, false, true, false, false, 1, dev_a(), v_exact()));
    }
    assert(!historical_authority(s5));
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5);
    assert(is_current_owner_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_current_owner(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i
                + 1] == s5);
        }
    }
    assert(t.last() == s5);
    assert(is_current_owner_trace(t) && !historical_authority(t.last()));
}

/// mutant-stale-grant: a grant prepared for sequence 2 is carried at
/// sequence 3 after an intervening ordinary control (RebindGrant skips the
/// sequence check) — usedGrants records carriedAt = 3 # grantedAt = 2.
proof fn mutant_stale_grant_violates()
    ensures
        exists|t: Seq<State>| is_stale_grant_trace(t) && !pinned_handoff(t.last()),
{
    let e = Set::empty();
    let d0 = idisk(false);
    let o0 = no_observation(false);
    let g1 = Grant { present: true, sequence: 2, predecessor: dev_a(), successor: dev_b() };
    let d1 = Disk {
        floor: 2,
        owner: dev_a(),
        signers: nmap().insert(1, dev_a()).insert(2, dev_a()),
        changes: nmap(),
        fault: 0,
    };
    let d2 = Disk {
        floor: 3,
        owner: dev_b(),
        signers: nmap().insert(1, dev_a()).insert(2, dev_a()).insert(3, dev_a()),
        changes: nmap().insert(3, dev_b()),
        fault: 0,
    };
    let ug1 = UsedGrant {
        carried_at: 3,
        granted_at: 2,
        predecessor: dev_a(),
        signer: dev_a(),
        successor: dev_b(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, g1, e, o0, 0);
    let s2 = st(d1, d1, pc_idle(), false, false, k_none(), 0, false, g1, e, o0, 0);
    let s3 = st(d1, d1, pc_publishing(), true, true, k_handoff(), 0, false, g1, e, o0, 0);
    let s4 = st(d2, d1, pc_readback(), true, true, k_handoff(), 0, false, g1, e.insert(ug1), o0, 0);
    assert(init(s0));
    assert(next_mutant_stale_grant(s0, s1)) by { assert(prepare_grant(s0, s1)); }
    assert(next_mutant_stale_grant(s1, s2)) by { assert(advance_control(s1, s2)); }
    assert(next_mutant_stale_grant(s2, s3)) by { assert(begin_handoff(s2, s3, true)); }
    assert(next_mutant_stale_grant(s3, s4)) by { assert(publish(s3, s4)); }
    assert(!pinned_handoff(s4)) by {
        assert(s4.used_grants.contains(ug1));
        assert(ug1.carried_at != ug1.granted_at);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_stale_grant_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_stale_grant(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_stale_grant_trace(t) && !pinned_handoff(t.last()));
}

/// mutant-future-observation: AdmitObservation turns a future claim by the
/// expected owner into an accepted control — the floor advances from 1 to
/// 2 inside an observation, violating ObservationOnly.
proof fn mutant_future_observation_violates()
    ensures
        exists|t: Seq<State>| is_future_observation_trace(t) && !observation_only(t.last()),
{
    let e = Set::empty();
    let d0 = idisk(false);
    let o0 = no_observation(false);
    let d1 = Disk {
        floor: 2,
        owner: dev_a(),
        signers: nmap().insert(1, dev_a()).insert(2, dev_a()),
        changes: nmap(),
        fault: 0,
    };
    let o1 = Observation {
        present: true,
        sequence: 2,
        signer: dev_a(),
        expected_owner: dev_a(),
        variant: v_exact(),
        result: r_missing(),
        base: 0,
        before_floor: 1,
        after_floor: 2,
        before_owner: dev_a(),
        after_owner: dev_a(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d1, d1, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o1, 0);
    assert(init(s0));
    assert(next_mutant_future_observation(s0, s1)) by {
        assert(owner_at(s0.disk.changes, 2) == dev_a());
        assert(observe(s0, s1, false, false, true, false, 2, dev_a(), v_exact()));
    }
    assert(!observation_only(s1));
    let t = Seq::empty().push(s0).push(s1);
    assert(is_future_observation_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_future_observation(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0);
            assert(t[i + 1] == s1);
        }
    }
    assert(t.last() == s1);
    assert(is_future_observation_trace(t) && !observation_only(t.last()));
}

/// mutant-precheckpoint: under the late-join checkpoint (base = 2,
/// floor = 3, changes[2] = B), a conflicting claim at sequence 1 signed by
/// the correct historical owner A starts a Fork with FaultBeforeCheckpoint
/// — KnownHistoryFault fails because sequence 1 < base 2.
proof fn mutant_precheckpoint_violates()
    ensures
        exists|t: Seq<State>| is_precheckpoint_trace(t) && !known_history_fault(t.last()),
{
    let e = Set::empty();
    let d0 = idisk(true);
    let o0 = no_observation(true);
    let o1 = Observation {
        present: true,
        sequence: 1,
        signer: dev_a(),
        expected_owner: dev_a(),
        variant: v_conflict(),
        result: r_fork(),
        base: 2,
        before_floor: 3,
        after_floor: 3,
        before_owner: dev_b(),
        after_owner: dev_b(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d0, d0, pc_publishing(), true, true, k_fork(), 1, false, no_grant(), e, o1, 0);
    assert(init_late_join(s0));
    assert(next_mutant_precheckpoint(s0, s1)) by {
        assert(owner_at(s0.disk.changes, 1) == dev_a());
        assert(observe(s0, s1, true, false, false, true, 1, dev_a(), v_conflict()));
    }
    assert(!known_history_fault(s1)) by {
        assert(s1.observation.result == r_fork());
        assert(s1.observation.sequence < s1.observation.base);
    }
    let t = Seq::empty().push(s0).push(s1);
    assert(is_precheckpoint_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_precheckpoint(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0);
            assert(t[i + 1] == s1);
        }
    }
    assert(t.last() == s1);
    assert(is_precheckpoint_trace(t) && !known_history_fault(t.last()));
}

/// mutant-uncertainty: a fork observation raises the latch, then a refused
/// precommit write releases it with UnlatchUncertainty — the process sits
/// idle with uncertain = TRUE and needsReopen = FALSE.
proof fn mutant_uncertainty_violates()
    ensures
        exists|t: Seq<State>| is_uncertainty_trace(t) && !uncertain_custody(t.last()),
{
    let e = Set::empty();
    let d0 = idisk(false);
    let o0 = no_observation(false);
    let o1 = Observation {
        present: true,
        sequence: 1,
        signer: dev_a(),
        expected_owner: dev_a(),
        variant: v_conflict(),
        result: r_fork(),
        base: 0,
        before_floor: 1,
        after_floor: 1,
        before_owner: dev_a(),
        after_owner: dev_a(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d0, d0, pc_publishing(), true, true, k_fork(), 1, false, no_grant(), e, o1, 0);
    let s2 = st(d0, d0, pc_idle(), false, true, k_fork(), 1, false, no_grant(), e, o1, 0);
    assert(init(s0));
    assert(next_mutant_uncertainty(s0, s1)) by {
        assert(owner_at(s0.disk.changes, 1) == dev_a());
        assert(observe(s0, s1, false, false, false, false, 1, dev_a(), v_conflict()));
    }
    assert(next_mutant_uncertainty(s1, s2)) by { assert(refuse_before(s1, s2, true)); }
    assert(!uncertain_custody(s2));
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_uncertainty_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_uncertainty(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_uncertainty_trace(t) && !uncertain_custody(t.last()));
}

/// mutant-clear-quarantine: a committed fork fault survives publication,
/// then ClearQuarantine reopens with the fault erased from the cached
/// image — everFault /\ ~needsReopen holds with cached.fault = 0.
proof fn mutant_clear_quarantine_violates()
    ensures
        exists|t: Seq<State>| is_clear_quarantine_trace(t) && !persistent_quarantine(t.last()),
{
    let e = Set::empty();
    let d0 = idisk(false);
    let o0 = no_observation(false);
    let d1 = Disk {
        floor: 1,
        owner: dev_a(),
        signers: nmap().insert(1, dev_a()),
        changes: nmap(),
        fault: 1,
    };
    let c1 = Disk {
        floor: 1,
        owner: dev_a(),
        signers: nmap().insert(1, dev_a()),
        changes: nmap(),
        fault: 0,
    };
    let o1 = Observation {
        present: true,
        sequence: 1,
        signer: dev_a(),
        expected_owner: dev_a(),
        variant: v_conflict(),
        result: r_fork(),
        base: 0,
        before_floor: 1,
        after_floor: 1,
        before_owner: dev_a(),
        after_owner: dev_a(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d0, d0, pc_publishing(), true, true, k_fork(), 1, false, no_grant(), e, o1, 0);
    let s2 = st(d1, d0, pc_readback(), true, true, k_fork(), 1, true, no_grant(), e, o1, 0);
    let s3 = st(d1, c1, pc_idle(), false, false, k_none(), 0, true, no_grant(), e, o1, 1);
    assert(init(s0));
    assert(next_mutant_clear_quarantine(s0, s1)) by {
        assert(owner_at(s0.disk.changes, 1) == dev_a());
        assert(observe(s0, s1, false, false, false, false, 1, dev_a(), v_conflict()));
    }
    assert(next_mutant_clear_quarantine(s1, s2)) by { assert(publish(s1, s2)); }
    assert(next_mutant_clear_quarantine(s2, s3)) by { assert(reopen(s2, s3, true)); }
    assert(!persistent_quarantine(s3));
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3);
    assert(is_clear_quarantine_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_clear_quarantine(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3);
        }
    }
    assert(t.last() == s3);
    assert(is_clear_quarantine_trace(t) && !persistent_quarantine(t.last()));
}

/// Completion witness for the normal model: PrepareGrant -> BeginHandoff
/// -> Publish -> Confirm carries an A->B handoff; a conflicting claim at
/// the accepted sequence 2 by its historical owner A quarantines the
/// custodian; the completion is lost and a process reopen still holds the
/// committed fault in both images.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>|
            is_trace(t) && t.last().ever_fault && !t.last().needs_reopen
                && t.last().disk.fault != 0 && t.last().cached.fault != 0 && t.last().disk.owner
                == dev_b(),
{
    let e = Set::empty();
    let d0 = idisk(false);
    let o0 = no_observation(false);
    let g1 = Grant { present: true, sequence: 2, predecessor: dev_a(), successor: dev_b() };
    let d1 = Disk {
        floor: 2,
        owner: dev_b(),
        signers: nmap().insert(1, dev_a()).insert(2, dev_a()),
        changes: nmap().insert(2, dev_b()),
        fault: 0,
    };
    let d2 = Disk {
        floor: 2,
        owner: dev_b(),
        signers: nmap().insert(1, dev_a()).insert(2, dev_a()),
        changes: nmap().insert(2, dev_b()),
        fault: 2,
    };
    let ug1 = UsedGrant {
        carried_at: 2,
        granted_at: 2,
        predecessor: dev_a(),
        signer: dev_a(),
        successor: dev_b(),
    };
    let ugset = e.insert(ug1);
    let o1 = Observation {
        present: true,
        sequence: 2,
        signer: dev_a(),
        expected_owner: dev_a(),
        variant: v_conflict(),
        result: r_fork(),
        base: 0,
        before_floor: 2,
        after_floor: 2,
        before_owner: dev_b(),
        after_owner: dev_b(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, g1, e, o0, 0);
    let s2 = st(d0, d0, pc_publishing(), true, true, k_handoff(), 0, false, g1, e, o0, 0);
    let s3 = st(d1, d0, pc_readback(), true, true, k_handoff(), 0, false, g1, ugset, o0, 0);
    let s4 = st(d1, d1, pc_idle(), false, false, k_none(), 0, false, g1, ugset, o0, 0);
    let s5 = st(d1, d1, pc_publishing(), true, true, k_fork(), 2, false, g1, ugset, o1, 0);
    let s6 = st(d2, d1, pc_readback(), true, true, k_fork(), 2, true, g1, ugset, o1, 0);
    let s7 = st(d2, d1, pc_idle(), true, true, k_fork(), 2, true, g1, ugset, o1, 0);
    let s8 = st(d2, d2, pc_idle(), false, false, k_none(), 0, true, g1, ugset, o1, 1);
    assert(init(s0));
    assert(next(s0, s1)) by { assert(prepare_grant(s0, s1)); }
    assert(next(s1, s2)) by { assert(begin_handoff(s1, s2, false)); }
    assert(next(s2, s3)) by { assert(publish(s2, s3)); }
    assert(next(s3, s4)) by { assert(confirm(s3, s4)); }
    assert(next(s4, s5)) by {
        assert(owner_at(s4.disk.changes, 2) == dev_a());
        assert(observe(s4, s5, false, false, false, false, 2, dev_a(), v_conflict()));
    }
    assert(next(s5, s6)) by { assert(publish(s5, s6)); }
    assert(next(s6, s7)) by { assert(lose_completion(s6, s7, false)); }
    assert(next(s7, s8)) by { assert(reopen(s7, s8, false)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
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
    assert(is_trace(t) && t.last().ever_fault && !t.last().needs_reopen && t.last().disk.fault
        != 0 && t.last().cached.fault != 0 && t.last().disk.owner == dev_b());
}

/// Late-join witness: over the retained checkpoint chain (floor = 3,
/// owner = B, changes[2] = B) a conflicting claim at the known sequence 3
/// signed by the correct historical owner B quarantines the custodian; a
/// lost completion and a reopen retain the committed fault.
proof fn late_join_witness()
    ensures
        exists|t: Seq<State>|
            is_late_join_trace(t) && t.last().ever_fault && !t.last().needs_reopen
                && t.last().disk.fault != 0 && t.last().cached.fault != 0 && t.last().disk.owner
                == dev_b(),
{
    let e = Set::empty();
    let d0 = idisk(true);
    let o0 = no_observation(true);
    let d1 = Disk {
        floor: 3,
        owner: dev_b(),
        signers: nmap().insert(1, dev_a()).insert(2, dev_a()).insert(3, dev_b()),
        changes: nmap().insert(2, dev_b()),
        fault: 3,
    };
    let o1 = Observation {
        present: true,
        sequence: 3,
        signer: dev_b(),
        expected_owner: dev_b(),
        variant: v_conflict(),
        result: r_fork(),
        base: 2,
        before_floor: 3,
        after_floor: 3,
        before_owner: dev_b(),
        after_owner: dev_b(),
    };
    let s0 = st(d0, d0, pc_idle(), false, false, k_none(), 0, false, no_grant(), e, o0, 0);
    let s1 = st(d0, d0, pc_publishing(), true, true, k_fork(), 3, false, no_grant(), e, o1, 0);
    let s2 = st(d1, d0, pc_readback(), true, true, k_fork(), 3, true, no_grant(), e, o1, 0);
    let s3 = st(d1, d0, pc_idle(), true, true, k_fork(), 3, true, no_grant(), e, o1, 0);
    let s4 = st(d1, d1, pc_idle(), false, false, k_none(), 0, true, no_grant(), e, o1, 1);
    assert(init_late_join(s0));
    assert(next_late_join(s0, s1)) by {
        assert(owner_at(s0.disk.changes, 3) == dev_b());
        assert(observe(s0, s1, true, false, false, false, 3, dev_b(), v_conflict()));
    }
    assert(next_late_join(s1, s2)) by { assert(publish(s1, s2)); }
    assert(next_late_join(s2, s3)) by { assert(lose_completion(s2, s3, false)); }
    assert(next_late_join(s3, s4)) by { assert(reopen(s3, s4, false)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_late_join_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_late_join(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_late_join_trace(t) && t.last().ever_fault && !t.last().needs_reopen
        && t.last().disk.fault != 0 && t.last().cached.fault != 0 && t.last().disk.owner
        == dev_b());
}

}
