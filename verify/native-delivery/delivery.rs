//! Verus pilot (5th model): inductive proof of NativeDelivery's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs`,
//! `verify/private-publication/publication.rs` and
//! `verify/host-recovery/recovery.rs`: `NativeDelivery.tla` under
//! `normal.cfg` (all seven mutant switches false, CrashBudget = 1) is
//! re-stated as a Verus transition system and the seven checked invariants
//! are proved inductive. Each of the six mutant configurations is proved
//! to reach a violation of the invariant TLC found for it —
//! `mutant-early-send` breaks `IntentBeforeTransport`, `mutant-retarget`
//! breaks `ExactRetryBinding`, `mutant-forget-uncertainty` breaks
//! `UncertaintyPreserved`, `mutant-reset-spend` and `mutant-charge-outage`
//! break `AttemptEvidenceConserved`, `mutant-unchecked-receipt` breaks
//! `CheckedRetention` — and a completion witness runs an outage-restored
//! attempt through an interruption and reopen to checked `Retained`. The
//! same invariant is also proved inductive over `uncertain-write.cfg`
//! (AllowWriteFailure = TRUE, CrashBudget = 2), matching its positive TLC
//! result.
//!
//! Encoding notes:
//!   * pc/state/outcome/binding/digest strings become int constants.
//!     `Bindings` is {0,1,2,3} with 0 = `Original`; the three foreign
//!     variants differ from it only in fields the model never reads beyond
//!     equality with `Original`, so `b = 0` is a lossless binding test.
//!   * The `saved` receipt record is the pair `(saved_digest,
//!     saved_position)`; `sends` is a `Set<SendRec>` of the send record
//!     `[serial, committed, binding, present, state, attempts]`.
//!   * BOOLEAN fields are bools; `unresolved \subseteq 1..s.intents` is a
//!     bounded `Set<int>`.
//!   * `\E b \in Bindings : Select(b)` and `\E o \in Outcomes, retained \in
//!     BOOLEAN : Transport(o, retained)` become one existential each.
//!   * CrashBudget is a parameter `cb` of the transition relation so one
//!     `next_cfg` covers `normal.cfg` (1) and `uncertain-write.cfg` (2);
//!     the proof is generic in `cb`.
//!
//! Verify with:
//!   verus --crate-type=lib verify/native-delivery/delivery.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// normal.cfg / uncertain-write.cfg constants.
pub open spec fn max_attempts() -> int {
    2
}

pub open spec fn outage_budget() -> int {
    2
}

/// MaxIntents == 2 * MaxAttempts + OutageBudget.
pub open spec fn max_intents() -> int {
    6
}

/// Phases == {"new","idle","intent","transport","outcome","needs-reopen",
/// "closed"} as 0..6.
pub open spec fn ph_new() -> int {
    0
}

pub open spec fn ph_idle() -> int {
    1
}

pub open spec fn ph_intent() -> int {
    2
}

pub open spec fn ph_transport() -> int {
    3
}

pub open spec fn ph_outcome() -> int {
    4
}

pub open spec fn ph_needs_reopen() -> int {
    5
}

pub open spec fn ph_closed() -> int {
    6
}

pub open spec fn is_phase(p: int) -> bool {
    0 <= p <= 6
}

/// States == {"Pending","Uncertain","Retained","Stopped"} as 0..3.
pub open spec fn st_pending() -> int {
    0
}

pub open spec fn st_uncertain() -> int {
    1
}

pub open spec fn st_retained() -> int {
    2
}

pub open spec fn st_stopped() -> int {
    3
}

pub open spec fn is_state(st: int) -> bool {
    0 <= st <= 3
}

/// Outcomes == {"receipt","outage","denied","capacity","permanent",
/// "wrong-digest","zero-position","large-position"} as 0..7.
pub open spec fn o_receipt() -> int {
    0
}

pub open spec fn o_outage() -> int {
    1
}

pub open spec fn o_denied() -> int {
    2
}

pub open spec fn o_capacity() -> int {
    3
}

pub open spec fn o_permanent() -> int {
    4
}

pub open spec fn o_wrong_digest() -> int {
    5
}

pub open spec fn o_zero_position() -> int {
    6
}

pub open spec fn o_large_position() -> int {
    7
}

pub open spec fn is_outcome(o: int) -> bool {
    0 <= o <= 7
}

/// bad == o \in {"wrong-digest","zero-position","large-position"}.
pub open spec fn is_bad_outcome(o: int) -> bool {
    o == o_wrong_digest() || o == o_zero_position() || o == o_large_position()
}

/// Bindings == {Original, bytes-variant, namespace-variant,
/// endpoint-variant} as 0..3; 0 is the original.
pub open spec fn b_orig() -> int {
    0
}

pub open spec fn is_binding(b: int) -> bool {
    0 <= b <= 3
}

/// Receipt digests {"none","exact","foreign"} as 0..2; "exact" is
/// Original.id.
pub open spec fn d_none() -> int {
    0
}

pub open spec fn d_exact() -> int {
    1
}

pub open spec fn d_foreign() -> int {
    2
}

/// Receipt(o).digest / .position.
pub open spec fn receipt_digest(o: int) -> int {
    if o == o_wrong_digest() {
        d_foreign()
    } else {
        d_exact()
    }
}

pub open spec fn receipt_position(o: int) -> int {
    if o == o_zero_position() {
        0
    } else if o == o_large_position() {
        3
    } else {
        1
    }
}

/// Valid(r) == r.digest = Original.id /\ r.position \in 1..2.
pub open spec fn valid_saved(s: State) -> bool {
    s.saved_digest == d_exact() && (s.saved_position == 1 || s.saved_position == 2)
}

/// The sends element [serial |-> s.current, committed |-> s.intents,
/// binding |-> s.selected, present |-> s.present, state |-> s.state,
/// attempts |-> s.attempts].
pub struct SendRec {
    pub serial: int,
    pub committed: int,
    pub binding: int,
    pub present: bool,
    pub state: int,
    pub attempts: int,
}

/// VARIABLE s: pc, present, state, attempts, spent, outages, resumes,
/// uncertain, due, intents, classified, unresolved, current,
/// priorAttempts, priorUncertain, selected, outcome, saved (as
/// saved_digest/saved_position), remote, sends, crashes, failedWrite.
pub struct State {
    pub pc: int,
    pub present: bool,
    pub state: int,
    pub attempts: int,
    pub spent: int,
    pub outages: int,
    pub resumes: int,
    pub uncertain: bool,
    pub due: bool,
    pub intents: int,
    pub classified: int,
    pub unresolved: Set<int>,
    pub current: int,
    pub prior_attempts: int,
    pub prior_uncertain: bool,
    pub selected: int,
    pub outcome: int,
    pub saved_digest: int,
    pub saved_position: int,
    pub remote: bool,
    pub sends: Set<SendRec>,
    pub crashes: int,
    pub failed_write: bool,
}

/// The Init record value.
pub open spec fn init_state() -> State {
    State {
        pc: ph_new(),
        present: false,
        state: st_pending(),
        attempts: 0,
        spent: 0,
        outages: 0,
        resumes: 0,
        uncertain: false,
        due: true,
        intents: 0,
        classified: 0,
        unresolved: Set::empty(),
        current: 0,
        prior_attempts: 0,
        prior_uncertain: false,
        selected: b_orig(),
        outcome: o_receipt(),
        saved_digest: d_none(),
        saved_position: 0,
        remote: false,
        sends: Set::empty(),
        crashes: 0,
        failed_write: false,
    }
}

pub open spec fn init(s: State) -> bool {
    s == init_state()
}

/// Enqueue == /\ s.pc = "new"
///            /\ s' = [s EXCEPT !.pc = "idle", !.present = TRUE]
pub open spec fn enqueue(pre: State, post: State) -> bool {
    &&& pre.pc == ph_new()
    &&& post == State { pc: ph_idle(), present: true, ..pre }
}

/// Due == /\ s.pc = "idle" /\ ~s.due /\ s' = [s EXCEPT !.due = TRUE]
pub open spec fn due(pre: State, post: State) -> bool {
    &&& pre.pc == ph_idle()
    &&& !pre.due
    &&& post == State { due: true, ..pre }
}

/// Select(binding) == /\ s.pc = "idle" /\ s.state \in {"Pending","Uncertain"}
///                    /\ s.due /\ s.attempts < MaxAttempts
///                    /\ s.intents < MaxIntents
///                    /\ binding = Original \/ Retarget
///                    /\ s' = [s EXCEPT !.pc = "intent", !.selected = binding,
///                         !.current = s.intents + 1,
///                         !.priorAttempts = s.attempts,
///                         !.priorUncertain = s.uncertain]
/// b \in Bindings is supplied by the existential in Next.
pub open spec fn select(pre: State, post: State, rt: bool, b: int) -> bool {
    &&& pre.pc == ph_idle()
    &&& (pre.state == st_pending() || pre.state == st_uncertain())
    &&& pre.due
    &&& pre.attempts < max_attempts()
    &&& pre.intents < max_intents()
    &&& (b == b_orig() || rt)
    &&& post == State {
        pc: ph_intent(),
        selected: b,
        current: pre.intents + 1,
        prior_attempts: pre.attempts,
        prior_uncertain: pre.uncertain,
        ..pre
    }
}

/// IntentCommit == /\ s.pc = "intent"
///                 /\ s' = [s EXCEPT !.pc = "transport", !.intents = @ + 1,
///                      !.attempts = @ + 1, !.state = "Uncertain",
///                      !.uncertain = TRUE,
///                      !.unresolved = @ \cup {s.current}, !.due = FALSE]
pub open spec fn intent_commit(pre: State, post: State) -> bool {
    &&& pre.pc == ph_intent()
    &&& post == State {
        pc: ph_transport(),
        intents: pre.intents + 1,
        attempts: pre.attempts + 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: pre.unresolved.insert(pre.current),
        due: false,
        ..pre
    }
}

/// Transport(o, retained) ==
///     /\ s.pc = "transport" \/ (EarlySend /\ s.pc = "intent")
///     /\ o # "outage" \/ s.classified < OutageBudget
///     /\ retained => o \in {"receipt", "outage"}
///     /\ o = "receipt" => retained
///     /\ s' = [s EXCEPT !.pc = "outcome", !.outcome = o,
///          !.remote = @ \/ retained, !.sends = @ \cup {...}]
/// o \in Outcomes is supplied by the existential in Next.
pub open spec fn transport(pre: State, post: State, es: bool, o: int, retained: bool) -> bool {
    &&& (pre.pc == ph_transport() || (es && pre.pc == ph_intent()))
    &&& (o != o_outage() || pre.classified < outage_budget())
    &&& retained ==> (o == o_receipt() || o == o_outage())
    &&& (o == o_receipt()) ==> retained
    &&& post == State {
        pc: ph_outcome(),
        outcome: o,
        remote: pre.remote || retained,
        sends: pre.sends.insert(SendRec {
            serial: pre.current,
            committed: pre.intents,
            binding: pre.selected,
            present: pre.present,
            state: pre.state,
            attempts: pre.attempts,
        }),
        ..pre
    }
}

/// OutcomeCommit == /\ s.pc = "outcome" /\ LET outage/accepted/bad/
/// permanent/uncertain/unresolved IN s' = [...]
pub open spec fn outcome_commit(pre: State, post: State, fu: bool, ir: bool, co: bool) -> bool {
    let outage = pre.outcome == o_outage();
    let bad = is_bad_outcome(pre.outcome);
    let accepted = pre.outcome == o_receipt() || (ir && bad);
    let permanent = pre.outcome == o_permanent() || bad;
    let unc = if accepted {
        false
    } else if bad || outage {
        true
    } else if fu {
        false
    } else {
        pre.prior_uncertain
    };
    let unres = if accepted {
        Set::<int>::empty()
    } else if outage || bad {
        pre.unresolved
    } else {
        pre.unresolved.remove(pre.current)
    };
    let state_v = if accepted {
        st_retained()
    } else if permanent || (!outage && pre.attempts >= max_attempts()) {
        st_stopped()
    } else if unc {
        st_uncertain()
    } else {
        st_pending()
    };
    &&& pre.pc == ph_outcome()
    &&& post == State {
        pc: ph_idle(),
        state: state_v,
        attempts: if outage && !co {
            pre.prior_attempts
        } else {
            pre.attempts
        },
        uncertain: unc,
        unresolved: unres,
        outages: if outage {
            pre.outages + 1
        } else {
            pre.outages
        },
        classified: if outage {
            pre.classified + 1
        } else {
            pre.classified
        },
        saved_digest: if accepted {
            receipt_digest(pre.outcome)
        } else {
            pre.saved_digest
        },
        saved_position: if accepted {
            receipt_position(pre.outcome)
        } else {
            pre.saved_position
        },
        ..pre
    }
}

/// Exhausted == /\ s.pc = "idle" /\ s.state \in {"Pending","Uncertain"}
///              /\ s.attempts >= MaxAttempts
///              /\ s' = [s EXCEPT !.state = "Stopped"]
pub open spec fn exhausted(pre: State, post: State) -> bool {
    &&& pre.pc == ph_idle()
    &&& (pre.state == st_pending() || pre.state == st_uncertain())
    &&& pre.attempts >= max_attempts()
    &&& post == State { state: st_stopped(), ..pre }
}

/// Resume == /\ s.pc = "idle" /\ s.state = "Stopped" /\ s.resumes = 0
///           /\ s' = [s EXCEPT !.state = IF s.uncertain THEN "Uncertain"
///                ELSE "Pending",
///                !.spent = IF ResetSpent THEN @ ELSE @ + s.attempts,
///                !.attempts = 0, !.resumes = 1, !.due = TRUE]
pub open spec fn resume(pre: State, post: State, rs: bool) -> bool {
    &&& pre.pc == ph_idle()
    &&& pre.state == st_stopped()
    &&& pre.resumes == 0
    &&& post == State {
        state: if pre.uncertain {
            st_uncertain()
        } else {
            st_pending()
        },
        spent: if rs {
            pre.spent
        } else {
            pre.spent + pre.attempts
        },
        attempts: 0,
        resumes: 1,
        due: true,
        ..pre
    }
}

/// OutcomePrecommitRefusal == /\ AllowWriteFailure /\ s.pc = "outcome"
///                            /\ ~s.failedWrite
///                            /\ s' = [s EXCEPT !.pc = "needs-reopen",
///                                 !.failedWrite = TRUE]
pub open spec fn outcome_precommit_refusal(pre: State, post: State, awf: bool) -> bool {
    &&& awf
    &&& pre.pc == ph_outcome()
    &&& !pre.failed_write
    &&& post == State { pc: ph_needs_reopen(), failed_write: true, ..pre }
}

/// Crash == /\ s.pc \notin {"closed","needs-reopen"}
///          /\ s.crashes < CrashBudget
///          /\ s' = [s EXCEPT !.pc = "closed", !.crashes = @ + 1]
/// cb is the config's CrashBudget.
pub open spec fn crash(pre: State, post: State, cb: int) -> bool {
    &&& pre.pc != ph_closed() && pre.pc != ph_needs_reopen()
    &&& pre.crashes < cb
    &&& post == State { pc: ph_closed(), crashes: pre.crashes + 1, ..pre }
}

/// Reopen == /\ s.pc \in {"closed","needs-reopen"}
///           /\ s' = [s EXCEPT !.pc = IF s.present THEN "idle" ELSE "new"]
pub open spec fn reopen(pre: State, post: State) -> bool {
    &&& (pre.pc == ph_closed() || pre.pc == ph_needs_reopen())
    &&& post == State {
        pc: if pre.present {
            ph_idle()
        } else {
            ph_new()
        },
        ..pre
    }
}

/// Next under arbitrary config constants: AllowWriteFailure, EarlySend,
/// Retarget, ForgetUncertainty, ResetSpent, IgnoreReceipt, ChargeOutage
/// and the CrashBudget bound cb.
pub open spec fn next_cfg(
    awf: bool,
    es: bool,
    rt: bool,
    fu: bool,
    rs: bool,
    ir: bool,
    co: bool,
    cb: int,
    pre: State,
    post: State
) -> bool {
    ||| enqueue(pre, post)
    ||| due(pre, post)
    ||| intent_commit(pre, post)
    ||| outcome_commit(pre, post, fu, ir, co)
    ||| exhausted(pre, post)
    ||| resume(pre, post, rs)
    ||| outcome_precommit_refusal(pre, post, awf)
    ||| crash(pre, post, cb)
    ||| reopen(pre, post)
    ||| exists|b: int| is_binding(b) && #[trigger] select(pre, post, rt, b)
    ||| exists|o: int, retained: bool|
        is_outcome(o) && #[trigger] transport(pre, post, es, o, retained)
}

/// normal.cfg: every mutant switch false, CrashBudget = 1.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, false, false, 1, pre, post)
}

/// uncertain-write.cfg: AllowWriteFailure = TRUE, CrashBudget = 2 (a
/// positive configuration).
pub open spec fn next_uncertain(pre: State, post: State) -> bool {
    next_cfg(true, false, false, false, false, false, false, 2, pre, post)
}

/// mutant-early-send.cfg: EarlySend = TRUE.
pub open spec fn next_mutant_early_send(pre: State, post: State) -> bool {
    next_cfg(false, true, false, false, false, false, false, 1, pre, post)
}

/// mutant-retarget.cfg: Retarget = TRUE.
pub open spec fn next_mutant_retarget(pre: State, post: State) -> bool {
    next_cfg(false, false, true, false, false, false, false, 1, pre, post)
}

/// mutant-forget-uncertainty.cfg: ForgetUncertainty = TRUE.
pub open spec fn next_mutant_forget(pre: State, post: State) -> bool {
    next_cfg(false, false, false, true, false, false, false, 1, pre, post)
}

/// mutant-reset-spend.cfg: ResetSpent = TRUE.
pub open spec fn next_mutant_reset_spend(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, true, false, false, 1, pre, post)
}

/// mutant-unchecked-receipt.cfg: IgnoreReceipt = TRUE.
pub open spec fn next_mutant_unchecked(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, true, false, 1, pre, post)
}

/// mutant-charge-outage.cfg: ChargeOutage = TRUE.
pub open spec fn next_mutant_charge_outage(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, false, true, 1, pre, post)
}

/// TypeOK. BOOLEAN fields are bool-typed; sends and saved carry no TLA
/// TypeOK constraint, matching the source model.
pub open spec fn type_ok(s: State, cb: int) -> bool {
    &&& is_phase(s.pc)
    &&& is_state(s.state)
    &&& 0 <= s.attempts <= max_attempts()
    &&& 0 <= s.spent <= max_attempts()
    &&& 0 <= s.outages <= outage_budget()
    &&& 0 <= s.classified <= outage_budget()
    &&& 0 <= s.intents <= max_intents()
    &&& 0 <= s.current <= max_intents()
    &&& 0 <= s.resumes <= 1
    &&& 0 <= s.crashes <= cb
    &&& is_binding(s.selected)
    &&& is_outcome(s.outcome)
    &&& forall|i: int| s.unresolved.contains(i) ==> 1 <= i <= s.intents
}

/// IntentBeforeTransport == \A t \in s.sends : t.present /\ t.serial <=
/// t.committed /\ t.state = "Uncertain" /\ t.attempts > 0
pub open spec fn intent_before_transport(s: State) -> bool {
    forall|t: SendRec| s.sends.contains(t) ==> (t.present && t.serial <= t.committed
        && t.state == st_uncertain() && t.attempts > 0)
}

/// ExactRetryBinding == \A t \in s.sends : t.binding = Original
pub open spec fn exact_retry_binding(s: State) -> bool {
    forall|t: SendRec| s.sends.contains(t) ==> t.binding == b_orig()
}

/// UncertaintyPreserved == /\ s.unresolved # {} => s.uncertain
///                         /\ s.remote /\ s.state # "Retained" => s.uncertain
pub open spec fn uncertainty_preserved(s: State) -> bool {
    &&& (!(s.unresolved =~= Set::empty())) ==> s.uncertain
    &&& (s.remote && s.state != st_retained()) ==> s.uncertain
}

/// AttemptEvidenceConserved == s.attempts + s.spent + s.classified = s.intents
pub open spec fn attempt_evidence_conserved(s: State) -> bool {
    s.attempts + s.spent + s.classified == s.intents
}

/// OutageEvidence == s.outages = s.classified
pub open spec fn outage_evidence(s: State) -> bool {
    s.outages == s.classified
}

/// CheckedRetention == s.state = "Retained" => Valid(s.saved) /\ s.remote
pub open spec fn checked_retention(s: State) -> bool {
    s.state == st_retained() ==> (valid_saved(s) && s.remote)
}

/// Auxiliary: the job is present in every working phase — Enqueue sets it,
/// Reopen only returns to idle when it holds, and nothing clears it.
/// This is what makes every recorded send present.
pub open spec fn aux_present(s: State) -> bool {
    (s.pc == ph_idle() || s.pc == ph_intent() || s.pc == ph_transport() || s.pc
        == ph_outcome()) ==> s.present
}

/// Auxiliary: inside the intent phase the select snapshot is intact —
/// current is the next intent serial, attempts still equals its snapshot,
/// and both budgets still have headroom (the Select guard).
pub open spec fn aux_intent(s: State) -> bool {
    s.pc == ph_intent() ==> (s.current == s.intents + 1 && s.attempts
        == s.prior_attempts && s.intents < max_intents() && s.attempts < max_attempts()
        && s.selected == b_orig())
}

/// Auxiliary: in transport/outcome the current serial equals the committed
/// intents count — IntentCommit made them equal and nothing between them
/// touches either.
pub open spec fn aux_current_intents(s: State) -> bool {
    (s.pc == ph_transport() || s.pc == ph_outcome()) ==> s.current == s.intents
}

/// Auxiliary: in transport/outcome attempts is exactly one above the
/// select-time snapshot, so an uncharged outage restores exactly the one
/// attempt this intent spent.
pub open spec fn aux_attempts_prior(s: State) -> bool {
    (s.pc == ph_transport() || s.pc == ph_outcome()) ==> s.attempts
        == s.prior_attempts + 1
}

/// Auxiliary: transport/outcome always run on an Uncertain job — the
/// recorded send state is the IntentCommit publication.
pub open spec fn aux_state_uncertain(s: State) -> bool {
    (s.pc == ph_transport() || s.pc == ph_outcome()) ==> s.state == st_uncertain()
}

/// Auxiliary: the uncertainty flag is set throughout transport/outcome —
/// IntentCommit published it and nothing else clears it there.
pub open spec fn aux_uncertain_flag(s: State) -> bool {
    (s.pc == ph_transport() || s.pc == ph_outcome()) ==> s.uncertain
}

/// Auxiliary: inside an intent lifecycle the selected binding is the
/// original — Select's safe guard admits only Original.
pub open spec fn aux_selected(s: State) -> bool {
    (s.pc == ph_intent() || s.pc == ph_transport() || s.pc == ph_outcome())
        ==> s.selected == b_orig()
}

/// Auxiliary: unresolved serials older than the current intent imply prior
/// uncertainty — they are the unresolved set the selecting Select already
/// had, which UncertaintyPreserved made uncertain then.
pub open spec fn aux_unres_prior(s: State) -> bool {
    ((s.pc == ph_intent() || s.pc == ph_transport() || s.pc == ph_outcome())
        && !(s.unresolved.remove(s.current) =~= Set::empty())) ==> s.prior_uncertain
}

/// Auxiliary: remote retention observed before this outcome commit implies
/// prior uncertainty — remote was already true at Select, which captured
/// the UncertaintyPreserved flag. A receipt/outage outcome itself may have
/// just set remote, so the obligation is lifted for those outcomes.
pub open spec fn aux_remote_prior(s: State) -> bool {
    (s.remote && (s.pc == ph_intent() || s.pc == ph_transport() || (s.pc
        == ph_outcome() && s.outcome != o_receipt() && s.outcome != o_outage())))
        ==> s.prior_uncertain
}

/// Auxiliary: a receipt outcome being committed was observed retained —
/// the Transport guard forced retained for receipt outcomes.
pub open spec fn aux_receipt_remote(s: State) -> bool {
    (s.pc == ph_outcome() && s.outcome == o_receipt()) ==> s.remote
}

/// Auxiliary: an outage outcome being committed was admitted under the
/// outage budget — the Transport guard checked classified < OutageBudget.
pub open spec fn aux_outage_budget(s: State) -> bool {
    (s.pc == ph_outcome() && s.outcome == o_outage()) ==> s.classified
        < outage_budget()
}

/// Auxiliary: the select-time attempt snapshot stays within the attempt
/// bound so an outage restore lands inside TypeOK.
pub open spec fn aux_prior_bounds(s: State) -> bool {
    0 <= s.prior_attempts <= max_attempts()
}

/// Auxiliary: before any resume nothing has been spent — Resume is the only
/// action that raises spent and it sets resumes to 1 atomically. This keeps
/// spent + attempts <= MaxAttempts at the single allowed Resume.
pub open spec fn aux_spent_resumes(s: State) -> bool {
    s.resumes == 0 ==> s.spent == 0
}

/// The inductive invariant: TypeOK plus the seven checked safety
/// invariants, strengthened by the ten auxiliaries.
pub open spec fn inv(s: State, cb: int) -> bool {
    &&& type_ok(s, cb)
    &&& intent_before_transport(s)
    &&& exact_retry_binding(s)
    &&& uncertainty_preserved(s)
    &&& attempt_evidence_conserved(s)
    &&& outage_evidence(s)
    &&& checked_retention(s)
    &&& aux_present(s)
    &&& aux_intent(s)
    &&& aux_current_intents(s)
    &&& aux_attempts_prior(s)
    &&& aux_state_uncertain(s)
    &&& aux_uncertain_flag(s)
    &&& aux_selected(s)
    &&& aux_unres_prior(s)
    &&& aux_remote_prior(s)
    &&& aux_receipt_remote(s)
    &&& aux_outage_budget(s)
    &&& aux_prior_bounds(s)
    &&& aux_spent_resumes(s)
}

proof fn init_inv(s: State, cb: int)
    requires
        init(s),
        0 <= cb,
    ensures
        inv(s, cb),
{
}

proof fn enqueue_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        enqueue(pre, post),
    ensures
        inv(post, cb),
{
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn due_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        due(pre, post),
    ensures
        inv(post, cb),
{
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn select_preserves(pre: State, post: State, b: int, cb: int)
    requires
        inv(pre, cb),
        is_binding(b),
        select(pre, post, false, b),
    ensures
        inv(post, cb),
{
    // aux_intent(post): the Select guard supplies intents < MaxIntents and
    // attempts < MaxAttempts; the updates give current = intents + 1,
    // attempts = prior_attempts and selected = b = Original.
    // aux_unres_prior(post): current' = intents + 1 is above every
    // unresolved member, so unresolved \ {current'} = unresolved; when
    // nonempty, UncertaintyPreserved(pre) made uncertain, which is exactly
    // prior_uncertain'.
    assert(!pre.unresolved.contains(post.current)) by {
        if pre.unresolved.contains(post.current) {
            assert(1 <= post.current && post.current <= pre.intents);
        }
    }
    assert(b == b_orig());
    assert(post.unresolved.remove(post.current) =~= post.unresolved);
    assert(aux_unres_prior(post)) by {
        if !(post.unresolved.remove(post.current) =~= Set::empty()) {
            assert(!(pre.unresolved =~= Set::empty()));
            assert(pre.uncertain);
        }
    }
    // aux_remote_prior(post): remote was already true at idle with state
    // Pending/Uncertain, so UncertaintyPreserved(pre) forces uncertain,
    // i.e. prior_uncertain'.
    assert(aux_remote_prior(post)) by {
        if post.remote {
            assert(pre.remote);
            assert(pre.uncertain);
        }
    }
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn intent_commit_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        intent_commit(pre, post),
    ensures
        inv(post, cb),
{
    // From aux_intent(pre): current = intents + 1, attempts =
    // prior_attempts, attempts < MaxAttempts, intents < MaxIntents.
    assert(pre.current == pre.intents + 1);
    assert(pre.attempts == pre.prior_attempts);
    assert(pre.selected == b_orig());
    // current is fresh to unresolved.
    assert(!pre.unresolved.contains(pre.current)) by {
        if pre.unresolved.contains(pre.current) {
            assert(pre.current <= pre.intents);
        }
    }
    // unresolved' = unresolved + current; its bound uses current = intents'.
    assert(post.current == post.intents);
    assert forall|i: int| post.unresolved.contains(i) implies 1 <= i <= post.intents by {
        if i == pre.current {
        } else {
            assert(pre.unresolved.contains(i));
            assert(1 <= i && i <= pre.intents);
        }
    }
    // aux_unres_prior(post): removing current from unresolved+{current}
    // leaves the pre set unchanged.
    assert(post.unresolved.remove(post.current) =~= pre.unresolved);
    assert(aux_unres_prior(post)) by {
        if !(post.unresolved.remove(post.current) =~= Set::empty()) {
            assert(!(pre.unresolved.remove(pre.current) =~= Set::empty()));
            assert(pre.prior_uncertain);
        }
    }
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn transport_preserves(pre: State, post: State, o: int, retained: bool, cb: int)
    requires
        inv(pre, cb),
        is_outcome(o),
        transport(pre, post, false, o, retained),
    ensures
        inv(post, cb),
{
    // With EarlySend = false the only enabled Transport runs at transport.
    assert(pre.pc == ph_transport());
    assert(pre.selected == b_orig());
    // From the pre-phase auxiliaries: current == intents, attempts =
    // prior_attempts + 1 > 0, state = Uncertain, uncertain, selected =
    // Original, present.
    let rec = SendRec {
        serial: pre.current,
        committed: pre.intents,
        binding: pre.selected,
        present: pre.present,
        state: pre.state,
        attempts: pre.attempts,
    };
    assert forall|t: SendRec| post.sends.contains(t) implies (t.present && t.serial
        <= t.committed && t.state == st_uncertain() && t.attempts > 0) by {
        if pre.sends.contains(t) {
        } else {
            assert(t == rec);
        }
    }
    assert forall|t: SendRec| post.sends.contains(t) implies t.binding == b_orig() by {
        if pre.sends.contains(t) {
        } else {
            assert(t == rec);
        }
    }
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(type_ok(post, cb));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post)) by {
        if post.remote && post.outcome != o_receipt() && post.outcome != o_outage() {
            // retained = false here, so remote was already true at transport.
            assert(!retained);
            assert(pre.remote);
            assert(pre.prior_uncertain);
        }
    }
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn outcome_commit_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        outcome_commit(pre, post, false, false, false),
    ensures
        inv(post, cb),
{
    let outage = pre.outcome == o_outage();
    let bad = is_bad_outcome(pre.outcome);
    let accepted = pre.outcome == o_receipt();
    // Under the safe flags, attempts' = prior_attempts on outage and
    // attempts otherwise; classified'/outages' bump only on outage.
    assert(pre.uncertain);
    assert(pre.attempts == pre.prior_attempts + 1);
    // attempt_evidence_conserved(post): on outage the restored snapshot is
    // exactly one below attempts, matching the classified bump.
    assert(attempt_evidence_conserved(post));
    // type_ok bounds: outages'/classified' use the Transport-admitted
    // budget headroom.
    if outage {
        assert(pre.classified < outage_budget());
        assert(post.outages <= outage_budget());
    }
    assert forall|i: int| post.unresolved.contains(i) implies 1 <= i <= post.intents by {
        assert(pre.unresolved.contains(i));
        assert(1 <= i && i <= pre.intents);
    }
    assert(type_ok(post, cb));
    // UncertaintyPreserved(post): for non-accepted non-outage non-bad
    // outcomes the earlier-serial remainder implies prior_uncertain, and
    // remote implies prior_uncertain; outage/bad set uncertain' directly.
    assert(uncertainty_preserved(post)) by {
        if !(post.unresolved =~= Set::empty()) && !post.uncertain {
            // impossible: unresolved' nonempty is only the remove branch,
            // which needs unresolved \ {current} nonempty at pre.
            assert(post.unresolved =~= pre.unresolved.remove(pre.current));
            assert(!(pre.unresolved.remove(pre.current) =~= Set::empty()));
            assert(pre.prior_uncertain);
        }
        if post.remote && post.state != st_retained() && !post.uncertain {
            assert(pre.remote);
            assert(pre.outcome != o_receipt() && pre.outcome != o_outage());
            assert(pre.prior_uncertain);
        }
    }
    assert(checked_retention(post)) by {
        if post.state == st_retained() {
            assert(pre.outcome == o_receipt());
            assert(pre.remote);
            assert(post.remote);
            assert(post.saved_digest == d_exact() && post.saved_position == 1);
        }
    }
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(outage_evidence(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn exhausted_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        exhausted(pre, post),
    ensures
        inv(post, cb),
{
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn resume_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        resume(pre, post, false),
    ensures
        inv(post, cb),
{
    // spent' = spent + attempts with resumes = 0 forcing spent = 0, so
    // spent' = attempts <= MaxAttempts; conservation is the same sum.
    assert(pre.spent == 0);
    assert(post.spent == pre.attempts);
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post)) by {
        if post.remote && post.state != st_retained() {
            assert(pre.remote);
            assert(pre.uncertain);
        }
        if !(post.unresolved =~= Set::empty()) {
            assert(pre.uncertain);
        }
    }
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

/// Holds for either AllowWriteFailure flag: the refusal only poisons the
/// handle and moves to needs-reopen, leaving every tracked field intact.
proof fn outcome_precommit_refusal_preserves(pre: State, post: State, awf: bool, cb: int)
    requires
        inv(pre, cb),
        outcome_precommit_refusal(pre, post, awf),
    ensures
        inv(post, cb),
{
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

/// Holds for any crash budget: the interruption only moves pc to closed.
proof fn crash_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        crash(pre, post, cb),
    ensures
        inv(post, cb),
{
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn reopen_preserves(pre: State, post: State, cb: int)
    requires
        inv(pre, cb),
        reopen(pre, post),
    ensures
        inv(post, cb),
{
    // post.pc = idle only when present already held.
    assert(type_ok(post, cb));
    assert(intent_before_transport(post));
    assert(exact_retry_binding(post));
    assert(uncertainty_preserved(post));
    assert(attempt_evidence_conserved(post));
    assert(outage_evidence(post));
    assert(checked_retention(post));
    assert(aux_present(post));
    assert(aux_intent(post));
    assert(aux_current_intents(post));
    assert(aux_attempts_prior(post));
    assert(aux_state_uncertain(post));
    assert(aux_uncertain_flag(post));
    assert(aux_selected(post));
    assert(aux_unres_prior(post));
    assert(aux_remote_prior(post));
    assert(aux_receipt_remote(post));
    assert(aux_outage_budget(post));
    assert(aux_prior_bounds(post));
    assert(aux_spent_resumes(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre, 1),
        next(pre, post),
    ensures
        inv(post, 1),
{
    if enqueue(pre, post) {
        enqueue_preserves(pre, post, 1);
    } else if due(pre, post) {
        due_preserves(pre, post, 1);
    } else if intent_commit(pre, post) {
        intent_commit_preserves(pre, post, 1);
    } else if outcome_commit(pre, post, false, false, false) {
        outcome_commit_preserves(pre, post, 1);
    } else if exhausted(pre, post) {
        exhausted_preserves(pre, post, 1);
    } else if resume(pre, post, false) {
        resume_preserves(pre, post, 1);
    } else if outcome_precommit_refusal(pre, post, false) {
        outcome_precommit_refusal_preserves(pre, post, false, 1);
    } else if crash(pre, post, 1) {
        crash_preserves(pre, post, 1);
    } else if reopen(pre, post) {
        reopen_preserves(pre, post, 1);
    } else if exists|b: int| is_binding(b) && select(pre, post, false, b) {
        let b = choose|b: int| is_binding(b) && select(pre, post, false, b);
        select_preserves(pre, post, b, 1);
    } else if exists|o: int, retained: bool| is_outcome(o) && transport(
        pre,
        post,
        false,
        o,
        retained,
    ) {
        let p = choose|o: int, retained: bool| is_outcome(o) && transport(
            pre,
            post,
            false,
            o,
            retained,
        );
        transport_preserves(pre, post, p.0, p.1, 1);
    } else {
        assert(false);
    }
}

proof fn step_inv_uncertain(pre: State, post: State)
    requires
        inv(pre, 2),
        next_uncertain(pre, post),
    ensures
        inv(post, 2),
{
    if enqueue(pre, post) {
        enqueue_preserves(pre, post, 2);
    } else if due(pre, post) {
        due_preserves(pre, post, 2);
    } else if intent_commit(pre, post) {
        intent_commit_preserves(pre, post, 2);
    } else if outcome_commit(pre, post, false, false, false) {
        outcome_commit_preserves(pre, post, 2);
    } else if exhausted(pre, post) {
        exhausted_preserves(pre, post, 2);
    } else if resume(pre, post, false) {
        resume_preserves(pre, post, 2);
    } else if outcome_precommit_refusal(pre, post, true) {
        outcome_precommit_refusal_preserves(pre, post, true, 2);
    } else if crash(pre, post, 2) {
        crash_preserves(pre, post, 2);
    } else if reopen(pre, post) {
        reopen_preserves(pre, post, 2);
    } else if exists|b: int| is_binding(b) && select(pre, post, false, b) {
        let b = choose|b: int| is_binding(b) && select(pre, post, false, b);
        select_preserves(pre, post, b, 2);
    } else if exists|o: int, retained: bool| is_outcome(o) && transport(
        pre,
        post,
        false,
        o,
        retained,
    ) {
        let p = choose|o: int, retained: bool| is_outcome(o) && transport(
            pre,
            post,
            false,
            o,
            retained,
        );
        transport_preserves(pre, post, p.0, p.1, 2);
    } else {
        assert(false);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

/// Every finite execution of the uncertain-write.cfg model
/// (AllowWriteFailure, CrashBudget = 2).
pub open spec fn is_uncertain_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_uncertain(t[i], t[i + 1])
}

pub open spec fn is_mutant_es_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_early_send(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_mutant_rt_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_retarget(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_mutant_fu_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_forget(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_mutant_rs_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_reset_spend(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_mutant_ir_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_unchecked(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_mutant_co_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_charge_outage(
        t[i],
        t[i + 1]
    )
}

proof fn trace_satisfies_inv(t: Seq<State>)
    requires
        is_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(t[i], 1),
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
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i], 1) by {
            if i == t.len() - 1 {
                let k = i - 1;
                assert(prefix[k] == t[k]);
                assert(inv(prefix[k], 1));
                assert(next(t[k], t[k + 1]));
                assert(t[k + 1] == t[i]);
                step_inv(t[k], t[i]);
            } else {
                assert(prefix[i] == t[i]);
                assert(inv(prefix[i], 1));
            }
        }
    } else {
        init_inv(t[0], 1);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i], 1) by {
            assert(i == 0);
        }
    }
}

proof fn uncertain_trace_satisfies_inv(t: Seq<State>)
    requires
        is_uncertain_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(t[i], 2),
    decreases t.len(),
{
    if t.len() > 1 {
        let prefix = t.drop_last();
        assert(is_uncertain_trace(prefix)) by {
            assert forall|i: int| 0 <= i < prefix.len() - 1 implies #[trigger] next_uncertain(
                prefix[i],
                prefix[i + 1],
            ) by {
                assert(prefix[i] == t[i]);
                assert(prefix[i + 1] == t[i + 1]);
                assert(next_uncertain(t[i], t[i + 1]));
            }
        }
        uncertain_trace_satisfies_inv(prefix);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i], 2) by {
            if i == t.len() - 1 {
                let k = i - 1;
                assert(prefix[k] == t[k]);
                assert(inv(prefix[k], 2));
                assert(next_uncertain(t[k], t[k + 1]));
                assert(t[k + 1] == t[i]);
                step_inv_uncertain(t[k], t[i]);
            } else {
                assert(prefix[i] == t[i]);
                assert(inv(prefix[i], 2));
            }
        }
    } else {
        init_inv(t[0], 2);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i], 2) by {
            assert(i == 0);
        }
    }
}

/// mutant-early-send: init -> Enqueue -> Select(Original) -> Transport
/// under EarlySend ships intent serial 1 against 0 committed intents.
proof fn mutant_early_send_violates()
    ensures
        exists|t: Seq<State>| is_mutant_es_trace(t) && !intent_before_transport(t.last()),
{
    let ei = Set::<int>::empty();
    let es = Set::<SendRec>::empty();
    let s0 = init_state();
    let s1 = State { pc: ph_idle(), present: true, ..s0 };
    let s2 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 1,
        prior_attempts: 0,
        prior_uncertain: false,
        ..s1
    };
    let rec = SendRec {
        serial: 1,
        committed: 0,
        binding: b_orig(),
        present: true,
        state: st_pending(),
        attempts: 0,
    };
    let s3 = State {
        pc: ph_outcome(),
        outcome: o_outage(),
        remote: false,
        sends: es.insert(rec),
        ..s2
    };
    assert(init(s0));
    assert(next_mutant_early_send(s0, s1)) by { assert(enqueue(s0, s1)); }
    assert(next_mutant_early_send(s1, s2)) by {
        assert(is_binding(0) && select(s1, s2, false, 0));
    }
    assert(next_mutant_early_send(s2, s3)) by {
        assert(is_outcome(1) && transport(s2, s3, true, 1, false));
    }
    assert(!intent_before_transport(s3)) by {
        assert(s3.sends.contains(rec));
        assert(!(rec.present && rec.serial <= rec.committed && rec.state == st_uncertain()
            && rec.attempts > 0));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3);
    assert(is_mutant_es_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_early_send(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3);
        }
    }
    assert(t.last() == s3);
    assert(is_mutant_es_trace(t) && !intent_before_transport(t.last()));
}

/// mutant-retarget: init -> Enqueue -> Select(endpoint-variant) ->
/// IntentCommit -> Transport records a send bound to a foreign endpoint.
proof fn mutant_retarget_violates()
    ensures
        exists|t: Seq<State>| is_mutant_rt_trace(t) && !exact_retry_binding(t.last()),
{
    let ei = Set::<int>::empty();
    let es = Set::<SendRec>::empty();
    let s0 = init_state();
    let s1 = State { pc: ph_idle(), present: true, ..s0 };
    let s2 = State {
        pc: ph_intent(),
        selected: 3,
        current: 1,
        prior_attempts: 0,
        prior_uncertain: false,
        ..s1
    };
    let s3 = State {
        pc: ph_transport(),
        intents: 1,
        attempts: 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1),
        due: false,
        ..s2
    };
    let rec = SendRec {
        serial: 1,
        committed: 1,
        binding: 3,
        present: true,
        state: st_uncertain(),
        attempts: 1,
    };
    let s4 = State {
        pc: ph_outcome(),
        outcome: o_outage(),
        remote: false,
        sends: es.insert(rec),
        ..s3
    };
    assert(init(s0));
    assert(next_mutant_retarget(s0, s1)) by { assert(enqueue(s0, s1)); }
    assert(next_mutant_retarget(s1, s2)) by {
        assert(is_binding(3) && select(s1, s2, true, 3));
    }
    assert(next_mutant_retarget(s2, s3)) by { assert(intent_commit(s2, s3)); }
    assert(next_mutant_retarget(s3, s4)) by {
        assert(is_outcome(1) && transport(s3, s4, false, 1, false));
    }
    assert(!exact_retry_binding(s4)) by {
        assert(s4.sends.contains(rec));
        assert(rec.binding != b_orig());
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_mutant_rt_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_retarget(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_mutant_rt_trace(t) && !exact_retry_binding(t.last()));
}

/// mutant-forget-uncertainty: an interrupted first intent stays in
/// unresolved; a later permanent refusal with ForgetUncertainty clears the
/// flag while serial 1 remains unresolved.
proof fn mutant_forget_violates()
    ensures
        exists|t: Seq<State>| is_mutant_fu_trace(t) && !uncertainty_preserved(t.last()),
{
    let ei = Set::<int>::empty();
    let es = Set::<SendRec>::empty();
    let s0 = init_state();
    let s1 = State { pc: ph_idle(), present: true, ..s0 };
    let s2 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 1,
        prior_attempts: 0,
        prior_uncertain: false,
        ..s1
    };
    let s3 = State {
        pc: ph_transport(),
        intents: 1,
        attempts: 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1),
        due: false,
        ..s2
    };
    let s4 = State { pc: ph_closed(), crashes: 1, ..s3 };
    let s5 = State { pc: ph_idle(), ..s4 };
    let s6 = State { due: true, ..s5 };
    let s7 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 2,
        prior_attempts: 1,
        prior_uncertain: true,
        ..s6
    };
    let s8 = State {
        pc: ph_transport(),
        intents: 2,
        attempts: 2,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1).insert(2),
        due: false,
        ..s7
    };
    let rec = SendRec {
        serial: 2,
        committed: 2,
        binding: 0,
        present: true,
        state: st_uncertain(),
        attempts: 2,
    };
    let s9 = State {
        pc: ph_outcome(),
        outcome: o_permanent(),
        remote: false,
        sends: es.insert(rec),
        ..s8
    };
    let s10 = State {
        pc: ph_idle(),
        state: st_stopped(),
        attempts: 2,
        uncertain: false,
        unresolved: ei.insert(1),
        ..s9
    };
    assert(init(s0));
    assert(next_mutant_forget(s0, s1)) by { assert(enqueue(s0, s1)); }
    assert(next_mutant_forget(s1, s2)) by {
        assert(is_binding(0) && select(s1, s2, false, 0));
    }
    assert(next_mutant_forget(s2, s3)) by { assert(intent_commit(s2, s3)); }
    assert(next_mutant_forget(s3, s4)) by { assert(crash(s3, s4, 1)); }
    assert(next_mutant_forget(s4, s5)) by { assert(reopen(s4, s5)); }
    assert(next_mutant_forget(s5, s6)) by { assert(due(s5, s6)); }
    assert(next_mutant_forget(s6, s7)) by {
        assert(is_binding(0) && select(s6, s7, false, 0));
    }
    assert(next_mutant_forget(s7, s8)) by { assert(intent_commit(s7, s8)); }
    assert(next_mutant_forget(s8, s9)) by {
        assert(is_outcome(4) && transport(s8, s9, false, 4, false));
    }
    assert(s9.unresolved.remove(s9.current) =~= ei.insert(1));
    assert(next_mutant_forget(s9, s10)) by {
        assert(outcome_commit(s9, s10, true, false, false));
    }
    assert(!uncertainty_preserved(s10)) by {
        assert(s10.unresolved.contains(1));
        assert(!(s10.unresolved =~= Set::empty()));
        assert(!s10.uncertain);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8).push(s9).push(s10);
    assert(is_mutant_fu_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_forget(
            t[i],
            t[i + 1],
        ) by {
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
    assert(is_mutant_fu_trace(t) && !uncertainty_preserved(t.last()));
}

/// mutant-reset-spend: a permanent refusal stops the job and Resume with
/// ResetSpent drops the spent charge, so attempts + spent + classified <
/// intents.
proof fn mutant_reset_spend_violates()
    ensures
        exists|t: Seq<State>| is_mutant_rs_trace(t) && !attempt_evidence_conserved(t.last()),
{
    let ei = Set::<int>::empty();
    let es = Set::<SendRec>::empty();
    let s0 = init_state();
    let s1 = State { pc: ph_idle(), present: true, ..s0 };
    let s2 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 1,
        prior_attempts: 0,
        prior_uncertain: false,
        ..s1
    };
    let s3 = State {
        pc: ph_transport(),
        intents: 1,
        attempts: 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1),
        due: false,
        ..s2
    };
    let rec = SendRec {
        serial: 1,
        committed: 1,
        binding: 0,
        present: true,
        state: st_uncertain(),
        attempts: 1,
    };
    let s4 = State {
        pc: ph_outcome(),
        outcome: o_permanent(),
        remote: false,
        sends: es.insert(rec),
        ..s3
    };
    let s5 = State {
        pc: ph_idle(),
        state: st_stopped(),
        attempts: 1,
        uncertain: false,
        unresolved: ei,
        ..s4
    };
    let s6 = State {
        state: st_pending(),
        spent: 0,
        attempts: 0,
        resumes: 1,
        due: true,
        ..s5
    };
    assert(init(s0));
    assert(next_mutant_reset_spend(s0, s1)) by { assert(enqueue(s0, s1)); }
    assert(next_mutant_reset_spend(s1, s2)) by {
        assert(is_binding(0) && select(s1, s2, false, 0));
    }
    assert(next_mutant_reset_spend(s2, s3)) by { assert(intent_commit(s2, s3)); }
    assert(next_mutant_reset_spend(s3, s4)) by {
        assert(is_outcome(4) && transport(s3, s4, false, 4, false));
    }
    assert(s4.unresolved.remove(s4.current) =~= ei);
    assert(next_mutant_reset_spend(s4, s5)) by {
        assert(outcome_commit(s4, s5, false, false, false));
    }
    assert(next_mutant_reset_spend(s5, s6)) by { assert(resume(s5, s6, true)); }
    assert(!attempt_evidence_conserved(s6)) by {
        assert(s6.attempts + s6.spent + s6.classified == 0 && s6.intents == 1);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_mutant_rs_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_reset_spend(
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
    assert(is_mutant_rs_trace(t) && !attempt_evidence_conserved(t.last()));
}

/// mutant-unchecked-receipt: IgnoreReceipt treats a wrong-digest outcome
/// as accepted, publishing Retained over a foreign digest.
proof fn mutant_unchecked_violates()
    ensures
        exists|t: Seq<State>| is_mutant_ir_trace(t) && !checked_retention(t.last()),
{
    let ei = Set::<int>::empty();
    let es = Set::<SendRec>::empty();
    let s0 = init_state();
    let s1 = State { pc: ph_idle(), present: true, ..s0 };
    let s2 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 1,
        prior_attempts: 0,
        prior_uncertain: false,
        ..s1
    };
    let s3 = State {
        pc: ph_transport(),
        intents: 1,
        attempts: 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1),
        due: false,
        ..s2
    };
    let rec = SendRec {
        serial: 1,
        committed: 1,
        binding: 0,
        present: true,
        state: st_uncertain(),
        attempts: 1,
    };
    let s4 = State {
        pc: ph_outcome(),
        outcome: o_wrong_digest(),
        remote: false,
        sends: es.insert(rec),
        ..s3
    };
    let s5 = State {
        pc: ph_idle(),
        state: st_retained(),
        attempts: 1,
        uncertain: false,
        unresolved: ei,
        saved_digest: d_foreign(),
        saved_position: 1,
        ..s4
    };
    assert(init(s0));
    assert(next_mutant_unchecked(s0, s1)) by { assert(enqueue(s0, s1)); }
    assert(next_mutant_unchecked(s1, s2)) by {
        assert(is_binding(0) && select(s1, s2, false, 0));
    }
    assert(next_mutant_unchecked(s2, s3)) by { assert(intent_commit(s2, s3)); }
    assert(next_mutant_unchecked(s3, s4)) by {
        assert(is_outcome(5) && transport(s3, s4, false, 5, false));
    }
    assert(next_mutant_unchecked(s4, s5)) by {
        assert(outcome_commit(s4, s5, false, true, false));
    }
    assert(!checked_retention(s5)) by {
        assert(s5.state == st_retained());
        assert(!valid_saved(s5));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5);
    assert(is_mutant_ir_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_unchecked(
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
    assert(is_mutant_ir_trace(t) && !checked_retention(t.last()));
}

/// mutant-charge-outage: ChargeOutage keeps the attempt charge for a
/// durably classified outage, double-counting it against intents.
proof fn mutant_charge_outage_violates()
    ensures
        exists|t: Seq<State>|
            is_mutant_co_trace(t) && !attempt_evidence_conserved(t.last()),
{
    let ei = Set::<int>::empty();
    let es = Set::<SendRec>::empty();
    let s0 = init_state();
    let s1 = State { pc: ph_idle(), present: true, ..s0 };
    let s2 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 1,
        prior_attempts: 0,
        prior_uncertain: false,
        ..s1
    };
    let s3 = State {
        pc: ph_transport(),
        intents: 1,
        attempts: 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1),
        due: false,
        ..s2
    };
    let rec = SendRec {
        serial: 1,
        committed: 1,
        binding: 0,
        present: true,
        state: st_uncertain(),
        attempts: 1,
    };
    let s4 = State {
        pc: ph_outcome(),
        outcome: o_outage(),
        remote: false,
        sends: es.insert(rec),
        ..s3
    };
    let s5 = State {
        pc: ph_idle(),
        state: st_uncertain(),
        attempts: 1,
        uncertain: true,
        unresolved: ei.insert(1),
        outages: 1,
        classified: 1,
        ..s4
    };
    assert(init(s0));
    assert(next_mutant_charge_outage(s0, s1)) by { assert(enqueue(s0, s1)); }
    assert(next_mutant_charge_outage(s1, s2)) by {
        assert(is_binding(0) && select(s1, s2, false, 0));
    }
    assert(next_mutant_charge_outage(s2, s3)) by { assert(intent_commit(s2, s3)); }
    assert(next_mutant_charge_outage(s3, s4)) by {
        assert(is_outcome(1) && transport(s3, s4, false, 1, false));
    }
    assert(next_mutant_charge_outage(s4, s5)) by {
        assert(outcome_commit(s4, s5, false, false, true));
    }
    assert(!attempt_evidence_conserved(s5)) by {
        assert(s5.attempts + s5.spent + s5.classified == 2 && s5.intents == 1);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5);
    assert(is_mutant_co_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_charge_outage(
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
    assert(is_mutant_co_trace(t) && !attempt_evidence_conserved(t.last()));
}

/// Completion witness for the safe model: an outage-restored attempt, one
/// interruption and reopen, then a retained receipt reaches Retained with
/// a valid saved receipt and observed remote retention.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>|
            is_trace(t) && t.last().state == st_retained() && valid_saved(t.last())
                && t.last().remote,
{
    let ei = Set::<int>::empty();
    let es = Set::<SendRec>::empty();
    let s0 = init_state();
    let s1 = State { pc: ph_idle(), present: true, ..s0 };
    let s2 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 1,
        prior_attempts: 0,
        prior_uncertain: false,
        ..s1
    };
    let s3 = State {
        pc: ph_transport(),
        intents: 1,
        attempts: 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1),
        due: false,
        ..s2
    };
    let r1 = SendRec {
        serial: 1,
        committed: 1,
        binding: 0,
        present: true,
        state: st_uncertain(),
        attempts: 1,
    };
    let s4 = State {
        pc: ph_outcome(),
        outcome: o_outage(),
        remote: false,
        sends: es.insert(r1),
        ..s3
    };
    let s5 = State {
        pc: ph_idle(),
        state: st_uncertain(),
        attempts: 0,
        uncertain: true,
        unresolved: ei.insert(1),
        outages: 1,
        classified: 1,
        ..s4
    };
    let s6 = State { pc: ph_closed(), crashes: 1, ..s5 };
    let s7 = State { pc: ph_idle(), ..s6 };
    let s8 = State { due: true, ..s7 };
    let s9 = State {
        pc: ph_intent(),
        selected: b_orig(),
        current: 2,
        prior_attempts: 0,
        prior_uncertain: true,
        ..s8
    };
    let s10 = State {
        pc: ph_transport(),
        intents: 2,
        attempts: 1,
        state: st_uncertain(),
        uncertain: true,
        unresolved: ei.insert(1).insert(2),
        due: false,
        ..s9
    };
    let r2 = SendRec {
        serial: 2,
        committed: 2,
        binding: 0,
        present: true,
        state: st_uncertain(),
        attempts: 1,
    };
    let s11 = State {
        pc: ph_outcome(),
        outcome: o_receipt(),
        remote: true,
        sends: es.insert(r1).insert(r2),
        ..s10
    };
    let s12 = State {
        pc: ph_idle(),
        state: st_retained(),
        attempts: 1,
        uncertain: false,
        unresolved: ei,
        saved_digest: d_exact(),
        saved_position: 1,
        ..s11
    };
    assert(init(s0));
    assert(next(s0, s1)) by { assert(enqueue(s0, s1)); }
    assert(next(s1, s2)) by { assert(is_binding(0) && select(s1, s2, false, 0)); }
    assert(next(s2, s3)) by { assert(intent_commit(s2, s3)); }
    assert(next(s3, s4)) by { assert(is_outcome(1) && transport(s3, s4, false, 1, false)); }
    assert(next(s4, s5)) by { assert(outcome_commit(s4, s5, false, false, false)); }
    assert(next(s5, s6)) by { assert(crash(s5, s6, 1)); }
    assert(next(s6, s7)) by { assert(reopen(s6, s7)); }
    assert(next(s7, s8)) by { assert(due(s7, s8)); }
    assert(next(s8, s9)) by { assert(is_binding(0) && select(s8, s9, false, 0)); }
    assert(next(s9, s10)) by { assert(intent_commit(s9, s10)); }
    assert(next(s10, s11)) by { assert(is_outcome(0) && transport(s10, s11, false, 0, true)); }
    assert(next(s11, s12)) by { assert(outcome_commit(s11, s12, false, false, false)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8).push(s9).push(s10).push(s11).push(s12);
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
    assert(s12.state == st_retained() && valid_saved(s12) && s12.remote);
    assert(is_trace(t) && t.last().state == st_retained() && valid_saved(t.last())
        && t.last().remote);
}

}
