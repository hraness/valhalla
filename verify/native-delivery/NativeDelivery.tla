-------------------------- MODULE NativeDelivery --------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS MaxAttempts, OutageBudget, CrashBudget, AllowWriteFailure,
          EarlySend, Retarget, ForgetUncertainty, ResetSpent,
          IgnoreReceipt, ChargeOutage

ASSUME /\ MaxAttempts \in Nat \ {0}
       /\ OutageBudget \in Nat /\ CrashBudget \in Nat

Original == [id |-> "exact", operation |-> "operation", sequence |-> 1,
             bytes |-> "ciphertext", namespace |-> "namespace", endpoint |-> "pinned"]
Bindings == {Original, [Original EXCEPT !.bytes = "other-ciphertext"],
              [Original EXCEPT !.namespace = "other-namespace"],
              [Original EXCEPT !.endpoint = "other-endpoint"]}
MaxIntents == 2 * MaxAttempts + OutageBudget
States == {"Pending", "Uncertain", "Retained", "Stopped"}
Phases == {"new", "idle", "intent", "transport", "outcome", "needs-reopen", "closed"}
Outcomes == {"receipt", "outage", "denied", "capacity", "permanent",
             "wrong-digest", "zero-position", "large-position"}
Receipt(o) == [digest |-> IF o = "wrong-digest" THEN "foreign" ELSE Original.id,
               position |-> IF o = "zero-position" THEN 0
                            ELSE IF o = "large-position" THEN 3 ELSE 1]
Valid(r) == r.digest = Original.id /\ r.position \in 1..2

VARIABLE s
vars == <<s>>

\* state/attempts/spent/outages/uncertain are durable queue data. intents,
\* classified and unresolved are history instrumentation, not implementation
\* counters: each committed intent is charged until a durable outage outcome
\* restores its charge. A crash before that outcome remains charged/uncertain.
Init == s = [pc |-> "new", present |-> FALSE, state |-> "Pending",
             attempts |-> 0, spent |-> 0, outages |-> 0, resumes |-> 0,
             uncertain |-> FALSE, due |-> TRUE,
             intents |-> 0, classified |-> 0, unresolved |-> {},
             current |-> 0, priorAttempts |-> 0, priorUncertain |-> FALSE,
             selected |-> Original, outcome |-> "receipt",
             saved |-> [digest |-> "none", position |-> 0],
             remote |-> FALSE, sends |-> {}, crashes |-> 0, failedWrite |-> FALSE]

Enqueue == /\ s.pc = "new"
           /\ s' = [s EXCEPT !.pc = "idle", !.present = TRUE]
Due == /\ s.pc = "idle" /\ ~s.due
       /\ s' = [s EXCEPT !.due = TRUE]
\* A hostile profile is rejected before intent or network effects. The mutant
\* permits selection of foreign exact bytes/namespace/endpoint instead.
Select(binding) ==
    /\ s.pc = "idle" /\ s.state \in {"Pending", "Uncertain"} /\ s.due
    /\ s.attempts < MaxAttempts /\ s.intents < MaxIntents
    /\ binding = Original \/ Retarget
    /\ s' = [s EXCEPT !.pc = "intent", !.selected = binding,
         !.current = s.intents + 1, !.priorAttempts = s.attempts,
         !.priorUncertain = s.uncertain]
IntentCommit == /\ s.pc = "intent"
                /\ s' = [s EXCEPT !.pc = "transport", !.intents = @ + 1,
                    !.attempts = @ + 1, !.state = "Uncertain", !.uncertain = TRUE,
                    !.unresolved = @ \cup {s.current}, !.due = FALSE]

\* A transport outcome may disappear before its local publication. Outage can
\* follow actual retention; a receipt comes from the modeled honest relay.
Transport(o, retained) ==
    /\ s.pc = "transport" \/ (EarlySend /\ s.pc = "intent")
    /\ o # "outage" \/ s.classified < OutageBudget
    /\ retained => o \in {"receipt", "outage"}
    /\ o = "receipt" => retained
    /\ s' = [s EXCEPT !.pc = "outcome", !.outcome = o,
         !.remote = @ \/ retained,
         !.sends = @ \cup {[serial |-> s.current, committed |-> s.intents,
                           binding |-> s.selected, present |-> s.present,
                           state |-> s.state, attempts |-> s.attempts]}]

OutcomeCommit ==
    /\ s.pc = "outcome"
    /\ LET outage == s.outcome = "outage"
           accepted == s.outcome = "receipt"
                       \/ (IgnoreReceipt /\ s.outcome \in
                           {"wrong-digest", "zero-position", "large-position"})
           bad == s.outcome \in {"wrong-digest", "zero-position", "large-position"}
           permanent == s.outcome = "permanent" \/ bad
           uncertain == IF accepted THEN FALSE
                        ELSE IF bad \/ outage THEN TRUE
                        ELSE IF ForgetUncertainty THEN FALSE ELSE s.priorUncertain
           unresolved == IF accepted THEN {}
                         ELSE IF outage \/ bad THEN s.unresolved
                         ELSE s.unresolved \ {s.current}
       IN s' = [s EXCEPT !.pc = "idle",
           !.state = IF accepted THEN "Retained"
                     ELSE IF permanent \/ (~outage /\ s.attempts >= MaxAttempts)
                          THEN "Stopped"
                     ELSE IF uncertain THEN "Uncertain" ELSE "Pending",
           !.attempts = IF outage /\ ~ChargeOutage THEN s.priorAttempts ELSE @,
           !.uncertain = uncertain, !.unresolved = unresolved,
           !.outages = IF outage THEN @ + 1 ELSE @,
           !.classified = IF outage THEN @ + 1 ELSE @,
           !.saved = IF accepted THEN Receipt(s.outcome) ELSE @]

Exhausted == /\ s.pc = "idle" /\ s.state \in {"Pending", "Uncertain"}
             /\ s.attempts >= MaxAttempts
             /\ s' = [s EXCEPT !.state = "Stopped"]
Resume == /\ s.pc = "idle" /\ s.state = "Stopped" /\ s.resumes = 0
          /\ s' = [s EXCEPT !.state = IF s.uncertain THEN "Uncertain" ELSE "Pending",
               !.spent = IF ResetSpent THEN @ ELSE @ + s.attempts,
               !.attempts = 0, !.resumes = 1, !.due = TRUE]

\* A precommit outcome refusal leaves the earlier durable intent and poisons
\* the handle. Postcommit barrier/readback failures are outside this action;
\* completed publication followed by interruption is covered by Crash.
OutcomePrecommitRefusal == /\ AllowWriteFailure /\ s.pc = "outcome" /\ ~s.failedWrite
                          /\ s' = [s EXCEPT !.pc = "needs-reopen", !.failedWrite = TRUE]
Crash == /\ s.pc \notin {"closed", "needs-reopen"} /\ s.crashes < CrashBudget
         /\ s' = [s EXCEPT !.pc = "closed", !.crashes = @ + 1]
Reopen == /\ s.pc \in {"closed", "needs-reopen"}
          /\ s' = [s EXCEPT !.pc = IF s.present THEN "idle" ELSE "new"]

Next == Enqueue \/ Due \/ IntentCommit \/ OutcomeCommit \/ Exhausted \/ Resume
        \/ OutcomePrecommitRefusal \/ Crash \/ Reopen
        \/ (\E b \in Bindings : Select(b))
        \/ (\E o \in Outcomes, retained \in BOOLEAN : Transport(o, retained))
Spec == Init /\ [][Next]_vars

TypeOK == /\ s.pc \in Phases /\ s.present \in BOOLEAN /\ s.state \in States
          /\ s.attempts \in 0..MaxAttempts /\ s.spent \in 0..MaxAttempts
          /\ s.outages \in 0..OutageBudget /\ s.classified \in 0..OutageBudget
          /\ s.intents \in 0..MaxIntents /\ s.current \in 0..MaxIntents
          /\ s.resumes \in 0..1 /\ s.crashes \in 0..CrashBudget
          /\ s.selected \in Bindings /\ s.outcome \in Outcomes
          /\ s.uncertain \in BOOLEAN /\ s.due \in BOOLEAN
          /\ s.remote \in BOOLEAN /\ s.failedWrite \in BOOLEAN
          /\ s.unresolved \subseteq 1..s.intents
IntentBeforeTransport == \A t \in s.sends :
    /\ t.present /\ t.serial <= t.committed
    /\ t.state = "Uncertain" /\ t.attempts > 0
ExactRetryBinding == \A t \in s.sends : t.binding = Original
UncertaintyPreserved == /\ s.unresolved # {} => s.uncertain
                        /\ s.remote /\ s.state # "Retained" => s.uncertain
AttemptEvidenceConserved == s.attempts + s.spent + s.classified = s.intents
OutageEvidence == s.outages = s.classified
CheckedRetention == s.state = "Retained" => Valid(s.saved) /\ s.remote
=============================================================================
