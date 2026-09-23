-------------------------- MODULE PrivateControl --------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS LateJoin, MaxControls, ReopenBudget,
          CurrentOwnerShortcut, RebindGrant, AdmitObservation,
          FaultBeforeCheckpoint, UnlatchUncertainty, ClearQuarantine

ASSUME /\ MaxControls = 4 /\ ReopenBudget \in Nat /\ LateJoin \in BOOLEAN
Devices == {"A", "B"}
Signers == Devices \cup {"foreign"}
Other(device) == IF device = "A" THEN "B" ELSE "A"
Base == IF LateJoin THEN 2 ELSE 0
InitialFloor == IF LateJoin THEN 3 ELSE 1

\* A carrying control is signed by the predecessor. Only a handoff at a
\* strictly earlier sequence changes the owner expected at this sequence.
OwnerAt(changes, sequence) ==
    LET earlier == {h \in 1..MaxControls : h < sequence /\ changes[h] # "none"}
    IN IF earlier = {} THEN "A"
       ELSE changes[CHOOSE h \in earlier : \A q \in earlier : q <= h]
InitialChanges == [h \in 1..MaxControls |-> IF LateJoin /\ h = 2 THEN "B" ELSE "none"]
Initial == [floor |-> InitialFloor,
            owner |-> IF LateJoin THEN "B" ELSE "A",
            signers |-> [h \in 1..MaxControls |->
                        IF h > InitialFloor THEN "none"
                        ELSE OwnerAt(InitialChanges, h)],
            changes |-> InitialChanges, fault |-> 0]
NoGrant == [present |-> FALSE, sequence |-> 0, predecessor |-> "A", successor |-> "B"]
NoObservation == [present |-> FALSE, sequence |-> 1, signer |-> "A",
                  expectedOwner |-> "A", variant |-> "exact", result |-> "Exact",
                  base |-> Base, beforeFloor |-> InitialFloor, afterFloor |-> InitialFloor,
                  beforeOwner |-> Initial.owner, afterOwner |-> Initial.owner]

VARIABLE s
vars == <<s>>
Init == s = [disk |-> Initial, cached |-> Initial,
             pc |-> "idle", needsReopen |-> FALSE, uncertain |-> FALSE,
             kind |-> "none", pendingFork |-> 0, everFault |-> FALSE,
             grant |-> NoGrant, usedGrants |-> {}, observation |-> NoObservation,
             reopens |-> 0]
Live == /\ s.pc = "idle" /\ ~s.needsReopen /\ s.cached.fault = 0
Handoffs == {h \in 1..s.disk.floor : s.disk.changes[h] # "none"}

\* Account signature, live validity, scope and exact rostered enrollment are
\* assumed. Preparing the grant has no durable authority effect.
PrepareGrant == /\ Live /\ s.disk.floor < MaxControls /\ Cardinality(Handoffs) < 2
                /\ s' = [s EXCEPT !.grant = [present |-> TRUE,
                      sequence |-> s.disk.floor + 1, predecessor |-> s.disk.owner,
                      successor |-> Other(s.disk.owner)]]

\* A separately admitted ordinary control may make the prepared grant stale.
\* Its normal transaction is atomic here; handoff and fork writes are split.
AdvanceControl ==
    /\ Live /\ s.disk.floor < MaxControls
    /\ LET h == s.disk.floor + 1
           next == [s.disk EXCEPT !.floor = h, !.signers[h] = s.disk.owner]
       IN s' = [s EXCEPT !.disk = next, !.cached = next]

BeginHandoff ==
    /\ Live /\ s.grant.present /\ s.disk.floor < MaxControls
    /\ Cardinality(Handoffs) < 2
    /\ s.grant.predecessor = s.disk.owner
    /\ RebindGrant \/ s.grant.sequence = s.disk.floor + 1
    /\ s' = [s EXCEPT !.pc = "publishing", !.kind = "handoff",
                       !.needsReopen = TRUE, !.uncertain = TRUE]

\* Claims are canonical and individually signature-valid. Expected ownership
\* comes from accepted handoff history, including the retained checkpoint chain.
\* "exact" is the known accepted ID; "conflict" is a different signed ID.
Observe(sequence, signer, variant) ==
    /\ Live
    /\ LET expectedOwner == OwnerAt(s.disk.changes, sequence)
           checkedOwner == IF CurrentOwnerShortcut THEN s.disk.owner ELSE expectedOwner
           result == IF signer # checkedOwner THEN "Policy"
                     ELSE IF sequence > s.disk.floor THEN "Missing"
                     ELSE IF sequence < Base /\ ~FaultBeforeCheckpoint THEN "Missing"
                     ELSE IF variant = "exact" THEN "Exact" ELSE "Fork"
           admit == AdmitObservation /\ signer = checkedOwner
                    /\ sequence > s.disk.floor /\ sequence <= MaxControls
           next == IF admit THEN [s.disk EXCEPT !.floor = sequence,
                                                 !.signers[sequence] = signer]
                   ELSE s.disk
       IN s' = [s EXCEPT !.disk = next, !.cached = next,
             !.observation = [present |-> TRUE, sequence |-> sequence,
                  signer |-> signer, expectedOwner |-> expectedOwner,
                  variant |-> variant, result |-> result, base |-> Base,
                  beforeFloor |-> s.disk.floor, afterFloor |-> next.floor,
                  beforeOwner |-> s.disk.owner, afterOwner |-> next.owner],
             !.pc = IF result = "Fork" THEN "publishing" ELSE @,
             !.kind = IF result = "Fork" THEN "fork" ELSE @,
             !.pendingFork = IF result = "Fork" THEN sequence ELSE @,
             !.needsReopen = result = "Fork", !.uncertain = result = "Fork"]

\* Before: storage refuses without changing any durable bytes. The process
\* retains a pending fork observation and stays latched until exact reopen.
RefuseBefore == /\ s.pc = "publishing"
                /\ s' = [s EXCEPT !.pc = "idle",
                                   !.needsReopen = ~UnlatchUncertainty]

\* State, control floor, accepted handoff chain and retained output publish as
\* one storage transaction. No completion response is assumed yet.
Publish ==
    /\ s.pc = "publishing"
    /\ LET h == s.disk.floor + 1
           next == IF s.kind = "fork" THEN [s.disk EXCEPT !.fault = s.pendingFork]
                   ELSE [s.disk EXCEPT !.floor = h, !.owner = s.grant.successor,
                            !.signers[h] = s.disk.owner,
                            !.changes[h] = s.grant.successor]
       IN s' = [s EXCEPT !.disk = next, !.pc = "readback",
              !.everFault = @ \/ s.kind = "fork",
              !.usedGrants = IF s.kind = "handoff" THEN
                  @ \cup {[carriedAt |-> h, grantedAt |-> s.grant.sequence,
                           predecessor |-> s.grant.predecessor,
                           signer |-> s.disk.owner, successor |-> s.grant.successor]}
                  ELSE @]

\* After and canceled HangAfter both leave a committed image but no confirmed
\* return. Live work stays blocked; reopen determines the committed outcome.
LoseCompletion == /\ s.pc = "readback"
                  /\ s' = [s EXCEPT !.pc = "idle",
                                     !.needsReopen = ~UnlatchUncertainty]
Confirm == /\ s.pc = "readback"
           /\ s' = [s EXCEPT !.cached = s.disk, !.pc = "idle",
                              !.needsReopen = FALSE, !.uncertain = FALSE,
                              !.kind = "none", !.pendingFork = 0]

\* Explicit reopen also models losing the process. An uncommitted pending
\* observation can disappear; a committed quarantine must remain. No action
\* clears durable quarantine or invents successor/recovery authority.
Reopen == /\ s.reopens < ReopenBudget
          /\ s' = [s EXCEPT !.cached = IF ClearQuarantine
                                      THEN [s.disk EXCEPT !.fault = 0] ELSE s.disk,
                 !.pc = "idle", !.needsReopen = FALSE, !.uncertain = FALSE,
                 !.kind = "none", !.pendingFork = 0, !.reopens = @ + 1]

Next == PrepareGrant \/ AdvanceControl \/ BeginHandoff \/ RefuseBefore
        \/ Publish \/ LoseCompletion \/ Confirm \/ Reopen
        \/ (\E sequence \in 1..(MaxControls + 1), signer \in Signers,
                variant \in {"exact", "conflict"} : Observe(sequence, signer, variant))
Spec == Init /\ [][Next]_vars

TypeOK == /\ s.pc \in {"idle", "publishing", "readback"}
          /\ s.disk.floor \in 1..MaxControls /\ s.disk.owner \in Devices
          /\ s.cached.floor \in 1..MaxControls /\ s.cached.owner \in Devices
          /\ s.disk.signers \in [1..MaxControls -> Signers \cup {"none"}]
          /\ s.disk.changes \in [1..MaxControls -> Devices \cup {"none"}]
          /\ s.disk.fault \in 0..MaxControls /\ s.cached.fault \in 0..MaxControls
          /\ s.needsReopen \in BOOLEAN /\ s.uncertain \in BOOLEAN
          /\ s.kind \in {"none", "handoff", "fork"}
          /\ s.pendingFork \in 0..MaxControls /\ s.everFault \in BOOLEAN
          /\ s.reopens \in 0..ReopenBudget
HistoricalSigners == /\ s.disk.owner = OwnerAt(s.disk.changes, s.disk.floor + 1)
                     /\ \A h \in 1..s.disk.floor :
                            s.disk.signers[h] = OwnerAt(s.disk.changes, h)
HistoricalAuthority == ~s.observation.present \/
    ((s.observation.signer = s.observation.expectedOwner)
        <=> (s.observation.result # "Policy"))
PinnedHandoff == \A grant \in s.usedGrants :
                  /\ grant.carriedAt = grant.grantedAt
                  /\ grant.predecessor = grant.signer
                  /\ grant.successor # grant.predecessor
ObservationOnly == /\ s.observation.beforeFloor = s.observation.afterFloor
                   /\ s.observation.beforeOwner = s.observation.afterOwner
KnownHistoryFault == s.observation.result = "Fork" =>
                     /\ s.observation.sequence >= s.observation.base
                     /\ s.observation.sequence <= s.observation.beforeFloor
                     /\ s.observation.signer = s.observation.expectedOwner
                     /\ s.observation.variant = "conflict"
UncertainCustody == s.uncertain =>
                    /\ s.needsReopen
                    /\ s.kind = "fork" => s.pendingFork # 0
PersistentQuarantine == s.everFault /\ ~s.needsReopen =>
                        /\ s.disk.fault # 0 /\ s.cached.fault # 0
=============================================================================
