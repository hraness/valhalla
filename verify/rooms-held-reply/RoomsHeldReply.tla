------------------------- MODULE RoomsHeldReply -------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS RequestCount, MetadataCapacity,
          DropEmpty, EarlyLiveReply, PublishTombstone, ForgetDeadline,
          ForgetAdmission

ASSUME /\ RequestCount \in Nat \ {0}
       /\ MetadataCapacity \in Nat
       /\ DropEmpty \in BOOLEAN
       /\ EarlyLiveReply \in BOOLEAN
       /\ PublishTombstone \in BOOLEAN
       /\ ForgetDeadline \in BOOLEAN
       /\ ForgetAdmission \in BOOLEAN

Requests == 1..RequestCount
Phases == {"idle", "held", "selected", "prepared", "publishing", "lost"}
Kinds == {"none", "live", "tombstone"}

\* Each request is a distinct (height, round, proposer) metadata slot. One
\* sequential connector awaits one reply at a time. The host also serializes
\* network publication before accepting its next message. Bytes, signatures,
\* fsync internals and a stopped host are outside this finite abstraction.
VARIABLES current, phase, arrived, expired, issued, seen, admitted, kind,
          replied, replyKind, published
vars == <<current, phase, arrived, expired, issued, seen, admitted, kind,
          replied, replyKind, published>>

Init == /\ current = 0
        /\ phase = "idle"
        /\ arrived = FALSE
        /\ expired = FALSE
        /\ issued = {}
        /\ seen = {}
        /\ admitted = {}
        /\ kind = "none"
        /\ replied = {}
        /\ replyKind = [r \in Requests |-> "none"]
        /\ published = {}

\* GetValue takes custody of the reply. Even the immediate-value path is
\* represented through the same selection/preparation stages as flush_held.
Request == /\ phase = "idle" /\ current < RequestCount
           /\ current' = current + 1
           /\ issued' = issued \cup {current + 1}
           /\ phase' = IF DropEmpty /\ ~arrived THEN "lost" ELSE "held"
           /\ expired' = FALSE
           /\ kind' = "none"
           /\ UNCHANGED <<arrived, seen, admitted, replied, replyKind, published>>

\* Retained exact bytes become available independently of adapter admission:
\* a future batch can remain on disk after earlier-height pending-map pruning.
\* This one-height abstraction starts with no confirmed adapter admission.
\* The supplied live candidate is valid at this frontier; validation rejection
\* and the preceding heights are exercised by the implementation regressions.
\* There is no fairness on Arrival: no producer need ever submit work.
Arrival == /\ ~arrived
           /\ arrived' = TRUE
           /\ UNCHANGED <<current, phase, expired, issued, seen, admitted, kind,
                          replied, replyKind, published>>

\* Time eventually crosses this request's deadline. This is not a hard
\* wall-clock bound: the subsequent poll still needs host scheduling.
Expire == /\ phase = "held" /\ ~expired
          /\ expired' = TRUE
          /\ UNCHANGED <<current, phase, arrived, issued, seen, admitted, kind,
                         replied, replyKind, published>>

\* drain_answerable_held prefers a materializable value even after expiry.
\* Otherwise the intake tick supplies a reply-only tombstone at the deadline.
Resolve == /\ phase = "held"
           /\ (arrived \/ (expired /\ ~ForgetDeadline))
           /\ kind' = IF arrived THEN "live" ELSE "tombstone"
           /\ phase' = "selected"
           /\ UNCHANGED <<current, arrived, expired, issued, seen, admitted,
                          replied, replyKind, published>>

\* prepare_local_parts records exact seen metadata before exposing a real
\* proposal to the engine, then restores confirmed adapter admission. Durable
\* availability and seen metadata alone cannot make a decision committable.
\* A full budget falls back to a tombstone and adds no adapter admission;
\* it never prunes existing evidence or releases an unrecorded real value.
Prepare == /\ phase = "selected"
           /\ LET admit == kind = "live" /\ Cardinality(seen) < MetadataCapacity
              IN /\ seen' = IF admit THEN seen \cup {current} ELSE seen
                 /\ admitted' = IF admit /\ ~ForgetAdmission
                                 THEN admitted \cup {current} ELSE admitted
                 /\ kind' = IF kind = "live" /\ ~admit THEN "tombstone" ELSE kind
           /\ phase' = "prepared"
           /\ UNCHANGED <<current, arrived, expired, issued,
                          replied, replyKind, published>>

\* Successful oneshot send precedes all paced network publication. Receiver
\* cancellation is outside the successful-reply contract, as is host exit.
Reply == /\ (phase = "prepared"
              \/ (EarlyLiveReply /\ phase = "selected" /\ kind = "live"))
         /\ replied' = replied \cup {current}
         /\ replyKind' = [replyKind EXCEPT ![current] = kind]
         /\ phase' = IF kind = "live" \/ PublishTombstone
                      THEN "publishing" ELSE "idle"
         /\ UNCHANGED <<current, arrived, expired, issued, seen, admitted, kind,
                        published>>

\* A stream may block the host loop until its network consumer drains it.
\* One action abstracts the finite paced stream, without a latency claim.
Publish == /\ phase = "publishing"
           /\ published' = published \cup {current}
           /\ phase' = "idle"
           /\ UNCHANGED <<current, arrived, expired, issued, seen, admitted, kind,
                          replied, replyKind>>

Next == Request \/ Arrival \/ Expire \/ Resolve \/ Prepare \/ Reply \/ Publish
SafetySpec == Init /\ [][Next]_vars
Fair == /\ WF_vars(Request) /\ WF_vars(Expire) /\ WF_vars(Resolve)
        /\ WF_vars(Prepare) /\ WF_vars(Reply) /\ WF_vars(Publish)
Spec == SafetySpec /\ Fair

OwnedReply == IF phase \in {"held", "selected", "prepared"}
              THEN {current} ELSE {}

TypeOK == /\ current \in 0..RequestCount /\ phase \in Phases
          /\ arrived \in BOOLEAN /\ expired \in BOOLEAN
          /\ issued \subseteq Requests /\ seen \subseteq issued
          /\ admitted \subseteq seen
          /\ kind \in Kinds /\ replied \subseteq issued
          /\ replyKind \in [Requests -> Kinds]
          /\ published \subseteq replied
ReplyCustody == /\ issued = replied \cup OwnedReply
                /\ replied \intersect OwnedReply = {}
DurableBeforeReply == \A r \in replied :
                        replyKind[r] = "live" => (arrived /\ r \in seen)
AdmittedBeforeReply == \A r \in replied :
                         replyKind[r] = "live" => r \in admitted
TombstonesStayLocal == \A r \in published : replyKind[r] = "live"
MetadataBound == Cardinality(seen) <= MetadataCapacity
AllRequestsAnswered == <> (replied = Requests)
=============================================================================
