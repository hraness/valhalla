------------------------- MODULE PrivateDelivery -------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Clients, Capacity, MaxCrashes, DropFuture, LosePending, DoubleApply
Items == 1..3
\* Item 1 is future-epoch application data; item 3 is its enabling control.
\* Item 2 is an independent application record. Positions are exact identities
\* in this model; crypto, bytes and the storage implementation are abstracted.
VARIABLES cursor, pending, applied, staged, online, crashes, effects
vars == <<cursor, pending, applied, staged, online, crashes, effects>>

Init == /\ cursor = [c \in Clients |-> 0]
        /\ pending = [c \in Clients |-> {}]
        /\ applied = [c \in Clients |-> {}]
        /\ staged = [c \in Clients |-> 0]
        /\ online = [c \in Clients |-> TRUE]
        /\ crashes = [c \in Clients |-> 0]
        /\ effects = [c \in Clients |-> [m \in Items |-> 0]]

Ready(c, m) == m # 1 \/ 3 \in applied[c]

\* A response can be lost before its strict image+item transaction commits.
Fetch(c) == /\ online[c] /\ staged[c] = 0 /\ cursor[c] < 3
            /\ Cardinality(pending[c]) < Capacity
            /\ staged' = [staged EXCEPT ![c] = cursor[c] + 1]
            /\ UNCHANGED <<cursor, pending, applied, online, crashes, effects>>

\* Production correspondence: durable exact item and progress are one publish.
PublishFetch(c) ==
    /\ online[c] /\ staged[c] # 0
    /\ cursor' = [cursor EXCEPT ![c] = staged[c]]
    /\ pending' = IF DropFuture /\ ~Ready(c, staged[c])
                  THEN pending
                  ELSE [pending EXCEPT ![c] = @ \cup {staged[c]}]
    /\ staged' = [staged EXCEPT ![c] = 0]
    /\ UNCHANGED <<applied, online, crashes, effects>>

\* Pending items are selected independently of mailbox order, within capacity.
Apply(c, m) ==
    /\ online[c] /\ m \in pending[c] /\ Ready(c, m)
    /\ pending' = [pending EXCEPT ![c] = @ \ {m}]
    /\ applied' = [applied EXCEPT ![c] = @ \cup {m}]
    /\ effects' = [effects EXCEPT ![c][m] = @ + 1]
    /\ UNCHANGED <<cursor, staged, online, crashes>>

\* Exact retained retries must not execute the ratchet/inbox effect again.
Replay(c, m) ==
    /\ online[c] /\ m \in applied[c] /\ effects[c][m] < 2
    /\ effects' = IF DoubleApply THEN [effects EXCEPT ![c][m] = @ + 1]
                  ELSE effects
    /\ UNCHANGED <<cursor, pending, applied, staged, online, crashes>>

Crash(c) ==
    /\ online[c] /\ crashes[c] < MaxCrashes
    /\ online' = [online EXCEPT ![c] = FALSE]
    /\ crashes' = [crashes EXCEPT ![c] = @ + 1]
    /\ staged' = [staged EXCEPT ![c] = 0]
    /\ pending' = IF LosePending THEN [pending EXCEPT ![c] = {}]
                  ELSE pending
    /\ UNCHANGED <<cursor, applied, effects>>
Recover(c) == /\ ~online[c]
              /\ online' = [online EXCEPT ![c] = TRUE]
              /\ UNCHANGED <<cursor, pending, applied, staged, crashes, effects>>

Next == \E c \in Clients : Fetch(c) \/ PublishFetch(c) \/ Crash(c) \/ Recover(c)
                              \/ (\E m \in Items : Apply(c, m) \/ Replay(c, m))
TypeOK == /\ cursor \in [Clients -> 0..3]
          /\ pending \in [Clients -> SUBSET Items]
          /\ applied \in [Clients -> SUBSET Items]
          /\ staged \in [Clients -> 0..3]
          /\ online \in [Clients -> BOOLEAN]
          /\ crashes \in [Clients -> 0..MaxCrashes]
          /\ effects \in [Clients -> [Items -> 0..2]]
NoLostWork == \A c \in Clients : (1..cursor[c]) \subseteq (pending[c] \cup applied[c])
Bounded == \A c \in Clients : Cardinality(pending[c]) <= Capacity
ExactlyOnce == \A c \in Clients : \A m \in Items : effects[c][m] <= 1
ControlBeforeFuture == \A c \in Clients : 1 \in applied[c] => 3 \in applied[c]
Disjoint == \A c \in Clients : pending[c] \intersect applied[c] = {}

SafetySpec == Init /\ [][Next]_vars
\* Liveness assumes finite crashes, eventual successful transport and storage,
\* sufficient deferred capacity, and fair execution. It makes no promise for
\* permanent failure, exhaustion, missing controls, expiry or revoked authority.
Fair == \A c \in Clients : WF_vars(Fetch(c)) /\ WF_vars(PublishFetch(c))
                           /\ WF_vars(Recover(c))
                           /\ (\A m \in Items : WF_vars(Apply(c, m)))
Spec == SafetySpec /\ Fair
EventuallyResolved == <> (\A c \in Clients : applied[c] = Items)
=============================================================================
