------------------------- MODULE PrivateRotation -------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Jobs, UnsafeCutover, ResetSpent, RelabelReceipt
VARIABLES generation, fenced, created, pending, retained, jobGeneration,
          receiptGeneration, spent, prepared, oldReadable, stored, frozenHead
vars == <<generation, fenced, created, pending, retained, jobGeneration,
          receiptGeneration, spent, prepared, oldReadable, stored, frozenHead>>

Init == /\ generation = 0 /\ fenced = FALSE
        /\ created = {} /\ pending = {} /\ retained = {}
        /\ jobGeneration = [j \in Jobs |-> 0]
        /\ receiptGeneration = [j \in Jobs |-> 0]
        /\ spent = 0 /\ prepared = FALSE /\ oldReadable = TRUE
        /\ stored = {} /\ frozenHead = {}

Queue(j) == /\ j \notin created /\ ~fenced /\ ~prepared
            /\ created' = created \cup {j} /\ pending' = pending \cup {j}
            /\ jobGeneration' = [jobGeneration EXCEPT ![j] = generation]
            /\ spent' = spent + 1
            /\ UNCHANGED <<generation, fenced, retained, receiptGeneration,
                           prepared, oldReadable, stored, frozenHead>>
Reachable(j) == jobGeneration[j] = generation
                \/ (jobGeneration[j] = 0 /\ oldReadable)
\* Storage admission and the controller's receipt are separate: the response
\* can be lost. After fencing, only a previously stored exact retry resolves.
Store(j) == /\ j \in pending \ stored /\ ~fenced
            /\ jobGeneration[j] = generation
            /\ stored' = stored \cup {j}
            /\ UNCHANGED <<generation, fenced, created, pending, retained,
                           jobGeneration, receiptGeneration, spent, prepared,
                           oldReadable, frozenHead>>
Retain(j) == /\ j \in pending \intersect stored /\ Reachable(j)
             /\ pending' = pending \ {j} /\ retained' = retained \cup {j}
             /\ receiptGeneration' = [receiptGeneration EXCEPT ![j] = jobGeneration[j]]
             /\ UNCHANGED <<generation, fenced, created, jobGeneration, spent,
                            prepared, oldReadable, stored, frozenHead>>
Fence == /\ generation = 0 /\ ~fenced /\ fenced' = TRUE
         /\ frozenHead' = stored
         /\ UNCHANGED <<generation, created, pending, retained, jobGeneration,
                        receiptGeneration, spent, prepared, oldReadable, stored>>
PrepareCutover == /\ generation = 0 /\ fenced /\ ~prepared
                  /\ (pending = {} \/ UnsafeCutover)
                  /\ prepared' = TRUE
                  /\ UNCHANGED <<generation, fenced, created, pending, retained,
                                 jobGeneration, receiptGeneration, spent, oldReadable,
                                 stored, frozenHead>>
\* Only the publication is durable. Interrupted preparation leaves old state.
Crash == /\ prepared /\ prepared' = FALSE
         /\ UNCHANGED <<generation, fenced, created, pending, retained,
                        jobGeneration, receiptGeneration, spent, oldReadable,
                        stored, frozenHead>>
Cutover == /\ prepared /\ generation = 0
           /\ generation' = 1 /\ fenced' = FALSE /\ prepared' = FALSE
           /\ oldReadable' = ~UnsafeCutover
           /\ spent' = IF ResetSpent THEN 0 ELSE spent
           /\ receiptGeneration' = IF RelabelReceipt
                 THEN [j \in Jobs |-> IF j \in retained THEN 1 ELSE receiptGeneration[j]]
                 ELSE receiptGeneration
           /\ UNCHANGED <<created, pending, retained, jobGeneration, stored, frozenHead>>
Next == Fence \/ PrepareCutover \/ Crash \/ Cutover
          \/ (\E j \in Jobs : Queue(j) \/ Store(j) \/ Retain(j))
Spec == Init /\ [][Next]_vars

TypeOK == /\ generation \in 0..1 /\ fenced \in BOOLEAN
          /\ created \subseteq Jobs /\ pending \subseteq Jobs /\ retained \subseteq Jobs
          /\ jobGeneration \in [Jobs -> 0..1]
          /\ receiptGeneration \in [Jobs -> 0..1]
          /\ spent \in 0..Cardinality(Jobs) /\ prepared \in BOOLEAN
          /\ oldReadable \in BOOLEAN
          /\ stored \subseteq created /\ retained \subseteq stored
          /\ frozenHead \subseteq stored
NoOrphans == \A j \in pending : Reachable(j)
PreservedSpend == spent = Cardinality(created)
BoundReceipts == \A j \in retained : receiptGeneration[j] = jobGeneration[j]
Conservation == /\ pending \cup retained = created
                /\ pending \intersect retained = {}
FrozenHead == (fenced \/ generation = 1) =>
                 {j \in stored : jobGeneration[j] = 0} = frozenHead
=============================================================================
