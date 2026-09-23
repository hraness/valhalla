------------------------- MODULE PrivateEgress -------------------------
EXTENDS Naturals, FiniteSets
CONSTANT TailFastPath
\* Two old-epoch applications precede a newly issued next-epoch acceptance in
\* the authenticated local outbox. Item 1 was staged by an earlier tick. The
\* separate owner control advances epoch zero to one. Queue capacity is one.
Items == 1..3
Old == {1, 2}
VARIABLES captured, queue, retained, control, admittedAtCutover
vars == <<captured, queue, retained, control, admittedAtCutover>>
Init == /\ captured = 1 /\ queue = {1} /\ retained = {}
        /\ control = FALSE /\ admittedAtCutover = {}

Capture == /\ captured < 3 /\ queue = {}
           /\ captured' = captured + 1
           /\ queue' = IF captured + 1 \in retained THEN {} ELSE {captured + 1}
           /\ UNCHANGED <<retained, control, admittedAtCutover>>
\* Known-bad receipt shortcut: bypasses the monotone frontier when a completed
\* job frees one slot, even though an earlier application is still unseen.
ReceiptFastPath == /\ TailFastPath /\ captured < 3 /\ queue = {}
                   /\ 3 \notin retained
                   /\ queue' = {3}
                   /\ UNCHANGED <<captured, retained, control, admittedAtCutover>>
SendItem(i) == /\ i \in queue /\ (i \in Old \/ control)
               /\ queue' = {} /\ retained' = retained \cup {i}
               /\ UNCHANGED <<captured, control, admittedAtCutover>>
\* The driver refills an empty bounded page before considering its control.
\* A nonempty page must therefore be the actual next authenticated output.
SendControl == /\ ~control /\ (captured = 3 \/ queue # {})
               /\ queue \intersect Old = {}
               /\ control' = TRUE /\ admittedAtCutover' = retained
               /\ UNCHANGED <<captured, queue, retained>>
Next == Capture \/ ReceiptFastPath \/ SendControl
          \/ (\E i \in Items : SendItem(i))
Spec == Init /\ [][Next]_vars
TypeOK == /\ captured \in 1..3 /\ queue \subseteq Items
          /\ Cardinality(queue) <= 1 /\ retained \subseteq Items
          /\ control \in BOOLEAN /\ admittedAtCutover \subseteq retained
OldBeforeControl == control => Old \subseteq admittedAtCutover
=============================================================================
