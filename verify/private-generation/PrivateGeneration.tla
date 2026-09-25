------------------------ MODULE PrivateGeneration ------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Controllers, SkipController, IgnoreHead, SkipAutomatic,
          SkipIntent, ResetSpent, DropArchive
VARIABLES created, pending, stored, applied, observed, paused, fenced,
          terminal, intent, selected, archive, spent, online
vars == <<created, pending, stored, applied, observed, paused, fenced,
          terminal, intent, selected, archive, spent, online>>

App(c) == <<"application", c>>
Ack(c) == <<"acceptance", c>>
Applications == {App(c) : c \in Controllers}
Acceptances == {Ack(c) : c \in Controllers}
Jobs == Applications \cup Acceptances
Foreign == <<"concurrent", "old-writer">>
Owned(c, jobs) == {j \in jobs : j[2] = c}
Incoming(c) == (stored \intersect Applications) \ {App(c)}
Required == IF SkipController THEN {CHOOSE c \in Controllers : TRUE}
            ELSE Controllers

Init == /\ created = {} /\ pending = {} /\ stored = {}
        /\ applied = [c \in Controllers |-> {}]
        /\ observed = [c \in Controllers |-> {}]
        /\ paused = {} /\ fenced = FALSE /\ terminal = {}
        /\ intent = [c \in Controllers |-> FALSE]
        /\ selected = [c \in Controllers |-> 0]
        /\ archive = [c \in Controllers |-> {}]
        /\ spent = [c \in Controllers |-> 0]
        /\ online = Controllers

Queue(c) == /\ c \in online \ paused /\ ~fenced /\ selected[c] = 0
            /\ App(c) \notin created
            /\ created' = created \cup {App(c)}
            /\ pending' = pending \cup {App(c)}
            /\ spent' = [spent EXCEPT ![c] = @ + 1]
            /\ UNCHANGED <<stored, applied, observed, paused, fenced,
                            terminal, intent, selected, archive, online>>

Store(j) == /\ j \in pending \ stored /\ ~fenced
            /\ stored' = stored \cup {j}
            /\ UNCHANGED <<created, pending, applied, observed, paused, fenced,
                            terminal, intent, selected, archive, spent, online>>

\* A lost PUT completion leaves pending evidence. This exact retry may still
\* obtain its original receipt after a fence; it never inserts into a successor.
Receipt(j) == /\ j \in pending \intersect stored
              /\ pending' = pending \ {j}
              /\ UNCHANGED <<created, stored, applied, observed, paused, fenced,
                              terminal, intent, selected, archive, spent, online>>

\* With two controllers each incoming application creates one acceptance.
\* The output must itself drain before a controller can pause safely.
Apply(c) == /\ c \in online \ paused /\ selected[c] = 0 /\ ~fenced
            /\ Incoming(c) \ applied[c] # {}
            /\ applied' = [applied EXCEPT ![c] = Incoming(c)]
            /\ created' = created \cup {Ack(c)}
            /\ pending' = pending \cup {Ack(c)}
            /\ spent' = [spent EXCEPT ![c] = @ + 1]
            /\ UNCHANGED <<stored, observed, paused, fenced, terminal,
                            intent, selected, archive, online>>

Observe(c) == /\ c \in online \ paused /\ selected[c] = 0 /\ ~fenced
              /\ (Incoming(c) \subseteq applied[c] \/ SkipAutomatic)
              /\ observed' = [observed EXCEPT ![c] = stored]
              /\ UNCHANGED <<created, pending, stored, applied, paused, fenced,
                              terminal, intent, selected, archive, spent, online>>

Pause(c) == /\ c \in online \ paused /\ selected[c] = 0 /\ ~fenced
            /\ Owned(c, pending) = {} /\ observed[c] = stored
            /\ (Incoming(c) \subseteq applied[c] \/ SkipAutomatic)
            /\ paused' = paused \cup {c}
            /\ UNCHANGED <<created, pending, stored, applied, observed, fenced,
                            terminal, intent, selected, archive, spent, online>>

\* Another admitted writer can finish after the controller's last observation.
\* Its identity is abstract; expected-head comparison must detect the change.
RaceWrite == /\ ~fenced /\ paused # {} /\ Foreign \notin stored
             /\ stored' = stored \cup {Foreign}
             /\ UNCHANGED <<created, pending, applied, observed, paused, fenced,
                             terminal, intent, selected, archive, spent, online>>

Fence == /\ ~fenced /\ Required \subseteq paused
         /\ ((\A c \in Required : observed[c] = stored) \/ IgnoreHead)
         /\ fenced' = TRUE /\ terminal' = stored
         /\ UNCHANGED <<created, pending, stored, applied, observed, paused,
                         intent, selected, archive, spent, online>>

Prepare(c) == /\ c \in online /\ fenced /\ c \in paused
              /\ observed[c] = terminal /\ Owned(c, pending) = {}
              /\ Incoming(c) \subseteq applied[c] /\ ~intent[c]
              /\ intent' = [intent EXCEPT ![c] = TRUE]
              /\ UNCHANGED <<created, pending, stored, applied, observed, paused,
                              fenced, terminal, selected, archive, spent, online>>

\* The intent and predecessor remain durable through crash/reopen. Selecting
\* generation 1 is one atomic publication, including archive and spent basis.
Select(c) == /\ c \in online /\ fenced /\ selected[c] = 0
             /\ (intent[c] \/ SkipIntent)
             /\ selected' = [selected EXCEPT ![c] = 1]
             /\ archive' = [archive EXCEPT ![c] = IF DropArchive THEN {} ELSE terminal]
             /\ spent' = [spent EXCEPT ![c] = IF ResetSpent THEN 0 ELSE @]
             /\ UNCHANGED <<created, pending, stored, applied, observed, paused,
                             fenced, terminal, intent, online>>

Crash(c) == /\ c \in online /\ online' = online \ {c}
            /\ UNCHANGED <<created, pending, stored, applied, observed, paused,
                            fenced, terminal, intent, selected, archive, spent>>
Reopen(c) == /\ c \notin online /\ online' = online \cup {c}
             /\ UNCHANGED <<created, pending, stored, applied, observed, paused,
                             fenced, terminal, intent, selected, archive, spent>>

Next == Fence \/ RaceWrite \/ (\E j \in Jobs : Store(j) \/ Receipt(j))
        \/ (\E c \in Controllers : Queue(c) \/ Apply(c) \/ Observe(c) \/ Pause(c)
              \/ Prepare(c) \/ Select(c) \/ Crash(c) \/ Reopen(c))
Spec == Init /\ [][Next]_vars

TypeOK == /\ created \subseteq Jobs /\ pending \subseteq created
          /\ stored \subseteq created \cup {Foreign}
          /\ applied \in [Controllers -> SUBSET Applications]
          /\ observed \in [Controllers -> SUBSET (Jobs \cup {Foreign})]
          /\ paused \subseteq Controllers /\ online \subseteq Controllers
          /\ fenced \in BOOLEAN /\ terminal \subseteq stored
          /\ intent \in [Controllers -> BOOLEAN]
          /\ selected \in [Controllers -> 0..1]
          /\ archive \in [Controllers -> SUBSET (Jobs \cup {Foreign})]
          /\ spent \in [Controllers -> 0..2]
CompleteInventory == fenced => paused = Controllers
ConditionalHead == fenced => \A c \in Controllers : observed[c] = terminal
AutomaticOutputDrained == fenced =>
    /\ pending = {}
    /\ \A c \in Controllers : Incoming(c) \subseteq applied[c]
IntentBeforeSelection == \A c \in Controllers : selected[c] = 1 => intent[c]
PreservedSpend == \A c \in Controllers : spent[c] = Cardinality(Owned(c, created))
PreservedArchive == \A c \in Controllers : selected[c] = 1 => archive[c] = terminal
FrozenPredecessor == fenced => stored = terminal
=============================================================================
