-------------------------- MODULE RoomsFrontier --------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Heights, SocialChanges, RoomsChanges, CrashBudget,
          RootsOnlyAck, EarlyAck, OverwriteIdentity, RestartOnFailure,
          WrongNextRoster, RoomsBeforeSocial, IndependentRoots

ASSUME /\ Heights = 2
       /\ SocialChanges \subseteq 1..Heights
       /\ RoomsChanges \subseteq 1..Heights
       /\ CrashBudget \in Nat

Values == {"a", "b"}
Evidence == {"vote", "lock"}
Phases == {"idle", "journal", "social", "rooms", "social-after-rooms",
           "apply", "ack", "respond", "engine-restart", "recover",
           "recovery-check", "blocked"}

\* Roots are intentionally NOT height identities. An empty batch, or a batch
\* changing only the other store, repeats a prior root while the full frontier
\* still changes. The integer labels stand for exact root equality, not hashes.
Root(h, changes) == CHOOSE k \in changes \cup {0} :
                      /\ k <= h
                      /\ \A p \in changes \cup {0} : p <= h => p <= k
Social(h) == Root(h, SocialChanges)
Rooms(h) == Root(h, RoomsChanges)
Frontier(h, value) == [height |-> h, value |-> IF h = 0 THEN "genesis" ELSE value,
                       social |-> Social(h), registry |-> Rooms(h),
                       control |-> h, time |-> h]
Genesis == Frontier(0, "genesis")
Roster(h) == IF h = 1 THEN "old" ELSE "new"

VARIABLE s
vars == <<s>>
At(h) == IF h = 0 THEN Genesis ELSE Frontier(h, s.journal[h])

\* journal and the two roots are durable. app/appSocial/appRooms are separate
\* process state. original is history instrumentation, never recovery input.
\* wal models one retained height-1 vote/lock set. Starting height 2 may retire
\* it after a successful application acknowledgment; a failed finalization
\* cannot authorize the engine's destructive same-height restart.
Init == s = [pc |-> "idle", journalHead |-> 0,
             journal |-> [h \in 1..Heights |-> "none"],
             original |-> [h \in 1..Heights |-> "none"],
             social |-> 0, rooms |-> 0, app |-> Genesis,
             appSocial |-> 0, appRooms |-> 0,
             target |-> 1, value |-> "a", outcome |-> "none",
             recovering |-> FALSE, crashes |-> 0,
             acks |-> {}, starts |-> {}, reopened |-> {},
             wal |-> Evidence, releasedWal |-> FALSE]

NewDecision(v) == /\ s.pc = "idle"
                  /\ s.journalHead < Heights
                  /\ s.app.height = s.journalHead
                  /\ s' = [s EXCEPT !.pc = "journal",
                                     !.target = s.journalHead + 1,
                                     !.value = v, !.outcome = "none"]

\* The real adapter checks the retained journal value before the already-
\* applied fast path. A conflicting certificate cannot relabel that history.
Redeliver(h, v) ==
    /\ s.pc = "idle" /\ h <= s.journalHead
    /\ s' = [s EXCEPT !.target = h, !.value = v,
         !.journal[h] = IF OverwriteIdentity /\ v # s.journal[h] THEN v ELSE @,
         !.outcome = IF v # s.journal[h] THEN "Rejected" ELSE "none",
         !.pc = IF v # s.journal[h] THEN "respond"
                ELSE IF h <= s.app.height THEN "ack"
                ELSE IF RootsOnlyAck /\ s.appSocial = Social(h)
                                     /\ s.appRooms = Rooms(h)
                     THEN "ack" ELSE "social"]

JournalCommit == /\ s.pc = "journal"
                 /\ s' = [s EXCEPT !.journalHead = s.target,
                                    !.journal[s.target] = s.value,
                                    !.original[s.target] = s.value,
                                    !.pc = "social"]

PublishSocial == /\ s.pc \in {"social", "social-after-rooms"}
                 /\ s' = [s EXCEPT !.social = Social(s.target),
                       !.pc = IF s.pc = "social" THEN "rooms" ELSE "apply"]
PublishRooms == /\ s.pc = "rooms" \/ (RoomsBeforeSocial /\ s.pc = "social")
                /\ s' = [s EXCEPT !.rooms = Rooms(s.target),
                       !.pc = IF s.pc = "rooms" THEN "apply"
                              ELSE "social-after-rooms"]

Apply == /\ s.pc = "apply"
         /\ s' = [s EXCEPT !.app = At(s.target),
                            !.appSocial = Social(s.target),
                            !.appRooms = Rooms(s.target),
               !.target = IF s.recovering /\ s.target < s.journalHead
                          THEN @ + 1 ELSE @,
               !.value = IF s.recovering /\ s.target < s.journalHead
                         THEN s.journal[s.target + 1] ELSE @,
               !.pc = IF ~s.recovering THEN "ack"
                      ELSE IF s.target < s.journalHead THEN "social"
                      ELSE "recovery-check"]

\* An acknowledgment records the actual observations at that boundary, not
\* merely a flag that the guarded path ran. Later progress/reopen cannot turn
\* an earlier incorrect acknowledgment into a correct one.
Acknowledge ==
    /\ s.pc = "ack" \/ (EarlyAck /\ s.pc = "journal")
    /\ s' = [s EXCEPT !.outcome = "Acked", !.pc = "respond",
         !.acks = @ \cup {[height |-> s.target, value |-> s.value,
                          journalHead |-> s.journalHead,
                          committedValue |-> s.journal[s.target],
                          app |-> s.app,
                          appliedValue |-> IF s.app.height = 0 THEN "genesis"
                                          ELSE s.journal[s.app.height],
                          social |-> s.social, rooms |-> s.rooms,
                          appSocial |-> s.appSocial, appRooms |-> s.appRooms]}]

\* A failed journal/snapshot operation may leave the earlier successful
\* boundaries durable. The call returns Withheld without rolling them back.
Fail == /\ s.pc \in {"journal", "social", "rooms", "social-after-rooms"}
        /\ ~s.recovering
        /\ s' = [s EXCEPT !.pc = "respond", !.outcome = "Withheld"]

HostSuccess == /\ s.pc = "respond" /\ s.outcome = "Acked"
               /\ s' = [s EXCEPT !.pc = "idle",
                    !.starts = @ \cup {[decided |-> s.target,
                         height |-> s.target + 1,
                         roster |-> Roster(IF WrongNextRoster THEN s.target
                                           ELSE s.target + 1)]},
                    !.wal = IF s.target = 1 THEN {} ELSE @,
                    !.releasedWal = @ \/ s.target = 1]
HostFailure == /\ s.pc = "respond" /\ s.outcome \in {"Withheld", "Rejected"}
               /\ s' = [s EXCEPT !.pc = IF RestartOnFailure
                                               THEN "engine-restart" ELSE "idle"]
\* Abstraction of the pinned engine's Restart -> RestartHeight -> WAL reset.
\* It is a modeled external consequence, not a theorem about Malachite.
EngineRestart == /\ s.pc = "engine-restart"
                 /\ s' = [s EXCEPT !.pc = "idle",
                                    !.wal = IF s.target = 1 THEN {} ELSE @]

Interrupt == /\ s.pc \notin {"recover", "blocked"}
             /\ s.crashes < CrashBudget
             /\ s' = [s EXCEPT !.pc = "recover", !.app = Genesis,
                                !.appSocial = 0, !.appRooms = 0,
                                !.recovering = TRUE, !.crashes = @ + 1]

\* A root may match several prefixes. Recovery must choose a compatible pair,
\* not independently treat either root's latest match as the applied height.
\* The journal is already validated and atomic in this abstraction. Prefix
\* choice abstracts production's search; remaining batches replay in order.
CompatiblePrefix(p) == /\ s.rooms = Rooms(p)
                       /\ s.social = Social(p)
                           \/ (p < s.journalHead /\ s.social = Social(p + 1))
LatestMatch(root, changes) == CHOOSE p \in 0..s.journalHead :
    /\ root = Root(p, changes)
    /\ \A q \in 0..s.journalHead : root = Root(q, changes) => q <= p
IndependentSkewInvalid ==
    LET roomsHeight == LatestMatch(s.rooms, RoomsChanges)
        socialHeight == LatestMatch(s.social, SocialChanges)
    IN socialHeight < roomsHeight \/ socialHeight > roomsHeight + 1
LoadPrefix(p) ==
    /\ s.pc = "recover" /\ p <= s.journalHead /\ CompatiblePrefix(p)
    /\ ~IndependentRoots \/ (~IndependentSkewInvalid
                             /\ p = LatestMatch(s.rooms, RoomsChanges))
    /\ s' = [s EXCEPT !.app = At(p), !.appSocial = s.social,
         !.appRooms = s.rooms,
         !.target = IF p < s.journalHead THEN p + 1 ELSE IF p = 0 THEN 1 ELSE p,
         !.value = IF p < s.journalHead THEN s.journal[p + 1]
                   ELSE IF p = 0 THEN "a" ELSE s.journal[p],
         !.pc = IF p < s.journalHead THEN "social" ELSE "recovery-check"]
RecoveryRefuse == /\ s.pc = "recover"
                  /\ (~\E p \in 0..s.journalHead : CompatiblePrefix(p))
                       \/ (IndependentRoots /\ IndependentSkewInvalid)
                  /\ s' = [s EXCEPT !.pc = "blocked"]
RecoveryReady ==
    /\ s.pc = "recovery-check"
    /\ s.app = At(s.journalHead)
    /\ s.appSocial = s.social /\ s.appRooms = s.rooms
    /\ s' = [s EXCEPT !.pc = "idle", !.recovering = FALSE,
         !.reopened = @ \cup {[frontier |-> s.app, head |-> s.journalHead,
                  value |-> IF s.journalHead = 0 THEN "genesis"
                            ELSE s.journal[s.journalHead],
                  social |-> s.social, rooms |-> s.rooms]}]

Next == JournalCommit \/ PublishSocial \/ PublishRooms \/ Apply \/ Acknowledge
        \/ Fail \/ HostSuccess \/ HostFailure \/ EngineRestart \/ Interrupt
        \/ RecoveryRefuse \/ RecoveryReady
        \/ (\E v \in Values : NewDecision(v))
        \/ (\E h \in 1..Heights, v \in Values : Redeliver(h, v))
        \/ (\E p \in 0..Heights : LoadPrefix(p))
Spec == Init /\ [][Next]_vars

TypeOK == /\ s.pc \in Phases /\ s.journalHead \in 0..Heights
          /\ s.journal \in [1..Heights -> Values \cup {"none"}]
          /\ s.original \in [1..Heights -> Values \cup {"none"}]
          /\ s.social \in 0..Heights /\ s.rooms \in 0..Heights
          /\ s.app.height \in 0..Heights
          /\ s.target \in 1..Heights /\ s.value \in Values
          /\ s.appSocial \in 0..Heights /\ s.appRooms \in 0..Heights
          /\ s.outcome \in {"none", "Acked", "Rejected", "Withheld"}
          /\ s.recovering \in BOOLEAN /\ s.crashes \in 0..CrashBudget
          /\ s.wal \subseteq Evidence /\ s.releasedWal \in BOOLEAN
CommittedIdentity == s.journal = s.original
PublicationOrder == \E p \in 0..s.journalHead : CompatiblePrefix(p)
AckAfterDurability == \A a \in s.acks :
                       /\ a.height <= a.journalHead
                       /\ a.value = a.committedValue
                       /\ a.social >= Social(a.height)
                       /\ a.rooms >= Rooms(a.height)
AckHasFullFrontier == \A a \in s.acks :
                       /\ a.app.height >= a.height
                       /\ a.app = Frontier(a.app.height, a.appliedValue)
                       /\ a.appSocial = a.app.social
                       /\ a.appRooms = a.app.registry
FailedFinalizationKeepsWal == ~s.releasedWal => s.wal = Evidence
NextRoster == \A n \in s.starts :
                /\ n.height = n.decided + 1
                /\ n.roster = Roster(n.height)
RecoveredFrontier == \A r \in s.reopened :
                       /\ r.frontier = Frontier(r.head, r.value)
                       /\ r.social = Social(r.head)
                       /\ r.rooms = Rooms(r.head)
\* Stronger than checking admitted reopen records: the equality guard on
\* RecoveryReady must not conceal a stuck or refused honest recovery. Every
\* durable cut generated by this model is recoverable under its success/atomicity
\* assumptions. No scheduling liveness is asserted.
HonestRecovery == /\ s.pc # "blocked"
                  /\ s.pc = "recovery-check" =>
                       /\ s.app = At(s.journalHead)
                       /\ s.appSocial = s.social
                       /\ s.appRooms = s.rooms
                       /\ s.social = Social(s.journalHead)
                       /\ s.rooms = Rooms(s.journalHead)
=============================================================================
