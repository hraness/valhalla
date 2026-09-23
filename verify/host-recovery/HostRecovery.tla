-------------------------- MODULE HostRecovery --------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Files, CrashBudget, ConsumeBackup, CleanupBeforeSync,
          SkipAbsentBarrier, PairOnlyAdmission, AllowCorruption

Targets == Files \cup {"config"}
Markers == {"none", "files", "committing"}
Phases == {"backup", "files", "config", "complete", "unlink", "sync",
           "cleanup", "recover", "restore", "validate",
           "done", "uncertain"}

VARIABLE s
vars == <<s>>

\* Successful rewrite() calls are atomic durable replacements. Marker unlink
\* is separately visible and durable: a process interruption preserves visible
\* absence, while power loss can recover the last durable marker. A backup
\* unlink may persist before the final directory sync (the adverse case).
\* Refusal preserves visible bytes/evidence; spontaneous OS persistence is
\* permitted to change durableMarker after an error without a service write.
Persistent == <<s.live, s.complete, s.marker, s.backups, s.tampered>>
PairMatches == s.live["config"] = s.complete
WholeSnapshot == PairMatches /\ \A f \in Files : s.live[f] = s.complete
NeedsRestore == s.marker = "files"
                \/ (s.marker = "committing"
                    /\ (~PairMatches \/ s.live["config"] = 0))
CanKeep == (s.marker = "none" /\ PairMatches)
           \/ (s.marker = "committing" /\ PairMatches
               /\ s.live["config"] = 1 /\ "config" \in s.backups)

Init == s = [pc |-> "backup", live |-> [f \in Targets |-> 0],
             complete |-> 0, marker |-> "none", durableMarker |-> "none",
             backups |-> {}, restoreTodo |-> {}, crashes |-> 0,
             tampered |-> {}, damaged |-> FALSE, badRead |-> FALSE,
             refusedAt |-> <<>>]

Backup(f) == /\ s.pc = "backup" /\ f \notin s.backups
             /\ s' = [s EXCEPT !.backups = @ \cup {f}]
MarkFiles == /\ s.pc = "backup" /\ s.backups = Targets
             /\ s' = [s EXCEPT !.pc = "files", !.marker = "files",
                                !.durableMarker = "files"]
WriteFile(f) == /\ s.pc = "files" /\ s.live[f] = 0
                /\ s' = [s EXCEPT !.live[f] = 1]
SealFiles == /\ s.pc = "files" /\ \A f \in Files : s.live[f] = 1
             /\ s' = [s EXCEPT !.pc = "config", !.marker = "committing",
                                !.durableMarker = "committing"]
WriteConfig == /\ s.pc = "config"
               /\ s' = [s EXCEPT !.live["config"] = 1, !.pc = "complete"]
WriteComplete == /\ s.pc = "complete"
                 /\ s' = [s EXCEPT !.complete = 1, !.pc = "unlink"]

UnlinkPresent == /\ s.pc = "unlink" /\ s.marker # "none"
                 /\ s' = [s EXCEPT !.marker = "none", !.pc = "sync"]
UnlinkAbsent == /\ s.pc = "unlink" /\ s.marker = "none"
                /\ s' = [s EXCEPT !.pc = IF SkipAbsentBarrier
                                             THEN "cleanup" ELSE "sync"]
SyncMarker == /\ s.pc = "sync"
              /\ s' = [s EXCEPT !.pc = "cleanup",
                                 !.durableMarker = IF CleanupBeforeSync
                                                     THEN @ ELSE "none"]
Cleanup(f) == /\ s.pc = "cleanup" /\ f \in s.backups
              /\ s' = [s EXCEPT !.backups = @ \ {f}, !.tampered = @ \ {f}]
Finish == /\ s.pc = "cleanup" /\ s.backups = {}
          /\ s' = [s EXCEPT !.pc = "done", !.durableMarker = "none"]

\* This fault changes no persistent bytes: it models a stopped process whose
\* next invocation sees the same kernel's directory cache.
ProcessInterruption == /\ s.pc \notin {"done", "uncertain"}
                       /\ s.crashes < CrashBudget
                       /\ s' = [s EXCEPT !.pc = "recover", !.restoreTodo = {},
                                          !.crashes = @ + 1]
PowerLoss == /\ s.pc \notin {"done", "uncertain"}
             /\ s.crashes < CrashBudget
             /\ s' = [s EXCEPT !.pc = "recover", !.restoreTodo = {},
                                !.marker = s.durableMarker, !.crashes = @ + 1]
\* Persistence can happen early, but it cannot be relied on before sync.
PersistUnlink == /\ s.marker = "none" /\ s.durableMarker # "none"
                 /\ s' = [s EXCEPT !.durableMarker = "none"]

RecoverRestore == /\ s.pc = "recover" /\ NeedsRestore
                  /\ "config" \in s.backups /\ s.tampered = {}
                  /\ s' = [s EXCEPT !.pc = "restore", !.restoreTodo = s.backups]
Restore(f) == /\ s.pc = "restore" /\ f \in s.restoreTodo
              /\ s' = [s EXCEPT !.live[f] = 0, !.restoreTodo = @ \ {f},
                                 !.backups = IF ConsumeBackup THEN @ \ {f} ELSE @]
RestoreComplete == /\ s.pc = "restore" /\ s.restoreTodo = {}
                   /\ s' = [s EXCEPT !.complete = s.live["config"],
                                      !.pc = "validate"]
ValidateRestore == /\ s.pc = "validate" /\ WholeSnapshot
                   /\ s' = [s EXCEPT !.pc = "unlink"]
RecoverKeep == /\ s.pc = "recover" /\ CanKeep /\ WholeSnapshot
               /\ s' = [s EXCEPT !.pc = "unlink"]
Refuse == /\ (s.pc = "validate" /\ ~WholeSnapshot)
                \/ (s.pc = "recover"
                    /\ ~(NeedsRestore /\ "config" \in s.backups /\ s.tampered = {})
                    /\ ~(CanKeep /\ WholeSnapshot))
          /\ s' = [s EXCEPT !.pc = "uncertain", !.refusedAt = Persistent]

\* The separate uncertainty case probes one corrupt rollback backup or one
\* drifted live file behind a matching new config pair. These are fail-closed
\* integrity failures, not states promised automatic repair or availability.
CorruptBackup(f) == /\ AllowCorruption /\ ~s.damaged /\ s.pc = "recover"
                    /\ NeedsRestore /\ f \in s.backups
                    /\ s' = [s EXCEPT !.tampered = {f}, !.damaged = TRUE]
DriftFile(f) == /\ AllowCorruption /\ ~s.damaged /\ s.pc = "recover"
                /\ CanKeep /\ s.live["config"] = 1
                /\ s' = [s EXCEPT !.live[f] = 0, !.damaged = TRUE]
Read == /\ ~s.badRead /\ PairMatches /\ (PairOnlyAdmission \/ WholeSnapshot)
        /\ s' = [s EXCEPT !.badRead = ~WholeSnapshot]

Next == MarkFiles \/ SealFiles \/ WriteConfig \/ WriteComplete
        \/ UnlinkPresent \/ UnlinkAbsent \/ SyncMarker \/ Finish
        \/ ProcessInterruption \/ PowerLoss \/ PersistUnlink
        \/ RecoverRestore \/ RestoreComplete \/ ValidateRestore \/ RecoverKeep
        \/ Refuse \/ Read
        \/ (\E f \in Targets : Backup(f) \/ Cleanup(f) \/ Restore(f) \/ CorruptBackup(f))
        \/ (\E f \in Files : WriteFile(f) \/ DriftFile(f))
Spec == Init /\ [][Next]_vars

TypeOK == /\ s.pc \in Phases /\ s.live \in [Targets -> 0..1]
          /\ s.complete \in 0..1 /\ s.marker \in Markers /\ s.durableMarker \in Markers
          /\ s.backups \subseteq Targets /\ s.restoreTodo \subseteq Targets
          /\ s.crashes \in 0..CrashBudget /\ s.tampered \subseteq s.backups
          /\ s.damaged \in BOOLEAN /\ s.badRead \in BOOLEAN
RestoreEvidence == s.pc = "restore" => Targets \subseteq s.backups
RestartEvidence == (s.pc = "recover" /\ s.marker # "none" /\ ~s.damaged)
                   => "config" \in s.backups
SealedAdmission == ~s.badRead
CompletedSnapshot == s.pc = "done" => WholeSnapshot
RefusalKeepsEvidence == s.pc = "uncertain" => Persistent = s.refusedAt
=============================================================================
