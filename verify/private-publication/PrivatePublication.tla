----------------------- MODULE PrivatePublication -----------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Sessions, EarlyOutput, RetargetDraft, IgnoreRevocation
VARIABLES roster, revision, revoked, phase, expected, draftRoster,
          stored, storedRoster, confirmed, released, authorizedAtRelease
vars == <<roster, revision, revoked, phase, expected, draftRoster,
          stored, storedRoster, confirmed, released, authorizedAtRelease>>

Init == /\ roster = 0 /\ revision = 0 /\ revoked = FALSE
        /\ phase = [s \in Sessions |-> "idle"]
        /\ expected = [s \in Sessions |-> 0]
        /\ draftRoster = [s \in Sessions |-> 0]
        /\ stored = {} /\ confirmed = {} /\ released = {}
        /\ storedRoster = [s \in Sessions |-> 0]
        /\ authorizedAtRelease = [s \in Sessions |-> TRUE]

\* Both modeled grants bind roster zero. A roster update never extends a grant.
Authority == ~revoked /\ roster = 0
Prepare(s) == /\ phase[s] = "idle" /\ Authority
              /\ phase' = [phase EXCEPT ![s] = "draft"]
              /\ expected' = [expected EXCEPT ![s] = revision]
              /\ draftRoster' = [draftRoster EXCEPT ![s] = roster]
              /\ UNCHANGED <<roster, revision, revoked, stored, storedRoster,
                             confirmed, released, authorizedAtRelease>>
Start(s) == /\ phase[s] = "draft" /\ Authority
            /\ phase' = [phase EXCEPT ![s] = "waiting"]
            /\ UNCHANGED <<roster, revision, revoked, expected, draftRoster,
                           stored, storedRoster, confirmed, released,
                           authorizedAtRelease>>
\* Atomic CAS publication is assumed, not proven by this model. The operation
\* identifier s is also its fixed ciphertext identity; no retry re-encrypts it.
Publish(s) == /\ phase[s] = "waiting" /\ s \notin stored
              /\ ((expected[s] = revision /\ draftRoster[s] = roster)
                   \/ RetargetDraft)
              /\ stored' = stored \cup {s}
              /\ storedRoster' = [storedRoster EXCEPT ![s] = roster]
              /\ revision' = revision + 1
              /\ phase' = [phase EXCEPT ![s] = "readback"]
              /\ UNCHANGED <<roster, revoked, expected, draftRoster,
                             confirmed, released, authorizedAtRelease>>
Readback(s) == /\ phase[s] = "readback" /\ s \in stored
               /\ confirmed' = confirmed \cup {s}
               /\ phase' = [phase EXCEPT ![s] = "ready"]
               /\ UNCHANGED <<roster, revision, revoked, expected, draftRoster,
                              stored, storedRoster, released, authorizedAtRelease>>
\* Cancellation, conflict, failed readback and an uncertain response all latch.
Interrupt(s) == /\ phase[s] \in {"waiting", "readback", "ready"}
                /\ phase' = [phase EXCEPT ![s] = "latched"]
                /\ UNCHANGED <<roster, revision, revoked, expected, draftRoster,
                               stored, storedRoster, confirmed, released,
                               authorizedAtRelease>>
\* Trusted recovery may reconcile existing bytes; it cannot restore authority.
Recover(s) == /\ phase[s] = "latched" /\ s \in stored
              /\ phase' = [phase EXCEPT ![s] = "readback"]
              /\ UNCHANGED <<roster, revision, revoked, expected, draftRoster,
                             stored, storedRoster, confirmed, released,
                             authorizedAtRelease>>
Release(s) == /\ (phase[s] = "ready"
                   \/ (EarlyOutput /\ phase[s] = "waiting"))
              /\ (Authority \/ IgnoreRevocation)
              /\ released' = released \cup {s}
              /\ authorizedAtRelease' = [authorizedAtRelease EXCEPT ![s] = Authority]
              /\ phase' = [phase EXCEPT ![s] = "done"]
              /\ UNCHANGED <<roster, revision, revoked, expected, draftRoster,
                             stored, storedRoster, confirmed>>
Revoke == /\ ~revoked /\ revoked' = TRUE
          /\ UNCHANGED <<roster, revision, phase, expected, draftRoster,
                         stored, storedRoster, confirmed, released,
                         authorizedAtRelease>>
ChangeRoster == /\ roster = 0 /\ roster' = 1 /\ revision' = revision + 1
                /\ UNCHANGED <<revoked, phase, expected, draftRoster,
                               stored, storedRoster, confirmed, released,
                               authorizedAtRelease>>
Next == Revoke \/ ChangeRoster \/ (\E s \in Sessions :
          Prepare(s) \/ Start(s) \/ Publish(s) \/ Readback(s) \/ Interrupt(s)
          \/ Recover(s) \/ Release(s))
Spec == Init /\ [][Next]_vars

TypeOK == /\ roster \in 0..1 /\ revision \in 0..(Cardinality(Sessions) + 1)
          /\ revoked \in BOOLEAN
          /\ phase \in [Sessions -> {"idle", "draft", "waiting", "readback",
                                     "ready", "latched", "done"}]
          /\ expected \in [Sessions -> 0..(Cardinality(Sessions) + 1)]
          /\ draftRoster \in [Sessions -> 0..1]
          /\ stored \subseteq Sessions /\ confirmed \subseteq stored
          /\ released \subseteq Sessions /\ storedRoster \in [Sessions -> 0..1]
          /\ authorizedAtRelease \in [Sessions -> BOOLEAN]
ConfirmedOutput == released \subseteq confirmed
DraftBinding == \A s \in stored : storedRoster[s] = draftRoster[s]
AuthorizedOutput == \A s \in released : authorizedAtRelease[s]
=============================================================================
