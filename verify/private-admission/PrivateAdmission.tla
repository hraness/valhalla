------------------------ MODULE PrivateAdmission ------------------------
EXTENDS Naturals, FiniteSets
CONSTANT Mutant
VARIABLES worker, serial, reviews, requestVersion, clock, status, revision,
          changed, competed, phase, pending, shown, packet, item, taken,
          checkedAt, expected, effect
vars == <<worker, serial, reviews, requestVersion, clock, status, revision,
          changed, competed, phase, pending, shown, packet, item, taken,
          checkedAt, expected, effect>>
\* TLC does not compare a record with a string sentinel. All optional values
\* use a record tag; the tag is representation only, not a consent field.
None == [present |-> FALSE]
StatusFields == {"room", "anchor", "account", "custodyDevice", "epoch",
                 "roster", "floor", "owner", "quarantined"}
TokenFields == StatusFields \ {"owner", "quarantined"}
PacketFields == TokenFields \cup {"session", "id", "position", "digest",
                                  "recipient", "device", "start", "expires"}
InitialStatus == [f \in StatusFields |-> 0]
ExactItem == [position |-> 1, digest |-> 1, payload |-> 1]
OtherItem == [position |-> 2, digest |-> 2, payload |-> 2]
Consent == [f \in PacketFields \cup {"present"} |->
  CASE f = "present" -> TRUE
    [] f = "session" -> worker [] f = "id" -> serial + 1
    [] f = "position" -> 1 [] f = "digest" -> 1
    [] f = "recipient" -> 1 [] f = "device" -> 1
    [] f = "start" -> clock [] f = "expires" -> 2
    [] OTHER -> status[f]]
SameMembership(c) == /\ \A f \in TokenFields : c[f] = status[f]
                     /\ status.owner = 0 /\ status.quarantined = 0
Bound(p) == /\ packet = p.consent
            /\ item.position = packet.position
            /\ item.digest = packet.digest /\ item.payload = p.bytes

Init == /\ worker = 1 /\ serial = 0 /\ reviews = 0 /\ requestVersion = 0
        /\ clock = 0 /\ status = InitialStatus /\ revision = 0
        /\ changed = FALSE /\ competed = FALSE /\ phase = "ready"
        /\ pending = None /\ shown = None /\ packet = None
        /\ item = ExactItem /\ taken = None /\ checkedAt = 0
        /\ expected = 0 /\ effect = None

\* Review represents authenticated offer/request decoding and a current owner.
\* All bytes, keys and hashes are symbolic identities, not cryptographic proofs.
Review == /\ phase = "ready" /\ reviews < 2 /\ clock < 2
          /\ status.owner = 0 /\ status.quarantined = 0
          /\ pending' = [present |-> TRUE, consent |-> Consent, bytes |-> 1, stamp |-> requestVersion]
          /\ shown' = Consent /\ serial' = serial + 1 /\ reviews' = reviews + 1
          /\ UNCHANGED <<worker, requestVersion, clock, status, revision,
             changed, competed, phase, packet, item, taken, checkedAt, expected, effect>>
\* Even a failed review or a read/sync request invalidates earlier permission.
Intervene == /\ phase = "ready" /\ requestVersion = 0
             /\ requestVersion' = 1
             /\ pending' = IF Mutant = "intervene" THEN pending ELSE None
             /\ UNCHANGED <<worker, serial, reviews, clock, status, revision,
                changed, competed, phase, shown, packet, item, taken,
                checkedAt, expected, effect>>
\* UI can retain old returned metadata; worker-local permission is not restored.
Reload == /\ worker = 1 /\ worker' = 2 /\ serial' = 0 /\ phase' = "ready"
          /\ pending' = IF Mutant = "reload" THEN pending ELSE None
          /\ taken' = None
          /\ UNCHANGED <<reviews, requestVersion, clock, status, revision,
             changed, competed, shown, packet, item, checkedAt, expected, effect>>
Start(c) == /\ phase = "ready" /\ shown.present
            /\ packet' = c /\ phase' = "retained"
            /\ UNCHANGED <<worker, serial, reviews, requestVersion, clock,
               status, revision, changed, competed, pending, shown, item,
               taken, checkedAt, expected, effect>>
\* Session reads the selected retained position BEFORE Admission::confirm takes
\* its pending value. The broker is busy throughout; a failure terminates it.
ReadRetained(i) == /\ phase = "retained" /\ item' = i /\ phase' = "take"
                  /\ UNCHANGED <<worker, serial, reviews, requestVersion,
                     clock, status, revision, changed, competed, pending,
                     shown, packet, taken, checkedAt, expected, effect>>
Take == /\ phase = "take"
        /\ IF ~pending.present
           THEN /\ phase' = "dead" /\ taken' = None
           ELSE /\ phase' = "binding" /\ taken' = pending
        /\ pending' = IF Mutant = "consume" THEN pending ELSE None
        /\ checkedAt' = clock
        /\ UNCHANGED <<worker, serial, reviews, requestVersion, clock,
           status, revision, changed, competed, shown, packet, item, expected, effect>>
CheckBinding == /\ phase = "binding"
                /\ phase' = IF (packet = taken.consent \/ Mutant = "packet")
                     /\ ( (item.position = packet.position
                             /\ item.digest = packet.digest /\ item.payload = taken.bytes)
                           \/ Mutant = "ciphertext")
                   THEN "membership" ELSE "dead"
                /\ UNCHANGED <<worker, serial, reviews, requestVersion, clock,
                   status, revision, changed, competed, pending, shown,
                   packet, item, taken, checkedAt, expected, effect>>
CheckMembership == /\ phase = "membership"
                   /\ phase' = IF (SameMembership(packet) \/ Mutant = "membership")
                        /\ ((packet.start <= checkedAt /\ checkedAt < packet.expires)
                              \/ Mutant = "expiry")
                      THEN "publish" ELSE "dead"
                   /\ expected' = revision
                   /\ UNCHANGED <<worker, serial, reviews, requestVersion,
                      clock, status, revision, changed, competed, pending,
                      shown, packet, item, taken, checkedAt, effect>>
\* One cooperating rival writer may publish without changing membership.
\* Successful storage CAS is an assumed contract, not proved here.
Compete == /\ ~competed /\ competed' = TRUE /\ revision' = revision + 1
           /\ UNCHANGED <<worker, serial, reviews, requestVersion, clock,
              status, changed, phase, pending, shown, packet, item, taken,
              checkedAt, expected, effect>>
\* Conservative Admission API schedule: another kernel operation changes one
\* authenticated membership field before confirm. Session invalidates earlier.
Change(f) == /\ ~changed /\ phase # "publish"
             /\ changed' = TRUE /\ status' = [status EXCEPT ![f] = 1]
             /\ revision' = revision + 1
             /\ UNCHANGED <<worker, serial, reviews, requestVersion, clock,
                competed, phase, pending, shown, packet, item, taken,
                checkedAt, expected, effect>>
Publish == /\ phase = "publish"
           /\ phase' = IF revision = expected \/ Mutant = "custody" THEN "done" ELSE "dead"
           /\ effect' = IF revision = expected \/ Mutant = "custody"
                THEN [present |-> TRUE, supplied |-> packet, reviewed |-> taken, selected |-> item,
                      current |-> status, at |-> checkedAt, observed |-> expected,
                      committed |-> revision, session |-> worker, stamp |-> requestVersion]
                ELSE effect
           /\ UNCHANGED <<worker, serial, reviews, requestVersion, clock,
              status, revision, changed, competed, pending, shown, packet,
              item, taken, checkedAt, expected>>
\* Covers failed retained read, failed membership read, cancellation and a
\* second command arriving while the broker is busy. Nothing is published.
Interrupt == /\ phase \in {"retained", "take", "binding", "membership", "publish"}
             /\ phase' = "dead" /\ pending' = None /\ taken' = None
             /\ UNCHANGED <<worker, serial, reviews, requestVersion, clock,
                status, revision, changed, competed, shown, packet, item,
                checkedAt, expected, effect>>
Tick == /\ clock < 2 /\ clock' = clock + 1
        /\ UNCHANGED <<worker, serial, reviews, requestVersion, status,
           revision, changed, competed, phase, pending, shown, packet,
           item, taken, checkedAt, expected, effect>>
Next == Review \/ Intervene \/ Reload \/ Take \/ CheckBinding
        \/ CheckMembership \/ Compete \/ Publish \/ Interrupt \/ Tick
        \/ (\E f \in StatusFields : Change(f))
        \/ (shown.present /\ (Start(shown)
              \/ (\E f \in PacketFields : Start([shown EXCEPT ![f] = @ + 1]))))
        \/ ReadRetained(ExactItem) \/ ReadRetained(OtherItem)
Spec == Init /\ [][Next]_vars

TypeOK == /\ worker \in 1..2 /\ serial \in 0..2 /\ reviews \in 0..2
          /\ requestVersion \in 0..1 /\ clock \in 0..2 /\ revision \in 0..2
          /\ status \in [StatusFields -> 0..1] /\ changed \in BOOLEAN /\ competed \in BOOLEAN
          /\ pending.present \in BOOLEAN /\ shown.present \in BOOLEAN
          /\ packet.present \in BOOLEAN /\ taken.present \in BOOLEAN /\ effect.present \in BOOLEAN
          /\ phase \in {"ready", "retained", "take", "binding", "membership", "publish", "dead", "done"}
ConsentLifetime == ~pending.present \/ (pending.consent.session = worker /\ pending.stamp = requestVersion)
ConsumedBeforeCheck == phase \notin {"binding", "membership", "publish", "done"} \/ ~pending.present
ExactReview == ~effect.present \/ (effect.supplied = effect.reviewed.consent
                /\ effect.selected.position = effect.supplied.position
                /\ effect.selected.digest = effect.supplied.digest
                /\ effect.selected.payload = effect.reviewed.bytes)
CurrentMembership == ~effect.present \/
  ((\A f \in TokenFields : effect.supplied[f] = effect.current[f])
    /\ effect.current.owner = 0 /\ effect.current.quarantined = 0)
LiveAtConfirmation == ~effect.present \/
  (effect.supplied.start <= effect.at /\ effect.at < effect.supplied.expires)
ExclusivePublication == ~effect.present \/ effect.observed = effect.committed
\* Deliberately false invariant in a separate coverage case: a completed
\* valid admission must be reachable, so safety cannot pass by refusing all.
NoSuccessfulAdmission == ~effect.present
=============================================================================
