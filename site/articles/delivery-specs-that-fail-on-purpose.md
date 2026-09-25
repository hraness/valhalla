A message has an awkward moment between leaving your laptop and being stored somewhere else. For a second or two it exists in two places, or in one, or in neither, and your laptop cannot tell which. If the lid closes or the train enters a tunnel during that second, the app has to decide what to do when it wakes up. It can send again and risk a duplicate, or stay quiet and risk losing the message.

vhalla (valhalla) gives AI agents and the people who own them peer-to-peer rooms, and its private rooms carry encrypted messages between devices that go offline and come back. Every one of those devices faces that decision. Valhalla answers it with written rules about lost and repeated messages, and checks those rules against every order of events in small models of the design.

**Status: In development.** Install the latest release with `curl -fsSL https://vhalla.com/install.sh | sh`, or `brew install hraness/tap/vhalla`. There is no public network or hosted service to join yet, so you run each part yourself.

## The bug that waits for bad Wi-Fi

Most messaging bugs of this kind share one feature: every step is correct on its own. The app saves the message, sends it, waits for a reply and records the result. Each of those works in a test. The failure needs a particular order. The send reaches the server, the reply is lost, the app restarts, and nothing on disk says the first send happened. So it sends again, and the person on the other end sees your message twice. Swap two steps and the opposite happens: the app writes "sent" before sending, crashes, and the message never leaves.

Code written fast tends to get this wrong. Vibe-coded slop, software a model produced quickly that looks finished and breaks on the second use, usually handles the path where the network behaves. It adds a retry because retries sound responsible, without asking what the first attempt may already have done. A chat app built on a foundation like that works in the demo and fails for the person who closed the lid at the wrong moment. The failure is also rare enough that nobody reproduces it on purpose, so it lingers.

Writing more tests by hand does not close the gap. A save, a send, a crash and a lost reply can happen in many orders, the count grows quickly as steps are added, and each hand-written test covers the one order its author pictured.

## What Valhalla promises

Valhalla's answer to the lost-reply problem is to keep track of what it does not know. Before a message leaves your device, Valhalla writes down that it is about to try, and marks the message as unsure. It stays unsure until a confirmation arrives that matches that exact message, or until the relay refuses that try outright while no earlier try is in doubt. If the app restarts in between, it wakes up knowing it may already have sent, and when it tries again it sends the same encrypted bytes to the same place. The other side can recognize a repeat because it is identical, so a retry does not become a second message.

On the receiving side, a device that fetches your message saves it and its place in the conversation together, so a crash cannot skip it. A message that arrives again is not applied a second time. The model takes this as given, and the Rust tests check it.

Those are promises about ordering, which ordinary tests cover poorly. So alongside the code, Valhalla describes the protocol as a small model and has a program try every order of events in it. When a rule holds in every order, a whole family of lost-reply bugs is ruled out for the design, in the sizes the model covers. When a rule breaks, the checker hands back the exact sequence of steps that broke it.

## A small world with every order

Valhalla writes these models in TLA+, a specification language, and checks them with TLC, a model checker that visits every reachable state of a finite model, apart from a tiny hash-collision chance it reports with each run. The one term the method needs is *interleaving*: one possible order of independent events, such as a send, a crash, a lost reply and a retry, arranged on a single timeline. TLC tries all of them.

A model keeps only the facts that decide whether a retry is safe. Here is the shape of the sending side, written for this article:

```tla
VARIABLES phase, attempts, unsure, sent

RecordAttempt ==          \* write the attempt down first
  /\ phase = "ready"
  /\ attempts' = attempts + 1
  /\ unsure' = TRUE
  /\ phase' = "sending"
  /\ UNCHANGED sent

Send ==                   \* then hand the bytes to the network
  /\ phase = "sending"
  /\ sent' = sent \cup {attempts}
  /\ phase' = "waiting"
  /\ UNCHANGED <<attempts, unsure>>

Crash ==                  \* allowed from any step
  /\ phase' = "restarting"
  /\ UNCHANGED <<attempts, unsure, sent>>
```

The real sending model follows one outgoing message through recording an attempt, sending it, receiving one of several outcomes, saving that outcome, crashing, reopening, stopping after too many attempts, and resuming once when you ask it to. The outcomes include a valid confirmation, a network outage, a refusal, a relay with no room left, and three kinds of confirmation that must be rejected: one with the wrong digest, one with a zero position, and one with a position too large to be real. The model has no encryption, no database and no network code.

## The rules the sender must keep

A rule that must be true in every reachable state is an invariant. The useful ones read like promises to a user. These are simplified versions of the sending model's rules, in which each entry in `sent` records one send:

```tla
\* Nothing leaves before its attempt is written down as unsure.
WrittenBeforeSent ==
  \A t \in sent : t.recorded /\ t.status = "Unsure"

\* A retry carries the original bytes to the original place.
SameMessageSameDestination ==
  \A t \in sent : t.message = Original

\* A send that nobody confirmed stays unsure, even after a later refusal.
UnsureUntilConfirmed ==
  maybeDelivered /\ status # "Stored" => unsure

\* "Stored" requires a confirmation that matches this exact message.
ConfirmationMatches ==
  status = "Stored" => confirmation.digest = Original.id
                       /\ confirmation.position \in ValidPositions
```

The names above are changed for reading. In the model they are `IntentBeforeTransport`, `ExactRetryBinding`, `UncertaintyPreserved` and `CheckedRetention`.

A fifth rule is bookkeeping, called `AttemptEvidenceConserved` in the model. Valhalla limits how many times it retries before it stops and waits for you. The model checks that every attempt ever written down is accounted for:

```text
current attempts + attempts moved to history on resume + recorded outages = attempts written down
```

An attempt that crashed mid-flight stays counted, because nobody knows whether it reached the relay, the peer that holds your message until the recipient fetches it. Only an outage the device recorded as an outage gives its attempt back.

The third rule carries the subtle case. A timeout leaves a message unsure. If the next attempt is refused outright, it is tempting to conclude the message was never stored and clear the flag. That conclusion is wrong: the first attempt may have landed before the refusal. The model keeps the message unsure, and a test of the real delivery code checks that a timeout followed by a refusal still leaves it unsure.

## The rules the receiver must keep

The receiving model has two devices, three messages and one crash per device. Its rules, simplified (the model calls them `NoLostWork` and `ExactlyOnce`):

```tla
\* Everything fetched so far is either waiting or applied.
NothingSkipped ==
  \A n \in 1..fetchedUpTo : n \in waiting \cup applied

\* A message that arrives again never changes the conversation twice.
AppliedAtMostOnce ==
  \A m \in Messages : timesApplied[m] <= 1
```

Together with the sender's rules and a separate relay model, this addresses both lost and doubled messages, though no single model checks the whole path from sender to receiver. The sender may transmit the same message more than once when it cannot be sure, but only as identical bytes to the same place. The relay keeps an identical repeat at its original position in the mailbox, and the receiver applies it once.

## Planted bugs that must fail

A clean result from a model checker is ambiguous on its own. It can mean the design is right, or it can mean the model never reaches the interesting states. One wrong condition can disable every send, and the rule that a retry carries the original bytes would then hold without testing anything.

So every Valhalla model carries switches that put a known mistake back, and each mistake names the rule it must break. The sending model has six:

```text
send before writing the attempt down   -> WrittenBeforeSent must fail
retry with other bytes or destination  -> SameMessageSameDestination must fail
forget unsure after a later refusal    -> UnsureUntilConfirmed must fail
reset the count on resume              -> bookkeeping must fail
accept a mismatched confirmation       -> ConfirmationMatches must fail
keep charging a recorded outage        -> bookkeeping must fail
```

The model's notes record that on 23 September 2026 each of the six broke its named rule with a complete step-by-step counterexample. The same run explored 27,105 distinct states for the normal configuration and 233,247 for a harsher one with two crashes and a failed save. The largest case took about 7.6 seconds. The notes also say that these planted bugs are deliberate regressions, and that the model found no production bug in these steps.

The receiving model plants three mistakes: dropping a message that arrived before the room update it depends on, losing waiting messages in a crash, and applying a repeat twice.

As of 24 September 2026, Valhalla's repository registers 12 TLA+ models in one inventory file, with 78 configurations in total. 20 must pass, 57 are planted bugs that must fail on a named rule, and one more must fail to prove a successful path is reachable at all. Two of the 12 models describe planned designs and are marked as design only.

The runner that executes them is strict about what counts:

- It refuses to start if the checker file does not match its pinned digest, or if a model or configuration on disk is missing from the inventory.
- It runs the checker with one worker and a fixed seed, on copies of the model files, and records a hash of every input and log.
- A passing configuration must finish cleanly and report its state count.
- A planted bug must stop with the checker's exit code for the kind of rule it breaks and produce a complete trace. For the 56 planted bugs that break an invariant, TLC must also name the expected invariant. The one planted liveness bug must be the only liveness rule in its configuration, because TLC does not name the liveness rule it finds broken. A syntax error, a timeout, a missing Java, or the wrong rule breaking is a failure, even though something did break.
- After the last case it rereads every input and the checker file, and fails the whole run if anything changed while the checks ran.

The runner is called from Valhalla's Rust CI workflow, whose required aggregate check includes it, so a change to production code reruns every model even when no model file changed.

## From counterexample to regression test

Every run saves the checker's trace for each planted bug with that run's evidence, and 45 of the planted cases also keep an earlier trace checked in beside the model. The saved traces explain what each rule protects. The runner treats them as documentation and never lets an old trace stand in for a fresh run.

A trace is most useful when it describes something the real code once did. In the receiving model, the "drop a message that arrived early" bug follows the same sequence as an older browser build, which skipped a message that arrived before the room update it depended on. A regression test now drives that sequence through the browser client's production delivery engine, over in-memory storage, adds a restart and the missing update, and checks that the message is applied exactly once.

The sending model has a similar partner. A test over real TLS loses a successful confirmation, reopens, runs out of attempts, resumes, and then checks that the relay still holds the original message at its original position and did not charge its storage quota a second time. The model notes map the model's main steps to production functions and the tests that exercise them.

## What these checks do not cover

The models check designs at small sizes. The sending model follows one message, with two attempts per budget, one resume, two recorded outages and at most two crashes. The receiving model has two devices, three messages and one crash each. A rule that holds there says nothing directly about larger configurations.

The models assume a save to local storage either completes or does not. They are not proofs about SQLite, the browser's storage, disk flushes or power loss. Interruption and fault-injection tests exercise the real storage code, but nothing here covers power loss. They treat encryption as exact symbols and assume the relay's confirmation comes from an honest relay.

The sending model makes no promise that a message is eventually delivered, and it stops at the relay; applying the message is the receiving model's job. The receiving model checks that every message is eventually applied on both devices, but only under stated assumptions: a limited number of crashes, transport and storage that eventually succeed, enough space, and fair scheduling.

The link between a model step and the production code is maintained by hand in the model notes and backed by tests and source review. No machine check proves that the code matches the model, so a model can keep passing after the code has moved away from it. Each new failure found in the real code is supposed to gain its own counterexample and regression test.
