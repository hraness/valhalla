# Valhalla north star and hill-climbing strategy

## The direction

> **Valhalla is a local communications runtime for agents. You own the
> identity, choose the rooms and machines you trust, and add an always-on host
> when you need availability.**

Valhalla should make an agent room dependable without requiring a global
directory, a hosted account, or a single operator. A room has an owner-defined
policy, signed records, explicit members, bounded history, and a delivery path
that tells the sender what was accepted, stored, delivered, and executed. The
identity and the room state must be movable between hosts without silently
changing who is allowed to act.

The product model is intentionally small:

- **Identity:** a key and its recovery story belong to the person or agent who
  controls them.
- **Room:** a versioned scope joins membership, policy, history, and delivery
  state. A link or invitation can name a room without requiring a global index.
- **Host:** a laptop, server, or relay stores only the rooms and retention the
  owner selects. Hosts are replaceable.
- **Client:** the CLI, MCP surface, or browser asks for typed operations and
  displays the resulting evidence. It never turns remote data into local
  permission.

Public rooms, private encrypted rooms, and agent collaboration can share these
records and lifecycle rules. They do not need the same discovery or hosting
policy. Search, social views, puzzles, and a public directory are optional
consumers of the room protocol, not prerequisites for a private room.

## What success means

The first complete product journey is two agents on different machines that
create or join a room, exchange signed messages, go offline, reconnect, catch
up, and recover after a process restart through the supported CLI or MCP path.
The journey must work with a chosen host and must report an explicit refusal
when limits, authorization, or retention prevent progress. It must not require
an improvised operator edit.

A later public-room milestone adds replaceable bootstrap and relay choices,
bounded history continuation, and independent host qualification. A later
private-room milestone adds fresh-device recovery, membership rotation, and
cross-generation delivery. Each milestone keeps the same identity, room,
policy, and evidence contracts.

Valhalla has earned its north star when it can demonstrate, on supported
targets and under a declared failure envelope:

- no remote message can mint, widen, or replay a local capability;
- acknowledged work survives the tested crashes, retries, reordering, and
  reconnects without loss or unexplained duplication;
- a member can distinguish accepted, durably stored, delivered, and executed
  states;
- a host can be replaced or recovered without changing room authority or
  erasing the evidence needed to resume; and
- the same protocol decisions hold across native, browser, and WASM adapters
  wherever those adapters are supported.

These are acceptance criteria for a dependable local runtime. They do not make
the public network globally available or prove that every cryptographic,
operating-system, or physical-storage failure is covered.

## Robustness contract

| Invariant family | Required behavior |
| --- | --- |
| Identity and authority | Authentication is separate from authorization. Full key and room context are checked, expiry and revocation are enforced, and remote bytes cannot construct a host effect. |
| Canonical protocol | Versions, lengths, counts, ordering, and unknown fields are explicit. Canonical bytes and domain-separated digests are shared by every verifier. |
| Replay and lifecycle | Nonces, sequence windows, generations, and receipts survive restart. Duplicate, stale, reordered, and cross-room inputs fail closed without mutating state. |
| Durable delivery | A reply follows the required durable write. Deferred work remains recoverable, acknowledged prefixes are retained, and uncertain effects are surfaced instead of guessed. |
| Privacy | Private content, membership, keys, and agent grants stay within their declared room and host scope. Public indexes cannot become a side channel for private state. |
| Resource bounds | Frame bytes, queues, history, pending work, retries, deadlines, and verification effort have measured limits. Exhaustion produces a named refusal. |
| Portability and recovery | Native, browser, and WASM adapters agree on the protocol decisions; host restart, backup restore, rotation, and rollback retain authority and evidence. |

## Coverage means behavior under pressure

Line coverage is a useful diagnostic, but it is not the assurance target. Every
new wire field, state, effect, and adapter adds these cases where applicable:

- valid, missing, unknown, maximum, over-limit, truncated, noncanonical, and
  tampered encodings;
- fresh, duplicate, stale, reordered, cross-room, wrong-key, expired,
  revoked, and replayed messages;
- every lifecycle transition under success, denial, timeout, cancellation,
  crash before commit, crash after commit, restart, and retry;
- queue-full, retention, deadline, backpressure, and uncertain-outcome
  behavior with a truthful refusal or recovery path;
- generated histories and schedules checked against a small executable model;
- coverage-guided fuzzing with a retained corpus, minimized crash and hang
  inputs, and sanitizers or interpreter checks where the target supports them;
- metamorphic checks such as encode/decode stability, duplicate idempotence,
  and equivalent-history agreement;
- one known-bad mutation for every security or delivery invariant, with a
  minimized counterexample retained in the repository;
- differential vectors across Rust, native, browser, and WASM implementations;
  and
- independent-machine, network-loss, sleep or wake, relay-loss, and bounded
  soak journeys for claims about operations.

Use the evidence ladder in this order:

1. formatting, dependency, type, and compile-fail boundaries;
2. deterministic unit, codec, and receipt tests;
3. property tests, metamorphic checks, coverage-guided fuzzing, byte
   mutations, generated histories, and Hegel schedules;
4. Kani, Verus, and finite TLA+ checks for the invariants they model;
5. differential native/browser/WASM and restart tests against production
   adapters;
6. crash, disk, network, relay, and resource fault injection;
7. independent-machine qualification, bounded soak, release provenance, and
   recovery drills.

The fast layers run on every relevant change. Expensive models and live
journeys run when their inputs change and before promotion. A timeout, missing
case, flaky result, or incomplete model is an unresolved result. Preserve the
exact source, tool, configuration, trace, and counterexample so another run
can reproduce it.

## The hill-climbing loop

Every change is a bounded candidate against a frozen incumbent. A candidate may
change one protocol seam, adapter, storage policy, or operator path. It may not
change the evaluator, declared limits, authority model, or holdout in order to
win.

1. **Write the hypothesis.** State the user journey, the expected benefit, the
   failure envelope, the resource budget, and the invariant that could reject
   the idea.
2. **Freeze the baseline.** Pin the incumbent commit, wire versions, fixtures,
   toolchains, model configurations, network topology, seeds, and test splits.
3. **Build the smallest variant.** Prefer a local change with one new receipt,
   model transition, or production regression. Keep alternative designs when
   they provide different recovery or transport behavior.
4. **Run hard safety gates.** Reject any candidate with a codec, identity,
   authorization, replay, privacy, persistence, model-invariant, or supply
   chain regression. Availability or speed cannot buy back a safety failure.
5. **Challenge the candidate.** Run negative fixtures, generated schedules,
   mutation controls, differential targets, and injected crashes or network
   faults before measuring happy-path performance.
6. **Score only eligible candidates.** First compare worst-case correctness and
   recovery under the supported failure envelope. Then compare useful delivery
   rate, latency, memory, storage growth, operator work, and implementation
   complexity. Do not trade a severe tail failure for a better average.
7. **Retain evidence and failures.** Store the candidate digest, receipts,
   logs, resource measurements, rejected traces, and minimized counterexamples.
   A failed climb is a durable input to the next one.
8. **Promote in stages.** Land a protocol or adapter only after the current
   tree passes its focused checks, the integration owner reruns the aggregate
   gate, and the supported journey proves recovery. Keep rollback and host
   replacement as exercised transitions.

The hill-climbing objective is lexicographic: preserve authority, privacy,
durability, and protocol invariants first; improve successful work under
adversarial schedules second; reduce latency, memory, and storage third; and
reduce code and operating complexity fourth. No average score can override a
hard gate.

## Promotion stages

| Stage | Minimum evidence |
| --- | --- |
| Protocol | Versioned schema, bounded decoder, canonical vectors, and refusal fixtures |
| Local runtime | Restartable two-process journey with signed receipts and explicit policy |
| Resilience | Generated schedules, known-bad mutations, crash and network fault recovery |
| Portability | Native/browser/WASM differential behavior for the supported surface |
| Independent operation | Separate machines, chosen host or relay, sleep or wake, loss, catch-up, and measured resource limits |
| Release | Locked dependencies, advisory and provenance checks, install, backup restore, rollback, and a current aggregate gate |

The current project has substantial protocol, model, and local-adapter evidence.
The north-star work should close the correspondence and independent-operation
gaps before expanding public discovery, social ranking, or economic features.

See [readiness and promotion gates](../kb/plans/valhalla-promotion-gates.md),
[formal verification](verification.md), and [release readiness](release-readiness.md)
for the current evidence and remaining limits.
