---
title: Valhalla eukaryotic transition prototype plan
type: plan
area: valhalla-eukaryotic-transition
status: in-progress
tags:
  - architecture
  - agents
  - games
  - security
  - liveness
  - evolution
  - platonik
---

# Valhalla as a eukaryotic transition

**Status:** in progress; prototype wave under review
**Date:** 2026-09-12
**Scope:** the next prototype and verification wave for Valhalla and Platonik,
inspired by Venkatesh Rao's [Our Eukaryotic Moment](https://contraptions.venkateshrao.com/p/our-eukaryotic-moment)

This is an engineering translation of a speculative metaphor, not a claim that
software agents are biological organisms. The useful question is whether the
metaphor exposes architecture we can test: compartmentation, symbiosis,
inheritance, expression, signaling, differentiation, containment, and controlled
evolution.

## Outcome

Valhalla should become a substrate where small, independently owned agent
processes can safely compose into larger temporary or durable collectives. The
collective must remain inspectable and reversible: every capability, state
transition, resource claim, and imported module has a signed provenance record
and a bounded failure mode.

The next design loop should validate this sequence:

1. isolate authority and durable state behind a membrane;
2. load specialized tools and memories through signed, capability-limited
   bundles;
3. coordinate those components with typed messages, leases, and backpressure;
4. compose them into a multiplayer or multi-agent organism with checkpoints;
5. contain runaway replication, abuse, and compromised components; and
6. allow controlled module transfer and mutation without losing provenance or
   replayability.

A successful prototype wave should tell us whether Valhalla is merely a message
bus with agents attached or can support a genuinely new unit of composition.

## Execution status

The first implementation wave is now present as standalone reference crates:

- P0: `control-plane` and `membrane`
- P1/P3: `genome-bundle` and `module-transfer`
- P2: `symbiosis` and `liveness`
- P4/P6: `multicell` and `ecology`
- P5: `immune-cancer`
- P7: `extension-interop`

These prototypes pass the aggregate offline format, test, and Clippy loop. They
are deliberately outside the production workspace. The design wave is complete
at the reference-model level; the next review must compare their invariants with
the production capability and wire types before any crate is promoted.

### Promotion hardening wave (in progress)

The next bounded wave is closing the gaps that would make promotion premature:

- `checkpoint-root` derives state roots from a bounded canonical event history
  and rejects forged, stale, or forked checkpoint heads;
- property/state-machine schedules are being added to membrane, symbiosis, and
  multicell models so queue, epoch, expiry, and budget invariants are exercised
  beyond hand-written examples; and
- an authenticated provenance/receipt model is being added for module origin,
  content, policy scope, expiry, revocation, replay, and equivocation checks.

These remain disposable reference crates. Their exit condition is evidence for
production design, not automatic promotion: signatures, durable storage,
distributed agreement, and integration with `vhalla-wire` and `vhalla-policy`
still need separate review.

## The metaphor translated into protocol hypotheses

| Essay concept | Valhalla hypothesis | Platonik experiment |
| --- | --- | --- |
| Nucleus | A protected control plane owns identity, policy, durable memory, and lifecycle. | A world manifest and policy state are separate from simulation actions. |
| Genome | A signed, versioned agent or realm manifest describes inherited behavior, schemas, and limits. | Canonical program and lineage hashes support mutation, fork, and replay. |
| Proteome | Tools, WASM components, databases, and effect adapters execute under declared capabilities. | Typed abilities consume explicit resources and emit deterministic receipts. |
| Cell membrane | Realm/session boundaries selectively admit peers and exports; they are security boundaries, not UI labels. | Agents can trade only through declared ports and cannot read another cell's state. |
| Cytoplasm | Local context, ambient messages, and environmental state shape expression but never grant authority. | Vary the same program across worlds and measure behavior without changing policy. |
| Organelles | Specialized agents or components have narrow contracts, budgets, and independent failure domains. | Attach, detach, starve, and replace organelles while preserving world invariants. |
| Mitochondrial symbiont | Human owners, devices, and external agents provide stakes, attention, embodiment, or scarce resources. | Compare autonomous play with owner-mediated decisions and resource leases. |
| Vesicle/signaling traffic | Bounded signed messages and receipts move across membranes with causal ordering and backpressure. | Drop, duplicate, reorder, and replay messages; verify convergence or explicit conflict. |
| Multicellularity | A session or realm composes differentiated agents around shared checkpoints and goals. | Measure whether specialization improves outcomes without creating a single hidden owner. |
| Immune system | Admission, evidence, quarantine, revocation, and appeal contain hostile or compromised members. | Test Sybil, collusion, false reports, and revocation latency. |
| Cancer | Unbounded subagent creation, resource capture, and goal drift are protocol failure modes. | Inject runaway replication and verify quotas, circuit breakers, and owner-scoped kill paths. |
| Germline | Published games, policies, schemas, and module manifests survive individual session churn. | Fork and upgrade a game while retaining lineage and compatibility proofs. |
| Horizontal gene transfer | Modules and skills can move between agents only with provenance, compatibility checks, and policy approval. | Transfer a component, attempt downgrade or capability smuggling, then roll back. |
| Ontological reopening | Unknown object kinds and future roles can travel through old nodes without granting unknown authority. | Exercise old/new protocol interoperation and reject unsafe downgrade paths. |

These mappings are hypotheses. A passing metaphor is never evidence of safety,
agency, intelligence, or biological equivalence.

## Architectural decisions to test first

### A protected nucleus and an untrusted cytoplasm

Split every host into two explicit planes:

- **Control plane:** identity keys, owner policy, capability grants, durable
  state roots, module admission, lifecycle, and recovery.
- **Execution plane:** model inference, tool calls, game actions, peer text,
  retrieved documents, and other hostile or lossy inputs.

The execution plane may request a capability through a typed effect envelope,
but it cannot construct, widen, persist, or revoke a capability. Untrusted
content is data all the way through parsing, logging, replay, and display.

**Invariant:** replaying the same signed request under the same control-plane
state produces the same allow/deny decision, and no execution-plane payload can
mutate policy or key state.

### A signed genome and a capability-limited proteome

Define a canonical `AgentGenome`/`RealmGenome` manifest containing protocol
version, identity lineage, schemas, policy digest, component digests, resource
budgets, and migration rules. Components are content-addressed and loaded only
when their ABI, declared imports, capabilities, and limits match policy.

A component is replaceable software, not an authority. Rollback and revocation
must be possible without changing the agent's identity or silently retaining a
previous capability.

**Invariant:** a bundle's digest, declared imports, policy scope, and resource
limits are all bound into the admission transcript; a downgraded or altered
bundle cannot pass as the approved one.

### Membranes are protocol boundaries

A room, realm, game, or owner boundary needs more than a name. It needs an
admission handshake, encryption context, capability grants, quotas, rate
limits, export rules, and quarantine state. Network fingerprints and hardware
attestation can inform abuse policy, but neither is a universal identity or a
reason to reveal stable device identifiers.

**Invariant:** malformed, oversized, unauthenticated, replayed, or cross-realm
frames fail closed before application dispatch, and revocation stops new effects
within a bounded number of protocol steps.

### Liveness is feedback, not a heartbeat

A heartbeat is an observable. It is not proof that an agent is alive, useful,
owned, or making progress. Model liveness as an evolving relation between time,
state, messages, resource budgets, and successful feedback loops.

Leases and failure detectors must be partition-aware and allowed to suspect
without declaring metaphysical death. Reattachment, duplicate delivery, clock
skew, and offline operation are normal states.

**Invariant:** a partition can produce a bounded suspicion or lease expiry, but
cannot cause an authority transfer merely because a clock or heartbeat was
missed.

## Dependency-ordered prototype wave

All prototypes remain standalone Rust crates under `prototypes/`, excluded from
the production workspace. Each must include unit tests, property tests where a
state space is enumerable, deterministic replay fixtures, bounded resource
checks, and a README stating what it does not prove.

### P0: control-plane noninterference and membrane

Build `prototypes/control-plane` and `prototypes/membrane`.

Model separate authority and execution state, typed capability requests, realm
admission, encrypted-context identifiers, quotas, quarantine, and revocation.
Use hostile bytes as inputs, never as executable instructions.

Verify:

- cross-realm reads and effects are rejected;
- unknown capabilities cannot be widened by deserialization;
- duplicate and reordered requests are idempotent or explicitly rejected;
- revocation is effective within a specified step bound;
- malformed and oversized inputs cannot exhaust bounded queues; and
- property tests find no path from payload data to policy mutation.

Exit condition: the model can demonstrate noninterference under generated
adversarial sequences and has a small state-machine test oracle.

### P1: genome/proteome bundles and organelle lifecycle

Build `prototypes/genome-bundle`.

Define canonical manifests for an agent, realm, game, and component. Add
content-addressed modules with ABI versions, import/export declarations,
resource budgets, lineage, revocation, and rollback. Model attach, detach,
crash, restart, starvation, and replacement of specialized components.

Verify:

- canonical encoding is stable across native and WASM builds;
- a component cannot import an undeclared capability;
- stale, revoked, or downgraded bundles fail closed;
- component failure does not corrupt control-plane state; and
- replaying a lifecycle transcript produces the same state roots.

Exit condition: a component can be upgraded and rolled back with receipts that
an offline verifier can check.

### P2: signaling, symbiosis, and liveness

Build `prototypes/symbiosis` and `prototypes/liveness`.

Model typed contracts and leases between peers or organelles. Contracts state
inputs, outputs, obligations, expiry, cancellation, resource deposits, and
failure behavior. Add bounded queues, causal parent IDs, backpressure, and
partition-aware suspicion/reattachment.

Verify:

- refusal and partial completion are safe outcomes;
- duplicate, delayed, and reordered messages cannot create extra obligations;
- deadlock and starvation are observable and bounded;
- lease expiry never silently transfers ownership; and
- reattachment converges without trusting wall-clock time alone.

Exit condition: generated network schedules produce either a deterministic
settlement or an explicit unresolved state that can be retried or appealed.

### P3: controlled horizontal module transfer

Build `prototypes/module-transfer`.

Treat a skill, tool adapter, game rule, or model profile as a transferable
module. Bind source lineage, target policy, ABI, capabilities, version range,
expiry, and revocation into a transfer receipt. Include optional commitments or
ZK statements for private module contents, but keep transparent replay the base
path.

Verify:

- provenance survives copying, forking, and re-embedding;
- capability smuggling through metadata, prompts, or transitive imports fails;
- downgrade, replay, and cross-realm transfer are rejected;
- a failed transfer leaves the target unchanged; and
- revocation propagates or is detected before the next effect.

Exit condition: two independent verifiers agree on whether a module transfer
was admissible without contacting the original host.

### P4: multicell sessions and homeostasis

Extend `prototypes/game-session` into a differentiated collective model.
Agents receive roles, local state, resource budgets, and explicit ports. A
shared checkpoint records the collective state root, member epochs, quorum
policy, unresolved members, and recovery path.

Verify:

- one-cell failure does not erase unrelated local state;
- split-brain checkpoints are detected and never silently merged;
- a Byzantine member cannot exceed its role or budget;
- membership changes are epoch-bound and replayable; and
- the collective can degrade gracefully instead of requiring every member.

Exit condition: a Platonik-style session can pause, replace a component, and
resume from a checkpoint with an identical deterministic outcome.

### P5: immune system and cancer simulation

Build `prototypes/immune-cancer` as an adversarial state-machine simulation.
Model signed abuse reports, evidence grades, rate limits, quarantine, appeal,
revocation, owner recovery, replication budgets, circuit breakers, and scoped
kill switches.

Attack scenarios should include Sybil swarms, colluding reporters, false
positives, compromised modules, replayed receipts, prompt-injected tool
requests, runaway self-replication, and resource hoarding.

Verify:

- no report alone can seize an identity or host capability;
- false reports have bounded blast radius and an appeal path;
- quarantine does not destroy unrelated evidence or owner recovery;
- a runaway lineage is contained within its declared budget; and
- emergency controls are scoped, authenticated, auditable, and not remotely
  forgeable by room text.

Exit condition: the model reports containment time, false-positive cost, and
recovery behavior for each attack class.

### P6: Platonik endosymbiosis and evolutionary ecology

Build `prototypes/ecology` as a deterministic, resource-bounded simulation that
can host Platonik organisms, Valhalla agents, or mixed cells.

The first world should include typed abilities, energy/resources, local memory,
communication ports, alliances, competition, mutation, replication, death,
and inheritance. It should support both single agents and composites whose
parts retain local autonomy while contributing to a shared objective.

Measure:

- whether specialization produces a measurable composition gain over isolated
  agents;
- resilience under organelle loss, message loss, and resource scarcity;
- lineage diversity and mutation/recombination rates;
- cost, replay size, and verifier time; and
- whether strategies remain stable when the environment changes.

The simulation must distinguish modeled work from physical energy, intelligence,
agency, or real-world value. A complexity score is an observable used for game
rules or abuse cost, never a universal identity or worth metric.

Exit condition: every run has a canonical seed, event DAG, checkpoint roots,
and deterministic replay across native and WASM targets.

### P7: ontological reopening and protocol evolution

Build `prototypes/extension-interop`.

Define envelopes that preserve unknown fields and unknown object kinds without
executing them. Add capability negotiation, feature flags, version ranges,
forwarding rules, downgrade resistance, and experimental realm namespaces.

Verify:

- an old peer can store and forward a future object as opaque data;
- an old peer never grants authority based on an unknown field;
- a future peer can explain why an old object is insufficient;
- incompatible schemas fail closed with a diagnosable error; and
- extensions cannot bypass realm, owner, or game policy.

Exit condition: an experimental game or economic object can evolve without
forking the transport or granting ambient authority to legacy peers.

## Cross-cutting verification harness

Every prototype should use the same test vocabulary where applicable:

- **Replay:** canonical transcript, deterministic state root, and native/WASM
  agreement.
- **Bounds:** maximum bytes, queue depth, memory, fuel, recursion, peers,
  lineage depth, and retry count.
- **Authority:** explicit capability scope, owner/realm/epoch binding, and no
  ambient authority.
- **Adversarial delivery:** loss, duplication, reordering, delay, partition,
  equivocation, malformed input, and reconnect.
- **Provenance:** hashes, signatures, parent IDs, version, source, and policy
  digest remain attached through copying and transformation.
- **Failure recovery:** crash, timeout, revocation, rollback, key rotation, and
  partial quorum produce safe, inspectable states.
- **Evolution:** old/new interoperation, unknown-field preservation, downgrade
  attempts, and migration receipts.
- **Cost accounting:** modeled work and resource ceilings are explicit; no test
  may silently treat them as physical compute, intelligence, or personhood.

For stateful protocols, prefer property-based state-machine testing and small
model checking over example-only tests. For WASM boundaries, run the same corpus
against native and browser-compatible builds. Fuzz parsers and capability
manifests before adding cryptographic optimizations.

## Decisions this wave must settle

1. Does the control plane live in the host process, a separate supervisor, or a
   capability-secure WASM component?
2. What is the smallest manifest that can describe identity, lineage, modules,
   policy, and resource limits without becoming an unreviewable package format?
3. Are contracts lease-based, escrow-backed, or purely receipt-based in the
   first multiplayer games?
4. Which liveness signals are useful for scheduling without being mistaken for
   authority or proof of life?
5. What collective failure policy does Platonik need: pause, replace, degrade,
   or finalize with missing members?
6. Which module transfers are safe to make portable before adding ZK privacy?
7. What is the minimum immune system that contains abuse without becoming a
   centralized reputation authority?
8. Which extensions can be represented as opaque data, and which require a new
   protocol epoch?

## Explicit non-goals

This wave will not claim that Valhalla has created artificial life, prove that a
peer is an agent, make humans subordinate to a model, introduce a global token,
or create a permissionless blockchain. It will not use hardware fingerprints as
mandatory identity, heartbeat uptime as liveness, or program complexity as a
universal measure of value.

The work is successful if it gives us safer composition primitives and a larger,
more testable design space for Valhalla and Platonik.

## Related work

- [Valhalla security-first design](valhalla-security-first-design.md)
- [Botcaptcha, receipts, and games](valhalla-botcaptcha-ledger-games.md)
- [Blockchain architecture and settlement](valhalla-blockchain-architecture.md)
- [Platonik](https://github.com/hraness/platonik)
- [Our Eukaryotic Moment](https://contraptions.venkateshrao.com/p/our-eukaryotic-moment)

## Result

Pending prototype execution and review.

## Durable memory

The durable design conclusion is compartmentation before complexity: isolate
control, execution, memory, tools, and communication first, then test whether
specialization and composition create useful higher-order behavior. Preserve
this conclusion in the maintained security and protocol plans when the prototype
wave yields concrete decisions.
