---
title: Valhalla global public-network north star
type: plan
area: valhalla-global-network
status: in-progress
tags:
  - architecture
  - p2p
  - public-network
  - eventual-consistency
  - scale
  - railway
  - verification
---

# Valhalla global public-network north star

**Status:** in progress; architecture selected, implementation gates open

**Outcome:** make public Valhalla rooms usable over a global peer-to-peer
network. Independent peers discover one another, exchange signed room events,
and repair local history after churn and partitions. Users can run a peer on a
laptop, server, browser, or ephemeral function. A declared custody class tells
them what persistence and recovery they can rely on.

## Context and current boundary

Valhalla already contains signed public-room records, local author outboxes,
bounded peer discovery, native serving, browser publishing, private-room
primitives, persistent stores, and formal/properties evidence. The current
release and Railway soak prove bounded operator-controlled paths. They do not
prove permissionless discovery, direct browser-to-browser operation, independent
replication, global convergence, or durable public history after provider loss.

The north star keeps public rooms as the primary product. Private rooms remain
a separate encrypted protocol and may reuse transport, custody, and recovery
machinery where the contracts are compatible.

## Decision

Use two planes. The existing validator/journal machinery is the selected
candidate for a shared directory, globally unique aliases, and validator
epochs; live multi-validator recovery and finality receipts remain open. Room
moderation is room-local signed policy, optionally referenced by the directory,
and is never a universal global censor. The data plane is a room-scoped signed event DAG
with causal/eventual consistency, deterministic merge, and bounded epidemic
anti-entropy. Use a provider/rendezvous DHT and signed manifests for discovery;
direct QUIC/WebRTC, WebTransport only for browser-to-server or relay paths, and
relay fallback for reachability; and
explicit `gossip`, `regional`, and `archive` custody classes for retention. Do
not make a blockchain, global sequencer for every message, hosted full-text
directory, or token economy a prerequisite for public messaging.

This choice preserves availability during partitions, makes locality visible,
and lets ephemeral peers participate without making an impossible durability
promise. Strong ordering is opt-in per room through a future room-local
sequencer or quorum checkpoint.

## Scope

- public room creation, discovery, join, publish, read, replay, and repair;
- control-plane alias, policy, moderation, and validator-epoch changes with
  explicit finality separate from data-plane convergence;
- causal event envelopes, deterministic merge, retention floors, and receipts;
- bootstrap diversity, provider discovery, NAT traversal, relays, and peer exchange;
- measured regional and archive custody with failure-domain declarations;
- abuse controls, quotas, admission puzzles, moderation records, and key rotation;
- deterministic simulation, local mesh, Railway qualification, and independent-host gates;
- unattended bounded experiments that retain artifacts and receipts without
  silently promoting protocol or trust-root changes.

## Non-goals for this roadmap

- a global total order for every room;
- anonymity or protection from traffic analysis;
- a blockchain or transferable token before a demonstrated product need;
- promising permanent storage from peer count alone;
- replacing room policy or moderation with a universal algorithm;
- treating one Railway project as independent global infrastructure.

## Dependency-ordered phases

### Phase 0 — measurement and experiment substrate

Freeze a topology/workload manifest, receipt schema, event counters, resource
sampling, failure scheduler, and bounded unattended runner. Establish the
Railway project with at least three services (validator, durable relay/replica,
and disposable churn/fault injector), persistent volumes, region/failure-domain
labels, health/metrics export, monthly budget and per-run egress/volume caps,
and a teardown/recovery procedure. Record project/environment/service/volume IDs,
region labels, health endpoints, image digests, and stop/recovery commands in a
private machine-local config. Keep credentials out of the repository and use a
short-lived provider identity where Railway supports one. The preflight fails
closed when auth is expired or no project is linked; it never creates a new
project implicitly. The watchdog records process/volume cleanup and lease
release, and can recover after a runner crash.

**Exit:** the same seeded run replays locally and on Railway; every result binds
the exact Git SHA and manifests; a declared custody test retains its data after
the worker fault schedule; gossip loss is reported as expected best effort. A
40-pull or single-service run remains a baseline only. The unattended runner
refuses to start without numerical monthly, per-run egress, and per-run volume
caps recorded outside the repository.

### Phase 1 — room event core

Define the canonical public event envelope and room manifest. Add parent refs,
causal gaps, deterministic merge, duplicate/replay handling, retention floors,
and receipts that distinguish local acceptance, peer observation, and custody.
Keep the control-plane directory as the authority for aliases and policy
epochs; a full room genesis ID remains valid during directory partitions.
Bound per-author forks, frontier metadata, frame size, parent count/depth,
orphan bytes, signature/key counts, and retained DAG state with numeric limits
recorded in the workload manifest; exercise each limit in the oversized-flood
run.
Content-address policy/config snapshots and migration rules so identical
retained evidence implies identical replay. Define EventID as a domain-separated
hash of the canonical envelope and payload, excluding the signature and the
EventID field itself; bind realm, room genesis, author key, sequence,
predecessor, bounded parents, policy hash/epoch, and payload digest. Keep HLC,
if used, as a display/order hint only. Store bounded orphans, retain flagged
same-author forks, and merge with a stable causal tie-break. Compaction requires
a signed frontier checkpoint and replay anchor; an archive/provider proof is
required only when archive custody is claimed. Keep tombstone floors until the
declared custody class acknowledges the checkpoint. Generate cross-language
vectors and model-check concurrent authors, malformed inputs, key
rotation/revocation, tombstones, checkpoint/archive proofs, and mixed-version
replay.

**Exit:** native and browser clients converge on every accepted vector after
reordering, duplication, restart, and partition/heal simulation. A write
capability is bound to author key, room policy epoch, and quota; stale or
revoked capabilities fail closed or remain visibly pending, and epoch rotation
replay is covered by a vector.

### Phase 2 — multi-provider reachability

Add signed provider advertisements, provider/rendezvous DHT lookup, peer
exchange, multiple bootstrap families, native QUIC and browser WebRTC adapters,
WebTransport only for browser-to-server/relay paths, and bounded relays. Do not
turn the DHT into a global full-text or alias index. Signed advertisements are
hints: challenge endpoint control on dial, pin the returned transport identity,
require k-of-m independent lookup responses with operator/ASN/address-family
diversity, and verify signed record sequence and TTL. Detect eclipse risk from
neighbor diversity, check DNS rebinding/SSRF boundaries, and apply lookup
quotas and anti-poisoning rules. Fresh clients still need an independently
obtained bootstrap pin or room invite; the DHT cannot bootstrap from nothing.
Separate transport keys from room/application keys. Bound learned peers,
advertisement age, lookup work, and relay bytes. Relays enforce per-peer/room
byte and age caps, backpressure or disconnect slow readers, and emit an
explicit drop/NACK receipt; a relay never claims regional/archive custody
without a durable receipt. Exercise NAT classes, browser suspension, address
churn, and bootstrap withdrawal.

**Exit:** fresh clients reach two independently keyed peers within 10 seconds
from a verified bootstrap pin, survive withdrawal of one bootstrap family, and
fall back through a bounded relay when direct paths fail; no single operator,
account, ASN, or failure domain exceeds the diversity target.

The onboarding gate is part of every later phase: a fresh laptop, browser, or
ephemeral worker can generate an identity, verify a bootstrap pin, resolve a
room genesis or committed alias, join, post/read, restart, and show custody and
convergence state without manual key copying. Install-to-first-verified-message,
reconnect time, and failure explanations are measured.

### Phase 3 — custody and anti-entropy

Implement custody-class negotiation, replica/provider manifests, locality-aware
placement, missing-range repair, and optional erasure-coded archive chunks.
Require signed retention receipts and verify retrieval after restart, provider
rotation, corruption, and failure-domain loss. Keep best-effort gossip visibly
separate from durable custody.

**Exit:** regional and archive experiments meet the retrieval targets in the
scale charter while a 30% churn run still converges retained room history.
Each retention receipt binds the exact event/range or chunk root, policy epoch,
provider and operator identity, failure-domain label, replica index, expiry,
and a retrieval challenge result.

### Phase 4 — public testnet

Run public rooms across at least three regions and multiple independently
controlled operators. Publish an incident/runbook surface, version/capability
negotiation, key rotation, room policy updates, and backwards-compatible
migrations. Exercise small-room gossip and hot-room topic sharding/edge
replicas only after deterministic shard assignment, overlap handoff,
cross-shard causal references, and no-loss/no-duplicate edge-failure tests
pass. Repeat the same manifests with local, Railway, and independent-host
lanes. The Railway qualification topology must include at least three services
with persistent volumes, a disposable churn/fault-injector service, region and
failure-domain labels, and exported health/metrics receipts; it cannot count as
independent-operator evidence.

**Exit:** the 100-peer gate passes, public operators can recover after a region
loss, bootstrap/provider root rotation has a dual-sign overlap and rollback
receipt, and all advertised guarantees link to receipts with explicit limits.

### Phase 5 — abuse, governance, and scale

Measure Sybil, replay, malformed-DAG, slow-reader, and oversized-event floods.
Tune quotas and bounded proof-of-work/Botcaptcha admission without making
ordinary reads depend on a token. Add moderation evidence, room-admin
rotation, protocol capability negotiation, and safe rolling upgrades.

Advance to 1,000 and 10,000 peers only after the previous gate remains green
under mixed versions and independent failure domains.

**Exit:** scale, abuse, portability, and convergence targets in
`docs/scale-measurements.md` pass with raw receipts and no unadvertised or
single-provider authority in the tested path. The selected realm committee and
its limits remain explicit control-plane dependencies.

### Phase 6 — global qualification and stewardship

Repeat the 1,000- and 10,000-peer workloads across at least five independently
controlled failure domains, multiple implementations, and a sustained retention
window. Qualify realm/alias bridge proofs, bootstrap family rotation, incident
disclosure, operator handoff, and a reproducible public evidence index. Keep
new economic, privacy, or anonymity mechanisms optional until their own threat
and recovery receipts exist.

**Exit:** the scale charter's global gates hold with confidence bounds and
independent-host evidence; a new operator can reproduce the published receipt,
recover a room after provider and realm-key rotation, and continue service
without relying on the original implementation team.

## Verification and delivery gates

Each phase has four gates: deterministic model/property checks; native/browser
conformance; live qualification on the declared lane; and independent review of
the receipt and its limits. Existing TLA+, Lean, Verus, Kani, and Rust property
checks remain useful for bounded protocol claims, but they do not substitute for
multi-host failure evidence.

No experiment may delete retained journals, reset author floors, replace a
network fingerprint, or silently change custody semantics. A failed or partial
run is retained as evidence with its cause and may not be promoted by silence.

## Recovery and rollback

Keep room manifests, event journals, WALs, custody receipts, and provider
advertisements versioned and append-only. Roll back a binary only to a version
that understands the retained format; use an explicit migration for incompatible
formats. If the DHT or relay lane fails, operators can use a pinned manifest and
direct peer addresses. If a custody provider is lost, re-replicate from verified
events before retiring its receipt chain. Never reset a sequence or erase a
history to clear a failed gate.

## Current evidence and next action

The existing Railway soak is the Phase 0 hosted-container baseline. Browser
access currently shows the existing `valhalla-private-host` production project
with four online services and four attached volumes. The account displays eight
days or $4.17 of trial capacity; it is not evidence for a month-long budget and
no paid upgrade is assumed. The observed IDs and a conservative local guard are
stored outside the repository at `/Users/bg/.config/valhalla/railway.json`.
The CLI is installed, but shell access still reports an expired OAuth refresh,
DNS failure, and no linked project; the machine runner must re-establish CLI
authority through the supported login/link flow before unattended qualification
runs can be trusted. The next implementation action is Phase 0's receipt
runner and provider setup, followed by the Phase 1 event-core contract.
