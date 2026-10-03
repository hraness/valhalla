# Valhalla scale and resilience measurements

This charter turns the public-network vision into experiments that can be
replayed and compared. A number without the topology, workload, failure model,
binary identity, and raw receipt is not a qualification claim.

## Baseline already available

The current Railway private-host soak sustained 3h16m of five-minute member
pulls. It recorded 40 pulls, 37 successful responses, one recovered wedge, and
one operator-caused failure; idle and pull latency were roughly one second end
to end. It exercised one hosted container and member reads only. It did not
exercise public publish, room rotation, discovery, browser delivery, or
independent custody. The local steel-thread round trip is currently about
11.3–11.6 seconds. Public activity append is a separate local-durable workload
and must be reported with its own p50/p95 receipt before it is used as a
performance comparison. Neither number is Internet qualification evidence.

## North-star targets

Targets below are promotion criteria to measure, not claims that the current
code already satisfies. Each target must be reported at p50, p95, p99, and by
region, transport, custody class, and peer implementation.

| Area | Initial target | Required failure test |
| --- | --- | --- |
| Bootstrap | 99% of fresh clients with an independently verified pin reach two independently keyed peers within 10 s | remove one bootstrap family and rotate addresses |
| Publish | 99% of accepted 1 KiB events receive a local durable receipt within 2 s | process restart during sign, queue, and send |
| Remote custody | p95 from local acceptance to a declared warm replica receipt is below 5 s | kill the first replica during delivery and retry exact bytes |
| Propagation | 99% of subscribed healthy peers in a 100-peer room observe a retained event within 30 s | 30% random churn and 10% delayed links |
| Convergence | after a healed partition, 99% of retained events converge within 10 min under 30% churn, then 99.99% at the 1,000-peer gate | two-region partition, concurrent authors, reordered delivery |
| Regional custody | `N=3,k=2` gives 99.99% retrieval of 24-hour events after one failure-domain loss, with p95 RTO below 60 s | kill one region and rotate providers |
| Archive custody | `N=5,k=3` or an explicitly declared erasure policy gives 99.999% retrieval of declared archive events over the retention window | remove one third of archive providers and corrupt samples |
| Discovery diversity | no operator, account, ASN, region, or storage failure-domain family accounts for more than 25% of successful joins | withdraw the largest family and repeat the run |
| Resource use | idle peer and relay memory, CPU, and bandwidth are recorded per connection and event; set release budgets from the first 100-peer baseline | slow readers, duplicate floods, and oversized frames |
| Portability | native Linux/macOS and browser clients pass the same vectors and replay receipts | mixed-version rolling upgrade and browser suspension |
| Abuse containment | one identity cannot exceed its declared room quota or consume unbounded relay/storage work | Sybil burst, replay flood, and malformed-DAG flood |
| Control finality | p99 directory/policy commit below 30 s while the control quorum is healthy | validator loss, delayed links, and epoch rotation |

The propagation and convergence denominators include only events within their
declared retention horizon and peers that were subscribed and healthy when the
workload was issued. Receipts report gossip, regional, and archive classes
separately, plus orphan, fork, tombstone, and stale-read-age counts. “Accepted”
never implies “globally observed.”

The 100-peer experiment is the first scale gate, not the final ambition. The
next gates are 1,000 peers across three regions and 10,000 peers across at
least five independently controlled failure domains. Message and room counts
are reported separately from peer counts so a large number of idle processes
cannot mask a small useful network. The first warm-custody gate is either
`N=3,k=2` across three failure domains (survive one domain loss) or `N=5,k=3`
across five domains (survive two). The receipt reports RPO, p95 RTO, quorum
acknowledgement, and whether a read came from a remaining replica or after
quorum re-formation; the room policy chooses the class.

The first resource envelope is intentionally explicit so the benchmark can
revise it with evidence: a native idle peer target of at most 64 MiB RSS, a
browser worker target of at most 32 MiB, a relay target of at most 1% CPU per
100 idle connections, a 2 s cold start for a disposable worker, and a 1 KiB
event budget of 4 KiB total network bytes per direct-path event at p95. Fanout,
anti-entropy, and relay bytes are reported separately per room workload.
These are qualification targets, not current capabilities. A revision records
the old and new target and the workload that justified it.

The first workload profiles are 100 peers at one 1 KiB message per second per
room and 1,000 peers at 0.1 message per second per room. Every report includes
CPU-ms/event, egress bytes/event, cost per million accepted and retrievable
events by custody class, cold-start success, and a bounded-memory result under
duplicate/orphan floods. Diversity is measured by independently controlled
operators, accounts, ASNs, regions, and storage failure domains.

## Comparative research track

“Post-SOTA” is a qualification outcome, not an assumption. Before using that
label, replay the same seeded workloads, topology, churn, and abuse schedules
against representative systems: Nostr relays with NIP-77 reconciliation,
Matrix/Conduit federation, Bluesky relay/PDS CAR sync, Secure Scuttlebutt or
Manyverse, P2Panda, libp2p GossipSub plus Kad-DHT, and Automerge Repo/Yjs.
Include Waku v2's relay/store/light-client split and RLN-style rate limiting in
the messaging comparison. Compare bootstrap and browser continuity, convergence time, egress per event,
custody RPO/RTO, recovery after provider loss, and abuse cost. Record protocol
version, deployment shape, and any feature that is not comparable; do not turn
a relay-local or federated result into a claim of global independence.

Add an operator-sustainability track: cost per million accepted and retrievable
events, volunteer or sponsored quota capacity, repair bandwidth, and the
failure mode when no operator is willing to host a declared custody class.
Valhalla can avoid a token prerequisite while still measuring how a global
network pays for durable anchors and abuse response.

Mobile continuity is a separate workload: measure wake or push delivery,
store-and-forward handoff to a durable anchor, reconnect after sleep, and
message loss under anchor rotation. Browser or serverless churn does not count
as mobile availability evidence by itself.

## Required receipt

Every run records the exact Git SHA, Cargo/Bun lockfile hashes, container or
image digest, Rust/Bun/browser toolchain, network and room manifests, peer and
operator identities, topology, workload generator, all topology/workload/churn
RNG seeds, failure schedule, scheduler version, environment resource limits,
raw event log, resource samples, and verifier version. The
receipt includes the number of accepted, delivered, retained, replayed, and
converged events. It distinguishes local acceptance from remote observation and
durable retrieval. Five-nines-style claims require at least 100,000 event
attempts or a reported confidence interval and failure upper bound; the current
40-pull Railway soak cannot support them. Latencies use monotonic send/receive
deltas or include a measured clock-skew bound; wall-clock timestamps alone do
not establish p95 or recovery time. Availability claims include a Wilson or
Clopper–Pearson interval, the signed-subscription health-window denominator,
and separate churn, cold-start, repair, and steady-state traffic; a peer that
left before an event is excluded from propagation coverage but counted in the
churn result.

## Experiment lanes

1. **Deterministic simulator.** Run `cargo run -p vhalla-public-sim --locked`
   with a committed seed/workload manifest to explore merge, anti-entropy,
   custody, and partition policies with replayable receipts before live work.
2. **Local multi-process mesh.** Exercise native and browser protocol vectors,
   crash recovery, bounded queues, and mixed versions on one machine.
3. **Railway qualification mesh.** Run reproducible multi-region or multi-service
   topologies with persistent volumes for regional custody and disposable
   workers for churn. Railway is an experiment substrate, never the trust root.
4. **Independent-host mesh.** Repeat the same manifest with operators and
   providers outside one Railway project before making a public availability
   claim.

## Guardrails for unattended hill climbing

An iteration may change one protocol or operational variable, runs the focused
receipt-producing experiment, and compares it with the previous accepted
baseline. It may retain an artifact and open a follow-up plan automatically,
but it may not promote a new protocol, delete retained history, rotate trust
roots, or spend outside the configured provider budget. A watchdog stops a run
on receipt loss, repeated crash loops, unexpected egress, or custody divergence.
