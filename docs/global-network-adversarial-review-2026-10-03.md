# Global-network adversarial review — 2026-10-03

This review is the pre-implementation challenge to the public-network north
star. It records what the current tree proves, what the selected architecture
still assumes, and the experiments that must falsify those assumptions. It is
not a public-network qualification report.

## Current evidence boundary

The public crates currently provide a certified directory replay client, signed
peer advertisements and discovery records, and a bounded public activity
protocol. Activity is an author-scoped numbered chain with a local durable
cursor. It is not yet a room-wide event DAG, a DHT, a multi-provider custody
protocol, or a direct browser-to-browser mesh. The current Railway evidence is
an operator-controlled private host and cannot establish independent public
replication, global discovery, or recovery after correlated provider loss.

That boundary is useful: it gives us reusable signing, scope, replay, and
receipt primitives without letting a local receipt become a global guarantee.
Every new public feature must preserve that distinction in its API, receipt,
and documentation.

## State-of-the-art challenge

The architecture was compared against the relevant families rather than one
nominal competitor:

| Family | Keep | Boundary or risk to measure |
| --- | --- | --- |
| libp2p GossipSub + Kad-DHT | scored peer exchange, push latency, provider lookup | eclipse, Sybil pressure, mesh churn, and DHT poisoning |
| Nostr + NIP-77 Negentropy | simple signed events and set reconciliation | relay-local retention and weak abuse/custody guarantees |
| Secure Scuttlebutt, Manyverse, P2Panda | signed append-only author histories and local-first repair | fork growth, offline fan-out, and compaction under missing peers |
| Matrix/Conduit and Bluesky relay/PDS sync | operational federation, bounded CAR/range repair | operator dependence and incomplete cross-provider durability |
| Waku v2 | relay/store/filter/lightpush split and constrained-client paths | relay economics, metadata leakage, and optional RLN authority |
| Automerge Repo/Yjs and OrbitDB/Helia | causal merge, content addressing, and blob separation | unbounded graph/index growth and hostile replication work |

Valhalla's selected combination is push for latency, periodic pull for
anti-entropy, causal room events, a provider/rendezvous DHT, and explicit
custody classes. That combination is only a hypothesis until identical seeded
topologies, churn, partitions, and abuse schedules produce comparable receipts.
"Post-SOTA" is therefore a measured result, not a design label.

## Adversarial findings

1. **Room creation must not depend on directory availability.** An owner-signed
   genesis and policy epoch 0 can be created offline and addressed by its full
   identifier. A globally unique alias is a later convenience. Otherwise a
   directory partition turns a public P2P product into a hosted service.
2. **Convergence is conditional.** A room converges only for retained events
   within its declared custody horizon. Offline peers outside that horizon
   must rebootstrap from a checkpoint; no global causal-stability horizon can
   wait for arbitrarily disconnected peers.
3. **Ephemeral participation is not durability.** Functions and browser workers
   are valuable forwarders and caches, but simultaneous cold starts cannot
   satisfy a retention promise. Regional/archive receipts require independent
   durable failure domains and a random retrieval challenge.
4. **Receipts need non-circular identities.** Event IDs exclude their own
   signature and field; custody receipts name the exact event/range or chunk
   root, policy epoch, provider, expiry, failure domain, repair threshold, and
   challenge result. A provider cannot prove its own claim by signing a promise
   whose bytes do not identify the promised data.
5. **Bootstrap is the trust bottleneck.** A DHT cannot bootstrap trust from
   nothing. Fresh clients need an independently obtained bootstrap pin or room
   invite, multiple operator/ASN families, endpoint-control challenges, and
   signed sequence/TTL floors. Withdrawal of one family is a required test.
6. **Mobile continuity is a separate product surface.** Wake/push,
   store-and-forward handoff, sleep/reconnect, and anchor rotation need their
   own receipts. Browser or serverless churn cannot stand in for WhatsApp-like
   availability.
7. **Public metadata remains visible.** Signed parents, timing, provider
   receipts, and transport paths expose social-graph information even when
   payloads are encrypted. Padding, batching, transport pseudonyms, or mix
   routing belong to a separately qualified privacy track.
8. **Hot rooms need a later scaling design.** Topic shards and edge replicas
   are acceptable only after deterministic assignment, overlap handoff,
   cross-shard causal references, and no-loss/no-duplicate failure tests.
9. **Abuse is a resource problem before it is a policy problem.** Quotas,
   bounded proof-of-work or Botcaptcha, malformed-DAG limits, slow-reader
   backpressure, and relay/storage byte accounting must be measured against
   honest false positives and operator cost. RLN-style admission is optional,
   because its membership root adds authority and recovery obligations.

## Required falsifiers before public-testnet language

- A deterministic simulator reproduces seeded topology, event, churn,
  partition, and repair schedules and emits a signed-tree-bound receipt.
- Native and browser implementations agree on event vectors, duplicate/fork
  handling, bounded orphan behavior, checkpoints, and custody receipt parsing.
- Four independent bootstrap/operator/ASN/failure-domain families survive one
  family withdrawal and an eclipse attempt.
- A 100-peer public-room run reaches the declared propagation and convergence
  targets under 30% churn, with raw event and resource receipts.
- Regional/archive custody recovers after correlated domain loss, provider
  rotation, corruption, and restart; gossip-only rooms make no durability
  claim.
- A fresh laptop, browser, and ephemeral worker can create or join, post/read,
  restart, and explain its observed frontier and custody class without copying
  private keys manually.
- The same manifests run locally, on the Railway trial lane, and with an
  independently controlled host before any global availability claim.

The measurement charter in [`scale-measurements.md`](scale-measurements.md)
defines denominators, confidence bounds, resource budgets, and receipt fields.
The north-star plan remains the sequencing authority; this review should be
updated whenever an experiment invalidates a stated assumption.
