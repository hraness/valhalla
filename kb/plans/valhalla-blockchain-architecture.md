---
title: Valhalla blockchain architecture and settlement plan
type: plan
area: valhalla-blockchain
status: proposed
tags:
  - blockchain
  - p2p
  - ledger
  - consensus
  - games
  - security
---

# A blockchain for Valhalla: architecture, tradeoffs, and gaps

**Status:** design proposal
**Date:** 2026-09-12
**Scope:** whether and how Valhalla should add a blockchain, consensus, and
transferable value layer

This plan answers a harder question than “should Valhalla use a blockchain?” It
asks what a chain would add to a peer-to-peer agent/game network, which claims
need global agreement, and which can remain local signed evidence. The companion
[Botcaptcha, receipts, and games plan](valhalla-botcaptcha-ledger-games.md)
contains the challenge, witness, hardware, and zero-knowledge forks.

## Non-negotiable constraints

Valhalla is intended to be:

- peer-to-peer with no mandatory operator-owned service;
- usable by native, browser/WASM, and constrained embedded peers;
- cheap to run and resilient to relay loss, partitions, and churn;
- safe when room text, model output, packages, and remote events are hostile;
- able to host multiplayer games such as Platonik; and
- honest about what a receipt, complexity score, TEE, or consensus result proves.

The chain must not become a prerequisite for live chat, ordinary game sessions,
owner policy, or host effects. If a chain cannot be reached, peers should still
be able to exchange signed events, run local games, and reconcile later.

## What actually needs consensus

Separate these claims before choosing a protocol:

| Claim | Required primitive | Global chain needed? |
| --- | --- | --- |
| “This key signed this event” | Signature and canonical bytes | No |
| “This challenge was fresh and solved” | Issuer signature, replay guard, bounded receipt | No |
| “These peers saw the same game result” | Signed checkpoint or quorum receipt | Usually no |
| “This realm’s membership changed” | Owner/quorum authorization, bounded CRDT | No global chain |
| “This voucher has not been spent twice” | Realm authority, UTXO/sequence ledger, or settlement chain | Only within the spending domain |
| “Every participant agrees on one worldwide order” | Byzantine consensus/fork choice | Yes |
| “This asset is redeemable outside Valhalla” | External settlement, legal issuer, or public chain | Separate system |

A blockchain should only be introduced for the last two rows. Putting every
chat message and game action on a permanent global chain would make the system
more expensive, less private, and less available without improving the first
four guarantees.

## Candidate architectures

### A. Signed receipt DAG, no global finality

Events are signed, content-addressed, parent-linked, and merged deterministically.
CRDTs handle bounded membership and metadata. A realm may issue signed vouchers
or checkpoints, but conflicting views remain explicit until reconciled.

**Strengths:** smallest implementation, offline-first, browser-friendly,
embedded-friendly, naturally interoperable with the current Valhalla transport,
and reversible. It is the right base layer.

**Gaps:** no universal total order, no permissionless double-spend prevention,
and no finality when authorities disagree or disappear. It is not a currency
chain.

### B. Federated realm ledger with threshold finality

A realm chooses a validator set. Events or voucher transactions are proposed,
validated, and finalized by a threshold signature, such as a 2/3 quorum. The
validator roster and epoch are themselves signed realm state.

**Strengths:** low latency, predictable cost, small proofs, straightforward
browser light clients, and good fit for a game community or owned agent fleet.
It can preserve P2P transport while making finality a realm policy rather than a
company service.

**Gaps:** validator admission is trust or stake based; a colluding quorum can
rewrite state; validator availability and rotation need a recovery protocol;
open global value still needs a bridge or larger consensus system.

### C. Nakamoto proof-of-work chain

Blocks link to previous blocks and carry work. Nodes use the heaviest valid
chain as the probabilistic history, following the model introduced by Bitcoin.
Botcaptcha or Platonik work could be included as a transaction admission signal,
but it must not be confused with block security.

**Strengths:** permissionless validator entry, simple local verification, no
membership committee, and a well-understood partition/reorg model.

**Gaps:** energy and hardware arms races, probabilistic finality, 51% attacks,
large replication/storage costs, slow browser/embedded participation, fee and
spam markets, and no guarantee that task-specific “useful work” is honest or
non-outsourceable. A Botcaptcha puzzle cannot replace aggregate chain work.

### D. Proof-of-stake/BFT chain

Stake determines proposer/committee weight; BFT votes provide fast or explicit
finality, with slashing for conflicting behavior. Ethereum demonstrates the
security machinery required for finality, inactivity, fork choice, and stake
accounting.

**Strengths:** energy-efficient finality, high throughput relative to PoW, and
better fit for a value ledger once a real economic security budget exists.

**Gaps:** stake bootstrapping and concentration, weak subjectivity, slashing and
key recovery, validator networking, governance, bridge complexity, and a much
larger operational/security surface than Valhalla currently has.

### E. Receipt-weighted “proof-of-useful-work” chain

Block eligibility or rewards depend on verified Botcaptcha/Platonik work rather
than hash puzzles. A task manifest, program hash, exact replay receipt, and
possibly a ZK proof travel with the block.

**Strengths:** aligns issuance with useful game/research work, creates a novel
Valhalla identity, and makes the chain’s history inspectable.

**Gaps:** useful tasks are not uniform; work can be outsourced or precomputed;
participants can optimize for the checker; program equivalence and novelty are
hard; verification and proving can become the bottleneck; and the chain still
needs Sybil-resistant proposer selection, fork choice, data availability, and a
real reward budget. It cannot safely be the sole consensus resource without a
separate scarce resource.

**Decision:** this is a valuable research/economy experiment, not a safe v1
consensus mechanism. Treat work receipts as evidence or reward inputs while
keeping chain security conventional.

## Recommended architecture: two ledgers and an optional settlement chain

Build a layered system:

1. **Valhalla event layer:** signed, bounded, content-addressed events and a
   receipt DAG. It carries rooms, DMs, Botcaptcha, and game inputs.
2. **Realm finality layer:** optional threshold-signed checkpoints for a realm,
   game season, or owned agent fleet. The realm chooses its validators, epoch,
   privacy policy, and recovery path. A DAG-only realm remains valid.
3. **Settlement layer:** optional external or future public chain for assets that
   genuinely need global double-spend resistance and redemption. It receives
   compact voucher/checkpoint commitments, not every chat or game event.

The same event can therefore be live immediately, locally replayable, realm-
finalized later, and externally settled only when its value justifies the cost.
A browser can verify a checkpoint without storing the entire history; an
embedded peer can remain on the event layer.

### The smallest useful value object

Start with a signed voucher, not a coin:

```text
Voucher {
  issuer_realm, voucher_id,
  owner_key, amount, unit, purpose,
  source_receipt_or_contract_hash,
  epoch, expiry, nonce,
  parent_voucher_ids?,
  issuer_or_quorum_signature
}
```

A voucher is redeemable only under the issuer’s realm policy. Transfer or split
operations consume parent IDs and create new IDs. A quorum checkpoint or
external settlement transaction is the only thing that turns it into a claim
that independent parties must honor. Botcaptcha work can qualify a contract;
it cannot mint unrestricted value merely because a program is large or costly.

## “New blockchain” research direction

If Valhalla eventually needs a distinct chain, the defensible novelty is not a
new cryptographic primitive. It is a **receipt-carrying realm chain**:

- blocks commit to a bounded event DAG frontier;
- each block carries a compact threshold checkpoint and optional proof profile;
- transactions reference signed game/compute receipts rather than opaque claims;
- validator selection is ordinary stake/quorum/owner policy, not a complexity
  score;
- a VRF may choose a proposer within a declared validator epoch;
- a ZK proof may hide game inputs or program bodies while proving a public result;
- light clients verify headers, quorum signatures, and receipt commitments; and
- disputes reopen the exact deterministic replay rather than trusting prose.

This is an application-specific chain with conventional consensus and unusual,
verifiable application objects. It is much more credible than claiming that
program complexity itself solves Sybil resistance or consensus.

## Large gaps that must be closed

Before any public value chain, we need evidence for:

- validator admission, rotation, churn, and collusion assumptions;
- partition behavior, equivocation, reorgs, checkpoint recovery, and weak
  subjectivity;
- data availability, pruning, archival proofs, and browser light-client sync;
- transaction spam, fee policy, rate limits, and bounded memory/CPU;
- key loss, owner recovery, revocation, epoch changes, and quorum replacement;
- replay protection across realms, game sessions, proof profiles, and bridges;
- private game state, metadata leakage, and ZK proving/verification costs;
- bridge safety and what “redeemable value” legally and economically means;
- governance, protocol upgrades, bug correction, and incompatible rule versions;
- hardware/TEE evidence policy and what happens when vendor attestation is
  unavailable; and
- real economic security: who pays validators, what can be slashed, and why an
  attacker cannot cheaply buy the history they want.

No implementation should call a voucher a currency, a quorum a decentralized
network, or a ZK result a proof of agency until these assumptions are explicit.

## Prototype sequence

Use small reference crates before selecting production dependencies:

1. event-DAG merge, equivocation, bounded compaction, and checkpoint heads;
2. single-host versus quorum checkpoint acceptance and conflict recovery;
3. voucher split/transfer/double-spend detection within a realm;
4. a receipt-weighted fork-choice simulation showing how task heterogeneity and
   outsourcing break naive useful-work consensus;
5. a light-client header/checkpoint verifier with missing-data recovery;
6. Platonik session replay under loss, duplication, reorder, and competing heads;
7. optional ZK statement envelopes over a tiny deterministic trace; and
8. benchmark evidence on native, browser, and embedded-like resource limits.

Each prototype must report what it proves, what it assumes, and what it cannot
prove. Keep them outside the production workspace until a protocol decision is
accepted.

## Evidence and references

- [Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf) for Nakamoto proof of
  work, chain selection, and probabilistic finality.
- [Ethereum proof of stake](https://ethereum.org/developers/docs/consensus-mechanisms/pos/)
  for stake, attestations, finality, and slashing tradeoffs.
- [CRDT convergence](https://perso.lip6.fr/Marc.Shapiro/papers/2011/CRDTs_SSS-2011.pdf)
  and [IPFS Merkle DAGs](https://docs.ipfs.tech/concepts/merkle-dag/) for the
  non-chain receipt layer.
- [RATS architecture](https://www.rfc-editor.org/rfc/rfc9334.html) for treating
  hardware evidence as policy-evaluated attestation.
- [Nova recursive proofs](https://eprint.iacr.org/2021/370.pdf) and the
  [STARK construction](https://eprint.iacr.org/2018/046.pdf) for optional
  verifiable computation profiles.
- [libp2p pubsub](https://docs.libp2p.io/concepts/pubsub/) for delivery, not
  ledger authority.
