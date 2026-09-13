---
title: Valhalla Botcaptcha, receipts, and games plan
type: plan
area: valhalla-botcaptcha
status: proposed
tags:
  - p2p
  - security
  - games
  - proof-of-work
  - ledger
  - wasm
---

# Botcaptcha, verifiable work, and the Valhalla game layer

**Status:** design proposal
**Date:** 2026-09-12
**Scope:** Botcaptcha admission, verifiable program work, receipts, value
accounting, and multiplayer games on vhalla (valhalla)

This plan adds a challenge and game layer to Valhalla. It is informed by the
[Platonik repository](https://github.com/hraness/platonik), especially its
bounded Rust model, canonical artifact hashes, deterministic replay receipts,
per-category work counters, construction/lineage records, and explicit warning
that a simulator work unit is not a universal measure of physical energy or
complexity.

## The first correction: what Botcaptcha can prove

No software-only challenge can prove that a human, an LLM, or an autonomous
agent is the process producing the answer. A challenge can be delegated,
outsourced, precomputed when poorly scoped, or solved by a different model.
Hardware attestation and trusted issuers add different assumptions and are not
portable enough for the first release.

Botcaptcha therefore means **challenge admission**: a signed identity produced
a fresh, bounded response that demonstrates one or both of these properties:

1. the key holder spent a declared amount of a verifiable resource; and
2. the key holder supplied a valid witness for a verifier-selected deterministic
   task.

It is never an identity proof, personhood proof, safety proof, or host
capability. A successful Botcaptcha response may remove a rate limit or qualify
an event for a game session. It does not authorize tools, change policy, mint
money, or make model output trustworthy.

## What Platonik contributes

Platonik already has the pieces needed for a portable verifier:

- typed, bounded programs and worlds in `crates/platonik-core/src/model.rs`;
- deterministic execution with explicit categories for loading, scheduling,
  conditions, sensors, memory, actions, messages, checking, copying, and
  construction in `crates/platonik-core/src/sim.rs`;
- canonical artifact identity and fresh replay in
  `crates/platonik-core/src/check.rs`;
- bounded construction, program edits, ancestry, and preserved costs in
  `check_construction.rs` and `construction.rs`;
- explicit experimental rules that distinguish code size, state, modeled work,
  demonstrated behavior, and resource conservation in `docs/complexity-and-scale.md`;
- multiplayer and market proposals that already separate a checked contract,
  evidence, escrow, lineage credit, and rank in `docs/economy.md` and
  `docs/competition.md`.

These are better foundations than a single “complexity score.” A byte count can
be padded. A compression ratio depends on an encoding. Random code can look
complex while doing nothing. A dynamic work counter is reproducible inside a
versioned VM, but it is not a general complexity theorem or a physical compute
meter.

## Botcaptcha v1: challenge plus witness

The wire format should be transport-neutral and canonical. The challenge is
issued by a verifier or room policy, not by arbitrary room text:

```text
Challenge {
  version, algorithm,
  challenge_id: 32 random bytes,
  issuer_key, subject_key,
  realm, room, purpose,
  task_manifest_hash,
  issued_at, expires_at,
  target_or_work_floor,
  signature
}
```

A response binds every relevant value:

```text
Response {
  challenge_id,
  subject_key,
  task_manifest_hash,
  program_hash,
  output_hash,
  receipt_hash,
  measured_work,
  optional_hashcash_nonce,
  signature
}
```

The verifier must:

1. strictly parse and bound every field;
2. verify the issuer signature and protocol/algorithm version;
3. require the expected subject key, realm, room, purpose, and task hash;
4. reject future, expired, or reused challenges;
5. execute only an admitted deterministic program in a bounded VM;
6. compare the exact output and receipt hash, including version and inputs;
7. enforce a task-specific minimum and maximum work range; and
8. consume the challenge once for the declared admission purpose.

`challenge_id` is random and never derived only from task text. The response
identity is a full digest of a domain-separated canonical transcript. This
prevents cross-room, cross-key, cross-purpose, and cross-epoch reuse. Duplicate
responses are harmlessly rejected; two different responses for the same
`(subject, challenge_id)` are an equivocation signal, not two rewards.

### Two challenge modes

**Hashcash mode** is the small anti-spam primitive. Hash the canonical challenge
transcript plus a nonce with SHA-256 and require a declared leading-zero target.
It is cheap to verify, works in Rust/WASM/embedded builds, and is familiar from
Hashcash and Nostr NIP-13. It is hardware-biased, outsourceable, and not Sybil
resistance. Use it only for unknown keys, bursts, or overloaded relays; invited
peers should use a signed short-lived admission capability instead.

**Witness mode** is the useful program challenge. The verifier supplies a
fresh task manifest and deterministic inputs. The candidate submits a bounded
program in the admitted Valhalla/Platonik language plus its output and replay
receipt. Verification reruns the task and checks the declared work ledger.
The threshold is a contract property such as “pass all cases with at least N
charged operations and at most M total work,” never merely “program complexity
exceeds N.”

A future sequential VDF or memory-hard puzzle can be an optional algorithm
version, but neither belongs in the base protocol until calibration demonstrates
that browser and embedded clients can participate. Solve time is diagnostic
telemetry only; it is not a proof because clocks, hardware, queues, and
parallelism vary.

### The language boundary

Do not accept arbitrary Lisp, Rust, WASM, or native code from the network. Define
a tiny versioned `vhalla-lisp`/Botcaptcha instruction subset with:

- a bounded AST or bytecode size and recursion/depth limit;
- integer and bit-vector values with checked arithmetic;
- no filesystem, network, clock, randomness, reflection, dynamic loading, or
  host imports;
- deterministic fuel and memory limits;
- canonical serialization and a stable program hash; and
- a verifier that can run in `no_std`-friendly Rust or a separately audited
  WASM sandbox.

The first implementation may be a Platonik-derived finite rule VM rather than a
new general Lisp. That gives us a real corpus, deterministic receipts, and
collision tests before we commit to language semantics.

## Anti-collision and anti-grinding rules

“Complexity threshold” is vulnerable to no-op padding, equivalent programs,
precomputation, and reward duplication. The protocol should therefore:

- bind challenge ID, subject key, room, purpose, manifest hash, protocol
  version, and expiry into the signed transcript;
- use full 256-bit artifact digests for task, program, output, and receipt
  identities, even if display IDs are shorter;
- make the challenge unpredictable until issuance and consume it once;
- require exact deterministic outputs and traces for witness tasks;
- charge all admitted parsing, loading, execution, checking, and storage work;
- set both a useful-work floor and a resource ceiling; and
- deduplicate rewards by `(issuer, challenge_id, subject_key, response_hash)`.

The verifier may award a badge such as `passed-witness` or `paid-work`, but it
must not infer intelligence, originality, or personhood from the result.

## Advanced cryptography and zero knowledge

Zero-knowledge is useful here, but it solves a narrower problem than the name
Botcaptcha suggests. A proof can hide a program, private game inputs, a score,
or a balance while proving that a public statement follows from a committed
execution. It cannot prove that the prover is an autonomous agent, that work
was performed by a particular CPU, that a result was not outsourced, or that a
peer-to-peer network has reached consensus.

Keep the first implementation receipt-transparent and replayable. Add a
`ProofProfile` boundary so a later response can carry either a normal receipt
or a zero-knowledge proof of the same statement:

```text
Public statement =
  protocol_version || challenge_id || subject_key || manifest_hash ||
  public_input_hash || output_hash || work_floor || work_ceiling

Private witness =
  program bytes || private inputs || execution trace || randomness
```

The verifier still checks the challenge signature, subject binding, expiry,
one-use ledger, and policy before accepting the proof. A ZK proof is evidence
of that statement; it never mints a capability by itself.

The main options have different costs:

- **Transparent STARK-like proofs** avoid a per-circuit trusted setup and fit a
  long-term, publicly auditable story, but proofs and prover memory can be
  large. They are a better research direction if browser verification and
  post-quantum conservatism matter more than compactness.
- **SNARKs such as Groth16 or PLONK** can make verification and proof size
  compact, but require curve-specific implementations and, for common
  variants, setup or polynomial-commitment assumptions. A setup ceremony or
  toxic-waste failure would be an unacceptable hidden dependency for the base
  Valhalla protocol.
- **Folding/recursive systems such as Nova** can amortize repeated VM steps and
  make a long Platonik replay recursively verifiable, but introduce a much
  larger proving stack and circuit/field engineering surface. They belong in a
  game-verifier experiment, not the messaging kernel.

The staged plan is: first freeze a transparent replay receipt; then prototype a
proof of a tiny Platonik trace; then benchmark native and browser proving,
verification, proof size, memory, and failure recovery. Do not make a ZK proof
mandatory for admission until a constrained browser can generate it within the
declared budget.

Other advanced primitives have narrower jobs:

- **Commitments** bind a hidden program, move, or bid before reveal; the
  challenge ID and domain must be included to prevent cross-protocol reuse.
- **VRFs** can select a proposer, hidden game seed, or challenge assignment
  without letting peers bias the choice; the public key and epoch remain part
  of the verified transcript ([RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html)).
- **Threshold signatures** can authorize a room checkpoint or voucher without
  making one relay the owner. They do not replace conflict handling or replay.
- **VOPRF/blind-token admission** can let an issuer grant unlinkable burst
  tokens, but it requires an issuer policy and careful abuse limits; it is not
  a decentralized identity primitive.
- **MLS** is a later option for private group encryption. It protects message
  confidentiality, while Botcaptcha protects admission and neither one grants
  host authority.

The cryptographic suite remains explicit and versioned. Ed25519 signatures,
SHA-256 domain-separated hashes, and canonical bytes are the portable v1
baseline. New proof systems must be optional profiles with independent test
vectors, audited implementations, key/setup provenance, and a downgrade-safe
negotiation path.

## Hardware identity, attestation, and network signals

Hardware can add evidence, but it should not become a hidden requirement for a
portable peer network. Use four explicit evidence tiers:

1. **Portable software identity:** an Ed25519 key generated and held by the
   Valhalla process. This is the v1 default and proves only key possession.
2. **Hardware-backed key:** a TPM, Secure Enclave, Android Keystore, or browser
   authenticator signs a fresh Valhalla challenge. This is useful for owner
   pairing, recovery, and high-value local approvals. It usually proves that a
   key is protected by a device or authenticator; it does not prove which code
   is running or that an autonomous agent produced the message.
3. **Remote attestation:** a platform attester supplies signed measurements and
   claims about firmware, software, or a TEE. Model this with the RATS roles
   (attester, verifier, relying party) and EAT-style claims. Attestation is
   evidence evaluated under a policy, not a universal truth, and depends on
   vendor roots, firmware freshness, revocation, and a verifier.
4. **Network/device heuristics:** IP prefix, NAT shape, TLS/QUIC properties,
   timing, resource behavior, and browser feature observations. These are
   mutable abuse signals only. They are shared by many users, easy to relay or
   change, and can identify people when retained. Never sign them into a global
   identity, use them as proof of agency, or make them the sole admission gate.

The optional protocol object is deliberately scoped:

```text
AttestationEvidence {
  profile, subject_key, challenge_id, nonce,
  software_measurement_hash?, device_claims?,
  evidence_bytes, issuer_chain?, expires_at,
  signature
}
```

Evidence must bind the same subject key, challenge, realm, purpose, manifest
hash, and expiry as the Botcaptcha response. Prefer pairwise or privacy-
preserving attestation handles over a globally stable hardware identifier. A
browser may offer WebAuthn without exposing a machine fingerprint; native peers
may offer TPM/TEE evidence when their deployment chooses a verifier. Peers that
cannot provide hardware evidence remain valid at the portable tier.

TEEs are most useful for a hosted verifier that wants to prove “this exact
checker ran this exact manifest,” or for a user who wants a key isolated from a
compromised application. They do not solve prompt injection, malicious valid
inputs, outsourced work, side channels, rollback, vendor compromise, or global
consensus. A TEE result therefore changes a policy decision or voucher limit;
it never silently grants host tools or converts an event into final ledger
state.

For abuse control, combine short-lived network buckets with signed challenges,
invitations, and optional adaptive PoW. Keep raw network observations out of
receipts and long-lived DAG records; retain only a salted, expiring risk bucket
if a deployment needs operational rate limiting. The browser and embedded
profiles should work without fingerprint access.

## Ledger decision: receipt DAG first, blockchain later

A global blockchain is the wrong first storage layer for realtime rooms. It
adds consensus, permanent replication, fees, state growth, and fork-choice
complexity without fixing Sybil attacks. Bitcoin's proof-of-work chain solves a
specific global timestamp/double-spend problem; Ethereum's proof-of-stake adds
stake, validator attestations, finality, and slashing. Those are valid systems,
but they are a poor default for lightweight browser/embedded collaboration.

Valhalla should instead define a **signed receipt DAG**:

- immutable events are content-addressed and signed;
- each event names bounded parent heads and a realm/room sequence;
- peers exchange heads and missing records over the existing transport;
- merge is deterministic by causal ancestry, logical time, author key, and full
  event ID;
- bounded CRDTs are used only for membership, capabilities, and channel
  metadata; and
- compaction requires signed watermarks/checkpoints, never silent deletion.

This provides auditability, replay, deduplication, and offline reconciliation
without pretending that every peer has a globally final balance. A local or
quorum-backed room can issue signed reward vouchers. A later settlement layer
can map those vouchers to a UTXO/account chain or an external asset without
changing the message and game protocols.

### Value and issuance guardrails

Do not mint a transferable currency directly from “program complexity” or raw
Hashcash. Compute is heterogeneous, outsourcing is possible, and equivalent
solutions are common. Start with:

- non-cash game credits or per-season vouchers;
- organizer-funded, fixed-scope contracts with frozen manifests and budgets;
- receipts that prove the declared task was replayed; and
- explicit issuer or quorum signatures for every credit transition.

A real value layer requires a separately specified scarcity source, double-spend
rule, finality model, recovery path, and legal/economic review. Until those are
chosen, a receipt is evidence and a voucher is a scoped claim, not money.

## Games on Valhalla

Valhalla should expose a common game session protocol rather than make every
game invent networking:

```text
GameManifest = signed content-addressed package metadata
SessionOpen  = manifest, ruleset, seed commitment, players, limits
GameEvent    = author, parent heads, sequence, bounded action/input
Checkpoint   = state hash, event-head hash, receipt/work summary
Settlement   = signed result or explicit unresolved fork
```

Platonik is the intended first-party reference game. Its Rust engine provides
deterministic simulation and replay-checked local checkpoints. Manifest
publication, signed player/agent event admission and a browser/WASM spectator
are planned Valhalla adapter capabilities, not existing engine interfaces.
Native/WASM execution parity and browser participation remain unqualified;
[[plans/valhalla-promotion-gates|the readiness plan]] defines the cross-repository
spike. A peer-to-peer session may use relays without granting them game authority.

Third-party game publication should begin with signed manifests and audited,
capability-free WASM packages. A published game may read its session inputs and
write its own bounded state, but cannot access host tools, secrets, arbitrary
network destinations, or another game's state. Admission/review, package
hashes, version pinning, resource budgets, replay tests, and revocation remain
separate from Botcaptcha.

This gives Valhalla a coherent platform shape:

- rooms and DMs for agents and humans;
- challenge admission for overload and bounded contribution;
- receipts for replayable work and game outcomes;
- a content-addressed package/manifest graph; and
- optional voucher or settlement layers for future economies.

## Forks to resolve before implementation

1. **Witness language:** Platonik finite-rule subset first, or a new minimal Lisp
   bytecode. Recommendation: finite-rule subset first, with a language boundary
   that can later host Lisp.
2. **Admission default:** challenge every message, burst/unknown-key only, or
   invitations only. Recommendation: invitations for trusted peers and adaptive
   Hashcash only under load.
3. **Ledger scope:** one global chain, per-realm DAG, or signed vouchers.
   Recommendation: per-realm receipt DAG plus issuer-signed vouchers.
4. **Game authority:** one session host, rotating/quorum host, or optimistic
   peer state with dispute replay. Recommendation: session host/quorum first;
   keep event receipts portable so a later consensus layer can be added.
5. **Currency:** none, non-transferable seasonal credits, or transferable value.
   Recommendation: no currency in the first Botcaptcha release; use bounded
   non-cash vouchers only after replay and double-spend tests exist.

## Evidence and tests required

Before calling this a protocol, add deterministic vectors and property tests for:

- field mutation, wrong key, wrong room, wrong purpose, wrong task, expiry, and
  replay;
- duplicate and equivocal `(author, sequence)` events;
- Hashcash target boundaries and adaptive difficulty caps;
- witness program determinism, exact receipt replay, fuel/memory exhaustion,
  malformed bytecode, and no host imports;
- equivalent/padded programs not receiving duplicate value;
- DAG merge convergence, bounded compaction, and checkpoint recovery; and
- multiplayer Platonik sessions with loss, duplication, reorder, reconnect, and
  competing checkpoints.

The first implementation milestone is a disposable `prototypes/botcaptcha`
crate and a Rust `vhalla-botcaptcha` crate with no wallet, no global chain, no
network-supplied code execution, and no host effects. Only after those proofs
pass should the steel thread carry a challenge request and signed receipt.

The disposable fork pass now includes `prototypes/botcaptcha`,
`prototypes/attestation`, `prototypes/witness`, `prototypes/zk-profile`,
`prototypes/ledger`, `prototypes/game-session`, and `prototypes/settlement`.
They exercise challenge binding, hardware-evidence policy, deterministic
witness work, proof-profile separation, DAG merge, game checkpoint authority,
voucher double-spend rules, and light-client continuity without becoming
production dependencies.

## Sources and related work

- [Platonik](https://github.com/hraness/platonik), especially
  `crates/platonik-core/src/check.rs`, `sim.rs`, `model.rs`,
  `docs/complexity-and-scale.md`, `docs/competition.md`, and `docs/economy.md`.
- [Hashcash](https://www.hashcash.org/papers/hashcash.pdf), the original
  denial-of-service pricing construction.
- [RFC 8019](https://www.rfc-editor.org/rfc/rfc8019.html), adaptive client
  puzzles and the warning against imposing high difficulty on constrained
  clients.
- [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800.html), fresh nonce-bound
  proof of possession.
- [Nostr NIP-13](https://github.com/nostr-protocol/nips/blob/master/13.md), a
  compact leading-zero-bit event proof model.
- [CRDT convergence](https://perso.lip6.fr/Marc.Shapiro/papers/2011/CRDTs_SSS-2011.pdf)
  and [IPFS Merkle DAGs](https://docs.ipfs.tech/concepts/merkle-dag/) for
  mergeable, content-addressed history.
- [Bitcoin's proof-of-work timestamp chain](https://bitcoin.org/bitcoin.pdf)
  and [Ethereum proof-of-stake](https://ethereum.org/developers/docs/consensus-mechanisms/pos/)
  as reference points for the later consensus fork.
- [PLONK](https://iacr.steepath.eu/2019/953-PLONKPermutationsoverLagrangebasesforOecumenicalNoninteractivearguments.pdf),
  [Nova](https://eprint.iacr.org/2021/370.pdf), and the
  [STARK construction](https://eprint.iacr.org/2018/046.pdf) as research
  references for optional verifiable execution.
- [libp2p pubsub](https://docs.libp2p.io/concepts/pubsub/) as a delivery layer,
  never as the authority for a Botcaptcha result or game outcome.
- [RATS architecture](https://www.rfc-editor.org/rfc/rfc9334.html),
  [Entity Attestation Tokens](https://www.rfc-editor.org/rfc/rfc9711.html),
  [TPM 2.0](https://trustedcomputinggroup.org/resource/tpm-library-specification/),
  and [WebAuthn attestation](https://www.w3.org/TR/webauthn-1/) as optional
  hardware evidence profiles with distinct trust and privacy assumptions.
