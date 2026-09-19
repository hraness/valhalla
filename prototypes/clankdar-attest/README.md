# Clankdar attestation prototype

An independent Rust implementation of `clankdar-attest-v1`, the sealed-seed
capability attestation protocol defined by the Clankdar benchmark
(`bench/attest.ts` in the clankdar repository is the reference), plus
`clankdar-gate-v1` admission checking (`bench/gate.ts`) and
`clankdar-tlog-v1` transparency-log checking (`bench/tlog.ts`).

A verifier issues a challenge whose generator seed is committed but
unrevealed: the puzzle instance has never existed publicly, so it cannot be
pre-solved or looked up. On a response, the verifier rescores
deterministically and signs a receipt that reveals the seed. Afterward anyone
can replay the episode: verify the Ed25519 signature over the verbatim
payload, recompute the seed commitment, regenerate the instance through the
canonical generator oracle, rescore the response, and check the answer landed
before expiry — no trust in the verifier beyond the signed episode.

## Commands

```sh
cargo build --manifest-path prototypes/clankdar-attest/Cargo.toml

clankdar-attest keygen --out KEY.json
clankdar-attest issue --key KEY.json --suite frontier --family automata --tier 6 \
    [--seed N] [--ttl SEC] [--context TEXT] [--out TICKET.json] [--clankdar DIR]
clankdar-attest verify --key KEY.json --ticket TICKET.json --response-file FILE \
    [--subject-key KEY.json] [--out RECEIPT.json] [--clankdar DIR]
clankdar-attest check RECEIPT_OR_ADMISSION.json [--deep] [--clankdar DIR]
clankdar-attest tlog check TLOG.json
clankdar-attest tlog prove TLOG.json --session gs_x
clankdar-attest tlog admit TLOG.json ADMISSION.json [--clankdar DIR]
```

`check` on a receipt is fully offline: signature, key identity, seed
commitment, response format, verdict rescore, and answer-before-expiry.
`check --deep`, `issue`, and `verify` additionally call the canonical
generator oracle — `bun bench/instance.ts` inside the clankdar repository
located by `--clankdar`, `$CLANKDAR_DIR`, or `../clankdar` — so the recorded
prompt and expected answer must regenerate exactly. `check` on a
`clankdar-gate-v1` admission always takes the deep path: every embedded
receipt regenerates through the oracle, so the clankdar checkout is
required. `tlog check` and `tlog prove` are fully offline — they consume
`{head, entries}` JSON like the TypeScript check commands; `tlog admit`
replays the admission's embedded receipts through the oracle like `check`.

Keys are Ed25519 OKP JWKs (`{kty, crv, x, d}`), byte-compatible with the
TypeScript `keygen`. Receipts, admissions, and transparency logs verify
across implementations: the Rust tests replay TypeScript-issued receipts,
admissions, and `bench/tlog.ts`-built logs, and `bun bench/attest.ts check`
/ `bun bench/gate.ts check` / `bun bench/tlog.ts check` replay the Rust
verdicts.

## Gate admissions (clankdar-gate-v1)

A gate session mints N sealed challenges under one session id and one shared
deadline, drawn from a policy (`suite`, `cells`, `challenges`, `minPass`,
`ttlSeconds`). A single submit consumes the session: each format-canonical
response verifies into a receipt, and the issuer signs an admission binding
the complete challenge list, the receipts, and the verdict
(`passed >= minPass`).

`check_admission` mirrors `checkAdmission` in `bench/gate.ts` step for step:
envelope and payload shape, the embedded policy, per-challenge session
binding / suite version / cell coverage / shared deadline / shared verifier
key / `keyId` recompute / subject-context binding / unique ids, the payload
signature, every embedded receipt through the deep regeneration check plus
canonical equality with a listed challenge, one subject key across proofed
receipts, and verdict arithmetic with `decidedAt <= expiresAt`. Challenge
parsing tolerates unknown members, as the protocol requires for forward
compatibility.

### Subject binding (optional)

A receipt may carry a `subjectProof` — `{publicKey, signature}` — binding the
response to an Ed25519 key the respondent controls (the same JWK shape as
verifier keys; `verify --subject-key KEY.json` mints one). The signature
covers a domain-separated transcript: `["clankdar/subject/v1", sessionId,
publicKey]` for session-bound challenges — one proof then serves the whole
gate session — or `["clankdar/subject/v1", challengeId, nonce, publicKey]`
standalone. `check_receipt`/`check_receipt_deep` replay embedded proofs
exactly like `checkReceipt`: a present `subjectProof` must be well-formed
`{publicKey, signature}` strings and must verify over the recorded
challenge's transcript. `check_admission` additionally requires every
proofed receipt in a session to share one `publicKey` — one subject per
session. Receipts and admissions without proofs remain fully valid.

**Documented divergence from the TypeScript checker.** `GatePolicy` (and the
embedded policy inside an admission) validates cell *shape* —
`family:tier` with the family-name charset — but does not check that the
cell exists in the suite pool, where `parsePolicy` rejects unknown cells
outright. The Rust side regenerates instances through the oracle rather than
embedding the pools, so "cell exists" is enforced by receipt regeneration
instead: a session cell that cannot regenerate can never produce a counted
pass, only a failed challenge. A policy naming a nonexistent cell therefore
parses here but is unpassable in practice — matching the spirit, not the
letter, of the TypeScript floor.

## Transparency log (clankdar-tlog-v1)

The gate ledger records every session issuance and every admission
decision, but only the issuer sees it. The transparency log is the
derived, signed view: each ledger record becomes one hash-chained entry
(`digest` over the verbatim record, `prev` over the previous `entryHash`,
genesis 64 zeroes), and the issuer signs a head committing to the entry
count and the last `entryHash` — the analogue of a CT signed tree head.

`check_log` mirrors `checkLog` in `bench/tlog.ts` step for step: every
`entryHash` recomputes over the five body fields, the `prev` chain walks
back to genesis, per-entry shape checks fire in order, entry order
satisfies ledger semantics (a session is issued once; a decision names an
issued, still-open session — strictly earlier in the chain), then the head
is recounted, `issuedAt` parsed, `keyId` recomputed, and the signature
re-verified over `canonical(head minus signature)`. `prove_session` runs
the same check and reports `{sessionId, sessionIndex, decisionIndex,
head}` — `decisionIndex: null` while a session is undecided.
`check_logged_admission` is the portable-badge test: the admission must
pass `check_admission` on its own AND its `sessionId` must have both a
session and a decision entry in a checked log — a valid admission with no
logged session is issuer-claimed only. The two verifications are
independent: the head is bound to the issuer's log key while the admission
is bound to the challenges' verifier key, so a head signed by a different
key still checks.

The crate only *checks* logs — it consumes `{head, entries}` JSON like the
TypeScript `check`/`prove`/`admit` commands. Building a log replays the
private `gate-state.jsonl` ledger (`entries_for`/`entry_hash` exist for
tests and tooling over already-public records, never for ledger replay).
And the honest limit stands: the log binds *this* issuer's history under
*its own* key — it does not stop self-minting, and it cannot detect a
fork alone; equivocation needs head comparison the issuer published
elsewhere (gossip or external anchoring, both future work).

## Honest scope

A receipt attests that **one signed response satisfied one challenge inside
one time window**; with a `subjectProof` it additionally attests that the
holder of that key signed the challenge's subject transcript. It does not
prove that a model, an AI, or any particular principal produced the response
— the answer can be outsourced or delegated, and a proof binds a key to a
response, never a model or a person. It is not a liveness credential, grants
no authority, and provides no durable replay protection; consumers should
issue fresh challenges and bind `context` to their own scope. It must never
mint host/tool capability by itself.

Run tests with
`cargo test --manifest-path prototypes/clankdar-attest/Cargo.toml --locked`.
