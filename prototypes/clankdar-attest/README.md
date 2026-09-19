# Clankdar attestation prototype

An independent Rust implementation of `clankdar-attest-v1`, the sealed-seed
capability attestation protocol defined by the Clankdar benchmark
(`bench/attest.ts` in the clankdar repository is the reference), plus
`clankdar-gate-v1` admission checking (`bench/gate.ts`),
`clankdar-tlog-v1` transparency-log checking (`bench/tlog.ts`),
`clankdar-holdout-v1` issuer-private held-out pools (`bench/holdout.ts`),
and `clankdar-badge-v1` subject-signed portable badges
(`bench/badge.ts`).

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
    [--seed N] [--ttl SEC] [--context TEXT] [--holdout POOL.json] [--out TICKET.json] [--clankdar DIR]
clankdar-attest verify --key KEY.json --ticket TICKET.json --response-file FILE \
    [--subject-key KEY.json] [--pool POOL.json] [--out RECEIPT.json] [--clankdar DIR]
clankdar-attest check RECEIPT_OR_ADMISSION.json [--deep] [--pool POOL.json] [--clankdar DIR]
clankdar-attest tlog check TLOG.json
clankdar-attest tlog prove TLOG.json --session gs_x
clankdar-attest tlog admit TLOG.json ADMISSION.json [--pool POOL.json] [--clankdar DIR]
clankdar-attest badge check BADGE.json [--pool POOL.json]... [--clankdar DIR]
clankdar-attest holdout gen --suite frontier --cells sat:t4,knights:t5 [--out POOL.json] [--clankdar DIR]
clankdar-attest holdout info POOL.json
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
`badge check` replays every carried admission, so it takes the deep path
too; repeat `--pool` to disclose several pools at once (the TypeScript
CLI takes one comma-separated `--pools` list — same effect, different
flag shape).

Keys are Ed25519 OKP JWKs (`{kty, crv, x, d}`), byte-compatible with the
TypeScript `keygen`. Receipts, admissions, transparency logs, and badges
verify across implementations: the Rust tests replay TypeScript-issued
receipts, admissions, `bench/tlog.ts`-built logs, and
`bench/badge.ts`-packed badges, and `bun bench/attest.ts check`
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
logged session is issuer-claimed only. Held-out receipts remain visible as
`unreplayed` unless `check_logged_admission_with_pool` (CLI: `tlog admit
... --pool POOL.json`) receives the matching disclosed pool. The two
verifications are independent: the head is bound to the issuer's log key
while the admission is bound to the challenges' verifier key, so a head
signed by a different key still checks.

The crate only *checks* logs — it consumes `{head, entries}` JSON like the
TypeScript `check`/`prove`/`admit` commands. Building a log replays the
private `gate-state.jsonl` ledger (`entries_for`/`entry_hash` exist for
tests and tooling over already-public records, never for ledger replay).
And the honest limit stands: the log binds *this* issuer's history under
*its own* key — it does not stop self-minting, and it cannot detect a
fork alone; equivocation needs head comparison the issuer published
elsewhere (gossip or external anchoring, both future work).

## Rooms dogfood: the room-side admission decision

Valhalla "rooms" are consensus groups (`crates/vhalla-*`). The product
vision: an agent joining a room presents a `clankdar-gate-v1` admission
proving it passed the room's published capability floor — admission
receipts as proof of cognitive work. The `rooms` mode runs that flow end
to end in Rust, the way a rooms node would:

```sh
# The room publishes POLICY.json (its floor) and its verifier key.
clankdar-attest rooms issue --key ROOM_KEY.json --policy POLICY.json \
    [--subject AGENT_ID] [--context room:ROOM_ID] [--seed-base N] \
    --out SESSION.json [--clankdar DIR]
# SESSION.json is issuer-private (it carries the seeds); stdout carries
# the session id, deadline, and public challenge list the respondent sees.

# Optional: the respondent binds a subject key to the session on its own
# side — the room never touches the respondent's private key.
clankdar-attest rooms prove --key RESPONDENT_KEY.json \
    --challenge CHALLENGE.json > PROOF.json

# The room consumes the respondent's answers into a signed admission.
clankdar-attest rooms submit --key ROOM_KEY.json --session SESSION.json \
    --responses RESPONSES.json [--subject-proof PROOF.json] \
    [--out ADMISSION.json] [--clankdar DIR]

# The room's admission decision over a presented admission.
clankdar-attest rooms decide ADMISSION.json --policy POLICY.json \
    --key ROOM_KEY.json [--clankdar DIR]
# -> {"admit": true|false, "reason": "..."} — exits nonzero on deny.
```

`rooms issue` mirrors `issueSession` in `bench/gate.ts`: `challenges`
sealed challenges drawn uniformly from the policy cells with replacement,
under one session id and one deadline (`--seed-base` is the `seedBase`
determinism hook). `rooms submit` mirrors `submitSession`: responses are a
JSON object keyed by challenge id, a missing or non-format-canonical
answer is a failed challenge with no receipt, and every minted receipt is
replayed through the independent deep check before the verdict is signed.
`rooms decide` replays the presented admission through `check_admission`
and then pins it to *this* room: the embedded policy must equal the
published floor and the session must have been issued under the room's
verifier key. `admit` is `true` exactly when the signed verdict replays as
a pass — the decision consumes the signed admission's own recomputed
verdict, never a caller-supplied flag. For a policy-agnostic replay, plain
`check` remains.

**What this proves.** The admission decision a rooms node would run is
replayable Rust verification: mint, submit, sign, and independently decide
are the same code paths as the gate-v1 checker, and the decision is a pure
function of the signed artifact pinned to the room's floor and key.

**What real rooms integration still needs.** Transport: sessions are
minted and responses collected through files here — a real room issues
challenges and receives responses over its room transport, and a session
is in-memory or ledger state, not a JSON file. Publication: the policy and
verifier key are CLI inputs — a real room publishes them to members (and
would version and rotate them). Consumption: `decide` prints
`{admit, reason}` — join logic in `vhalla-*` must consume the verdict,
bind it to the join request (`subject`/`context` are the binding hooks),
and decide what an admission does and does not authorize. As ever, an
admission is capability evidence under one policy in one window — never
identity, liveness, or authority — and it must never mint room membership
or host capability by itself. The room helpers currently issue published
cells only and fail closed when an admission contains `unreplayed` held-out
scores; pool-aware room issuance and decisions remain future integration.

## Held-out pools (clankdar-holdout-v1)

A holdout pool is an issuer-private set of secret labels that re-parameterize
published generator cells: the held-out instance for a cell is
`generate(tier, mixSeed(label, seed))`, where `mixSeed` is the FNV-1a label
mix over the label's UTF-16 code units (JavaScript `charCodeAt` semantics,
reproduced exactly). The label decorrelates the cell's stream from the
published one while the public `seed` stays the caller seed recorded in the
receipt. `poolKey` — `sha256(canonical({protocol, suite, cells}))` — commits
the pool; challenges minted from it carry `heldout: {poolKey}`.

Receipt checking is three-way, exactly as `checkReceipt(receipt, {pool})`
in `bench/attest.ts`:

- **Pool supplied and committed:** `check_receipt_with_pool` regenerates
  through the cell's secret label — prompt, expected answer, and the
  verdict rescore all replay.
- **No matching pool:** the signature, seed commitment, answer format,
  timing, and subject proof still verify, but the score stays
  issuer-claimed — `{ok: true, verdict, replayable: false}`.
- **Pool key matches but lacks the named cell:** proof of fabrication — a
  hard `{ok: false}` failure, not an unreplayed pass.

Issuing a held-out challenge requires the pool at issuance: `issue
--holdout POOL.json` fails fast when the pool's suite differs from the
requested suite or the pool lacks the cell, and `verify --pool` /
`check --pool` carry the same pool through `instance_for` —
a `heldout` ticket without its matching pool refuses rather than falling
back to the published stream.

Gate policies name held-out cells as `h:family:tN`. `issue_session` /
`submit_session` / `check_admission_with_pool` mirror
`bench/gate.ts`: a policy naming `h:` cells without a supplied pool fails
fast; the pool's suite must equal the policy's and must carry every named
held-out cell (membership is checked only when a pool is supplied — the
checker path cannot verify it); every `heldout` challenge marker must be
well-formed, name an `h:` policy cell, and share one `poolKey` across the
session; an unmarked challenge must name a published policy cell. An
admission check without the pool reports `unreplayed` — the count of
receipts whose held-out scores stayed issuer-claimed — alongside `ok`,
`verdict`, and `passed`.

**Documented divergence, same as gate policies.** `HoldoutPool::parse`
validates protocol, suite, cell count and shape (including the
`^[A-Za-z0-9_-]{22,128}$` labels and distinct cell ids) and recomputes the
`poolKey` commitment, but — like `GatePolicy::parse` — does not confirm
each cell exists in the suite's base pool: the Rust side regenerates
through the oracle rather than embedding the pools, so a nonexistent base
cell fails at regeneration instead of at parse. The TypeScript fixtures in
`tests/fixtures/` exercise real cells both ways, so the observable behavior
is identical wherever it matters.

## Subject badges (clankdar-badge-v1)

A badge is a portable dossier: a respondent aggregates subject-bound
admissions — from any issuer — under one Ed25519 key and signs the
envelope itself. The subject signs, never an issuer, so a badge is a
curated claim "these signed episodes are bound to my key"; admissions from
different verifier keys mix freely. Optional tlog inclusion proofs tie a
carried session to a logged decision, upgrading issuer-claimed admissions
to logged ones.

`check_badge` mirrors `checkBadge` in `bench/badge.ts` step for step:
envelope and payload shape, the `subjectKey` public key, 1–64 members each
through the full `check_admission_with_pool` replay with distinct
`sessionId`s, subject binding (every proof-carrying receipt uses
`subjectKey`, and at least one receipt must carry a proof), at most 64
inclusion proofs each replayed against their own log through
`prove_session` (indexes and head must match a fresh proof, and the
session must have a logged decision), `issuedAt` shape, and finally the
badge signature over the payload bytes verbatim. `passed` counts
admissions whose recorded verdict is `pass` — not receipt tallies — and
`logged` counts the distinct sessions a verified proof covers. Disclosed
pools are indexed by `poolKey` and may mix issuers; each admission replays
against the pool its `heldout` marker commits, and undisclosed scores stay
valid but sum into `unreplayed`. Malformed members produce the same
structured failures the TypeScript checker emits — never a panic.
`pack_badge` signs a badge and replays it through the checker before
returning, the same self-check `packBadge` performs.

`badge check BADGE.json` prints the TypeScript command's reshaped result —
`{ok, subject, admissions, verdicts: {pass}, logged, unreplayed?}` on
success, `{ok: false, reason}` and a nonzero exit on failure.

**Documented divergence, one step narrower.** The TypeScript `issuedAt`
check is `Date.parse`, which accepts exotic strings ("Sep 18 2026") that
RFC 3339 parsing rejects. `check_badge` parses RFC 3339 — the
`toISOString` output every `packBadge` writes — so a hand-crafted badge
with a JS-only timestamp passes there and fails here.

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
