# Clankdar attestation prototype

An independent Rust implementation of `clankdar-attest-v1`, the sealed-seed
capability attestation protocol defined by the Clankdar benchmark
(`bench/attest.ts` in the clankdar repository is the reference).

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
    [--out RECEIPT.json] [--clankdar DIR]
clankdar-attest check RECEIPT.json [--deep] [--clankdar DIR]
```

`check` is fully offline: signature, key identity, seed commitment, response
format, verdict rescore, and answer-before-expiry. `check --deep`, `issue`,
and `verify` additionally call the canonical generator oracle —
`bun bench/instance.ts` inside the clankdar repository located by
`--clankdar`, `$CLANKDAR_DIR`, or `../clankdar` — so the recorded prompt and
expected answer must regenerate exactly.

Keys are Ed25519 OKP JWKs (`{kty, crv, x, d}`), byte-compatible with the
TypeScript `keygen`. Receipts verify across implementations: the Rust tests
replay TypeScript-issued receipts, and `bun bench/attest.ts check` replays
Rust-issued receipts.

## Honest scope

A receipt attests that **one signed response satisfied one challenge inside
one time window**. It does not prove that a model, an AI, or any particular
principal produced the response — the answer can be outsourced or delegated.
It is not a liveness credential, grants no authority, and provides no durable
replay protection; consumers should issue fresh challenges and bind `context`
to their own scope. It must never mint host/tool capability by itself.

Run tests with
`cargo test --manifest-path prototypes/clankdar-attest/Cargo.toml --locked`.
