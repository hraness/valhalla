# Wire-format prototype

This is a throwaway, dependency-free Rust experiment for one Valhalla protocol fork: the bytes that are signed for an event envelope. It is reference material for the eventual `vhalla-wire` crate, not a production parser.

## What it compares

The prototype implements a minimal envelope with realm, room, event ID, author key ID, issue/expiry timestamps, and a bounded body:

- **Canonical JSON** emits a fixed, lexicographically ordered object and base64url body. It is easy to inspect and interoperate with, but needs a precisely specified escaping/number profile and costs more bytes (the example is 189 bytes).
- **Canonical CBOR** emits a definite-length map, sorts keys by their encoded bytes, and keeps the body as bytes. It is smaller, naturally typed, and a better fit for constrained devices and WASM.

Both formats expose `Envelope::signing_transcript(format)`. The signature is intentionally absent: an implementation will hash/sign these exact bytes and carry the signature in a separate outer field.

## Security behavior exercised

- Input has a 64 KiB wire limit, 16 KiB body limit, and 256-byte string limit.
- CBOR rejects indefinite lengths, unsupported value types, duplicate keys, trailing bytes, and oversized values.
- JSON rejects duplicate keys, malformed structure, unsupported escapes, wrong types, and trailing bytes.
- Unknown fields are retained only as names in `ignored_unknown_fields`; they never enter the trusted envelope or signing transcript.
- Version `!= 1` is rejected. A future schema must be admitted explicitly rather than silently changing the signed meaning.

## Recommendation

Choose **canonical CBOR as the protocol wire format**. Keep a canonical JSON projection only for diagnostics, fixtures, and human tooling; never accept a JSON projection as an alternative unsigned command path. Specify the selected CBOR canonicalization profile in the protocol (definite lengths, key ordering, integer width rules, duplicate-key rejection, and unknown-field policy), then replace this hand-written codec with an audited Rust implementation and cross-language golden vectors.

The experiment deliberately has no crates.io dependencies, so its tests can run offline. The hand-written JSON and CBOR codecs are not suitable for production until replaced or independently audited.

## Verification

```text
cargo test --manifest-path prototypes/wire-format/Cargo.toml
```

Result: **6 passed, 0 failed** (unit tests plus doc-test harness).
