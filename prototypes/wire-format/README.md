# Wire-format prototype

This is a throwaway, dependency-free Rust experiment for one Valhalla protocol fork: the bytes that are signed for an event envelope. It is historical reference material; the current `vhalla-wire` crate uses a separate format.

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

## Historical recommendation

This experiment originally favored canonical CBOR over its JSON alternative. That recommendation is superseded for application envelopes: [the current wire crate](../../crates/vhalla-wire/src/lib.rs) retains fixed-field v1 bytes, wrapped in [signed framing v2](../../crates/vhalla-crypto/src/lib.rs). Neither experimental codec is an accepted alternative message path. The [readiness plan](../../kb/plans/valhalla-promotion-gates.md) tracks format review, rejection vectors and target qualification; an extensible object may justify a separate encoding decision later.

The experiment deliberately has no crates.io dependencies, so its tests can run offline. The hand-written JSON and CBOR codecs are not suitable for production until replaced or independently audited.

## Verification

```text
cargo test --manifest-path prototypes/wire-format/Cargo.toml
```

Result: **6 passed, 0 failed** (unit tests plus doc-test harness).
