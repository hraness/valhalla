# Portable private relay wire contract

This crate owns canonical opaque relay v1 items, retention receipts, page
validation and length-prefixed framing. Native TCP, authenticated TLS and the
loopback browser gateway use the same implementation. It has no filesystem,
SQLite, socket or Unix API. Its kernel dependency provides the existing portable
outbox classifications and committed-artifact types.

The item magic, field order, kind tags and SHA-256 commitment are unchanged.
`wire_tests` freezes a complete pre-extraction item and PAGE request vector.
Legacy plaintext bootstrap and confidential contact offers remain inadmissible.
A relay position/receipt means retention only; it is neither MLS membership nor
an authenticated member acceptance receipt.

`codec::decode_frame(raw, max)` validates the length prefix, one operation/status
byte, total size and absence of trailing bytes. `MAX_REQUEST` and `MAX_RESPONSE`
exclude the four-byte length prefix. `frame` requires an already bounded body.
PAGE request bodies are an eight-byte big-endian exclusive cursor and two-byte
big-endian limit (1–64). Callers must independently select and check the opaque
namespace. `decode_page` enforces contiguous positions, head and continuation;
canonical empty absence beyond the head remains valid for a standalone fetch.
A durable catch-up controller must separately refuse rollback of retained state.

Focused validation:

```sh
cargo test --locked -p vhalla-private-relay
cargo check --locked -p vhalla-private-relay --target wasm32-unknown-unknown
```
