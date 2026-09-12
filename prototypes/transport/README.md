# Transport prototype

This crate keeps the application event API independent from sockets and models
only the delivery properties that affect the protocol: loss, duplication,
reordering, relay fallback, and bounded inboxes. It deliberately has no
network dependency, because pulling a full transport stack into a throwaway
comparison would hide the actual browser and footprint tradeoffs.

The comparison is:

- **Iroh:** the smallest native-first candidate and a good relay-backed QUIC
  path, but browser traffic is relay-dependent today.
- **libp2p:** more protocol surface, but the stronger fit when direct browser
  connectivity is a first-class requirement; WebRTC and relay adapters remain
  replaceable.
- **IRC/Nostr/Matrix:** useful interoperability or federation references, but
  they do not satisfy the desired direct peer-first topology as the primary
  runtime.

Recommendation: keep this transport-neutral event seam, then prototype
libp2p first because browser capability is a stated priority. Keep the
transport crate feature-gated and allow an embedded profile to omit browser
and discovery features. A relay can drop, delay, duplicate, or reorder events;
it must never be treated as an authority or durable store.

Run:

```sh
cargo test --manifest-path prototypes/transport/Cargo.toml
```
