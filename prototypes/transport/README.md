# Transport prototype

This crate keeps the application event API independent from sockets and models
only the delivery properties that affect the protocol: loss, duplication,
reordering, relay fallback, and bounded inboxes. It deliberately has no
network dependency, because pulling a full transport stack into a throwaway
comparison would hide the actual browser and footprint tradeoffs.

The original stack comparison was a hypothesis, not a footprint or connectivity
measurement. Follow the [dated transport decision](../../kb/plans/valhalla-promotion-gates.md#transport-decision-after-current-source-review)
for current candidates: libp2p browser WebRTC-direct dials native peers, while
Iroh browser connections are relayed. Direct browser-to-browser connectivity
remains a separate experiment. This prototype executes neither stack and does
not establish which is smallest or suitable for embedded devices.

Retain the transport-neutral event seam while real native and browser spikes
qualify the adapters. Keep small core profiles independent of the full network
stack. A relay can drop, delay, duplicate or reorder events; it is neither an
authority nor evidence of durable storage.

Run:

```sh
cargo test --manifest-path prototypes/transport/Cargo.toml
```
