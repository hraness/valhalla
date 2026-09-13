# Valhalla native QUIC prototype

Disposable reference code for vhalla (valhalla), excluded from the production
workspace. Two separate native processes exchange opaque bytes over real QUIC.
This proves transport connectivity and expected transport PeerId checking; it
provides no Valhalla application authentication or authority.

**All fixture keys are public. Any local process can impersonate a fixture peer.**
Listeners and invitations are restricted to IPv4 loopback. There is no discovery,
relay, DNS, DHT, public bootstrap, account, or external service configured. This
is not a browser, NAT traversal, durability, consensus, or production proof.

## Reproduce

From the repository root, using its configured host scheduler when required:

```sh
cargo fetch --manifest-path prototypes/native-quic/Cargo.toml --locked
cargo fmt --manifest-path prototypes/native-quic/Cargo.toml -- --check
cargo test --manifest-path prototypes/native-quic/Cargo.toml --locked --offline --all-targets -- --nocapture
cargo clippy --manifest-path prototypes/native-quic/Cargo.toml --locked --offline --all-targets -- -D warnings
```

The Rust integration driver starts a listener and independent sender processes,
checks 17-byte and 65,536-byte binary echoes, then changes the peer component of
the same invitation and requires an identity-specific `WrongPeerId` rejection.
Every child process has a bounded wait and is killed/reaped by a guard on failure
or completion. The listener fixture has a 60-second lifetime to cover the entire
multi-connection test; individual handshake, request, idle, and sender-loop
limits remain ten seconds.

The executable modes are:

- `peer-id <fixture-seed-byte>`: print the fixture transport identity.
- `listen <fixture-seed-byte> <expected-sender-PeerId>`: bind an ephemeral loopback
  UDP socket and print its invitation, including the listener's transport
  identity in the `/p2p/` address component.
- `send <fixture-seed-byte> <invitation> <payload-length>`: connect only to the
  invitation's transport identity and check the returned deterministic bytes.

## Boundaries and dependencies

The codec checks its four-byte big-endian length against a 64 KiB maximum
**before allocating or reading the body**. It rejects truncation, trailing bytes,
and oversized writes. Four unit tests cover these boundaries and invitation
validation.

QUIC has a four-stream cap, a 66,560-byte stream window and a 266,240-byte
connection window. Admission caps pending incoming and outgoing connections at
four each, established connections at four, and connections per peer at one.
Only the configured remote PeerId is admitted. Per-connection swarm event
buffering is four; dial concurrency is one. These controls do not establish a
measured upper bound on every allocation inside the dependency stack.

Direct dependencies are `libp2p = "=0.57.0"` with default features off and only
`tokio`, `quic`, `ed25519`, `macros`, `request-response`; `futures = "0.3"`; and
feature-restricted `tokio = "1.53"`. The lock resolves futures 0.3.34, Tokio 1.53.1,
libp2p-quic 0.14.0, libp2p-request-response 0.30.0, Quinn 0.11.11, quinn-proto
0.11.17, rustls 0.23.44, aws-lc-rs 1.18.1, and ring 0.17.14. All authored code is
Rust; native cryptography includes C/assembly, and the transport is not no_std.

Primary implementation references:
[libp2p manifest](https://docs.rs/crate/libp2p/0.57.0/source/Cargo.toml),
[codec contract](https://docs.rs/crate/libp2p-request-response/0.30.0/source/src/codec.rs),
[QUIC controls](https://docs.rs/crate/libp2p-quic/0.14.0/source/src/config.rs),
[connection limits](https://docs.rs/crate/libp2p-connection-limits/0.7.0/source/src/lib.rs).

## Observed evidence — 2026-09-12

On Apple arm64 macOS with Rust 1.97.1, four unit tests and the real-process
integration test passed. Initial compilation took about 17 seconds. The complete
connection test took about 0.7 seconds, including process startup and teardown;
this is not a throughput or network latency benchmark. Focused Clippy passed
with warnings denied. The declared MSRV is 1.88, matching libp2p, but no 1.88 build
was performed.

The unoptimized executable with dev debug information disabled was about 19.7 MB.
The active native normal/build dependency graph contained 195 dependencies;
maximum reported RSS during compilation/testing was about 399 MB. That RSS is
**build/test memory, not idle or steady-state peer memory**. No optimized-release,
browser, embedded, loss/reorder, handshake-flood, or wide-area measurement was
performed.

The first integration attempt exposed a lifecycle issue: the small echo passed,
but replacing its sender process under the same peer identity collided with the
one-connection-per-peer limit. Dropping the old swarm did not prove the listener
had released its connection slot. The sender now disconnects explicitly and
briefly retains its runtime for Quinn to flush closure; the runner requires the
listener's `PEER_CLOSED` event before reconnecting. The repaired test passed.
The short flush grace and observed close handoff are local empirical evidence,
not a guarantee of reconnection under arbitrary scheduling or packet loss.

Cargo.lock SHA-256:

```text
cc39e0b9697d43e5aa833093b172c9bc317def01b02bec77a300cf572a04fd84
```

Native QUIC is viable as an optional host adapter behind the opaque frame
boundary. Its footprint supports keeping it out of the portable core. The
browser-first fork still needs its own real-browser acceptance test: Rust
libp2p's browser WebRTC transport currently only dials native WebRTC-direct peers.
