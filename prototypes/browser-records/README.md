# Bounded browser records

Disposable reference for vhalla (valhalla), excluded from the maintained
workspace. A `no_std` Rust state machine transfers one object of at most 64 KiB
in 4 KiB records, waiting for the exact acknowledgment before sending another.
The [real browser/native fixture](interop/README.md) exercises the same code.

## Why

An actual browser/native WebRTC test transferred 64 KiB while reads kept up, but
pausing the browser reader for 100 ms overflowed the browser adapter's fixed
16 KiB receive buffer. Small writes and flushing alone did not provide receive
flow control. Sixteen acknowledged records succeeded under the same pause,
without raising that dependency's buffer limit.

## Boundary

Each record is `VR01 | total:u32be | offset:u32be | sha256:32 | body`, with at most
4,140 bytes before transport framing. Every nonfinal body is exactly 4,096 bytes;
the final body is the exact remainder. An empty object uses one header-only
record with SHA-256 of empty bytes. There is no alternative encoding.

The receiver admits the length, total and offset before allocating its single
bounded object. It rejects duplicate, skipped, reordered and changed-context
records, and verifies the complete digest before returning the last
acknowledgment. Any error closes the state and drops partial receive data.
The sender allows one outstanding record and compares the whole acknowledgment
with that record. Both owners are non-Clone, have a fixed ten-second lifetime,
reject clock rollback/overflow, and cannot reopen after error or completion.

The caller supplies monotonic milliseconds, binds each owner to one authenticated
connection, bounds the number of owners, and drops idle/closed connections. The
objects have no ambient clock, socket, filesystem, executor or authority.

**These are untrusted bytes and flow-control acknowledgments.** A digest is not
a peer signature, and an echo is not a durable receipt. Verify the complete
Valhalla signed envelope and current session before applying application policy.
A malicious peer can lie about receipt or exhaust its own bounded allocation.
This reference adds no remote tool or game authority.

## Verify

```sh
cargo fetch --manifest-path prototypes/browser-records/Cargo.toml --locked
cargo test --manifest-path prototypes/browser-records/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/browser-records/Cargo.toml --all-targets --locked --offline -- -D warnings
```

Nine unit/property tests cover boundary-size and arbitrary-object round trips,
a fixed wire vector, arbitrary input, payload mutation, changed total/digest/offset, duplicate and
reordered records, stale/unsolicited acknowledgments, expiry, clock rollback,
overflow, truncation and failure-state cleanup. The live browser fixture is a
separate gate; the state-machine tests do not simulate WebRTC.
