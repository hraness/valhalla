# vhalla (valhalla) local chat

The experimental native adapter joins private application identities, fresh
paired sessions and real QUIC sockets. It is **loopback only**, available through
an explicit CLI build feature. Independent protocol/security review remains
outstanding. Public networking, browser participation and general rooms are
still being built.

From the repository root on Unix, build and initialize two new identities:

```console
cargo build -p vhalla-cli --features experimental-network --locked
./target/debug/vhalla identity init ./alice
./target/debug/vhalla identity init ./bob
```

Each prints `application-key` followed by a full public key. Keep both private
directories. In one terminal, start Bob with Alice's public key:

```console
./target/debug/vhalla experimental listen ./bob <alice-public-key>
```

It prints `route <address> <expiry>`. In another terminal, send Alice's message
using Bob's independently obtained public key and those two route fields:

```console
./target/debug/vhalla experimental send ./alice <bob-public-key> <address> <expiry> "hello"
```

Replace angle-bracket placeholders with the printed values. The listener lasts
60 seconds, and each send has a ten-second deadline. Restart the listener for a
fresh address and expiry. Application keys persist; transport keys and session
nonces are generated anew. The fixed experimental realm/room/epoch are 1/2/1.
There is no discovery, room-name registry, background daemon or global install.

The sender prints `received` only after verifying Bob's signed acknowledgment
of the exact signed frame. This means receipt in volatile memory; it does not
mean durable storage, human attention or agent execution. Bob prints verified
messages with their full signer, session and a hexadecimal body, so foreign
terminal escapes and newlines cannot become control sequences or forged log
records. This temporary line interface is not the planned JSON-lines API.

## Boundaries

- Each side pins the other's complete application key locally. A route is an
  untrusted address hint, not a signed invitation or membership grant. The
  authenticated QUIC PeerId supplies the observed transport key; the signed
  handshake binds both transport keys, both application keys and room context.
- Each connection has separate, consumed handshake/replay state. Invalid input
  closes only that exact connection. A new connection cannot reuse another's
  confirmation or signed chat. Errors do not trigger automatic sends or retries.
- Transport keys use OS entropy and temporary zeroizing seed buffers. The
  application identity stays inside its existing custodian. No transport secret
  is printed or persisted. The default CLI feature set has no network dependency.
- Frames are bounded to 65,536 bytes before payload allocation; signed bodies
  fit in 65,341 bytes. Four established connections, four pending connections
  per direction, one connection per transport peer and four concurrent streams
  per connection are the maximum. QUIC stream/connection receive windows and
  pending handshake deadlines are explicit. This is not a process-memory or
  denial-of-service guarantee; four unauthenticated local peers can occupy slots.
- Listener polling drives progress and deadline cleanup. Stop/drop releases the
  sockets and identity lock. Expiry and observed clock rollback permanently
  close the adapter. Message bodies have no path to policy or host execution.

The native dependency graph is larger than the portable core. TLS dependencies
include C/assembly; an all-Rust-authored adapter is not an all-Rust dependency
graph or an embedded profile. The lockfile adds libp2p 0.57.0 already exercised
by the isolated QUIC experiment, without replacing existing locked versions.

## Evidence

```console
cargo test -p vhalla-native -p vhalla-cli --all-targets --all-features --locked
cargo clippy -p vhalla-native -p vhalla-cli --all-targets --all-features --locked -- -D warnings
```

The real CLI process test creates identities, rejects strangers and wrong
recipient pins, checks escaped output, restarts the receiver, and confirms the
same application identity with new transport/session keys. A socket test runs
two concurrent connections for the same application key: a full-size old frame
replayed on the second connection is rejected, while the first still exchanges
full-size signed messages. Pure tests cover malformed/oversized framing, route
bounds, handshake deadlines and permanent closure after clock rollback.

The earlier process-restart replay experiment remains reference evidence; the
maintained suite separately proves actual process restart and cross-connection
replay rejection. Physical power loss, Internet/NAT behavior, sustained flooding,
loss recovery, signed invitations, durable history, origin security, browser
execution and independent review remain open gates.
