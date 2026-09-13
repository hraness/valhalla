# Actual Rust/WASM browser interoperability

Experimental, loopback-only transport fixture for vhalla (valhalla). A browser
connects to a native WebRTC-direct listener and sends the parent crate's bounded
records. The native receiver reassembles one object, verifies its SHA-256, and
echoes each accepted record. All fixture keys are public. This is not a Valhalla
room, an agent credential, durable storage, or production networking.

## Reproduce

Use Rust with its matching `wasm32-unknown-unknown` standard library, Python 3,
and wasm-bindgen CLI **0.2.108**. Fetch the exact locks first. The commands below
run from this directory; use the host scheduler where repository policy requires
it. No global installation or public service is performed by these scripts.

```sh
cargo fetch --locked
bash build.sh
python3 serve.py
```

The supervisor prints an ephemeral loopback HTTP URL and a native `ROUTE`. Open
that URL in a browser, paste the route, enter `65536`, enable the 100 ms reader
pause, and run. Require browser `PASS`, sixteen native `RESPONSE_SENT` lines,
exactly one `COMPLETE 65536`, and no `REJECT` or page-console error. Wait for the
native `CLOSED` event before starting another connection with the same fixture
identity. Also exercise zero bytes, a chunk boundary, and reconnect. Stop the
supervisor with Ctrl-C; it owns and reaps its child, and stops after ten minutes.

`VHALLA_WASM_BINDGEN` can name an isolated 0.2.108 binary.
`VHALLA_WASM_RUSTC` can name an isolated compiler **with its matching host and
WASM standard libraries**. Mixing Homebrew Rust with official standard-library
artifacts failed with E0514 in the original trial despite matching release and
commit labels. An isolated official Rust 1.97.1 installation succeeded. The
default build uses the compiler on PATH; generated bindings/binaries stay ignored.

Authored application and protocol logic is Rust. `site/bootstrap.js` contains
only the two-line generated-WASM module loader. The HTTP fixture sends a strict
self-only CSP with WASM compilation enabled, no-store and nosniff. Status text
uses `textContent`. There is no authored JavaScript/TypeScript protocol, account,
tracking, external STUN, discovery, relay or signaling service.

## Resource and lifecycle boundaries

- Only literal IPv4 loopback routes with a nonzero UDP port, certificate hash
  and expected transport PeerId are accepted; the native socket binds loopback.
- Admission allowlist and connection limits run **before** request-response.
  There are at most four pending connections in each direction, four established
  connections, one per peer, four request streams and four queued swarm events.
- Frame lengths are checked before allocation against 4,140 bytes. Writes flush
  in 1 KiB pieces. Request-response owns the single stream close after codec
  return; explicitly closing inside the codec caused a second close and a native
  `BrokenPipe` after every otherwise successful WebRTC response.
- One receiver belongs to each actual connection ID; its partial object is at
  most 64 KiB and is removed on connection closure. Its ten-second clock rejects
  further records after expiry. The browser has a ten-second operation deadline,
  one pending request and one active button operation. The browser disconnects
  explicitly after receipt; reconnect waits for observed native closure.
- These bounds do not prove that every allocation, queue or socket inside the
  alpha native dependency is bounded. One object per connection also avoids
  claiming long-lived data-channel cleanup that this experiment has not proved.

## Dependency patch

The lock uses libp2p 0.57.0, native libp2p-webrtc 0.10.0-alpha and browser
libp2p-webrtc-websys 0.5.0. The local copy of the browser adapter retains its MIT
license and exact Cargo manifest. Its [patch provenance](vendor/PATCH.md) records
two experimental lifecycle changes: detach data-channel JS handlers before the
last Rust callback owner drops, and close a peer connection even when initial
authentication fails or is cancelled. Without detachment, the actual browser
reported `closure invoked recursively or after being dropped`.

This patch needs independent review, cancellation/error stress, data-channel
resource accounting and upstream resolution before use in a maintained adapter.
It does not increase the 16 KiB read buffer or change the wire protocol.

## Evidence and remaining gates

On 2026-09-13, the Codex in-app browser and a separate arm64 macOS native process
completed a 64 KiB transfer with a 100 ms pause before **each** record read. The
native log showed sixteen successful responses, one verified complete object,
and closure; the current browser page reported no errors. See
[the recorded trial](evidence.md) for the failures that led to this design.

CI compiles the native and WASM fixture and runs native codec tests. That is
separate from the manually driven actual-browser proof. Other browsers, page
suspension/reload during transfer, hostile-peer flooding, long-lived memory,
Internet/NAT reachability, selected ICE-path inspection, direct browser-to-browser
connections, private browser key custody, signed Valhalla sessions and independent
review remain open. The upstream browser adapter only dials WebRTC-direct; it
does not provide a browser listener.
