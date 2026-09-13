# Native WebRTC pre-admission diagnostic

Status: confirmed retention in a bounded local probe; no dependency repair
enabled. This is an additional public-networking blocker for the fixture.

The registry source of `libp2p-webrtc` 0.10.0-alpha keeps a `new_addrs` HashSet
inside `src/tokio/udp_mux.rs`. It inserts an address before yielding `NewAddr`,
which the transport turns into an incoming upgrade offer. Success registration
removes it, and closing the whole multiplexer clears it. Source inspection found
no cap, expiry or decline cleanup for an offer whose upgrade is never polled.

The [probe module](native-admission-probe.rs) sends one small STUN fixture from
each of 32 owned loopback sockets and drops the offered events without creating
connections. It asserts the actual private multiplexer state, closes the sockets,
then polls for 150 ms. The result on 2026-09-13 was:

```text
OBSERVED retained_addresses=32 admitted_connections=0 mapped_addresses=0
1 passed; 0 failed; 6 filtered out
```

The complete asynchronous probe has a five-second deadline. It creates at most
32 source sockets and one listener, sends no Internet traffic, and drops its
owned resources on completion/failure. This is not a full Swarm denial-of-service
test, a measured process-memory bound or proof about all native WebRTC queues.
It establishes that dropping reported offers leaves state below the admission
layer; the source shows why an outer connection limit cannot clean up that set.

To reproduce, make a **disposable copy** of the exact registry crate, append the
module to its `src/tokio/udp_mux.rs`, and run:

```sh
cargo test --manifest-path /path/to/disposable-copy/Cargo.toml --lib --features tokio valhalla_admission_probe -- --nocapture
```

Never edit the registry cache or the maintained adapter for this diagnostic.
The original offline run reused this experiment's dependency versions, added an
empty `[workspace]` to the disposable manifest, and removed unused upstream
`quickcheck`/`tracing-subscriber` test dependencies. Tokio's test features were
`net`, `macros`, `rt`, `time`. No production source changed; the test module was
the only append to the multiplexer. Those adjustments avoid unrelated package
downloads and are not evidence that the upstream full test suite passed.

The preserved [repair reference](native-admission-reference/README.md) contains
the reviewed disposable candidate, exact historical receipts, fixture lockfile,
upstream MIT notice, and hash-checked reproduction instructions. It is not an
active dependency repair; real browser/native success and full RTC lifecycle
cleanup remain unqualified.

Any activated candidate must use bounded reservations with cancellation/decline,
timeout, success and listener-close cleanup. Test capacity exhaustion, repeated
source addresses, source-port churn, late registration, timeouts and fairness of
polling under sustained input. A hard cap with no cleanup would merely turn the
retention problem into permanent slot starvation. Keep the candidate outside
public networking until it has independent review and real transport evidence.
