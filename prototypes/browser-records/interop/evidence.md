# Browser trial record — 2026-09-13

Environment: Codex in-app browser, arm64 macOS native listener, Rust 1.97.1,
wasm-bindgen 0.2.108. All trials used explicit loopback WebRTC-direct routes and
public fixture transport keys, with no external STUN or relay configured.
These are transport experiments, not private application-session tests.

| Variant | Observed result |
| --- | --- |
| Whole 64 KiB frame, 1 KiB flushed writes, reader unpaused | Exact echo passed |
| Same frame, browser read paused 100 ms | Failed with `remote overloaded us with messages`; native had sent the frame |
| Original browser dependency, repeated connections | Browser logged `closure invoked recursively or after being dropped`; some reconnects failed authentication |
| Detach callbacks and close raw data channel on final Drop | 8 KiB paused trial timed out; this aggressive patch was rejected |
| Detach callbacks without closing raw data channel; peer-connection RAII | 8 KiB paused trial and reconnect after native `CLOSED` passed; no current-page console errors |
| Sixteen 4 KiB acknowledged records, pause before each read | 64 KiB completed with correct digest; native reported a close error after every response |
| Same records; request-response owns stream close | 64 KiB passed; sixteen `RESPONSE_SENT`, one `COMPLETE 65536`, then `CLOSED`; no rejection or current-page console errors |

An earlier repeated-connection trial exposed a separate libp2p behaviour-ordering
bug: request-response recorded connection state before a later allowlist/limit
rejected it. A later close panicked against the inconsistent count. Commit
`5f89b12` puts rejectors first and adds fail-before/pass-after regressions to the
maintained native adapter. This was not a buffer-overflow result.

The repository reproduction uses the same record implementation, a connection-ID
binding, explicit ten-second receiver cleanup, bounded supervisor output, and a
single owner for each process. Building WASM is distinct from this real-browser
trial; CI does not claim to have driven a browser. Console queries were restricted
to the current fixture URL because the browser log includes older-page errors.

The exact repository reproduction also completed `65536`, `0` and `4096` byte
objects with the read pause enabled, across three fresh connections. Each prior
connection had a native `CLOSED` observation before reuse; all three complete
sizes matched, all eighteen responses completed, and no current-page console
error was reported. The source/lock manifest and native log for that trial were
retained by the coordinator.

Replacing only the route's PeerId with a third fixture identity produced the
specific browser `WrongPeerId` error. No record or complete-object event was
emitted for that connection. The native listener observed its closure and the
current page had no callback errors.

A fresh correct route subsequently transferred 17 bytes successfully, after
the rejected connection's native close event. That tests recovery after a failed
identity check without restarting the native listener or browser page.

The native application observes `COMPLETE` only after recomputing the digest.
The browser observes an exact echo, not a cryptographically signed durable
receipt. Reconnect requires observed native closure; the 50 ms browser close
grace alone is not proof of remote resource release.

Compiler setup used official Rust 1.97.1 host/compiler/WASM components from the
2026-07-16 distribution, verified against its release manifest, and the official
wasm-bindgen 0.2.108 arm64 macOS release asset. No global toolchain was replaced.
Native compilation used Homebrew Rust 1.97.1; WASM used the matching isolated
official compiler and standard libraries. Authored protocol/UI code is Rust;
browser loading uses a two-line module loader and generated wasm-bindgen glue.

Independent review, adversarial network tests, supported-browser matrix,
long-lived channel/memory accounting, page interruption/recovery, private keys,
Valhalla session integration, NAT and direct browser-to-browser support remain
open. Success on these local trials is not production readiness.
