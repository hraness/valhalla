# Dioxus boundary spike

**Decision: keep the shared Dioxus UI; do not promote the unmodified 0.7.10 desktop launcher as a privileged agent client.** This disposable spike reproduces concrete upstream behavior and tests a small proposed denial policy. It does not patch or secure a running renderer.

The library is `no_std + alloc`, forbids unsafe code, and has no runtime dependencies. Exact cached dev dependencies are `percent-encoding 2.3.2` (the extracted resolver) and `proptest 1.11.0`. It is not a second UI framework or production IPC codec.

## Evidence and limits

On 2026-09-13, published `dioxus-desktop 0.7.10` source files `webview.rs`, `protocol.rs`, `config.rs`, `app.rs`, and `launch.rs`, plus `dioxus-asset-resolver 0.7.10/src/native.rs` and `manganis-macro 0.7.10/src/lib.rs`, were byte-identical to the audited official `v0.7.10` tag. The resolved WebView dependency is Wry 0.53.5. `upstream/source-hashes.json` pins the tagged source; `extract-upstream.py` checks those hashes and the handler ordering before extracting two routines. Extraction changes only browser opening into a recording stub and supplies a task-owned asset root.

| Reproduction | Actual result | Implication |
| --- | --- | --- |
| HTTP, HTTPS, and mailto with a custom navigation callback returning false | Browser-open stub called before the callback | The configuration callback cannot prevent that external effect. |
| First navigation to `http://dioxus.evil.invalid/` | Broad internal prefix accepted | Compare the full expected document URL; a scheme or hostname prefix is insufficient. Reachability as a first navigation in a real WebView remains untested. |
| Existing absolute path to a test-owned sentinel | Default resolver returns that path | Bundle-relative assets are not its only readable namespace. |
| `/assets/%2e%2e/%2e%2e/sentinel.txt` | Returned path canonicalizes outside the fixture bundle | Percent-decoded traversal can escape the bundle. |
| `/%FF` | Resolver panics at UTF-8 decoding | Reject malformed URLs without panicking. |

These are compiled source-derived tests, not a live exploit demonstration. No private file is read, no external browser is opened, and no application JavaScript or remote HTML is evaluated. The protocol route is reachable in source: `desktop_handler` handles the index, `__events`, and `__file_dialog`, then registered asset prefixes, then the filesystem resolver. The resolver's asset response has permissive CORS. A renderer able to issue same-origin requests therefore must not share this unrestricted filesystem authority with agent keys.

The pure policy tests exact one-time document navigation, a closed static byte asset registry, bounded typed intentions, session/sequence checks, and narrow candidate CSPs. Failed messages do not advance sequence state. Two compile-fail tests show that public UI intentions cannot construct a privileged effect token. The token deliberately has no issuing broker yet. A renderer nonce or `isTrusted` event is not independent user consent; native authorization must reconstruct current evidence and control effects separately.

## Smallest complete interception boundary

The audited [desktop source](https://github.com/DioxusLabs/dioxus/tree/v0.7.10/packages/desktop/src) exposes useful hooks, but no supported combination closes every path:

| Surface | Existing hook limitation | Required adapter/upstream contract |
| --- | --- | --- |
| Navigation and external opening | `Config::with_navigation_handler` runs after default external opening. The `browser_open` IPC handler also opens an arbitrary href directly. | One pre-effect policy for both paths; exact initial document URL, deny subsequent renderer navigation, typed external-open proposal to an independently authorized broker. |
| Local resources and native dialogs | Asset registry runs after index/`__events`/`__file_dialog`. Its path-prefix handlers cannot replace all dispatch. Registering a second `dioxus` custom protocol fails with Wry's `DuplicateCustomProtocol`. | Full request interception before reserved routes; reject native dialogs and file-bearing events when disabled; allowlisted bundle bytes, no URI-to-filesystem fallback. |
| IPC and event decoding | Wry request metadata is discarded and JSON decoded before application policy. The event observer returns `()` and cannot cancel dispatch. | Check trusted callback origin/context and raw byte bounds before parsing, then closed message/event vocabulary and per-session work/rate bounds; reject file paths and unknown capabilities before dispatch. |
| Document bootstrap | `custom_head`/`custom_index` do not control response headers or nonce insertion into the generated interpreter scripts. | A response/bootstrap hook setting real CSP headers and nonce-authorized framework loader scripts, or audited external generated scripts. Keep generated framework JS in the dependency audit; no app `document::eval`. |
| Desktop edit transport | Release uses a random-port loopback WebSocket edit queue. | Limit `connect-src` to the current exact loopback endpoint; retain authenticated key checking. A port restart needs a fresh document policy, not a wildcard. |

A small reviewed upstream hook set is preferable to a broad private framework fork. No patch in this spike is claimed compiled or integrated. API presence alone is insufficient: the final release must prove pre-effect ordering, all reserved paths, IPC rejection, and successful normal interaction. The proposed `Session` frame is an application contract model, not a replacement for the framework's JSON event protocol.

## Renderer choice

| Approach | Useful property | Remaining cost or gap |
| --- | --- | --- |
| Dioxus web + hardened desktop WebView adapter | Shares the browser DOM/CSS renderer and existing component code; small application dependency delta | Requires the complete upstream interception set above and per-platform WebView qualification. Linux GTK dependency advisories need a maintained resolution. |
| Dioxus native / Blitz, custom launcher | Keeps the Dioxus component model while removing the JavaScript/WebView IPC boundary | The standard native launcher still installs external-opening and the same filesystem asset providers. Use explicit custom `DocumentConfig` navigation/resource providers; disable unused net, HTML parsing, file dialog, clipboard and hot reload features. Verify actual feature unification. Layout, input, accessibility, fonts, GPU/software renderer, asset loading and bundle size need evidence. |
| Privilege-separated UI and broker | Renderer has no key-store authority; broker can expose only bounded typed commands | Process separation alone is not an OS sandbox. Requires platform-enforced filesystem/network/process restrictions, authenticated bounded IPC, independent consent and crash/recovery qualification. It complements either renderer. |

The native tagged source publicly exposes `DioxusDocument`, `DioxusNativeApplication`, and `DocumentConfig` via its DOM re-export, allowing a custom launcher to supply providers before document creation. The separate [closed native launcher](../dioxus-native-closed/README.md) now has a compiled baseline, a passing audit of the package's selected critical feature variants, and initial native GUI evidence. Its small fallback-title compatibility patch is documented there. Search/disclosure and package-metadata corrections still await rebuilt verification; the corrected builds were rejected before starting. The standard `Config` only selects window attributes. Native/Blitz also brings its own layout, graphics, font and accessibility dependencies; removing WebView does not prove its replacement safe or lightweight. U0/U3 own the same-screen renderer comparison and live evidence.

The initial U0 lock audit reported no advisory classified as a vulnerability, but that does not mean no security findings: active Linux WebView `glib 0.18.5` is covered by [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html), an unsound iterator implementation fixed in 0.20.0. `rand 0.7.3` appears through a code-generation build dependency and is covered by [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html), whose trigger requires a particular logger/reseeding combination. Do not label that an observed runtime exploit. Audit the selected renderer's exact target/feature closure and resolve or explicitly justify every applicable finding before promotion; an all-target lock warning and an active runtime path are different evidence.

## Assets and release qualification

Manganis 0.7.10 `asset!` canonicalizes local source paths and rejects paths outside the crate at build time. This is useful package input containment; it does not constrain the separate runtime asset resolver. Use local CSS/fonts/icons, an exact generated bundle asset manifest, and a closed byte provider. Validate manifest paths, byte sizes and digests; reject symlinks/traversal and unexpected files. Dynamic portraits should come from their typed renderer, not an arbitrary external URL or filesystem path.

Use the verified official Dioxus CLI **0.7.10** from an explicit task-owned path. `/opt/homebrew/bin/dx` is an unrelated Deno command on the investigated host and must not be overwritten. Build release web with U0's `web` feature and lock. U0's `desktop` feature remains an unqualified WebView experiment. Native builds use the separate [closed native workspace](../dioxus-native-closed/README.md) and its local `native` alias, with `--features native --renderer native`; U0 no longer exposes a `native` feature. The official CLI performs Manganis asset collection; a successful bare `cargo build` does not prove installable assets. The desktop CLI defaults to `.app`/DMG on macOS, NSIS on Windows, and AppImage on Linux. Bundled runtime roots differ by platform.

The integration owner performs these probes on the actual release artifact under the applicable host lane:

1. Record exact Rust/dx versions, target, features, lock digest, executable/HTML/WASM/glue/asset digests and package size. Launch the installed bundle from outside its source/build directory.
2. Exercise navigation, search, thread/reply selection, notifications and source-first read receipts using the shared signed fixture. Check text such as `<img onerror=...>`, script-looking bodies and false-alias facets is inert. Confirm local links route through typed references.
3. For WebView, instrument the reviewed pre-effect adapter: external URL schemes, broad-prefix impostors, `browser_open`, reserved file dialog/event requests, forged file form events and oversized/malformed IPC must fail before OS opening, file access, JSON allocation or store mutation. Use only a task-owned sentinel for absolute and encoded traversal paths. The app must survive malformed `%FF` and rejected messages.
4. Verify the real CSP response and generated scripts: intended loader/rendering works; injected script, inline event handler, remote image/font/style/script, frame and form are blocked. Probe WebAssembly compilation on web. Check the exact release edit socket policy and reconnect/restart behavior on WebView; test unexpected connections fail.
5. On native/Blitz, prove the custom resource/navigation providers were actually installed, unknown resources never reach the filesystem/network, external links do not invoke the OS, and file dialog/clipboard/HTML parsing stay disabled unless explicitly qualified. Repeat size, input, layout and accessibility checks.
6. Disconnect network after serving the static web origin, then exercise locally available data and packaged assets. Distinguish this from a cold offline browser launch, which needs a separately qualified cache/service worker. For desktop, cold-launch the installed bundle offline and inspect attempted connections; a working development server is not offline evidence.
7. Confirm renderer compromise cannot mint a broker capability, bypass source-first durable publication, or read keys. Verify crash, cancellation and reopening preserve the source/private-state contract. Keep default privileged activation disabled until these pass.

## Validation

From this directory:

```sh
cargo fmt --check
cargo test --locked --offline
cargo clippy --all-targets --locked --offline -- -D warnings
```

Focused receipt: **8 integration tests passed**, including 2 property tests ×128 cases; **2 compile-fail doctests passed**. Strict Clippy passed after fixing test initialization/documentation lint issues. No Dioxus renderer is compiled by these tests.

To reproduce the upstream extraction, download only the files listed in `upstream/source-hashes.json` from the official tag into a separate directory, using the mappings in `fetch-upstream.py`, then run:

```sh
python3 fetch-upstream.py /tmp/vhalla-upstream-source
python3 extract-upstream.py /tmp/vhalla-upstream-source
cargo test --locked --offline --test upstream
```

The first command requires authorized network access. The extractor refuses changed source bytes; its test-owned stubs cannot open a browser or access user fixtures. Exact release-source equality can be rechecked with `verify-released.py /path/to/cargo/registry/source`.
