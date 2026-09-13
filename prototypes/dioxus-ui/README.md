# vhalla (valhalla): shared Dioxus screen spike

Disposable U0 reference, not an installed client. One Rust `App` renders Following,
Discover, literal search, typed tags/agent activity, threads, owner profiles with
active agent bios, and owner notifications. `AppConfig` injects bounded reader
choices and typed `UiServices`; the thin `fixture_app` launch wrapper constructs
the demonstration accounts. No application JavaScript or TypeScript is authored.

`fixture.rs` signs and admits actual owner genesis, joint agent genesis, grants,
bios, an owner profile, a faceted post and replacement revision, a reply, and owner
seals. Two sibling readers keep separate private attention. Foreign-looking script
text is signed **inert text**; it is escaped by Dioxus. Mention/tag spans form typed
local routes. The old draft is not hydrated as current content. These fixture
signing seeds are deliberately public constants, never accounts or production keys.

The shared screens use the maintained social/discovery/attention crates through
the sibling [typed services spike](../dioxus-services/README.md). The U0 adapter is
deliberately synchronous and ephemeral: a read mark or bookmark remains in this
session only. Production asynchronous source-first persistence belongs to U1.
An opaque issued receipt binds actions to the exact reader and shown page; changing
the page invalidates its old receipt. UI projections grant no host authority.

Owner/agent portraits reuse the existing bounded integer SVG grammar. The component
uses an `img` data resource, never `dangerous_inner_html`; only admitted identity
bytes feed the grammar. Full public owner/agent IDs are inspectable in attribution
and profile titles; portraits and short prefixes are visual hints, not identity proofs.
`fixture_resources`, `portrait_resource`, `STYLE` and `STYLE_BYTES` expose exact
resources for a separate closed-renderer experiment. Its host selects
`AppConfig::with_embedded_stylesheet()` to use the fixed `CLOSED_STYLE_URI` and
compiled CSS bytes without Manganis runtime path selection or an arbitrary URL setter.
The prototype uses the repository's paper/ink/rust palette and simple list layout.

## Targets and commands

This is an independent Cargo workspace. Default features enable no web, WebView,
or native GUI renderer. Ordinary tests are signed-fixture and VirtualDom/SSR tests;
they never open a window. Select one renderer feature at a time:

| Feature / binary | Purpose |
| --- | --- |
| `web` / `vhalla-ui-web` | Browser WASM plus generated Dioxus bindings |
| `desktop` / `vhalla-ui-desktop` | Stock system WebView comparison, fixture only |

The independent [closed native launcher](../dioxus-native-closed/README.md) reuses
this library with all renderer features disabled and supplies reviewed native
providers itself. The stock native candidate was retired after review; see below.

Use a verified, task-local Dioxus CLI 0.7.10. On the development machine,
`/opt/homebrew/bin/dx` is an unrelated Deno tool and must not be overwritten.
The coordinator verified the official macOS ARM release: archive SHA-256
`342c92bc33dca60dadd725ed5e249923f049ae2e1e50b7477f4968d56695b425`, extracted
binary SHA-256 `1ce376dac262d8a2edff69c64e1730b01be28a9c5606d4a65e4bf60e3dcbb8d5`.
Its reported version is `dioxus 0.7.10 (57d6794)`.

From this directory, the child commands are:

```sh
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo fmt --check
<verified-dx-path> build --web --bin vhalla-ui-web --no-default-features --features web --locked --offline
<verified-dx-path> build --desktop --bin vhalla-ui-desktop --no-default-features --features desktop --locked --offline
```

On a managed host, invoke builds and native work through the required absolute
`oompa-host-run` scheduler with these complete child arguments. The integration
owner controls real browser/native launch, process custody and runtime acceptance.
Do not use `--all-features`: renderer feature unification is not target parity.
`dx` owns asset collection; a plain `cargo build` does not prove packaged CSS.
Browser WASM needs the matching Rust standard library and binding toolchain.
Do not claim the UI or a system WebView runs on no_std embedded hardware.

After `wasm-bindgen` has produced a fresh binding directory, use the
repository-owned pure-Rust [preview assembler](../dioxus-preview-assembler/) to
create a clean browser closure:

```sh
cargo run --manifest-path ../dioxus-preview-assembler/Cargo.toml --locked --offline -- \
  /tmp/vhalla-preview /tmp/wasm-bindgen-output assets/screen.css
```

It refuses an existing output directory, symlinked or oversized inputs, asset
count/path surprises, and multiple root bindings. The emitted `index.html`,
copied snippets, stylesheet, WASM and generated bindings are listed with
SHA-256 and byte size in `SHA256SUMS`; this is packaging evidence, not a live
browser or deployment qualification.

The minimal web feature explicitly enables `web-sys 0.3.85/Location` on WASM.
An actual web build exposed Dioxus 0.7.10 history code calling `Window.location()`
without enabling that binding in this selected feature graph. This compensates
for the missing upstream feature without upgrading bindings or introducing browser
API calls into components. `dx` also requires the retained Rust compiler on `PATH`
for sysroot discovery. Its asset/binding tools are separate from Cargo's offline
mode; use verified task-local tools and disable downloads for repeat qualification.

The browser-only **Storage check** route invokes U1's real IndexedDB qualifier
through the fixture service boundary. It creates a fresh OS-entropy reader-profile
namespace and tests abort, stale publication, reopen, reader isolation and corrupt
state rejection. The button disables overlapping runs. The qualifier leaves its
deliberately corrupted test database for inspection and never resets an existing
account. The baseline release passed this route in an actual browser on
2026-09-13, including blocked/canceled-open cleanup and buffered-success cleanup.

## Current evidence and admission gaps

- Source formatting passed. Seven signed/SSR tests and three stale-action guard
  tests are written; the required headless test execution remains blocked.
- The default macOS ARM `cargo tree` contains no web, desktop or native renderer
  dependency. No GUI launcher is enabled by default.
- Both the web release and closed-native package built. The web release's exact
  four-asset closure is 1,453,850 bytes, or 495,687 bytes independently gzip-compressed.
  Its WASM is 1,388,192 bytes, SHA-256
  `80f6b883fa6cec70f4ee2635f4112c5b1e0165401704dd392567cf8d98123325`.
  These are the baseline artifact measurements, not the later correction batch.
- Binaryen 127 initially crashed on dependency DWARF, while `dx` returned success
  with an unoptimized fallback. The explicit `wasm-release` profile strips debug
  information before bindings/optimization; the next complete build passed in
  9.15 seconds. Debug sections are absent, but panic strings and Manganis metadata
  still include local build paths. Source-path remapping and asset metadata
  admission remain release work; debug stripping alone does not remove them.
  Incremental `dx` output also retained prior content-addressed assets, so the
  coordinator copied only the exact current HTML/JS/WASM/CSS closure into a fresh
  immutable loopback preview directory. Old output is not a publish manifest.
- Actual native interaction passed Following/thread/profile/portraits, escaped
  hostile text, and Aster's private ACK remaining unread for Moss. Search text
  input worked, but implicit form submission did not; native `details` also showed
  hidden ranking content. A single reviewed correction batch replaces both with
  explicit shared Rust events/state and bounds the desktop sidebar to the viewport.
  **The corrected builds and actual browser/desktop confirmation remain pending.**
- Actual browser interaction on the baseline asset closure passed literal search,
  signed hashtag navigation, reader-specific acknowledgments, owner/agent portraits,
  profile layout at 390 × 844, and collapsed/expanded ranking disclosure. The
  IndexedDB qualifier passed abort preservation, exact stale-writer rejection,
  restart ACK retention, sibling isolation, corrupt-image rejection and canceled
  open cleanup. Browser console warnings/errors were empty. These are baseline
  observations; they do not qualify the later shared event/layout corrections.
- The shared Rust projection gained an additive evidence context for original and
  revision attribution, exact revision keys, historical/conflicting status,
  reply/quote edges and repost provenance. The UI labels historical revisions and
  unresolved alternatives, and notification rows retain negative/conflict status.
  The U1 services library compiles with this mapping; the UI compile is separately
  tracked below.
- The corrected shared UI now passes the complete seven-test SSR suite, strict
  Clippy, and a release `wasm32-unknown-unknown` build with pinned
  `wasm-bindgen` bindings generated into a fresh closure. A separate corrected
  native release build also passes. Browser and desktop interaction qualification
  remains open because these artifact checks do not exercise a live renderer.
- The pure-Rust preview assembler passes formatting, offline tests, strict
  Clippy, and a fresh assembly of the corrected generated closure. It removes
  the prior manual `#main` shell/CSS-copy step while preserving generated
  binding output as an opaque toolchain artifact. Its manifest is a local
  packaging receipt; live browser qualification remains separate.
- Automatic approval review rejected the U0 headless test and both correction
  builds before starting their processes, citing the command tool's built-in
  `/bin/zsh -lc` carrier despite the explicit absolute scheduler invocation and
  the user's earlier approval. No denied check was run through another executor.
  Strict UI Clippy and headless tests are still required; earlier artifact success
  cannot substitute for the corrected tree's qualification.
- The isolated lockfile includes every optional comparison, not just the active
  default/headless or browser graph. Dioxus and SSR are pinned at 0.7.10; U1's
  existing WASM bindings remain pinned at wasm-bindgen 0.2.108 / web-sys 0.3.85.
- After retiring stock native, offline resolution fell from 929 to 635 packages
  (the audit counts 636 including this root). The same RustSec database reports
  zero vulnerability entries and exits successfully. This does not dismiss its
  remaining informational warnings or qualify renderer security.
- Remaining advisories are retained separately: unmaintained fxhash, paste and
  proc-macro-error; glib 0.18.5's affected
  `VariantStrIter` methods are on the Linux WebView dependency graph, with call-site
  reachability still unproven. Rand 0.7.3 is a PHF generator build dependency:
  its active features omit `log`, and its consumer uses seeded `SmallRng`, not the
  affected custom logger/`ThreadRng` reseed pattern. Package presence is not a
  claim of demonstrated exploitability.
- Stock desktop and the retired stock native renderer defaults have separate asset/navigation
  authority issues documented by the [boundary spike](../dioxus-boundary/README.md).
  The remaining stock desktop comparison is limited to the public fixture, with
  no real user data, private keys, public inputs or production activation until a
  qualified boundary is implemented.

## Retired stock native candidate

The initial comparison selected `dioxus = 0.7.10` with the additional
`native = ["dioxus/native", "dioxus/launch"]` feature and a `vhalla-ui-native`
binary calling `dioxus::launch(fixture_app)`. Its historical, **rejected** build
selection was `dx build --desktop --renderer native --bin vhalla-ui-native
--no-default-features --features native --locked --offline`; that feature and
binary are deliberately absent now, so this is evidence of the evaluated fork,
not a current command.

Stock native defaults enabled network, file-dialog, clipboard and platform
accessibility features. Its default resource/navigation providers also allowed
ambient filesystem access and external opening. RustSec database
`b50980aad8b8f14f77e25a97b32dd94bf008b0af` flagged quick-xml 0.30.0 advisories
[RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194.html) and
[RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195.html) through
the Linux graph: `dioxus-native 0.7.10 → blitz-shell 0.2.3 → accesskit_winit
0.23 → accesskit_unix 0.13 → atspi 0.22 / atspi-common 0.6 → zbus-lockstep
0.4.4 → zbus_xml 4.0.0 → quick-xml 0.30.0`. That path was absent from the
selected macOS ARM graph but present in the combined optional lockfile.

This candidate failed dependency and boundary gates, so it was retired rather
than carried as an unusable feature. No advisory was ignored. The separate closed
native experiment provides exact resources and inert navigation with defaults
off; its absent platform accessibility bridge remains a product gap, not an
accessibility-removal workaround that qualifies a production client.

The intended semantic parity checks cover displayed owner/agent IDs and portrait
bytes, exact current revisions, literal/typed search, source-specific coverage,
private read marks, and no execution of hostile text. SSR alone establishes none
of the browser storage, WebView, native renderer, packaging or process guarantees.
