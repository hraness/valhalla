# Closed native Dioxus launcher

Disposable reference for vhalla (valhalla). This launcher constructs the shared U0 fixture component with Dioxus 0.7.10's public native/Blitz APIs, an explicit resource provider, and `DummyNavigationProvider`. It does **not** invoke the standard native launch function or the default filesystem resource provider. It is not a production client or an OS sandbox.

## Boundary

Before constructing the document, the launcher configures the shared App with `with_embedded_stylesheet()` and registers its fixed `CLOSED_STYLE_URI` to the exact compiled U0 stylesheet and the five portraits returned by U0's deterministic fixture resource generator. This bypasses Manganis runtime path selection entirely: Cargo execution, direct execution and the presence of CLI environment variables cannot change the selected stylesheet URI. The provider compares full URI strings against this immutable registry and serves the stored bytes. It neither decodes incoming `data:` URIs nor interprets them as paths. Unknown HTTP/file/data/relative paths, percent-encoded traversal, native dialog paths, non-GET requests, headers and request bodies fail closed. Nested CSS requests pass through the same provider.

Registry construction is crate-private. Components cannot register another resource through this API. Portrait URI/byte pairs must agree exactly; they come from the shared trusted portrait generator, **not an SVG sanitizer for arbitrary peer markup**. All imported peer text remains inert UI content. Adding other agents or real data later requires an explicit bounded registry refresh under host control, not acceptance of arbitrary image URLs.

The registry admits at most 16 resources, 64 KiB per payload, 512 KiB aggregate payload, and 196,640 bytes per URI. One window permits 4,096 requests and 16 MiB of served payload copies; rejected requests also consume attempts. Exhausting the attempt allowance denies subsequent requests until the host constructs a new document; a payload must also fit the remaining byte allowance. URI storage, framework URL parsing, styling/layout and graphics work are separate costs; these limits are not a total process memory or CPU instruction ceiling. Request bounds apply after the renderer has created its typed request. The UI must continue preventing untrusted strings from becoming resource attributes.

Accepted byte delivery drops the policy mutex before invoking the synchronous parser, so a nested stylesheet request cannot deadlock the provider. The custom callback tolerates a closed event loop. Rejected resources do not call a filesystem or network fallback.

The explicit `DocumentConfig` supplies no HTML parser. `DioxusNativeApplication` installs `MemoryHistory` before the first build, so local typed routes use the shared router without browser navigation. The navigation provider performs no external-opening effect. The first live session verified selected routes and resource rendering; its input failures and remaining qualification gates are recorded below.

## Exact dependency selection

The optional `renderer` feature selects:

| Crate | Version | Selection |
| --- | --- | --- |
| dioxus-native | 0.7.10 | defaults off; `svg`, `system-fonts` |
| blitz-dom | 0.2.4 | direct defaults off |
| blitz-shell | 0.2.3 | defaults off; no platform accessibility bridge, clipboard or file dialog |
| blitz-traits | 0.2.0 | defaults off |
| winit | 0.30.13 | direct defaults off; `rwh_06` |
| shared U0 UI | local | no `web`, `desktop`, `native`, `launch` or devtools feature |

Cargo features are additive. Upstream `dioxus-native` still enables `dioxus-native-dom` defaults, which include DOM accessibility, SVG and system fonts. That yields `blitz-dom` features `accessibility,accesskit,svg,system_fonts`. Winit defaults are also re-enabled by upstream dependencies. This spike does not mislabel those inherited features as disabled or fork upstream manifests to hide them.

Audited macOS and Linux selected metadata graphs exclude Wry, Tao, `blitz-net`, `blitz-html`, `arboard`, `rfd`, `accesskit_winit`, `accesskit_unix` and `glib`. Linux retains `quick-xml 0.41.0` through `wayland-scanner 0.31.11` build tooling; it is a different dependency path/version from the standard native launcher's optional accessibility `quick-xml 0.30` finding. DOM accessibility code alone does not qualify an accessible application: the platform bridge is absent here, so screen-reader operation remains a product gap.

`dioxus-asset-resolver` and `webbrowser` remain compiled transitive dependencies of Dioxus native. This launcher does not invoke their default providers; their presence has **not** been eliminated by the compiler. System-font discovery and font parsing, windowing, graphics drivers, renderer parsing and the UI's native Rust dependency graph retain host-process authority. No signing key, live transport or user store is loaded by this fixture, but moving those into the same process would not make them isolated. A production privilege boundary still needs separately reviewed custody/broker and applicable OS sandboxing.

## Prototype-only upstream compatibility patch

The integration owner's initial actual release build reached upstream `dioxus-native` and failed: `src/config.rs` referenced optional `dioxus_cli_config` while `hot-reload` was disabled. Enabling hot reload merely to compile would weaken the selected feature boundary.

This standalone workspace therefore patches **only** the default window-title lookup in the exact published 0.7.10 crate: when `hot-reload` is enabled, retain the original CLI-config lookup; when disabled, use its existing `Dioxus App` fallback. All other 11 published files remain byte-identical. The custom launcher supplies its own explicit title anyway. `upstream/config-no-hotreload.patch`, original MIT/Apache licenses and `upstream/provenance.json` record the change. The official crate archive SHA-256 is `6d022085082d379df7f453cc465a7cfb75926c5e23d5781dbcbdf5df269840e5` (published VCS commit `57d6794ad60b949e5bd8aa282f6f8c3dc97a365e`).

`verify-upstream.py` checks the complete vendored file set against original/patched hashes; passing the original release archive also verifies its provenance. Independent review verified that archive and the exact source delta. The integration owner's subsequent plain-Cargo release build passed (2.98 seconds). The `[patch.crates-io]` applies only inside this disposable prototype; this is not a maintained framework fork approved for distribution.

## Official dx packaging must select the local native alias

The first actual `dx bundle --renderer native --features renderer` artifact expanded the dependency features: it compiled native network loading, HTML parsing, clipboard, dialogs and the platform accessibility bridge. That artifact was rejected for this boundary and must not be launched or described as closed. Plain Cargo metadata was not sufficient evidence for the different packager invocation.

The exact Dioxus CLI 0.7.10 helper in `packages/cli/src/build/renderer.rs` first chooses a root package feature named `native`. Without such a feature, it falls back to `dioxus/native`, which enables broad upstream defaults. `--no-default-features` alone cannot prevent this: `build/request.rs` injects the selected renderer feature afterward and always passes Cargo's no-default-features flag.

The supported fix is the local alias `native = ["renderer"]`. The CLI selects this feature, which preserves the explicit closed dependencies. Packaging should use `--renderer native --features native` with the reviewed macOS/bin/release arguments and official pinned CLI. There is no CLI fork, global binary replacement, or resource-policy relaxation.

`upstream/dx-feature-helper.rs` retains the unchanged selection function; its unit tests supply small metadata types and a no-effect logger. They reproduce both the rejected fallback and the corrected alias. `verify-cli-helper.py SOURCE_DIRECTORY` checks the retained helper against three separately downloaded official tagged files pinned in `upstream/dx-feature-source.json`. Six pure tests now pass, including these two regressions; strict Clippy and formatting pass. The native-alias metadata audit also passes with the root features exactly `native,renderer`.

For the actual corrected package, the build owner uses a fresh task-owned target directory, retains the invocation and executable digest, and checks the emitted compiler fingerprints. `audit-built-features.py EXACT_BIN_FINGERPRINT_JSON EXACT_BUILT_EXECUTABLE` follows every critical numeric dependency edge from the root through the launcher library, native renderer, native DOM, shell, DOM, UI, Dioxus, traits and window library. Every **selected** critical variant is checked, including transitive variants that differ from a direct dependency; a convenient closed variant elsewhere in the cache cannot hide an expanded selection. Parsing bounds each fingerprint, dependency list, feature list, stamp and critical-variant count, and verifies the root and launcher-library alias. The script records the artifact digest, but the build owner must bind both input paths to the same fresh owned build. Cargo fingerprint format is toolchain-specific local evidence, not a cryptographic attestation against a compromised host; unknown formats fail closed. The full metadata and dependency audit remain separate gates.

`PYTHONDONTWRITEBYTECODE=1 python3 prototypes/dioxus-native-closed/test-built-features.py` passed ten adversarial tests in 0.053 seconds. They cover direct and cached variants, broader transitive selections through the launcher library/native/native DOM, missing or ambiguous references, root identity and alias, and malformed feature/dependency/stamp encodings. Independent source review approved the repaired gate. Its earlier version also **actually rejected** the first expanded package's fingerprint because `dioxus_native` contained `default,net,html,clipboard,file-dialog,hot-reload,accessibility`. The corrected package build completed in 90.11 seconds in a fresh target directory, and the integration owner ran the repaired recursive gate successfully against that package's actual compiler fingerprints and executable. This establishes the checked feature selection; the package and live interaction gaps below still prevent full qualification.

## Evidence and commands

Default features compile only the pure registry policy. On 2026-09-13:

- Six focused tests passed: the registry cases include 128 generated unknown URIs, exact byte selection, malformed/traversal denial, registration limits and cumulative work exhaustion; two additional tests exercise the actual retained CLI feature-selection helper.
- Strict default-feature Clippy and formatting passed.
- Offline metadata resolved 440 macOS nodes and 450 Linux nodes, including development dependencies. `audit-features.py` verifies exact selected renderer features, rejects feature-unification drift and reports inherited authority. This is dependency resolution evidence, not a renderer build or runtime receipt.
- After the U0 stock native feature retirement, an offline lock refresh retained all 611 package identities with no version changes. The refreshed lock SHA-256 is `c33f79086d277eac810705ced39730490494c77f51237fb3d0b3085138b5efc4`. Both plain-Cargo metadata gates passed again (440/450 nodes); the actual macOS `cargo tree` also excludes the forbidden resource, WebView and platform-bridge dependencies listed above.
- The exact refreshed lock passed `cargo-audit 0.22.2` against RustSec database `b50980aad8b8f14f77e25a97b32dd94bf008b0af`: 611 packages, zero vulnerability entries, with three retained unmaintained warnings: paste 1.0.15 (`RUSTSEC-2024-0436`), rustybuzz 0.20.1 (`RUSTSEC-2026-0206`) and ttf-parser 0.25.1 (`RUSTSEC-2026-0192`). No advisory ignore is configured. Audit success does not qualify font parsing, renderer behavior, accessibility or process isolation.

The metadata results above apply to the explicit **plain Cargo** command below. The first `dx bundle` expanded the renderer features and remains rejected. The corrected `--features native --renderer native` package has separate actual compiled-feature evidence, recorded next; neither result substitutes for the other.


### Corrected package and first native session

The integration owner built with official Dioxus CLI 0.7.10, `--features native --renderer native`, in a fresh target directory. The build passed in 90.11 seconds. The repaired recursive critical-fingerprint gate passed for the resulting `VhallaNativeClosed.app` executable:

- Binary: `Contents/MacOS/vhalla-native-closed`, 25,040,416 bytes.
- SHA-256: `5357dc5d90350c095fee842e8cb1190bbe8d77c279f1a51bf530e985def1b0b6`.
- Verified selected features include native `blitz-paint,svg,system-fonts`, shell with no optional features, DOM `accessibility,accesskit,svg,system_fonts`, UI with no optional features, and root/launcher library `native,renderer`.

An actual native GUI session passed owner-profile and agent-bio rendering, portraits, thread navigation, escaped hostile text, and the reader-isolation sequence **Aster ACK → Moss unread → Aster read**. These are fixture interactions; the private changes are ephemeral.

That same session found two interaction failures: search did not submit through either its button or Enter, and the ranking disclosure appeared collapsed while its explanatory content remained visible. The explicit Rust Search/disclosure handlers and sidebar layout corrections are implemented and independently source-reviewed. Automatic approval review rejected the corrected web and native builds before they started, so the updated artifacts have not been verified in either renderer. The receipt above applies only to the baseline artifact and does not claim those fixes are verified.

After that review, a fresh root-owned plain-Cargo release build of the corrected
closed native launcher passed with `--features renderer --locked --offline` in
the task-owned target directory. This proves compilation of the corrected Rust
source and closed feature graph; it does not replace a live GUI session, package
metadata audit, or offline resource and accessibility qualification.

The baseline process exited with status 0. `/usr/bin/time` reported maximum resident set size **128,761,856 bytes** and peak memory footprint **550,913,032 bytes** over a **417.66-second interactive session**. These are session measurements, not startup latency or steady-state memory measurements.

The baseline artifact's Mach-O header declares minimum macOS **11.0**, while its bundle plist declares **10.15**. Current `Dioxus.toml` explicitly sets `minimum_system_version = "11.0"`; the corrected plain-Cargo binary has not been packaged, so agreement in a newly produced bundle remains unverified. Root-owned confirmation still needs the corrected search/disclosure interactions, sidebar layout and package metadata, plus the remaining offline, accessibility, malformed-resource and install checks. No durable storage, real-key custody, OS sandbox, Linux qualification or complete-client claim follows from this first native session.

```sh
cargo test --manifest-path prototypes/dioxus-native-closed/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/dioxus-native-closed/Cargo.toml --all-targets --locked --offline -- -D warnings
cargo fmt --manifest-path prototypes/dioxus-native-closed/Cargo.toml --check
cargo metadata --manifest-path prototypes/dioxus-native-closed/Cargo.toml --locked --offline --format-version 1 --features renderer --filter-platform aarch64-apple-darwin > /tmp/vhalla-native-metadata.json
python3 prototypes/dioxus-native-closed/audit-features.py /tmp/vhalla-native-metadata.json
```

The integration owner runs native builds/tests and actual GUI work through the required host scheduler, with the complete command argument list:

```sh
cargo build --manifest-path prototypes/dioxus-native-closed/Cargo.toml --features renderer --bin vhalla-native-closed --release --locked --offline
cargo test --manifest-path prototypes/dioxus-native-closed/Cargo.toml --features renderer --lib --locked --offline
cargo clippy --manifest-path prototypes/dioxus-native-closed/Cargo.toml --features renderer --all-targets --locked --offline -- -D warnings
```

The feature-enabled fixture test sends the actual shared stylesheet and portrait URIs through the actual `NetProvider` adapter into a recording handler; unknown URIs must deliver zero bytes. That test opens no window. The plain-Cargo release adapter now compiles; the integration owner retains the separate test, live-window and package qualification gates.

For actual qualification, cold-launch the release binary outside the repository while offline, record its digest/size and requested resources, and compare Following/Discover/search/thread/profile/inbox interactions with the web build. Confirm all portraits and compiled CSS render, inert hostile text stays inert, reader switching and explicit private actions work, typed navigation remains local, and malformed resource attempts cause no OS opening or file/network access. Repeat keyboard/input and accessibility checks separately. The fixture is ephemeral; successful rendering does not establish durable storage, package installation, cross-platform behavior or a complete agent client. No official `dx` invocation or asset copying is needed for these exact embedded fixture bytes, although a distributable platform package still requires its own build/install verification.
