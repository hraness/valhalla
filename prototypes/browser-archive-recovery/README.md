# Browser archive recovery isolation spike

This fixture proves an additive destination scheme without changing production
archive routing or migrating user data. Each new destination is SHA-256 over a
fixed versioned domain, full private context, and authenticated archive ID. The
existing fixed archive namespace remains untouched and readable.

The fixture uses a publicly derivable synthetic account in a fresh Chromium
profile. Real MLS creates two source revisions; real archive authentication
must succeed before a destination is selected. Three dedicated workers create
the fixture, stop after one durable import page, and reopen/verify it. The
harness terminates the middle worker before import completion.

Assertions cover:

- Archive A and newer B coexist for the same device, while legacy A stays readable.
- Substituted context and archive ID fail before any destination mutation.
- Reopening after worker termination retains the exact confirmed page; retrying
  that page does not advance its record count or cursor.
- An injected `QuotaExceededError` at a real IndexedDB transaction boundary
  requires reopening and leaves image, record count, and bytes unchanged.
- The resumed B completes and independently exposes its newer outbox.

The quota error is injected, not a full physical disk. The worker is terminated
after acknowledged page durability, not at every crash timing. This is one
browser on one host, not independent-device qualification or a live-custody
transfer protocol.

Run from the repository root using the installed host scheduler. Select the
repository toolchain explicitly and use its existing target directory:

```sh
cargo test --locked -p vhalla-browser-storage --features private-archive-qualification --example private_archive_recovery
cargo clippy --locked -p vhalla-browser-storage --features private-archive-qualification --example private_archive_recovery --target wasm32-unknown-unknown -- -D warnings
cargo build --release --locked -p vhalla-browser-storage --features private-archive-qualification --example private_archive_recovery --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/examples/private_archive_recovery.wasm --target web --out-name archive_recovery --out-dir GENERATED_DIRECTORY
node prototypes/browser-archive-recovery/qualify.mjs GENERATED_DIRECTORY CHROMIUM_EXECUTABLE NEW_OUTPUT_DIRECTORY
```

Use `wasm-bindgen` 0.2.108 to match `Cargo.lock`. The runner also accepts bindings
from a debug build; it has no release-only assumptions. Native tests, builds,
and lint use the compute lane; Chromium qualification uses `browser-auth`.

Local qualification on 22 September 2026 passed the native namespace test
(1 test), strict WASM Clippy, the release WASM build, and Chromium 153 runtime
assertions above with Rust 1.98.1. The 20,765-byte synthetic fixture reported
page 2 before worker termination. Setup, interrupted import, and reopened
verification performed 12, 3, and 2 strict write transactions respectively;
the reopened worker observed exactly one injected quota refusal. No production
namespace or migration behavior was changed. The generated WASM SHA-256 was
`fe52a7606e9e006d57f434df8566bf7bd39925d4d4dde46a8c714369c8861cd8`.

Promotion requires explicit legacy destination selection. In particular,
`ArchiveImport::resume` consumes its authenticated source on refusal, so a safe
non-consuming legacy probe or explicit user-selected legacy route is needed
before production can choose between destinations. Never reinterpret a failed
resume as permission to replace old state. Also retain storage budgets across
multiple snapshots, expose snapshot choice in recovery UI, and qualify
interrupted writes in additional browsers before broader durability claims.
