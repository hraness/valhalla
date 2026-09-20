# Private-room MLS qualification (not a shipping client)

This isolated workspace exercises real OpenMLS 0.9.0, matching provider/traits/
credential/storage 0.6.0, and standard RFC 9420 features. It is outside Valhalla's
production workspace and lockfile. Its only public API runs an ephemeral synthetic
two-member exercise. It has no network, filesystem store, invitation controller,
browser UI, production identity access, or arbitrary signing API.

The private model stages OpenMLS against a fresh hydrated MemoryStorage, seals the
next complete state with XChaCha20Poly1305, and atomically replaces one encrypted
image only after exact base comparison. Outgoing ciphertext is retained in that
same image. Decrypted inbox text is quarantined until a committed image is read.
Fault tests cover refusal, uncertain completion requiring reopen, competing CAS,
one-use KeyPackage consumption, exact retries, removal and tampered inputs.

The in-memory assignment models a transaction; it does not prove IndexedDB quota,
filesystem durability, power-loss safety, or concurrent process locking. The
model's wrapping key exists only in memory. Cryptographic keys and nonces are fresh
OS/browser randomness, while labels and operation IDs are public synthetic test
data. The browser build follows upstream `openmls/js` plus `getrandom0.2/js`.
The synthetic flow passed in a Chromium 153 dedicated worker with the exact
bindings below, without cross-origin isolation. A separate worker with denied
secure randomness refused before proceeding. This exercises runtime/entropy
compatibility; its memory model still does not establish real storage durability.

Use a separate fresh MLS leaf on a recovered/new device. A reused account label
does not recover old KeyPackage secrets or authorize an invitation. No live
ratchet snapshot import/clone is exposed. The tests do not claim defense against
coherent disk rollback, browser eviction, malicious origin code, backups retaining
old message keys, or exhaustive zeroization of OpenMLS/serde allocations.

Before maintained integration, add canonical full private-room/owner/device scope,
typed identity-to-device credentials and owner-approved one-use invitation grants,
credential/committer authorization at Welcome and every staged Commit, durable
Commit ordering, encrypted state/outbox/inbox transactions with real backend crash
tests, worker generation gates, bounded ciphertext relay and explicit rejoin.
The prototype merges its owner's add/remove commits locally for a sequential test;
that is not a concurrent delivery or owner-authorization protocol. No private data
may enter the public directory or public activity without a separate explicit
release. Public discovery can coexist without listing private rooms or members.

Budgets here are deliberately finite qualification limits: 4 MiB encrypted-state
plaintext, 256 provider records, 64 outbox/inbox records, 128 KiB wire frames,
4 KiB application content, two members in the exercised join. They are not a
production retention design. Old outbox payloads are retained as ciphertext;
historical decrypted inbox content remains recoverable from the current storage
key, which is different from retaining old MLS message keys.

Run with the repository-selected Rust 1.98.1 through its host scheduler:

```sh
cargo test --locked --manifest-path prototypes/private-rooms-mls/Cargo.toml
cargo clippy --locked --all-targets --manifest-path prototypes/private-rooms-mls/Cargo.toml -- -D warnings
cargo check --locked --lib --target wasm32-unknown-unknown --manifest-path prototypes/private-rooms-mls/Cargo.toml
```

Security baseline: 0.9.0 fixes GHSA-w62v-gv48-63rh and GHSA-rrmv-c79f-cf5r;
earlier tag-validation and secret-tree persistence advisories are also fixed.
No draft or sensitive logging features are enabled by this prototype. Upstream's
RustCrypto provider still has a wider dependency graph, including HPKE's
`experimental` feature; selecting a standard suite does not erase those edges.
See the task report `outputs/mls-adapter-qualification.md` for pinned source links,
WASM/entropy details, exact storage APIs, and remaining qualification gates.

The target-WASM-only `qualify_browser()` export runs the same synthetic native
exercise and returns success or a fixed error label, without inputs or secret
outputs. Its generated bindings are pinned to the maintained browser versions
`wasm-bindgen0.2.108`/`js-sys0.3.85`. Run the retained real-browser harness from
the repository root with Node 24 and a Chromium executable:

```sh
cargo build --locked --manifest-path prototypes/private-rooms-mls/Cargo.toml --target wasm32-unknown-unknown
wasm-bindgen prototypes/private-rooms-mls/target/wasm32-unknown-unknown/debug/valhalla_private_rooms_mls_qualification.wasm --target web --out-name private_rooms_mls --out-dir GENERATED_DIR
node prototypes/private-rooms-mls/tools/qualify_browser.mjs GENERATED_DIR CHROMIUM_EXECUTABLE NEW_OUTPUT_DIR
```

Use absolute paths and a new task-owned output directory. The harness creates a
fresh browser profile, serves only generated files on a random loopback port,
blocks external DNS and stops its browser/server within 90 seconds. It records
artifact hashes and a success/entropy-denial receipt, never keys or plaintext.
Its strict CSP requires neither third-party scripts nor shared memory. Required
browser CI runs this check separately from production packaging.
