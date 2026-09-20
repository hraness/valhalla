# Valhalla browser

This Rust/WASM development application implements a locally verified public-room
client. It is not an activated public network or a completed browser release.

- Encrypted identity creation, worker-owned unlock/signing, `.vhkey` backup and
  same-key restore. The main thread never receives a raw private key.
- Full bootstrap fingerprint selection, certified directory replay, transactional
  retained history and explicit signed HTTPS peer selection.
- Bounded discovery listings with independently verified candidates. A candidate
  is not contacted until explicitly selected and used in a network action.
- Exact draft reservation before signing, an immutable local outbox, signed
  public-page reading and separately retained proof-bound receipts per peer.
- Bounded multipart encrypted author-state export/import, including sequence
  history, pending draft and receipts. Import activates only after complete
  verification into an absent scope; it never resets or merges existing state.
- Explicit public puzzle-part preview/queueing through the same draft/outbox,
  and one bounded incoming artifact assembly from signature-verified posts.

The controller treats an uncertain storage or signing operation as a recovery
condition. Peer receipts attest to that peer's observed local retention; they
are not consensus, independent work verification or global availability.

All product logic is Rust. Trunk produces the JavaScript loader and wasm-bindgen
glue, including the worker loader; no authored JavaScript or TypeScript is used.
Build with Rust's `wasm32-unknown-unknown` target and Trunk 0.21.14:

```sh
cd browser
trunk --skip-version-check build --release --locked
python3 tools/package.py dist
```

The pinned wasm-bindgen CLI is 0.2.108, matching the workspace libraries. Use the
same Rust toolchain for Cargo and rustc; a second compiler earlier in PATH may
not have the WebAssembly target installed. Deploy the generated `dist` directory
on a separate HTTPS application origin, not inside a third-party script-heavy
marketing origin. There are no analytics, third-party scripts or fonts.

A `.vhkey` restores the application key only. Author recovery additionally needs
all numbered `.vhauthor` parts, including the final part, for each used room.
Keep authoring and delivery idle while exporting. Restore the latest complete
backup and stop the previous authoring device: no offline backup can prove that
no later signature exists elsewhere. A restored key without author state cannot
safely begin that room's sequence again. Neither backup restores owner-control
history or grants a room's posting permission.

No browser storage API prevents eviction or coherent rollback, and
a password vault does not protect an unlocked key from same-origin compromise.
Backups permit offline password guessing: use a strong independent password.
The UI never calls a download request proof that a backup is saved elsewhere.

Network integration uses `vhalla-public-client` for pinned genesis/certified
room replay and `vhalla-public-protocol` for signed route advertisements. Those
crates alone do not activate a serving endpoint or confer public posting rights.
Public activity must name the complete room identity and an explicitly enabled,
committed public-activity policy. The ordinary social archive's lifetime ceiling
must not become the room activity history store.

Before operational activation, qualify real browser worker and IndexedDB
lifecycles, competing tabs, interrupted writes, quota errors, backup recovery,
pinned-network replay, provider failover, and strict production CSP. Browser
storage completion and independently verified consensus are different states.

Production packaging extracts only Trunk's generated loader bytes into an
external module, emits restrictive CSP/security headers and hashes every asset.
It rejects embedded local-qualification routes by default. The explicit
`--allow-local-qualification` packaging override is only for development tests;
its manifest is labeled `local-qualification` and must never be deployed. The
production CI build does not enable that Cargo feature.

Public content is rendered as inert text. Browser Fetch cannot pin hostname DNS
answers or establish that selected peers are independent operators. Selected
peers are replaceable transport providers, not validators by discovery. The
current browser transport is HTTPS to native peers; direct browser-to-browser
mesh and automatic peer replication remain separate capabilities.

The room's puzzle panel accepts one CLI-prepared public challenge, response or
admission part at a time. Validate and preview it, then explicitly sign and save
that unchanged part. An existing pending draft is never replaced or resumed by
this action, ordinary composer text is preserved, and sending remains separate.
For reception, select the full sharer key, artifact kind and SHA-256 digest,
start collection, then read public activity pages (or the latest 16 local outbox
posts). One selected artifact is bounded to 256 KiB / 94 parts. Room, network or
selector changes discard only derived collection state, never author history.

Download becomes available only after the exact complete digest matches. The UI
shows its full room scope and sharer attribution; it does not interpret artifact
contents as verified issuer authority or a successful solve. No model, downloaded
code, arbitrary URL or host command executes in the browser. Native Clankdar
history checking remains the separate explicit verification step. This local
artifact exchange surface does not establish peer PUBLISH availability or
completed public-network/browser qualification.
