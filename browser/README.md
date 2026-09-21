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

The room's puzzle panel first requires the complete public JSON artifact. Review
its decoded fields and exact input, then explicitly approve it for the selected
room and author. Nested duplicate fields are rejected. Approval binds the exact
bytes, kind, network, bootstrap fingerprint, full room identity and author.
Each CLI-prepared part must exactly match that approved artifact before signing;
changing the content or destination requires a new review. Approval remains
local to this tab and is lost on reload. It does not verify a solve or issuer. An existing pending draft is never replaced or resumed by
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


## Reproducible browser regression

The development harnesses use an isolated Chromium profile and synthetic data.
They do not attach to a personal browser, import a private identity, or contact a
production peer. Node 24 runs them without an additional browser-test dependency.
Use the host browser lane where the repository scheduler is installed.

For the storage adapter, build the `indexeddb_qualification` example for WASM,
generate web bindings with wasm-bindgen 0.2.108 into a new test directory, then
run `node browser/tools/qualify_storage.mjs GENERATED_DIR CHROMIUM_EXECUTABLE`.
It checks strict writes, read-only unlock under write denial, ignored durability,
throwing durability getters, transaction abort and competing identity snapshots
against real IndexedDB in both the page and a dedicated worker. The latter has
no Window object and owns its storage transaction in that realm.

For the complete client, build and package a separate local-qualification
artifact and the synthetic two-room fixture:

```sh
cargo build --release --locked -p vhalla-public-peer --example browser_fixture
# In browser/, use a separate absolute output path:
trunk --skip-version-check build --release --locked --features local-qualification --dist TEST_DIST
python3 tools/package.py TEST_DIST --allow-local-qualification
# Back in the repository root; every path below selects task-owned test data:
node browser/tools/qualify_product.mjs TEST_DIST FIXTURE_EXECUTABLE CHROMIUM_EXECUTABLE NEW_OUTPUT_DIR --recovery
```

Use absolute paths for the artifact, executables and new output directory. The
harness binds only 127.0.0.1 ports 8790, 9781 and 9782, and refuses collisions.
It creates a fresh profile and network, imports that network's public bootstrap
and advertisements, creates a new synthetic identity through the real UI and
stops its own children within 300 seconds. Existing test evidence is never
replaced. Keep the local-qualification artifact out of production deployment.

The tested flow refuses cross-room drafts before storage mutation, explicitly
moves a draft, injects a post-reservation finalization failure, reloads and
resumes the exact draft without erasing unrelated text, previews all JSON fields,
refuses changed artifact bytes/destinations, and verifies three posts through
two peers' retained receipts and signed history. The output contains a receipt,
artifact hash, screenshot and synthetic fixture logs. Two local peer processes
are not evidence of independent operators or a qualified public deployment.


The optional `--recovery` extension creates encrypted key and multipart author
backups from that synthetic identity and holds them only in test-driver memory.
It stops the former author, restores into the separate `localhost:8790` origin,
and checks key-only, wrong-room, final-part-first and incomplete-backup refusals.
A reload interrupts staged import; completing it must preserve the exact pending
draft and both peer receipts. The next signature must use sequence four, and a
further reload must retain it without resending already acknowledged history.
This remains a same-machine test with controlled local peers, not independent
device or storage rollback protection. Required CI uses the extension; its
encrypted fixtures are never taken from an existing user profile.


The complete synthetic recovery journey passed in Chromium153 on20September2026:
one encrypted key backup and three author-state parts restored into a fresh
loopback origin. Key-only, wrong-room, final-part-first and incomplete imports
did not authorize signing. Staged import survived reload; the recovered author
retained both peers' receipts through sequence3, finalized the exact reserved
fourth post and retained its new receipts across another restart. The former
writer was locked and its browser target closed before restored signing. The
two peers observed exactly eight POSTs in total, with no resend of acknowledged
history. This is a single-machine Chromium result, not independent-device or
private MLS recovery evidence.


## Optional private room custody

The off-by-default `private-rooms` feature adds a typed trusted-UI broker and
private commands to the existing identity worker. Entering private mode is
irreversible for that worker: public signing, public author export and account
replacement refuse while private custody is ready, busy or failed. Leaving ends
both account and kernel custody and requires explicit unlock in a new worker.
It adds no relay, automatic network operation or agent execution environment.

Each operation rechecks the exact saved account image before and after kernel
access. Interrupted, failed or canceled work terminates custody; reopen must use
the exact full room/anchor/account/device locator and retained store. Missing
state refuses. Creation has separate preparation, explicit locator-retention
acknowledgment and commit steps. A download request alone is not acknowledgment
that the locator has been retained. Message consent binds exact content, operation,
epoch and roster; changing membership requires fresh review.

The actual emitted-worker journey is reproducible with a separate artifact:

```sh
# From browser/, select a new absolute test output directory.
trunk --skip-version-check build --release --locked --features private-rooms,local-qualification --dist TEST_DIST
python3 tools/package.py TEST_DIST --allow-local-qualification
# From the repository root:
node browser/tools/qualify_private_session.mjs TEST_DIST CHROMIUM_EXECUTABLE NEW_OUTPUT_DIR
```

It uses a fresh synthetic Chromium profile and the real account KDF, worker and
IndexedDB. It checks public-command refusal in all three private modes, locator
retention before creation, cancellation after a committed send, late old-worker
reply refusal, exact reopen and ciphertext recovery, changed vault/account
refusal, and missing-store preservation. The public production artifact excludes
these local qualification hooks; packaging rejects their presence by default.
The optional private panel also has a real DOM/file-exchange journey:

```sh
node browser/tools/qualify_private_panel.mjs TEST_DIST CHROMIUM_EXECUTABLE NEW_PANEL_OUTPUT_DIR
```

It creates two isolated browser accounts with the normal KDF, retains real `.vhroom`
locator downloads before initialization, reviews confidential recipient-bound offers,
exchanges encrypted join requests/replies and bidirectional messages, and reopens
exact retained ciphertext. It checks real keyboard activation, inert imported text,
ordered control catch-up, consent invalidation on roster/text changes, metadata-only
secret outbox entries, and clearing plaintext/file selections/blob URLs on lock.
Responsive checks cover 1280, 768 and 390 CSS pixels. This journey uses local file
exchange with no external relay or network publication. Production packaging still
rejects qualification hooks; the optional private interface requires an explicit
`private-rooms` build.

The panel also handles the canonical `.vharchive` container shared with the
native CLI. An open room exports its complete retained state as one encrypted
file through bounded `ArchiveExport`/`ArchiveExportNext` page requests; a
selected file imports page-by-page into a separate read-only IndexedDB namespace
(`ArchiveImportBegin`/`ArchiveImportFeed`/`ArchiveImportFinish`) whose durable
receiving cursor resumes exactly after interruption, and `ArchiveOpen` reopens a
finished archive for read-only membership, inbox and redacted-outbox inspection
plus explicit ciphertext downloads. Header fields are unauthenticated hints;
foreign accounts, malformed containers, oversized pages and trailing bytes are
refused before any kernel call. An archive destination never becomes a live
sender and never overwrites existing state. The emitted-worker journey now also
exports a real archive, refuses a foreign-account header, interrupts and resumes
an import at its durable cursor, reopens the finished archive read-only, verifies
its recorded head against the live room, and refuses a foreign archive context
terminally. The DOM journey also restores a `.vhkey` backup into a third
browser context, admits it through a self-addressed confidential offer as a
distinct same-account device, and verifies it starts with no pre-join history
while exchanging post-join messages both ways. Owner succession and safe
live-device transfer remain separate work.
