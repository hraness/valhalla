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
  A draft stranded by a certified policy revocation keeps its unchanged
  unsigned bytes; resume refuses it under the new current policy, and the
  explicit recover action signs it only after the retained enabling revision
  check — local continuity material, never a fresh posting grant.
- Fixed-target continuity transfer to one explicitly selected v2 peer route:
  each request attempt is durably reserved before any network exchange, the
  authenticated reply is retained before the next step, and a target completes
  only on the peer's signed terminal-admission and contiguous-retention
  evidence. Stage acknowledgements are never delivery. A target beyond the
  peer's staged-ancestor bound advances through ordered intermediate terminal
  admissions of exact signed local events without replacing the selection.
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
no Window object and owns its storage transaction in that realm. The fixture
also covers the open lifecycle: queued pending opens hold their bounded slots,
a dropped mid-open future closes its late connection, a canceled queued open
aborts its own upgrade, a foreign version bump closes live handles and refuses
v1 reopen, and a terminated worker leaves exactly its last committed state.

The same harness drives the `private_indexeddb` private-store fixture (built
with `--features private-rooms,qualification`, bindings generated under the
`indexeddb_qualification` name): exact CAS, stale competing tabs, quota denial,
aborted/canceled writes, missing/corrupt/oversized records, orphan keys and
bounded refusal. The `private_archive_indexeddb`, `private_custody_indexeddb`,
`private_mls_indexeddb` and `continuity_indexeddb` fixtures use the same entry
point and isolated profile; CI builds and runs all five.

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
harness binds only 127.0.0.1 ports 8790, 9781, 9782 and 9783, and refuses
collisions. It creates a fresh profile and network, imports that network's
public bootstrap and advertisements, creates a new synthetic identity through
the real UI and stops its own children within 300 seconds. Existing test
evidence is never replaced. Keep the local-qualification artifact out of
production deployment.

The tested flow refuses cross-room drafts before storage mutation, explicitly
moves a draft, injects a post-reservation finalization failure, reloads and
resumes the exact draft without erasing unrelated text, previews all JSON fields,
refuses changed artifact bytes/destinations, and verifies three posts through
two peers' retained receipts and signed history. It then selects a third,
continuity-mode peer, opens one receipt session bound to that peer's exact
route, retains a fixed terminal, and verifies the peer's signed
terminal-admission plus contiguous retention evidence — including ordered
intermediate admissions under a narrowed qualification bound and a strictly
later terminal replacing the target. It then reserves an exact unsigned draft
in the lobby room, watches the fixture commit a certified policy revocation to
the shared journal, syncs the new bundle, and verifies current-policy resume is
refused twice with the draft preserved before explicit recovery signs the
unchanged request under its retained enabling revision.
The output contains a receipt, artifact hash, screenshot and synthetic fixture
logs. Three local peer processes are not evidence of independent operators or a
qualified public deployment.


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
It adds no automatic network operation or agent execution environment. The optional explicit local-gateway connection described below transfers only already-encrypted artifacts.

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
native CLI. On browsers exposing
[`showSaveFilePicker`](https://developer.chrome.com/docs/capabilities/web-apis/file-system-access),
the original click requests a user-selected file before starting the export.
The app writes one bounded encrypted page at a time and closes only a complete
container. Picker cancellation starts no worker export. A write failure or Leave
and lock aborts its temporary writer; no file handle is retained for later use.
An interrupted close may have published the file, so inspect it before an explicit
retry. Browser-managed completion is not a filesystem fsync guarantee.
The picker is not supported uniformly across browsers or mobile platforms;
availability is detected at runtime. Without it, the existing 16 MiB aggregate
Blob download ceiling applies. Rust, JS and browser backing copies have separate
memory costs. Reaching a limit preserves all retained room data.

Imports authenticate the complete source image before choosing SHA-256 over a
versioned domain, full context and archive ID. Independent snapshots of one device
coexist. An origin-wide append-only catalog reserves at most four new snapshot
destinations before creation, each capped at 256 MiB of encrypted record payload
and 100,000 records. The global reserved payload cap is 1 GiB; bounded state/index
metadata and browser-engine overhead are additional. Physical quota can refuse
sooner. Reservations survive interruption and remain usable by their exact archive
at capacity. There is no automatic deletion, reset, pruning or slot reclamation.
The selected complete archive file identifies which snapshot to resume or open.
Read-only opens require existing schema: a valid file for an absent destination
refuses without creating even an empty database or consuming a catalog slot.

The explicit legacy checkbox selects the former fixed namespace for open/resume
only. New imports never create legacy state, and a failed new-route resume never
falls back to it. Existing legacy state retains its prior limits, independently
of the new catalog. Catalog integrity follows the existing trusted-origin storage
model; coherent deletion or rollback is not externally fenced.
`ArchiveImportBegin`/`ArchiveImportFeed`/`ArchiveImportFinish` retain an exact durable
receiving cursor. Worker wire version 4 introduced the explicit archive route.
The current local worker protocol is version 7, which adds retained-request
admission review and confirmation; it refuses older frames. This IPC upgrade
does not change retained room, archive or delivery images. `ArchiveOpen` reopens a
finished archive for read-only membership, inbox and redacted-outbox inspection
plus explicit ciphertext downloads. Header fields are unauthenticated hints;
foreign accounts refuse before import begins; malformed containers, oversized
pages and trailing bytes refuse as their bounded slices are read. Earlier
authenticated pages may already be retained. A local read failure after import
begins locks custody and directs the user to unlock and reselect the same
complete archive to resume its exact durable cursor. An archive destination never becomes a live
sender and never overwrites existing state. The emitted-worker journey now also
exports a real archive, refuses a foreign-account header, interrupts and resumes
an import at its durable cursor, reopens the finished archive read-only, verifies
its recorded head against the live room, and refuses a foreign archive context
terminally. The DOM journey also restores a `.vhkey` backup into a third
browser context, admits it through a self-addressed confidential offer as a
distinct same-account device, and verifies it starts with no pre-join history
while exchanging post-join messages both ways. It also applies an ordered
owner removal control: the excluded device keeps read-only retained state but
cannot prepare new sends. The controls section additionally pages retained
encrypted envelopes and signed owner-control proofs, downloads exact
`.vhproof` files, and observes an imported proof against local history —
reporting retained, unknown future floor, or below the joining device's
retained base — while the fork-evidence read reports whether a durable
contradiction exists. A local-qualification-only phase then has the owner
device re-sign divergent claims at a retained removal floor; the member
observes the resulting `.vhproof` through the real observation path, the
kernel quarantines durably and the worker ends terminally, and a fresh
document in the same browser context reopens the exact locator to show
quarantine status plus the retained accepted/conflicting proof while sends
stay refused and retained history stays readable. A second
qualification-only phase applies a real next-floor control under a caller
clock past the enrollment validity: the ordinary time refusal ends the
worker without publishing or quarantining anything, and after another
document teardown the identical envelope applies under the real clock. The
journey then exercises owner succession end-to-end: the owner hands authority
to its already-admitted same-account fresh device through one distributed
owner control, the predecessor keeps ordinary membership but loses owner
actions, the promoted successor issues a renewal control, and the predecessor
applies it in order without regaining owner actions. Safe live-device
transfer remains separate work.


## Explicit local-host private sync

Build the production private UI from the `browser/` directory into a separate
output path, then generate its checked asset manifest:

```sh
trunk --skip-version-check build --release --locked --features private-rooms --dist /absolute/new-private-browser
python3 tools/package.py /absolute/new-private-browser
```

Use that directory as the gateway's `assets_dir`. The default public build does
not include private-room controls, and a `local-qualification` build is refused
by the gateway.

A production `private-rooms` build can run at a **fixed**
`http://127.0.0.1:PORT` origin served by `vhalla private-gateway`. The gateway
forwards opaque relay requests through the selected CA/name-pinned TLS endpoint.
Run native Tailcat forwarding on that browser's machine when the relay host is
elsewhere. A generic `tailcat browse` chooses a random local port and therefore a
new IndexedDB origin; use a fixed explicit forward instead. Browser-only/mobile
Tailcat, autonomous browser hosting and background persistence are not implemented.
When forwarding the gateway itself, use the same `127.0.0.1` host and local port
as its configured origin: its Host/Origin checks intentionally reject a different
forwarded port. A local gateway may instead forward only its upstream TLS socket.
Your Mac can sleep or disconnect: queued ciphertext remains durable locally and
progress resumes when you explicitly reopen and select **Sync now**.

After opening a room, choose a private JSON connection profile:

```json
{
  "format": 1,
  "origin": "http://127.0.0.1:8790",
  "namespace": "<64 lowercase hexadecimal digits from the selected relay host>",
  "capability": "<distinct gateway capability, 64 lowercase hexadecimal digits>",
  "initial_cursor": "0"
}
```

The origin must exactly match this worker's fixed loopback origin. The gateway
capability is distinct from the host-only relay token and is supplied again on
each unlock. The worker holds it only in memory, and clears the selected file
input immediately. Browser-managed temporary copies are outside a guarantee of
complete memory erasure. Keep this profile file `0600` inside a `0700`
directory and never in Downloads or other shared locations; its capability is
a bearer credential. Revocation or replacement requires an explicit gateway
configuration change and drained restart; locking a worker does not revoke the
shared gateway capability.
An authorization refusal locks that worker and retains its exact pending job,
charged attempt and backoff. Explicitly unlock and select a profile carrying the
current capability to resume; correcting authority never resets finite budgets.
The same explicit recovery applies after the operator repairs a rejected upstream
relay credential. Malformed frames, pages or receipt commitments instead persist
a permanent stop before custody closes; reopening preserves that refusal.

**Configure new connection** requires wholly absent delivery progress.
**Open retained connection** requires its exact retained profile, including full
room/anchor/account/device, origin, namespace and initial cursor. Neither path
resets budgets or rewrites a changed profile. A fresh admitted member must obtain
its initial mailbox cursor from the trusted admission handoff, after older
ciphertext has been published; it cannot decrypt pre-join history. A rejected MLS
record is never an excuse to guess a later cursor or silently skip it.
The canonical decimal initial cursor must be within the mailbox's 4,096-item
lifetime limit; an oversized cursor refuses before any delivery state is created.

Each **Sync now** reserves its finite attempt before networking, fetches one
page of at most four incoming records, processes inbound work before sending,
and transmits at most two queued artifacts. Encrypted membership controls have
their own retained stream: admitting another member automatically forwards the
control existing members need, while confidential bootstrap admission remains
explicit. The two outgoing streams merge by authenticated epoch so an earlier
local application precedes its epoch-changing control and a newer application
waits for that control. This establishes local source order, not a global order
across independent devices. Applying a membership change stops at the roster
review boundary. Every sync clears any prepared message consent. The worker streams
bounded Fetch replies with a ten-second request deadline, no cookies, redirects,
referrer or background polling. IndexedDB retains exact pending ciphertext,
charged attempts/backoff, a staged canonical page and its progress. Future-epoch,
ahead-ratchet and missing-control records enter an eight-item durable deferred
queue so later prerequisites can still be fetched. Each sync retries that bounded
queue before and after its incoming page. Status distinguishes fetched progress
from the contiguous resolved prefix. If all eight slots are occupied, the next
retryable item stays staged and delivery reports the capacity block; ciphertext
is never evicted to manufacture progress. This bound does not promise liveness
for every backlog. Reopening validates each retained item against its indexed
commitment. Version-1 and version-2 images upgrade without resetting budgets,
pending work or recorded refusals; older binaries refuse the version-3 image. A new
worker claims an exact CAS ownership token; stale tabs refuse further progress.
Deploy the upgraded clients together: independently retained older clients have
no control-stream capability negotiation and may classify a future-epoch message
incorrectly before encountering the new control kind. Mixed-version delivery is
not qualified by the same-custody image upgrade.
Room publication has its own kernel CAS. These fences do not promise isolation
from trusted same-origin code or browser storage rollback/eviction.

An outage preserves an uncertain exact send. Reopening never re-encrypts it or
replenishes the lifetime cap of 4,096 attempts / 1 GiB charged relay-frame bytes
(HTTP/TLS headers and browser-engine overhead are additional). Every exchange
reserves its worst-case frame bytes before networking; a completed exchange
settles to its exact request/reply bytes, while an interrupted or failed
attempt keeps the full reservation. Ten
consecutive reserved unsuccessful attempts stop delivery; success clears only
that consecutive count. Terminal room/storage errors end custody and preserve
state for inspection. Bootstrap contact artifacts require explicit admission,
never automatic membership. An owner can select a retained encrypted join
request, enter its full recipient account and select the original confidential
offer (or use the matching offer still held in this unlocked panel). **Review
selected join request** authenticates the request and shows the full room,
owner account/device, recipient account/device, current roster and epoch,
request commitment and capped invitation expiry. It does not consume the offer
or change membership. **Admit this reviewed device** separately confirms that
exact review; the worker rereads retained bytes and rechecks current membership
before invoking the existing kernel admission operation. The offer remains
confidential and is never included in a relay request.

Review permission exists only in the unlocked worker, is single-use and is
bound to that worker session. An intervening worker operation, including a
membership read or same-roster sync, invalidates it. Changing the selected
recipient, offer file or retained item also clears the panel's confirmation.
Lock/reload requires a fresh review. A refusal preserves retained evidence;
if custody closes, unlock and reopen before reviewing again. Successful
admission saves the encrypted response and leaves the original retained
request until explicit discard; it does not automatically admit another item.

This flow removes the owner's request download/reimport step. A browser
awaiting its first welcome still cannot connect or sync. Confidential offer
handoff and recipient response file import remain explicit; prejoin transport
and response review need a separate contract. The sender's status reports
relay retention; incoming status reports local committed acceptance. Neither
claims human reading. Normal incoming applications queue a device-signed
acceptance artifact; receipt messages do not generate receipt loops.
The live outbox displays peer claims that the kernel has signature-verified
against the exact retained ciphertext and the locally accepted roster. Each
claim names its signing device and claimed durable inbox position. A relay
receipt alone produces no such claim; a device claim does not prove human
reading, remote disk durability or globally current membership.
A recipient can accept a message but return its receipt after the sender has
advanced epochs; that stale receipt is recorded as refused. An absent claim
therefore does not establish that the recipient missed the message.

The production browser-to-gateway-to-TLS journey uses synthetic identities and
actual native services, including durable outage/reload/retry and stale-tab
checks:

```sh
node browser/tools/qualify_private_delivery.mjs PRODUCTION_PRIVATE_DIST CHROMIUM_EXECUTABLE NEW_OUTPUT_DIR VHALLA_CLI OPENSSL_EXECUTABLE [--gateway-port N] [--tls-port M]
node browser/tools/qualify_private_panel.mjs PRODUCTION_PRIVATE_DIST CHROMIUM_EXECUTABLE ANOTHER_NEW_OUTPUT_DIR --production
```

The harness verifies a packaged **production** artifact and uses no qualification
entry points. It binds only `127.0.0.1` loopback addresses: one ephemeral gateway
HTTP port and one ephemeral relay TLS port by default, or explicit
`--gateway-port`/`--tls-port` values. An occupied port always refuses and is
never reused, and the receipt records the selected gateway origin and TLS
address. Run it through the repository's browser-auth scheduler lane. Its
same-machine receipt does not substitute for independent-machine Tailcat or
sleep/wake qualification.
The second command covers ordinary private UI, archive routes and streaming
export on the same production artifact. Without `--production`, that driver
requires a local-qualification artifact and additionally exercises injected
fork and expired-clock cases; those entry points never enter the production build.
