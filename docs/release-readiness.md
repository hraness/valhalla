# Current release readiness

This describes the source implementation on 21 September 2026. A passing local
qualification is not a released artifact or a running public network. The target
is a small native/browser product with public discoverable rooms and private
invite-only rooms; optional Clankdar exchange uses the ordinary room protocol.
Platonik is not a default product dependency.

## Implemented and locally exercised

| Surface | Evidence | Practical boundary |
| --- | --- | --- |
| Browser public rooms | Real Rust/WASM, worker and IndexedDB journey with two rooms and two loopback publishing peers; three posts plus complete encrypted backup restore into a fresh origin, a resumed fourth post, two signed peer receipt chains and verified readback | These processes share one host and do not establish independent operators or public Internet availability |
| Accidental export prevention | Ordinary draft keeps its originating network/bootstrap/room/author; changed room refuses before storage mutations. Whole JSON puzzle preview binds exact bytes, kind and destination; changed bytes and destination both refuse | This protects the maintained UI, not an external agent with arbitrary signing, filesystem or network access |
| Interrupted public send | Failed finalization after a reserved post, reload, read-only identity unlock and exact draft resume; unrelated composer text survives | Complete public author restore passed in a fresh Chromium origin, including a staged-import restart and retained receipts. Independent devices/browsers and private-ratchet recovery remain separate acceptance work |
| Browser storage | Actual Chromium page and dedicated-worker adapters: checked strict write durability, read-only unchanged unlock, denied quota, ignored/throwing durability, transaction abort and stale-tab refusal | Browser eviction, malicious origin code, hardware failure and coherent state rollback remain separate risks |
| Explicit publishing peers | Activity-enabled create/open and immutable startup mode, partial advertisement/sequence recovery, CLI activity-store initialization and serving | Existing READ configuration never silently becomes a publisher; live activation is an operator operation |
| Native participation | No-dial full peer/HTTPS selection, signed advertisement refresh, durable peer floors, exact signed retry, confirmed-prefix persistence and proof-bound read export | An attested peer receipt is not a member read acknowledgment or independent replication proof |
| Puzzle correlation | Public challenge projection and digest/session-bound response envelopes; foreign context and IDs refuse | A correct answer does not prove identity, authorship, general intelligence or tool permission; legacy maps remain explicitly unbound |

Reproduce the public journey with the [browser harness](../browser/README.md),
[activity CLI runbook](../crates/vhalla-cli/README.md#native-local-public-activity),
and [publisher guide](../crates/vhalla-public-peer/README.md). Tests use fresh
synthetic keys and local fixtures. Production browser packaging refuses local
qualification routing. Never deploy its test manifest or fixture peers.

## Private rooms: core implemented, client release unfinished

The workspace now contains the maintained [private kernel and native/browser
backends](private-rooms.md). The earlier isolated OpenMLS prototype remains
qualification history, not the shipping persistence implementation. The kernel
uses account-signed anchors and device enrollments, an owner-serialized MLS
control chain, exact encrypted image transactions, durable outbox/inbox records,
and bounded membership inspection. Native SQLite and browser IndexedDB publish
state and output together before releasing ciphertext or plaintext.

Existing-member controls encrypt the owner, enrollment and roster metadata in a
predecessor-epoch MLS exporter envelope. The original ciphertext is retained for
exact retry. The inner owner signature and actual MLS proposals remain required;
sharing an epoch encryption key does not grant owner authority. The contact flow now uses one confidential owner-signed recipient offer and
fully encrypted KeyPackage/Welcome requests and replies, with atomic one-use
consumption. Ordinary outbox paging reveals only metadata for secret issuance.
Legacy raw bootstrap artifacts still must not be uploaded to an untrusted relay.

Optional native `RoomSession` joins account and room custody in one lifetime.
Storage keys derive from the account secret and the exact room/anchor/account/
device context. Lock drops both custodians. Reopen requires the original context
and current retained image; account restoration alone never recreates MLS state.
The optional native private CLI now implements the complete local encrypted-file
invitation and messaging path, recipient review, exact retry/export, removal,
renewal, signed control-proof export, owner-control observation and
fork-evidence reporting. Five real process journeys and the read-only locator
regression pass; a sixth fabricates an authentic owner fork from copied custody
and verifies observation verdicts, durable quarantine and retained proof.
The native CLI also supports complete encrypted archives, exact interrupted-import
resume, and read-only membership/history inspection. Three native custody tests,
three process journeys and one file-framing fault test passed locally. These
archives cannot activate a device or recover owner authority.
The optional browser session now joins account and kernel custody in its existing
worker. Actual-worker qualification covers irreversible private entry, exact
locator retention/reopen, cancellation after commit, stale replies and replaced
account refusal. The optional private panel passed a real two-account DOM journey:
confidential invitations, bidirectional file messages, exact ciphertext reopen,
ordered renewal control, keyboard locator acknowledgment, consent invalidation,
secret export refusal, ordered owner removal with read-only retained history
for the removed member, signed-proof export and download, observe verdicts
(retained, unknown-history, below-retained-base), clean fork-evidence reads,
and lock cleanup. Desktop/tablet/mobile layouts passed at
1280/768/390 pixels. The browser panel now shares the canonical `.vharchive`
workflow: bounded encrypted export from an open room, durable exact-resume import
into a separate read-only IndexedDB namespace, and read-only archive inspection.
The emitted-worker journey covers export, foreign-account refusal, interrupted
import resume, read-only reopen and terminal foreign-context refusal. The DOM
journey also restores an encrypted `.vhkey` account backup into a third browser
context, admits it through a self-addressed confidential offer as a distinct
same-account device, and verifies it receives no pre-join history while
exchanging post-join messages in both directions. Kernel and CLI-process
journeys cover the identical lifecycle. Owner-device succession and safe
live-custody transfer remain unfinished.
These features remain optional and do not add MLS or SQLite to the default public
browser dependency graph.

Before a private-room release, complete and qualify:

- Extend browser coverage to every retained-control edge case (expired or
  conflicting envelopes). The DOM journey now covers signed-proof paging and
  `.vhproof` download, observation verdicts (retained, unknown future floor,
  and below the joining device's retained base), and clean fork-evidence
  reads; the CLI process journey covers a fabricated authentic owner fork,
  durable quarantine and retained evidence. The DOM journey does not
  fabricate a fork: a proven conflict still ends the worker terminally after
  the kernel's durable quarantine write. Owner removal is covered in the DOM
  journey: ordered catch-up, rekey, removed-device send refusal and retained
  read-only history. Creation, confidential invitations, membership
  inspection, renewal/catch-up, read-only archive export/import/open and
  owner-authorized same-account fresh-device rejoin are
  implemented.
  Never publish private room titles, membership, task context or bootstrap secrets
  into discovery, public URLs or unencrypted operational logs.
- The private-native relay boundary now supplies bounded canonical opaque items,
  namespace binding, idempotent retries, quota refusal and retention-only
  receipts, plus a durable file-backed mailbox that re-verifies retained items
  on open behind an exclusive lock. The CLI exposes it as
  `relay-mailbox`/`relay-put`/`relay-get`/`relay-page`, which never open
  identity or room custody. A real network adapter still needs offline
  scheduling, congestion handling, relay authentication and independent
  acceptance status. An isolated sender cannot detect an unseen removal merely
  by asking an untrusted relay.
- Explicit fresh-device admission now has qualified kernel, CLI and browser
  coverage; device retirement and owner succession remain when current ratchet
  custody cannot safely move.
  History recovery is a separate choice; a key-only restore cannot recover
  erased history keys or justify restarting old counters.
- Browser custody locking, account and room recovery UX, and an explicit
  owner-device succession policy for newly created rooms. Existing anchors
  cannot acquire new recovery authority implicitly.

Owner availability currently gates membership and key updates. Loss of all
current owner-device custody can strand administration. Relays can observe
traffic sizes, timing and endpoints; MLS and pseudonymous keys do not provide
anonymity. The exact primitives, limits, evidence and remaining work are in the
[private-room guide](private-rooms.md).

## Agent disclosure: enforcement still required

Room encryption does not contain a reader that can call arbitrary tools. A
private agent must run in a room compartment for its entire lifetime, including
its conversation, caches, memories and model-provider state. It cannot read room
A and then gain a general public-posting tool by switching its current room.

The trusted local broker must retain keys, enforce room/device/operation/expiry
and usage grants at the actual effect boundary, and withhold general network and
filesystem access. External inference is also disclosure: a private task needs
an explicit provider/content processing grant; otherwise processing stays local.
Incoming room text, a signature or a puzzle solve cannot mint grants.

Intentional cross-room/public sharing releases immutable selected output to an
exact full destination. Changes require a new decision. The broker records the
release locally without publishing private source metadata. Ordinary authorized
same-room work should not need repeated prompts. Durable effect intent and
provider idempotency or reconciliation are required before claiming restart-safe
external actions. The native fixed-room grant interface now enforces exact context, epoch, roster,
method, quota, expiry and host revocation checks around kernel operations. It
returns no generic signer, raw ciphertext, membership capability or ambient
network/filesystem tool. The optional native client now consumes its trusted
`RoomSession` into an account-owned fixed-room adapter, preserving room-state
drop order and refusing locked or uncertain conversion. This remains a
cooperating-host boundary: it does not sandbox an independently privileged agent
or provide a room-lifetime inference compartment.

## Public history, capacity and operations

The native activity controller now supports an authenticated locally verified
checkpoint and durable incremental continuation. Each step retains the 4,096-bundle
and 30-second operation budget and refuses authoring if incomplete. A synthetic
4,101-bundle replay continued across process restarts; fresh-cache adoption retained
an existing author's pending work and exact policy anchor. Initialization writes
only verified genesis. Existing authors must bind their outbox through `catch-up`
before advancing a fresh profile. Bare replay cannot advance an anchored profile.
A saved height or peer-supplied snapshot is not accepted as application state or
ancestry. The protected local checkpoint key does not make the cache a portable
trust root or defend against coherent rollback of the host's complete state.

Continuity staging separately retains at most 4,096 ancestor bundles across 64
slots with 32-bundle pages. The new portable continuity codec separates staged ancestry, admitted terminals,
status and role-aware evidence, and binds each reply to the exact selected peer,
request, body and nonce. It does not activate a peer route or install client
receipts. The store now checks exact limits before recovery, exposes checked author/stage
positions, refuses implicit stage consumption and separates bounded maintenance
from checked mutations. Its complete 39-test suite and strict lint passed.
The optional peer route now integrates one continuity writer with exact persisted
mode/configuration, bounded certified replay and independent request/input/stored/
prefix/cleanup credits. The full peer/identity suites passed 73 tests including
doctests, and strict workspace lint passed. Legacy activity uses that same writer
without implicitly consuming a staged prefix. Explicit CLI continuity-store
initialization and serving passed all eight operator process tests, including
typed proof readback, mode/limits mismatch preservation and monotone restart. Portable receipt state and native/IndexedDB persistence now retain exact signed
terminal and role-aware Evidence replies, tied to the selected peer, endpoint,
author, latest request/nonce and immutable source outbox. Stage and Status never
advance the retained prefix; the legacy delivery floor is unchanged. The native
controller now explicitly initializes/selects an exact signed target, saves an
attempt before dialing, and performs one advertisement refresh plus at most three
continuity exchanges within a 90-second step. Fifteen real-store/typed-HTTP tests
and strict native CLI lint passed. Explicit native `recover-history` now checks
one exact retained unsigned draft against certified historical policy before
signing. Its sequence, content and chain fields stay unchanged; actual pending
state and final journal HEAD are checked first. Three portable, six real-store
refusal/order tests and three certified-journal CLI journeys passed. Recovery
does not grant current posting permission or claim past admission. The browser
now drives the same receipt session: an explicit per-room, per-peer-route
session is created without dialing, a fixed terminal is selected (only a
strictly later retained terminal replaces it), and each step refreshes the
pinned peer's evidence, durably reserves every fresh-nonce request before the
exchange, and retains each verified signed reply. The local-Chromium journey
completes two targets against a dedicated continuity-mode fixture peer and
reads local receipt status without dialing. Incremental finalization beyond
the staged-ancestor bound is implemented: a farther fixed target advances
through ordered intermediate terminal admissions of exact signed local events,
each separately reserved, current-policy checked and never beyond the fixed
selection. Native tests cover multi-phase admission to one fixed target; the
local-Chromium journey exercises it under a narrowed qualification bound.
The same journey now strands an unsigned pending draft behind a certified
mid-run policy revocation, refuses current-policy resume twice without
replacing it, then recovers the unchanged request under its retained enabling
revision through the browser recover-draft action. Recovery produces local
continuity material only — never current posting permission, past admission
or delivery.
Public peer hints are bounded to 512 entries; signatures do not
prevent Sybil flooding. Admission, retention and overload behavior must be
qualified under measured traffic. Preserve old evidence when a budget fills;
never silently prune or reset a used sequence to recover capacity.

Measure sustained enqueue/fsync latency, acknowledgment latency, restart and
catch-up time, memory, disk growth, browser bytes and idle wakeups. Start with
1,000 and 10,000 messages on recorded hardware; only run larger cases with
measured time and disk headroom. Current finite store bounds are not a scalability
claim. Two receipts from one machine are not independent replication.

Before public operational acceptance, establish actual operator-owned DNS/TLS,
origin/CORS, deployment identity, more than one independent peer failure domain,
monitoring, storage-full behavior, peer withdrawal, lost-peer recovery and a
clean-device browser/native journey. An independently obtained bootstrap pin
remains the trust root; a discovery response cannot choose it.

## Artifact and deployment gates

Run the required final integrated tests, strict lint, formatting, production
browser packaging, dependency/advisory checks and exact-head CI. New source needs
new evidence; earlier commit checks do not cover a dirty working tree. Prototype
success cannot substitute for tests of a promoted production boundary.

The marketing site includes a home page and ten static documentation pages.
Its release gate includes content/link tests, production build, desktop/mobile
and dark-mode visual review, keyboard navigation, direct documentation URLs,
JavaScript-disabled reading and CSP. Publishing the website does not activate
private rooms or establish a public network. Verify the deployed artifact and
live HTTPS paths separately, retaining the prior deployment for rollback.

Report vulnerabilities through the verified private channel in [SECURITY.md](../SECURITY.md).
