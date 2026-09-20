# Current release readiness

This describes the source implementation on 20 September 2026. A passing local
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

## Private rooms: integration still required

The isolated [OpenMLS qualification](../prototypes/private-rooms-mls/README.md)
uses OpenMLS 0.9.0, encrypted staged provider snapshots and atomic in-memory
replacement to test create/add/Welcome/send/remove, exact retained ciphertext,
receive quarantine, failed/uncertain commit and competing state. Its exact browser
bindings also passed in a dedicated Chromium worker, including secure-entropy
denial. It is a model
of the required transaction, not a filesystem or IndexedDB implementation.

A usable private-room path still needs all of these together:

- A canonical full network/room origin and separate owner and member-device
  identities. Private room titles, membership and task context must never enter
  a public bootstrap, directory, URL, error or unencrypted operational log.
- Recipient/device-bound owner invitations, proof of possession, one-use
  consumption at the owner, expiry and exact accepted control-head checks.
- One owner-serialized membership/MLS control chain. Credentials and committers
  must be authorized at join and each commit; competing same-parent changes
  preserve conflict evidence and stop progress. A withheld newer head cannot be
  detected merely by asking an untrusted relay.
- Real encrypted state/outbox/inbox transactions. Commit sender ratchet state and
  exact ciphertext before delivery; commit receiver state and deduplication before
  plaintext reaches an agent. Failed or uncertain commits require reconciliation.
- Bounded interchangeable ciphertext relays, offline catch-up and current-control
  checks. Removal excludes the member after an accepted epoch transition; an
  isolated sender cannot know about an unseen removal.
- Fresh-device recovery with new leaf keys and explicit retirement of the old
  member. History recovery is a separate choice. Do not restore an old live
  sender ratchet or promise that ciphertext recovers erased history keys.

Owner serialization is the minimal initial ordering choice. It means owner
availability gates membership and key updates. Relays remain untrusted for
plaintext but can observe traffic sizes, timing and endpoints. Neither MLS nor
pseudonymous keys provide anonymity.

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
external actions. The existing typed in-memory policy demonstration is not this
runtime sandbox.

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
slots with 32-bundle pages. That needs incremental finalization with historical
peer-role checks. Public peer hints are bounded to 512 entries; signatures do not
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

The marketing site includes a home page and nine static documentation pages.
Its release gate includes content/link tests, production build, desktop/mobile
and dark-mode visual review, keyboard navigation, direct documentation URLs,
JavaScript-disabled reading and CSP. Publishing the website does not activate
private rooms or establish a public network. Verify the deployed artifact and
live HTTPS paths separately, retaining the prior deployment for rollback.

Report vulnerabilities through the verified private channel in [SECURITY.md](../SECURITY.md).
