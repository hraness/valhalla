---
type: plan
area: headless-mvp
status: in-progress
tags:
  - protocol
  - launch
---

# Valhalla headless MVP

Valhalla will provide a local communications service for agents, with CLI/JSON
and MCP clients, public and private rooms, verified synchronization, and optional
participant-operated hosts. The implementation is complete only when the
supported workflows pass the launch requirements below on the release candidate.

The user authorized implementation through launch readiness after the AT Protocol
assessment. AT Protocol adoption and Delvetown interoperability are outside this
scope. Borrowing ideas about signed records, synchronization and optional indexes
does not make the Valhalla protocol AT-compatible.

## Starting state and decisions

- Integration branch: `codex/headless-mvp-20261001`.
- Worktree: `/Users/benguo/Documents/valhalla-headless-mvp-20261001`.
- Base: `dd0dd2863fa47ae087d64e96864a70d6019bd23e` (published v0.2.13
  installer guidance). The earlier Habitat Link checkout is preserved.
- Integrated governed main through `fdc21029` by a clean fast-forward on
  1 October. This retains the evergreen-docs, private contact-test, and
  analytics-redaction changes from PRs #251–253. Task and worker edits survived.
- Public and private room workflows both remain in scope. A private-only pilot
  does not satisfy the objective.
- The browser application, games, social-credit room creation, reputation, feeds,
  and mandatory global directory consensus leave the required MVP path. The
  static installation/documentation website remains.
- Public rooms use independently pinned owner authority and explicit posting
  policy. Room links/invitations provide discovery; an index can be added later.
- Existing persisted formats and user histories remain recoverable. New room
  semantics require a distinct versioned protocol, not a fabricated legacy
  consensus registry or silent reinterpretation of old records.
- Keys and room authority stay with participants. A host provides availability;
  its acknowledgement cannot claim that a recipient processed a message.
- Synchronization reports the sources and verified history it covered. It must
  report missing history, forks, capacity refusal, and stale policy explicitly.
- Authoring, membership, ownership, and device recovery preserve monotonic state
  and existing safety rules. Key-only recovery cannot reset a signing sequence.
- Shipping requires an independently reviewed scope/policy change for obsolete
  release requirements. Native security, signing, provenance, and final gates
  remain required.

## Dependency-ordered work

Only the current phase is in progress. Independent lanes share this worktree and
own disjoint files; the integration owner controls shared contracts, manifests,
lockfiles, versions and final validation. There is no `update_plan` tool in this
session, so this document is the durable orchestration record.

1. **Contract and scope (complete).** Freeze public-room wire/state semantics,
   local service and client interfaces, compatibility policy, and launch tests.
   Independently detach optional browser packaging from native release.
2. **Protocol and persistence (complete).** Implement owner-authorized public
   rooms, durable author/inbox/outbox state, verified sync, and preservation of
   existing private-room guarantees. Validate tampering, forks, stale policy,
   interrupted writes, capacity and recovery.
3. **Headless runtime and clients (in progress).** Implement supported setup,
   create/join, send/read, background synchronization, status, scoped MCP, and
   service installation/lifecycle. Prove shared custody and failure behavior.
4. **Independent-machine operation (pending).** Complete optional host deployment,
   real-network public/private delivery, offline catch-up, restart, host loss,
   membership change, and safe recovery on independent machines.
5. **Release and documentation (pending).** Finish native artifact matrix,
   compatibility and upgrades, quick start, protocol/reference docs, accurate
   product site and capacity/cost guidance. Publish only after required gates.
6. **Launch audit (pending).** Independent full review, current-tree aggregate
   checks, signed installation/upgrade checks, deployed documentation readback,
   and requirement-by-requirement evidence review. Resolve remaining work before
   marking this plan or the thread goal complete.

## Launch requirements and evidence

Every row is pending until exact candidate evidence is recorded. Earlier releases
and narrow local fixtures cannot satisfy broader requirements by themselves.

| ID | Required outcome | Authoritative evidence |
| --- | --- | --- |
| L01 | Standard native installation runs the supported workflow without a browser product, global validator network, social credits, games or AT services. | Release feature/dependency graph, clean install and end-to-end native journey. |
| L02 | CLI/JSON and MCP cover identity, room create/join, send/read, synchronization, status and supported recovery. | Command/schema tests and real process journeys using documented commands. |
| L03 | Public rooms verify owner authority, posting policy and author continuity; tampering, replay, forks and stale policy cannot become fresh authorized messages. | Versioned specification, cross-implementation vectors, adversarial/stateful tests and independent protocol review. |
| L04 | Private rooms retain MLS confidentiality, scoped membership changes and finite agent access. | Kernel/native tests plus current-candidate independent-machine exchange, removal and rekey journeys. |
| L05 | Local service owns state safely and supports clients without competing writers or leaked sessions. | Custody/concurrency tests, managed-service install/start/status/stop/restart evidence. |
| L06 | Queued messages survive process restart and network loss; retries preserve bytes and do not create duplicate logical messages. | Fault-injection tests and offline catch-up process journeys for both room modes. |
| L07 | Sync verifies selected-peer checkpoints/history and identifies gaps/forks; missing state is never reported as complete. | Protocol/property tests, interrupted pagination and alternate-host catch-up journeys. |
| L08 | Room links and host replacement preserve pinned identity and history; optional hosting has a reproducible recipe. | Clean-device join, host replacement/recovery and documented deployed host checks. |
| L09 | Retention, storage growth and capacity have documented supported limits and a preserving recovery/expansion path. | Near-capacity tests, resource/latency measurements and recovery/export/import evidence. |
| L10 | Identity, device and author-state backup/recovery preserve histories and cannot cause signing equivocation. | Restore tests, crash/reopen tests and independently reviewed recovery procedure. |
| L11 | Release supports its stated OS/architecture matrix with checksums, provenance, macOS signing/notarization, and safe upgrades. | Exact release assets, required CI, install/upgrade verification and preserved legacy-format access. |
| L12 | Public docs/site match supported behavior, commands, costs and limits. | Current-candidate command checks, site checks/rendered review and deployment readback. |
| L13 | Both room modes work across independent machines with recorded transport paths and failure outcomes. | Current-candidate live runs, including disconnect/reconnect, restart, invalid membership and cleanup. |
| L14 | Required aggregate gates and independent reviews pass on the integrated candidate; all review findings are resolved. | Final exact-tree receipts, CI/PR/merge state, review records and release audit. |

No minimum arbitrary throughput claim is chosen in advance. Measure real paths,
declare a useful supported workload, and resolve bottlenecks that prevent normal
agent conversation. Cheap idle hosting is not evidence of traffic capacity.

## Ownership and current evidence

| Agent | Owned scope | State |
| --- | --- | --- |
| `/root` | Shared contract, integration, manifests, plan, final gates and delivery | Working |
| `/root/valhalla_scope_audit` | Private delivery manager, process qualification and public transport evidence | Adapters frozen; reviewing cross-runner orchestration |
| `/root/headless_runtime_audit` | Private adapter, MCP, commands/runtime and private integration tests | Fairness passed aggregate; enum-storage lint repairs frozen |
| `/root/headless_release` | Release/store foundations, public sync, private setup and managed lifecycle | API review complete; browser expectation repaired; hosting guide in progress |

Initial audit confirms that the existing public activity format, NativeOutbox and
continuity records bind the consensus/social directory. A direct owner-managed
room protocol must have its own format identity. The private RoomSession already
owns account/room custody, and the present MCP server consumes it; a daemon
serving concurrent clients requires deliberate ownership changes.

## Implementation evidence

The direct public-room protocol is a new `no_std` crate, with canonical signed
genesis, policy and event records, full room pins, explicit writer lists, author
hash chains and owner-sealed historical boundaries. It remains unavailable as an
end-user workflow until storage, transport and runtime integration are qualified.

Independent review found and repaired three issues before native integration:
policy seals now prove extension from prior seals; unresolved observations retain
every revision rather than only the newest; fresh author admission proves the
exact known sealed anchor rather than trusting only a sequence number. Observation
capacity overflow remains fenced until complete evidence reconstruction. The
reviewer reported no remaining blocking pure-core finding after these repairs.

- Direct protocol: 17 tests passed, including the exact fork regressions,
  64-case stateful replay, atomic seal pages and frozen independent wire vectors.
- Identity with `direct-room`: 11 tests and one compile-fail doc test passed.
  The scheduled command was `cargo +1.98.1 test --locked --offline
  -p vhalla-direct-room -p vhalla-identity --features vhalla-identity/direct-room`.
- Independent Bun/Node-compatible Ed25519/SHA-256 vector check passed with
  `bun crates/vhalla-direct-room/tools/vectors.mjs --check`.
- Shared private account custody: nine new controller tests and five existing
  client tests passed; independent review found no blocker. Handles retain the
  account lock while each room keeps its own exclusive writer.
- Shared private archive handles preserve the existing inert import format and
  final-seal checks. All five new account-archive tests and three existing archive
  tests passed. Combined Clippy passed for account-controller, client,
  account-archive and archive targets with the client feature and `-D warnings`.
  Logs: `/private/tmp/valhalla-account-archive-20261001-tests.log` and
  `/private/tmp/valhalla-private-controller-20261001-clippy.log`.
- Protocol Clippy identified one large enum variant. Boxing its history verifier
  repaired that warning. The unsigned `AuthorChain::authoring_head` check now
  validates policy/ancestry before native reservation and signing. All 17 protocol
  tests, the two direct identity integration tests and strict Clippy passed after
  these changes (root sessions 14752 and 33084 completed successfully).
- Borrowed `AgentAccess` keeps each grant's budgets, draft and cancellation state
  while a daemon owns the private room. Independent source review found no
  blocker. The focused 32-test agent/RPC/library run passed. Root session 81544
  passed all 16 controller/client/scoped integration tests after fixing a fixture
  that recomputed validity across a one-second boundary. The fixture now also
  pins refusal of an offer extending beyond owner expiry, with no mutation.
- Root session 44546 passed 20 direct-native tests, 20 protocol tests, 101
  private-native library tests and the mixed public/private account integration.
  This includes core anchor proofs, bounded replay, historical visibility,
  filtered paging and capacity expansion. Strict combined lint is running.
- Direct-store v2 passed 24 tests and strict all-target Clippy. It supports
  in-place monotonic quota expansion through one SQLite transaction; the marker
  pins only format and context. Tests include six uncertain expansion boundaries,
  five actual killed-process expansion boundaries, legacy-v1 preservation/refusal
  and the 64-case interleaved model. Logs:
  `/private/tmp/valhalla-direct-store-20261001-v2-tests-r2.log` and
  `/private/tmp/valhalla-direct-store-20261001-v2-clippy.log`.
  Independent source review by the native-controller agent found no blocker.
- Native release packaging removes the browser archive and checksum (ten native
  assets). Legacy browser jobs are explicit opt-in. Focused release-script tests,
  25 scope tests and actionlint passed. Full integrated release validation remains
  pending.
- Public snapshot verifier: ten adversarial/vector tests passed. Independent
  source review found no blocker in authenticated source binding, exact prepared
  page ownership, atomic refusal, final-only coverage or completed-prefix
  extension. Strict Clippy found a test-only Rust 1.98 slice-iteration lint; the
  repair is in place and its rerun remains pending.
- Durable public replica: all eleven tests passed in root session 61214,
  including the interleaved state model, exact historical checkpoints after
  append/reopen, retained forks, missing images, quota expansion and uncertain
  publication. This is storage evidence, not real-network catch-up evidence.
- Private retained-send lookup: all six focused kernel tests passed in root
  session 37124. They cover unchanged bytes after membership changes/removal,
  operation conflicts, authoritative-image checks, missing/tampered lookup,
  read uncertainty and harmless read cancellation. Native delivery integration
  and the borrowed network driver's four new regressions remain pending.
- Combined headless foundations passed all 57 tests in root session 21768.
  Root session 69789 then passed all 69 tests, including scoped historical-send
  refusal, clean conflict handling, immutable public creation/join provenance,
  and an output read/write gate held through native work, final grant audit and
  bounded response writes. The latter log is
  `/var/folders/vh/qdfcqc514qj47bbvzslcwjsc0000gn/T/system-one-rztliW/check.log`.
- Root session 21916 passed all 51 direct-native library tests, three bound
  creation tests and two bound join tests. This covers durable Follower pages,
  exact retry, source forks/epochs, same-epoch backing rollback, uncertain
  writes, quota growth, typed operation metadata and policy-scoped sends.
  Independent Follower/lookup/operation review found no blocker.
- Root session 32281 passed both retained-delivery tests and both shared-account
  bound creation/join tests. The four borrowed driver tests and legacy network
  driver regressions are still pending.
- Root session 33814 passed all 232 CLI unit tests after repairing shutdown,
  fixture, and native-error isolation failures. This includes the service actor,
  scoped MCP client, and four borrowed-driver tests. An agent native failure now
  closes all grants for its room even when cached status remains readable.
  Legacy standalone private-driver integration remains pending.
- Root session 79836 passed all 68 direct-native library tests in 88.66 seconds,
  including sixteen projection and twelve Follower tests. Projection checks now
  prevent a forged cursor from skipping an unscanned ninth frame and preserve
  stronger backing/native floors observed by status. A Follower exposes its
  immutable initial target separately from later target extensions.
- The non-default `headless` feature now exposes daemon init, run, status, stop,
  JSON calls and scoped MCP. The first combined run (85209) failed to compile
  a macOS FIFO fixture because rustix has no `mkfifoat` there. The fixture now
  uses the POSIX utility. Run 90440 compiled 288 tests but aborted with a stack
  overflow in the real command create/send/reopen test; it is not a passing run.
  Non-run commands bound runtime shutdown after timed stdio, since Tokio cannot
  cancel a blocked standard-input read or standard-output write. Run preserves
  joined native shutdown. Daemon commands skip automatic update network access.
- A separate persistent transport key and authenticated public links are written.
  Default listening is direct UDP on `0.0.0.0:48888`; HTTPS relays require an
  explicit option. Independent network review found no blocker. Listener policy,
  sticky key refusal and link verification tests await the combined CLI rerun.
  Service integration now tests live key replacement, peer refusal, joined drain
  and retained native state; this new test is not yet validated.
- Private delivery selection preserves exact operation receipts, selected profile
  hashes, prior queues and later selections. Fifteen manager tests are written;
  their relay fixture limits were corrected before the failed 85209 compilation.
  Review found that driver strings erase native-versus-transport error origin.
  The typed borrowed-driver outcome is now implemented: corrupted authenticated
  native history closes the room, while relay/profile refusal closes its driver.
  These repairs compiled in 90440; their integrated tests passed in 4188 below.
- Root run 80329 passed strict all-target Clippy for direct-native and direct-sync
  with the pinned Rust 1.98.1 toolchain, locked and offline. This closes the
  earlier `chunks_exact_to_as_chunks` lint failure.
- The stack-layout probe passed without constructing or polling large futures.
  The native dispatch future occupied 26,408 bytes and was embedded through
  service and client wrappers. The command owner has boxed actor operations and
  init/run awaits, retaining joined shutdown. All thirteen command tests and
  four actor-runtime tests passed on default thread stacks. With the assembled
  service, the outer CLI future fell from 32,792 to 2,896 bytes; the daemon run
  wrapper is 10,640 bytes. Regression bounds pin only the outer future sizes.
- The public sync manager now has durable publication/source receipts, an
  immutable first target, independent polling/maintenance/admission cursors,
  bounded owned read futures and explicit reopening. Independent review repaired
  canonical parent paths on macOS and separated definite sync capacity from
  native uncertainty and selected-source corruption from shared backing failure.
  Only safety fences close native room grants; a healthy full sync store retains
  pending transfer intent and reports capacity separately.
- The service now constructs persistent network identity plus public/private
  managers inside shared service custody, binds the configured peer endpoint,
  runs finite background steps, and audits after calls, peer reads and ticks.
  Owner JSON routes cover publication, source selection, links and private
  profile setup/attachment/status. New tests exercise two running daemons,
  signed public delivery, exact send retry, disconnect/restart and catch-up.
  These public integration tests passed in run 32534; independent machines and
  real process journeys remain required.
- The first post-integration full CLI run passed 273 tests with 33 failures,
  mostly repeated fixture failures. Run 32534 passed 298 tests with eight
  failures. All public-manager, command, local-runtime and public service
  integration tests passed. Remaining fixes give setup fixtures real Ed25519
  keys and explicit owner-private parents, and preserve exact grant request
  timestamps when testing replay across service generations. The production
  permission checks and sticky invalidation were retained. Logs:
  `/var/folders/vh/qdfcqc514qj47bbvzslcwjsc0000gn/T/system-one-Fiuovo/check.log`
  and `/var/folders/vh/qdfcqc514qj47bbvzslcwjsc0000gn/T/system-one-EcbKQw/check.log`.
- The private setup helper initializes only an explicitly selected version-four
  profile's new local queues. It pins parsed bytes and filesystem identity,
  preserves partial state, syncs new directory names and never changes native
  room authority or implicitly attaches the profile. Profile refusals do not
  invalidate healthy room grants. All nine focused tests passed in run 37334.
- Read-only environment review identified the existing Iroh two-runner GitHub
  Actions harness as the independent-machine path. It binds source/binary/run
  identity and retains sanitized results with joined cleanup. The repository is
  public and GitHub authentication is available. No provider resource has been
  provisioned; separate runner VMs do not establish distinct physical hosts or
  NATs. The new headless process adapter and actual candidate execution remain
  pending.
- Integrated CLI run 4188 passed all 311 tests with default thread stacks,
  pinned Rust 1.98.1, locked dependencies and offline mode (84.87 seconds).
  Three service-level private TLS journeys verify device acceptance reporting,
  relay-retained versus accepted evidence, offline restart without duplicate
  messages, profile refusal without losing healthy grants, and room-specific
  fencing after authenticated-encryption corruption while a public room remains
  usable. Owner outbox metadata includes verified device claims; scoped agents
  receive bounded counts only after their outbox permission and allowance checks.
  Catalog and native public-room capacity tests prove monotone expansion,
  preservation of history and exact signed retries across reopen. Log:
  `/var/folders/vh/qdfcqc514qj47bbvzslcwjsc0000gn/T/system-one-e59J79/check.log`.
- Actual CLI build 40731 passed in 26.62 seconds. Its immutable task-owned copy,
  `/private/tmp/valhalla-headless-process-qozbvwvq/vhalla`, has SHA-256
  `e5bcb24492be1c5fbde3486b5a31186aa8013c55b4f0bdb89e6fd1585fd65f58`.
  The public process journey passed in run 88919 with joined cleanup:
  `/private/tmp/valhalla-headless-process-qozbvwvq/journey3/local-receipt.json`.
  It verifies writer admission, bidirectional signed messages, exact retries,
  offline restart and catch-up from a read-only replacement peer reconstructed
  through public sync after the original owner stops. This is same-machine
  loopback evidence; the immutable binary predates later receipt/maintenance
  additions and must be rebuilt for final candidate qualification. Two earlier
  failed fixture runs are retained with successful cleanup.
- The final public process adapter passed another local journey in run 37436:
  `/private/tmp/valhalla-headless-process-qozbvwvq/journey4/local-receipt.json`.
  Its 14 focused Python tests passed; the root's combined controller discovery
  passed all 31 tests. The new `headless-qualification.yml` runs the actual CLI
  on two independent VMs and can be selected through the already registered
  Iroh workflow's `headless` input. Actionlint passed both workflows. No remote
  run has been dispatched yet. Subsequent path-observation additions still
  require renewed controller validation.
- Managed installation/status/removal is registered through
  `daemon managed install|status|uninstall`. Installation first opens existing
  state under the daemon's custody and joins all handles before registering
  the canonical current executable. Status and uninstall consult the exact
  saved selection without requiring healthy native data. Twenty managed tests,
  two command/preflight tests and four launchd restart tests await the next
  combined CLI run. The quiet launchd helper now resumes an exact loaded,
  cleanly stopped job with `kickstart` without `-k`; it never restarts a running
  job. Stopping the daemon acknowledges the request before the process finishes
  draining, so an immediate reinstall can still report a truthful custody
  conflict until shutdown completes.
- Standalone private delivery run 90319 passed 14 of 15 tests. The remaining
  membership-change case was reproduced: native state had accepted control 2,
  but the old grant closed before the host could retain the accepted-control
  marker. The repair separates local marker publication from agent output
  authorization, retains locked/latched native checks, and preserves all later
  grant-release gates. Run 52303 is queued for the complete standalone suite;
  this repair is not validated yet. Exact-feature warning gates are also being
  tightened for helpers used only by headless or borrowed-driver tests.
- Public transport observation now has an explicit `--relay-only` option that
  requires a configured HTTPS relay and disables IP transports. The peer client
  records local before/after connection-path snapshots only around a successful
  authenticated reply; per-source status reports those transient observations.
  They do not prove per-byte routing or NAT diversity. Rust and Python tests for
  this extension await the next converged run. Default operation still permits
  direct peer transport and configures no relay implicitly.

Toolchain resolution must pin the complete child `PATH` to the installed Rust
1.98.1 directory. Pinning only `build.rustc` left Homebrew 1.97.1 rustdoc/Clippy in
use. The first direct-room run passed its 14 then-current tests but failed doctests
from that mismatch; the corrected full run above passed. The earlier cancelled
private Clippy wait was superseded by the successful combined check recorded above.

The next storage layer has its own format and no room authority: a portable,
owner-private SQLite store supplies exact opaque state CAS, bounded immutable
records, contiguous local pages, custody checks and sticky uncertain outcomes.
The protocol controller must separately reserve exact bytes before signing,
retain observations/forks and reconstruct verified state. Storage checksums cannot
detect coherent rollback by the file owner and never imply global sync coverage.

## Convergence record, 1 October

- Session 75648 passed 352 CLI tests, 104 private-kernel tests and 195
  private-native tests (two explicitly network-dependent tests ignored).
  Log: `/var/folders/vh/qdfcqc514qj47bbvzslcwjsc0000gn/T/system-one-WkWZKd/check.log`.
  This supersedes the earlier aggregate failures below. The auxiliary sender
  in the fairness fixture now runs on its own joined runtime; the daemon keeps
  its production two-worker runtime, 24-tick and 20-second bounds.
- Strict Clippy found large enum storage and constant-size chunking issues in
  the CLI. The payloads are boxed without changing their wire representation,
  and decoding uses `as_chunks`. Strict all-target Clippy passed for the CLI,
  private kernel/native and all four direct-room crates. The CLI aggregate is
  queued after these representation changes and three test-only lint repairs.
- Full site checks passed 68 tests and built the home, 20 documentation pages,
  five comparisons, one writing index and 11 articles. The first real browser
  run found an outdated setup-prompt expectation; the source expectation now
  matches the two rendered prompts, with all other browser assertions retained.
  The rerun passed all 40 pages, desktop/mobile and light/dark checks, full-source
  clipboard behavior, and process/profile cleanup. Receipt:
  `/private/tmp/valhalla-headless-site-20261001-review2/receipt.json`. Pinned
  browser: Chrome for Testing 149.0.7827.55.
- The API reference documents exact owner operations, private profiles and
  public/private grants. Independent review corrected validity propagation,
  writer-list replacement, device-acceptance field paths, and queue accounting.
  Documentation and site now separate public listener relay configuration from
  private profile relay configuration and the source build from published v0.2.13.
- Qualification controller discovery passes 68 tests, the workload adapter
  passes 18 tests, and the changed workflows pass Actionlint. The complete
  delivery/security Python suite passed 254 tests. No current binary process
  result is claimed yet. Independent review found no blocker in VM handoffs,
  cleanup, source/binary provenance, or the final representation lint repair.
- The optional Linux hosting guide covers public read replicas, private Iroh
  mailboxes, persistence, service restart, network routing, and costs. It is a
  source recipe with explicit operational checks, not a claimed deployment.

- Aggregate session 74575 compiled and ran 346 CLI tests: 343 passed and three
  failed. The managed fixture used the wrong supervisor lock path. The grant
  growth regression incorrectly expected an active exact issuance retry to be
  refused; it now checks the original token and decremented allowance. The
  fairness fixture used one Tokio worker while production uses two. All three
  were repaired without relaxing runtime checks.
- Session 79966 compiled the CLI, private kernel and private native libraries;
  the CLI binary ran 352 tests, with 350 passing. Cargo stopped before the two
  library binaries. Its log is
  `/var/folders/vh/qdfcqc514qj47bbvzslcwjsc0000gn/T/system-one-AIvl5N/check.log`.
  Public capacity, stopped private archive/reopen, private accounting, managed
  fixture, DNS refusal, output expiry, and private diagnostic/profile tests in
  that CLI binary passed. A storage-target schema regression found that Serde
  ignored extra fields on internally tagged unit variants; these are now empty
  struct variants. The fairness test exposed a second setup error: unrelated
  rooms shared one mailbox. Its repair and the schema fix still need reruns.
- `public.sync_storage` reports replica, projection, per-source and fixed shared
  metadata use. `public.sync_expand_limits` grows exactly one selected store;
  retries preserve generation, records and cursors, and shrinking is refused.
  Independent review caught a full-follower recovery gap: its terminal refusal
  drops the live handle. Maintenance now opens only the metadata-bound retained
  ledger, preserving its refusal until an explicit room reopen. The full-store
  regression passed in session 79966.
- Private status reports immutable storage limits through an exact-image-checked
  accessor. Errors and cancellation require reopen. Independent source review
  found no remaining blocker. Stopped export/import yields read-only history;
  the original home can reopen, retry exactly and advance its message sequence.
- Private Iroh profiles support explicit relay-only mode. Diagnostic path
  snapshots publish only after typed success, survive driver failure, and reset
  on a new selection or reopen. Independent source review passed. Native tests
  and real forced-relay headless journeys remain pending; the old raw-client
  relay test is not evidence for this constructor.
- Public, private and managed qualification adapters are present. Combined
  Python discovery passed 68 tests. Native release policy tests passed 18 tests;
  release/headless workflows passed Actionlint. A workload adapter is in progress.
  All actual-process adapters still need a new immutable candidate.
- The source default and Unix release features now select `headless`. Native
  Windows retains its member-side private tools. README, daemon documentation,
  current readiness and repository scope guidance now describe this path; site
  updates are in progress. Release pins remain v0.2.13 until a new release passes.
- The first source checkpoint is being prepared for real-process qualification;
  no PR, release or deployment has been created. L09–L14 and exact-candidate
  launch evidence remain open. Earlier loopback
  receipts predate the new transport and recovery changes and are not reused.

## Runtime and recovery interface baseline

The shared `AccountController` owns one account identity while private, public,
archive and maintenance handles retain their own account hold. Public room
creation/join/open use an input-only shared identity; no signer getter is exposed.
A new live public join creates a fresh room-author key. Joining with an account
whose key matches the room owner does not confer owner-policy signing capability.
That capability requires preserved local creator and policy-operation state.
Cold loss of that state permits archive/read access and a new pinned room, not a
guessed signing high-water mark. Ordinary public messages use the room author.

One async runtime actor will own the room controllers. CLI/JSON administrative
requests and scoped agent requests use the Hraness control-kit wire format and
paths, with distinct admin and agent Unix sockets. The agent protocol is
`valhalla.rooms/1`; the backend must enforce each retained launch grant before
room access. A reconnect never recreates or replenishes the grant. The transport
adapter is exposed through the default headless feature while integration and
launch qualification continue; the published installer still serves v0.2.13.
Unix daemon qualification and the existing portable member-side CLI are separate;
the final supported matrix must match actual release evidence.

Review found that the shared control-kit server could release its lock after a
request timeout while actor work continued, and per-read timeouts allowed a
trickling client to prevent shutdown. The replacement uses total frame deadlines,
bounded Tokio I/O tasks, an owned backend, and a lock retained through backend
drop and transport drain. Shutdown stops intake while awaiting accepted work;
undispatched queued requests are refused. Four connection slots are reserved for
administration and twelve for agents. Complete request, success and error frames
are bounded. Recognized interrupted transport metadata is preserved; replaced
filesystem objects are never cleaned up as if they belonged to this service.

Scoped responses retain a final output permit through frame encoding. A shared
read/write gate excludes output while the actor mutates native state and audits
grants. A response holds the read side from its final authority check through its
bounded write. Revocation, expiry, room-authority invalidation and backend
destruction invalidate pending responses. Restart ends grants, and durable
one-use grant claims prevent replay from replenishing a budget. The catalog
records immutable room-creation intents, a fresh local nonce, original creator
or join mode and locators. Every public reopen checks those values, so another
same-account controller at the same room pin cannot replace the selected author
or silently confer ownership. Incomplete creation is preserved or reconciled
with the exact intact native room, never replaced with a new identity.

Public peer transport exposes only genesis, checkpoint and bounded page reads
over authenticated QUIC. A checkpoint identifies one source, room and source
epoch. Coverage means the complete chosen snapshot matched; partial pages remain
pending. The source replica stores signed public records only, without signing
keys or unsigned local reservations. Persistent Follower progress now retains
ordered references to actual signed frames, replays them through the verifier
on open and pins a checked minimum backing prefix. Completed source coverage
remains distinct from controller admission. Durable projection has passed its
native tests; the public manager and background synchronization are being joined
to the daemon and still need process and independent-machine qualification.

Direct-native stores exact unsigned intent before signing, then atomically saves
signed records, indices and operation completion. Its replication API filters out
configuration, reservations, completion metadata and unpublished text. Ordinary
operations now use verified incremental state and at most 65 cached authors.
Reconciliation consumes at most 128 ancestry frames and eight policy commits per
call; status exposes remaining work. Filtered pages scan at most 128 source
entries for up to 32 outputs and advance even across empty output. Historical
visibility uses exact immutable indexes established by full policy verification;
numeric seal bounds alone never establish ancestry. Full replay remains required
on open. Resource measurements and capacity/archive recovery remain under L09.

Quota expansion retains the exact emergency frame and required indices/fork or
lost-custody evidence atomically before clearing the capacity slot. Insufficient
growth leaves that slot intact. It never clears policy observation overflow,
owner/author forks, pending reservations or lost signing custody.

Independent native review found two repairs completed before tests:
every retained policy must be compared with its first-observation index, including
observations beyond the in-memory budget; and a filled emergency capacity image
must refuse before authenticating another observation it cannot retain. Policy
application cannot proceed through an unresolved observation-overflow fence.

## Recovery and delivery rules

Keep task edits and temporary validation data separate from operator accounts,
room histories and deployed services. Retain old readable formats and recovery
tools while changing defaults. Never erase journal/WAL state, shrink safety
bounds, or disable access controls to make a test pass. Any migration is explicit,
preserving and tested before activation. New protocol data cannot overwrite old
formats in place.

Use the installed host scheduler for heavy validation and process-custody tests.
Give each focused test and each external wait one owner. Record failed checks and
their repairs here. Release and deployment occur only after their required gates;
social announcements are outside this implementation request.
