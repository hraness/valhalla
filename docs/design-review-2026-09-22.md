# Design and engineering continuation — 22 September 2026

## Baseline and outcome

This review resumes Devin session `valhalla` (`near-mochi`) at
`dbef8ee6e9f2053e373cab5fed0591d751cc3ca9`, in PR #85. The checkout remains on
`wip/codeql-input-hardening`; its remote destination is `devin/overlay-profiles`.
The baseline is clean. This review does not certify the entire historical
implementation or constitute an independent cryptographic audit.

The earlier handoff classified the remaining work as heavyweight infrastructure.
Source review found security and recovery defects that can be fixed locally.
Infrastructure qualification remains necessary after those repairs. Public
activation, application release and merge remain separate gated operations.

## Architectural assessment

The useful product is a room that an owner can delegate to an agent, leave
offline, rejoin and recover without accidentally granting a signer, tool or
network capability. Public discovery and private membership are separate
contracts; keep private room metadata out of public discovery and generic
relays. Optional puzzle evidence should remain ordinary room content, outside
the default collaboration dependency graph.

The strongest implementation boundaries are the pure private kernel, joint
account/room custody, exact consent, transactional state/output publication,
strict browser storage durability, read-only recovery archives and independently
pinned public bootstrap. Retain these while simplifying their callers.

The principal weakness is disagreement between adapters about what a verified
value proves. A signed grant was treated as a completed owner handoff by new
clients, while existing clients required the predecessor's carrying control.
Generic relay constructors accepted artifacts that CLI export already regarded
as confidential bootstrap material. A paginated source could supply a valid
item with invalid progress metadata and control a local durable cursor.
Centralize these decisions at the narrowest shared constructor/validator;
caller documentation and parallel allowlists are insufficient enforcement.

The second weakness is recovery composition. Durable kernel state alone does
not establish a resumable user journey: relay item publication must precede
cursor publication, and a frontend file error must leave a usable path back to
the importer's retained cursor. Each integration needs a test that crosses its
actual interruption boundary and resumes the exact operation.

The third weakness is evidence maintenance. PR #85 spans roughly 114,000 added
lines and its description trails the source by multiple checkpoints. Existing
tests and qualification are valuable, but assertions about a whole product
must link to current source, exact artifacts, observed outcomes and explicit
limits. Keep future changes bounded by one behavioral contract and its tests.

## Review findings and repair lanes

| ID | Severity | Finding | Owner / repair contract |
| --- | --- | --- | --- |
| R1 | P1 | Generic relay accepts plaintext legacy KeyPackage/Invitation bootstrap artifacts | Relay lane: one canonical encrypted-artifact allowlist used by construction and decoding |
| R2 | P1 | Scan writes final item names before completion and does not sync the item directory before its cursor | Relay lane: atomic item publication, directory barrier, then cursor; preserve conflicting evidence |
| R3 | P1 | Invalid pages can regress progress, skip items or keep scanning indefinitely | Relay lane: validate request-relative positions, count, head and completion before effects; bound total work |
| R4 | P2 | Scan cursors lack namespace binding and exclusive custody | Relay lane: versioned explicit namespace and one lock through scan/consumption; refuse legacy nonempty unbound state |
| R5 | P2 | Socket timeouts measure inactivity rather than an absolute operation deadline | Relay lane: absolute bounded request I/O; slow-trickle regression |
| R6 | P2 | Pull reads staged files without regular-file/size protections | Relay lane: canonical names and bounded custody reads, including items below the saved cursor |
| R7 | P2 | A supplied relay-submit namespace is ignored | Relay lane: require equality with the canonical item before credential or transport access |
| K1 | P1 | Succession can promote an expired successor that cannot accept its own handoff | Kernel lane: validate successor enrollment on emission and application before mutation |
| K2 | P1 | Fresh onboarding accepts a grant without predecessor-authorized handoff proof | Kernel lane: bounded verified carrying-control chain; deliberately version affected formats |
| B1 | P2 | Lock and busy handling omit the successor device field | Browser lane: centralized private-field handling and DOM regression |
| B2 | P2 | Frontend archive parse failure strands an active worker importer | Browser lane: close uncertain frontend custody, preserve durable progress, explain exact-file resume |
| B3 | P2 | Archive export accumulates up to hundreds of MB with multiple copies | Browser lane: explicit bounded download fallback; complete streaming/multipart export remains a separate spike |
| D1 | P2 | Readiness says owner succession is unfinished while later paragraphs describe it as implemented | Integration owner: reconcile against actual predecessor-required behavior and remaining dead-device recovery |

The public HTTP path inspected already checks structural requests, bounded
bodies, absolute body timeouts and pre-work credits. This is not a completed
independent audit of every public continuity store transition.

## Execution graph

1. **Recovered / reviewed:** preserve checkout and branch; read source contracts
   and prior handoff; independent relay, private-authority and browser reviews.
2. **Parallel repairs, complete:** disjoint relay/native-CLI, private
   kernel/protocol, and browser panel lanes. The integration owner updates
   cross-crate succession callers and maintained readiness.
3. **Repair join, complete:** focused regression evidence, dependent caller integration,
   formatting and strict lint; no grant-only compatibility fallback.
4. **Parallel spikes, complete:** operational relay transport; room-lifetime execution and
   provider compartment; browser multi-snapshot recovery and fault journeys;
   dead-device recovery design. Preserve all existing authority boundaries.
5. **Final join, local checks complete / CI pending:** integrated native/WASM/browser and repository final gates,
   independent review, exact-head CI and honest remaining acceptance status.
   Pin the site's source links to the retained repair commit before delivery.

## Remaining work and promotion criteria

| Area | Useful next bounded result | Evidence required before promotion |
| --- | --- | --- |
| Public relay | Server-authenticated transport and bounded scheduling around the existing opaque mailbox contract | Wrong server/token/namespace refusal, slow clients, congestion, restart, exact retry; deployed DNS/TLS evidence |
| Delivery status | Member-authenticated acknowledgment of one exact ciphertext after durable processing | Wrong member/context/ciphertext refusal; crash before/after publication; no claim of human reading or global freshness |
| Agent compartment | One room for a process lifetime; broker retains keys and explicitly mediates provider calls | Actual OS escape probes, denied ambient file/network/process access, grant revocation across waits; unsupported platforms refuse |
| Dead-device recovery | Fresh-device policy model separate from history archives | Partitions, competing recovery, old-device return and interrupted retirement; no reused ratchets/counters or invented legacy authority |
| Browser recovery | Multiple authenticated archive snapshots and bounded export/import UX | Two revisions coexist, exact interrupted resume, malformed/substituted IDs, quota refusal, document/worker teardown |
| Operational acceptance | Exact artifacts tested on explicitly owned independent targets | Failure-domain identity, bootstrap pin, clean-device journeys, storage-full/crash/partition evidence, measured resource limits and retained failure logs |

Existing anchors provide no unilateral dead-owner recovery authority. An
account-key backup cannot revive erased MLS state, fence a live clone or
establish that an old device was retired. Recovery must use live authorized
membership, explicit migration to a new room, or a separately designed anchor
policy agreed at creation. Do not add an archive-to-live shortcut.

The operator identified the development Mac and `vhalla.com`; live inspection
confirmed the existing Vercel project, and repository configuration identifies
its static `site/dist` artifact. No independent relay host is selected. The
[operational qualification plan](operational-qualification.md) explains the
smallest next topology without provisioning or activating a public service.

## Security gate status at baseline

The current Rust aggregate and workflow analysis completed successfully, but
the separate CodeQL PR check is failing: it reports 239 new critical
`rust/hard-coded-cryptographic-value` findings and one high logging finding.
The branch also includes older findings. The inspected logging finding is
`crates/vhalla-rooms-node/src/unix/tests.rs`: a public consensus certificate's
byte length is printed, not secret key material. The nonce findings include
deterministic synthetic test fixtures, which the test design deliberately uses.
Further source triage of the current 364 open branch findings identified 363
nonce/value reports and that one logging report. Most locations are test modules,
examples or isolated prototypes. The production-file locations inspected are:

- `public-protocol/{response,activity,discovery}`: zero-initialized decode
  destinations whose every byte is filled from validated complete input.
- `browser-vault::seal`: an envelope buffer populated with caller-supplied salt
  and nonce before encryption; encryption uses the nonce argument directly.
- `browser::transport::nonce`: a buffer filled by browser CSPRNG, with RNG
  failure returned rather than a zero fallback.
- `session::Handshake::decode`: the absent responder field in an initial Hello;
  real response nonces come from input and pass freshness validation.

The [complete source review](codeql-review-2026-09-22.md) subsequently accounted
for all 364 saved alert IDs across 60 unchanged files: 356 synthetic fixture
reports and eight data-flow false positives, with exact boundaries and rationale.
No exploitable vulnerability was confirmed in that saved set. These are
source-level reasons for classification, not permission to replace entropy or
weaken nonce checks. The actual required GitHub check remains separate from
local triage. No alert is dismissed, suppressed or treated as a passed merge
gate by this continuation.

## Validation record

Focused evidence so far (not a final integration gate):

- Browser private codec: 9 tests passed, including predecessor-authorized
  succession proof decoding and refusal of bare grants.
- Browser private panel model: 7 tests passed, including private-field inventory
  and archive download bounds.
- Private kernel/protocol: 76 kernel tests, 9 protocol tests and 5 doctests passed.
- Native relay: the initial 26 regression tests and six real CLI relay journeys passed;
  strict focused native/CLI lint passed. This includes hostile page progress,
  namespace and legacy preservation, publication interruptions, bounded custody
  reads and slow-trickle deadlines.
- Real Chromium private panel: passed with three isolated synthetic contexts,
  complete owner handoff, all-field lock cleanup, malformed archive tail after
  durable progress, and exact complete-file resume. Artifact digest:
  `00d0929360efc2a2fbd45224e7a3d3f9bd2a8a3b0c21ef42aac151c89340227d`.
- Site: 10 tests / 626 assertions and production build passed; actual Chromium
  qualification passed all documentation routes, 320–1365px layouts, light/dark,
  keyboard and no-JavaScript checks with no console errors. Phone/private-room
  and desktop/home screenshots were inspected. This is local evidence, not a
  website deployment.
- Delivery/security workflow regressions: 29 tests passed.
- Recovery-policy experiment: 5 tests passed; all 5,461 bounded observation
  histories retain indistinguishable loss/partition worlds, and the unsafe
  timeout proposal produces a concrete counterexample.
- Agent compartment: 16 broker/framing tests passed, including post-I/O deadline
  enforcement added after independent review. The scheduled macOS 26.5.2
  synthetic probe denied canary read/write, TCP/Unix connections, fork and
  external execution; inherited pipe communication succeeded, with no provider
  calls. The deprecated backend is not a production sandbox.
- Browser archive isolation: native namespace regression passed; Chrome 153
  exercised three real workers, termination after two confirmed pages, exact
  retry, quota abort preserving retained state, independent A/B snapshots and
  unchanged legacy A. Context/ID substitutions refused before destination writes.
  WASM digest: `fe52a7606e9e006d57f434df8566bf7bd39925d4d4dde46a8c714369c8861cd8`.
- TLS relay: nine actual loopback TLS tests and strict all-target lint passed.
  Cases include trust/name failure before application bytes, credential/scope
  refusal, absolute handshake limits, malformed frames, durable lost-receipt
  retry, bounded large pages and production-frame parity. No endpoint was deployed.
- macOS desktop: separate menubar workspace compiled and both tests passed.
- Dependency audit: all 54 maintained/reference graph reports were retained;
  no active vulnerability findings. Inactive lockfile findings, the preserved
  historical reference's rustls advisory and maintenance warnings remain visible.

The local unsharded `cargo test --workspace --all-targets --all-features --locked`
attempt reached its runner's 900-second cap during the CLI consensus mesh suite.
It completed 32 test targets / 259 tests with no explicit test failure before
the timeout, and several long mesh journeys also reported success. This is an
incomplete run, not a passed aggregate gate. The repository's unchanged CI
shards cover the entire workspace, including the documented long consensus
tests; their exact-head aggregate result remains required. Final focused native
and CLI tests, workspace doctests and workspace strict lint are run separately
below; the timeout does not waive any CI shard.

An independent reviewer found no additional P0–P2 defect in the repaired
production paths or isolated spikes. Its P3 broker-deadline finding was repaired
with late-readiness/final-I/O regressions, and the TLS experiment was aligned
with native empty-page behavior beyond the retained head. The review covered
succession proof/expiry and format refusals, relay custody/publication/paging,
browser lock/import/download behavior, archive destination selection, provider
grants, actual macOS isolation and TLS trust before credentials. This is a scoped
engineering review, not a claim of independent cryptographic certification.

Final local `cargo test -p vhalla-private-native --all-targets --all-features --locked`,
`cargo test -p vhalla-cli --all-features --locked --test private_rooms`,
`cargo test --workspace --doc --all-features --locked` and
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
all passed after the final corrections. Workspace/prototype formatting and
`git diff --check` passed. The exact-head CI aggregate remains pending delivery;
baseline CI does not validate subsequent working-tree changes. Use Rust 1.98.1 explicitly
on this host; its default toolchain is older. Heavy commands use the installed
host scheduler, with one owner per browser flow and one integration owner for
the final gate.
