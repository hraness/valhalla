# Agent readiness execution

Continuation requested on 22 September 2026, starting at
`8afd571098aa2057ee6e4f10692227642cdc6aef` in the original PR #85 checkout.
The stopping condition is an installable, documented agent workflow with current
integration evidence and honest operational acceptance. Passing library tests
alone does not meet it.

## Acceptance contract

- An existing CLI agent can use a bounded, versioned machine interface without
  receiving account signing keys or an arbitrary room/recipient selector.
- Trusted setup selects the full room/device and finite permissions, identifies
  the inference disclosure boundary, and retains revocation authority. Ambient
  host access is never described as an OS sandbox.
- Production relay transport authenticates the server before sending scoped
  credentials; hostile and slow clients cannot consume unbounded work. Exact
  encrypted delivery jobs survive restart and back off under outage or overload.
- Local queueing, relay retention, member processing, and human reading remain
  distinct claims. Any member-processing evidence authenticates the exact
  message and context after durable processing.
- Recovery preserves existing custody and read-only history. Missing owner
  custody offers authorized fresh admission or an explicit new room, never an
  archive-to-live ratchet shortcut.
- Browser archives can retain separate authenticated snapshots with bounded
  storage and export memory, exact interrupted resume, and explicit legacy
  selection. No failure is interpreted as permission to overwrite old state.
- Release artifacts include the maintained agent/private-room surface. Exact-head
  source/security/package gates, independent review, and real deployment checks
  pass before claiming the corresponding capability ready.

## Execution and ownership

1. **Contract and discovery — complete.** Root integrates scope and acceptance;
   `review_private` maps agent/runtime contracts; `review_relay` maps transport,
   scheduling and acceptance; `recover_session` identifies available operational
   targets and audits delivery gates. These discovery tasks are read-only.
2. **Parallel implementation — complete.** Assign disjoint source
   paths, focused tests and owners before writes. Root owns shared manifests,
   release workflow, this plan and integration. The release publisher's missing
   separate CodeQL gate is owned by `recover_session` with its focused tests.
3. **Integration — in progress.** Test real agent/room/delivery composition, browser
   recovery, restart/uncertainty boundaries and supported containment where used.
4. **Independent review and final gates — pending.** Focused cross-lane reviews
   repaired launchctl failure classification, staged-cursor corruption, browser
   Origin handling and release artifact provenance. Review the complete changes,
   repair concrete findings, run final repository gates and exact-head CI. One
   owner per expensive validation and external wait.
5. **Operational acceptance and delivery — pending.** Use identified owned
   targets and synthetic state. Qualify clean installation, independent delivery,
   outage/restart, storage-full and recovery. Record exact artifacts and results;
   no unrun capability receives a readiness claim.

## Decisions and evidence to retain

The user selected existing CLI agents (Codex and Devin) first, with the Mac as
an explicitly local, mostly persistent host and Tailcat or equivalent private
networking. Browser sessions are also in scope. No paid server, provider budget
or public domain is required for this first workflow. `vhalla.com` remains the
static website; publishing it does not start a Valhalla host.

The MCP adapter is a cooperating-host capability interface. External CLI tools
and their configured model providers retain ambient authority; this is not OS
containment. Host sleep and browser suspension pause delivery, preserving exact
queued ciphertext and finite retry evidence for an explicit resumed session.

Current local-host lanes: `recover_session` owns bootstrap, status and a dedicated
macOS LaunchAgent; `review_relay` owns the portable relay codec and authenticated
loopback HTTP gateway; `local_host_map` owns browser worker transport and durable
synchronization. Root owns shared manifests, native trusted bootstrap cursors,
actual CLI qualification and integration. Tailcat uses a saved server key and a
fixed browser forwarding port so the IndexedDB origin survives restart. A browser
client requires native Tailcat for this first remote path; install-free/mobile
browser networking is not yet qualified.

Existing-anchor unilateral dead-owner recovery is excluded by the retained
policy model: loss and partition are observationally indistinguishable. A new
anchor recovery policy would be a distinct product/security design, not a
compatibility fix. A useful ready product must explain and exercise its supported
fresh-device/new-room recovery path.

The previous source review classified all 364 baseline CodeQL reports; the
approved individual dispositions cleared that baseline. Current-head CodeQL
remains a real delivery gate. Resolve any new findings
through specific verified fixes or supported individual dispositions; do not
exclude a rule, path tree, language or security gate to get a green result.

## Current implementation evidence

- Fixed-room MCP: 10 native tests, three original real stdio process journeys;
  modern and legacy protocol, one-use claims, malformed framing, cancellation,
  fixed context, host-supplied checked delivery metadata and recipient claims.
- Member acceptance: five kernel tests covering durable receive prerequisites,
  context/ciphertext/signature refusal, crash publication and exact retries,
  cancellation after commit and later membership epochs. Host wrappers retain
  uncertainty and do not add agent signing tools.
- TLS/delivery: 47 original focused relay tests plus the saturating-backoff
  regression, 20 scan tests including one-page/caller-deadline recovery, and
  the final 12-test TLS suite including independent-review storage-health repair.
  Strict native/kernel Clippy passed at those lane boundaries.
- Browser: catalog two tests, codec ten, panel seven, strict WASM Clippy and a
  production worker/DOM journey. The receipt at
  `/private/tmp/valhalla-production-archive-dom-20260922-r2/receipt.json` covers
  snapshots, legacy preservation, exact resume, reservation capacity and real
  writable-stream abort; the injected picker does not qualify the OS dialog.
- Release publication: 26 publisher regression tests and all 49 workflow-script tests passed. Live readback
  established that managed CodeQL emits the separate security verdict on PR
  heads but not on this repository's main branch. Publication now requires all
  four exact-main successful analyses and an empty fully paginated open-alert
  inventory, plus a successful authentic CodeQL verdict whenever present. Both
  pre-upload and pre-publication checks remain; all severities block release.

These are focused lane receipts, not the final converged-tree gate. The CLI
delivery driver passed independent review, 32 focused CLI tests including three
real two-process TLS delivery journeys, and strict Clippy. No changes from this continuation have been published yet.

The refreshed 364-alert inventory exactly matches the reviewed IDs/rules/locations
at `8afd5710`; all 60 affected files remain byte-identical to the source review.
The user explicitly approved all 364 individual dispositions on 22 September.
The exact full per-alert reasons remain at
`/private/tmp/valhalla-codeql-reviewed-dispositions-20260922.json`; API comments
were shortened to fit GitHub's 280-character limit without changing alert IDs,
reasons or the reviewed rationale. All 364 dispositions were applied and individually verified; a separately
paginated readback confirmed every approved ID, reason and comment. Evidence:
`/private/tmp/valhalla-codeql-disposition-receipt-20260922.json`. Rules and security checks remain enabled; final current-head
CodeQL evidence is still required.

Installed-client qualification now includes Codex CLI 0.155.1: one real app-server
thread connected a synthetic room, discovered all five tools, and successfully
called `private_status` with the exact granted context. No inference request was
made. Receipt: `/private/tmp/valhalla-codex-live-20260922-r4/receipt.json`.
Its separate `mcpServerStatus/list` probe starts another MCP process and therefore
refuses the consumed one-use grant; qualification uses the actual thread tool
call and its observed tool inventory. Devin 3000.11.1 also completed its handshake, discovered all five tools, and
executed exactly one synthetic `private_status` through its configured model in
Ask mode with only that call approved once. Receipt:
`/private/tmp/valhalla-devin-live-20260922-r3/receipt.json`.

The production browser artifact now explicitly includes `private-rooms`; network
activation still requires the user's selected profile/capability and Sync action.
The real production browser→gateway→TLS journey is a required CI step. Release
packaging takes that exact tested browser artifact and requires it alongside the
two native CLI archives and macOS menubar (four archives and four checksums).
Missing browser output blocks release before network writes.
The reusable validation workflow exposes the manifest hash from the successful
production browser delivery receipt. Packaging requires that exact hash and
rechecks every bounded flat artifact file; changed, missing, extra or linked
files refuse. This avoids relying on an artifact download's warning-only digest
comparison. Release also runs the macOS host lifecycle unit tests.

Actual Tailcat v0.7.0 qualification passed TLS retention, exact scan, offline
refusal and restart with the same saved server key, mailbox, TLS identity and
client port. A surviving client forward failed eight bounded retries after the
server restart; explicitly restarting that forward recovered on its first retry
without changing stored state. Automatic overlay reconnection is not claimed.
Receipt: `/private/tmp/valhalla-tailcat-live-20260922-r3/receipt.json`. All synthetic
test processes were stopped. This is one-Mac overlay evidence, not independent
machine qualification.

The continuation was checkpointed as `6aa3f76`, then merged with current main
`caaf180` (PR #87's Platonik removal) in `4d1f438`. The merge preserves the
private/browser work and all intentional game removals. Only the two removed
game packages left the expanded lockfile; no unrelated versions changed. The
incoming tracked browser bundle remains historical main content, not the new
qualified production artifact used by packaging.

The final review found recovery defects before delivery: Sync cleared only UI
consent, authorization denial could permanently strand exact queued ciphertext,
and HTTP port 80 had a noncanonical browser origin. Repairs invalidate consent
in the worker, end the current unauthorized session while retaining attempt/
backoff budgets for explicit credential replacement, and refuse the unsupported
port. Malformed receipts and exhausted lifetime budgets still stop permanently.
The first actual LaunchAgent attempt also exposed an oversized whole-domain
`launchctl` preflight. The scoped service probe replaces that broad dump; fresh
live qualification is required before claiming installation success.

The final merged dependency gate passed with pinned `cargo-audit 0.22.2` across
47 retained graphs. No active vulnerability findings; two inactive lockfile
advisories, one archived advisory and 15 warnings remain recorded without
suppression. Reports: `/private/tmp/valhalla-final-security-reports-20260922`;
gate log: `/private/tmp/valhalla-final-security-20260922.log`.

The repaired real macOS LaunchAgent journey passed: init/install/status, pinned
TLS submit and exact retry, second-credential scan, wrong-credential refusal,
uninstall and exact absence/closed-listener readback. Private files and the
retained mailbox item remained intact. Receipt:
`/private/tmp/valhalla-launchagent-qualification-20260922-r2/receipt.json`;
binary SHA-256 `a106888ef98898c5440d2ba90b93cf50978ce13c7afc76bc1a8509eed0763f77`.
The synthetic host is stopped and uninstalled. Reboot and sleep/wake were not
performed on the user's active Mac.

The merged integration gate passed 325 protocol/kernel/native/browser-storage/
browser tests, 95 CLI unit/process tests (including four real TLS agent-delivery
journeys), 43 workspace doctests, 49 workflow/security script tests, five recovery
policy tests and 16 disclosure-broker tests. Commands and durations:
`/private/tmp/valhalla-final-integration-results-20260922.json`. No test was ignored.

The exact production private-browser panel/archive journey also passed with
manifest `e8b9b347cc00498cbe3177da42044b67a82a5a30490b6c040e3da87bd84c12ef`.
It covered three contexts, fresh-device admission, removal/succession, snapshot
coexistence/resume/global quota and 44-chunk OPFS streaming with cancellation and
write-failure checks. Receipt:
`/private/tmp/valhalla-browser-private-production-archives-20260922/receipt.json`.
Desktop and narrow-layout screenshots were inspected. The OS picker is still
represented by an injected handle to a real browser writable file.

The first browser/gateway journey exposed macOS inheriting a nonblocking listener
flag on accepted sockets, truncating large WASM assets. The gateway now restores
blocking connection I/O while its wrapper recomputes the original remaining
deadline for every read/write. Three real TCP regressions cover complete 8 MiB
responses, forced inherited mode and stalled-reader shutdown; they passed in the
integrated suite. The macOS release lane repeats gateway socket tests.

Final workspace formatting and strict all-target/all-feature Clippy passed again
after the socket repair; log:
`/private/tmp/valhalla-final-workspace-quality-after-http-20260922.log`.
