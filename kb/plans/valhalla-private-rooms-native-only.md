---
title: "Private rooms run where you are: native hosts only"
type: plan
area: private-rooms
status: accepted
tags:
  - architecture
  - operations
  - security
  - qualification
---

# Private rooms run where you are: native hosts only

## Outcome

Every private-room participant, person or agent, runs Valhalla natively on a
machine they control: a laptop that is usually on, or a server they administer.
Hraness hosts nothing for private rooms. The relay for a room runs on one
participant's machine, other participants reach it through their own Tailcat
forward, and the browser interface is an optional local client that talks only
to a gateway on the same machine. The install-free browser path selected on
24 September 2026, a hosted HTTPS application origin with a multi-tenant
ciphertext gateway, is withdrawn before activation.

The owner made this decision on 24 September 2026 after seeing what the hosted
path still required: a persistent public host with direct TCP, a public
certificate and its renewal, a credential portal, fenced backups of a hosted
mailbox, and a recurring budget. None of that buys end-to-end encryption the
native path lacks; it only moves who operates the relay. This plan records the
decision, restates the design under the new assumption, and orders the work
that remains.

## Context

The native path already exists and is the qualified one. `private-host` runs a
loopback TLS mailbox with a pinned CA, per-client tokens and bounded quotas;
`private-gateway` gives a browser on the same machine a same-origin loopback
path; `agent-serve` gives an existing CLI agent a finite MCP grant; Tailcat
v0.7.0 exposes the one relay port to remote participants as a capability
address. The [local host guide](../../docs/local-host.md), the
[CLI-agent guide](../../docs/cli-agents.md) and the
[operational qualification baseline](../../docs/operational-qualification.md)
describe it. Two physical Macs completed native bidirectional delivery and
stopped-member catch-up on 24 September
([evidence](../../docs/evidence/private-two-mac-native-20260924.json)); the
production browser journey passed on the second Mac against a local gateway.
Release v0.2.3 already ships `aarch64-apple-darwin` and
`x86_64-unknown-linux-gnu` CLI archives.

What the hosted direction added, and what this plan retires: an explicit HTTPS
format-2 transport and gateway mode (pull request #116, never merged), a hosted
operations review with seven activation gaps, a browser-only second-machine
harness, and a Tailcat-WASM transport spike. The
[private-room pilot plan](valhalla-private-room-pilot.md) continues the
protocol and product work (responsive delivery, relay admission, mailbox
generations, owner and device recovery, the collaborative pilot) and is
unaffected except where it names a hosted browser route.

## Scope and non-goals

In scope: the deployment shapes below, the operator model for a laptop host and
for a server host, what changes in code and documentation, the qualification
matrix, and the decisions still open. Out of scope: any Hraness-operated relay
or gateway, a public HTTPS application origin for private rooms, install-free
browser participation, browser transport that bypasses the local gateway,
automatic certificate issuance, and any change to the MLS, custody, admission
or delivery contracts frozen in the readiness and pilot plans.

## Constraints and decisions

1. **Where the relay runs.** One participant's machine hosts a room's mailbox.
   A laptop host is usually on; sleep, logout and network loss are expected
   outages during which durable clients retain exact ciphertext and retry. A
   server host is always on and is administered by a participant; it runs the
   same `private-host` and the same Tailcat overlay under a supervisor. Both
   are private hosts in the sense of the existing guides; the server merely
   changes the availability expectation and the supervisor.
2. **How remote participants reach it.** Through Tailcat only, in the first
   release. `private-host` keeps refusing non-loopback listeners; the Tailcat
   address remains a capability handed over privately; each client keeps a
   fixed local forwarding port because it is part of the persisted endpoint
   binding. A direct public TLS listener on a server is a separate, later
   decision (see open decisions): the pinned CA and tokens would authenticate
   it, but it exposes the mailbox to the open Internet and needs its own
   scheduling and abuse evidence, which the design review already lists under
   "public relay".
3. **How a person uses a browser.** Only on a machine that also runs the
   loopback gateway. A second laptop runs its own CLI, its own gateway and its
   own Tailcat forward; the browser opens `http://127.0.0.1:PORT` on that
   laptop. The browser's refusal of any non-loopback origin stays as a security
   boundary rather than a limitation to remove. Whoever serves the application
   assets can read what the user types, so the assets come from the local
   release archive, never from a remote origin.
4. **How an agent participates.** Unchanged: an existing CLI agent on a
   cooperating host receives a finite one-use grant through `agent-serve`; a
   server may host agents the same way. Grants, provider disclosure and room
   membership remain separate authorities.
5. **One mailbox per room per host home.** A host home has one namespace,
   two credentials and one mailbox generation. Run one host home per room, on
   its own port, until multi-mailbox hosting is designed; do not share a
   mailbox between rooms because every client would fetch and charge for the
   other room's ciphertext.
6. **What the relay is not.** It holds opaque ciphertext and quotas, not
   history. Members' native and browser stores are the source of truth; a lost
   mailbox loses only items not yet fetched by every member. Recovery from a
   lost host is therefore a new mailbox generation on a new host under the
   drained-transition contract, extended to a changed endpoint, never a restore
   of an old image over a live one.
7. **Supervision and evidence.** macOS keeps the LaunchAgent path (host,
   optional gateway, optional Tailcat overlay, separate `supervisor.log`).
   Linux servers get an equivalent systemd path with the same custody rules:
   exact executable and home, owner-private files, bounded restart, structured
   `events.log` separate from supervisor output, `status`, `install` and
   `uninstall` with the same refusals. Until that exists, a server runs the
   host in the foreground under an operator-chosen supervisor, and the guide
   says so.
8. **What is withdrawn.** The format-2 HTTPS gateway mode and its browser
   profile format, the hosted-origin documentation, the browser-only second
   machine harness, the Tailcat-WASM prototype, and the hosting discovery's
   provider selection. #116 is closed with its branch retained; nothing from it
   reaches `main`. The seven hosted activation gaps map as follows: the
   supervisor-log defect is fixed on `main` (#112); persistent storage and a
   fenced restore, credential renewal and revocation, a finite capacity policy,
   and actionable status and restart qualification carry over to the server
   host as operator procedures; the public certificate and browser recovery at
   a permanent public origin are dropped.
9. **Public copy.** The site and README describe private rooms as something you
   run on your own laptop or server, with nothing hosted for you. The readiness
   page keeps distinguishing implemented, released, locally tested and
   independently tested.

## Dependency-ordered work

1. **Record the decision (this change).** Add this plan; point the local-host
   and operational-qualification guides at it; close #116 with the reason.
   No code changes.
2. **Second-laptop browser route.** Re-run the two-Mac browser evidence in the
   native shape: Mac B runs its own CLI, gateway and Tailcat forward, and its
   browser uses B's loopback gateway. Reuse the native two-Mac coordinator and
   the loopback browser journey; retire the browser-only participant. Required
   evidence: admission, both directions, receiver offline and reopen at the
   same profile, gateway restart with exact retry, Tailcat forward restart with
   the same key, cleanup readback on both machines. This closes the
   "cross-device browser transport" row in the readiness matrix in its only
   remaining meaning.
3. **Linux server host.** Implement the systemd backend for `private-host`
   and `private-gateway` (`install`, `status`, `uninstall`, current-shape
   refresh, supervisor output), a Tailcat unit template mirroring
   `tailcat-plist`, and Linux process tests for install and refusal paths;
   extend the release qualification so the Linux archive carries the same
   feature set and provenance checks as the macOS one. Add a server section to
   the local-host guide: foreground first, then supervised start, then the
   backup and restore procedure below.
4. **Server operations.** Write and test the operator procedures the hosted
   review identified, now for a self-administered server: fenced backup and
   restore of the host home into an isolated target with the previous writer
   stopped and retained positions, exact ciphertext, quotas and duplicate
   results verified; credential replacement, expiry and revocation with a
   drained restart; a finite capacity policy with monitored headroom and an
   explicit end-of-capacity procedure that hands off to a new generation;
   `status --probe` and event tails as the operator view, with the supervisor
   log for coarse errors.
5. **Host change.** Extend the drained mailbox-generation contract from the
   pilot plan to a successor on a different host: new address, TLS name and CA
   are accepted only through an explicit reviewed owner control carried in the
   old mailbox, clients refuse an unreviewed endpoint change as they do today,
   and the old host remains readable until every member has cut over. This is
   the recovery path for a retired laptop and the migration path from a
   laptop to a server. Model it before implementing it; every counterexample
   becomes a regression.
6. **Independent-device acceptance.** Run the pilot plan's phase 5 across a
   laptop host and a server host: Tailcat path classification, forward restart,
   host restart and upgrade, sleep, logout and reboot on the laptop with an
   agreed window, the sparse soak on the server. Sleep, logout and reboot need
   an explicit device window and operator presence.
7. **Public copy and release record.** Update the site's private-room pages and
   the CLI README to the native-only description, run the copy check, and
   record the release that first ships the Linux supervisor.

Steps 2 and 3 are independent of each other; 4 depends on 3; 5 depends on the
pilot plan's phase 3; 6 depends on 2, 3 and 5; 7 follows the first release that
contains 3.

## Verification

- Each code step keeps the repository gates: strict formatting and Clippy,
  the workspace test matrix, the private-host process tests on both platforms,
  the production browser journeys, security and Kani/Verus/TLA+ checks, and
  current-head CI before merge.
- Qualification uses fresh synthetic homes, identities and rooms; never the
  owner's live host on this Mac, whose services stay untouched until an
  explicit upgrade window.
- Every independent-device claim names the machines, the exact artifact
  hashes, the route, and the retained receipts; a local pass is never described
  as a remote result.
- The site copy check and vault checks run before handoff.

## Recovery

- A failed step leaves retained evidence and preserves existing homes; nothing
  deletes state to regain a budget, cursor, grant or ratchet.
- If the Linux backend is not ready for a server pilot, run the host in the
  foreground under the operator's supervisor with the documented drain
  behaviour; do not ship an unqualified `install` path.
- If the second-laptop browser route fails qualification, browser use stays
  documented as same-machine-as-host until it passes; native and agent paths
  do not wait for it.
- Reopening the hosted direction means reopening #116 and the hosted
  operations review; this plan would then move to `superseded`.

## Open decisions

1. Is the first native-only release macOS laptops only, or does it include the
   Linux server supervisor (step 3)? The Linux CLI archive already exists.
2. Should a server ever expose the pinned-TLS mailbox directly on a public
   address instead of through Tailcat? Default here: no, until the public-relay
   evidence in the design review exists.
3. Does the browser interface stay in the first release at all (same-machine
   only), or is the first release CLI and agent only? Default here: it stays,
   because the loopback journey is already qualified and the boundary is clear.

## Implementation log

- 24 September 2026: plan created on `claude/private-rooms-native-only-20260924`
  from `main` `364777a`. The hosted-browser pull request #116 was closed
  with its branch retained; the two-Mac browser-only runs c1 to c3 and the
  Tailcat-WASM spike remain in the session workspace as evidence of why the
  hosted route was expensive, not as work to continue. The single-machine
  browser journey, the native two-Mac result and the supervisor-log fix stay
  in force.
