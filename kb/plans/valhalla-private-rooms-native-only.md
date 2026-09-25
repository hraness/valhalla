---
title: "Private rooms run where you are: native hosts only"
type: plan
area: private-rooms
status: in-progress
tags:
  - architecture
  - operations
  - security
  - qualification
---

# Private rooms run where you are: native hosts only

## Outcome

Every private-room participant, person or agent, runs Valhalla natively on a
machine they control: a laptop, a server, or a sandbox that only has outbound
network access. Hraness hosts nothing for private rooms. One participant's
machine hosts a room's mailbox; every other participant connects out to it
over pinned TLS, directly when the host is reachable and through Tailcat when
the host sits behind NAT. The browser interface is an optional local client
that talks only to a gateway on the same machine. The install-free browser
path selected earlier on 24 September 2026, a hosted HTTPS application origin
with a multi-tenant ciphertext gateway, is withdrawn before activation.

The product goal that shapes every choice below: setup is one binary and one
file per role, running costs are imperceptible, and any environment with an
outbound TCP connection can take part. macOS, Linux and Windows are all
targets; the current host on this Mac already idles at 11 MB of memory and
0.0 percent CPU after 37 hours, and the plan keeps clients in that class.

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
Release v0.2.3 ships `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`
CLI archives of 12 to 14 MiB; the CLI binary is about 32 MB on disk.

What Tailcat is, checked against its upstream README on 24 September 2026:
Tailscale's data plane without its control plane, BSD-3-Clause open source,
free, no Tailscale account and no root or admin rights. A server prints a
`tc...` address that is a bearer capability (it embeds a WireGuard pre-shared
key); a client with that address rendezvous through a DERP relay, then both
sides attempt UDP hole punching and usually upgrade to a direct peer-to-peer
path, including a direct local path when both are on the same network; DERP
stays as the relay of last resort. The default relays are Tailscale's public
ones, rate limited and offered best effort with no uptime promise; anyone can
run their own DERP relay (a hostname with a certificate) and bake it into the
address. Static binaries exist for Linux, macOS (Homebrew) and Windows, about
6 MiB compressed. On this Mac the Tailcat server idles at 32 MB of memory and
0.0 percent CPU.

What the hosted direction added, and what this plan retires: an explicit HTTPS
format-2 transport and gateway mode (pull request #116, never merged), a hosted
operations review with seven activation gaps, a browser-only second-machine
harness, and a Tailcat-WASM transport spike. The
[private-room pilot plan](valhalla-private-room-pilot.md) continues the
protocol and product work (responsive delivery, relay admission, mailbox
generations, owner and device recovery, the collaborative pilot) and is
unaffected except where it names a hosted browser route.

## Scope and non-goals

In scope: the deployment shapes and connection tiers below, the platform
targets, the footprint budget, the one-file setup, the operator model for a
laptop host and for a server host, what changes in code and documentation, the
qualification matrix, and the decisions made. Out of scope: any
Hraness-operated relay, gateway or DERP server, a public HTTPS application
origin for private rooms, install-free browser participation, browser
transport that bypasses the local gateway, automatic certificate issuance,
LAN auto-discovery, and any change to the MLS, custody, admission or delivery
contracts frozen in the readiness and pilot plans.

## Constraints and decisions

1. **Three connection tiers, one client.** A client always dials out over the
   same pinned TLS with its own token; only the host's reachability differs.
   Same machine: loopback, as today. Same network (home or office Wi-Fi, a
   LAN, a cloud VPC): the host binds a LAN address and clients dial it
   directly; nothing else is installed. Public Internet: a host with a public
   address (a server, a VPS the participant already pays for) binds that
   address on a chosen port and clients dial it directly; a host behind NAT (a
   laptop at home) serves its relay port through Tailcat, and clients run a
   Tailcat forward to it. Tailcat is therefore the NAT escape hatch, not a
   requirement, and no tier needs Hraness infrastructure or money beyond what
   the participant already runs.
2. **Agents are outbound only.** A participant in a sandbox, container or
   locked-down server needs no inbound port, no daemon and no root: one
   `vhalla` binary, one owner-private profile, one process for the session.
   Only the room host needs to be reachable. This is what makes the design
   universal.
3. **The host may leave loopback.** `private-host` gains explicit non-loopback
   listeners, and with them the hardening a hostile network requires: TLS 1.3
   with the pinned CA and exact name before any work, a valid token before any
   storage read, the existing 16-connection cap (configurable 2 to 64),
   handshake caps per window and per source address, absolute per-request
   deadlines, slow-client refusal, and no plaintext or unauthenticated path.
   The connection descriptor lists the reachable addresses; tokens travel
   separately, as today.
4. **Imperceptible when idle.** Budgets, measured as sampled RSS and CPU time
   in the existing runtime harness: host at most 16 MB and no measurable CPU
   at idle; client at most 12 MB and at most one relay request per minute at
   idle; message arrival latency under one second while a session is active.
   Today's client polls with a fresh TLS exchange every 1 to 5 seconds while
   active and every 5 to 30 seconds while idle, which is where idle cost goes.
   The relay's page operation gains a bounded wait: the host holds an
   authenticated page request open until items arrive or the wait expires, so
   an idle client keeps one quiet connection and still hears a message within
   the wait's granularity. Polling remains the fallback and keeps its error
   backoff. Tailcat adds about 30 MB when a host uses it; clients that dial a
   reachable host add nothing.
5. **One file to join.** The owner produces one owner-private invite file per
   participant containing the host's addresses, the pinned CA, that
   participant's own relay token, the namespace and the room offer; the
   participant runs one command with it and is ready to request admission,
   receive a grant, or connect a browser on that machine. The file is a secret
   capability, shared privately like a Tailcat address; it changes packaging,
   not the admission, custody or authority semantics.
6. **Platforms.** macOS (today), Linux (binary ships today; supervisor and
   packaging follow), Windows (new). The Unix-only surface is concentrated:
   the custody crate (209 lines), 16 files in the CLI, 7 in the public peer, 5
   in the private native crate and a dozen single-file spots in the stores;
   there is no Windows CI yet. The port introduces a custody abstraction whose
   Windows backend uses owner-only ACLs, exclusive file locking and
   reparse-point refusal, then brings the client first (agent-serve and
   delivery), then the host with a Windows service. Supervisors: LaunchAgent
   on macOS, a systemd user unit on Linux, a Windows service; every one keeps
   the exact-executable, owner-private, bounded-restart and separate
   supervisor-log rules.
7. **Where the relay runs and what it is.** A laptop host is usually on;
   sleep, logout and network loss are expected outages while durable clients
   retain exact ciphertext and retry. A server host is always on and is
   administered by a participant. One host home has one namespace, two
   credentials and one mailbox generation; run one host home per room until
   multi-mailbox hosting is designed. The relay holds opaque ciphertext and
   quotas, not history; members' stores are the source of truth, and recovery
   from a lost host is a new mailbox generation on a new host under the
   drained-transition contract, never a restore of an old image over a live
   mailbox.
8. **Browser stays same-machine only.** A second laptop runs its own CLI,
   gateway and, if needed, Tailcat forward, and its browser opens the loopback
   gateway. The loopback-only refusal is a security boundary: whoever serves
   the application assets can read what the user types, so assets come from
   the local release archive.
9. **What is withdrawn.** The format-2 HTTPS gateway mode and its browser
   profile format, the hosted-origin documentation, the browser-only second
   machine harness, the Tailcat-WASM prototype, and the hosting discovery's
   provider selection. #116 is closed with its branch retained. Of the seven
   hosted activation gaps: the supervisor-log defect is fixed on `main`
   (#112); persistent storage with a fenced restore, credential renewal and
   revocation, a finite capacity policy, and actionable status and restart
   qualification carry over to any always-on host as operator procedures; the
   public certificate and browser recovery at a permanent public origin are
   dropped.
10. **Public copy.** The site and README describe private rooms as something
    you run on your own laptop or server, with nothing hosted for you, and say
    plainly when Tailcat is needed (only for a host behind NAT) and what it
    costs (nothing; best-effort public relays, or your own).

## Dependency-ordered work

1. **Record the decisions (this change).** No code changes.
2. **LAN and public listeners.** Allow explicit non-loopback `--listen` on
   `private-host` with the hardening in decision 3; make `connection.json`
   carry the reachable addresses; add hostile-network tests (token, CA and
   namespace floods, slow and half-open clients, handshake storms from one
   source, congestion under the connection cap, restart with exact retry) and
   keep the loopback default. Document the three tiers in the local-host guide
   with one command per tier.
3. **Quiet clients.** Add the bounded wait to the relay page operation, the
   native delivery driver and the browser worker; keep polling as fallback;
   extend the runtime harness to report idle requests per minute, sampled RSS
   and CPU time per client and host; record the before and after numbers
   against the budgets in decision 4.
4. **One-file invite.** `vhalla private invite` writes the bundle;
   `vhalla private join` consumes it, creating the delivery profile and the
   admission request in one step. Focused tests for wrong or reused bundles;
   no change to kernel admission.
5. **Linux supervisor and packaging.** systemd user units for host, gateway
   and the Tailcat overlay with `install`, `status` and `uninstall` parity,
   Linux process tests for the install and refusal paths, and a `.deb` or
   plain tarball recipe in the release workflow with the same provenance
   checks as macOS.
6. **Windows.** Custody abstraction and Windows backend; client build and CI
   on `windows-latest`; release archive; then the host and a Windows service.
   Each stage ships behind its own CI evidence; Windows host support is not
   claimed until the service lifecycle journey passes.
7. **Second-laptop browser route.** Re-run the two-Mac browser evidence in
   the native shape (B's own CLI, gateway and forward); retire the
   browser-only participant.
8. **Host change.** Extend the drained mailbox-generation contract from the
   pilot plan to a successor on a different host with a changed endpoint,
   accepted only through an explicit reviewed owner control; model first.
9. **Independent-device acceptance.** A laptop host and a server host on a
   LAN and across the Internet, direct and through Tailcat with path
   classification; a Windows client; sleep, logout and reboot on the laptop
   with an agreed window; the sparse soak on the server.
10. **Public copy and release record.** Update the site's private-room pages
    and the CLI README to the native-only, three-tier description and record
    the first release that ships each platform.

Steps 2, 3, 4 and 5 are independent of each other and start immediately; 6
follows the custody abstraction inside it and can begin its abstraction work
in parallel; 7 depends on 2; 8 depends on the pilot plan's phase 3; 9 depends
on 2, 3, 5 and 7; 10 follows each first release.

## Verification

- Each code step keeps the repository gates: strict formatting and Clippy,
  the workspace test matrix on every supported platform, the private-host
  process tests, the production browser journeys, security and
  Kani/Verus/TLA+ checks, and current-head CI before merge.
- Footprint claims come from the runtime harness with sampled RSS, CPU time
  and request counts, never from a description of the design.
- Qualification uses fresh synthetic homes, identities and rooms; never the
  owner's live host on this Mac, whose services stay untouched until an
  explicit upgrade window.
- Every independent-device claim names the machines, the exact artifact
  hashes, the tier and route, and the retained receipts; a local pass is never
  described as a remote result.
- The site copy check and vault checks run before handoff.

## Recovery

- A failed step leaves retained evidence and preserves existing homes; nothing
  deletes state to regain a budget, cursor, grant or ratchet.
- If the non-loopback listener fails its hostile-network qualification, it
  stays behind the loopback default and Tailcat remains the only remote tier.
- If the bounded wait misbehaves, clients fall back to the existing polling
  policies without a format change.
- If the Windows custody backend cannot meet the owner-only guarantees, the
  Windows client ships without local host support and says so.
- Reopening the hosted direction means reopening #116 and the hosted
  operations review; this plan would then move to `superseded`.

## Decisions made on 24 September 2026

- Linux and Windows are supported targets alongside macOS; Linux first
  because its binary already ships, Windows client before Windows host.
- A host may listen on a LAN or public address directly; Tailcat is required
  only when the host is behind NAT. Both are free; Tailcat's public relays are
  best effort, and a participant who wants independence runs their own DERP
  relay.
- The browser stays in the product as a same-machine client only.
- The owner asked that the mechanics be decided here rather than by them;
  these calls optimise for one binary, one file, no inbound ports for
  participants, and idle cost that is not noticeable.

## Implementation log

- 24 September 2026: plan created on `claude/private-rooms-native-only-20260924`
  from `main` `364777a`. The hosted-browser pull request #116 was closed
  with its branch retained; the two-Mac browser-only runs c1 to c3 and the
  Tailcat-WASM spike remain in the session workspace as evidence of why the
  hosted route was expensive, not as work to continue. The single-machine
  browser journey, the native two-Mac result and the supervisor-log fix stay
  in force.
- 24 September 2026, second pass: the owner asked for Linux and Windows, asked
  what Tailcat costs and how same-network and public-Internet participation
  work, and asked for the mechanics to be decided with simplicity, footprint
  and universality as the goals. Added the three connection tiers, the
  outbound-only participant rule, the non-loopback host with hardening, the
  footprint budgets and bounded-wait page operation, the one-file invite, the
  platform port order, and the resolved decisions. Measured on this Mac:
  host 11 MB RSS and 0.0 percent CPU after 37 hours, gateway 19 MB, Tailcat
  server 32 MB and 0.0 percent CPU; Tailcat binaries about 6 MiB compressed
  for Linux, macOS and Windows.
- 25 September 2026, step 5 supervisor: #122 merged as `1329c6a`. On Linux,
  `private-host` and `private-gateway` `install`, `status` and `uninstall`
  manage a per-user systemd unit under the LaunchAgent's exact-identity rules;
  the flows are unit-tested on every platform with injected `systemctl`
  replies, and `status` reports an unavailable user manager instead of
  failing. Still open for step 5: the Tailcat overlay unit, an operator-run
  journey on a Linux host with a user manager, and release packaging.
- 25 September 2026, step 2 listeners: #125 merged as `b519083`.
  `private-host init --listen`
  accepts one unicast address of the machine (wildcard, multicast, broadcast
  and link-local refused) and `--advertise` up to four addresses clients
  dial instead, for a cloud server behind 1:1 NAT; `connection.json` and
  `status` carry `addresses`. The relay holds each peer that is not loopback,
  keyed by IPv4 address or IPv6 /64, to a quarter of the connection slots and
  a quarter of each window's handshakes, and caps the per-window source table
  at 4,096 entries; loopback peers, including Tailcat forwards, share only
  the totals. Mailbox generations and the Tailcat template stay
  loopback-only; moving the clients of a network host is step 8. Linux CI
  dials the runner's routed address to exercise the per-source refusals and
  a network-listener round trip. Still open for step 2: floods of slow and
  half-open clients from many sources, and a LAN run between two machines.
- 25 September 2026, step 3 quiet clients: #136 merged as `fab2301`.
  `OP_PAGE` accepts a 12-byte waited shape (`wait_ms`) alongside the
  ordinary 10-byte request; a host that predates it answers bounds and the
  client retries the ordinary body on the same gesture, so timed polling
  stays the fallback. The TLS service holds a page request open up to
  `max_wait` (60-second default, 120-second cap, `max_wait_ms` optional in
  the relay configuration), wakes it on each committed put or on drain, and
  keeps it billed against its admission quotas; a poisoned store fails
  closed. The delivery driver runs one lazy watch on a second connection
  that publishes only the observed mailbox head; the bounded scan still
  validates and stages every record, and a dead or refused watch falls back
  to the existing cadence. The browser sends an eight-second wait on
  discovery and sync gestures and remembers a refusal for the worker's
  life. Measured on this Mac with release binaries of the parent commit
  and the change through the same quiet scenario: idle relay connections
  went from two per minute to none inside the 30-second window, post-quiet
  delivery acceptance from 28.7 to 3.6 seconds, host 11.8 MB sampled RSS,
  agents 13.7 to 13.9 MB and under 0.4 percent of a core. The agent figure
  exceeds the 12-megabyte client budget in both builds, a pre-existing
  baseline the wait did not change; the budget needs its own decision
  rather than a regression fix. Still open for step 3: the same numbers on
  Linux and Windows, an active-profile measurement of the one-second
  arrival bound, and the two-Mac idle run folded into step 9. A floor
  check on the same release binary gives the budget decision real shape:
  `--help` peaks at 7.4 MB, `identity init` at 9.3 MB and a one-shot
  `private create` — no driver, no TLS, no delivery threads — at 13.0
  MB, so the overage is the private-store/MLS baseline, not the
  quiet-client runtime.
- 25 September 2026, step 4 one-file invite: #138 merged as `ee94e18`.
  `private invite` verifies the sealed host home and bundles a
  confidential offer with one enrolled, unrevoked credential's relay
  material — namespace, TLS name, CA, token and the advertised dial
  addresses — into one owner-private file. `private join --invite`
  authenticates the bundle against the expected owner and the joiner's
  account, commits the fresh member store, lays down the delivery
  profile in a new owner-private directory, initializes delivery state
  and writes the encrypted admission request; `accept` and
  `join --response` are unchanged. The bundle is packaging only: the
  credential stays an ordinary revocable bearer capability and a
  failure after commit is recovered through the granular commands,
  never a rerun into the same store or directory. Focused tests cover
  unenrolled, zero and revoked credential indexes, malformed, tampered
  and mismatched bundles, unadvertised address selection, store and
  delivery-directory reuse and conflicting join modes.
