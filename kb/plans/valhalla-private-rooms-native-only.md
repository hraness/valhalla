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
   at idle; client at most one relay request per minute at idle; message
   arrival latency under one second while a session is active. The client
   memory budget was revised after measurement — see the 25 September log
   entry: it is now the measured private-store/MLS process floor (about
   13 MB on macOS, about 19 MB on Linux for the current link) plus at most
   4 MB of delivery-runtime overhead, under a 24 MB absolute idle cap;
   the original flat 12 MB was unreachable because the floor alone
   exceeds it. The host's 16 MB is a settled-idle figure; a loaded guardrail
   of 32 MB bounds transient delivery work (a Linux host sampled 20.2 MB
   mid-delivery).
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
   accepted only through an explicit reviewed owner control; model first
   (the model is the dated section below).
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

## Step 8 model — a mailbox successor on a different host (25 September 2026)

This section is the model for step 8. No code changes accompany it; it names
what the shipped contract does, the delta a different host introduces, and the
owner-control gate that makes the move an explicit decision rather than an
observed redirect. Sources: `crates/vhalla-cli/src/private_rooms.rs`,
`crates/vhalla-cli/src/private_rooms/agent_delivery.rs` and
`agent_delivery/generation.rs`, `crates/vhalla-cli/src/private_host/generation.rs`,
`crates/vhalla-private-native/src/private_rooms/generation.rs`,
`crates/vhalla-private-native/src/relay/delivery.rs` and
`relay/delivery/generation.rs`, `crates/vhalla-private-native/src/relay/tls.rs`,
`crates/vhalla-private-protocol/src/records.rs`,
`crates/vhalla-private-kernel/src/engine/controls.rs`,
`crates/vhalla-cli/tools/qualify_private_generation.py`,
`docs/private-generations.md`, `docs/private-rotation-contract.md` and
`verify/private-generation/README.md`.

### The shipped same-host contract

`private delivery-init` consumes a fresh version-2 profile and initializes its
state directory; `delivery-upgrade` establishes the split control queue an old
profile lacks — a profile without the control stream cannot take part in a
transition. During operation the driver forwards the kernel's authenticated
encrypted controls into the mailbox's `RelayKind::Control` lane (any joined
member may forward its suffix; dedup makes identical forwards one item) and
ordinary outbox artifacts into the outbox lane; mailbox positions are one
shared ordered sequence across both kinds.

`delivery-pause ID STORE --config --transition HEX64 --head N --out RECEIPT`
re-authenticates the complete drained state — every mailbox position staged
and applied through the scan, `outbox_head`, `control_head`, both queue
ledgers and the retained applied markers, including a reviewed digest list
for any bootstrap items via `--reviewed-bootstrap` — then produces a 650-byte
`VHCDRAIN` pause receipt committing room context, transition, generation,
namespace, endpoint commitment, profile binding, terminal head, items
commitment, both stream heads, the MLS image commitment and per-stream
accounting. The kernel retains the receipt as `NN.pause` and refuses all
publication (`publish` checks `delivery_is_paused`) until a successor is
selected. The receipt is private operator evidence of an exact drained state;
it is not a peer signature, not delivery proof, and authorizes nothing alone.

On the host, `private-host generation-check HOME --plan --receipts` validates
the complete controller inventory — every enrolled credential ID, including
revoked ones, mapped to a decoded receipt that matches the plan's context,
endpoint, profile and receipt commitments — plus the pinned expected head and
items commitment against the live mailbox. `generation-prepare` additionally
publishes the immutable intent, per-controller receipts and a
`generation.pending` marker that blocks `serve`. `generation-fence`
re-checks the head and writes the store's permanent fence and the exportable
`generation-N.fence.json`; `generation-cutover` verifies the exact fence,
seeds the successor mailbox (`FileStore::create_successor` bound to the fence
and intent digest) with the fenced credential-spend snapshot and the plan's
bounded allowances, and seals a version-3 selection that retains every
predecessor's namespace, mailbox, listener and credential IDs;
`generation-recover` finishes or re-checks that state without ever unfencing.

`delivery-transition ID STORE --config --successor --receipt --fence`
re-verifies the receipt against the predecessor's stored pause, ledger
snapshots and image commitment, checks the fence against the receipt and both
profiles, then writes the durable intent, seeds successor stores from the
receipt's accounting, atomically replaces the selected profile and records
the kernel `NN.selected` marker. `delivery-resume` re-arms stopped jobs under
the same profile while the driver is offline; `delivery-status` exports
per-stream queue state for the drain. `agent-serve` refuses a stale profile
copy before any network effect.

What each artifact does not prove is as specified in
[the transition contract](../../docs/private-rotation-contract.md): a relay
receipt proves only that opaque bytes were retained at a position; the fence
proves the predecessor closed at the exact expected head; the intent proves
the reviewed selection; none authorizes a successor by itself.

The shipped contract is same-host by construction. `validate_plan` refuses a
predecessor host on a non-loopback listener and requires a loopback
`successor_address`; `planned_selection` clones the predecessor config, so the
successor inherits the same CA, TLS name and credential identities and differs
only in namespace, mailbox directory and listen port. The member side
enforces the same boundary: `check_fence` requires the fence's single
`tls_name`/`ca_sha256` to equal both profiles' TLS identity. The shipped
contract's genuine degrees of freedom are therefore one machine, one host
identity, one credential basis, a fresh namespace and a fresh port.
`qualify_private_generation.py` proves exactly that shape: two native
controllers drain to a common head, both pause, the host fences and cuts
over, members transition to a changed address and namespace under unchanged
CA, TLS name and credentials, and the run asserts preserved spend, retained
predecessor reads and exact retries, no replay into the successor and clean
recovery. The 25 September two-Mac run moved no mailbox between machines —
its two rooms were separate — so cross-host continuation of one room is
unproven.

### The cross-host delta

A successor on a different host changes every field that identifies where and
how a member connects: the dial address, the TLS name, the CA, the relay
namespace, the derived endpoint commitment (`EndpointId::tls` binds address,
name, CA bytes and namespace; it deliberately excludes the token so rotation
cannot redirect queued work), the credential identity and token (credential
IDs are random per home — `private-host init` mints fresh ones), the host
identity itself (the successor home's sealed configuration and CA key live
under different custody, possibly on a different machine and a different
operator), and possibly the reachability path — a successor behind NAT
changes whether a member needs a Tailcat forward and which address it dials.

Stable across the move: the room scope, anchor, account and device context;
the MLS image commitment; the transition ID and the generation relationship;
the predecessor's terminal head, items commitment and fence commitment;
outbox and control ordering — the control stream remains a sequence domain
independent of mailbox positions; the pause receipt commitments; cumulative
per-stream accounting (outgoing/applied watermarks, retained jobs, canonical
bytes, charged attempts, outages, resumes, prior ledger commitment); and the
member's profile policy fields.

Invariants the model preserves: no replay of predecessor ciphertext into the
successor (a copied item is not an exact retry — its retention identity is
the original namespace and position); no fork — one successor namespace, one
reviewed descriptor, one generation; no duplicate application — the new
mailbox starts its scan at position zero because positions are
namespace-local, while application markers and kernel state continue
unchanged; no unjustified cursor advance — outgoing and control watermarks
begin exactly at the authenticated predecessor heads; no nonduplicate write
to the fenced predecessor ever; outgoing/control streams stay separated;
quota is cumulative — the successor mailbox opens with prior spend already
charged and any additional allowance explicit in the reviewed plan; and a
member updates its complete delivery profile — namespace, address, TLS name,
CA, endpoint commitment and token/capability — never just the address. The
predecessor host keeps serving its fenced mailbox read-only for history and
exact retries on its own saved port — which requires retaining at least one
active enrolled credential for that generation; the successor host serves
the new namespace on its own listener. The two homes share nothing but the
reviewed evidence package.

### The reviewed owner control

The authorization is a new owner control: one `ControlChange` variant — call
it `MailboxSuccessor` — inside the existing signed-and-encrypted control
machinery (`SignedOwnerControl` over `OwnerControlClaims`, KIND 4 records, a
new envelope kind beside 1–4). Like every control it is signed by the room's
pinned owner device, sequenced on the `parent` floor, bound to the room
scope, and carried under an MLS commit — an empty commit whose only effect
is the required epoch step; the change admits no device, moves no owner
authority and mutates no membership. Authentication, ordering, fork
detection and quarantine machinery are unchanged; the extension is
vocabulary only. Its payload binds, at minimum: the transition ID; the
predecessor and successor generation ordinals and namespaces; the expected
terminal head, items commitment and the exact fence commitment that may
exist — all computable at authoring time, since the fence commitment is a
pure function of transition, namespaces, head and items; the successor
endpoint descriptor — a bounded list of dial addresses with the TLS name and
CA digest, and the namespace-derived endpoint commitment; the successor host
commitment — the digest of the successor home's sealed configuration, which
pins its CA, name, credential identities and listener; the credential
mapping from each predecessor identity to a successor credential identity
plus the digest of each member's replacement token file; the per-credential
allowance additions (the same 4,096-item/256-MiB bounds); the controller
inventory digest; and freshness — the review timestamp and a not-after
expiry checked at transition time.

Ordering is constrained by two facts: publication refuses once a member is
paused, and a fence is terminal. The owner therefore authors the control
after the drain converges — when head, items commitment and fence commitment
are all predictable — and publishes it into the predecessor's control lane
as the terminal write. Members apply it like any control while still live,
drain it to the terminal head it named, and pause; the pause receipt's
`control_head` then proves the member had accepted the authorization before
it stopped mutating, and the fence's items commitment pins the control item
itself in the drained history. A binary too old to apply the kind fails its
drain and never pauses, so the transition stalls visibly instead of
producing a member that skipped the review.

`delivery-transition` gains the gate: in addition to today's receipt, fence
and profile checks it must find exactly one `MailboxSuccessor` control for
the transition in the member's retained control history at a floor at or
below the receipt's `control_head`, verify its owner-device signature
against the retained floor's owner set, confirm every bound field —
transition, generations, namespaces, head, items commitment, fence
commitment, endpoint descriptor, host commitment, this member's credential
mapping and token digest, allowances, inventory digest — and confirm the
successor profile's derived endpoint commitment appears in the reviewed
descriptor. The fence document gains `successor_tls_name`,
`successor_ca_sha256`, `successor_endpoint` and `successor_host` fields beside
the predecessor's, and `check_fence` compares next-profile identity against
the descriptor rather than requiring equality with the predecessor's. The
kernel's `NN.selected` then records the successor profile binding, which
already commits the new endpoint — the review decision, fence, receipt and
selected binding all chain to the same transition.

A relay retention receipt, a TLS handshake, a page response, an endpoint
announcement or the successor host's existence authorize nothing. Neither
does relay metadata about the successor namespace. The delivered token file
travels owner-privately like the invite bundle did; the control binds only
its digest, so the confidential channel never enters the signed artifact.

On the successor host, the owner-plus-successor-operator flow mirrors
check/prepare/fence: a new staged command — `generation-accept` — creates or
prepares the successor home under the plan's chosen namespace, enrolls the
mapped credential set with prior spend carried from an exported
fenced-spend snapshot, writes the seeded successor mailbox
(`create_successor` binds the imported fence and intent digests) and refuses
any deviation from the fence document. The predecessor home's `PENDING`
marker, sealed selection and recovery commands stay unchanged; the successor
home gets the same pending/exact-recover discipline on its side of the move.
The fence document, intent file, receipts and spend snapshot cross between
operators through the same owner-private channel as today's plan and
receipts.

### Failure and refusal model

Every case refuses safely, preserves predecessor and successor stores plus
all evidence, and reconciles from the durable intent — never by deleting or
recreating either generation, never unfencing, never unpausing, never
advancing a cursor on an ambiguous announcement.

- A member offline during the drain produces no receipt; the plan's complete
  inventory refuses and the whole transition stalls. Undrained or offline
  migration stays separate future work.
- A changed head after pauses: the conditional fence refuses; pauses and the
  pending plan stand; recovery is separately reviewed, as today.
- Host fenced but successor unreachable: a member's transition is local
  evidence-keeping — it may complete selection while the successor is down;
  resumption then retries the dead endpoint under the existing bounded
  retry policy, identical to an ordinary outage.
- An owner control that reached only some members cannot happen in-band —
  the drained terminal head includes the control item — and a member that
  retained but could not apply it never pauses, so the inventory blocks.
- A successor descriptor announced without the complete signed control —
  relay metadata, a TLS endpoint alone, an unsigned file — never advances
  anything: `delivery-transition` requires the applied control.
- Conflicting successor announcements: the transition refuses when more than
  one valid `MailboxSuccessor` names the same transition ID at or below the
  pause floor; precedence is never silently chosen.
- A stale control after a newer generation is selected fails its generation
  and transition binding.
- A copied old profile or receipt cannot select itself: the existing stale
  selection and active-profile guards apply unchanged.
- Wrong namespace, TLS name, CA, dial address, host commitment, fence,
  generation, room context, controller receipt, or a member credential
  mapping not in the reviewed map: each is an exact field comparison against
  the control, receipt and fence and each refuses.
- A quota mismatch or an attempted reset: successor stores seed from the
  receipt's accounting and the host seeds mapped spend from the exported
  snapshot; any deviation refuses.
- Crashes at each boundary — before/after the durable intent, before/after
  successor initialization, before/after the atomic profile selection — are
  recovered by rerunning the exact command, which reconciles the retained
  intent and refuses substitution, as the harness asserts today.
- A host restart mid-transition: `generation.pending` keeps `serve` refused
  until the exact fence/cutover or recover finishes, on both homes.
- A member that missed cutover entirely retains its paused predecessor
  profile; it reconciles by obtaining the reviewed control evidence and the
  fence and running the same transition — it cannot invent a successor.
- A botched authorized control discovered after the fence has no in-band
  correction path: the predecessor accepts no further items and paused
  members cannot apply a new control. This is the contract's hard edge —
  the authorization is the last reviewed act before fencing — and recovery
  is explicitly out of this contract, same as a post-pause head change.

### Test and qualification plan

Extend `qualify_private_generation.py` into a two-home shape — or a sibling
harness sharing its fixture — that runs two real `private-host` homes with
distinct CAs, TLS names, namespaces, credential sets and listeners; the full
drain including the published successor control; the predecessor fence; the
evidence package carried between homes as private files; `generation-accept`
seeding the second home with mapped credentials and carried spend; member
`delivery-transition` onto the new endpoint identity; `delivery-resume` and
fresh post-cutover delivery through the successor; predecessor reads and one
exact retained retry against the fenced mailbox; and the receipt-level
assertions already pinned (lineage rows, inherited ledgers, empty successor
queues, no replayed items, unchanged ciphertext). Negative cases: a forged
descriptor, a swapped CA or TLS name, a stale or second conflicting control,
a control for the wrong room, generation or transition, a missing token
digest, a quota reset attempt, each crash boundary on both homes and both
member sides, an offline member blocking the inventory, and the successor
host dead after the fence. Then the live gates, separately run and recorded:
a loopback multi-home run on one machine, a two-machine run over the LAN
listener and over a Tailcat forward pair — the Tailcat template forwards one
port per generation, so remote multi-generation routes need their own
reviewed configuration — and a member that joins the room only through the
successor. A local pass is not evidence of public-Internet operation, sleep,
logout or reboot recovery, Windows or Linux resource behaviour, or Tailcat
multiport forwarding; a real two-machine cross-host move is its own gate,
distinct from the 25 September separate-rooms run.

### Non-goals for step 8

Step 8 changes no kernel admission, MLS membership or custody rule, no
device key, ratchet or room state handling, no confidential offer, request,
accept or join machinery, no contact admission semantics, no offer
transport, no message encryption, no owner or device succession, no relay
retention semantics, no host quota bounds, no agent-grant authority and no
browser origin or custody semantics. The browser controller follows the same
contract: same gateway origin, a new retained route for the successor
upstream, an IndexedDB selector that commits the new binding, and the
unchanged cumulative attempt and byte ceilings. Kernel admission and custody
remain exactly as implemented.

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
- 25 September 2026, step 5 Tailcat overlay: #139 merged as `55451db`.
  `private-host tailcat-plist` emits a per-user systemd unit on Linux
  alongside the existing macOS plist: the same executable, saved-key and
  output custody checks, a distinct `.tailcat` label, a 30-second
  restart throttle and `StandardOutput=null` so the capability address
  cannot reach the journal. The unit path writes `ExecStart` literally
  and refuses rather than escapes a path that cannot appear there
  unambiguously, so a home containing whitespace or shell punctuation is
  refused on Linux where the plist's XML still carries it on macOS.
  Linux release packaging needed no new code: the release workflow
  already ships an `x86_64-unknown-linux-gnu` tarball and SHA-256
  manifest from the same validate-gated build as macOS. Still open for
  step 5: an operator-run install/status/uninstall journey on a real
  Linux machine.
- 25 September 2026, two-device live run (step 9 partial): one release
  build — sha256
  `569488144e9c441fe8312b0c16f31ed76b7b7786dbc1f9424bc55e3cc14277c6`,
  compiled at `ee94e18` — on two MacBooks, HRA2 (host, 172.16.16.153)
  and HRANESS1 (member, 172.16.16.155). The step-4 invite carried the
  member from bundle to admission request in one command per lane.
  A room served on the host's LAN listen address delivered a published
  message into the member's store about 0.7 seconds after the outbound
  page committed — inside the one-second arrival bound — and a second
  room reached the member through a Tailcat serve/forward pair in the
  same time, the member binding its forward to the advertised loopback
  port so the bundle's dial address resolved verbatim. Idle, the
  member's agent held exactly one page connection, matching the
  quiet-client shape the harness asserts. Host processes sampled 12.0
  to 12.3 MB RSS; the member agent 13.1 MB — the same private-store/MLS
  baseline noted under step 3, not a delivery regression. Two operator
  details surfaced: `accept` requires the member's declared validity
  window to sit inside the offer's own bounds, and one account identity
  serializes `agent-serve` runs (the docs' "one active custodian"
  wording). Retained receipts: `/private/tmp/vhalla-two-mac-live` on
  HRA2, `~/Documents/valhalla-live-20260925` on HRANESS1. Still open:
  the public-Internet lane, Windows and Linux resource numbers, sleep,
  logout and reboot recovery, and the sparse server soak.
- 25 September 2026, step 5 Linux operator journey and a Linux client
  lane (step 9 partial): a release build compiled at `8e6cb21` — the
  same tree as the two-Mac run plus the step-5 log merge — inside a
  real Linux machine, the Lima VM `hra-release` (Ubuntu 26.04 LTS,
  aarch64, four cores, 4 GiB). The host journey ran end to end under
  the systemd user manager: `private-host init` created the home once
  the binary and parent satisfied custody (the installer correctly
  refused a group-writable copy and a non-private location);
  `install` produced an enabled, active unit; `status --probe` reached
  the live TLS listener; `journalctl --user` showed no capability
  address; `tailcat-plist` emitted and activated the `.tailcat`
  overlay unit with `StandardOutput=null`; `uninstall` removed the
  unit while preserving the home. Settled RSS on Linux: host 15.9 MB
  (within the 16 MB budget after the initial 20.5 MB startup sample),
  Tailcat overlay 21.4 MB. For the client lane the VM joined a fresh
  room on the Mac host's LAN listener through the step-4 invite —
  `join --invite`, `accept`, `join --response` — and ran an
  outbound-only `agent-serve` with a finite grant; a published
  message was applied in the member store about 0.15 seconds after
  the outbound page committed, inside the one-second bound, over
  exactly one held page connection. The member agent sampled 19.4 MB
  RSS — above the 12 MB client budget and above the macOS figure,
  consistent with the private-store/MLS baseline being larger on
  Linux; the budget decision noted under step 3 now has Linux data.
  Two operational details surfaced: each `private` command mints its
  own fresh operation id (passing the invite's id to `accept` is a
  retained-operation `Conflict`), and `agent-serve` closes a grant
  on any detected wall-clock regression — a one-time NTP slew after
  VM provisioning killed the first grant; a fresh grant ran clean.
  Still open: the public-Internet lane, Windows, sleep/logout/reboot,
  the second-laptop browser route, and the sparse soak (the VM host
  and Tailcat units stay up as the soak pair). A second lane then put
  the mailbox itself on the VM: a fresh room on the same Mac owner used
  the VM's `private-host` as its mailbox, with the owner dialling
  through a `tailcat forward` into the serve unit — the NAT-behind-
  Linux-host case. The member VM imported, requested, was accepted and
  joined through the granular commands (the one-file invite reads the
  host's sealed home, so cross-machine owner/host pairs still onboard
  through `offer`/`import`/`request`/`accept`/`join` plus an
  out-of-band credential copy — worth a docs note). A published owner
  message reached the Linux host through the tunnel and was applied in
  the VM member's store about 0.33 seconds after the outbound page
  committed. Under that active delivery the host sampled 20.2 MB RSS
  — above its settled idle figure and the first honest look at the
  Linux host's loaded footprint; the 16 MB budget holds at idle and is
  crossed under load on this platform.
- 25 September 2026, step 10 public copy and release record (this change).
  The site's private-room page now describes the native-only deployment —
  one participant hosts the mailbox, every member dials out over pinned TLS,
  Tailcat only when the host sits behind NAT — the one-file invite and the
  same-machine browser gateway, and states the measured footprint (host about
  12 MB, member agent 13 to 14 MB, above the 12 MB client target) beside the
  unexercised public-Internet, Windows/Linux and sleep/reboot paths. The
  status and security pages name the two-Mac run instead of claiming
  independent machines are untested. The CLI README opens its private-room
  section with the same shape and links the operator guides.
  `docs/release-readiness.md` records the first published release per
  artifact: CLI and menubar at v0.1.0, the browser bundle at v0.2.1, the
  private commands first in published binaries at v0.2.1 (tag v0.2.0 exists
  but was never released), and Windows as unshipped; the listeners, invite,
  held page request and Linux units are recorded as merged but untagged.
  The site's documented source revision moved from v0.2.3 to `8e6cb21` so the
  linked source matches the described commands.
- 25 September 2026, step 6 custody portability (#145 on
  `claude/windows-custody-20260925`): `vhalla-custody` becomes a
  platform-neutral facade over `unix` and `windows` backends behind
  the unchanged contract — exclusive-create refuse-existing
  semantics, owner-only objects, link and reparse refusal, post-open
  identity, bounded reads and bounded lock retries. Ownership moves
  from a `u32` uid to an opaque `Owner`: the effective uid on Unix,
  the process token's user SID on Windows. The Windows backend
  builds each private object's descriptor from SDDL with a protected
  DACL holding exactly one ACE — full control for the object's
  owner — with the owner set explicitly so an elevated token cannot
  substitute Administrators, and refuses a NULL, absent, inherited
  or multi-ACE DACL the way `0600`/`0700` refuses a wider mode;
  SYSTEM and Administrators grants are deliberately not tolerated.
  Opens carry `FILE_FLAG_OPEN_REPARSE_POINT` (the `O_NOFOLLOW`
  role), directories open through `FILE_FLAG_BACKUP_SEMANTICS` so
  `sync_all` reaches `FlushFileBuffers`, and identity after open
  compares the volume serial and file index from
  `GetFileInformationByHandle` on two live handles — the NTFS
  analogue of `dev`/`ino`; FAT-family filesystems cannot satisfy the
  contract. `check_regular_file` gained a `path` parameter and
  `same_file`/`same_open_file` became public because Windows answers
  owner, DACL and link count only from a live handle; every custody
  caller — the stores, the CLI private-host and private-rooms paths,
  the private-native relay and grant code, and the public peer —
  moved to `Owner` in the same change, so no caller retains a raw
  uid. CI gains a `windows-portable` lane on `windows-latest` wired
  into `required`: custody clippy and its test suite, `cargo check
  --workspace` (every crate compile-checks for
  `x86_64-pc-windows-msvc`, verified locally — the Unix-gated store,
  peer and private-native modules compile empty), and test-target
  compile for the ten crates whose dev-dependencies are pure Rust.
  `cargo check` is compile coverage only: the CLI is not yet claimed
  to link on Windows, so no Windows release archive ships. Local
  gates: fmt, custody clippy on both targets, custody tests, and
  workspace clippy `--all-features --all-targets` all pass; the
  workspace test run still stops in
  `vhalla-identity/tests/custody_hegel.rs`'s
  `interleaved_faults_preserve_exact_open_and_sign_semantics` on a
  pre-existing model subtraction overflow reproduced on the clean
  parent tree — unrelated to this change. Still open for step 6: a
  `cargo build` link check and runtime tests for the CLI on
  `windows-latest`, a release archive once it links, and the Windows
  host service lifecycle.

- 25 September 2026, decisions from measurement: the client memory
  budget in decision 4 is revised from a flat 12 MB to the measured
  private-store/MLS process floor — a one-shot `private create`
  peaks at 13.0 MB on macOS before any delivery thread exists, and
  the idle `agent-serve` adds only 0.1 to 0.9 MB on top (13.1 to
  13.9 MB observed) — plus a 4 MB delivery-overhead allowance under
  a 24 MB absolute idle cap. On Linux the same floor lands at about
  19.4 MB, so the 12 MB figure was unreachable on either platform
  without redesigning the MLS/store baseline; the floor itself is
  the candidate for footprint work if it ever matters, not the
  delivery path. The host budget stays 16 MB but is now specified
  as settled idle, with a 32 MB loaded guardrail for transient
  delivery work (Linux host: 15.9 MB idle, 20.2 MB mid-delivery).
  Request budgets are unchanged: at most one relay request per
  minute at idle, sub-second arrival while active — both met (one
  held page connection, 0.15 to 0.7 second arrivals). Separately,
  the Hegel model flake that `vhalla-custody`'s CI run surfaced —
  `interleaved_faults_preserve_exact_open_and_sign_semantics`
  underflowing `bytes.len() - 1` when an earlier rewrite emptied the
  record — is fixed on the same day (#146): the tamper step appends
  one drawn byte to an emptied record instead of drawing an offset
  into nothing.
- 25 September 2026, step 7 — the second-laptop browser journey ran
  live between the two Macs over Tailcat. A fresh room (699b1d8f) was
  owned by the Mac A identity and a headed Chrome 153 instance on Mac B
  joined it: confidential offer and encrypted request crossed as
  bounded artifacts, the owner accepted, and the browser's device
  (1f84e669) joined at epoch 1. The browser reached its mailbox through
  its own loopback gateway on Mac B (`private-gateway serve` at the
  fixed origin http://127.0.0.1:8790, separate browser capability)
  whose upstream TLS went browser → gateway → `tailcat forward` 19473 →
  Mac A's tailcat serve → `private-host` on 127.0.0.1:9473 — the only
  reachable lane, since the host binds loopback. Bidirectional traffic
  was measured both ways: the browser's message arrived in the owner's
  CLI inbox (sender 1f84e669, sequence 1, alongside its admission
  control), and the owner's reply appeared in the browser inbox about
  two seconds after relay-push. The offline leg reaped Chrome cleanly;
  the gateway was then SIGTERM-drained and restarted under the same
  immutable configuration, and the reopened worker's connect-time
  stableSha256 equalled the last committed image across every restart
  — IndexedDB custody at an unchanged origin — with attempts and
  charged bytes carried (43→45). B's receipt:
  sha256 c78234490f32ab8a65ce6ab4fad992013267b78ff2c7843c48dc6f8d991c8f46;
  B evidence under
  `valhalla-qualification-20260923/browser-drive-20260925-r1/` and
  `two-mac-browser-20260925-r1/`; A evidence under
  `/private/tmp/vhalla-two-mac-live/browser-lane/`. One incident worth
  retaining as a custody proof: the driver's first run was killed at a
  session boundary mid-join; reopening the retained Chrome profile
  produced the identical account key, so the already-minted offer stayed
  valid and the run resumed — the model's resume-over-recreate rule
  worked under a real kill. Findings: (a) relay client ops require
  --tls-ca and --tls-name together with --addr/--token — omitting them
  silently selects raw TCP and the TLS listener's alert reads back as a
  "noncanonical frame" failure; (b) the installed v0.2.1 host, and even
  the newest tag v0.2.3, predate the bounded-wait page protocol (#136)
  and the whole current private-relay era (#115, #125) — no released
  binary can serve a current-main gateway, so the run substituted a
  source-built fixture host on the same port while preserving the
  personal home, which was restored afterward; the release-record needs
  a build that actually carries this protocol before public clients can
  rely on an installed host; (c) the PR-101-era browser worker
  occasionally never resolved a panel call under rapid scripted clicks
  (busy latch, 45-second deadline, no surfaced error) — retried with an
  action-aware wait, probe replays pass, worth a separate look.
  Outstanding: the sleep/logout/reboot journey and the sparse soak; the
  public-Internet lane still wants a genuinely public host.
