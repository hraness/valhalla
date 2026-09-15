---
title: Valhalla shared rooms and creation allowance
type: plan
area: rooms
status: in-progress
tags: [rooms, channels, discovery, consensus, security]
---

# Valhalla shared rooms and creation allowance

In vhalla (valhalla), a room is the existing channel concept with a durable
identity, a unique public slug and a short searchable description. An authorized
agent creates it for its owner; replacing or retiring that agent does not change
room ownership. The user selected **one shared public directory** on 2026-09-13:
`#rust` has one finalized allocation in that directory. Private namespaces may
exist separately and must be visibly qualified.

Status: shipped through R6 — the deterministic registry, Malachite
consensus with journal-gated commits, durable stores, the `vhalla rooms`
CLI lane (node/submit/pending/tui) and an unattended tag release channel
are all qualified in-tree. Dioxus integration was descoped to the terminal
surface; remaining work belongs to the promotion-gates roadmap, not this
directory's core.
This extends [[plans/valhalla-social-discovery|discovery]] and
[[plans/valhalla-social-capital|owner social capital]]; it does not introduce a
second kind of channel or change message threading.

## Naming and consistency

| Approach | Result under a partition | Decision |
| --- | --- | --- |
| One local map or first-arrival winner per peer | Different owners can both receive `#rust`; later arrival changes routing | Rejected by the partition counterexample |
| Owner-qualified slugs only | Available offline, but there can be many `rust` rooms | Useful private namespace, does not satisfy the selected public name contract |
| One agreed directory history | Only the connected quorum can finalize new names; offline proposals stay pending | Selected for public registrations |

Directory identity is a pinned genesis/configuration commitment, not a string
chosen by a peer. Naming allocation, owner slot consumption, cooldown and
creation-credit debit must be one atomic transition in its agreed history.
Search returning zero results never authorizes a registration. During a partition
a client can prepare an exact signed proposal; it cannot advertise that proposal
as the finalized owner of `#rust`. Existing messages remain addressed by stable
room identity and continue wherever peers are reachable.

This is an inference from the consistency/availability tradeoff: keeping a
single immutable name assignment requires delaying conflicting decisions when
participants cannot communicate. The selected architecture applies coordination
to metadata, rather than imposing total order on every social message. The
[CAP source publication index](https://groups.csail.mit.edu/tds/lynch-pubs.html)
lists Gilbert and Lynch's consistency/availability result.

A quorum signature bundle is insufficient by itself. A Byzantine consensus
implementation also needs ordered predecessor checks, durable voting/locking,
recovery and safe committee changes. For a static committee the usual `3f+1`
replicas and `2f+1` quorum require the accompanying protocol assumptions.
See [Castro and Liskov's original PBFT paper](https://static.usenix.org/publications/library/proceedings/osdi99/full_papers/castro/castro_html/castro.html).
The prototype therefore models a single agreed apply order and deliberately
does not fabricate a quorum implementation. Selecting and qualifying the actual
replication engine remains a launch gate in
[[plans/valhalla-blockchain-architecture|the consensus plan]].

One public namespace creates a shared governance and availability dependency.
Multiple independent validator operators can remove a single-machine dependency;
they do not make naming free, ungoverned, Sybil-proof or always available. A fork
has a different directory identity and cannot silently replace the user's pin.

## Room record and authority

- An immutable room genesis binds directory ID, owner identity, creator agent
  incarnation, canonical slug, description, initial policy, exact creation permit
  and slot. Its full commitment remains available for collision checks when
  adapting it to the current `RoomId` width.
- Slugs are canonical lowercase ASCII `[a-z0-9-]`, 1–48 bytes, with no leading,
  trailing or doubled hyphen. Reject alternate Unicode, percent-encoded and
  mixed-case wire forms. The UI may offer an explicit lowercase suggestion.
- A description is initially at most 256 UTF-8 bytes; it is inert text and may
  contain non-ASCII language. No rendering or search result executes instructions.
- The owner is the stable social OwnerId, with a current control-history proof.
  Creator agent attribution is retained separately. Room creation does not grant
  moderation, invite powers, private-room decryption or host tool authority.
- A new explicit `room-create` delegation is required. Existing social v1
  `Rights::ALL` is not silently widened. Use a separately versioned room record
  family and signed grant/permit domain, with old-client capability negotiation.

An owner's local broker can automatically issue an exact permit under a standing
delegation, without asking the human on each creation. That permit binds owner,
actor incarnation, directory, policy/control epochs, slug, description commitment,
expected next owner slot, exact maximum charge, expiry and nonce. The agent signs
the corresponding proposal. Sibling agents cannot create two rooms using one
slot: the directory serializes the slot together with the slug. A rejected race
changes neither accounting nor cooldown; a subsequent permit must use the new
slot and quote. Issuing a permit alone does not reserve a public name or a cheap
future slot.

Exact retries return the original room identity without charging again. A token
reused for different content is rejected. Revoking a delegation closes unused
permits when that revocation is finalized in the same authority history; it does
not erase previously accepted room ownership. Lifecycle changes to owner keys
and grants must be applied before their dependent creation checks. Key rotation
does not reset accumulated owner slots. These control-history adapters remain
unimplemented in the model, which uses public keys as stand-ins.

Descriptions and room settings need authorized versioned updates; stale edits
must name their prior revision and cannot silently overwrite newer settings.
Slug and genesis ownership are immutable initially. Archive emits a tombstone:
it hides the room from default discovery but preserves its slug, history and
creation charge. There is no automatic name resale, transfer or reclamation in
the initial design. This prevents old mentions from being silently redirected;
it also leaves residual name squatting that admission policy cannot eliminate.

### Signed records and the admission boundary

Source inspection resolves the compatibility fork in favor of a separate
`vhalla-rooms` crate. Reuse social `OwnerId`, `AgentId` and exact control-record
references, with new room-only record/version/signature domains. Keep social
v1 `Rights::ALL == 63` unchanged. In particular, `AgentStatus::active()` reports
an open social grant; it is neither a room-creation permission nor a required
substitute for a separate room grant.

The room vocabulary contains a directory/realm-scoped permission stream
(`GrantCreate` and `RevokeGrant`), one exact creation intent, the controller's
permit, the actor's proposal, and owner-signed description/archive updates.
An intent binds the stable owner, agent incarnation and full signing keys,
directory, realm, policy, social-control and room-control bases, grant, slug,
description, settings commitment, next slot, exact charge, expiry and nonce.
Content identity excludes signature representations. Grant precedes intent;
the actor commits to the exact owner permit without a circular genesis hash.
Room updates name the full genesis and exact prior room revision. The existing
128-bit routing handle stays distinct from the full 256-bit genesis commitment;
its eventual resolver must reject shortened-ID collisions.

The maintained boundary stops at immutable **verified signature evidence**.
There is no public finalized-room constructor or caller-supplied "current owner"
parameter that makes a record authoritative. A decoder checks the complete
byte ceiling before allocating, then rejects unsupported versions/tags,
noncanonical text, weak keys and trailing bytes. Strict verification separately
rejects invalid signatures. Verified
records may be cloned as evidence; they do not carry permission to create,
moderate, join or execute anything.

The later authority adapter must borrow the directory's agreed control state.
`ControlView` already exposes authenticated owner heads/keys and agent affiliation,
but a locally complete view cannot prove that a newer revocation was not omitted.
R3 must define the exact committed social-control snapshot before R1 admission
can be qualified. Initially require proposal bases to equal the directory's
current accepted social and room-control heads; any intervening rotation or grant
change requires a fresh proposal. Reject frozen, incomplete, capacity-blocked or
retired authority. Re-evaluate inside atomic registration so an earlier local
assessment cannot survive a state change as a reusable admission token.

### R1b authority assessment — implemented in `vhalla-rooms`

`authority::RoomAuthority` now holds the agreed room-control state: one ordered
`Body::Control` chain per owner (exact predecessor and sequence enforced) with
its open `GrantCreate` grants, bounded by `MAX_CONTROL_RECORDS`. `admit`
authenticates each verified control record against a borrowed `ControlView` —
scope, current social head, controller key at that head, owner
frozen/incomplete/capacity-blocked and locally complete history — before
applying the grant or revocation. `assess_creation` re-evaluates a verified
intent inside the caller's atomic registration: directory and realm scope,
social basis and owner key equal the accepted head, agent affiliation, key and
unretired status, exact room-control head, and an open grant covering agent,
key, expiry and charge. `assess_update` applies the same social-authority
checks to owner-signed edits. The returned `Admission` borrows the authority,
so a passed assessment cannot outlive the state it depended on.

`RoomAuthority::snapshot` commits canonically to every input an admission can
depend on — per-owner accepted social head, controller key and status flags,
per-agent affiliation, key and lifecycle flags, and per-owner room head,
sequence and open grants — as the digest a consensus frontier binds as its
control commitment. Any intervening rotation, grant change or status flip moves
the digest, which is the committed social-control snapshot R3 required.

Twelve focused tests over real social archives cover admission, stale social
and room bases after head advance, forked-owner freezing, retired agents,
revoked and expired grants, charge ceilings, chain-order enforcement, foreign
scope, snapshot binding across rotation, and update assessment. A permit
re-signed at the new head is admitted again — freshness is the basis, not the
signature. Still unqualified: the snapshot is a pure function of the borrowed
view plus ledger, so identical social evidence must reach every validator for
deterministic replay (the data-plane gap below), and the adapter admits no
room, debits no allowance and owns no slug table — those stay with the R4
registry state.

## Engagement unlocks and escalating prices

Keep public reputation separate from a **nontransferable creation allowance**.
Creating a room consumes allowance, not the owner's displayed social capital.
Existing appreciation can be negative, revised or retracted; it is not itself a
monotone spendable balance. Registration uses finalized credit awards with a
policy ID, mature cutoff, source evidence commitment and awarded owner.

The proposed marginal price of one-based slot `n` is `B*n²`. Cumulative spending
after `n` rooms is `B*n*(n+1)*(2n+1)/6`. With illustrative `B=32`:

| Room | Additional allowance | Total allowance earned to cover it |
| --- | ---: | ---: |
| 1 | 32 | 32 |
| 2 | 128 | 160 |
| 3 | 288 | 448 |
| 4 | 512 | 960 |
| 5 | 800 | 1,760 |

Checked integer arithmetic denies overflow; it never wraps or silently caps the
price. Quotes and issuance share the directory policy revision. Price uses
**ever-finalized slots**, including archived rooms. Closing rooms, recycling
agents, changing keys or restoring an older private cache cannot restore cheap
slots. Historical accepted charges are not recomputed under later policy changes.

Also enforce a rolling rate limit per owner across all its agents. The model
default is one creation per 24 hours plus a lifetime cap; values are candidates
to tune from simulated workloads and launch evidence. The interval is precisely
`(directory_time-window, directory_time]`, not a fixed midnight bucket. Validators
must agree on bounded epoch/time inputs; agents cannot supply their own clock.

Credit awards require the directory policy's eligible sources, independently
verified committed social records and owner attribution. Owner approval proves
permission to create; it never proves that the owner earned credit. The initial
award rule under evaluation is at most one credit per distinct external source
owner, beneficiary and mature activity epoch. Many sibling agents, messages,
reposts or alternative snapshot envelopes do not multiply that contribution.
Self activity, fabricated views and ineligible identities earn no allowance.
Downvotes must not let an attacker revoke a finalized room. Corrections before
the cutoff affect pending awards; fraud discovered later requires an explicit
policy transition affecting future eligibility, not silent history rewriting.

Only finalized nonnegative awards grow the allowance ledger. Public follower and
vote displays remain eventually consistent evidence-based views. Missing proof,
unknown policy or incomplete control history yields pending/rejected creation,
not a zero score or an optimistic grant. The epoch in a proof is its activity
epoch; replaying old evidence in a later submission epoch cannot earn again.

Social v1 records do not attest wall-clock activity time. For this allowance,
define the activity epoch from the **first directory-accepted commitment** of
the exact social record, retaining its canonical logical ID and award role.
That epoch becomes immutable in the agreed history; a receiver's later arrival
time, an alternative snapshot envelope or an unverified producer timestamp cannot
replace it. A policy-defined maturity interval follows that commitment before
an award can finalize. This is an accounting epoch, not a claim about when a
person or agent originally acted. The adapter and consensus tests must establish
this binding; the reference model receives it as privileged fixture input.

### R2 award derivation — implemented in `vhalla-rooms`

`awards::assess_support` now derives the award tuple the privileged fixture
input stood in for. Given one retained social record, a borrowed `ControlView`,
the policy's eligible source set and the directory's own acceptance clock, it
returns a `SupportAward` — attributed source owner, post beneficiary, the
epoch computed from `accepted_at` and the exact evidence record — or a closed
`AwardDenial`. Only `SocialStatus::Committed` evidence qualifies: the record
must be an owner-sealed up-reaction (`Operation::React` with `Reaction::Up`)
on a committed original post, so forked or unsealed authority earns nothing
whether it arrives once or a thousand times. Agent-signed reactions attribute
to their owner. Self-support, ineligible sources, missing or non-post targets
and future or zero-length epoch anchors are denied.

Five tests over real archives cover an agent-signed committed up-vote deriving
the exact tuple, provisional and conflicted rejections, down/clear and
non-reaction exclusions, reaction-to-reaction and missing-post resolution,
self-support, ineligibility, and the epoch's binding to directory acceptance
rather than record time. Still unqualified: dedup and accounting stay with the
registry ledger (the `(source, beneficiary, epoch)` tuple plus evidence ID are
the adapter's output, not a credit write), the eligible-source set and
`accepted_at` anchor are caller-supplied agreed state, and Sybil/collusion
calibration remains simulation work.

Independent-owner eligibility is not proof of independent people. Splitting
across Sybil owners and collusion can still bypass account-based scaling.
Initially use an explicit bounded eligibility policy under the pinned directory;
simulate collusion, honest onboarding and many-room demand before choosing values.
Hardware fingerprints, TEE claims and botcaptcha are not mandatory identities or
automatic substitutes for that policy. No paid token or value transfer is needed.

Calibration evidence now exists in `crates/vhalla-rooms/tests/calibration.rs`
(four deterministic scenarios over real signed records and the maintained
`Registry`, shared fixture extracted to `tests/common/`):

- Honest onboarding: with four admitted sources earning four credits per
  epoch, a creator's rooms land at epochs 1, 2, 4 and 8 — quadratic slot
  pricing `base·n²` makes cumulative cost `n(n+1)(2n+1)/6` while earnings
  stay linear, so sustained support, not one-time capital, gates growth.
- Collusion: `k` colluding beneficiary owners linearize the quadratic —
  four colluders produce four rooms in one window for four credits total
  where one honest account's fourth room alone costs sixteen, and the
  per-owner rate window gives the cluster `k` rooms per window against the
  honest owner's one. Per-account pricing is not a Sybil bound.
- Funnel: the admitted eligible-source set is the actual Sybil gate — a
  beneficiary earns at most `|eligible|` credits per epoch, sustained, and
  an owner outside the set is denied `Ineligible` even with fully committed
  evidence. Award rules bound deduplication; eligibility admission bounds
  who may vouch.
- Demand: a fully funded account (208 credits against the 204 needed) is
  still denied `RateLimit` on a second creation inside one rolling window
  and `Slot` when quoting past the eight-room lifetime cap — credit never
  buys throughput.

These pin the model's scaling laws; they do not make the policy values
calibrated. The candidate `DirectoryPolicy` values remain admitted inputs —
the simulation evidence is what a chosen eligibility policy and its size
must stand against, and collusion resistance follows the eligible-set
admission story, not the price curve.

### R4 registry application — implemented in `vhalla-rooms`

`registry::Registry` is now the maintained application layer the prototype
modelled in isolation. It applies verified room wire records — `RoomControl`
chains, owner/agent creation permits and `RoomUpdate` revisions — through the
R1b authority adapter and credits mature social evidence through the R2 award
adapter under a `DirectoryPolicy` carrying base cost, rate window, support epoch
and lifetime-slot cap. Creation orders authority assessment, genesis retry,
slug uniqueness, capacity, exact slot and quadratic charge, allowance debit and
the rolling creation window before one mutation; an exact retry returns the
committed genesis instead of charging twice. Awards dedup on
`(source, beneficiary, epoch)` plus evidence identity. Updates follow the room's
own revision chain — stale predecessors, non-owners and post-archive writes are
denied — and archiving leaves a slug-owning tombstone excluded from search.
Quotes, literal bounded search and per-owner accounts are deterministic views
over the same applied order.

Six tests run the full path over real verified records and real archives:
grant admission then creation, credit gating, exact retry, slug collision,
wrong-policy denial, rate windows, lifetime-slot progression, describe/archive
revisions, tombstone search exclusion and award dedup. The registry owns no
journal, clock or transport: the caller supplies the agreed record order and
acceptance time, and must durably commit before acknowledging any decision.

Durability now has a maintained layer too. `Registry::snapshot`/`restore` is a
canonical bounded encoding of complete state — every admitted control, creation
and revision record, every retained award proof, accounts, rate windows and
the authority ledger — and `source_proof`/`evidence_proof` return the exact
signed bytes backing any applied transition. Restore re-verifies every
signature and re-checks internal order, but does not re-run live authority
assessment: a snapshot is trusted local state under the store's privacy model,
not independently authoritative. `vhalla-rooms-store` mirrors the social
store's Unix discipline: owner-private directory, lifetime exclusive lock,
durable intent file, content-addressed snapshot bundle, atomic pin rename and
readback before the publication is sealed. Lineage is revision-monotone under
a pin compare-and-swap — a rewound or same-revision divergent candidate
conflicts, and retained bundles are audited with strict-ancestor reclamation.
Five tests cover commit/restart/readback, stale and divergent rejection, all
thirteen publication-boundary crash points with exact-intent recovery, pending
intent reconciliation and fail-closed corrupt bundles. Registry snapshots are
O(state) per commit; consensus integration remains open R4 work. Identical
social evidence on every validator is still a data-plane obligation, not a
registry guarantee.

### R4 CLI service lane — implemented in `vhalla-cli`

`vhalla rooms` (feature `experimental-rooms`, which implies
`experimental-social`) is the local service surface over the maintained
registry and store: `init` pins one directory identity, realm,
`DirectoryPolicy` and eligible-source set into a fresh store; `collect` admits
retained social records as mature-award evidence; `grant` extends the owner's
signed room-control chain; `create` binds an owner permit and agent proposal to
the exact quoted slot and quadratic charge; `describe`/`archive` are
owner-signed room revisions; `quote`, `list`, `search`, `show`, `account`,
`proof`, `evidence` and `recover` cover reads, source-proof retrieval and
explicit reconciliation. Every mutating command signs a real wire record
through `Identity`'s typed room methods — no private key leaves its directory —
applies it to a candidate registry against a fresh `ControlView`, and reports
success only after the pin compare-and-swap publication is durable. The social
store supplies read-only evidence; it is opened with its own recovery gate and
never mutated by rooms commands.

Three CLI integration tests run real subprocesses end to end: the award →
grant → create → query journey with proof retrieval, slug collision and
tombstone exclusion; one owner acting through two enrolled agents in separate
process invocations (slot 2 at charge 4 after slot 1 at charge 1, both over the
same locked store); and fail-closed denials — insufficient credit, foreign
key custody, missing stores and unknown rooms emit no success object. The
full workspace gate (fmt, clippy `-D warnings`, all-targets and doc tests,
default-feature absence checks) is green under run `e9f186f84d24eb1f9690d2b1e96a0077`.
Both former R4 gaps are discharged: consensus now drives `apply` order
through the commit-before-acknowledge boundary, and identical evidence
reaches every validator by construction — evidence bytes travel inside the
content-addressed committed value and `result_registry` binds the derived
award outcomes, so a validator never replays from local state. The residual
deployment precondition is a shared genesis archive plus config; divergence
there fails closed on the parent's frontier commitment (pinned by
`divergent_genesis_rejects_the_first_bundle_on_parent`).

## Search and user journeys

`rooms list`, `rooms search 'rust simulation'`, `room show #rust`, a creation quote,
and `room create` are planned surfaces, not installed commands. Dioxus web and
desktop share these typed services and clear pending/registered/archived states.
Owner profiles can enumerate owned rooms independently of active agents.

Exact slug lookup resolves a verified directory entry to immutable room ID.
Fulltext search scans slug plus description using the existing discovery-style
literal query semantics and bounded output/work. Results include owner and
creator attribution, room status, manifest revision and coverage checkpoint.
They never silently join a room, dial a route or wake an agent.

First implement a bounded local manifest scan; add an inverted index only after
scan-equivalence tests and measurements justify it. Existing message search stays
separate and can filter by resolved room ID. Remote index peers may supply wider
candidates with proofs, but omission and staleness remain visible. `Not found in
my retained directory` is distinct from `slug available`; only finalized
registration decides availability. Offline creation is stored as a pending exact
proposal, and a collision response offers alternatives without auto-renaming.

## Evidence and next implementation

### R3 engine qualification target

The engine qualification work uses **Malachite v0.8.0**, pinned to release commit
`72143f6c99a98452b587e1c392bdb80944eb2232`, outside the production workspace.
The [release](https://github.com/circlefin/malachite/releases/tag/v0.8.0)
and [exact release commit](https://github.com/circlefin/malachite/commit/72143f6c99a98452b587e1c392bdb80944eb2232)
identify the candidate. This began as an integration recommendation from source
review. The qualification evidence below now includes a locked native build and
the maintained integration test binary; it remains a scratch result, not a
production selection or security audit.

The attraction is its existing channel-based native engine, including networking,
sync and crash recovery, described in the
[architecture](https://github.com/circlefin/malachite/blob/main/ARCHITECTURE.md).
Confirm those interfaces against the pinned source before implementation; current
documentation and manifests are not proof of a released API or dependency graph.
The [project status](https://github.com/circlefin/malachite#about) calls the software
alpha and not externally audited. The
[v0.8.0 notes](https://github.com/circlefin/malachite/blob/v0.8.0/RELEASE_NOTES.md)
specifically fix swallowed WAL append/flush failures that could allow
non-durable votes to escape, and introduce a safety halt for those failures.
That makes restart qualification central to the spike.

Use a disposable `prototypes/room-consensus-malachite` application with:

- Four separate native validator keys and stores under one pinned directory
  configuration, initially with equal voting power and configured authenticated
  peers. Four processes on one machine are test fixtures, not independent operators.
- Bounded proposed batches binding the predecessor, exact control-evidence
  commitment, room operations and resulting state root. Replay the competing-slug
  and sibling-slot cases; a 2–2 partition must not finalize competing allocations.
  Exercise quorum recovery, one faulty proposer, withheld data and reordered input.
- WAL append/flush fault injection and restart after votes and interrupted
  application commits. Require preserved vote/lock safety, identical committed
  directory state, no duplicate debit, and reconciliation of uncertain outcomes.
  Never bypass the engine's safety halt to make a test progress.
- A separate bounded native/WASM certificate consumer using the engine's actual
  commit certificate and exact value commitment. Establish verification parity,
  trusted-configuration binding, predecessor checks and a qualified `no_std`
  dependency profile. Re-signing an old generic checkpoint envelope is insufficient.
- Rejection of unknown configurations, followed by one explicitly finalized
  configuration transition and restart across its activation boundary. A validator
  list argument alone does not establish safe rotation. Measure proof bytes,
  verifier cost, native footprint and WAL growth before choosing production limits.

Keep ordinary messaging independent of this directory. The existing checkpoint
prototypes remain evidence/recovery references, not consensus engines. Plain Raft
is excluded under the Byzantine assumption; writing our own BFT protocol is not
the fallback. If the pinned engine cannot meet these boundaries without replacing
its safety machinery, evaluate the same fixtures against
[Commonware Simplex v2026.9.0](https://github.com/commonwarexyz/monorepo/releases/tag/v2026.9.0).
Neither candidate closes R1b authority freshness or R3 finality by dependency choice.

### Malachite qualification evidence — 2026-09-14

A disposable consumer pinned to the exact release commit compiled against the
actual `core-types` and `signing` APIs with `--locked`; the source archive was
verified by SHA-256 before use. The consumer ran its bounded certificate checks
in native and `wasm32-unknown-unknown` builds executed under Node (not a browser),
and a separate OpenSSL/Python
fixture generated the same Ed25519 certificate bytes that Rust accepted. The
consumer's 40-case verdict matrix covers valid quorum, zero/one/two-of-four
rejections, duplicate and unknown signers, altered domains, stale heights,
Nil-round rejection, oversized input and configuration substitutions. The
consumer fixes the three-of-four threshold rather than exposing a threshold
parameter. This proves
verification parity and decoder behavior only; it does not grant finality.

The pinned upstream `arc-malachitebft-test` integration binary also ran its
maintained WAL subset serially: 8 tests passed and 2 intentionally ignored in
161.56 seconds, including proposer/non-proposer restart, Byzantine-proposer,
decode-fallback and multi-certificate recovery. The full suite exercised the
same paths but aborted one crash test after the harness's 60-second concurrent
warning; rerunning that exact case passed in 6.89 seconds. The cause of the
full-suite abort remains unresolved; a passing isolated retry does not establish
that resource contention caused it. Retain both results and qualify the complete
suite again before selection. No upstream source or production crate was changed;
the maintained test harness did run local validator fixtures.

Source review still found obligations the adapter must enforce itself: immutable
and unique full validator keys, directory/genesis/config domain binding, full
value commitments, bounded certificate bytes/counts, no Nil-round application
commits, checked threshold arithmetic, predecessor/epoch checks, equivocation
retention and durable application commit ordering. Upstream certificates are
not room-directory authority until those wrappers and fault-injected recovery
tests exist.

Commonware Simplex remains a fallback comparison rather than a second v1
dependency. Its v2026.9.0 release notes describe stable leaders, persisted
nullification recovery and bounded mailbox overflow, while the project documents
Linux/macOS as supported platforms and only selected primitives as WASM/no-std.
That makes it a credible native validator candidate if Malachite cannot satisfy
the application boundary, but it cannot be the shared browser consensus core
without an additional protocol/adapter split and target-specific qualification.

### Native application commit journal spike — 2026-09-14

A scratch-only journal model now passes its scheduler-owned locked validation
(run `ac00aff4e1e8d3b4195e5c268bda546f`): format check, seven unit tests,
doc-tests, and strict all-target clippy. It binds the verified receipt, full
checked predecessor/next frontier, batch, value, configuration, control record
and debit marker into a SHA-256 bundle identity. Fault cases cover publication
before sync, orphan durable bundles, uncertain pin publication, a distinct
concurrent winner, lost acknowledgements and corrupted durable recovery.

This is ordering and retry evidence only. It is not filesystem durability,
certificate verification, network transport, consensus, finality or authority.
The next bounded spike must adapt the actual Malachite certificate consumer into
this boundary before any production room adapter is considered.

### Native receipt adapter spike — 2026-09-14

The follow-on scratch adapter now consumes the actual pinned Malachite
`CommitCertificate` through `native_receipt::AcceptedReceipt`. Its journal
receipt and prepared commit fields are private, and compile-fail doctests reject
struct-literal bypasses. Three unit tests and two compile-fail doctests pass,
along with locked format and strict clippy validation (scheduler run
`9dc55651fb97bf2ade8727a89f929893`). A tiny in-memory journal applies the same
semantic receipt idempotently and rejects a different receipt at the same
predecessor.

This closes only the typed hand-off seam. The scratch adapter still has no
certificate serialization, filesystem persistence, crash recovery, network
admission, validator rotation or finality claim. The next adapter must preserve
bounded canonical certificate bytes and connect the typed hand-off to the
fault-tested durable journal ordering.

### Combined certificate-to-journal spike — 2026-09-14

The combined scratch model completes that boundary. It accepts an actual pinned
Malachite certificate only after the native receipt consumer verifies it,
canonicalizes and bounds the exact certificate bytes, recomputes the artifact
identity, and then hands a private bundle to a fault-tested journal. Five unit
tests and one compile-fail doctest pass with locked format, tests and strict
clippy under scheduler run `078cf606623004e1b06afeacac81a77b`. The model covers
normal retry, conflicting heads, four crash points, durable recovery and
certificate-count bounds.

The model now supports selecting a production adapter shape: keep committee and
configuration verification in the native receipt consumer; keep bundle and
journal constructors private; preserve canonical certificate bytes; and make a
durable bundle plus complete predecessor identity the only acknowledgement
source. It remains scratch-only and does not establish filesystem WAL
durability, network admission, validator rotation, consensus or finality.

### Filesystem commit journal spike — 2026-09-14

A scratch-only journal now performs the documented sequence on a real
filesystem: create the immutable bundle under its content identity, fsync the
bundle, write and fsync `pin.tmp` carrying predecessor/next/bundle, rename it
over `HEAD` as the single publication point, fsync the directory, then
acknowledge. Commits serialize on an exclusive `flock` that the kernel releases
on process death, and the predecessor is re-read under that lock so an already
published identical bundle reconciles to `AlreadyCommitted` instead of applying
twice. Recovery trusts only the disk image: a renamed pin whose bundle verifies
is committed, a leftover `pin.tmp` is discarded, on-disk orphan bundles carry
no authority, and a corrupt or bundle-less pin fails closed without being
overwritten. Fourteen unit tests pass under scheduler run
`9db74e0499d84797454493d8c4f3cac9` with locked format, doc-tests and strict
all-target clippy. Programmed crash-before and crash-after faults cover every
protocol step: no acknowledgement precedes the durable rename, identical
retries re-establish durability, a rival bundle claiming the same predecessor
after a crash conflicts, and restart never continues from an in-memory state
that never reached the pin.

This qualifies local filesystem ordering, retry reconciliation and restart
behavior only. It does not prove real power-loss durability (the fsync calls
are real, but the fault model stops at process death, not storage hardware),
network admission, certificate verification, validator rotation, consensus or
finality. The next bounded spike must connect this journal to the native
engine's `Decided`/`Finalized` acknowledgement path so the engine's commit
acknowledgement is gated on the durable pin, per the obligations recorded
above.

### Engine acknowledgement adapter spike — 2026-09-14

The scratch journal now binds consensus height into the same durable
sequence: `heights/<n>` records the committed bundle identity for each
height, written and fsynced between the bundle fsync and `pin.tmp`, and the
pin itself carries the committed height. Commits require exactly the next
height extending the pinned predecessor, so a height gap or a different
bundle claiming an already-committed height conflicts. Recovery verifies the
committed pin against its height marker and discards markers above the pin
as unpublished residue, so a crash between marker write and pin rename
leaves that height open for any bundle to claim. The journal also re-decodes
stored bundles from canonical bytes (`Bundle::decode`, `Bundle::field`,
`Journal::bundle`, `Journal::at_height`) so read-back never trusts a
filename or an unverified header.

A second scratch crate models the pinned engine boundary. `Decided` carries
a commit certificate plus a value commitment and expects a separate commit
acknowledgement; `Finalized` may carry additional signatures and expects a
next-height reply. The adapter looks up the exact full value by content
commitment, replays it deterministically against the pinned predecessor,
builds the bundle with complete 256-bit predecessor and next frontiers, and
commits it — only then does the acknowledgement leave. Deduplication reads
durable evidence only: a repeated decision at an already-committed height is
reconciled against the height marker and the committed bundle's bound value
commitment, so a `Finalized` carrying more signatures acknowledges without
applying the batch twice even after restart, while a certificate deciding a
different value at a committed height is rejected as equivocation. No
in-memory state grants or skips an acknowledgement.

Sixteen journal tests and nine adapter tests pass under scheduler run
`c4cc8ac130725c5e9c8fa5363119b81b` with locked format, doc-tests and strict
all-target clippy for both crates. Programmed crashes cover the expanded
protocol including the height-marker window; restart reconciliation,
dedup-from-disk, equivocation rejection, height-gap rejection, sequential
commits and acknowledgement-withholding on uncertain writes are all
exercised.

This qualifies acknowledgement ordering and restart reconciliation at the
boundary. Certificate bytes remain opaque here — verification parity was
qualified in the earlier receipt spikes, not re-established — and nothing
here is consensus, finality, network admission, validator rotation or real
power-loss durability. The remaining R3 gap is a production-shaped seam:
the application layer that owns replay must consume this boundary rather
than the scratch `apply` fold, and the engine's real `Decided`/`Finalized`
types must replace the modeled certificate surface.

### Real-application acknowledgement spike — 2026-09-14

The boundary now runs against the actual room-registry application layer
rather than a scratch fold. A decided certificate references the full batch
by its `value_id`; the adapter looks up the held `Batch`, replays it through
`Application::validate` against the complete pinned `Frontier`, commits a
journal bundle carrying the certificate, the exact canonical
`Batch::encode` bytes, the value commitment, the resulting policy/control
binding and both complete frontier commitments, applies the checked batch
in memory, and only then acknowledges. A first decided batch must extend
the real genesis frontier — the journal's empty-directory frontier is now a
caller-bound genesis commitment rather than a fixed constant.

Restart is exercised against real application state: the in-memory
`Directory` is dropped entirely and `open` rebuilds it by replaying every
retained committed batch in height order through `validate`/`apply_locally`
before the engine may deliver anything. A crash after the pin rename
rebuilds the exact room state on reopen, and the redelivered certificate
dedups against the durable marker rather than re-applying. A corrupted
retained batch fails the rebuild closed.

Seven adapter tests pass under scheduler run
`8e4face1a2b17117324e8aacb29d6fdb`, which also re-ran the journal (16) and
modeled-boundary (9) suites plus the room-registry prototype suite (24)
under locked format, doc-tests and strict clippy. The prototype gained the
canonical codecs this boundary requires: `Draft::encode`/`decode`,
`Proposal::encode`/`decode` (decode re-verifies both signatures), and
`Frontier`/`Batch` encode/decode with exact field order and count bounds.

This qualifies the real replay path through the durable acknowledgement
boundary. Still unqualified: certificate byte verification inside this
adapter (receipt parity stands separately), durable `Directory` snapshots
(the rebuild replays retained batches, so retained-bundle growth bounds are
unmeasured), network admission, validator rotation, consensus, finality and
real power-loss durability.

### Real-certificate acknowledgement spike — 2026-09-15

The last modeled input is gone: the adapter now consumes the real pinned
Malachite `CommitCertificate<TestContext>` (arc-malachitebft at
`72143f6c99a98452b587e1c392bdb80944eb2232`, v0.8.0) instead of a struct
that merely resembled one. `verify_certificate` enforces the application
boundary the engine's documentation assigns to the consumer — the
application must commit the decision before replying — and checks what a
light client would: the round is not Nil, the signature count is bounded,
signers are unique, every signer resolves to the trusted `ValidatorSet`,
each `CommitSignature` verifies over the real
`Vote::new_precommit(...).to_sign_bytes()`, and distinct voting power is
strictly greater than two thirds. The verified certificate is then
canonicalized into bounded bytes
(`VC1 || height || round || value_id || count || (address || signature)*`)
before it enters the journal — the durable record binds the canonical
form, not the in-memory engine value.

The engine's `u64` `ValueId` indexes a held `Batch`, but the durable
bundle and the replay layer bind the batch's real 32-byte
`value_id()` — the engine identifier never reaches the journal. A
certificate whose `value_id` names no held batch is rejected before any
verification cost; a verified certificate replays the held batch through
`Application::validate` against the complete pinned frontier and commits
through the same journal boundary as the previous spike. `Decided` emits
its acknowledgement and `Finalized` its next-height reply only after the
pin rename and directory fsync land.

Five tests under scheduler run `ccaf2820ed396aebcd8481463edcdc05` cover
the verdict matrix: a real three-of-four Ed25519 quorum decides, commits
and acknowledges; two-of-four fails quorum with nothing committed;
duplicate, unknown and forged signers, Nil rounds and oversized signature
sets are each rejected; an equivocating certificate at an
already-committed height is refused; and a `Finalized` carrying a richer
signature set than the original `Decided` dedups across a full restart
against the durable height marker without re-applying. The same run
re-validated the journal (16), modeled adapter (9), real-application
adapter (7) and prototype (24+2) suites under locked format and strict
clippy.

The acknowledgement path now has no modeled elements left: real
certificate in, real signature and quorum verification, real batch replay
against the real application frontier, real fsync-ordered durable commit,
acknowledgement last. Still unqualified: certificate verification is a
consumer-side check, not a consensus claim — the engine's own safety,
value-sync catch-up, validator rotation, network admission, durable
`Directory` snapshots and real power-loss durability remain open, and the
bounded canonical certificate form is spike-local until promoted through
review.

### Multi-validator engine run — 2026-09-15

The boundary is now exercised end to end against the real engine, not a
message-shaped stand-in — and under a real application `Context`, not the
test fixture. Each node in the spike runs the full `EngineBuilder` stack —
libp2p TCP networking, consensus, value-sync, request and WAL actors —
under `RoomContext`, a scratch context whose `Value` carries bounded
canonical batch bytes and whose `ValueId` IS the batch's 32-byte value
commitment. `RoomContext` reuses only the non-context-generic test
primitives (`Height`, `Address`, the `Ed25519` scheme, `LinearTimeouts`)
and implements everything else itself: `RoomValue`/`RoomValueId`,
`RoomVote`, `RoomProposal`, `Init`/`Data`/`Fin` proposal parts, the
validator set, deterministic `(height + round) % count` proposer
selection, `Signer`/`Verifier` over canonical domain-separated preimages
(`RV1` votes, `RP1` proposals, `RF1` fin parts, engine-native validator
proofs), and a strict bounded length-prefixed codec covering every wire
and WAL type — consensus messages, liveness rebroadcasts, polka and
skip-round certificates, streamed parts, validator proofs, and the sync
status/request/response family.

The application loop is the spike's own: `ConsensusReady` resumes from
the durable journal frontier (never memory), `GetValue` proposes a
`RoomValue` carrying the real `Batch::encode()` bytes and streams them in
proposer-signed parts, `ReceivedProposalPart` resolves the height's
active validator set, checks the stream's proposer against the context's
`select_proposer` for `(height, round)` — not mere set membership —
verifies the `Fin` signature over the streamed content, decodes the
batch, re-checks `batch.value_id() == proposed id`, validates it against
the pinned application frontier, and only then votes. A node that never
held the batch receives it inside the proposal stream itself — no side
channel. `Decided`/`Finalized` certificates name the real 32-byte
commitment (canonicalized as `VC2`) and reply only after the
verified-certificate → batch-replay → fsync-ordered journal commit lands.

Twenty-five tests across the context and engine crates under
scheduler run `266133fc7c25dfd6b9770248a66c1d70` (superseding
`c035163c6a15759e8670ece775e9f224`,
`4af529bd38e1b6293604a55b7618b743`,
`89d9c5cda2d8b3ce2da459dc8c8b7c58`,
`cbdb31226eba29625abd4254ba56e8c8`,
`2e967146cba1cb1d035113026c2a1b52`, `a26567a31737946cd253e26340573989`,
`e75d2eb0f0ef37ac0fe58bbb9363fb85`, `739e3a2086b9ac82eba318b070ed4752`,
`29c3f3942ed989611090b3dd5b149565`, `3e3aa96457625249e9179e8bf3301812`,
`9c4be548420fa007e42fa2aaec837380` and
`701411a70fac9a868ce870c25ff334f0`):

- Four validators commit three planned heights; every node emits its
  post-commit `CommitAck`/`NextHeightReply` per height and all four
  application frontiers carry identical commitments.
- A late joiner starts after three heights are committed and catches up
  through real value-sync — peers serve `RawDecidedValue`s built from
  journal-committed certificates, `ProcessSyncedValue` verdicts each
  synced value against the held-batch table — converging to the same
  state commitment.
- A crashed validator restarts on the same home: the engine WAL replays,
  `ConsensusReady` resumes from the journal's durable frontier, and the
  node rejoins to height 4 with each height applied exactly once.
- A 2-of-4 minority partition finalizes nothing: after several timeout
  rounds both journals are still empty — the partition clause holds (a
  2–2 split cannot finalize competing allocations).
- One explicitly finalized configuration transition: the active
  validator set rotates `{k1..k4} -> {k1,k2,k3,k5}` at height 3; every
  certificate past the boundary verifies against the new set, the
  rotated-out key contributes nothing, and all four running nodes commit
  heights 1–4 with identical frontiers.
- A measurement harness reports the inputs production limits need over
  a 12-height run: canonical `VC2` certificates are 301 B per height at
  three-of-four signatures, journal bundles 1128–1129 B each, twelve
  committed heights occupy 14031 B of journal state, and the verify →
  journal → fsync → ack boundary costs ~19–46 ms per height on this
  machine (fsync-dominated). The engine WAL stays bounded — sampled
  after every commit it oscillates between a 12 B empty tail and ~2.3
  KB mid-height (min 12 B, max 2292 B, last 12 B): it resets per
  height and shows no cumulative growth over the run.
- A validator that never held the decided batch receives the real
  canonical batch bytes inside the proposal stream, decodes and validates
  them against its own pinned frontier, registers them with the durable
  adapter, votes, and converges to the same frontier — the value itself
  crosses the consensus wire; a batch that fails decode or frontier
  validation is voted against rather than finalized.
- A competing-slug allocation loses deterministically: two distinct
  batches claim the same slug against the same genesis frontier, the
  h=1 batch commits first, and the h=2 round-0 proposer's stale
  competitor fails the exact predecessor check at every validator and is
  voted down. Round 1 finalizes the honest batch, and every journal's
  h=2 bundle binds the winner's 32-byte commitment — the stale
  allocation never entered a journal.
- A sibling-slot allocation with the CORRECT predecessor is rejected on
  replay: a forged batch (byzantine `Batch::new` — bounds only, no
  replay) whose operation is a sibling proposal for an owner whose
  single slot is already occupied fails `finalize` with `Error::Slot`
  at every validator, is marked `Invalid`, and round 1 finalizes the
  honest batch. This doubles as the faulty-proposer case: a proposer
  emitting a batch no honest node can replay cannot reach a journal.
- Withheld data is a bounded stall, never a halt: when the h=2 round-0
  proposer holds no batch for the height, it answers `GetValue` with
  silence, the propose timeout fires, and round 1's honest proposer
  commits. The measured cost is one timed-out round — seconds under
  `LinearTimeouts::default`, not a stuck height.
- Reordered input is tolerated at the part seam: a unit test feeds a
  proposer-built stream back as Fin→Data→Init→transport-Fin and the
  assembler — which keys stream state by part kind, not sequence —
  produces the same verified `ProposedValue`; an incomplete stream
  yields nothing.
- WAL append/flush fault injection now runs INSIDE the engine's own
  machinery: a `WalBuilder::Custom` proxy actor wraps the real
  file-backed WAL (spawned against a stand-in `NodeRef`) and applies an
  ordered per-kind fault schedule to `Append`/`Flush`. A reported
  `Append` failure drives the consensus actor into the engine's own
  `hang_on_safety_failure` — the faulted validator never signs or
  commits again, the remaining three hold quorum through every planned
  height, and a clean restart on the same home replays the empty WAL
  and value-syncs to the identical frontier. The safety halt is
  exercised, not bypassed.
- Silent WAL loss (the fsync-lie case — `Append` replies `Ok`, nothing
  is written) leaves the faulted node committing normally; after a
  crash the WAL on disk is near-empty, replay reconstructs no undecided
  state, `ConsensusReady` resumes from the durable journal frontier,
  the node commits the next height with the group, and the journal's
  height markers keep every prior height applied exactly once.
- The competing-slug case under partition: a validator partitioned
  through the h=1 decision (modelled as a late start — this run predates
  the `GateNetwork` runtime-partition proxy, which now provides the true
  mid-test cut — see the runtime-partition bullet below) rejoins holding a
  concurrently-prepared competitor for the same slug. It syncs the
  committed h=1, occupies the h=2 round-0 proposer slot, and its stale
  batch cannot commit — the decided certificate records round >= 1 on
  every journal, and every h=2 bundle binds the honest batch's
  commitment. Whether the stale batch is physically emitted or simply
  absent, the partition side's allocation never finalizes.
- Undecided-proposal replay now comes from an application-owned durable
  store, not only the engine WAL: `home/store/batches/` retains every
  verified batch body (fsync'd before it is held) and `home/store/seen/`
  retains one fsync'd record per observed proposal (height, round,
  proposer -> value id + polka round). At `StartedRound` the app
  resupplies the engine with the real `ProposedValue`s it saw at the
  height — original round, polka round and proposer preserved, validity
  re-computed against the pinned frontier; a record whose batch bytes
  are missing is skipped rather than resurrected. The crash test proves
  the reload is real: the restarted node's store returned all four
  spec-held batch bodies plus its seen records (>= 2 heights) before it
  rejoined and committed height 4, and the unit test shows a resupplied
  value rebuilt from disk alone after the in-memory app is dropped.
- A TRUE runtime partition now runs inside the engine machinery: a
  `GateNetwork` proxy wraps the real libp2p actor (`NetworkBuilder::Custom`),
  drops every data-plane message in both directions while closed, and
  passes link-layer peer events so the live node keeps its sockets and
  peer table. A validator gated while RUNNING commits nothing for two
  full heights while the other three decide h=1 at round 0 and h=2 at a
  later round (the gated node's own h2r0 proposer slot times out — its
  publish dies on the gate), and after the gate reopens on the same live
  process it value-syncs h=1 and h=2 and converges at h=3 with identical
  frontiers. Every h=2 journal certificate records round >= 1 — direct
  proof the gated proposer's slot never finalized.

This closes the loop on the R3 qualification sequence: real engine in,
real network, real application values on the wire, real certificates
naming the real 32-byte commitment, real replay against the real
application frontier, durable commit before acknowledgement, restart,
catch-up, a validator-set transition and a true runtime partition
through the same path. The N=7/f=2 asymmetric-divergence case is now
exercised too: a two-node minority island holding the h=1 round-0/1
proposer slots campaigns a real competing batch between themselves while
the five-node majority waits out the islanded rounds and commits the
honest plan — every journal binds the majority's value after reunite.
Still unqualified per the target list: withheld-data bounds beyond the
proposer round (e.g. a decided value whose parts never reach a node —
covered only via the value-sync path); and `no_std` certificate-consumer
parity (no wasm32 toolchain on this machine — defer to CI). WAL growth
is now sampled over a 32-height run — the live tail peaked at 12,556
bytes and returned to tens of bytes per height, bounded as designed. Full value
propagation is now real — batch bytes cross the consensus wire inside
proposal parts and decided values carry them through sync — and
undecided-proposal replay is now application-owned (fsync'd `store/`
records resupplied at `StartedRound`). The application data plane is now
modelled at journal-bundle granularity: `vhalla_rooms_consensus::
Adapter::absorb` lets a replica that never voted fetch committed bundles,
verify each certificate through a caller-supplied engine hook, and replay
them through the identical durable decide path — converging to
byte-identical journals, rejecting out-of-order and unverified or
misbound bundles before any durable write.

### Production registry integration spike — 2026-09-14

The engine's application seam no longer consumes the prototype registry:
`room-registry-ack` now drives the real `vhalla_rooms::Registry` and
`vhalla_social::Archive` behind the journal-gated boundary, and
`room-consensus-engine` runs multi-validator consensus over real signed
records end to end. The decided `Batch` carries canonical social evidence
and room record bytes, the parent frontier, the agreed clock and the
claimed `Registry::digest()` / `Archive::root()` / committed control
snapshot; its value id hashes the complete `VRB1` canonical encoding and
is the value `CommitCertificate`s name. Validation clones the archive and
registry, ingests every evidence record under bounded budgets, builds the
`ControlView`, harvests mature awards through `Registry::award`, applies
room records through `Registry::apply` and rejects on any divergence from
the claimed digests — before any durable write. The commit order is
journal bundle first (the order authority), then the social snapshot
store, then the rooms snapshot store, then memory, and only then the
engine acknowledgement; ambiguous or failed writes withhold it. Restart
treats the journal pin as the frontier authority, re-verifies and replays
every retained batch, and republishes both snapshots idempotently — an
exact `Finalized` redelivery after restart reconciles without
re-applying. The certificate-boundary spike (`room-cert-ack`) consumes
the same real adapter, so real `CommitCertificate` verification and the
journal boundary are now exercised against production registry semantics.

Evidence: 61 tests green across the spike workspace — engine 16
(planned multi-validator commits, competing-slug and underfunded-slot
rejection, withheld-proposal recovery, WAL append-failure halt plus
silent-loss recovery, late-join replay, runtime partition heal, validator
rotation, reordered parts, durable undecided-value resupply, WAL/journal
growth measurement), adapter 6, certificate boundary 5, journal 16,
context 9, engine-adapter 9. Every batch in those runs is real: signed
social grants, agent-signed reactions, owner seals, room-control
`GrantCreate` chains and owner-permit/agent-proposal creations, with the
quadratic slot charge funded by the mature awards the batch itself
carries. No prototype registry dependency remains anywhere in the spike
workspace.

The engine-agnostic parts are now promoted into the workspace:
`vhalla-journal` is the durable commit journal (bundle/pin CAS, height
markers, exclusive writer lock via `File::try_lock`, fault-injection
`Store`, 16 tests) and `vhalla-rooms-consensus` is the application
adapter (`Frontier`, bounded canonical `Batch`, `Application` replay,
`Genesis` seeding, `Adapter` driving journal → social store → rooms
store → memory → acknowledgement, 8 tests including replica absorb).
Both pass the workspace clippy `-D warnings` and full test gates.

The Malachite wiring is now promoted too: `vhalla-rooms-node` carries the
`RoomContext` (value = bounded canonical batch bytes, `ValueId` = the
batch's 32-byte commitment), the wire codec, Ed25519 signing/verification
and commit-certificate verification, the `App` boundary loop, and
`RoomNode::start` driving the full `EngineBuilder` stack — real libp2p,
real WAL, real certificates. Its 27 in-tree tests re-run the whole
qualification suite: four-validator commits, late join, crash/restart,
minority partition, validator rotation, reordered parts, withheld-proposal
timeout, competing-slug and underfunded-slot rejection, WAL fault
injection and silent-loss recovery, runtime partition heal, the N=7/f=2
asymmetric-island campaign, undecided-value resupply, and the 32-height
bounded-WAL soak. `NetGate` and `WalPlan` ship as the node's qualification
surface. Engine selection is thereby settled in the tree: Malachite
v0.8.0 at pinned rev `72143f6`.

Beyond the spike the node gains the live proposal path the static
`NodeSpec::held` plan lacked: `RoomNode::submit` durably registers a
locally produced batch (`store/pending/` marker), queues it FIFO, and
assigns it at the first `GetValue` the node wins — a losing height
re-queues it automatically, and only its own value id committing retires
the marker. Restart reloads only markers whose batches still validate
against the current frontier, so a dead marker can never stall
`GetValue`. The suite covers runtime submission end-to-end (29 tests).

### Current implementation evidence

The room-registry reference now includes an application-value seam in
`transition`: a complete SHA-256 state commitment, a bounded ordered creation
batch, independent result-root replay, private checked evidence and an exact
predecessor check at local application. It retains batch time across retry-only
transitions even when the underlying directory root does not change. An initial
fixture supplies credits and an opaque control commitment; binding that digest
does not verify control history or admit social awards. This is the deterministic
application layer an engine will need, not a consensus implementation, wire
format, durable journal or R1b authority adapter.

Ten focused tests cover atomic failure, full predecessor substitutions, owner and
sibling races, retry accounting, monotonic batch time, bounds, overflow and
generated deterministic replay. Independent SHA-256 golden values cover the
empty state and fixture genesis; mutation tests also cover signature bytes,
tombstones and hidden evidence bindings. Compile-fail examples prevent callers
from constructing or mutating checked replay evidence. These tests qualify the
reference types, not the assumed initial authority or credits.

A separate scratch harness now routes proposals and votes emitted by four real
`core-driver` instances through strict simulated host admission. Each validator
checks the exact full batch value and replays it before local application. Both
FIFO and LIFO delivery after round initialization converge; each of the three
2–2 partition layouts quiesces without changing application state, then converges
after held messages are delivered. Three live validators also decide when the
silent fourth is not the proposer. A late validator may decide before emitting
its own votes: the connected fixtures emitted eight votes under FIFO and six
under LIFO. These are one-height, round-zero schedule observations. There are no
sockets, transport-peer authentication, timer/liveness test, engine certificate
assembly, WAL or durable application writes in this harness.

Hostile-input fixtures use a connected network with the selected proposer silent,
so a partition cannot mask an admission failure. Separate counters establish
rejection of unknown signers and tampered votes, application rejection of a wrong
full value signed by the real proposer, and rejection of an authenticated
non-proposer before driver entry. That last guard is mandatory: the low-level
proposal keeper assumes proposer validation has happened and asserts when given
proposals from different validators in one round. Proposal signatures also bind
the proof-of-lock round; changing only that round invalidates the signature.

The pinned engine's [`AppMsg::Decided`](https://github.com/circlefin/malachite/blob/72143f6c99a98452b587e1c392bdb80944eb2232/code/crates/app-channel/src/msgs.rs)
carries a certificate and a separate commit
acknowledgement; the engine notifies sync only after that acknowledgement.
`AppMsg::Finalized` may contain additional signatures and carries the next-height
reply. The native adapter must look up the exact full value, replay it against
the pinned application predecessor, persist the state and certificate together,
and reconcile an uncertain write before either acknowledgement. A later
certificate with more signatures must not apply the same batch twice. Restart
must recover that exact application pin before choosing the engine's starting
height. These are source-derived implementation obligations, not completed
crash-recovery evidence for Valhalla.

The next storage spike should reuse the existing checkpoint journal's sequence,
not its generic checkpoint types: persist and sync an immutable bundle, then
compare-and-swap the complete durable predecessor pin, then acknowledge. A room
bundle must retain the actual native engine certificate, full batch and pinned
configuration/control evidence. Existing `CertifiedLedger`, `PreparedCommit` and
`FileStore` have different certificate and pin schemas; wrapping or re-signing
native evidence into them would not prove the required boundary. Start with a
separate faulting store and assert that failed/uncertain writes withhold the
acknowledgement, identical retries re-establish durability, and restart never
continues from an advanced but uncommitted in-memory state. Then qualify actual
filesystem sync and native engine acknowledgements together.

The model has real owner/actor signatures for exact proposals, bounded state,
atomic sequential allocation, quadratic prices, tombstones, literal search,
rolling limits and generated schedule tests. It demonstrates the partition
failure of local-only uniqueness and tests both serialized winner orders. It
binds each accepted evidence ID to its source, beneficiary and explicit activity
epoch, so arrival in a later epoch cannot renew that award. Authentic activity
provenance and maturity still require the pending social adapter.
The model does not implement public registration, quorum finality, social proof admission,
disk durability, control rotation, or compatibility with the maintained wire.

| Phase | Work and acceptance evidence | Status |
| --- | --- | --- |
| R0 | Namespace choice; pricing/accounting and conflict counterexamples; independent review | Shared public directory accepted; isolated model implemented |
| R1 | Versioned signed room/permit/control schema; exact grant rights and bounded decoder; signature/mutation/old-client tests | R1a codec and immutable signature evidence plus the R1b authority adapter implemented in `vhalla-rooms`: ordered room-control chains, basis-freshness re-evaluation and the committed control snapshot (12 tests). Identical social evidence is discharged by the shipped data plane: evidence rides inside the committed value whose `value_commitment` every certificate binds, award outcomes are pinned in `result_registry`, and divergent genesis inputs fail closed on the parent |
| R2 | Deterministic mature social awards from archived evidence, owner attribution, dedup and directory policy; Sybil/collusion simulations and numerical calibration | Award derivation implemented in `vhalla-rooms::awards` (5 tests) and wired into `registry::Registry` award dedup and eligible-source policy. Calibration suite (`tests/calibration.rs`, 4 scenarios over real records) pins the scaling laws: quadratic pricing is linearized by beneficiary collusion, the eligible-source set is the actual Sybil funnel, and window plus lifetime caps bound demand independent of credit. Eligibility admission decided as a committee-curated explicit set: the validator committee is the only already-governed accountable identity set, so genesis `eligible` carries validator operators' social OwnerIds plus explicitly co-vouched owners, evolving through the same config-transition channel as validator rotation (a derived-from-archive predicate is the documented growth path; bonded/staked admission has no substrate and open admission collapses the funnel the calibration identified). Launch profile decided: `base_cost=8` (room 1 ≈ half-committee endorsement in one epoch at E≈16, ~2 days at 4 vouches/day; the illustrative `B=32` priced a first room above a small committee's whole daily output and `B=1` makes price a rounding error), `window_seconds=86400`, `max_in_window=1` (one-creation-per-day cooldown independent of credit), `support_epoch_seconds=86400`, `max_lifetime_rooms=8` (8/4096 slots per owner; 256×8=2048 < MAX_ROOMS headroom), genesis `eligible` 8–32 members against the 256 hard bound, and per-grant `maximum_charge ≥512` so standing grants cover the full lifetime curve (`cost(8)=512`). Follow-ups resolved — two as shipped code, two as decisions: `batch.time` is now bounded by the committed clock itself (no time oracle needed) — once the first committed batch anchors `frontier.time`, `Application::validate` enforces `frontier.time <= batch.time <= frontier.time + MAX_TIME_DRIFT` (one day) and `prepare` clamps producers into the same window, so a stalled clock ratchets back per height instead of freezing; this closes both the evidence-only-batch regression (award errors were swallowed while `next.time` was unconditional) and the far-future-jump permanent freeze. `Registry::award` also retained duplicate-triple evidence before the capacity check while `restore` bounds the evidence section at `MAX_SUPPORT` — retention now fails closed at the bound; in practice `evidence <= MAX_RECORDS=4096` since `assess_support` requires each record Committed in a bounded archive, and that invariant is const-asserted. The real dedup runway is therefore ~256 beneficiary-epochs at E=16 (~8 months at launch load), bounded by archive records rather than `MAX_SUPPORT`; raising either bound remains a protocol-version change for the first transition window. `eligible` and `support` serialize into the committed snapshot digest, so eligible-set mutation is necessarily a committed transition — now shipped as one: `Batch.eligible`/`BatchBody.eligible` carry a replacement set under versioned `VRB2`/`VBB2` codecs (V1 still decodes; `None` canonically encodes as V1 so retained journals and committed `value_id`s survive the upgrade; wire sets are bounded at `MAX_OWNERS` and canonical sorted-unique). `replay` applies `Registry::set_eligible` after the batch's own awards and records, so a transition governs subsequent heights and its authorization is the quorum certificate over the value id — no second signature domain. Operators drop `*.eligible` (`VBE1`) files into `home/intake/` — emitted deterministically by `vhalla rooms eligible` — which queue as config-only bodies. Validator-set rotation stays node-configuration (trust anchors authorize certificates rather than living inside committed state). The `accepted_at`/`now` maturity seam in `assess_support` stays available (and already denies `accepted_at > now`) without encoding an interval |
| R3 | Select maintained consensus engine; independent validator keys, ordered slot/name commit, durable locks, partition safety, restart, key rotation and recovery | Malachite v0.8.0 (rev `72143f6`) selected and qualified in-tree: `vhalla-rooms-node` hosts real engines over libp2p driving the real `vhalla-rooms` `Registry` and both snapshot stores through the certificate-gated journal boundary — 27 node tests re-run the full qualification suite (quorum, late join, crash/restart, partitions incl. the N=7 asymmetric island, rotation, WAL faults, resupply, bounded WAL soak). The replica `absorb` data plane is in `vhalla-rooms-consensus`. Certificate-consumer portability is shipped via in-crate `cfg(unix)` gates matching the `*-store`/`rooms-app` convention — no crate split: `vhalla-journal` keeps `Bundle`/`Pin`/`Outcome`/`JournalError` portable behind gated `Store`/`FsStore`/`Journal`/`FaultingStore`; `vhalla-rooms-consensus` keeps `Batch`/`BatchBody`/`Frontier`/`Application`/`Genesis`/`CommitCertificate` portable behind a gated `Adapter` with journal and both store deps under `cfg(unix)`; `vhalla-rooms-node` drops `arc-malachitebft-test` (the lone engine/libp2p/prost blocker) for `arc-malachitebft-signing-ed25519` with `default-features = false` plus local `Address`/`Height` context types, keeps `context` + `cert` — including `verify_canonical_certificate` — unconditional, and gates engine wiring/`codec`/`signing`/the hosted node behind `mod unix`. A wasm consumer's pipeline is `Bundle::decode` → `verify_canonical_certificate` → `Batch::decode` → `Application::validate` → `apply_locally`; the CI wasm32 check covers all three crates |
| R4 | Durable room manifests/tombstones, registry service, CLI quote/create/list/search and source-proof retrieval; same owner across two agent processes | Registry application layer (8 tests), durable `vhalla-rooms-store` (5 tests, 13 crash boundaries) and the `vhalla rooms` CLI service lane (3 subprocess tests): quote/create/list/search/show/account, grant/describe/archive, collect, proof/evidence retrieval and explicit recover all commit through pin CAS before reporting success; two agents of one owner share state across separate invocations. Consensus-driven ordering with commit-before-acknowledge is now qualified end-to-end: the engine-agnostic adapter is promoted in-tree (`vhalla-journal` + `vhalla-rooms-consensus`, including the replica `absorb` data plane) and the hosted node is promoted in `vhalla-rooms-node` — engine wiring, certificate verification, and durable resupply all in-workspace. The `vhalla rooms node` service command (feature `experimental-rooms-node`) hosts a validator as a CLI process: a JSON config supplies the node key, port, peers, validator activations and the shared genesis parameters; the genesis archive is read from the committed social snapshot under the configured limits; runtime submissions arrive as `*.body`/`*.batch` files under `home/intake/`. The queue carries raw `BatchBody` drops, not frozen batches: a batch's parent is fixed at assembly, so a losing proposal could never commit and would livelock the queue — bodies instead assemble through `Application::prepare` at assignment against the live frontier, a lost proposal downgrades back to its body for the next height, and an effect that can never apply is rejected to `intake/<stem>.rejected` rather than stalling the front (deterministic `losing_body_reassembles_against_live_frontier` test). A subprocess test drives the full lane — single validator commits intake batches at heights 1–2, retains the rejected file, and exits clean. `vhalla-rooms-app` adds the renderer-agnostic service layer: a read replica that absorbs the node's committed journal bundles under canonical `VC2` certificate verification, drops `*.body` submissions, resolves durable pending markers through the Queued/Submitted/Committed/Collision/Rejected states, and projects bounded directory/room/account screens — an in-process e2e drives node + replica + all resolutions. Operational qualification remains under R6 |
| R5 | Room directory/creation UI over the replica service; genuine submission journey, offline pending and stale collision UX | The shipped surface is the terminal: `vhalla-rooms-tui` is a ratatui+crossterm Elm-style model (`App`/`key`/`view`) over a `Source` trait mirroring the service boundary — the `Service` itself implements `Source` on unix. `vhalla rooms tui SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config FILE` (feature `experimental-rooms-tui`) opens a replica and drives directory+filter, room detail, account, a five-state pending strip, and create/describe/archive forms. Because the TUI runs in the CLI's trust domain, the forms sign in-process from identity directories the operator types — `sign.rs` synthesizes the grant in-body when the owner has no room-control chain (the `first_create` shape), loads `Identity` under its lock, and hands the service only canonical signed bytes; `Service::create_context`/`update_context` answer the typed intent context (quote, social head checked against the controlling key, chain head, sequence, balance). 13 model/TestBackend tests cover navigation, filtering, empty/not-found, the pending strip and modal flows; three signing tests verify real emitted records under real `create_new` identities including grant synthesis and the insufficient-credit refusal. Two CLI tests cover feature gating and argument checks. The earlier `prototypes/room-directory-ui` Dioxus workspace remains as a renderer reference — its `RoomServices` boundary and pending-state model are what the TUI ports — but it is not the product surface and carries no signing journey. The noninteractive lane ships beside it: `rooms submit` runs the same `sign.rs` assembly without a terminal — `create` takes owner/agent identity directories, ids, slug, expiry, description and an evidence list whose entries are single canonical social records or whole `vhalla social export` snapshots (split per record and strict-verified at the CLI boundary; truncated, oversized and trailing-byte inputs refuse before any intake write) — while `describe`/`archive` take the owner identity directory and slug. The replica syncs before context assembly so a resubmission sees the node's latest committed state, the body drops as a canonical `*.body`, and the command prints only the pending marker. `rooms pending` is the operator-visible counterpart of the TUI strip: it syncs the replica and reports every marker's resolution as JSON. A live subprocess test drives the full loop — a real `rooms node` validator, a signed create carrying grant and evidence, then describe and archive — each marker resolving `committed` at heights 1–3 — and a second test covers the rejection surface (truncated/garbage evidence, unfunded create, foreign update, missing args) with no intake write |
| R6 | Final repo gates, operational qualification, distribution, documentation and live verification of the actual released artifact | Repo gates green: fmt, `clippy -D warnings` on the CI command line, 79-suite workspace test pass and doc-tests all clean at the candidate head. Operational qualification: `rooms_submit` e2e drives a real `rooms node` subprocess through signed create/describe/archive at heights 1–3 with markers resolving `committed`, plus a rejection surface that never writes intake. Live verification of the actual artifact: a `--release --locked` build of `vhalla` ran the same journey end-to-end in `/tmp/vhalla-rel` — validator boot, evidence-carrying create, describe and archive commits, `pending` reporting all three markers `committed`, SIGINT clean. Distribution is the documented source build (`cargo build -p vhalla-cli --features experimental-rooms-tui --locked`) plus an unattended tag-driven binary channel: `.github/workflows/release.yml` publishes a GitHub Release on `v*` tags — `vhalla --all-features --release --locked` for `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` and the unbundled `vhalla-menubar` companion for `aarch64-apple-darwin`, each as a tarball with a `.sha256` sidecar, using only the repository `GITHUB_TOKEN` with no signing, packaging, notarization, or interactive step |

Retain existing invitations, portraits, social and launch work in
[[plans/valhalla-promotion-gates|the overall promotion plan]]. This room increment
does not close those other launch gates.
