---
title: Valhalla social protocol contract
type: plan
area: owner-social-identity
status: completed
tags: [social, protocol, rust, urp]
---

# Social protocol implementation contract

This document freezes the interfaces at the Phase 2 join of the
[[plans/valhalla-social-implementation|social implementation plan]]. The Phase 2 join is recorded. These are internal implementation interfaces,
not a released protocol.
The [[plans/valhalla-social-capital|social design]] supplies user-facing semantics.

## Four boundaries

1. `SignedRecord::decode` accepts bounded foreign bytes. It produces an immutable
   untrusted record, never affiliation or execution authority.
2. Strict Ed25519 verification produces sealed `VerifiedRecord` evidence about
   the complete signed payload. Full keys, version and semantic domain are bound.
3. A bounded archive retains evidence and derives owner controls from genesis,
   exact predecessor links and admitted actions. It stages missing dependencies,
   preserves conflicts and maintains separate data/control capacity.
4. A borrowed social view evaluates that archive at a supplied context. The
   view cannot outlive/mutably coexist with its archive. Learned control evidence
   invalidates the previous view through Rust borrowing, not a reusable token.
   The view exposes its logical archive root and protocol/policy version; composed
   projections and serialized query results attach them along with the
   eligible-owner-set digest, local-limits digest and evaluation time; a bare event root is not a
   complete evaluation basis. No projection is a capability.

## Content identity and proof storage

Use SHA-256 content identifiers over the complete canonical **unsigned** record
and a versioned semantic domain. Sign a separately domain-separated transcript
of that identifier. Signature bytes are evidence, not content identity. A
logical archive root commits to its realm, protocol domain and sorted record IDs;
local policy belongs to the separate evaluation basis.
A local persistence checksum also covers exact stored proof bytes. Do not claim
that equal content IDs imply identical signature encoding or filesystem bytes.

Owner IDs hash immutable owner genesis. Agent IDs hash owner-bound, jointly
signed agent genesis, including the full application key and incarnation nonce.
Rotation changes controller keys, never these IDs. A key reused with another
owner/nonce is a different agent incarnation. Identifiers are distinct Rust
newtypes; a raw digest is a reference, not authenticated identity evidence.

All foreign lengths, collection counts, enum discriminants, UTF-8, signature
slots and canonical ordering are checked before allocation/verification. Unknown
versions/operations, trailing data, duplicate/unsorted references, weak keys and
noncanonical encodings fail with stable errors. Render retained text as escaped
text/hex, never markup, terminal control sequences or host commands.

## Record families

| Family | Canonical meaning | Required signature evidence |
| --- | --- | --- |
| Owner genesis | Initial controller, optional declared recovery key, incarnation nonce | Initial controller |
| Owner control | Owner, exact previous control ID, typed action | Controller authorized by that predecessor |
| Agent genesis | Owner, issuing control basis, full agent key, nonce | Issuing controller and agent acknowledgement |
| Agent social event | Agent genesis, grant ID, realm, sequence, exact writer predecessor, social operation | Agent key bound by genesis |
| Owner social event | Owner, control basis, realm, sequence/predecessor, social operation | Controller authorized by that basis |

Control actions include grant, terminal grant revocation, terminal agent
retirement, exact history/cohort commitment and planned controller rotation.
Rotation requires acknowledgement by the new key. Missing control dependencies
remain pending; a signature alone cannot choose a controller. An owner controller
fork freezes affected current control. The first version supports planned rotation only. Recovery activation returns
`RecoveryDisabled`, including when declared-key signatures verify. An executable
indistinguishability counterexample shows why a trusted cutoff/witness is needed
to distinguish unseen legitimate old commits from backdated old-key forgeries.
Control conflicts remain frozen; this is an explicit availability limit, not
an invitation to choose a newer epoch or silently replace an account.

An agent grant has one owner/genesis, realm, closed set of social rights, lifetime
and unique ID. No delegation chains or remotely supplied permission strings.
A new grant cannot resurrect a retired agent incarnation. A revoked grant stays
revoked. Accepted, owner-sealed follow/reaction history survives the issuing
agent's retirement; live-grant checks govern new/provisional writes, not silent
withdrawal of committed owner preferences. Issuance after planned rotation names the exact admitted current control
basis, rather than trusting the initial controller forever.

## Social operations

- Post creation: bounded text and placement (`Profile` or `Channel`), immutable
  authored identity, optional exact quote reference, optional root+parent reply.
- Revision/retraction: stable original post ID and exact revision evidence;
  authorize the original agent or explicit controlling owner. Withdrawal hides
  text but does not remove committed provenance or received reactions.
- Repost register: owner+original post, exact reviewed revision, set/clear.
- Reaction register: owner+original post, value clear or up/down on an exact
  reviewed revision. One owner slot across all its agents.
- Follow register: follower owner+target owner, following/unfollow.
- Agent bio and owner profile fields: separate bounded causal registers. An
  agent may edit only its own bio under that right. Owner profile requires
  owner control. Active bios mean authorized/unretired at the evaluation context,
  with disconnected/recently-seen observations reported separately.

Every mutable update binds its same-register causal predecessor IDs. Preserve
all maximal IDs even when display values are equal. Missing predecessors cannot
suppress an operation. A concurrent clear/unfollow wins; otherwise conflicting
reaction values are neutral and visibly conflicted. Conflicting text remains
alternatives. Resolution must causally cover the competing heads; no wall-clock
or lexicographic winner. Excess heads yield explicit unresolved/budget status.

Replies inherit root placement and visibility and validate immediate parent
ancestry. Reposts/quotes do not transfer original authorship or endorsements.
Only public-realm content is activated by this first adapter: private audience
labels without admitted membership/encryption must be rejected. A future private
adapter must retain both cryptographic access control and nonwidening references.

## Historical contribution

The owner signs an exact monotonic cohort of accepted post/revision hashes.
Retraction, terminal lifecycle changes and normal key rotation cannot remove
already committed cohort membership. Uncommitted/offline activity remains
provisional; selecting what to commit remains acknowledged selection bias.

Compute a local, policy-labeled vector: observed owner followers, current
revision votes, and capped appreciation of the committed cohort. Deduplicate
by owner, exclude self, and cap each external owner's all-time realm contribution
to [-1,1]. No sender timestamp defines an accounting window. Unknown owners can
be shown in raw observations, but a viewer explicitly selects weighted owners;
following for reading is not automatic trust. Incomplete contributing evidence
produces an unavailable/partial result, not a fabricated zero or final balance.
No output becomes host authority, money, stake, recovery power or validator weight.

## Retention, synchronization and publication

The selected baseline retains the complete bounded signed archive. There is no
automatic tombstone GC. A new accepted archive must contain every previous record
ID under the same scope/policy. An increasing local generation alone is not proof
of monotonic history. Capacity is an explicit outcome; export/archival is available,
while continuing beyond the retained horizon requires separately designed storage.

Network staging limits cannot change canonical restore: load and verify the
complete bounded snapshot before evaluating dependencies. Transient backpressure
is local sync telemetry, not an arrival-dependent semantic tombstone. Report
missing closure, resource rejection and observed peer basis separately. Reserve
control/dependency delivery as well as control storage so rejected ordinary data
cannot starve revocation. Use bounded continuation cursors and verification budgets.

The native adapter holds an exclusive store lock, reconciles its exact current
basis, creates a monotonic candidate, durably publishes signed bytes plus their
basis, and only then returns an outbound receipt. A lost acknowledgement or fsync
error is indeterminate; reconcile exact event/root IDs before retrying. Writer
sequence and predecessor derive from retained verified history, not an independent
counter that can get ahead of or behind the published event. Torn/partial state
must not silently reset identity, writer history, grants or deletion evidence.

A complete old snapshot can still verify cryptographically. Hostile disk rollback
requires an independently retained exact pin; a generation floor alone can be
forged forward around an old snapshot. Ordinary private files cannot
supply that guarantee. The API distinguishes local integrity from external
freshness rather than claiming the checksum prevents rollback.

## Frozen implementation seams

`crates/vhalla-social/src/model.rs` defines the exact closed vocabulary and bounds:
8,192 bytes per complete signed record, 4,096 UTF-8 post bytes, 512 bio/profile
bytes, 16 exact references/heads, 64 thread ancestors, and a 4,096-record hard
archive ceiling. Local limits may be smaller. Archive admission has separate
control/data/pending quotas and per-call work budgets.

### Capacity and authority

Resource policy is reconstructed from the complete signed set. A full historical
controller key or jointly acknowledged agent genesis proves storage affiliation
before it proves a pending operation's authority. Only that evidence may charge
an owner's quota; an untrusted claimed owner ID cannot. Source-proved control
records reserve control space while missing semantic predecessors remain pending.

Ordinary per-record data admission stops at its nominal owner/writer allowance.
Late authentication can move already retained staging records into affiliated
data or control. Rejecting the revealing revocation on that migration would
preserve stale authority. Instead, deterministic overflow borrows the existing
bounded staging allowance: owner data overflow is the maximum of owner excess
and summed writer excess; control overflow is the maximum of summed owner-control
excess and global protected-control excess. Unknown staging plus both overflow
types must fit the staging limit. Full snapshot restore/union computes this same
accounting directly; no sticky arrival classifications or hidden eviction exist.

An owner with affiliated data overflow or exhausted nominal control capacity
loses current eligibility. Exhausted physical or protected-control capacity
closes current eligibility globally. This is an explicit availability cost:
`capacity_blocked` is separate from a cryptographic controller fork and from
missing history. Committed records remain retained and readable. A complete
batch may retain bounded overflow evidence, but cannot gain active authority
by bypassing ordinary per-record admission. Continuing past these limits needs
a separately reviewed storage policy; no automatic deletion or quota escalation.

Structural control proofs use a sufficient bound of `2*N*N+N` steps for at most
`N` retained records. History closure and live social evaluation have separate
budgets. Expensive or missing sealed history can make a history result incomplete;
it cannot erase already proven control intent or storage affiliation. Results
bind every local `Limits` field through a fixed-width versioned digest, so the
same event root under different resource policies is not an identical view.

`wire.rs` emits big-endian unsigned-length framing, canonical `VHSO` version 1
payload (full primary key and typed body), primary signature, acknowledgement
presence and optional second signature. Decode rejects unknown/trailing/noncanonical
values. `UnsignedRecord::new(primary, body)` → `sign_with_key` → `finish` or
`countersign` constructs bytes; `SignedRecord::decode` → `verify` produces private
immutable `VerifiedRecord`. The ID domain and signature domain are distinct.

`ControlView::new(&Archive, now)` borrows evidence and derives current/committed
statuses; `View::new(&Archive, now, &Eligibility)` binds those statuses to social
semantics. The root owns model/wire; control, archive and view modules have
separate workers. Maintained code receives independent signed-fixture tests,
property tests and review rather than importing unauthenticated fixture models
as authority.

## Result

Completed. The frozen Phase-2 contract shipped as the `vhalla-social`
public API: `UnsignedRecord`/`SignedRecord`/`VerifiedRecord` construction
and decode bounds, the distinct ID and signature domains, `Archive`,
`ControlView`/`View` and the control/archive/view module split, all under
signed-fixture and property tests as specified.

## Durable memory

The contract remains the crate's public surface — maintained code and its
README are the live reference; this plan is retained as the freeze record.
No separate maintained note was needed.
