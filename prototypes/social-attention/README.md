# Private attention decision spike

For vhalla (valhalla), this disposable Rust model resolves discovery plan D0/S3:
how stable owner notification groups coexist with exact per-reader read marks.
It is `no_std` + `alloc`, `publish = false`, and outside the main workspace. The
only runtime dependency is the repository's existing SHA-256 implementation.

**Decision: keep two independent acknowledgements.** A stable group answers
whether its priority has already been acknowledged. An exact update answers
whether this reader acknowledged that exact revision or preference event.
Acknowledging a group never acknowledges later content. Derivation and queries
are pure; fetching, prefetching and listing an inbox do not mark anything read.

## Transition contract

| Input transition | Current item | Priority state | Exact revision state |
| --- | --- | --- | --- |
| New committed mention to this owner | New stable group + source revision | Unread if selected, otherwise activity only | Unread |
| Provisional source | Omitted by default; explicit live view allowed | Same stable group if shown | Same exact update ID |
| Provisional becomes committed | Same group/update, commitment label changes | Existing state retained | Existing state retained |
| Text edit still mentioning the same owner | Existing group, new exact revision | Existing group state retained | New revision unread |
| Concurrent mention revisions | One group, separate exact alternatives | One group count | Separate revision counts |
| Mention removed/retracted | No current active row | No stale active badge | Existing private marks retained |
| Mention later re-added | Existing group, new exact revision | No new priority after prior group acknowledgement | New revision unread |
| New recipient owner | Different group in that owner's inbox | Independent priority | Independent read state |
| Multiple recipient agents of one owner | One owner group, routes retained by the future adapter | No owner priority multiplier | Separate reader namespaces |
| Duplicate or reordered source facts | Identical canonical result | No additional group | No additional update |
| Source invalidated or unresolved | Omitted | No active badge | Existing exact marks retained |
| Same source becomes valid again | Same exact identity | Existing group state retained | Existing exact state retained |
| Late previously unseen historical revision | Existing or new group | Depends on that group | Unread, independent of ID order |
| Exact ACK capacity exhausted/compacted | Current rows still visible | Retained group knowledge remains | Retained marks Read; unproven status Unknown |
| Stable group ACK capacity exhausted | Current rows still visible | Retained groups Read; other groups Unknown | Separate exact state |
| Partial canonical restore loses an ACK's source | Source unavailable | No source-derived row | ACK retained and reported unresolved |

“Unread priority” is a stable presentation state, not a newly emitted delivery
event on every query. A later wake/delivery adapter must deduplicate by stable
group and use its own durable delivery protocol; this spike neither emits alerts
nor authorizes waking a tool-capable agent. Negative reactions, unfollows and
unselected sources may be activity with `priority = false`.

## API and trust boundaries

`Reader` binds realm, durable owner, optional exact agent incarnation, local
profile and device. Only explicit local host selection may construct it. It is
not derived from an incoming display label. Two sibling agents can see the same
owner inbox while acknowledging it independently. Namespace validation prevents
mix-ups, not access by another process with the same OS-account permissions.

`Group = (recipient_owner, source_owner, reason, semantic_target)`. For mentions,
the target is the original source post. For preference interactions it is the
target slot. `Update = (Group, exact_source_event_or_revision)`. The model uses
these complete structural identities, avoiding unnecessary hash collision
assumptions. Production can hash a versioned canonical encoding if a compact
external key is necessary. Agent/controller turnover does not change stable owner
identities. Different typed recipient routes to one owner collapse at the adapter,
which must retain those routes as presentation provenance.

`Fact` is **already derived current social evidence**, not a signed record or
proof of validity. A maintained adapter must verify owner/agent bindings, exact
source revisions, causal preferences, authorized commitment, current control,
retraction, source policy and route provenance before providing rows. Inactive
mentions are excluded. Pending/invalid sources never become actionable rows.
Contradictory duplicate facts are rejected, because silently choosing one would
make adapter mistakes arrival-order dependent. This model cannot establish the
correctness of the existing social reducer or filesystem store.

`Durable::model_fixture` is deliberately named as a model constructor. It asserts
a bounded exact source-ID set, realm and archive basis; it does not verify any
signature, source body or disk operation. A production adapter must mint the
corresponding receipt only after canonical source publication and readback.

`snapshot(durable, current_facts, live, offset, limit)` returns a private-field
`Snapshot` containing the exact shown entries, owner/reader scope and observed
basis. A page contains at most 64 entries. `acknowledge(snapshot, current_durable)`
returns a **candidate** private state. It must not be reported as durably read
before a separate journal commits it. Every exact source must remain present;
missing sources fail the entire operation before mutation. Later valid additions
and a changed archive root do not invalidate exact old acknowledgements. The
snapshot never expands into all members of a group or all events below an ID.

An old snapshot can acknowledge only what it showed. Existing marks from a partial
source restore remain unresolved until their exact source returns; they never
attach to another revision. Their retained group knowledge suppresses repetitive
priority without asserting that replacement content was read. The model's stable
ID ordering is for reproducibility, not a globally meaningful clock or feed rank.

## Bounds and saturation decision

- At most 256 input facts/durable source IDs, including duplicates before dedup.
- At most 64 returned entries, with no claim of 64-entry peak allocation: current
  derivation builds a `BTreeMap` bounded by all 256 inputs first.
- At most 256 group marks and 256 exact marks; the chosen capacity is persisted.
- Encoded private state is at most 100,000 bytes; the actual maximum canonical
  representation is under 60 KiB. Decode bounds length before allocation, counts
  before insertion, and rejects unsupported flags/reasons, wrong namespaces,
  repeated/unsorted marks, truncation, checksum damage and trailing bytes.
- No semantic source history is pruned. Private state does not enter public sync.

There is no exact lifetime unread count with indefinitely many source events and
finite exact ACK storage. We choose **visible degradation** over a probabilistic
filter or hidden eviction: once capacity cannot record a shown acknowledgement,
retain known marks and turn other unproven read states Unknown. Explicit exact
mark compaction similarly sets Unknown permanently for untracked revisions.
Future exact marks can still establish Read. A later generation/retention design
may recover finer fresh-event precision, but cannot infer it from content-ID
order or remote timestamps. Counts expose unread **and unknown** revisions/groups
for the returned page; zero unread with unknown greater than zero is not an exact
lifetime zero. This conservative baseline sacrifices useful unread precision
after saturation instead of manufacturing replay storms.

Within capacity, exact/group acknowledgements are set unions: order and duplicate
acknowledgements converge. At saturation, retained precision depends on local
journal history; this is a local private store, not a declared replicated CRDT.
Future cross-device replication needs its own authenticated merge/retention rules.

## Durable-source-first and crash decision

The intended sequence is:

1. Commit canonical signed source evidence and obtain its exact durable receipt.
2. Derive a local snapshot and receive an explicit read acknowledgement.
3. Validate the snapshot's source IDs against the current durable source set.
4. Produce the candidate private state, then publish it in a separate owned
   private journal with its own intent, atomic rename, directory sync and recovery.
5. Only after that private publication succeeds report a durable read mark.

The test models five private-journal cut points. Before durable intent, recovery
can legitimately lose the recent read mark. A torn intent fails closed. A complete
intent can recover the candidate; publication/cleanup retain it. These are
**in-memory crash protocol fixtures**, not evidence that any native filesystem
adapter implements the steps. The maintained adapter needs fault injection and
real locking/private-path tests independently.

The `VHATTN01` checksum detects damage; it provides neither authentication nor
rollback protection. Old coherent bytes still decode. Rolling back both stores
coherently is indistinguishable without an external anchor. The canonical
store's exact-pin guarantee must not silently extend to this private journal.

## Evidence and integration criteria

Focused commands:

```text
cargo test --manifest-path prototypes/social-attention/Cargo.toml --locked --offline
cargo fmt --manifest-path prototypes/social-attention/Cargo.toml --check
cargo clippy --manifest-path prototypes/social-attention/Cargo.toml --all-targets --locked --offline -- -D warnings
```

The executable fixtures cover provisional promotion, edit/remove/re-add,
concurrent revisions, new recipients, siblings, exact mark-all pages, invalidation,
negative activity, ACK saturation/compaction, partial source restore, additive
source growth and realm separation. Four generated suites (256 cases each) compare
against an independent set-membership oracle, execute visibility/read traces,
exercise saturation/roundtrip behavior and decode arbitrary bounded bytes.

2026-09-13 result: all 18 tests passed, including four property suites with 256
cases each; strict Clippy and formatting passed. The maximum-state fixture fixes
the current canonical representation at 58,065 bytes. No dependency version absent
from the current root lockfile was introduced. This is model evidence; no maintained
notification reducer or native private journal is qualified by that result.
The pure crate also compiled for `wasm32-unknown-unknown` with the retained official
Rust 1.97.1 toolchain; this is compile evidence, not a browser execution/parity test.

Before promotion, implement the maintained reducer adapter, selected/request
capacity policy, real private persistence, CLI workflows, archive-basis cursor
invalidation, WASM parity and public-export exclusion. Keep the useful grouping
and exact-read contract; do not import `model_fixture` as proof of durable evidence.
