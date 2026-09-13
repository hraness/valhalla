# vhalla (valhalla): bounded social archive reference

Disposable `no_std` + `alloc` Rust model, excluded from the production workspace.
It imports no Valhalla authority, host or network crate. No automatic compaction,
filesystem backend or settlement is implemented. Its pinned fixture policy stands
in for the separately reviewed owner/control admission seam.

## Decision

Keep a **bounded full signed archive with no garbage collection** for the first
social slice. At capacity, preserve evidence, signal partial/frozen progress, and
require explicit export and a newly admitted scope before accepting more history.
A new scope is not permission to erase the old history, transfer its score, reset
an agent's signing counter, or drop revocation evidence. Archive transitions need
an explicit owner action; this model does not authorize one.

Time-based tombstone deletion fails the offline-peer test. An authenticated
compaction scheme requires additional authority/freshness rules: who may certify
complete causal coverage, which writer branches are covered, how new peers obtain
that trust, and how stale peers rebootstrap without resurrecting old state. This
spike deliberately does not invent that authority or claim secure compaction.

## Bounds and admission

Test constants are intentionally small: at most four configured owners, four
writers per owner, eight data records per owner, four data records per writer,
four separate control records per owner, two pending records per writer, eight
causal references, and 512 bytes per signed event. These are executable test
bounds, not proposed production quotas.

Incoming work charges a budget before decoding/verifying: eight attempts and
4096 bytes per tick. Invalid signatures consume attempts. Strict Ed25519 verifies
canonical domain-separated bytes. Dependency closure uses a finite fixed-point
pass with an explicit polynomial work bound; it never recursively rewalks shared
ancestors without memoization. Full signed records remain available for replay.
One owner's agent fleet cannot spend another owner's slots, and pending orphans
from one writer do not consume all other writers' slots. The owner-level limit
also prevents obtaining a larger data allowance merely by adding more writers.
Control capacity is separate, so an owner resolution can resolve a full data
register. Exhausting the finite control reserve still requires stopping and
explicit recovery; no finite reserve guarantees unlimited hostile control churn.

Writer progress requires a matching writer/owner, exact previous hash and sequence
+1. A maximum observed sequence is not a prefix proof. Unknown dependencies remain
inert. Equal displayed values retain all original record IDs; no causal evidence
is discarded. Writer equivocation quarantines its suffix; owner control forks
freeze that owner's projection. Projections are rebuilt after control evidence
changes rather than retaining an earlier accepted count.

The minimal action vocabulary tests set/retract/revoke/owner-resolution behavior.
It is not the production social reducer. It omits real grants, joint owner binding,
rotation/recovery, grant expiry evaluation, cross-room post schemas, and full
register-reference semantic validation. Do not promote these fixture semantics
as an alternative to the owner/social prototypes.

## Synchronization and storage

A peer cursor cycles configured owners; each page provides at most two missing
records per owner and four records total. Within each owner, a separately rotating
priority class carries controls and requested missing ancestors; a rotating regular
class gets the other slot. This prevents rejected data at the front of a sorted
inventory from permanently hiding a later revocation. Missing events use full
IDs, not a newest-sequence watermark. Tests cover finite page work, owner fairness,
blocked-data/control progress and missing-ancestor coverage; they do not prove
starvation freedom under arbitrary changing inventories. Receivers still need
explicit rejected/partial-page acknowledgments in a real protocol. Infinite retries
against a permanent quota failure are not a synchronization strategy.

Canonical local snapshots retain every signed event and a separate reception
receipt recording observed backpressure. That local receipt is deliberately outside
the deterministic social projection and `evidence_root()`; the logical root binds
pinned policy plus sorted canonical event IDs. Alternate valid signature bytes for
one event ID may change physical storage bytes, but cannot change this logical
identity. The regression receives e3,e4,e2(rejected),e1,e2(retried): its complete
projection/root matches ordered e1,e2,e3,e4 despite different local receipts. Restore decodes all bounded evidence before applying closure analysis;
network pending limits must not make disk restoration depend on digest ordering.
Equal complete event sets under the same evaluation context converge in the
property test. Different local retention/admission scopes can legitimately expose
different partial views; the marker must survive restart.

The in-memory disk fault model stages an immutable whole snapshot, then conditionally
publishes its full generation/root pin. A lost acknowledgment is retried with the
same intent, not a newly signed event. Stale writers cannot replace the current
pin. Every forward candidate must also preserve the previous authenticated event
ID set under exactly the same pinned policy/context. Advancing a CAS generation
alone is insufficient: replacing `{create,retract}` with `{create}` is rejected,
as is changing policy to make old evidence invisible. An independently retained
floor rejects an older snapshot; rolling back the
entire disk succeeds without that external floor, which is explicitly tested.
An external floor in this model is only a caller-provided test fixture, not a
production anti-rollback service or authenticated constructor.

For a native adapter, prefer the repository's existing immutable bundle plus
atomic pin publication ordering for this bounded first slice. If using an append
journal instead, a record needs canonical framing, previous full hash and control
basis, a torn-tail recovery contract, exclusive writer lock, and fsync before a
publishable result. Signing counters derive from verified durable history;
an independently persisted counter can diverge after a crash. Indeterminate fsync
or acknowledgment results require reconciliation of the exact signed event ID.

## Evidence

Tests exercise three replicas, duplicate/reordered delivery, revocation and control
fork rebuilding, causal gaps, data/control pressure, pending quotas, verification
budgets, simple owner page fairness, tombstone resurrection after unsafe GC,
full snapshot restart, crash/retry/CAS behavior, rollback limitations, malformed
structured input and writer equivocation. Two property tests run 32 cases each:
complete under-cap event permutations and bounded arbitrary incoming bytes.
The final focused suite has 13 tests. Formatting and strict all-target Clippy pass.
Independent review supplied three additional counterexamples—sticky partial flags,
control starvation and forward-generation tombstone removal—which now have explicit
regression tests.

No sockets, native files, browser or blockchain are exercised. This is an executable
architecture reference, not a qualified persistence implementation or full CRDT
convergence proof. Actual platform durability, rollback protection, sustained
fairness, semantic admission, and end-to-end social integration remain separate
gates. Scarce reward/double-claim modeling remains in the settlement layer.

```console
cargo fmt --manifest-path prototypes/social-sync/Cargo.toml --check
cargo test --manifest-path prototypes/social-sync/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/social-sync/Cargo.toml --all-targets --locked --offline -- -D warnings
```

Run those through the installed host scheduler, using the shared compute lane.
