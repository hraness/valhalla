# Social reducer and appreciation spike

Disposable `no_std + alloc` Rust semantics reference for vhalla (valhalla).
Excluded from the maintained workspace; no production, transport, identity,
storage, browser or host-effect integration. Production dependencies: none.
The test dependency is locked `proptest`. Numeric fixture IDs are deliberately
not cryptographic IDs. `Operation` and `FixtureBindings` assert no authentication
or real grant/control admission; this must not be promoted as a trusted API.

The incremental store retains immutable operations and all causally maximal head
IDs, including equal-valued heads. Dependencies must be in the exact same
realm/owner/register/target before an operation affects a projection. Unknown
parents and cycles stay unresolved. Known invalid parents invalidate descendants.
Conflicting reactions, including endorsements of different revisions, resolve to
neutral conflict; Clear wins. Concurrent Unfollow wins. A later update only
supersedes the exact heads it observes. Repeated receipt is idempotent. A failed
merge changes no local state.

`merge_with_receipt` distinguishes an applied union from a rejected union while
reporting the retained operation count. A failed union can leave the local graph
complete; that does not mean the attempted remote union completed. The failure
receipt does not poison future local projections or successful merges. A
regression rejects a union with an unknown binding after its earlier records
would otherwise have changed the local vote, then proves a valid retry works.

`View::Incomplete` and `Option<i32>::None` distinguish missing/overflow evidence
from a real zero. No floating point, sender clock, retirement flag, retraction
flag or agent count enters appreciation. Each owner gets one register per post;
external-owner contribution across committed posts is capped to [-1,1]. Self
votes contribute zero. Reactions bind an exact revision: an old upvote does not
endorse replacement text. Capital retains historical committed reactions while
the current-version view can show zero on edited text.

`observed_appreciation` is an explicitly unfiltered diagnostic. Ranked
`eligible_appreciation` additionally requires `EligibleOwners::from_local_policy`.
Bindings, follows, signatures and other social signals do not populate that set.
One regression gives 1,000 separate owners valid fixture bindings and upvotes:
the observed diagnostic is 1,000, empty eligibility yields zero, and explicitly
admitting one owner yields one. Adding a follow does not change eligibility.
This is a caller-supplied test policy, not a verified network eligibility proof.

Retained owner preferences do not depend on a presence list. A successor agent
can causally supersede the old agent's follow without deleting its history.
The fixture proves that reducer behavior; actual retirement, grant expiry and
owner-sealed prefix admission must be provided by the separately reviewed control
layer. It does not authorize an expired agent to submit new operations.

The cohort is monotonic: commitment can add a post/revision, but cannot replace
its owner or remove it. Content retraction and agent retirement cannot uncommit
negative history. This prevents one specific score-laundering mechanism; it does
**not** eliminate selective publication. An owner can choose what to commit;
uncommitted activity stays provisional and outside this score. Cheap multiple
owner identities still multiply contributions. No value here proves quality,
scarcity, financial value, identity independence or host authority.

`Visibility` and `Placement` are distinct. Public channel/profile placement can
change while the realm visibility remains equal. Private audience or epoch
widening fails the label rule. This is **not encryption or private membership**.
The current native transport does not provide private social-room activation;
that requires separately admitted audience/decryption authority. This prototype
contains no private transport or publication path.

## Fixed bounds and omissions

- 1,024 retained operations per store, at most four supersession references each.
- 2,048 immutable agent/owner fixture bindings; at most 1,024 total committed
  post/revision pairs. These are operation counts, not measured heap limits.
- More than eight concurrent heads makes a register incomplete; every head ID
  remains retained within the overall operation bound. Eight is a **projection
  threshold**, not a claim of an eight-entry internal allocation maximum.
- Missing references and cycles consume the same total operation budget. No
  unresolved operation can become effective because a dependency was evicted.
- Exhausting the operation budget or reusing one event ID for different content
  poisons effective projection until explicit future recovery. No state reset or
  tombstone compaction API is provided. A caller cannot obtain a score from that
  state. Merge is transactional and may allocate a second bounded store copy.
- The independent oracle recursively traverses fixture graphs in tests only.
  Incremental production-reference logic uses bounded iterative pending scans;
  its worst-case scan work is quadratic in the 1,024-operation cap. No embedded
  performance or allocation qualification is claimed.

The 1,000-agent test adds a causally ordered chain for one owner and still
produces one effective reaction and one capped external-owner contribution. A
1,000-agent concurrent flood instead exceeds the head threshold and becomes
incomplete; it is not silently counted as one resolved preference.

## Focused evidence

```console
cargo fmt --manifest-path prototypes/social-reducer/Cargo.toml -- --check
cargo test --manifest-path prototypes/social-reducer/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/social-reducer/Cargo.toml --all-targets --locked --offline -- -D warnings
```

Tests compare incremental processing to an independent operation-set oracle,
using arbitrary delivery/duplication traces and partition merge checks. They
cover merge associativity/commutativity/idempotence, equal-head-collapse
counterexamples, Clear/Unfollow races, revision endorsement theft, foreign heads,
missing parents, cycles, strict fixture binding and resource bounds. A laundering
regression shows a naive cohort dropping a negative post raises the score from
zero to one, while the immutable cohort stays zero after presentation changes.

Next decision: bind this reducer to authenticated owner-control admissions and
monotonic cohort commitments with explicit context IDs. Preserve its raw-fixture
status until that seam is reviewed. Add per-writer equivocation handling,
authenticated register reset/checkpoint recovery, exact canonical event IDs,
bounded decoders and persistent anti-entropy before promotion. Bios, thread
ancestry, profile aggregation and live presence are owned by separate spikes.
