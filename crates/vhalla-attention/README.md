# Owner notifications and private read state

For vhalla (valhalla), this pure Rust crate derives a bounded owner inbox from
the maintained verified social archive. It uses `no_std` + `alloc`, existing
social/core types and SHA-256. Public outputs contain inert metadata, never host
capabilities, wake requests, executable text, or arbitrary network locations.

`ReaderScope::new` validates an explicitly selected realm/owner/optional agent
against historical control binding. Retirement does not erase that reader's
namespace. Profile/device IDs partition private state; they are local values,
not hardware identifiers or permission credentials. A sibling agent must select
its own namespace to keep acknowledgements separate.

`Attention::notifications` constructs a fresh social view internally. It derives
mentions, replies, follows/unfollows, reactions, reposts, quotes and watched-thread
activity. Typed agent mentions route through the immutable historical owner even
after retirement; unresolved binding is a coverage gap. Legacy `@text` has no
identity meaning. Current exact revision facets determine mentions, including
conflicting alternatives and removal/re-addition. Replies/quotes retain exact
reviewed targets. Effective causal preference heads determine engagement activity;
superseded toggles do not become fresh notifications. Clear/negative/conflicted
preferences confer no priority. Default source evidence is committed; explicit
live mode badges provisional activity. Invalid or unresolved sources are omitted.

Stable group identity is recipient owner + source owner + reason + semantic
target. Exact update identity additionally includes its source event/revision.
Group acknowledgements suppress repeated priority from edits or re-added mentions;
later revisions remain unread. Multiple owner agents do not multiply group
priority. `Notification::id()` hashes the full versioned update identity for
explicit cross-process selection; it is not an authorization key.

Reading a page is pure. `NotificationSnapshot::select` accepts only exact IDs already present
in that locally derived page. `Attention::acknowledge` accepts the issued snapshot
and current archive, checks every exact source still exists, and returns a new
candidate state. It never expands to unshown group members, later revisions, IDs
below a watermark, or remote timestamps. A native host reports durable read
success only after separately publishing the candidate in `vhalla-discovery-store`.

The selected lane has independent candidate/read storage from unknown-source
requests. Explicit source selection, committed follows, and watched roots select
the lane. Local muted/blocked owners and muted threads suppress presentation;
control evidence remains in the canonical archive. Limits are 256 candidates per
lane, 32 per source owner, 64 returned entries, and 512 values per local filter.
Pagination is stable ID order within selected then requests, not global time.
Unread filtering happens before pagination and includes explicitly Unknown entries.
Projection builds bounded collections over the full retained archive first; a
64-entry page is not a 64-entry peak-memory claim.

Each lane retains at most 256 acknowledged groups and 256 exact updates. A group
retains an exact source witness for durability checks. Capacity exhaustion or
explicit exact-history compaction preserves known marks and labels unproven state
Unknown; it never claims an exact lifetime unread zero. Bounded sets remember
which source owners lost precision. Their Unknown status follows lane changes,
preventing selection changes resurrecting read content while unrelated selected
sources retain precise state. Each owner set holds at most 256 IDs; if it too
saturates, explicit global Unknown is the conservative fallback. This bounds
memory without claiming indefinite exact precision or indefinite lane isolation.
Counts distinguish unread and unknown updates/groups for the returned
page. Repeated queries do not emit new alerts; any future external alert delivery
adapter needs its own group deduplication and local capability/quota checks.

`encode/decode` implements bounded canonical private state, expected-reader
binding, strict counts/order/flags, and a domain-separated damage checksum. It
offers no authentication or rollback protection. The codec is absent from public
archive export. `new_claim_sources(previous)` compares **semantic claims**, not
the union of source IDs, so an old observation/group witness cannot justify a
fresh exact acknowledgement after that source disappears from durable storage.
Old missing marks remain unresolved and cannot attach to another source ID.

Validation includes actual signed fixtures for every reason, historical agent
routing, edits/remove/re-add/concurrent alternatives, live promotion and terminal
lifecycle, exact page acknowledgement, negative/clear conflict policy, thread
mute, independent sibling read state, owner budgeting, partial source loss, private
roundtrip/damage, and reordered/duplicated signed archive property tests. Run:

```text
cargo test -p vhalla-attention --locked --offline
cargo clippy -p vhalla-attention --all-targets --locked --offline -- -D warnings
```
