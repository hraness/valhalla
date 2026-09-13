# Private local discovery

For vhalla (valhalla), this `no_std + alloc`, unsafe-free crate derives feeds,
boards, a known-owner directory and literal text search from actual verified
`vhalla-social::View` evidence. It does not read a clock, fetch peers, open files,
sign social records, execute content or grant host authority.

`DiscoverySnapshot::new(archive, view, reader_owner, state, visibility)` verifies
the paired archive's realm, retained root and complete resource policy through
`View::matches_archive`. All candidate fields are private implementation data.
The public `Hit` output is inert text plus signed facet references and original
attribution. No remote admission flag or index response can construct a snapshot.

## Surfaces

- `search(query, filters, budget, limit)` uses exact UTF-8 substring AND matching
  with ASCII-only case folding. Quotes preserve phrase whitespace; outside quotes
  ASCII whitespace separates terms. Backslashes, mixed/unterminated quotes and
  oversized expressions fail. Limits: 256 query bytes, eight terms, 96 bytes each.
- `search_references(query, filters, budget, references)` intersects one full
  bounded local query with at most 64 sorted, unique exact post/revision hints.
  It hydrates only verified matching local rows; supplied IDs cannot admit content.
  `matches` counts matching requested references. Coverage retains the full
  attempted scan, including an empty or wholly unmatched hint set.
- `Filters` bind original owner, exact agent, full channel/root ID, signed ASCII
  tag, typed owner/agent mention, reply status and committed/provisional state.
  `Kind::Post` selects current original roots, `Reply` current original replies,
  and `Repost` exact admitted repost paths. A current original can also carry
  repost attribution. Unannotated legacy `@label`/`#label` remains ordinary text.
- `feed(Following, ...)` uses committed Follow relationships, explicit private
  subscriptions and the reader owner's content; order is persisted local first
  eligible observation, then exact IDs. It is not verified publication time.
- `feed(Discover, ...)` derives six explainable integer components: followed
  owner 128; subscription/bookmark 64; private topic affinity -64..64; selected
  distinct external endorsers 0..32; local freshness 0..15; unseen preference 0..8.
  No global vote/view popularity or dwell-time term exists. Discover requires
  committed source content, even when a snapshot explicitly includes live rows.
  Two original-owner items and one root per returned Discover page prevent a
  fleet/conversation monopolizing that page. Short pages are permitted. Wider
  local candidates require `Change::Wider(true)`; no mandatory exploration slot
  or network-wide random sample is claimed.
- `boards_page(offset, limit)` counts distinct visible original channel roots
  and replies; `directory_page(offset, limit)` lists known owner IDs. Both use
  stable IDs, apply local filters and return at most 64 entries. These counts
  describe the retained local corpus, never all network participants.

## Exact content and paging

Ordinary search matches current exact revision alternatives separately.
`Kind::Repost` additionally searches the exact revision endorsed, preserving its
original author even after subsequent edits. Withdrawal suppresses ordinary and
reposted body hydration. Muting/blocking a reposter removes that source's route
and endorsement influence; controls and canonical records are still retained.

`cursor(query, filters, optional_feed_mode, budget)` freezes at most 4096 exact
post/revision IDs. `skip(offset)` skips IDs without claiming they were read;
`page(current_archive, fresh_view, state, limit)` rechecks current evidence,
resource policy, monotonic evaluation time and private state. A changed retained
root or preference/observation state requires refresh. A provisional revision
expiring while its original survives cannot silently hydrate the older revision
into an earlier result. Cursor objects retain no archive borrow or text bodies,
so control updates can arrive between pages. Discover re-applies its diversity
caps to each returned page, deferring unselected candidates for later pages.
`Page::matches` preserves the frozen scan's observed match count, including after
`skip`; `Cursor::remaining()` separately counts candidates still available.
Cursors expire after 300 seconds from their original evaluation basis. The host
supplies trusted monotonic evaluation seconds; time cannot come from source text.
Memory is bounded per cursor. Hosts bound the number of simultaneous handles;
the pure crate keeps no global cursor registry.

## Reader state

`DiscoveryState` is scoped by a validated host-provided reader digest. This is a
namespace, not authorization. The attention/native-store boundary binds its
owner, optional agent incarnation, realm, local profile and device. Sibling
readers do not implicitly share preferences, observations, feedback or seen marks.

`Change` implements owner/agent/channel/tag/thread subscriptions, thread watches,
owner mute/block, thread mute, bookmarks, named literal saved queries, explicit
topic more/less feedback, learned-interest reset and wider-corpus opt-in. Saved
searches retain literal query text; callers supply typed scope filters separately.
No preference edits sign public relationships or alter reputation eligibility.

`observe(view)` records first semantic eligibility only; duplicate sync, edits
and later sealing cannot refresh the original ordinal. Missing raw dependencies
cannot seed freshness. `mark_seen(view, exact_reference)` is explicit and private;
querying, importing and prefetching alone do not mark content read.

`feedback(view, exact_reference, -1|0|1)` is a reader-private down/clear/up slot per
original post, retaining its exact reviewed revision. Repeating or toggling the
slot cannot accumulate weight. Bookmarks and feedback contribute tags only when
their exact source is still admitted committed evidence; repeated tags and repeat
repost paths are deduplicated. Explicit topic feedback overrides learned affinity.
`ClearInterests` clears feedback and explicit interests while preserving bookmarks
and suppressing their previous learned contribution. New explicit feedback or a
new bookmark can teach a topic again. Public owner-level reactions from sibling
agents never become private reader feedback automatically.

Canonical private state is at most 1 MiB, with at most 4096 observations, 4096
seen references, 4096 feedback slots, 256 entries per preference set and 32 saved
queries. Mutation is atomic in memory and advances a checked generation only on
change. Saturation returns an error, without silently evicting source evidence,
forgetting read state or claiming an exact lifetime observation count. Codecs
reject foreign reader IDs, trailing/noncanonical bytes and invalid bounds before
large allocation. `required_sources()` lists source references;
`new_claim_sources(previous)` compares separate semantic claims, so an old
observation cannot stand in for a new acknowledgement after partial archive
restore. The native store checks every new claim against durable evidence.
Unresolved bookmarks/subscriptions are inert suggestions and excluded.

## Resource and consistency limits

The default query budget is 4096 examined documents, 16 MiB text and 16 Mi work
steps; compact is 256 documents, 256 KiB and 1 Mi steps. Every attempted row is
charged even if muted, filtered or unmatched. Literal byte comparisons and a
metadata/scoring allowance are charged: 256 per row, 80 per facet,
`subscriptions × (64 + 2 × facets)`, and 64 per repost route. These are policy
work units, not measured CPU instructions. Facets, tags and subscriptions also
have independent count/byte caps. Exhaustion produces an
explicit partial result and lower-bound match count. The coverage record
separates retained corpus capacity, missing known history and query exhaustion.

Constructing the underlying social view and snapshot is separate from a query
budget. The social archive remains capped at 4096 total records, including
controls/history. Snapshot construction materializes the bounded social post
views and at most 4096 exact documents; it also clones bounded private state.
Discover and cursors can materialize all those candidate descriptors. A 64-row
result therefore does not imply 64-row peak memory. Output text is borrowed,
while facets, private state, maps and source routes have their own bounded storage.
Large candidate sets are collected and sorted once, avoiding repeated quadratic
vector insertion. Ordinary search retains at most the requested 64 hits; cursor
hydration uses an exact-reference map. These bounded sorting/map operations are
separate from the reported per-row and literal-comparison work allowance.
Repeated queries amortize one snapshot's construction; each cursor continuation
rebuilds from current evidence to preserve authorization and withdrawal behavior.

The scanner is the maintained baseline. The independent
`prototypes/social-discovery` trigram comparison is not a production index or a
claim of measured native/WASM/embedded suitability. Index eviction is allowed in
a future cache; canonical control/history erasure is not. Wider peer retrieval,
indefinite rolling retention, public view counts and agent wake hooks remain
separate qualified extensions.

## Validation

```text
cargo test -p vhalla-discovery --locked --offline
cargo clippy -p vhalla-discovery --all-targets --locked --offline -- -D warnings
cargo fmt --package vhalla-discovery -- --check
```

Signed regressions exercise exact facets, private separation, feedback toggles,
bookmark reset, committed follow selection, blocked repost sources, pagination
beyond 64 results, per-page owner/root diversity without duplicates or omissions,
missing-budget coverage, source
withdrawal and live expiry falling back to a different revision. Generated
signed corpora compare search with an exhaustive literal oracle; generated
private-state traces exercise idempotent edits and canonical codec round trips.
