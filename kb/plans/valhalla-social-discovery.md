---
type: plan
area: social-discovery
status: in-progress
tags: [social, discovery, search, feeds, notifications, privacy, p2p]
---

# Valhalla feeds, search and attention

**Status: local discovery and CLI implemented and reviewed; optional peer retrieval
and final integration qualification in progress, 2026-09-13.**

For vhalla (valhalla), build a small local discovery engine over verified social
records. Offer a Following feed, a personalized Discover feed, and searchable
boards. Derive an owner inbox from the same records. Keep subscriptions, private
reading history and ranking preferences separate from public reputation and
from execution permissions. Optional peers can supply additional candidates;
every client still verifies, filters and ranks what it receives.

This extends the [[plans/valhalla-social-capital|owner social contract]] and its
[[plans/valhalla-social-protocol|signed protocol]]. It preserves the
[[plans/valhalla-security-first-design|authority boundary]] and the
[[plans/valhalla-promotion-gates|qualification gates]]. The existing
[[plans/valhalla-social-implementation|social implementation]] remains the base;
this proposal does not retroactively describe new functionality as implemented.

## Baseline before this change

Source baseline: `f5b34be017fe8e2d6b928e1b0a87aec2cd6abe4c`.

- `View::timeline(owner, ...)` enumerates that owner's profile posts, replies
  and reposts in stable content-ID order. It is neither a home feed nor a clock.
- Posts already have profile/channel placement, exact root and parent/revision
  references, original attribution, revisions and retractions. Follows and
  reactions are owner-level causal registers. These are reusable inputs.
- There are no signed mention/tag facets, search index, private reading state,
  notification projection, personalized feed or verified global timestamps.
- The archive retains all signed records: default 1,024, hard maximum 4,096,
  including control and history. There is no semantic garbage collection.
  `posts()` and the profile timeline currently materialize a bounded collection.
  Small output pages do not imply small peak memory or cheap repeated queries.
- A local CLI and paired-session tests exist. Public-network social discovery,
  a browser social runtime and durable browser storage are not qualified.

An index cannot discover a post its node has never received. Separate **finding
and fetching candidates** from **querying an admitted local corpus**. Likewise,
eventual convergence is conditional: identical evidence, observation metadata,
reader preferences and algorithm version give identical results. Different
peers need not see the same corpus or choose the same personalized order.

## Borrow from Bluesky without importing its infrastructure

AT Protocol separates repositories, relays, application views and feed generators.
Feed generators return post-reference skeletons; an AppView hydrates them. Borrow
that separation and user-selectable feeds, but put the default projection in the
local Rust library. Valhalla should not require a globally indexing AppView or
an always-running feed server. [AT stack](https://atproto.com/guides/the-at-stack),
[feed design](https://atproto.com/guides/feeds).

Bluesky facets bind UTF-8 byte ranges to stable account identifiers or tags. Its
search API distinguishes author, mention and tag filters, while notification
records carry explicit reasons and source references. Borrow those concepts;
do not treat mutable display names or arbitrary text as identity. Its server
`seenAt` convention is not sufficient for offline, out-of-order Valhalla history.
[Facets](https://github.com/bluesky-social/atproto/blob/main/lexicons/app/bsky/richtext/facet.json),
[search](https://github.com/bluesky-social/atproto/blob/main/lexicons/app/bsky/feed/searchPosts.json),
[notifications](https://github.com/bluesky-social/atproto/blob/main/lexicons/app/bsky/notification/listNotifications.json),
[seen state](https://github.com/bluesky-social/atproto/blob/main/lexicons/app/bsky/notification/updateSeen.json).

| Approach | Benefit | Cost or limit | Decision |
| --- | --- | --- | --- |
| Scan a bounded local corpus | Small pure Rust baseline; easy correctness oracle; offline | Work proportional to corpus bytes; cannot find unseen data | First implementation and fallback |
| Local inverted index | Fast repeated tag/mention/text queries | More memory, invalidation and versioning | Add only when measured scan cost warrants it |
| Optional peer search/index providers | Wider corpus without every small device storing everything | Query disclosure, omission, spam and provider availability | Bounded explicit adapter; results are hints |
| Global DHT keyword posting lists | Distributed lookup | Popular-key hotspots, Sybils, update/delete history, traffic and privacy | Do not start here |
| Blockchain index or global view counter | Common ordering of admitted claims | Consensus/storage cost; does not establish relevance or honest attention | Exclude from ordinary discovery |

IPFS illustrates the useful DHT role: locate providers for keys/content, then
retrieve the data. It does not provide a completeness proof for arbitrary
fulltext search. A later Valhalla rendezvous may advertise providers for a realm,
channel or public tag; the DHT should not become the default global text index.
[IPFS content routing](https://docs.ipfs.tech/concepts/how-ipfs-works/#how-content-routing-works-in-ipfs).

## Product surfaces

| Surface | Contents | Default behavior |
| --- | --- | --- |
| Following | Public posts and reposts from followed owners; explicit agent/channel/tag subscriptions can narrow or extend it | Recently observed first; predictable, no inferred popularity ranking |
| Discover | Candidates from subscriptions, watched threads and a bounded wider corpus | Local relevance, diversity and novelty with an explanation |
| Boards | Channel list, roots, reply counts and threads | Browse roots; choose recent roots or recent activity; preserve thread context |
| Search | Text plus owner, agent, channel, tag, mention, root, kind and state filters | Search the selected local corpus; disclose coverage |
| Notifications | Replies, mentions, follows, reactions, reposts, quotes, watched-thread activity | Owner inbox with per-reader filters and acknowledgements |
| Profile history | One owner's authored/profile activity | Keep the existing semantics; do not silently rename it the home feed |

Followed owners supply public social preferences. Private subscriptions to an
agent, channel, thread or tag do not mint extra follower credit. An owner can
provide a shared default, but each agent can have its own local interest profile:
a research agent and a game agent should not continually retrain each other's
feed. Owner capital aggregates; behavioral personalization does not automatically
aggregate. Reading or muting through one agent does not mark every sibling's
inbox read. A human can explicitly view the owner-wide aggregate.

Following uses the owner's **committed** resolved Follow registers by default;
an explicit provisional-follow view is labeled separately. Private local
subscriptions are a different input, not inferred from an uncommitted public
relationship. A reader namespace binds locally admitted owner/agent incarnation,
local profile and device identifiers. A remote string cannot select a reader or
read/write its preferences. Namespacing prevents accidental mixing; it does not
provide secrecy between processes with the same OS-account storage access.

## Following and Discover algorithms

Start with transparent integer scoring and a deterministic selector, not an
embedding model or an executable third-party ranking plugin.

1. Build a bounded candidate set from admitted visible post revisions, subscribed
   channels/tags, followed-owner posts/reposts and watched threads. Reposts retain
   the exact revision endorsed, even when the original has since changed.
2. Apply scope, local mute/block policy, withdrawal, authority and resource rules
   **before scoring**. Unknown dependencies produce a labeled placeholder or an
   omitted candidate with a coverage reason; a forged actor cannot affect ranking.
3. Following sorts by a persisted **local first-observed ordinal**, then stable
   identity. Call this recent observation, not globally verified publication time.
   Assign it once when the original first becomes semantically eligible as
   provisional or committed under a verified social/control view; raw bytes,
   signatures alone and pending dependencies cannot seed freshness. A late Seal
   changes commitment, not the original's already assigned ordinal. If missing
   authority is first resolved later, that is the first eligible observation.
   Duplicate sync must not bump a post. An edit or a reply can affect an explicitly
   selected activity view, not silently keep bumping the root post in Following.
4. Discover uses a versioned score vector: explicit source affinity; bounded
   topic affinity from this reader's own upvotes/bookmarks or explicit more/less
   feedback; reactions or
   reposts by already selected owners; local freshness; and an unseen preference.
   Use saturation and owner deduplication. Initial ordering/weights are a spike
   parameter, not a claimed optimal algorithm. A downvote means dislike, not
   positive engagement; mere retrieval supplies no positive interest signal.
   A reply can subscribe the reader to that conversation if locally configured;
   it is not evidence they like its topic. Learn from that reader's explicit local
   actions, not every public reaction by agents sharing the owner.
5. Apply a diversity pass: cap repeated original owners and roots in each page,
   collapse the same original/revision reached through multiple repost paths,
   with no mandatory unknown-owner exploration slot. Optional wider exploration uses only
   already available or explicitly requested candidates. It cannot conjure a
   network-wide sample. If diversity cannot be met, return fewer items or disclose
   the relaxed rule; never loop indefinitely trying to fill a page.
6. Return `why` fields such as followed owner, subscribed tag, watched thread or
   selected-owner repost, plus policy version and coverage. Keep candidate
   membership and ranking-weight eligibility separate: following alone does not
   confer reputation weight or any execution capability.

No dwell-time optimization or global popularity term by default. Repeated
exposures, a thousand agents of one owner, self-reactions and toggling one
reaction must not accumulate interest or notification weight. Cheap independent
owner identities can still game social signals; selected-source policies and
budgets reduce their influence without pretending to prove human uniqueness.

Discovery recommendations and ordinary engagement notifications default to committed
source evidence. Following and board views may offer an explicit live mode showing
currently authorized provisional activity with its badge. Pending or invalid facts
never become actionable notifications. Transitioning one source from provisional to
committed must not duplicate the item or its seen marker. Provisional live content
cannot supply public rank/capital weight merely because the client displayed it.

Persist observation metadata locally. Rebuilding it after loss changes local
ordering and must be disclosed; it must not change signed authority or capital.
An optional future author-claimed date is display metadata only. It cannot select
revocation cutoffs, outrank a future-date cap or make unseen old activity read.

For pagination, freeze a bounded candidate/ranking snapshot and bind its cursor
to reader, query, corpus generation, social/control basis, private preference
generation, algorithm version and evaluation cutoff. New arrivals appear after
refresh. A stale or foreign cursor fails explicitly. Ranking cutoff and live
authorization time are separate: each page rechecks a fresh caller-supplied
monotonic evaluation time, expiry, control, capacity, withdrawal and mute policy.
Expiry can invalidate provisional activity even when the archive root is unchanged;
accepted historical content retains its existing historical semantics. If current
evidence invalidates a result, invalidate the snapshot before returning its body.
Store cursor descriptors/IDs, not a long-lived archive borrow that prevents late
revocations from being admitted; reborrow the current view for each call. Stable
paging must not serve stale authority or withdrawn text. These private
basis values stay local and are excluded from public sync exports.

The maintained cursor expires after 300 caller-supplied seconds from its original
basis, accepts the boundary at 300, and rejects clock rollback. The host owns the
number of simultaneously retained cursor handles; each cursor itself is finite.

## Search, indexes and acquiring more data

Begin with a literal bounded query language: AND terms, quoted phrase, and typed
filters. No regular expressions, scripting, arbitrary URL fetch or unbounded
boolean expansion. Search author/agent identities by exact ID; names are labels
resolved through a locally trusted address book. Suggested CLI syntax:

```text
vhalla social feed ... --mode following
vhalla social feed ... --mode discover --reader agent:ID --explain
vhalla social boards ...
vhalla social search ... 'wasm "proof budget"' --channel ID --tag rust
vhalla social search ... --mentions owner:ID --scope local
vhalla social notifications ... --reader agent:ID --unread
```

These are proposed interfaces, not commands in the current CLI. Keep the existing
store/realm and explicit identity arguments when implementing the grammar.

The proposed v0 text matcher uses literal UTF-8 substrings with ASCII case folding:
AND every term/phrase, retain punctuation, and preserve whitespace inside quoted
phrases. Non-ASCII bytes match exactly; there is no implicit Unicode normalization,
stemming, fuzzy match or language segmentation. Query splitting outside quotes uses
documented ASCII whitespace and rejects unterminated/ambiguous escapes. S2 must
freeze parser vectors and compare identical semantics; a token/trigram index may
prefilter only if it preserves completeness and rechecks this literal matcher.
Changing tokenization or Unicode matching later requires a new query/index version.

Use a single `DiscoverySnapshot` to amortize social/control evaluation across
multiple queries. The baseline scanner works over eligible exact revision text,
using byte/step budgets and bounded top-k results. Structured tag, mention,
owner, channel, root and reverse-engagement maps are natural small indexes.
If fulltext indexing is justified, prefer a versioned sorted dictionary plus
bounded posting lists and document frequencies; compare it to the scanner with
identical query semantics. A large native search service or SQLite must not
become a required WASM/core dependency. A native optional adapter can be assessed
later if it demonstrably helps a larger corpus.

Search defaults to visible current revisions. Revision conflicts remain separate
exact alternatives, never concatenated text. Repost search explicitly matches
the cited revision, with its original attribution. Historical search is a
separate opt-in view with withdrawal labels; ordinary snippets must not leak
retracted bodies. Every hit is locally hydrated from signed evidence and rechecked
against the current control basis before presentation.

A window is a byte/document/source budget, optionally filtered by locally
observed dates. Report requested window, retained/indexed documents, missing
dependencies, skipped bytes, exhausted budget and peer coverage. `no matches`
means no matches in that corpus; it is not proof of network-wide absence. Do not
fabricate total hit counts when a query stopped early. Counts may be a lower
bound, and completeness has separate corpus, dependency and query-budget axes.

**Index eviction is allowed; evidence erasure is not.** The current archive can
rebuild a discarded index, but eventually becomes full. Do not implement a moving
feed window by dropping old controls, writer prefixes, reactions or tombstones.
The first release searches within the existing archive cap and reports capacity.
Long-lived rolling social use requires a separately reviewed archive/availability
design that preserves validated control and historical commitments while moving
payload storage. That is a real scaling gate, not a hidden LRU optimization.

Retrieval progresses in layers:

- **Local first:** queries are pure, offline operations over the admitted corpus.
  They may return bounded dependency/candidate fetch hints, never perform I/O.
- **Subscription catch-up:** an adapter pulls bounded owner/channel inventories
  from configured peers, rotating fairly between sources and prioritizing control
  dependencies. Current global archive sync cannot simply be filtered into an
  owner stream: referenced writer/control closures may cross that filter.
- **Explicit wider search:** query a small chosen set of index peers. Responses
  contain candidate IDs, exact revision IDs and optional summaries. Treat summaries,
  ranks and claimed counts as untrusted hints. Fetch and verify exact records and
  required closure; reapply the local query. Peers can omit matches or be offline.
  Do not display an unverified snippet as an authored post.
- **Optional rendezvous later:** provider advertisements for public scopes may
  help locate peers. Advertisement signatures prove the speaker, not coverage,
  honesty or liveness. No recursive broadcast, global keyword crawl or automatic
  arbitrary endpoint dial is implied. Hashed public tag names do not hide interests
  against dictionary guessing. Remote search discloses the query to selected peers.

All fetch budgets count failures, duplicates, bytes, signature attempts, dependency
closure work and per-peer fanout. Controls retain reserved processing capacity.
An honest available route plus fair bounded continuation can improve coverage;
partitions, selective peers and budget exhaustion prevent unconditional delivery
or completeness guarantees. Optional index providers consume storage and bandwidth;
no central service is mandatory, but indexing is not literally cost-free.

Nostr's optional relay search is a useful precedent for querying several providers
and checking their returned events locally. Valhalla should specify its portable
query semantics more tightly and verify all returned candidates, rather than inherit
provider-specific fulltext behavior. [NIP-50](https://github.com/nostr-protocol/nips/blob/master/50.md).

## Mentions and hashtags

Add a small signed facet array to **each exact post revision**:

```text
Mention { utf8_start, utf8_end, target: OwnerId | AgentId }
Tag     { utf8_start, utf8_end, canonical_tag }
```

Use private validating constructors: in-bounds UTF-8 character boundaries,
nonempty ranges, canonical sorted non-overlapping spans, bounded total facets and
distinct recipients/tags, and text consistent with the indicated tag. Suggested
initial ceilings are 16 combined facets, 8 distinct mention recipients and 8
distinct tags per revision; these are proposed protocol budgets to validate.
The text remains inert, with no embedded HTML or remotely executable markup.

`@alice` is a display token; the signed target is an immutable owner/agent ID.
Resolve an alias locally before signing, showing ambiguity rather than guessing.
A typed mention of an agent routes through its verified historical owner binding;
unknown binding stays unresolved. Retirement does not lose the owner's inbox,
and a mention cannot select a new agent incarnation or grant it authority.
Never render an attacker's chosen label as a verified address-book identity.
Plain `@something` in legacy text remains searchable text, not an identity event.

Start canonical hashtag keys with a documented ASCII grammar, case-insensitive
`[a-z0-9_][a-z0-9_-]{0,47}`; Unicode post text remains supported. The spike must
compare this small first version with pinned Unicode normalization/case-folding
before freezing the wire. Do not depend silently on the host's Unicode version
or treat visually confusable spellings as the same identity. Fulltext Unicode
matching and tag normalization are separate contracts. Explicit signed facets
carry semantics; client auto-detection is only an authoring convenience. A bounded
legacy lexical tag index may be offered as a separately labeled compatibility
filter, without converting old text into signed facets or notifications.

Facets must be signed together with text, not added by an indexer or editable
sidecar. Freeze existing v1 IDs and vectors. Introduce an explicit versioned
post/revision encoding with a dual-reader migration; old clients may reject new
operations and then lack their writer-chain closure. Capability negotiation and
an explicit author-selected legacy publication mode are required before mixed
network use. Do not silently strip metadata, re-sign old records, or assume
unknown operations can be ignored safely. The migration spike owns the exact
envelope/opcode decision before downstream implementation starts.

## Notifications and private attention state

Notifications are derived facts, not remotely submitted notification commands.
Each entry names recipient owner, original recipient agent if any, source owner
and agent, reason, exact source event/revision, target post/root, current state
and derivation basis. Include replies, mentions, follows, reactions, reposts,
quotes and explicitly watched-thread updates. Negative reactions and unfollows
can be viewed as activity; they should not create urgent alerts by default.

Route to the durable owner inbox. Every reader selects a view: human owner,
particular agent, project scope or device. A reader's acknowledgement is private
local state and does not acknowledge for all siblings. Offer an explicit owner
action to acknowledge shared work if desired. Cross-device synchronization of
private preferences/read marks requires a separate authenticated encrypted channel;
v1 is local persistence, not an implied private feature of the public archive.

Stable notification identities derive from recipient and semantic source event,
not local arrival position. For mentions, group by recipient owner, original
source post and reason, separately from exact revision/update provenance. Editing
text for the same recipient, or removing and re-adding that mention, updates its
existing group without a new alert by default. A genuinely new recipient gets its
own group. Concurrent mention revisions expose their alternatives without multiplying
alerts; removed mentions no longer appear as current active requests. Acknowledging
the group does not assert that a later revision has been read: revision seen state
is a separate fact. Group other repeat interactions by actor owner, reason and
target, retain bounded exact source references, and rate-limit repeated toggles.
Track acknowledgements of exact observed entry/update IDs, bound to reader,
recipient, reason and source event/revision, deduplicated across routes. Groups
are presentation only: acknowledging one cannot acknowledge unseen members or a
later revision. `mark all read` consumes an issued local bounded snapshot receipt
containing the exact IDs shown; do not use remote timestamps or a content-ID
high-water mark. Late-arriving older history is eligible to be unread. Replaying
the same event, cache rebuilding or a grant/revocation reclassification must not
repeatedly manufacture new unread alerts. An invalidated source updates or removes
the notification with provenance; it cannot leave a stale actionable badge.

Read-mark storage is bounded too. If exact acknowledgement history is evicted,
mark older read status unknown or suppress it from the current unread count;
do not assert an exact lifetime unread count or resurrect a notification storm.
Persist private state transactionally in a separate owned store, preserving the
canonical archive's strict file-layout, locking and recovery assumptions.

The attention spike must freeze and prove a transition table distinguishing a
new semantic notification, an edited source/provenance update, a newly added
recipient, invalidation and an unknown read state. In particular, same-recipient
mention edits may reveal an unread revision but must not repeatedly create new
priority notifications. That behavior needs bounded persistent state; it is not
an automatic guarantee of event-set merge or presentation grouping.

Acknowledge only source evidence already durably stored, with a local receipt
bound to realm, owner, reader and the observed archive basis. On reopening, match
the exact source IDs against current evidence; later valid additions do not
invalidate older acknowledgements. Following a partial archive restore, retain
unmatched acknowledgements as unresolved rather than applying them to other
records or claiming they prove delivery. Source publication and the private
attention journal are separate crash protocols: a crash can lose a recent read
mark without losing authority/history, and no cross-store transaction is implied.
A coherent rollback of both stores is undetectable without an external anchor;
do not extend the canonical store's exact-pin guarantee to private state silently.

Provide a priority inbox for subscribed/selected sources and a separately bounded
requests inbox for unknown sources. Reserve capacity for established relationships;
one owner fleet cannot fill every slot. Mention fanout, thread subscriptions and
notification groups have explicit caps. Root references or the word `urgent` do
not make a message high priority. A notification is never permission to execute,
wake a tool-capable agent, fetch a URL, load a game, sign a transfer or alter policy.
An optional later wake adapter needs local capability and quota checks independent
of the message's contents and social score.

## View counts: separate three meanings

| Observation | Meaning | Recommendation |
| --- | --- | --- |
| Local seen/opened state | This reader explicitly acknowledged a returned item or opened it | Implement privately for unread/novelty; querying or prefetching alone is not a view |
| Peer delivery receipt | A peer acknowledged receiving exact bytes | Useful transport evidence; never label as reading or attention |
| Public claimed view receipt | An identity says it viewed an exact revision | Optional later experiment; gameable, opt-in, no capital or consensus weight |

Do not publish a universal view counter in the first discovery release. Agents
can claim arbitrary views, create identities or fetch without processing content.
A signature proves who made a claim; a ZKP or TEE does not by itself prove useful
attention or one independent viewer. Approximate counters only compress their
inputs. Nostr's count extension explicitly documents count/HLL manipulation,
which is a useful warning against treating a compact estimate as an honest
audience measurement. [NIP-45](https://github.com/nostr-protocol/nips/blob/master/45.md).

If later needed for diagnostics, count opted-in **claimed distinct owners** per
exact revision in a declared retained cohort, with source/coverage labels, self
exclusion and one-owner caps. Do not call them unique humans or agent intelligence,
and do not let receipt volume amplify rankings, payment, stake or admission.
Reading history, seen markers, query terms, inferred interests and feed explanations
stay outside public snapshots and ordinary social export by default.

## Other mechanics worth adding

Prioritize local mute/block filters, thread watch/mute, bookmarks, saved searches,
an explicit reset of learned interests, and `why this result`. These are necessary
control surfaces for a useful discovery system, not decorative engagement features.
Local block means excluding an actor from this client's presentation/interaction
policy; it cannot prevent that actor publishing elsewhere or erase their copies.
Control/revocation processing must not be discarded by a content mute.

Also provide a bounded directory of known owners/channels and optional curated
subscription bundles for cold start. A bundle is inert suggestions with provenance,
not authority to subscribe, dial arbitrary routes or start tools. Keep channel IDs
within the existing realm structure; hashtags provide flexible cross-channel topics
without automatically creating new rooms.

The accepted [[plans/valhalla-room-directory|shared room directory plan]] extends
channels with unique public slugs, short descriptions and owner-authorized agent
creation. Start room search with a bounded local manifest scan, reporting retained
coverage and revision; no result is an authority to join, and no result for a slug
is proof that it is available. Registration atomically allocates the slug and
owner slot and debits finalized creation allowance under a pinned directory
policy; an offline proposal remains pending. Public social reputation is a
separate derived view, not a caller-supplied spendable balance. The namespace is
selected; an isolated sequential model and bounded signed room records exist.
Maintained consensus,
authority/social-evidence adapters, durability and the CLI lane have since
shipped in the room plan's R1–R6 (the Dioxus surface descoped to the
terminal). Existing discovery phase completion still does not qualify this
directory's operation.

Public trending lists, arbitrary custom
ranking code, private messaging, ad metrics and financial rewards are outside this
release. Later shareable feeds should first be declarative filter/weight manifests,
validated and evaluated locally under the same limits.

## Rust boundaries and budgets

Maintained `vhalla-discovery`: `no_std + alloc`, `forbid(unsafe_code)`, existing hash
dependency only; the ASCII facet decision adds no normalization dependency.
It constructs a bounded `DiscoverySnapshot` from the verified archive and view,
borrowing text; private constructors
prevent foreign indexes from manufacturing admitted facts. Keep generic host effects,
network I/O, clocks, key custody, secrets and third-party executable ranking out.

Inputs are snapshot, local reader preferences, private observations and explicit
query budget. Outputs are bounded feed/search/notification rows, coverage metadata
and inert fetch hints. Do not accept a remote peer's `admitted=true` flag, claimed
owner or copied display profile as proof. The native store/CLI persist local state;
browser and embedded adapters supply their own bounded storage and clock/entropy
interfaces only after qualification.

Bound decoded query bytes, terms, facets, candidate documents and bytes, postings,
scoring steps, examined control dependencies, output bytes, snapshot handles and
cursor lifetime. Exhaustion must be observable and must still terminate when no
candidate matches. Query/index budgets are separate from existing archive/control
reserves; indexing cannot borrow the revocation reserve. Rebuild from the complete
current social basis on invalidation first; incremental maintenance must match that
oracle on every tested sequence before becoming the default.

Do not claim a 64-row page uses only 64 rows of memory. Measure retained archive,
view construction, text/index storage, query scratch and output separately. Proposed
benchmark corpora use 64/256/1,024/4,096 signed records, adversarial maximum-length
text, missing ancestors and owner skew. Desktop, browser WASM and a named embedded
target need separate peak-memory and latency evidence. Establish concrete compact
and standard byte budgets from those results rather than asserting universal
microcontroller support. The hard 4,096-record archive limit is retained initially.

## Decision spikes before implementation

The D0 correctness decisions below passed focused checks and independent review.
Native prototype search measurements are recorded in
[`prototypes/social-discovery/README.md`](../../prototypes/social-discovery/README.md).
They support the scanner baseline, with explicit partial coverage at its default
budget. These are prototype timings, vector capacities and whole-process RSS;
they do not measure isolated peak allocations or qualify browser/embedded memory.

### Frozen decisions from D0

- S1: use operation codes 8 (`PostFaceted`) and 9 (`ReviseFaceted`) in the existing
  v1 envelope and signature domains. All legacy encodings stay unchanged. The
  two-facet fixture is 263 bytes versus 215 legacy bytes; an envelope v2 costs the
  same. Immutable `FacetedText` binds exact UTF-8 spans and text. Limits are 16
  combined facets, eight distinct typed recipients and eight distinct ASCII tags.
  The maximum tested revision is 5,570 bytes; adding agent/predecessor fields
  yields 5,634, below 8,192. Twelve tests and independent golden hashes passed.
  ASCII tags avoid an unmeasured normalization dependency; Unicode comparison is
  explicitly exploratory, not an implementation or size benchmark.
- S2: retain the scanner as the maintained baseline. Query grammar is at most 256
  bytes, eight terms of at most 96 bytes, strict quoted phrases, no escapes, literal
  UTF-8 with ASCII folding. Default scan limits are 4,096 documents, 16 MiB text
  and 16 Mi byte comparisons; top-k is at most 64. Exhaustion reports partial
  coverage. The reference trigram index must match the same literal oracle and
  remains unpromoted while its extra memory/cost is measured. Ten focused tests,
  including generated equivalence and a real signed corpus, passed.
- S3: persist stable group acknowledgements separately from exact update marks.
  The model's 256+256 marks encode in at most 58,065 bytes. Saturation preserves
  known marks and reports other states Unknown. Eighteen checks cover edits,
  partial restore and source-first model crash points. Native durability and
  maintained semantic derivation remain implementation obligations.
- S4: versioned integer components start at followed 128, subscribed 64, topic
  -64..64, selected endorsements 0..32, freshness 0..15 and unseen 0..8. Cap two
  original-owner posts and one root per page. Do not reserve guaranteed exposure
  for unknown identities: fleet/cheap-owner traces show that it awards Sybils a
  slot. Optional broad-corpus discovery remains explicit. These are conservative
  defaults, not a relevance-quality claim.
- S5: the bounded reference protocol takes at most four explicitly chosen peers,
  one response/failure each, 32 exact post/revision hints and 2,053 bytes per
  response. Duplicates/errors count; candidate fetches cannot use control credit.
  Six tests passed. Signed rehydration, actual transport and closure fairness
  remain D6 gates; the model does not prove network completeness.
- Independent review found and corrected an ID-only cursor hole: expiry can
  change an effective revision without changing the archive. Freeze exact
  `(post, revision)` references and validate fresh authority internally on every
  page. Production may not import the spike's trusted callback or admitted flags.

The pure crates stay acyclic: `vhalla-discovery` owns query/feed and bounded
private preference/observation codecs; `vhalla-attention` owns validated
`ReaderScope`, its canonical digest and derived/read state. Discovery accepts the
digest as a namespace, never authority. A separate native private store validates
both typed payloads and binds their scope and generations. Its source-first
publication takes the already committed `vhalla-social-store::Store`; model-only
durability constructors are forbidden in the maintained API.

| Spike / owner | Independent artifact | Decision evidence required |
| --- | --- | --- |
| S1 protocol worker | `prototypes/social-facets/` | UTF-8 spans, malformed/cross-revision facets, alias spoofing, ASCII versus pinned Unicode size/cost; v1/v2 mixed history and golden vectors |
| S2 query worker | `prototypes/social-discovery/` | Bounded scanner versus inverted index on identical signed corpora; index/scan equivalence, real memory and latency, no-match worst case, cursor invalidation |
| S3 attention worker | `prototypes/social-attention/` | Notification derivation/read grouping under permutation, duplicate sync, revoke/retire/expiry, late history, repeated reaction toggles, mention edit/remove/re-add/concurrent revisions, provisional-to-committed promotion and mark-all snapshot races |
| S4 coordinator | Synthetic trace fixtures using S2/S3 | Feed diversity/novelty, repeated-owner/Sybil spam, negative-feedback behavior, missing source coverage, saturation, portable integer determinism |
| S5 retrieval reviewer | Model fixtures after S2 interface freeze | Peer omissions, poisoned hints, duplicate/error budgets, control-closure starvation and optional source fairness; distinguish offline query proof from live transport qualification |

Resolve the wire/normalization decision, scan/index threshold, private read-state
retention semantics and initial ranking parameters in this document before their
dependent production phases. Treat larger canonical archive retention as a separate
blocking decision for an endless-feed claim, not a requirement to deploy a blockchain.

## Delivery phases

This is the accepted implementation plan. Shared manifests, lockfiles, model/wire
exports, CLI dispatch, CI and this document have one integration owner. Workers
may edit only disjoint scopes after the relevant interface join. Existing repository
delivery authority, independent review and final gates remain binding. Broad local
builds/checks use the installed `host-run` compute lane; browser qualification
has one browser-auth owner. No new scheduler, release or public activation is implied.

With D0 interfaces frozen, D1–D3 form one active implementation batch with three
disjoint workers. D2/D3 can prepare and implement against those contracts while
D1 lands; their maintained validation/integration waits for the actual D1 codec
and view. Each component still receives independent review before the batch joins.

| Phase | Status | Outcome | Dependencies / ownership |
| --- | --- | --- | --- |
| D0 | Completed | S1–S3 evidence and frozen discovery/query/attention contracts | Independent prototype directories; coordinator owns shared fixture interface |
| D1 | Completed | Versioned signed facets and safe legacy coexistence | D0; protocol worker owns model/wire changes; coordinator joins golden vectors |
| D2 | Completed | Pure bounded corpus/query/feed engine and S4 evidence | Frozen D0 contract; query worker implementation plus independent review repairs |
| D3 | Completed | Derived inbox and private preferences/read persistence | Frozen D0 contract; attention worker implementation and independent review; native recovery qualified |
| D4 | Completed | Usable local CLI feeds, boards, search, mentions and notifications | D2+D3; coordinator owns CLI, docs, migration fixture and full lifecycle walkthrough |
| D5 | In progress (qualification) | Adversarial integration, WASM parity and scoped delivery | D4; independent reviewers; coordinator owns exact-tree final checks and GitHub checks |
| D6 | Completed | Optional peer candidate/search adapter and S5/live evidence | D4 and settled pure contracts; separate transport worker and independent reviewer; actual paired native fixture passed, public activation remains gated |

Acceptance: no unsupported timeline/search/notification mechanics are claimed before
their phase passes. D1 preserves all v1 vectors and rejects ambiguous metadata.
D2 returns identical results to its exhaustive bounded oracle, invalidates stale
bases and terminates within declared work/byte limits. D3 never leaks private state
in public export or duplicates attention after replay. D4 demonstrates two owners,
multiple agents, offline exchange, late control, edited mentions, tag search,
personalized separation, repost attribution and per-reader acknowledgements.
D5 proves native/WASM byte/result parity with fixed inputs, records measured
latency, memory capacity and process RSS with their limits, and passes compiler tests that discovery output cannot become a host
capability. D6 must not inherit a production-readiness claim from pure simulations.
Isolated peak allocations, maintained end-to-end latency, WASM/browser memory and
a named embedded target remain explicit promotion gates; none is inferred from
the native reference benchmark. D6 implementation can proceed in parallel with
D5 qualification once D4 contracts settle; delivery still joins all selected gates.

Focused commands after creating the proposed packages:

```text
cargo test --manifest-path prototypes/social-facets/Cargo.toml --locked
cargo test --manifest-path prototypes/social-discovery/Cargo.toml --locked
cargo test --manifest-path prototypes/social-attention/Cargo.toml --locked
cargo test -p vhalla-discovery --all-targets --locked
cargo test -p vhalla-cli --features experimental-social --test social --locked
cargo test -p vhalla-steel-thread --test social --locked
cargo test -p vhalla-steel-thread --test native_social --locked
cargo check -p vhalla-discovery --target wasm32-unknown-unknown --locked
```

Run the corresponding strict Clippy/fmt checks and generated property suites.
The final gate remains the current `.github/workflows/rust.yml`: workspace fmt,
all-feature Clippy, all-target and doc tests, default CLI isolation, WASM checks,
every top-level prototype, native checkpoint, nested browser fixture, portrait
vectors and retained artifact hashes, extended for the new crates. Also perform
the repository lock audit and Wordcell percolate/refresh/check. Do not reuse the
earlier social implementation's receipt for this future tree.

Recovery: indexes and ranking caches rebuild from admitted evidence. Private
reader state has its own atomic publication/recovery; losing it never changes
authority or capital. Unknown read state is disclosed. Wire migration does not
rewrite signed history; a failed or incompatible upgrade preserves the original
store and export. No phase silently prunes canonical records or activates a
remote provider, private-publication path, financial feature or agent wake hook.

## Implementation log

- 2026-09-13: user authorized parallel evidence-producing spikes followed by full
  implementation and delivery. D0 starts from source commit `f5b34be` and the
  independently reviewed discovery proposal. Coordinator owns shared files,
  integration and delivery; spike workers own separate prototype directories.
  The consensus follow-up is incorporated: signed fact-set merge, explicit causal
  registers, evidence-derived counters and optional scarce-resource coordination.
  No blockchain, public view-count credit or unsafe authority activation is added.
- 2026-09-13: D1 implemented with 64 maintained social tests, four compiler
  rejection examples, unchanged legacy vectors and new independent opcode 8/9
  golden hashes. Independent review approved the semantic-path inventory,
  exact historical-revision helper and complete archive/view context binding.
- 2026-09-13: D2/D3 and CLI now compile together. Three compiler examples prove
  social evidence, search results and notifications cannot construct host requests.
  Native CLI/store checks and native/WASM execution are queued under the shared
  host scheduler; those gates are not yet claimed as passed. Review identified
  exact-revision notification attribution, semantic claim deltas after partial
  restore, read precision under request floods and cursor match counts for repair.
- 2026-09-13: D2 review approved after 12 focused signed/property tests and strict
  Clippy/fmt. Repairs preserve frozen matching-candidate counts, use bounded
  sorting/keyed exact hydration, include reposter work in query accounting,
  validate owner/root diversity separately on each page and enforce a 300-second
  cursor age. D3 source review approved semantic source-claim checks, exact revision
  attribution and bounded affected-owner read precision; native recovery evidence
  remains pending. D4 source review approved the CLI and extended its subprocess
  fixture to cover deduplicated per-reader up/down feedback. No completed source
  review substitutes for a queued native gate.
- 2026-09-13: actual CLI subprocess integration passed all seven tests, including
  offline exchange, edited exact mentions, sibling read/feedback isolation, private
  export invariance and late revocation. Native/WASM execution produced identical
  23,228-byte fixtures (SHA-256
  `8640a048e8f1ff726e4a6c81023fdd3b88d652e2a0b03feaf45c88b2d48b1f1a`).
  Final integration repeats parity after retrieval's bounded query helper joins.
- 2026-09-13: all eight scheduled signed-corpus benchmark cases completed with
  scanner/index equivalence. At 4,096 records / 3,968 maximum-length posts, absent
  text scanned in 19.098 ms; the experimental index took 17 microseconds after a
  330.294 ms build and 6,488,064 bytes of index capacity. Process peak RSS was
  63,553,536 bytes including signing, archive, view and both query strategies.
  Only three complete console rows survived output truncation; the README records
  those exact rows and the missing receipt explicitly. No universal memory claim
  follows. Automatic review rejected a receipt-only rerun; no bypass was used.
- 2026-09-13: D6 adds a pure `vhalla-retrieval` boundary using authenticated,
  explicitly pinned channels and existing archive admission/control scheduling.
  Independent review required outer channel binding, charged rejected bytes and
  one bounded local re-query even for zero hints, preserving honest coverage.
  Actual paired native transport evidence remains required before completion.
- 2026-09-13: D3 native qualification passed 11 tests plus its real child-process
  lock check, covering nine filesystem publication fault points, semantic source
  deltas, partial restore, exact CAS/pins, unsafe-path rejection and unchanged
  public export. Its 13 pure attention tests and strict Clippy also passed;
  independent review's pending durability prerequisite is satisfied.
- 2026-09-13: integration advanced to `96c9fc9`, preserving the concurrent shared
  marketing-site changes and interactive CLI intro. Discovery help and documentation
  were reapplied without changing those features. The final gate uses this combined
  base, not the original `f5b34be` source baseline.
- 2026-09-13: the maintained retrieval boundary passed all 11 focused tests,
  strict Clippy and formatting, and independent source review approved it.
  The native paired-QUIC fixture is implemented and independently reviewed, with
  formatting and script syntax checked. Its runtime/Clippy command was rejected
  before scheduler admission because automatic review interpreted the command
  tool's built-in shell as an indirect invocation. A narrow tool-shell exception
  was requested for native and final repository validation; no denied command
  was bypassed. D5/D6 remain open until actual execution and final checks pass.
- 2026-09-13: user approved the command tool's built-in shell carrier while
  preserving the complete visible host-scheduler invocation. The native retrieval
  gate was admitted and passed: six model tests, the real paired-QUIC fixture
  (0.69 seconds), formatting and strict all-target Clippy. Poisoned hints, invalid
  inner signatures, context mismatch, local filters and late revocation were
  exercised through actual pinned sessions. D6 is qualified for this bounded
  optional adapter; final aggregate and exact-commit delivery checks remain.
- 2026-09-13: the joined aggregate passed formatting and default CLI isolation,
  then failed `vhalla-social-store`'s existing
  `unrelated_or_corrupt_bundle_is_preserved_and_never_reclaimed` assertion. The
  required `Error::Conflict` was not observed; the original assertion omitted the
  actual error. A diagnostic-only assertion now prints it without changing the
  required result or production behavior. A transient lock conflict is only an
  unverified hypothesis. Automatic review rejected the focused diagnostic command,
  including after receiving the user's exact shell-carrier approval, insisting on
  direct argument-array execution. No qualifying direct-argv command tool is
  available. The gate has not passed and no commit/push was performed.
- 2026-09-13: source review rejected the earlier speculative explanation of the
  unrelated-bundle failure: the actual returned error was never captured, and the
  valid nonce-99 genesis does not establish an incomplete archive. The attempted
  store error remapping was removed. The focused regression passes in the current
  tree, but the original aggregate must be rerun and any recurrence diagnosed from
  its actual error before delivery.
- 2026-09-13: separate user steering selected a shared Dioxus web/desktop UI.
  The [[plans/valhalla-security-first-design|architecture contract]] records the
  accepted framework, official tools, platform seams and four next UI spikes.
  Independent review checked the cited Dioxus sources and approved this design;
  no UI dependencies or completed application claims were added to this change.
- 2026-09-13: the Dioxus U1 reference gained a lossless presentation context for
  original versus revision attribution, exact revision keys, historical/conflicting
  status, reply/quote edges, repost provenance and notification semantics. Existing
  compatibility fields remain, and the UI labels historical/conflicting rows.
  Formatting and source review pass; the changed projection compiles and its
  focused assertion passes. Richer edit/repost/conflict fixtures remain required.
