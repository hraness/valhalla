# Optional paired retrieval

`vhalla-retrieval` is the bounded candidate exchange for vhalla (valhalla). It is
a pure Rust `no_std` + `alloc` library with no filesystem, dial, task execution,
background retry, subscription, agent wake, or public service entry point.
Applications must explicitly select full peer keys and an already authenticated
paired channel. Installing or building Valhalla does not activate this protocol.

Peers suggest exact post/revision references and supply ordinary signed social
records. A reference is only a hint. Every record passes the maintained archive's
signature checks and resource limits; every presented candidate passes the
maintained query engine against the current local authority view. Remote snippets,
scores, actor labels and assertions of completeness have no input field.

## Contract

1. The caller creates `Request::new` with a fresh OS-generated nonce, a social
   realm, a literal query, an optional canonical tag and a bounded sorted inventory.
   Query text, tag and inventory IDs are intentionally disclosed to selected peers.
   Other filters, private preferences, bookmarks and read state stay local.
2. A receiver uses `Request::from_message` with a full requester key and explicit
   `ChannelScope`. The message must already be a `VerifiedEnvelope` from the
   paired transport. The fixed capability is **`social-facets-v1`**, denoting
   envelope-v1 signed facet operations 8 and 9. Unsupported versions are rejected.
3. `Provider::next` derives committed query/tag hints from its real archive. It
   obtains record pages through `Archive::next_page`, preserving that maintained
   owner/control/dependency scheduling instead of importing search-specific facts.
4. `Round::receive` pins the responder key, outer realm/room/epoch, inner social
   realm, request nonce, exact next response sequence, kind and expiry. Each inner
   record goes through `Archive::ingest`. One invalid record does not prevent the
   remaining bounded records or another pinned peer from making progress.
5. `Round::candidates` calls `DiscoverySnapshot::search_references` once, applying
   the current query, requested tag and all local typed filters, then intersects
   exact hinted references. Missing, filtered or revoked evidence is not presented
   as a matching candidate. Ordinary current-post queries exclude superseded
   revisions; explicit repost queries may legitimately return the exact historical
   revision endorsed. Queries with no hints or hits still report incomplete known
   local history accurately.

`ChannelScope` is independent of the requested social realm. The existing
experimental native transport uses outer realm 1 / room 2 / epoch 1 and can carry
an explicitly requested different social realm. Fresh session binding, audience
and replay admission belong to that paired transport; `Round` does not independently
reconstruct a session or authenticate raw outer frames. The caller supplies fresh
evaluation time and must not route previously consumed sessions into a new round.

The receiving archive is in memory. Successful receive and transport acknowledgment
do not mean durable persistence, attention, approval, agent execution or consensus.
An application requiring durable evidence must persist through its ordinary social
store before publishing a durable receipt or private read acknowledgment.

## Resource limits

| Resource | Limit and accounting |
| --- | --- |
| Selected peers | 4 explicit, distinct full application keys |
| Response attempts | 32 per peer; malformed, duplicate and explicitly recorded transport failures consume credit |
| Response body | 48 KiB; compile-time checked below the native signed-body ceiling of 65,341 bytes |
| Cumulative body processing allowance | 32 × 48 KiB per peer; rejected oversized bodies are charged before returning an error |
| Hint reserve | 16 exact references per peer for the whole round, at most 64 overall |
| Signed hydration records | 5 per response, each at most the archive's 8,192-byte record limit |
| Inner signature attempts | At most 160 per peer; duplicates and invalid signatures consume the same record allowance |
| Disclosed known IDs | 1,024 sorted unique IDs per request |
| Query | Maintained parser limits: 256 bytes, at most 8 terms; no arbitrary remote predicates |
| Local query work | Maintained default bounded query budget; one scan, including empty intersections |

Known peer bodies are charged before retrieval parsing and inner signature checks.
The transport must bound raw frames before allocation/authentication and own its
outer signature/connection budget. `Round::failed` accounts for a known peer's
transport failure or timeout without scheduling a retry; it does not observe the
raw rejected bytes. Counters describe work this layer can observe. Once attempts
are exhausted, subsequent input returns `Budget` without entering retrieval work.
Repeated oversized bodies can make the observed byte counter exceed the processing
allowance; none becomes accepted credit. The observed counter is bounded by 32
attempts times the outer transport's maximum admitted body size (65,341 bytes for
the current native transport). A body exceeding either the per-frame limit or
the remaining processing allowance is never parsed. One peer cannot consume
another's allowance.

`Round::next_peer` rotates the finite selected set; it returns a key, never a route
or dial instruction. Hints cannot add providers. A slow or malicious selected peer
may still withhold useful data; the adapter does not promise service or completeness.

## Coverage and continuation

`Candidates::network_complete` is always false. `local_query_complete` means the
known local query and evidence construction finished within their bounds, not that
all network posts were obtained. `unresolved` includes every hint that was not
returned, whether absent, invalidated, filtered or outside completed query work.
Contradictory requested/local tag filters yield a logically empty result without
claiming anything about network coverage.

The provider's remaining-record count is an untrusted bounded wire observation;
the consumer never uses it to assert completeness or expand work. Each round has a
static inventory and an in-memory archive synchronization cursor. A fresh provider
resets that cursor. **Repeated new rounds with the same 1,024-ID inventory subset
do not guarantee full catch-up of a larger archive**: the same finite pages may
repeat. Cross-round continuation and a reviewed inventory rotation strategy remain
future host-integration work. Query hints similarly cover a bounded local page,
not every match. No cursor or source-completion token is currently serialized.

## Validation and qualification

The maintained pure tests use actual signed social records and authenticated
envelopes. They cover poisoned hints, bad inner signatures, delayed retraction and
control, local filters, channel/nonce/realm/capability/sequence/expiry mismatches,
failure isolation, charged oversized bodies, incomplete zero-hit history, codec
truncation and property-generated invalid frames and failure traces.

```sh
cargo test -p vhalla-retrieval --locked --offline
cargo clippy -p vhalla-retrieval --all-targets --locked --offline -- -D warnings
cargo fmt -p vhalla-retrieval --check
```

The separate [`social-retrieval` experiment](../../prototypes/social-retrieval/README.md)
owns actual paired loopback transport qualification. Its original S5 set model is
not signature, transport or closure evidence. Public networking, provider discovery,
browser transport interoperability, persistent serving, cross-round continuation
and adversarial liveness remain separately gated. This optional library does not
activate any of them.
