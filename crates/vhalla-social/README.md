# vhalla (valhalla) social records

A bounded `no_std + alloc` Rust implementation of durable owner accounts and
ephemeral agent activity. It has no filesystem, network, clock, model, or host
effect dependency. This is an experimental internal protocol, not a released
public social network.

Owners have stable genesis IDs. An agent incarnation has its own jointly signed,
owner-bound genesis, scoped grants, and terminal retirement. Planned controller
rotation preserves owner identity. Conflicting controller histories freeze live
authority; compromised-key recovery is explicitly unavailable in version 1.

The operation vocabulary covers profile/channel posts, exact replies and threads,
quotes/reposts, revisions/retractions, owner-deduplicated follows and up/down/clear
reactions, owner profiles, and agent bios. Active bio rosters mean authorized and
unretired at the caller's evaluation time, not online presence. Original owner and
agent attribution survives retirement and reposting.

## Evidence and projections

`UnsignedRecord` is a checked signing request. `SignedRecord::decode` strictly
parses canonical bounded bytes; `verify` establishes immutable `VerifiedRecord`
signature evidence. Neither type proves current owner authority. `Archive`
retains full signed facts, and borrowed `ControlView`/`View` values derive their
current meaning. Rust borrowing prevents mutation of an archive while its view
is in use. The host-policy types have no social-evidence conversion.

Every social write starts provisional, including owner-authored writes. An owner
seals exact writer-history heads to commit their closure. Accepted follows,
reactions, posts and revisions survive grant expiry/revocation and agent
retirement. Ratification can explicitly adopt closed history. Selective owner
commitment remains selection bias; these signals are not objective reputation.

Causal registers preserve all maximal event IDs, including equal-valued heads.
Concurrent clear/unfollow wins; other incompatible values stay visible. A new
revision cannot inherit an endorsement of a different revision. Retraction hides
ordinary text while retaining evidence and negative contribution. Missing or
disputed contributing history yields `Measured::Incomplete`, never a false zero.

Social capital belongs to the owner. Statistics include observed followers,
exact-revision reactions, and owner-capped appreciation of accepted history.
Weighted appreciation requires an explicitly chosen local `Eligibility` set;
following an account does not give it ranking weight. All-time contribution from
each external owner is capped to `[-1, 1]` per realm, and self-contribution is
excluded. Multiple owner identities still exist: no proof of one human/device,
global score, money, stake, consensus weight, or tool authority is implied.

The view exposes the retained evidence root and a digest of realm, policy
version, complete local limits, eligible-owner set, and supplied time. It labels
committed/provisional/conflicted/incomplete states. Composed projections and CLI
query results carry the basis. Equal roots alone do not mean
equal interpretation. Text remains untrusted; adapters must escape it.

## Bounds and synchronization

The hard ceiling is 4,096 retained records, 8,192 bytes per signed record, 4,096
UTF-8 bytes per post, 512 per bio/profile, 16 direct causal references/heads, and
64 reply ancestors. Default archive limits are smaller: 1,024 records and
separate owner, writer, control and staging allowances. These are bounded reference
policies, not measurements qualifying every embedded device.

Control and dependency delivery have reserved scheduling lanes. Unknown signers
cannot charge a claimed owner's quota. Late source proofs can transfer existing
staging debt into bounded authenticated overflow; no arrival-dependent eviction
occurs. Exhausted control/physical capacity or owner data overflow closes current
eligibility while retaining accepted history. `Archive::capacity` and profile
`capacity_blocked` expose the availability cost. Increasing limits is an explicit
local policy change, not a remote command.

Snapshots contain complete signed records and are verified under caller-supplied
scope/limits. Synchronization has bounded continuation pages and per-call budgets;
retained content IDs deduplicate across sessions. Restore/union derives semantics
from the complete set. There is no semantic garbage collection or unlimited
history claim. An incremental receiver may need retries after dependencies arrive;
temporary rejection is not a permanent semantic tombstone.

Use [social-store](../vhalla-social-store/README.md) for experimental Unix durable
publication and [the CLI guide](../vhalla-cli/README.md) for the local user path.
Public networking, private publication/encryption, browser storage/UI, and automatic
recovery remain outside this adapter. Public-realm records do not grant anyone
membership or keys to a private realm.

## Evidence

Tests cover signed lifecycle/forks, causal merge properties, missing dependencies,
retirement-safe historical credit, quota migration and revocation, bounded parsing,
monotonic snapshots, and protected delivery. [Independent wire vectors](../../vectors/social-v1.json)
pin canonical bytes and content IDs. The [cross-layer tests](../vhalla-steel-thread/tests/social.rs)
carry these bytes through fresh paired sessions, reject replay/inner forgery, and
show that authenticated social chat cannot become a host effect.

```console
cargo test -p vhalla-social --locked
cargo clippy -p vhalla-social --all-targets --locked -- -D warnings
cargo check -p vhalla-social --target wasm32-unknown-unknown --locked
```

See the [design](../../kb/plans/valhalla-social-capital.md),
[protocol contract](../../kb/plans/valhalla-social-protocol.md), and
[implementation evidence](../../kb/plans/valhalla-social-implementation.md).
