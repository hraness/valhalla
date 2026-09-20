# Durable local room activity

This Unix adapter stores signed public room activity separately from social
`Archive` and room-control snapshots. One store is pinned to the complete
network, realm, directory and room genesis. It holds one exclusive advisory
filesystem lock for its lifetime and uses the shared `vhalla-custody` private
file, stable-read, no-follow and ownership checks.

Stored events are local evidence. They confer no consensus finality, current
permission, global admission, delivery, human identity, reputation or host
execution authority. The original signature authenticates the full application
key and signed scope; a local index/checksum alone provides no network authority.

## API and registry trust

- `Store::create(path, scope, limits)` creates only a nonexistent directory.
  Existing or partial state is never overwritten or reset.
- `Store::open(path, scope, limits, expected_pin)` opens without repair. The
  exact scope and immutable resource limits must match. An optional independently
  retained pin detects a differing published state.
- `author_head(full_key)` reads the exact admitted head through its retained
  record and sequence index. No remote advertised head establishes a local floor.
- `append(verified_event, expected_author_head, context, current_registry_digest)`
  prepares admission internally, checks the exact author compare-and-set base,
  and requires the context digest to equal the caller's pinned current digest.
- `recover()` completes one exact prior local admission intent or resolves
  unpublished preparation scratch. A torn authoritative intent fails closed;
  it is never guessed or replaced.
- `read_page(after_cursor, limit)` reads up to 64 records directly by local disk
  ordinal. A local paging cursor is separate from author sequence and consensus
  height and is not proof of global completeness.

The caller **must hold its certified-registry integration lock for the entire
new append call**, serializing registry advancement with the checked admission
and durable publication. `AdmissionContext` must come from that caller's
certified replay path; its digest is an evaluation basis, not a certificate.
The store does not acquire, own, or simulate the registry update lock, nor can
it prove that the supplied local frontier is globally latest.

The store prepares a move-only activity candidate only after loading the trusted
local author head. After every publication sync succeeds it commits that
candidate under the same context. Exact historical byte retries are readbacks,
not new admission or permission refreshes: they remain available after a room
closes. Changed bytes at an existing author sequence, gaps, changed predecessors,
and stale expected heads refuse without creating a new intent.

## Durable transaction

The private root contains `format`, `lock`, `HEAD`, `records/`, `authors/`, and at
most one `intent`, `HEAD.tmp`, and `author.tmp`. Before any successor effect,
`intent.tmp` prepares the future intent; it cannot coexist with those publication
files. The root inventory remains bounded to eight entries. The immutable format records
scope and local capacity limits. Every metadata envelope has a versioned magic,
fixed bounds, exact framing and SHA-256 checksum. Checksums are local integrity
evidence, not hostile-host authentication.

`records/<20-digit-ordinal>` contains one bounded signed event, its exact registry
basis, the preceding local receipt digest and cumulative immutable history byte
count. `authors/<64-hex-full-key>/<20-digit-sequence>` maps to that exact receipt;
a small author `HEAD` points to the latest admitted record. Index lookups verify
full scope, full key, sequence, event ID and receipt digest against signed bytes.
The root `HEAD` pins the latest global ordinal, accounted bytes and receipt digest.

Publication proceeds in this order:

1. Validate current policy, exact author base, scope and capacity while the caller
   holds its registry lock. Write one bounded exact `intent.tmp`, sync that file,
   atomically rename it to `intent`, then sync the root directory before any
   successor effects. This freezes a previously checked local admission
   decision; its acknowledged outcome may still be uncertain.
2. Write the immutable record and sync it and the records directory. Write the
   immutable sequence index and sync it and the author directory.
3. Write and sync the author-head temporary, atomically rename it over that
   author's head, and sync both affected directories.
4. Write and sync the global-head temporary, atomically rename it over `HEAD`,
   and sync the root directory. Only this head exposes the record to paging.
5. Remove only the reconciled transaction intent and sync the root directory.
   Return the stored receipt only after all steps succeed.

A failure after preparation creation is indeterminate. Preserve all files and reopen;
never delete state, reset counters, or sign another event on an assumed outcome.
A byte-identical `append` retry or explicit `recover` can finish a valid retained
intent after later policy revocation because it completes the exact already-checked
local decision, not a new admission. A different pending event is refused. Recovery first syncs the validated intent file and root again, since the original
writer may have stopped before syncing it. Recovery
accepts only exact complete bytes or a known unpublished prefix of that intent.
Writer open remains write-free and reads refuse while scratch remains. Explicit
recovery first validates the exact current head, full format scope and limits,
published tip, and absence of any successor record or publication temporary.
Every available scratch pin/scope prefix must match this state. Structurally
incomplete `intent.tmp` can then be discarded without advancing any head or
returning a stored receipt. A later retry must satisfy the then-current policy
and exact author basis. Complete canonical scratch is strictly signature/scope/
chain checked and synced before promotion; identical retries can finish that
exact previously checked admission after policy revocation. Different complete
pending events, malformed complete scratch, and contradictory effects refuse.

Committed corruption, unrelated temp contents, missing referenced evidence and
torn indexes refuse. A torn authoritative `intent`, including an empty file left
by an older version, remains preserved and cannot be recovered automatically.
This prospective change does not repair old damaged stores or authorize deleting
state. Such repair requires a separate explicit history-bound procedure.

The durable append-only log also provides replayable outbound bytes. This crate
does not claim network delivery, create a separate delivery queue, or track peer
acknowledgments. A delivery adapter can retain its own durable local cursor and
replay pages idempotently; an old exact retry does not append or re-enqueue data.

## Bounds, restart and protection limits

No vector or map collects lifetime history. Startup reads constant-size root
metadata, the last record/author index, and at most one bounded intent. Author
lookups use direct paths; pages allocate at most 64 bounded receipts. Neither
startup nor a page enumerates all author or record directories. Older records
are checked when read; opening is not a complete historical audit.

A local event quota and exact immutable receipt/index byte quota provide
backpressure independently of social Archive's 4096-record limit. They never
prune admitted history. Directory metadata, per-author head files and bounded
transaction files require additional filesystem capacity. Real ENOSPC and sync
errors remain indeterminate; configured logical-byte accounting is not a claim
about physical filesystem allocation. Limits are immutable for this format;
capacity expansion needs an explicit preserving migration, not changing a file.

Restart restores author heads only from this store's own admitted record/index
publication, including events under policies now closed. It does not re-admit
those old events under current policy or produce a fresh authority receipt.
Author indexes, scope metadata and history are durable application state: do not
remove or rebuild them from remote sequence advertisements.

Paths and ancestors must be owner-controlled on a local filesystem supporting
advisory locks, atomic rename, and file/directory synchronization. Symlinks,
hardlinks, unexpected root entries, loose permissions and inconsistent ownership
are refused when observed. As with the repository's existing stores, this is not
a sandbox against the directory owner/root replacing paths, deleting entire
indexes, or rolling back coherent state. Retain an independent exact pin where
local replacement detection is required. Fault tests exercise application
interruptions and reconciliation, not every filesystem or power-loss behavior.
