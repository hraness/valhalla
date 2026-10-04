# Direct public-room snapshot verification

In development. This Rust crate verifies the public signed records in one
selected peer's frozen room snapshot. It provides source accumulation and receiver
verification; network transport and durable storage belong to its caller.

The transport authenticates both the configured peer and the checkpoint contents.
`Receiver::begin` compares that configured identity with the authenticated identity
and the checkpoint's claimed source. Passing a field copied from an incoming
message as the authenticated identity provides no authentication. Checkpoints
contain hashes, not signatures.

## Source snapshots

`SourceAccumulator::new` binds the full source identity, independent room pin and
a fresh random nonzero source epoch. The caller generates that epoch. `push`
accepts the exact pinned signed genesis first, followed by signed policies or
events. A second genesis is refused. Policies must have the pinned owner's valid
signature; events must have a valid author signature and match the pinned room.
Forks and messages from unlisted authors remain available for the native room
controller to classify.

Each append hashes the previous digest, one-based source position, record kind,
signed byte length and SHA-256 of the canonical signed bytes. `checkpoint()`
returns the resulting count, byte total and digest with the source, room and epoch.
The checkpoint identifier hashes every field. Source snapshots contain at most
one million records and 8 GiB of signed bytes. Empty snapshots are refused.

## Receive and retain pages

A page names its checkpoint and inclusive source range and contains one to 32
frames. `prepare_page` verifies those inputs without changing the receiver. Its
returned token owns the verified records, so their lifetime does not depend on
the incoming buffer. Persist every frame before calling `commit_after_persist`.
The commit checks that both the receiver's previous prefix and target checkpoint
are unchanged. This pure library cannot verify that a caller performed disk I/O.

Partial pages prove canonical signatures, room scope and contiguous source
positions. They do not prove inclusion in the checkpoint's final hash. An altered
prefix containing otherwise valid signed records can pass an intermediate page
check and fail when the last page arrives. Coverage stays `Pending` until the
exact final record count, byte total and digest match. A failed final page leaves
the prior prefix unchanged; earlier valid frames may remain saved as evidence.
`finish()` reports a truncated stream until coverage is `Complete`.

After exact completion, `extend` can accept a later checkpoint from the same
authenticated source, room and epoch. Counts and byte totals must increase
together; repeating an identical checkpoint is a no-op. A changed epoch, rollback,
or same-count change is refused. There is no arbitrary-cursor restore or silent
reset API. A new receiver starts at zero.

The source and receiver keep fixed-size progress plus the pinned genesis. A
prepared page owns at most 32 verified records. No lifetime history map is kept.
Complete coverage describes that selected source snapshot only. It does not
establish current room policy, complete ancestry, other peers' history, message
admission, delivery, or recipient reads.

Run `cargo test --locked -p vhalla-direct-sync` from the workspace root. The
independent hash fixture is checked with
`node crates/vhalla-direct-sync/tools/vectors.mjs --check`.

`tests/schedule_hegel.rs` generates source histories that include the smallest
and largest valid records and events from unlisted authors. Each case mixes
honest pages with repeated, skipped, reordered, damaged, wrong-room and
non-owner frames, stale prepared pages, checkpoint extensions and restarts that
replay the saved frames into a new receiver with different page sizes. After
every step the test compares the receiver with a separate model of the expected
progress. A refused page changes nothing, an honest page is accepted, and
coverage is `Complete` only after the exact history arrives.
