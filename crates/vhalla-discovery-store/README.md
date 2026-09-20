# Private discovery persistence

For vhalla (valhalla), this Unix adapter stores typed `DiscoveryState` and
`Attention` components in one explicit private reader directory. It requires
owner-controlled local path ancestors, cooperating writers, advisory file locks,
atomic rename, and working file/directory synchronization. It is not a hostile
OS-account sandbox or a browser storage adapter.

The directory is **separate from the canonical social store**. `create` rejects
that store and its descendants, including parent-path aliases, before creating
anything. Its strict inventory contains only `lock`, `state`, optional `intent`,
unpublished `intent.tmp`, and optional `state.tmp`. Owner modes are 0700 directories / 0600 regular files;
observed symlinks, hardlinks, FIFOs, mismatched ownership, unexpected files and
oversized files fail closed. Opens use no-follow/nonblocking flags and verify
opened metadata. No secret key is stored by this adapter. Sharing an OS account
does not provide secrecy from another process with the same access.

`PrivateState::new(scope)` constructs both codecs for the same validated reader.
Use `attention()` / `discovery()` to clone a component, apply an explicit local
change, then `with_attention` / `with_discovery` to assemble a typed candidate.
Both codecs are revalidated at publication. Generation cannot decrease; changed
bytes at an unchanged component generation are rejected. An exact private `Pin`
compares the complete current image, not only a caller-claimed generation.

`Store::commit(candidate, expected_pin, &social_store)` requires the independently
locked canonical store to have no pending publication. Every newly claimed
observation, seen item, notification update or group witness must reference exact
source records in that durable archive. Delta checking compares semantic claims
per component: an old reference to the same ID cannot excuse a new read claim.
Bookmarks and subscriptions are inert references and may point to absent future
content. Missing old read/observation sources after a partial archive restore stay
unresolved; unrelated preference edits can still publish.

Publication writes a complete checksummed `intent.tmp`, synchronizes it, atomically
renames it to authoritative `intent`, and synchronizes the directory before any
successor state write. It writes/synchronizes a temporary exact candidate, renames it over the
old private image, synchronizes and reads back the new image, then removes only
the matching intent and synchronizes cleanup. At most one pending candidate is
retained. An existing complete intent allows only that exact candidate or explicit
`recover`; a torn intent is preserved and rejected. New missing sources block
recovery while the old image remains current. Once the new image was published,
missing sources are old unresolved claims; recovery may finish cleanup.

`open` validates retained preparation without modifying it; `recovery_required`
includes both preparation and authoritative intent. Explicit recovery (or an
exact commit retry) promotes complete canonical preparation only after validating
the exact current private image, reader namespace, component generations and new
canonical source claims. A structurally incomplete preparation may be removed only
after current-image and source readiness checks, with no authoritative intent or
successor temporary image present. That cleanup leaves the private pin unchanged;
the caller must retry the candidate. Wrong-base/scope, malformed complete frames,
and ambiguous combinations are preserved and rejected. Empty or torn authoritative
intents written by older versions remain fail-closed; this change does not repair
legacy damaged stores. Never delete an authoritative intent to force opening.

Any uncertain publication requires reopening and reconciling the retained exact
intent/state. A failed pre-intent write does not establish read success. The
canonical source publication and private journal are separate crash protocols:
there is no transaction spanning them, and a crash before a private durable intent
can lose a recent acknowledgement without losing social authority/history.

`Pin` is private and separate from the canonical social pin. Its checksum detects
damage, not freshness. Retaining an exact private pin independently can detect a
different coherent private image; without it, coherent rollback is undetectable.
Neither the public archive nor its export contains private preferences, interests,
observations, search history, read marks, private pins or this directory's bytes.

Focused native tests exercise eleven actual filesystem publication cut points,
zero/mid-write preparation, promotion interruptions, legacy intent refusal,
source-before-private ordering, semantic claim deltas, partial archive restore,
exact CAS/reopen, public snapshot invariance, same/descendant path rejection,
permissions/links/FIFO/unknown-file rejection, real process lock exclusion and
coherent rollback with/without an independent private pin. Use the repository's
host scheduler for these native/process checks:

```text
cargo test -p vhalla-discovery-store --locked --offline
cargo clippy -p vhalla-discovery-store --all-targets --locked --offline -- -D warnings
```
