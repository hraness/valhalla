# Native social archive persistence

This Unix adapter keeps the complete bounded signed archive behind a private
directory and a lifetime exclusive file lock. It creates no agent identities,
keys, listeners, relays, or recovery controllers. Other platforms have no
filesystem activation in this crate.

`Store::create(path, realm, limits)` requires a nonexistent directory.
`Store::open(path, realm, limits, optional_exact_pin)` verifies existing evidence.
`commit(candidate, expected_pin)` retains every prior event ID in the same
archive context and returns a `Publication` only after durability succeeds.
`recover()` resumes the exact complete retained intent; it cannot construct a
different candidate. A lost acknowledgement can be reconciled by retrying the
same candidate or comparing its exact physical/logical pin with reopened disk.

Publication writes a checksummed intent containing the previous pin, next pin,
and complete signed candidate; syncs it and the directory; writes/syncs an
immutable content-addressed bundle; then writes/syncs and atomically renames the
new pin and syncs the directory. It reads back that pin before removing the
resolved intent. Old physical copies are reclaimed only after their signed
archives verify as subsets of the current archive, their exact names/checksums
and private regular-file metadata match, and the current pin is rechecked.
Every signed event, fork, cohort commitment, and tombstone remains in the current
archive. This physical-copy reclamation is not semantic garbage collection.

A complete pending intent blocks different publications. Known partial temporary
files may be completed only when they are prefixes of that exact intent's bytes.
Torn intents and unrelated/corrupt temporary bytes remain on disk and fail
closed. They require explicit operator inspection; the adapter never silently
resets state or reuses an uncertain writer sequence. I/O errors during a
publication are indeterminate. Reopen and reconcile before another attempt.

The adapter requires owner-controlled path ancestors and a local filesystem
supporting exclusive locks, atomic rename, and file/directory synchronization.
It checks observed directory/file permissions, file types, link counts, matching
owner IDs, and bounded lengths. These checks do not defend against the directory
owner or root swapping paths between system calls. They do not verify that the
filesystem or hardware truthfully implements durability.

An optional independently retained pin is an **exact anchor**, not merely a
minimum generation: a hostile disk can put an old signed archive behind a larger
unsigned local generation. Any unequal anchor fails, including a stale anchor
after a legitimate advance; independently retaining the new pin is the caller's
responsibility. Without an external anchor a coherent full-disk rollback remains
undetectable. No checksum is described as rollback protection.

Storage is bounded by the social archive limits (default 1,024 records; hard
maximum 4,096 records and 8,192 bytes per record), at most eight recognized files,
one current full snapshot, one full pending intent, and bounded publication/crash
copies. Obsolete copies do not impose a 64-publication lifetime limit. Unknown
files or corrupt/unrelated copies are preserved and rejected.

Tests cover exact-intent interruptions at every API publication boundary, known
partial and corrupt files, process/handle locking, permissions and links, stale
CAS and forward truncation, durable restart, duplicate-copy reclamation, lost
acknowledgement reconciliation, and the coherent-hostile-rollback limitation.
These are real temporary-filesystem/API fault tests, not physical power-loss
qualification or a claim of durability on every filesystem.
