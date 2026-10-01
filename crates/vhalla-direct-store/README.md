# Direct room storage

In development. This Rust crate stores local state and immutable records for
direct public rooms. The [room controller](../vhalla-direct-native/README.md)
uses it to save authenticated room operations.

The store binds each directory to one room and account and holds an exclusive
writer lock. It treats application state and record payloads as opaque bytes.
The caller verifies signatures and decides what the records mean. Raw storage
may contain unpublished text and local operation metadata, so network services
must use the controller's public-record filter.

`publish` compares the complete previous state and atomically saves the next
state with up to eight records. Identical key and payload retries consume no
additional capacity; conflicting payloads refuse the transaction. Reads return
local records, with pages of at most 32 entries.

## Grow capacity

Call `store.expand_limits(target)` to increase the record or payload allowance
in the same directory. Both target fields must be at least their current values.
Repeating the current target succeeds without writing. Expansion returns current
accounting and preserves state bytes, records, cursors, usage, and the state
publication generation.

The format supports at most one million records and 8 GiB of record payloads,
subject to the platform's address-size limit. Each record holds at most 16 KiB;
application state holds at most 4 MiB. Database overhead and rollback journals
need additional disk space. Increasing a quota does not add physical storage.
The controller must separately reconcile any application recovery block.

## Reopen after an interrupted write

An `Uncertain` result disables further use of that handle. Drop it and open the
same path with the same room and account. Reopening checks file ownership and
format before SQLite transaction recovery; ordinary reads never recover a
journal. Incomplete or foreign files are preserved and refused.

The `VHDS0002` format marker fixes the room and account. Mutable limits and their
checksum live in SQLite metadata, so interrupted expansion recovers either the
old limits or the new limits in full. Version-one namespaces are refused intact.
File checksums detect inconsistent damage; they cannot detect a coherent edit
or rollback performed by the file owner.

Run the storage tests with `cargo test --locked -p vhalla-direct-store` from the
workspace root.
