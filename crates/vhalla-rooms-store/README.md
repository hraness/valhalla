# Native room registry persistence

This Unix adapter retains the bounded signed room registry in an owner-private
directory under a lifetime exclusive writer lock. `Store::create` requires a
new directory. `Store::open` validates the pinned snapshot, retained files, and
optional exact external pin without repairing them. `read_registry` holds a
bounded shared lock and never performs recovery.

`commit(candidate, expected_pin)` accepts an allowed registry extension under
the exact basis. It writes the complete checksummed decision to `intent.tmp`,
syncs that file, atomically renames it to `intent`, and syncs the directory
before writing any successor snapshot or pin. It publishes the immutable
snapshot, replaces and syncs the pin, reads that pin back, then removes the
resolved intent and syncs the directory. A `Publication` is returned only after
these steps complete; I/O errors can leave an uncertain outcome.

`recover()` reconciles the exact complete authoritative intent. For unpublished
`intent.tmp`, it first validates the current pin/snapshot, private paths,
inventory, and absence of any authoritative intent or successor effects. A
complete canonical scratch frame must name the exact current pin and an allowed
registry extension; recovery syncs and promotes it. A structurally incomplete
preparation can be discarded with the current pin unchanged, leaving retry to
the caller. Writer open remains read-only; shared readers return
`RecoveryRequired` while either scratch or authoritative intent remains.
Complete malformed scratch, unrelated snapshots, and ambiguous combinations
are preserved and rejected.

A malformed authoritative `intent`, including an empty intent written by an
older version, still fails closed. This change prevents new torn authoritative
intents; it does not repair already-damaged stores or the captured CI artifact.
Any legacy repair requires a separate explicit procedure tied to independently
retained exact history. Never delete an authoritative intent to force startup.

The file inventory remains bounded to sixteen recognized private regular files.
Only verified obsolete physical copies are reclaimed; registry evidence is not
pruned. The caller must control path ancestors and use a filesystem that
implements atomic rename and file/directory synchronization. An independently
retained exact pin detects replacement; a checksum alone does not prove
freshness or protect against a coherent full-store rollback.

Tests cover all fifteen publication boundaries, interrupted scratch framing,
malformed and unsafe paths, incompatible successor state, exact external pins,
legacy authoritative corruption refusal, and generative restart/retry traces.
The consensus adapter regression also exercises journal commit followed by
interrupted social or rooms preparation and exact replay on restart. These
checks model process interruption on a real temporary filesystem, not arbitrary
hardware failure or physical power-loss qualification.
