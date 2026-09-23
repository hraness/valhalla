# Private delivery generation transition

Status: proposed contract, not an implemented migration. The existing
`private-host rotate` creates a new mailbox and namespace while retaining old
files. That operation alone does not move live clients or pending delivery.

The first supported transition should require a drained predecessor. It must
preserve the exact MLS device, ratchets, account/room custody, committed outputs,
attempt evidence and verified receipt history. It must never reinterpret an
archive as a live sender or restart counters under the same device key.

## Required transition

1. A trusted operator selects the exact old and new namespace and endpoint pins.
   A relay reply cannot authorize redirection or a higher starting cursor.
   Pause new authoring on all participating controllers and drain all known
   never-retained jobs before fencing. The drain includes encrypted controls.
2. The old service durably fences new nonduplicate PUTs while continuing exact
   retries and PAGE. Its terminal retained head is fixed after admitted writes
   drain. Stopping one client does not fence other clients.
3. Every migrating controller resolves all pending, uncertain and stopped jobs;
   drains staged/deferred inbound work and explicitly handles retained admission
   artifacts; and reaches that terminal mailbox head. Its authenticated kernel
   outbox and encrypted-control enumeration must be complete. A capacity refusal
   or unknown transport result is not proof that an item was never retained.
   After fencing, only exact already-retained retries can resolve uncertainty;
   a job proven absent cannot be newly PUT into the fenced namespace. Refuse
   cutover while any such job remains, preserving its evidence. A separately
   reviewed recovery is required; do not skip it by advancing successor heads.
4. Under exclusive controller custody, publish a durable transition intent
   binding full private context, exact old/new connection commitments, terminal
   relay head, current outbox head and control floor, and prior spent allowances.
   These private records remain local or travel through an explicitly
   confidential controller channel, never public discovery or relay metadata.
5. Initialize the successor with incoming cursor zero and outgoing/control
   cursors at the authenticated predecessor heads. Do not replay the whole
   historical outbox into the new namespace. Publish successor selection and
   seal the old generation only through an exact recoverable transaction.
6. Keep prior generation data readable. Retain cumulative usage and explicit
   approval of any new finite allowance. A new directory is not permission to
   reset attempts, uncertainty, quota evidence or provider authority.

Absent any precondition, refuse the transition and keep the predecessor usable.
After an uncertain transition, reconcile its exact intent and existing stores;
do not delete and recreate either generation. If a browser tab still holds old
custody, its stale generation must fail before networking or output.

## Offline clients and capacity

A drained-only transition cannot finish while a required client has undrained
offline work. Supporting that case requires a separate dual-generation design:
the old namespace remains available read-only, authenticated predecessor/successor
bindings are explicit, and each retained operation is assigned to exactly one
generation with reconciliation of uncertain outcomes. Merely copying ciphertext
to the successor changes the relay digest and retention identity; it is not an
exact retry against the original mailbox.

Reserve maintenance capacity before a mailbox fills. Neither a protocol marker
that itself needs an unavailable final slot nor a quota reset is a recovery
mechanism. The host's durable quota ledger, client finite budgets, and kernel
record/byte limits are distinct; a transition must identify which one exhausted.
No arbitrary history pruning is authorized by this design.

## Acceptance evidence

Use small configured quotas and actual native/browser stores. Cover a clean
drain, concurrent old writers, old exact retries, an uncertain last PUT, a
deferred control, stale browser ownership, unauthorized successor substitution,
an unavailable old namespace, and crashes before/after every intent/selection
publication. Reopen must choose one authoritative transition state. Assert
unchanged MLS image/ciphertext, no duplicate application or acceptance, no
unjustified cursor advance, preserved prior budgets and bounded work. Model the
same transitions with fairness assumptions stated explicitly; model checking
does not prove host durability or availability of an offline participant.
