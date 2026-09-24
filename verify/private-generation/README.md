# Drained private mailbox generations

This finite design model describes two controllers moving from one drained
mailbox to a successor. It checks safety, not eventual availability. An offline
controller may prevent a transition indefinitely.

Each controller can create one application. Applying the other controller's
application creates an acceptance that must also be retained before pause.
An additional old writer can race the last observation, requiring the host's
conditional head check. The selected successor preserves the durable intent,
predecessor archive and cumulative spend through controller crash/reopen.

The normal case checks controller completeness, exact observed heads, generated
output drain, intent-before-selection, preserved spend and archives, and a
permanently frozen predecessor. Six mutations independently remove those
guards. Their historical traces document the resulting failures; every check
must obtain its own current counterexample through `verify/run_tlc.py`.

The controller inventory is a trusted operator input. This model cannot discover
private membership, authenticate that inventory, prove cryptography or establish
filesystem durability. Atomic publication is an assumption. The relay's ordered
head is represented by a set of distinct jobs because this model tests exact
agreement and retention, not wire ordering. The source correspondence below
has been independently reviewed. The manifest remains design-only until the
joined controller and host qualification completes.

| Model guard | Production guard | Regression evidence |
| --- | --- | --- |
| `CompleteInventory` | Host `validate_plan` requires every enrolled stable credential ID and an explicit complete-controller assertion; every receipt must match the plan. | Host dry-run, unknown-receipt and unenrolled-credential tests. This cannot discover an omitted physical controller sharing a credential. |
| `ConditionalHead` | Host compares the ordered retained head and commitment; `FileStore::fence` conditionally commits the fence. | Host changed-head refusal and relay conditional-fence tests. |
| `AutomaticOutputDrained` | Native pause checks authenticated outbox/control heads and both queues; browser drain and pause check sent/control/cursor state, admissions and in-flight work. | Native drained-controller integration and browser generated-output drain regressions. |
| `IntentBeforeSelection` | Native retained generation intent and selected-profile/kernel guards; browser durable pause and atomic successor selection. | Native publication fault tests and real IndexedDB transaction/cancellation tests. |
| `PreservedSpend` | Native successor seeds retain prior ledgers, host TLS snapshots retain credential spending, and browser successor images carry cumulative counters. | Native ledger, host quota-seeding and browser counter-preservation tests. |
| `PreservedArchive` | Old host mailboxes, native queues and pause records, and browser archived generation keys remain saved. | Host history/retry tests, native transition tests and browser archive checks. |

The model's `Prepare` represents controller intent after the fence; host plan
publication happens earlier. Its crash action changes controller availability
and assumes atomic storage publication. It does not explore partial files or
SQLite schemas, IndexedDB transaction interleavings, wire/receipt cryptography,
successor traffic, repeated rollover, byte/retry limits, the sixteen-generation
bound, or stale-tab races. Production fault tests and application journeys cover
those separate implementation obligations; the model is not a proof that every
publication crash recovers or that a storage device makes writes durable.
