# Move a drained private room to a new mailbox

The opt-in private runtime can move cooperating native and browser controllers
to a new mailbox while keeping the same encrypted room and device state. This
is planned maintenance: every controller must be present, fully caught up and
durably paused. It does not recover an offline controller with unfinished work.
The older `private-host rotate` command still refuses.

Use a compatible `experimental-private` CLI and browser build throughout the
operation. See the [pilot plan](../kb/plans/valhalla-private-room-pilot.md) for
tested artifact identities and outstanding cases. Local tests do not qualify a
second machine, an overlay route, sleep or reboot. The
[transition contract](private-rotation-contract.md) explains the invariants.

## Prepare the participants and routes

Inventory every controller using the current namespace, including pending
joiners and controllers whose transport credential was revoked. Membership is
not a complete controller inventory. Record each controller's room, anchor,
account, device and stable transport credential ID privately. The host verifies
the supplied receipts and credential coverage; the operator remains responsible
for the completeness of this inventory. Receipts are local operator evidence,
not peer signatures or admission authority.

Keep the host home, controller stores, profiles and maintenance files private.
Native directories must be owner-only (`0700`), with private files (`0600`).
Preserve the original stores and use new output names. Do not restore a backup,
delete a queue, change a namespace in place or copy a live device to perform
this operation.

Choose a fresh 32-byte transition identifier, fresh namespace and unused
loopback listener for the successor. Retain the CA and TLS name. The host serves
the predecessor and successor on their separate saved ports after cutover;
it keeps old messages readable and allows exact retries of already saved items.
New writes to the predecessor refuse permanently. Each earlier mailbox accepts
only the credentials enrolled before its transition. If all of them are later
revoked, `private-host serve` refuses to start and names that mailbox directory
and its credential indexes. `private-host replace-credential HOME INDEX` issues
a fresh token for one of them without resetting its quota.

For a browser, keep the same gateway origin and saved browser identity. Gateway
configuration version 2 accepts one active route and up to 15 `retained`
routes. Each route has its own namespace, browser capability and pinned native
TLS upstream. Retain the old route and capability for reads and exact retries.
See the [gateway configuration](../crates/vhalla-cli/src/private_gateway/README.md).
Changing the browser origin does not transfer its IndexedDB state.

The existing Tailcat LaunchAgent template forwards one saved port. It does not
configure all generation ports. Multiport remote forwarding needs its own
reviewed configuration and route tests before a remote transition.

## Drain and pause each controller

Stop new authoring and let delivery finish on every controller. Drain incoming
applications, generated member acceptances and encrypted membership controls
until every controller reaches the same stable relay head. Resolve stopped,
pending, uncertain and deferred work first. Pause before capacity exhaustion;
acceptances and the final drain still need their ordinary capacity.

For a native controller, stop its agent cleanly after the drain. Its selected
delivery profile must have complete scan history from `initial_cursor: 0`.
A profile that started at a later checkpoint cannot manufacture that history
for maintenance. Use `delivery-status` on both normal and control streams while
the agent is stopped, then run:

```sh
vhalla private delivery-pause /absolute/account /absolute/room \
  --config /private/controller/delivery.json \
  --transition HEX64 --head TERMINAL_HEAD \
  --out /private/controller/pause.receipt
```

If the retained scan contains bootstrap records, privately inspect each exact
record through its dedicated admission workflow first. Supply the sorted,
duplicate-free JSON array of their retained digests with
`--reviewed-bootstrap /private/controller/reviewed-bootstrap.json`. Omitting or
adding a digest refuses. This records operator review; it never accepts a join
request or creates room membership. The pause command rechecks the complete
scan, authenticated outbox, controls, acceptance records and spent allowances
before durably preventing further room mutation.

In the browser, open **Move a fully synced room to its next mailbox**. Enter the
same transition and terminal head, then use **Check next drain page** until it
offers the pause receipt.
Each action scans a bounded page. Review a changed head and explicitly restart
the scan only before a durable pause. Save the `.vhpause` receipt through the
private operator channel. The browser's pause and room publication guard are
stored in one IndexedDB transaction; old tabs cannot publish into the paused
or superseded generation.

Keep each original receipt. Native receipts contain separate normal/control
queue accounting; browser receipts preserve the browser's shared transport
accounting. These counters are not interchangeable.

Inspect a receipt into a new private JSON file when preparing the host plan:

```sh
vhalla private-host generation-inspect /private/controller/pause.receipt \
  --out /private/operator/controller-view.json
```

This command validates the receipt's format and field consistency and writes
its context, commitments and counters. It does not open a host or room store,
change the receipt, verify a peer signature or assert that a supplied receipt
came from the selected physical controller. Keep the JSON private alongside the
original. Its `controller` object supplies the plan fields except
`credential_id`, which you must map to the host's enrolled identity separately.
The output file must be new and its containing directory owner-only.

## Check the private host plan

Stop the exact host service after all controllers are paused. Leave its home
and stable maintenance lock intact. Create a private receipts directory with
one file named `CONTROLLER_ID.receipt` for each participant, containing its
unchanged binary receipt. Prepare one private JSON plan with these fields:

| Field | Required value |
| --- | --- |
| `version` | `1` |
| `complete_controller_inventory` | Explicit operator assertion `true`, after inventory review |
| `config_sha256` | SHA-256 of the exact current host `config.json` bytes |
| `transition` | The shared 64-character lowercase hexadecimal identifier |
| `generation` | Current zero-based generation ordinal |
| `predecessor`, `successor` | Exact old and selected new namespaces |
| `successor_address` | The selected unused loopback `IP:PORT` |
| `expected_head`, `items_commitment` | Common terminal head and ordered-item commitment from every receipt |
| `controllers` | Complete list described below |
| `allowances` | Explicit additions to cumulative relay allowances, or `[]` |

The host also requires those bytes to be the encoding that the current release
writes. A home created by an older release can hold an equivalent `config.json`
in an older encoding, for example one without the `mailbox` field.
`generation-check` then refuses and names the fix: while the service is stopped,
run `vhalla private-host renew HOME --leaf-days N` once. It issues a new serving
certificate under the same CA and rewrites `config.json`, keeping the TLS name,
credentials and mailbox. Compute `config_sha256` from the rewritten file.

Each controller entry contains `credential_id`, `room`, `anchor`, `account`,
`device`, `controller_id`, `original_profile_binding`, `profile_binding`,
`endpoint` and `receipt_commitment`. Copy the exact receipt fields and the
privately established credential mapping. Stable credential IDs come from the
host configuration, not credential indices or token bytes. All enrolled IDs,
including revoked ones, must be covered. At most 32 controllers are supported.

An allowance entry contains `credential_id`, `additional_items` and
`additional_bytes`. Each addition is bounded to 4,096 items and 256 MiB. Prior
spending remains charged. An empty list grants no new capacity. Client byte,
attempt, queue and kernel storage limits remain separate constraints.

```sh
vhalla private-host generation-check /private/operator/host \
  --plan /private/operator/plan.json --receipts /private/operator/receipts
vhalla private-host generation-prepare /private/operator/host \
  --plan /private/operator/plan.json --receipts /private/operator/receipts
vhalla private-host generation-fence /private/operator/host
vhalla private-host generation-cutover /private/operator/host
```

`generation-check` validates without publishing a transition. Prepare saves the
exact plan and receipts. Fence checks that the complete mailbox still has the
reviewed head before refusing new nonduplicate writes. Cutover carries the quota
ledger into the successor and publishes the sealed host selection. Keep the
resulting `generation-N.fence.json` with the plan and receipts.

From prepare until cutover or recovery finishes, `private-host serve` refuses to
start. An installed LaunchAgent or systemd unit that restarts the service
therefore cannot reopen the old mailbox and change its head mid-transition. Once
prepared, finish the fence and cutover; after that the service starts with the
successor selected and the earlier mailbox kept for reads and exact retries.

## Select the successor on every controller

Prepare a native successor profile with version `2`, no `lineage` field, the
same full context and TLS identity, the new namespace/address, a fresh absolute
state directory and `initial_cursor: 0`. Preserve retry policy, queue limit and
acceptance setting. Its `max_bytes` is an explicit cumulative ceiling that may
stay unchanged or increase up to 1 GiB; a new directory does not renew it.

```sh
vhalla private delivery-transition /absolute/account /absolute/room \
  --config /private/controller/delivery.json \
  --successor /private/controller/successor.json \
  --receipt /private/controller/pause.receipt \
  --fence /private/operator/host/generation-1.fence.json
```

The command replaces the existing selected profile atomically with version 3.
Keep using that selected path for later launches. The successor starts incoming
delivery at zero and outgoing/control progress at the authenticated predecessor
heads. Historical ciphertext is not republished into the new mailbox. The old
profile, receipt, queues and transition intent remain available for recovery.

In the browser, select the successor connection profile and host fence file,
enter the cumulative attempt ceiling, review the exact room, namespace, profile,
fence and paused receipt, then confirm. The successor profile uses the same
gateway origin and cursor zero. Confirmation is specific to this worker and
expires; changing selection or reloading requires a fresh review. The old
generation is retained, and the successor is selected atomically.

Restart the host and gateway with their reviewed selections. Reopen the same
controller stores and issue fresh finite agent grants as needed. Verify one
numbered application and authenticated member acceptance through each route,
then read predecessor history and retry one exact already-saved item. Check
that old spending and original ciphertext remain unchanged. Local success
qualifies only the tested build, storage and routes.

## Recover an interrupted transition

Retain all stores and files and rerun the exact operation that was interrupted.
After fencing, `private-host generation-recover HOME` reconciles the saved
intent and finishes the successor selection. It never unfences the predecessor.
Native `delivery-transition` accepts the same receipt, successor profile and
fence for exact recovery; it refuses substitution. Browser reopen consults the
saved selector and pause before accepting mutations.

If the head changed after controllers paused, preserve the pauses and pending
plan. Automatic unpause, replacement planning and recovery of the added work are
not implemented. A damaged or inconsistent partial store also refuses rather
than being overwritten. These cases need separately reviewed recovery.

At most 16 generations are retained. Browser lifetime transport bytes remain
capped at 1 GiB and cumulative attempts at 65,536. Native queue byte ceilings
are at most 1 GiB. Exhausting a lifetime or room-storage limit requires a
different reviewed migration; this command does not erase history or renew
agent/provider authority.
