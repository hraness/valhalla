# U1: typed services and private persistence

Disposable reference code for vhalla (valhalla)'s accepted shared Dioxus client.
This is a **private-state service spike**, not a complete messaging application.
The UI fixture, browser storage qualification and native adapter qualification are
separate evidence layers. No maintained crate is changed by this package.

## Component contract

`Service::project(Screen)` returns owned inert rows; `Service::submit(Intent)`
returns an asynchronous result. The launcher supplies storage and a trusted local
clock. Components receive neither signing keys nor native stores, database keys,
file paths, URLs, transport routes or a generic command/IPC invocation method.

Screens cover Following/Discover, literal search, exact thread, owner profile and
inbox. Rows retain exact post/revision IDs, owner/agent attribution, root, signed
facets, inert text, commitment and ranking explanation. Profile bios preserve
conflicts/incompleteness. Inbox coverage is separate from post-query coverage.
No UI string, including `<script>`, becomes markup or a command in this layer.
Actual escaping, navigation and IPC remain the renderer spike's responsibility.

An issued `Receipt` binds reader namespace, local projection serial and the exact
source/private image. One engine retains one bounded page. Replacing that page
invalidates its receipt; ACK selects only exact issued notification IDs, while
seen/bookmark intents must name an exact post revision on the issued page.
Queries never acknowledge or persist implicit views. There are at most 64 rows,
128 canonical source records and a 2 MiB serialized storage image in this spike.
These are conservative operating bounds, not measured browser memory ceilings.

`Engine::apply_ephemeral` and the synchronous U0 fixture wrapper deliberately
return `Persistence::Ephemeral`. Their success cannot be called saved, delivered
or durable. The single-page engine does not implement the full maintained cursor
or a complete subscription/reconnect loop.

Readers are host-configured `ReaderScope` values admitted against signed source
history. A route cannot select an arbitrary reader. Separate instances isolate
sibling agents/profiles/devices; an owner inbox still derives owner-level activity.
Receipts are not persisted or authentication credentials. A reopened engine starts
a new local serial; a previously held equal receipt can only select exact entries
present on a newly issued equal page. This is exact-observation binding, not proof
of a physical user gesture or an adversarial IPC nonce.

The prototype keeps contracts and adapters in one package for comparison. Promotion
must put the component-facing contract in its own crate and restrict the UI's
dependency graph to that crate. Merely choosing a trait object here does not confine
hostile native Rust code that is allowed to import the entire prototype package.

## Shared engine and source-first state

`Image` is host-only material: a verified canonical archive, typed attention state,
typed discovery state and expected reader. Its strict bounded encoding includes a
domain-separated damage checksum. It is **not** a public export. Public exchange
continues to use the canonical archive's ordinary signed snapshot only.

The engine prepares an opaque candidate, preserving both component generations.
New semantic claims, not merely the union of referenced IDs, must have exact source
records. A source candidate must extend existing history. The host persists before
confirming a change in visible read state. A guaranteed aborted transaction in the
model leaves the old engine and saved bytes unchanged. A platform error may follow
successful publication; uncertain results require reopening and readback.
The deterministic `MemoryStorage` tests model these transitions, not filesystem
or browser crash behavior.

## Native adapter

`NativeService` accepts already opened `vhalla-social-store` and
`vhalla-discovery-store` handles. It accepts no path from a component. Both retained
journals must already be reconciled. It delegates real publication to the maintained
private store, supplying the maintained canonical store for source-first checks.
Only successful publication produces a `Persistence::Native` projection. A failed
publication disables the service until the launcher reconciles/reopens it.

The focused native fixture persists an exact inbox ACK, drops all handles, opens
both stores again, checks the exact read item and verifies unchanged public export.
It is an adapter test, not a repeat of every maintained store fault boundary.
Storage paths/permissions, locking, separate journals and exact external-pin limits
remain the maintained stores' contract. This adapter currently loads an immutable
source image at open; live source refresh/reconnect is future integration work.

## Browser adapter

`browser::IndexedStorage` implements actual IndexedDB calls in Rust/WASM with the
already retained wasm-bindgen 0.2.108 / web-sys 0.3.85 generation. The database name
derives from a locally admitted reader digest; schema and object keys are fixed.
Opening creates schema only. Initial import is explicit, conditional on no image
already existing. Missing, evicted, corrupt or incompatible saved data is an error;
opening never replaces it with an empty reader.

One image contains canonical sources and private state in the same object store.
Before a readwrite transaction, the service verifies signatures and typed state,
checks semantic claim sources and prepares the next complete image. Inside the
transaction's read-success callback, it compares the exact previously read bytes
and issues one `put` synchronously. There is no asynchronous validation or `await`
inside the transaction that could let IndexedDB auto-commit early. This byte CAS
binds both source evidence and private generations across competing tabs.

Only the transaction's `complete` event reports success. Failed requests/abort
report errors. Transaction guards detach handlers; canceling an unfinished transaction
requests abort. The service marks itself unavailable before awaiting publication,
so cancellation or a failure cannot lead to an assumed rollback and automatic
retry. Reopening reads and verifies whichever complete image actually survived.
There is no cross-store half-ACK because this browser experiment uses one image.

IndexedDB open requests cannot be canceled. At most four pending opens retain
self-owned cleanup callbacks until their final success/error event. A blocked open
reports an error but retains its slot; dropping an open future marks it canceled.
Any later successful connection is closed, and a canceled version upgrade aborts.
Successful results buffered in the oneshot also retain a closing RAII owner until
the awaiting caller takes them, covering cancellation after the success callback.
An indefinitely blocked request retains one slot, so repeated cancellation cannot
accumulate unlimited orphaned callbacks or invisible connections. This is bounded
fail-closed behavior, not a claim that the application can force another tab closed.

This atomic image duplicates source bytes per reader and rewrites them with every
private mutation. It is intentionally small and simple; it is not a promoted
multi-reader data layout or a measured performance winner. Splitting source and
private object stores later requires one explicit multi-store transaction and
source-pin CAS, with its own tests.

`browser::qualify(image, now)` is an actual-browser fixture entry point. Supply a
fresh test-owned reader namespace containing signed committed mention evidence.
It tests abort after queued put, exact stale-writer rejection, close/reopen ACK
retention, sibling reader isolation, rejected injected corruption, and late cleanup
after blocked/canceled opens, including success buffered before receiver polling.
The last case proves release by completing a version-2 upgrade. It never
deletes or resets a database, and intentionally leaves its test namespace damaged
after the final corruption case, then leaves that isolated schema at version 2.
Every new qualification uses a fresh reader namespace; it does not reuse real saved
reader state. U0 exposes a fixture-only launch path; the root
coordinator owns running and observing it in the real browser.

Browser storage is same-origin state, not a secret vault or a signing identity.
Same-origin script compromise can read/change it. Checksums do not authenticate
private state, detect coherent rollback, prevent browser eviction or guarantee
physical power-loss durability. The actual browser qualifier covers the specified
blocked-open and cancellation sequences; arbitrary interleavings remain outside
that evidence. Quota exhaustion, real eviction, crash at OS/browser boundaries and
persistence-policy requests remain explicit qualification gaps. This spike owns
no key storage or ambient signing capability.

## Next service: explicit message composition

### Lossless presentation evidence

The U1 projection now keeps the original attribution separate from the exact
revision signer and primary key. Each post also retains current versus historical
or conflicting revision status, placement, reply and quote references, repost
owners and bounded observation metadata. Inbox rows retain the complete owned
`Notification`, including lane, source/root/target references, conflict and
negative/clear status, while compatibility fields remain available to the current
fixture UI. Projection basis, match count and profile roster/capacity state are
preserved for partial-result messaging. The mapping is source-reviewed, formatted,
strict-Clippy clean, and its focused projection test passes. Fixtures for edits,
reposts and concurrent alternatives remain required before promotion.

A complete client still needs a separately reviewed composer/identity/transport
service. Components should submit a bounded typed draft (realm, locally selected
channel or exact reply target, text and validated facets), never arbitrary signing
bytes or an executable string. The host resolves an explicitly configured owner
or agent writer, verifies its current grant/control basis, shows the exact draft
and recipient context for the required owner action, then signs through platform
key custody and persists signed evidence before transmitting through already
paired, locally selected transport. Its source-first publication, sequence
reservation, uncertain delivery and retry semantics need their own fixtures.

No generic `sign(bytes)`, `execute`, arbitrary path, remote-selected endpoint or
financial operation belongs in this component service. The current read/private
preference experiment cannot qualify sending, receiving, pairing or a complete
web/desktop messaging application merely because it displays signed fixture posts.

## Evidence

- Ten pure unit/property tests are present, including exact ACK subsets, inert hostile
  text, stale/foreign receipts, aborted model publication, competing image CAS,
  restart reconstruction, typed source filters, corrupt image rejection and a pre-signature count ceiling
  (64 generated cases per property suite).
- The focused lossless-projection assertion passed after the attribution and
  conflict-context mapping was added. The full suite still requires its ordinary
  repository gate.
- Strict native all-target Clippy passed, including compilation of the native
  adapter test; formatting passed.
- Two compile-fail examples passed: components cannot manufacture the private
  receipt fields or request a generic execution/signing command.
- Actual Rust IndexedDB code compiled for `wasm32-unknown-unknown` with retained
  Rust 1.97.1. This establishes target compatibility, not runtime correctness.
- The baseline Dioxus web release passed the actual-browser qualifier on
  2026-09-13: abort preserved the image; exact CAS rejected a stale tab; restart
  retained the exact ACK; sibling state remained isolated; corruption was rejected;
  blocked/canceled opens were reclaimed, including success buffered before receiver
  cancellation. It used a fresh test-owned namespace and performed no reset.
- The native scheduled test invocation was rejected by automatic approval review
  over the command tool's built-in shell carrier, despite explicit user approval.
  It was not run through an alternate executor. Actual native adapter execution
  remains pending.

```sh
cargo test --manifest-path prototypes/dioxus-services/Cargo.toml --lib --locked --offline -- --skip native::
cargo clippy --manifest-path prototypes/dioxus-services/Cargo.toml --all-targets --locked --offline -- -D warnings
cargo fmt --manifest-path prototypes/dioxus-services/Cargo.toml --check
```

Native execution uses the installed absolute `oompa-host-run` wrapper with the
complete `cargo test ... --lib --locked --offline` argv. The repository final gate
and real browser/desktop renderer qualification remain separately owned and required.
