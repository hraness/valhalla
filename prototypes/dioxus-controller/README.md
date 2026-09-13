# Async controller reference

Disposable reference for vhalla (valhalla)'s shared UI. This is a controller
experiment, not a maintained client, renderer sandbox, transport or new store.
It consumes U1's actual `Engine`, `Service`, typed projections and exact intents.
No existing prototype or maintained source is changed by this package.

## Decision

| Approach | Consequence | Decision |
| --- | --- | --- |
| Keep synchronous U0 `UiServices::apply` | Cannot await IndexedDB completion; blocking or early success would misrepresent persistence | Reject for durable integration |
| Call mutable service during render and hold its borrow across an async write | Reissues exact receipts on rerenders; couples route teardown to writes and permits borrow/reentrancy failures | Reject |
| Cache DTOs; explicitly drive one owned operation per reader | Separates rendering from source evaluation and transaction completion; makes cancellation and stale views testable | Use this reference |

The launcher privately owns each `BoundBackend<S>`. Binding verifies a read
projection's expected reader and retains that service without a mutable getter.
U1 lacks a reader accessor, so this one initial query is necessary in the spike.
Every operation checks that binding before invoking `submit`; detecting a wrong
reader only after a mute returned would be too late.

Components read `Controller::display()` and emit `Mutation` values. Rendering
does not call the service or issue a new receipt. The host takes the returned
`Operation` and drives `run(&mut bound_backend)`. The host must drive it outside
the component's render borrow and retain the operation through route changes.
There is no implicit executor, detached task, retry or queue in this crate.

At most eight distinct configured readers, one pending query **or** mutation per
reader, and one cached bounded U1 page per reader are retained. Additional work
gets `Busy`; there is no hidden backlog. A caller can hold an operation pending
indefinitely, so host deadlines remain required. Arbitrary callers retaining DTO
clones are outside the controller-owned memory bound.

## Exact view and reader binding

`PageLease` uses private, process-local allocation identity. It cannot be decoded
from a route, mistaken for another controller's identically numbered page, or
reconstructed after reopening. It is an observation identity, not a credential,
gesture or owner approval. U1's exact source/private-image receipt remains a
second check at the backend; the lease does not replace it.

ACK IDs must be a nonempty unique subset of the exact cached notification IDs,
with at most 64 entries. Seen/bookmark targets must be exact observed post/revision
pairs. Mute is also tied to the current page and the configured reader binding.
Rejected membership or lease checks happen before calling the service.

Selecting a reader invalidates that view's freshness. Requesting a route/refresh
advances the presentation epoch even if a busy backend prevents immediate work.
Thus a delayed completion from A→B, A→B→A, or an old route never installs its old
projection into the current view. Its reader's transaction status still settles;
the UI must request a fresh projection before further writes. Old DTOs may remain
visible only as stale. A refused busy query is not queued automatically.

## Completion and cancellation contract

| Event | Classification | Next step |
| --- | --- | --- |
| Invalid lease/membership, full slot, or wrong backend binding | Definitely rejected before submit | Correct the request; no automatic retry |
| Operation dropped before its first poll | `CanceledBeforeStart` | No submission occurred |
| Query succeeds | `Projected` | Install only if its view epoch is current |
| Mutation succeeds with U1 `Ephemeral` | `AppliedEphemeral` | Never label it saved |
| Mutation succeeds with U1 `Native`/`Browser` | `Published` | Relies on that trusted backend's publication contract |
| Any error after submission started | `Uncertain(error)` and `NeedsReopen` | Reconcile and reopen before more operations |
| Started mutation future is dropped | `CanceledUncertain` and `NeedsReopen` | Same recovery obligation, even if it might not have written |
| Mutation returns a foreign or invalid projection | `InvalidProjection` and `NeedsReopen` | May already have written; never install the DTO |

U1 returns an unphased `Result<Projection, Error>`. The controller cannot distinguish
a rejection before publication from failure after publication or during its final
projection. In particular, `Storage` and `Stale` do **not** justify saying “nothing
was applied; try again.” Tests show the same error with and without an applied
change. The conservative uncertainty classification is intentional.

`attach_reopened` is a trusted launcher seam: it requires `NeedsReopen`, matching
configured reader and a successful query from the supplied backend. It does not
prove from a DTO that a filesystem or IndexedDB transaction was reconciled. The
launcher must actually reopen/reconcile the store first. The reference preserves
an obligation while the controller lives; process crash/restart relies on the
platform journals and cannot be established by this memory-only controller.

## Promotion changes still required

- Replace U0's synchronous interface while preserving its current uncertainty-safe
  error copy. Add cached projections and explicit pending/uncertain state to the UI.
- Give the maintained backend an immutable reader accessor and explicit phased
  mutation outcome, including recovery-required state. Do not expose an arbitrary
  “committed” flag as remote input.
- Move synchronous native filesystem/signature work off the UI event thread.
  This reference drives U1's synchronous `project` inside an explicit operation;
  merely returning a future does not move that work to another thread. Browser
  transaction cancellation and worker choices require their own runtime evidence.
- Preserve advancing clock, source refresh/withdrawal, page cursors, live reader
  lifecycle, operation deadlines and controlled shutdown in the next host adapter.
  This reference has no network subscription or refresh loop.
- Split component-facing contracts from host engine/adapters in the dependency
  graph. A suggested small `vhalla-client-api` crate contains inert DTOs and typed
  requests/outcomes; `vhalla-client` owns the pure engine; `vhalla-ui` depends on
  the API and Dioxus; web/desktop launchers own platform adapters. Conditional
  features in a single shared crate do not provide compiler isolation because
  Cargo features unify.
- Redesign U1's private `Receipt`/`Action` construction when separating crates.
  Host issuance and exact runtime checks are the authority boundary; an opaque
  Rust value alone is not a broker authentication protocol.
- Preserve currently omitted projection facts: exact revision actor versus
  original author, repost provenance, historical/current/conflict context, and
  inbox request/selected lane, clear/conflict flags and source/target links.
- Keep signing and identity outside the renderer. The accepted real-key desktop
  gate requires an isolated broker and an OS-enforced renderer sandbox; the
  same-process closed renderer is insufficient. Existing native networking is
  loopback-only, and browser transport/key custody remains separately gated.

## Validation scope

Focused evidence on 2026-09-13: 18 unit/property tests passed (0.45 seconds),
strict all-target Clippy passed, and formatting passed. Independent source review
approved the repaired page-lease and presentation-epoch boundaries. These receipts
cover this standalone prototype; no maintained or application gate is replaced.

Tests exercise the actual U1 signed `Engine` and `MemoryStorage` CAS model, with
independently controlled async gates before and after application. They cover
cached rendering, exact ACK subset properties, stale leases across pages/readers/
controller instances, route and reader switches, wrong-backend mute denial,
cancellation before first poll/before write/after write, uncertain errors on both
sides of application, and competing image writers. Each property uses 24 traces.

One test explicitly simulates a trusted backend reporting `Native` to check label
mapping. It is not a native persistence test. Other successful model writes remain
`Ephemeral`. Reopening in tests reconstructs the surviving in-memory image.

```sh
cargo test --manifest-path prototypes/dioxus-controller/Cargo.toml --lib --locked --offline
cargo clippy --manifest-path prototypes/dioxus-controller/Cargo.toml --all-targets --locked --offline -- -D warnings
cargo fmt --manifest-path prototypes/dioxus-controller/Cargo.toml --check
```

No U0/U1 dependency tests, native filesystem/socket/process adapter, browser API
or previously denied command runs through these checks. This crate is not wired
into either Dioxus application. Root-owned actual platform qualification remains
separate, and the denied U1-native/social-store checks remain untouched.
