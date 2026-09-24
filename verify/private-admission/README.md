# Retained-request review and confirmation

This finite safety model describes the browser owner's two-phase admission
boundary. A review authenticates one retained encrypted contact request and
returns metadata; confirmation must consume the same worker-local permission,
recheck that exact request and current membership, and then enter the existing
kernel admission operation. It creates no new room authority.

## Source and regression correspondence

| Model boundary | Implementation | Real regression evidence |
| --- | --- | --- |
| `Review`, `Consent`, `ExactReview` | `Admission::review` in `browser/src/private/admission.rs`; all `AdmissionConsent` fields in `private/types.rs` and wire codec | `admission_review_is_read_only_and_confirm_consumes_exact_request_once`; `admission_modified_confirmation_or_retained_item_cannot_rebind_review` includes the worker nonce/counter, full context, position, digest, recipient/device, epoch/roster/floor and validity. |
| `Intervene`, `ConsentLifetime` | `Admission::before`, review's initial pending clear, `Session::execute_selected` | `admission_sync_read_and_reload_invalidate_worker_held_consent`; `admission_failed_second_review_invalidates_prior_permission`. Rendering already-returned metadata is not another worker command. |
| `Reload`, `Start`, `ReadRetained`, `Interrupt` | Worker `Broker::dispatch/current/dead` and Session's retained lookup before calling `Admission::confirm` | Existing emitted-worker private-session/delivery tests exercise actual worker teardown and stale IPC. The native regression `admission_sync_read_and_reload_invalidate_worker_held_consent` exercises a new Admission with a distinct session nonce. |
| `Take`, `CheckBinding`, `ConsumedBeforeCheck` | `Admission::confirm` takes `pending` before its checks and first membership await | `admission_refused_confirmation_consumes_permission_before_retry`; `admission_cancellation_during_membership_load_cannot_reuse_permission` polls the actual confirm future until its store load suspends, drops it, and proves corrected retry cannot reuse consent. |
| `CheckMembership`, `CurrentMembership` | Confirm compares full context, epoch, roster, control floor and current owner, refusing quarantine | `admission_membership_change_after_review_requires_fresh_consent`. |
| `Tick`, `LiveAtConfirmation` | Review's offer/enrollment/one-hour minimum expiry; confirm's `Validity::check_at(now)` | `admission_wrong_recipient_and_expired_offer_never_publish` demonstrates end-to-end refusal. Kernel validity checks also defend this boundary; the model mutant does not localize the production rejection to Admission's redundant guard. |
| `Compete`, `Publish`, `ExclusivePublication` | Kernel `load_state` exact-image comparison and `publish` storage CAS | `admission_competing_custody_refuses_without_restoring_consumed_permission` tests early stale-image load refusal. `admission_rival_publication_after_membership_snapshot_refuses_final_cas` pauses the actual confirmation at Store.publish, commits a rival Kernel's offer, resumes the original exact CAS, and proves Conflict with no admission writes or reusable permission. Store atomicity is assumed by the model. |

The Rust tests live in `browser/tests/private_delivery_engine.rs`. They execute
production Admission and Kernel code over a strict in-memory CAS backend.
The gated backends delegate real reads/writes unchanged except for a
single deliberately pending load or a resumed publication boundary. These are adapter conformance tests, not
physical IndexedDB failure or cryptographic proofs.

## Cases

| Configuration | Expected result | Regressed boundary |
| --- | --- | --- |
| `normal.cfg` | All safety properties pass | Bounded good and hostile schedules. |
| `witness-admitted.cfg` | `NoSuccessfulAdmission` fails | Positive reachability probe: a valid admission actually reaches publication. This is intentional coverage evidence, not a production defect mutant. |
| `mutant-intervene.cfg` | `ConsentLifetime` fails | A read/sync/failed replacement review retains old permission. |
| `mutant-reload.cfg` | `ConsentLifetime` fails | A new worker restores the previous worker's volatile permission. |
| `mutant-consume.cfg` | `ConsumedBeforeCheck` fails | Permission remains reusable while confirmation begins validation/awaits. |
| `mutant-packet.cfg` | `ExactReview` fails | Confirmation omits equality with the complete reviewed consent. |
| `mutant-ciphertext.cfg` | `ExactReview` fails | Changed retained ciphertext/position bypasses the byte and commitment checks. |
| `mutant-membership.cfg` | `CurrentMembership` fails | Confirmation omits current owner/membership binding. |
| `mutant-expiry.cfg` | `LiveAtConfirmation` fails | Captured confirmation time is outside the reviewed validity interval; a defense-in-depth model mutation, not a claim that removing one redundant implementation guard permits admission. |
| `mutant-custody.cfg` | `ExclusivePublication` fails | A stale expected storage image is accepted after a competing publication. |

Each mutant changes one explicit model switch; none establishes that the
corresponding production defect exists. The runner must observe the named
invariant, exit 12 and a complete current counterexample. The reachability
probe additionally prevents a vacuous model that refuses every admission.

## Bounds, assumptions and limits

- Two worker lifetimes, at most two successful reviews total, two exact item
  identities, one intervening request, one membership-field change, one rival
  publication, and three clock values. Every consent field can independently
  differ in a supplied packet. Session IDs are assumed distinct and nonzero;
  serials increment within a worker. Randomness, collision resistance and
  overflow arithmetic are exercised by implementation boundaries, not proved.
- Optional state uses presence-tagged records. The tag is model representation,
  outside the implementation consent fields and hostile packet mutations. This
  avoids TLC's undefined record/string comparison without restricting any
  operational schedule, reducing bounds or removing a safety check.
- The full room/anchor/account/custody-device, epoch, roster and control floor
  have separate symbolic fields. Recipient account/device, item position and
  digest, worker/session counter and validity are also explicit. The model
  assumes authenticated decoding and treats unequal ciphertext identities as
  unequal digests. It does not prove MLS, signatures, AEAD or canonical codecs.
- Session's retained lookup precedes Admission's `pending.take()`. The model
  explicitly keeps permission while that lookup is in flight; failure or an
  overlapping request ends the busy broker. Consumption is claimed before
  Admission's own checks/awaits, not before every await in Session. A terminated
  broker cannot expose a late old-worker result. The retained-read action
  conservatively permits a wrong item so confirmation's checks remain tested.
- `Change` represents the Admission API's conservative schedule in which a
  caller changes authenticated membership through another kernel operation
  before confirming. The actual Session dispatcher invalidates permission
  earlier for its own intervening operations. The model permits this extra
  schedule to exercise the independent final membership guard.
- `Publish` represents only successful atomic kernel storage admission. A
  competing writer after the membership snapshot can cause an exact-image CAS
  refusal. Earlier stale-image reads may refuse sooner in production. Atomic
  storage, authenticated reopening, kernel request-consumption checks and
  readback-before-output are assumed contracts; this model does not prove them.
- `checkedAt` is the time captured on entry to Admission confirmation. Existing
  code passes that value through its awaits and into `accept_contact`; later
  clock advances do not retroactively revoke it. This is not a wall-clock
  publication-deadline or instantaneous distributed revocation guarantee.
- There is no fairness or eventual-delivery claim, new device recovery,
  independent-origin security claim, physical browser crash/power-loss proof,
  automatic Rust refinement or general production-readiness assertion.

Run the full pinned inventory using `verify/run_tlc.py` as documented in
[`../README.md`](../README.md). Focused real-code checks:

```console
cargo test --locked -p vhalla-browser --features private-rooms --test private_delivery_engine admission_
```
