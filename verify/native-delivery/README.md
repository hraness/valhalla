# Native sender delivery custody

This finite safety model checks one retained sender job through durable attempt
intent, transport outcome, local outcome publication, interruption, reopen,
exhaustion and one explicit resume. It distinguishes the current attempt budget
from accumulated spent-attempt and outage evidence. It does not model receiver
application effects or interpret relay retention as member acceptance.

## Production correspondence

| Model boundary | Shipping boundary | Exercised correspondence |
| --- | --- | --- |
| `Enqueue`, `Select`, `ExactRetryBinding` | `DeliveryStore::enqueue`, `open`, `tick_selected`; canonical `RelayItem` and `EndpointId` | `binding_conflict_limits_and_expired_budget_refuse_before_dial` rejects mismatched scope and immutable identity; the new compound TLS test preserves one real address/name/CA/namespace through restarts. |
| `IntentCommit`, `Transport`, `IntentBeforeTransport` | `tick_selected` commits and synchronizes attempt/uncertainty before `Transport::submit_until` | `exact_job_and_attempt_are_durable_before_transport_and_success_survives_reopen`, `crash_after_attempt_intent_retries_without_reencrypting`, and the TLS wrapper's independent read-only SQL observation before its actual PUT. |
| `OutcomeCommit`, `UncertaintyPreserved` | Receipt checking and refusal/outage handling in `tick_selected` | `denial_preserves_prior_uncertainty_and_original_failure_budget_across_reopen`, `finite_failure_budget_preserves_uncertainty_and_known_capacity_refusal`, and the compound timeout → denial → stopped → resume trace. |
| `OutcomePrecommitRefusal`, `Crash`, `Reopen` | `begin`/`commit` latch `needs_reopen`; `open` validates the same retained store | `failed_receipt_publication_preserves_intent_and_exact_retry` forces a SQL-trigger refusal before commit and requires exact-store reopen. |
| `Resume`, `AttemptEvidenceConserved` | `DeliveryStore::resume` transfers attempts into `JobEvidence::spent_attempts` while preserving uncertainty and bytes | `stopped_jobs_resume_in_place_with_spent_attempts_retained_as_evidence` and the compound TLS test check retained accounting, exact identity and idempotent repeated resume. |
| `CheckedRetention` | `tick_selected` requires the exact digest and a positive supported mailbox position | `hostile_receipt_stops_without_claiming_retention_and_custody_cannot_split`; the compound test reconciles the original real retention receipt after token replacement. |

Production implementation and focused existing tests are in
`crates/vhalla-private-native/src/relay/delivery.rs` and `delivery/tests.rs`.
`formal_relay_lost_receipt_resume_preserves_custody_and_quota` in
`relay/tls/tests.rs` joins this model to the [relay quota model](../relay-quota/README.md).
Its test wrapper loses the completion only after production `TlsRelay` has
received and validated a successful receipt from production `Service`.

## Properties and mutants

`intents`, `classified` and `unresolved` are independent history instrumentation,
not extra production counters. Every committed intent contributes one charge;
only a durably classified outage restores that charge. Thus:

```text
current attempts + spent attempts + classified outages = committed intents
```

Successful submissions and unknown interrupted attempts remain charged. A
timeout classified before a process interruption can be uncharged while still
retaining uncertainty about remote effects. A later denial cannot retroactively
turn that earlier uncertain outcome into known non-retention.

| Configuration | Required result |
| --- | --- |
| `normal.cfg` | All invariants pass with two attempts per budget, two outage outcomes, one interruption and one explicit resume. |
| `uncertain-write.cfg` | The same invariants pass with two interruptions and one precommit outcome refusal requiring reopen. |
| `mutant-early-send.cfg` | `IntentBeforeTransport` fails when transport runs before its durable intent. |
| `mutant-retarget.cfg` | `ExactRetryBinding` fails when changed ciphertext, namespace or endpoint is selected. |
| `mutant-forget-uncertainty.cfg` | `UncertaintyPreserved` fails when a refusal erases prior uncertain custody. |
| `mutant-reset-spend.cfg` | `AttemptEvidenceConserved` fails when resume resets attempts without retaining spent evidence. |
| `mutant-unchecked-receipt.cfg` | `CheckedRetention` fails when an invalid digest or position establishes Retained. |
| `mutant-charge-outage.cfg` | `AttemptEvidenceConserved` fails when a durably classified outage keeps its attempt charge. |

No production bug was established in these transitions. Mutants are deliberate
regressions used to test the properties, not descriptions of current behavior.

## Bounds and assumptions

- One job, one exact original binding, three foreign binding variants, two
  attempts per budget, one resume, two classified outages and at most two
  interruptions. No multi-job fairness, credential-denial batching or capacity
  theorem is claimed. Existing Rust tests cover those separate behaviors.
- Successful local transactions and their barriers are atomic and durable.
  `OutcomePrecommitRefusal` leaves the prior durable intent; `Crash` after a
  completed publication keeps the completed outcome. A production failure
  after COMMIT, during sync or readback, can retain the outcome and latch the
  handle; that intermediate failure boundary is not modeled. This is not a
  SQLite, directory-fsync, physical power-loss or coherent-rollback proof.
- `Due` abstracts eligibility only. It does not prove elapsed wall-clock bounds,
  exponential arithmetic or time-regression handling. The production tests
  retain those checks. No eventual-delivery claim is made.
- An exact valid receipt comes from the modeled honest selected relay. The
  model exercises invalid receipt refusal but does not prove cryptographic
  authenticity or protect against a dishonest transport lying about retention.
  Receipt positions are equivalence-class representatives: 0 is zero, 1/2 are
  supported positive positions, and 3 represents an integer above the production
  `i64::MAX` bound. This is not a claim that literal mailbox position 3 is invalid.
- Canonical item identities are exact symbolic values. There is no
  re-encryption, cancellation, deletion or automatic budget-renewal action.
  Reopen preserves the retained queue; explicit resume is an operator action.

## Validation

The focused 23 September 2026 run explored 27,105 distinct normal states and
233,247 uncertain-write states. All six mutants exited 12 and violated their
named invariant with complete ordered counterexamples. The largest case took
about 7.6 seconds under pinned TLC, one worker, a 512 MiB heap, seed 1 and
fingerprint index 0. These are observations for the checked source/configs.

The checked-in `counterexamples/` traces include model/config/tool hashes and
are explanatory historical artifacts. The complete repository runner produces
fresh evidence from the registered manifest; these files never substitute for
a current check. See [`../README.md`](../README.md) for that command.

Relevant focused Rust commands are:

```console
cargo test --locked -p vhalla-private-native --features relay-tls,client formal_relay_
cargo test --locked -p vhalla-private-native --features relay-tls,client relay::delivery::tests::
```
