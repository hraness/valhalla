# Historical private control and quarantine

This finite safety model checks sequence-bound owner authority across two
handoffs, observations of signed control claims, uncertain publication, and
durable fork quarantine. The normal case can carry A → B → A: the control that
carries each handoff is still signed by its predecessor; only later sequences
use the successor. The model has four accepted control positions, two owner
devices, one foreign signer, and two process replacements.

The late-join case starts at floor 3 with a checkpoint at sequence 2 and a
retained A → B handoff chain. The chain establishes historical signing
authority, but does not create missing control evidence below the checkpoint.
An exact known observation does nothing, a future claim returns missing, and a
different claim signed by the correct historical owner at a known sequence can
quarantine the local custodian. Observation never advances its floor or owner.

## Production correspondence

| Model boundary | Production boundary | Real regression evidence |
| --- | --- | --- |
| `OwnerAt`, `HistoricalSigners`, `HistoricalAuthority` | `State::owner_device_at` in `crates/vhalla-private-kernel/src/model.rs`; `reconcile_control` in `engine/controls.rs` | `formal_control_two_handoffs_preserve_sequence_bound_observation_authority` completes A → B → A, observes both accepted controls, refuses a current-owner signature at B's historical sequence, and quarantines a real conflicting B signature. |
| `PrepareGrant`, `BeginHandoff`, `PinnedHandoff` | `Kernel::succession_request`, `succeed`, `check_grant` in `engine/succession.rs` | Existing succession tests reject stale pinned grants; `formal_control_handoff_publication_faults_require_reopen_and_exact_retry` covers real handoff publication and exact retained-output retries under all three storage faults. |
| `Observe`, `ObservationOnly`, `KnownHistoryFault` | `observe_owner_control`, `reconcile_control` in `engine/controls.rs` | The two-handoff test refuses future observation without advancing floor, owner or epoch. `formal_control_late_join_distinguishes_missing_history_from_checkpoint_fork` refuses a signed precheckpoint fork while retaining and authenticating a checkpoint-bound fork. |
| `RefuseBefore`, `Publish`, `LoseCompletion`, `Confirm` | `Kernel::publish` in `engine.rs`; `Memory::publish` and `Fault::{Before, After, HangAfter}` in `src/tests.rs` | `formal_control_historical_fork_faults_preserve_custody_across_handoff` checks the pending proof, latch, exact durable fork evidence, unchanged control floor and epoch, and refusal of new live work. |
| `Live`, `Reopen`, `UncertainCustody`, `PersistentQuarantine` | `begin_live`, `Kernel::open`, `pending_fork_evidence`, `fork_evidence` | Both publication-fault tests replace the Kernel using the same retained storage. A committed quarantine survives replacement; a refused precommit observation may disappear with the old process and must be supplied again. |

All four new tests are in
`crates/vhalla-private-kernel/src/tests/succession.rs`. They use actual Kernel
operations, signed account grants, signed owner claims, MLS controls, and the
existing atomic in-memory fault backend. They are conformance evidence at these
boundaries, not a simulation of physical storage failure.

## Cases and counterexamples

| Config | Expected result | Meaning |
| --- | --- | --- |
| `normal.cfg` | All invariants pass | Controls and up to two accepted handoffs, including A → B → A; exact, historical, foreign-owner and future observations; refusal, uncertain completion and process replacement. |
| `late-join.cfg` | All invariants pass | Retained authority chain with unavailable history below checkpoint 2, plus a later handoff. |
| `mutant-current-owner.cfg` | `HistoricalAuthority` fails | After A → B, checking all history against B wrongly refuses an accepted A signature. The same shortcut also permits signatures from the wrong generation. |
| `mutant-stale-grant.cfg` | `PinnedHandoff` fails | Prepare a sequence-2 grant, admit another control, then incorrectly carry the stale grant at sequence 3. |
| `mutant-future-observation.cfg` | `ObservationOnly` fails | Merely observing a future signed claim advances the accepted floor. |
| `mutant-precheckpoint.cfg` | `KnownHistoryFault` fails | A differing claim below the retained checkpoint starts quarantine without the accepted control evidence needed to establish a fork. |
| `mutant-uncertainty.cfg` | `UncertainCustody` fails | A failed quarantine write releases the latch, allowing live work while a pending observation remains uncertain. |
| `mutant-clear-quarantine.cfg` | `PersistentQuarantine` fails | Process replacement ignores a committed fault and resumes with an unquarantined cache. |

These mutations are deliberate regression probes. This slice did not establish
that any of them was a production defect. The model records each observation's
immediate before/after floor and owner, and each published grant's original and
carrying sequences. Checking those records on every transition prevents later
observations or controls from hiding a violation.

## Assumptions and limits

- One custodian serializes its mutations. A successful transaction atomically
  publishes state, retained controls and output. `Before` leaves storage
  unchanged; `After` and canceled `HangAfter` leave a committed image whose
  completion was not confirmed. This is the existing test backend contract,
  not a filesystem, database or physical power-loss proof.
- `Reopen` constructs a new process/Kernel from the exact retained image. It
  discards volatile pending observations. It is not same-handle `begin_live`,
  which preserves the latch and pending proof. A refused write followed by
  process loss may lose that observation; the model makes no durable claim for
  it. A published quarantine has no clearing or recovery-authority action.
- Canonical decoding, signatures, account authority, scope, live validity and
  exact rostered successor enrollment are assumed. Symbolic `exact` and
  `conflict` claims represent equal and unequal signed IDs. No cryptographic
  theorem or hostile-storage proof is claimed.
- The authority state is floor, owner, signer history and accepted handoffs.
  MLS epoch, membership, ciphertext processing and other application state are
  outside that abstraction. The real observation tests additionally require
  the MLS epoch to remain unchanged. Ordinary admitted controls are atomic in
  the model; split publication is explored for handoffs and quarantine.
- Prepared grants can be retained externally across process replacement.
  Operation IDs and exact ciphertext-output retry are checked by the Rust
  tests, not represented by this model. The latest observation is sufficient
  for these step-local safety checks; it is not a complete audit log.
- No fairness, eventual recovery, disconnected-replica agreement, global fork
  discovery, new owner-recovery mechanism, or machine-checked Rust refinement
  is established. TLC checks this finite bound only.

## Validation

The focused development run on 23 September 2026 explored 14,765 distinct states
for `normal` and 1,275 for `late-join`. Both completed; all six mutants exited
12 and violated exactly their named invariant. Each case finished in under five
seconds with one worker, a 512 MiB heap, fingerprint index 0 and seed 1.

The checked-in `counterexamples/` files contain the ordered traces and exact
model/config/tool hashes from that run. They explain failures; the repository
runner still generates fresh evidence for every current manifest case.

Run pinned TLC through [`../README.md`](../README.md). Relevant Rust checks are:

```console
cargo test --locked -p vhalla-private-kernel tests::succession
cargo test --locked -p vhalla-private-kernel owner_fork
cargo test --locked -p vhalla-private-kernel canceled_fork
cargo test --locked -p vhalla-private-kernel missing_precheckpoint
cargo test --locked -p vhalla-private-kernel observing_unsupported_owner_claim
```
