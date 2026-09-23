# Sealed host recovery

This finite safety model checks one replacement of two existing selected data
files plus `config.json` and `complete`, followed by up to two interruptions.
It distinguishes a stopped process, which leaves the kernel's visible directory
state intact, from power loss, which may recover a previously durable marker.
It checks recovery source retention, exact snapshot admission and fail-closed
refusal. It makes no liveness or physical filesystem qualification claim.

## Source correspondence

All production symbols below are in
[`private_host/config.rs`](../../crates/vhalla-cli/src/private_host/config.rs).

| Model action or predicate | Production boundary |
| --- | --- |
| `Backup`, `MarkFiles` | `begin_seal`: every selected old file and old config is backed up before the durable `files` marker. |
| `WriteFile`, `SealFiles`, `WriteConfig`, `WriteComplete` | Successful `rewrite` calls, `seal_files` and `commit_seal`: data precedes the `committing` marker and the new config/complete pair. |
| `NeedsRestore`, `RecoverRestore`, `Restore`, `RestoreComplete` | `recover_seal` restores a `files` transaction, a torn pair, or the still-old config; `restore_seal_backups_with` validates every enumerated backup first, copies individual files without consuming backups, then rewrites `complete`. |
| `CanKeep`, `WholeSnapshot`, `RecoverKeep`, `ValidateRestore` | A matching config/complete pair is only a branch selector. `recover_seal` always calls `load`, which checks every expected file commitment, before cleanup. |
| `UnlinkPresent`, `UnlinkAbsent`, `SyncMarker`, `Cleanup`, `Finish` | `remove_seal_scratch_with`: visible marker removal, unconditional directory durability barrier, individual backup removal, final directory sync. |
| `Read`, `SealedAdmission` | `load`: every admitted home matches one complete config and all its data commitments. |
| `CorruptBackup`, `DriftFile`, `Refuse` | Two bounded integrity-failure examples: a corrupt rollback backup refuses before restoration; a matching new pair with a drifted live file refuses before cleanup. |

`RestoreEvidence` requires the intact selected backup set during restoration.
`RestartEvidence` requires a config backup when a nondamaged interrupted
transaction reappears. Corrupt inputs are separately marked uncertainty; they
are not promised automatic repair. `RefusalKeepsEvidence` compares visible
bytes and retained evidence, permitting the OS to persist an earlier unlink
without a new service write.

## Cases and the discovered retry defect

| Configuration | Required result |
| --- | --- |
| `normal.cfg` | All six safety invariants pass. |
| `uncertain.cfg` | The same invariants pass with one bounded integrity fault. |
| `mutant-consume.cfg` | `RestoreEvidence` fails when restoration consumes a backup. |
| `mutant-cleanup.cfg` | `RestartEvidence` fails when cleanup precedes marker durability. |
| `mutant-absent-marker.cfg` | `RestartEvidence` fails when a retry skips the barrier because the marker is already visibly absent. |
| `mutant-pair-only.cfg` | `SealedAdmission` fails when config/complete agreement alone admits a home with mismatched data. |

The absent-marker mutant represents the code before this change. TLC found:

1. The new files and config/complete pair are sealed.
2. Cleanup unlinks the marker, but the process stops before directory sync.
3. Recovery sees no visible marker and a valid sealed home.
4. The former cleanup code skips the pre-cleanup sync and deletes the config
   backup; that unfenced deletion may persist.
5. Power loss restores the older durable `committing` marker with no config
   backup. `recover_seal` then refuses despite the otherwise valid sealed home.

The repair syncs the directory before deleting backups even when the marker
was already absent. This establishes the missing ordering requirement. The
counterexample does not demonstrate observed APFS corruption, mailbox data
loss or a change to retained message authority.

## Rust regressions

The `formal_host_recovery_*` tests in the same source file cover:

- `absent_marker_sync_failure_preserves_every_backup`: inject failure at the
  first actual cleanup sync after marker absence; no backup may be deleted.
  It exercises the production cleanup helper, not a copied algorithm.
- `two_interruptions_retain_exact_snapshot`: all 4 × 4 pairs of interruptions
  while restoring three data files plus config preserve exact backup bytes and
  permit subsequent idempotent recovery.
- `matching_pair_still_checks_live_commitments`: the old matching pair refuses
  mixed files during mutation; a new matching pair with a drifted selected file
  refuses without clearing recovery evidence.
- `partial_cleanup_retries_without_changing_snapshot`: after durable marker
  removal, every prefix of backup cleanup can be retried safely.
- `corrupt_backup_refuses_before_any_restore`: a later corrupt backup prevents
  every restoration write, preserving the uncertain state for diagnosis.

These deterministic tests operate only on synthetic owner-private homes. They
do not simulate physical power loss. Existing maintenance-lock, torn-commit,
renewal and missing-evidence tests remain required.

## Bounds and execution

Both positive configurations use `Files = {a, b}`, versions 0/1, three backup
targets and `CrashBudget = 2`. There is one cooperative maintenance owner.
Every successful individual `rewrite` is abstracted as atomic and durable.
A backup unlink can persist before the final directory sync; the model takes
that adverse unfenced-metadata outcome. `PersistUnlink` also permits marker
removal to become durable early, without relying on it.

Crashes inside `rewrite`'s temporary-write/rename/fsync implementation,
arbitrary or coherent malicious rewrites, additive target creation, actual
filesystem persistence ordering, cryptography, service activation and mailbox
contents are outside this model. The two integrity faults are examples of
fail-closed handling, not complete storage-failure coverage.

Use the repository's checksum-pinned TLC runner from the repository root:

```sh
python3 verify/run_tlc.py --jar /absolute/tla2tools.jar --java /absolute/java --out /new/owned/evidence-directory
CARGO_BUILD_JOBS=4 cargo test -p vhalla-cli --all-features --locked --offline private_host::config
```

The Rust tests require a compiler at least 1.98, including the compiler
actually resolved by Cargo when several installations are on `PATH`.

The runner requires complete positive checks and the named invariant failure
with a counterexample for each mutant; logs and traces belong to that run's
receipt. Local pinned TLC checks on 23 September 2026 explored 277 distinct
states for `normal` and 465 for `uncertain`; all four mutants failed their named
invariant. The absent-marker counterexample has 16 states. These counts are
observations for this source/configuration, not guarantees for later edits.
