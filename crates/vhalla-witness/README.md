# vhalla-witness

Witness-mode program execution for Botcaptcha: the platform side of a
Roc-style platform/application split. The application supplies only an
assignment of finite-rule programs (the `habitat-v1` cell language);
the platform owns the world, the tick loop, the work ledger, the allowance, and
every effect, and hands back plain data.

Read the [witness platform plan](../../kb/plans/valhalla-witness-platform.md)
for the reference design, the discovery spikes, and the decision record.

## What a valid run proves

A `WitnessRun`, and the `WitnessReceipt` sealed from it, prove that bounded,
replayable work happened on a verifier-selected task under one manifest and
one assignment: the case results, the delivered-spark floor quantity, the
total work ceiling quantity, and whether every case passed. A verifier
reproduces the run and compares the receipt encoding bit for bit.

It proves nothing else. It is not identity, personhood, intelligence,
originality, or host authority. `RunCapability` is minted locally from data
the caller already holds; the compiler proves only that one capability runs
once and names the manifest and assignment it was minted for. The signed
challenge and response, the one-use window, and admission live in a separate
crate; this crate has no key type, no clock, and no entropy.

## Boundaries

- `no_std` plus `alloc`; `sha2` is the only dependency.
- Every decoder checks its byte bound first, then version and language, reads
  with bounds-checked slices, and rejects trailing bytes. Bounds are derived
  from the widest variants: a program is at most 1059 bytes, an assignment
  16947, a manifest 23991, a final state 9572.
- Every counter and state update uses checked arithmetic; the tick loop
  allocates nothing after the machine is built.
- Programs and assignments have private fields: bytes stop at
  `codec::decode_candidate`, and `ValidManifest::assign` is the only path to
  the `Assignment` that `platform::run` accepts.

## Evidence

`tests/vectors/` holds one file per reference fixture, every `bridge-v1`
suite case, and the densest 64 KiB case: the canonical manifest and candidate
bytes and every digest and quantity a replay must reproduce.
