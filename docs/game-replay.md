# Bounded game replay

`vhalla game replay BUNDLE` independently checks the signed records in a frozen
`key: value` session bundle and reproduces its checkpoints and final receipt.
It holds no identity key and does not grant the sender access to the machine.

```console
vhalla game replay game-v1-session-replay.txt
vhalla game replay game-v1-session-replay.txt --max-work 10000000 --max-replays 1
```

The normal defaults are 10,000,000 total replay-work units and 64 replays. The
operator can select a positive `--max-work` and a `--max-replays` from 1 through
64. A sender's declared session limits can only reduce these local allowances.
Work units are deterministic execution charges, not milliseconds; this is not
a measured wall-clock service-level guarantee. Prefix verification consumes the
same receiver budget as final verification when another replay is required.

The command accepts a regular, non-symlink UTF-8 file up to 64 MiB. Descriptor
checks and nonblocking open reject devices, directories and FIFOs. Reading is
bounded even if a regular file grows after its initial size check. Inputs have
at most 1,024 records, bounded line and field counts, and no duplicate fields.
Each canonical object's hex is checked against that object's byte ceiling
before decoding. Indexed record fields outside `record_count` are refused;
auxiliary vector annotations are ignored and unverified, but count toward the
same resource bounds. `verified` does not authenticate those annotations.

`verified` is printed only when all declared records and seals pass. The final
receipt hash comes from the receiver's already-charged final replay. Reading
that verified result does not execute the final program a second time. An
oversized input, bad signature, mismatching checkpoint, exhausted budget, or
missing final seal returns failure without printing `verified`.

A receipt demonstrates reproduced work for one ruleset, manifest and input. It
does not prove personhood, originality, general intelligence, host permission,
or permissionless network membership. Quorum-ordered game sessions have their
own certificate-consumer path; this command retains its existing session-vector
scope rather than silently treating arbitrary certificates as authority.

The frozen replay/live session vectors remain the compatibility gate. The CLI
tests also exercise special files, oversized inputs, ambiguous fields, record
counts and local budget refusal. These are local verifier checks, not evidence
of multi-host game transport, relay availability or a deployed public room.
