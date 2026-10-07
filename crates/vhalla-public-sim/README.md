# Public-network simulator

`vhalla-public-sim` is a deterministic, allocation-bounded model for the
Valhalla public-network measurement lane. It generates a seeded peer topology
and event workload, applies a deterministic partition/churn schedule, and
simulates epidemic forwarding with duplicate suppression. The result keeps
aggregate receipts that distinguish generated, delivered, converged, duplicate,
and orphan accounting.

The model has no sockets, clocks, files, external randomness, or provider
dependencies. A caller records the seed and configuration in its experiment
manifest and can replay the exact run in a native process, browser worker, or
ephemeral runner. It is a measurement substrate, not evidence that a
deployment has a particular availability or custody guarantee.

Run the bounded default workload and retain the JSON line as an experiment
receipt:

```console
cargo run -p vhalla-public-sim --locked -- --seed 7 --peers 100 --events 500 --steps 400
```

The receipt reports generated and converged events, delivered events,
duplicate suppression, orphan references, partition/churn steps, and a
deterministic digest. The digest also commits to every manifest-controlled
input, including churn probability and partition endpoints, so a receipt
cannot be mistaken for a different schedule with identical observed counters.
Inputs are parsed strictly: unknown, duplicate, missing, and out-of-range
options fail closed. Use `--partition-start N --partition-end N` together for
an explicit interval; providing only one endpoint also fails closed. Use
`--no-partition` to disable the default interval. Per-step and whole-run
forwarding budgets are also enforced in `src/lib.rs`; a live Railway or
independent-host run must bind the same seed and workload manifest to its own
deployment and resource receipts.
