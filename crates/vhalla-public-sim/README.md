# Public-network simulator

`vhalla-public-sim` is a deterministic, allocation-bounded model for the
Valhalla public-network measurement lane. It generates a seeded peer topology
and event workload, applies a deterministic partition/churn schedule, and
simulates epidemic forwarding with duplicate suppression. The result keeps
per-event receipts that distinguish local acceptance, first remote delivery,
and convergence across peers that were healthy when the event was issued.

The model has no sockets, clocks, files, randomness, or provider dependencies.
A caller records the seed and configuration in its experiment manifest and can
replay the exact run in a native process, browser worker, or ephemeral runner.
It is a measurement substrate, not evidence that a deployment has a particular
availability or custody guarantee.

Run the bounded default workload and retain the JSON line as an experiment
receipt:

```console
cargo run -p vhalla-public-sim --locked -- --seed 7 --peers 100 --events 500 --steps 400
```

The receipt reports generated and converged events, duplicate suppression,
orphan references, partition/churn steps, and a deterministic digest. Inputs
are deliberately small and fail closed at the limits in `src/lib.rs`; a live
Railway or independent-host run must bind the same seed and workload manifest
to its own deployment and resource receipts.
