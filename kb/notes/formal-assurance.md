---
type: concept
title: Formal assurance with implementation correspondence
---

# Formal assurance with implementation correspondence

Formal assurance connects a precisely bounded claim to a checked artifact,
its assumptions and the production behavior it represents. A passing reference
model does not establish that the deployed program implements it. Keep an
explicit correspondence map, real-code regression tests and independent review
beside the model; require a deliberately broken variant to demonstrate that the
chosen property can expose the intended failure.

For Valhalla, TLA+ is the current fit for interleavings, recovery custody and
conditional progress. Kani checks selected production Rust decisions within
declared symbolic bounds, while Verus carries the existing unbounded ledger
reference model. The [[plans/valhalla-lean-assurance-trial|Lean trial]] maintains
unbounded weighted-certificate proofs and tests Lean-generated cases against
both authenticated Rust verifiers. Its identity-list theorem proves why known,
distinct signer lists match weighted roster membership; certificate uniqueness
also requires one signing context and honest non-equivocation within it.
Finite conformance does not prove Rust refinement, and the trial does not
establish a maintenance advantage over Verus. The
[assurance ledger](../../verify/README.md) owns the current tool decision,
source mappings and limits.

Distinguish visible state from durable state when modeling recovery. A process
restart can observe an unsynced deletion that later power loss reverses. The
[[plans/valhalla-formal-rigor|formal-rigor implementation]] found this distinction
material: cleanup needed a directory fence even when its recovery marker was
already visibly absent. The [host model](../../verify/host-recovery/README.md)
and production fault test own that example; they do not claim physical power-cut
qualification.

Snapshot contents and protocol progress are different state. An empty batch can
preserve both snapshot roots while advancing height, value identity, clock and
clock-dependent authority. Roots also need not uniquely identify a publication
height. The [[plans/valhalla-protocol-formal-expansion|protocol expansion]]
reproduced false acknowledgment and false recovery refusal from conflating
these facts. Recovery must reconcile a reachable combination of snapshots and
the complete committed frontier, rather than infer independent heights from
root equality.

Durable retention and current protocol admission are also separate facts. A
future batch may remain on disk after an earlier decision prunes its pending
entry. A local proposer must restore validated admission before exposing that
candidate to consensus. The [held-reply model](../../verify/rooms-held-reply/README.md)
and a three-height production regression own this distinction; metadata
durability alone does not establish that a later decision can be applied.

A property checked only after successful admission can pass while legitimate
recovery remains stuck or refused. Check the admissibility of reachable honest
interruption states as well; state fairness and environmental assumptions
separately when claiming eventual progress.

Checker evidence also needs a contract. Inventory every configuration, retain
the exact model inputs, identify the expected failed property and distinguish a
counterexample from a parser error, timeout or killed process. Hashes establish
which artifacts were checked; they do not establish that the abstraction or
theorem statement was the right one.
