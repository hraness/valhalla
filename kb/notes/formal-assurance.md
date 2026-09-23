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
reference model. Lean is viable for weighted-quorum mathematics, but its
checked optional spike does not establish a distinct maintenance advantage over
Verus or prove Rust correspondence. The [assurance ledger](../../verify/README.md)
owns the current tool decision, source mappings and limits. Reconsider Lean
when a stable theorem needs substantial reusable mathematics or a supported
extraction path, with a named owner for the implementation relationship.

Distinguish visible state from durable state when modeling recovery. A process
restart can observe an unsynced deletion that later power loss reverses. The
[[plans/valhalla-formal-rigor|formal-rigor implementation]] found this distinction
material: cleanup needed a directory fence even when its recovery marker was
already visibly absent. The [host model](../../verify/host-recovery/README.md)
and production fault test own that example; they do not claim physical power-cut
qualification.

Checker evidence also needs a contract. Inventory every configuration, retain
the exact model inputs, identify the expected failed property and distinguish a
counterexample from a parser error, timeout or killed process. Hashes establish
which artifacts were checked; they do not establish that the abstraction or
theorem statement was the right one.
