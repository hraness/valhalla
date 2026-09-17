# Formal verification

Valhalla carries two complementary verification layers on top of the ordinary
test suite. Both are real evidence with explicit limits; neither is a claim
that the protocol as a whole is verified.

## Kani bounded model checking

`#[cfg(kani)]` harnesses live next to the code they check. They prove
properties over *every* symbolic input within an unwind bound — stronger than
property tests, which sample, but bounded: nothing is claimed beyond the
bounds written in each harness.

| Crate | Harnesses | Properties proven |
| --- | --- | --- |
| `vhalla-journal` | `mod proofs` in `src/lib.rs` | `Bundle::decode` rejects inputs past the scratch bound without panicking |

Ledger admission invariants (tip advance, atomicity, per-actor monotonicity, duplicate and capacity rejection) are handled in the unbounded Verus model below. The journal Kani proof checks that the bundle decoder rejects oversized inputs without panicking. Bounded Kani harnesses on the production `BTreeMap<EventDigest, Event>` implementation proved intractable on this toolchain: CBMC unwinds the standard-library `find_key_index` and node-scan loops far beyond a useful bound even for one- or two-element maps, so the trade-off favors the Verus abstraction for admission logic and a small, fast Kani check for the self-contained codec.

The Kani harness is intentionally not run in CI: CBMC is too slow and
resource-hungry to complete on GitHub's free runners within an acceptable
PR gate. Run it locally when the decoder surface changes:

```console
cargo install kani-verifier --locked   # once; then cargo kani setup
cargo kani -p vhalla-journal -j --output-format terse
```

## Verus functional verification

`verify/ledger.rs` is a self-contained verified model of the ledger admission
machine — ids are `u64` stand-ins for digests and the retained event set is a
vector (the production `BTreeMap`s are caches over it), while the transition
function applies the same checks in the same order as `Ledger::append` and
fails closed. It is a reference artifact: the production code stays idiomatic
and the model stays provable.

Proven with no bounds assumed: append-only growth, linear parent chain,
distinct ids (no double admission), strictly increasing per-actor sequences,
capacity, and atomic rejection — `13 verified, 0 errors`.

Run (needs rustup with toolchain `1.98.1`, then the matching Verus release):

```console
verus --crate-type=lib verify/ledger.rs
```

The pinned binary is `verus 0.2026.09.13.671956e` (release tag
`release/0.2026.09.13.671956e`, bundles `verus-…-arm64-macos.zip` /
`verus-…-x86-linux.zip`) on rustup toolchain `1.98.1`.

## What is not verified

Hash functions are stubbed in Kani and abstracted in Verus; signatures,
quorum, transport, persistence, and the host boundary are outside both
models. Bounded Kani results do not extend past their unwind bounds, and the
Verus model proves the *transition discipline*, not the byte-level codecs or
the BTreeMap implementation — those are covered by the test suites.
