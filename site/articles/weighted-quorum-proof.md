A room has one owner and one posting policy. Suppose two conflicting changes to the same room are proposed at the same moment, and the network briefly splits so that each change reaches only some of the validators. If both could collect enough signatures, half the network would follow one policy and half the other, and nobody could say which room is the real one.

vhalla (valhalla) rules this out with a counting threshold. Its certified room directory, the shared record of which rooms exist, who owns them, and who may post, changes only when validators holding more than two thirds of the voting weight sign the change. As long as faulty validators hold at most a third of the weight and honest ones sign only one value per signing context, that threshold keeps two conflicting decisions from both being certified in the same signing context, and a machine-checked proof of that counting argument covers every roster and weighting, including the ones no test tried.

**Status: In development.** There is no hosted network, and the [readiness page](/docs/status/) lists what has been tested so far. If you are new to rooms, start with [A room in sixty seconds](/writing/a-room-in-sixty-seconds/).

## Two answers to the same question

Most people have seen a quieter version of this failure. Two people edit the same shared document offline, both reconnect, and one set of edits silently wins. Or a group chat shows a different message order on two phones. The software worked in every demo, then broke the first time two things happened at once while the network was misbehaving.

Tests rarely catch this. They try the timings someone thought of, and the failure needs one nobody did. The damage is worse when that code sits underneath everything else. A room's owner and posting rules are a foundation: messages, invitations, and moderation all assume the directory tells one story. A crack there shows up far away, as a message rejected by half the room or an owner who is the owner only on some machines.

## What it looks like when the conflict cannot happen

In a system built on this rule, two conflicting decisions in the same signing context are ruled out by arithmetic, given a limit on faulty weight. No timeout has to be tuned, and no test has to have tried the right interleaving. If faulty validators hold at most a third of the weight, any two decisions in the same signing context on the same roster share at least one validator who behaved correctly, and that validator will not sign both.

For a room member, the result is plain. When your software shows a room directory decision with a valid certificate, no second valid certificate for the same height, round and validator roster says something else, as long as the room's assumptions hold and the Rust verifier matches the Lean rule, which is tested on generated cases rather than proved. The guarantee is only as good as those assumptions, and the sections below name each one.

## The counting rule underneath

Every validator in a room directory has a voting weight, a whole number. A decision is accepted when the validators who signed it hold more than two thirds of the total weight. Call any such group a quorum.

Take two quorums, L and R, drawn from the same roster. Add up their weights and you count every member of both groups, and you count the members they share twice. So:

```
weight(L) + weight(R) ≤ total + weight(L and R)
```

Each quorum holds more than two thirds of the total, so the left side is more than four thirds of the total. That leaves the shared part with more than one third of the total weight. If faulty validators together hold at most one third, they cannot fill that shared part alone. At least one validator in both quorums is honest.

The threshold is simple to compute. Here it is as a TypeScript illustration; Valhalla's own certificate code is Rust:

```ts
// "More than two thirds" in whole numbers; exact for totals up to 2^52 (JavaScript numbers lose precision beyond that).
function minimumQuorum(totalWeight: number): number {
  return Math.floor((2 * totalWeight) / 3) + 1;
}

minimumQuorum(3);  // 3: every unit of weight must sign
minimumQuorum(64); // 43: 42 of 64 equal validators is not enough
```

The proof includes a theorem that "three times the signed weight is greater than twice the total" is exactly the same test as "signed weight is at least this minimum", so the two ways of writing the rule agree for every whole-number total.

## What the proof adds to the tests

The paragraph above is an argument a person could get wrong. Weights might not add the way the argument assumes, a signer might be counted twice, or an unknown signer might add weight that the roster never granted. Valhalla states the rule in [Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/), a language whose checker verifies each step of a proof, and proves it for any finite roster with any weights. In simplified form, the central theorem says:

```lean
theorem strict_quorums_have_honest_signer
    (roster left right : List Validator)
    -- no duplicates, and every signer is on the roster
    (left_quorum  : 3 * weight left  > 2 * weight roster)
    (right_quorum : 3 * weight right > 2 * weight roster)
    (fault_bound  : 3 * faultyWeight roster ≤ weight roster) :
    ∃ v ∈ roster, v ∈ left ∧ v ∈ right ∧ ¬ faulty v ∧ 0 < power v
```

The conclusion names a specific validator with positive weight who is honest and signed both. The next theorem needs that named validator; a statement that the overlap has positive weight would not be enough on its own. A second theorem uses that validator: if two certificates were signed in the same signing context (for precommits, the same height and round) over the same validator roster and honest validators sign only one value there, the two certificates carry the same value.

The proof also has to handle the bookkeeping that the pencil argument skips. One theorem shows that a list of distinct signers, all on a roster with no duplicate entries, carries exactly the weight the roster assigns them, whatever order they appear in. That is the step where a duplicated or unknown signer would otherwise sneak in extra weight.

## Each assumption, and what breaks without it

The same file holds small checked examples showing that each of the four assumptions below is needed. Each one is a way to build this wrong.

- **"More than two thirds", not "at least two thirds".** Three validators of weight one. One quorum is the first and second, the other is the first and third. Each holds exactly two thirds, the faulty weight is one third, and the only shared validator is the faulty one.
- **Faulty weight at most one third.** Give the first validator weight two and make it faulty, with two honest validators of weight one. Both two-member quorums pass the strict threshold, and again the only overlap is faulty.
- **Honest validators sign one value per signing context.** With a single validator that is willing to sign anything, two certificates for different values both pass. This is an assumption about the consensus engine's behavior. The proof uses it and does not prove it.
- **The same signing context.** Certificates from two different signing contexts can carry different values without any contradiction. The proof says nothing across rounds.

## How the proof meets the running code

A proof is about a definition written in Lean, not about the Rust that runs in a Valhalla node. Two things connect them.

First, Lean code generates a file of test cases along with the expected accept or reject for each: all 340 signer subsets across 30 small rosters of one to four validators with weights one or two, one starter example, and 13 edge cases such as exactly two thirds, 64 validators, duplicate signers, unknown signers, and totals near the arithmetic limit. That makes 354 cases, 94 accepted and 260 rejected. Both Rust certificate verifiers must agree with every one, using real signatures. Each case is signed at one fixed height and round; a separate test varies height, round and value to check that signatures bind them. The Rust tests also check 315 ordered pairs of accepted small certificates against every fault assignment within the theorem's fault limit, 1,451 pair-and-assignment combinations in all.

Second, the Lean check runs on every candidate change as part of the required CI check, and the runner refuses unfinished proofs, extra axioms, missing or extra theorems, and a test-case file that differs from what Lean generates. A change to the production Rust reruns the comparison even when no proof file changed, though someone still has to review whether the theorem still describes the changed code. So far the theorem statements have been drafted and reviewed by AI agents only.

The trial has already turned up one real mismatch, though not through the proof or the generated cases, which have no notion of rounds. Reading the certificate code for the trial turned up the suspicion, and a separate real-signature regression test in the same suite reproduced it: Valhalla's verifier for certificates coming from the consensus engine accepted a certificate at the largest possible round number, while both readers of the stored certificate bytes rejected it as a reserved value. That verifier now rejects that value before the certificate is recorded. Rechecking the proof is cheap. In one run on an Apple silicon Mac on 24 September 2026, with other checks running at the same time, Lean 4.34.0 checked the quorum file in 4.68 seconds; the whole admission run, including unpacking Lean, took 135.86 seconds. That is a single observation, not a benchmark.

For the broader question of why a room of a few peers needs agreement rules at all, see [Consensus for a group chat](https://hraness.com/reference/peer-to-peer-systems/room-scale-consensus).

## What the proof leaves open

The theorem is about one fixed roster in one signing context, and it assumes authenticated signatures, faulty weight of at most one third, and honest validators that never sign two values in the same signing context. It does not prove the cryptography, agreement across rounds, safe changes to the validator set, the consensus engine as a whole, or that the Rust code computes exactly what the Lean definition does. The connection to Rust is the finite set of generated cases above. The room directory validators also sit behind the experimental `experimental-rooms-node` build feature, and ordinary message delivery in public rooms does not wait on this consensus.
