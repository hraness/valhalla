Valhalla's room directory changes only when validators holding more than two thirds of the voting weight sign the change. A Lean proof shows that, for any roster and any weights, two such groups always share at least one honest validator, provided faulty validators hold at most a third of the weight. Because that shared validator signs only one value per signing context, two conflicting decisions cannot both be certified there. The proof covers one fixed roster in one signing context, and it connects to the running Rust code through a set of generated test cases, not through a proof.


## The failure the threshold prevents

The certified room directory is Valhalla's shared record of which rooms exist, who owns them, and who may post. A room has one owner and one posting policy. Suppose two conflicting changes to the same room are proposed at the same moment, and the network briefly splits so that each change reaches only some of the validators. If both changes could collect enough signatures, part of the network would follow one policy and part the other, and nobody could say which room is the real one.

A conflicting directory decision affects more than the directory: messages, invitations and moderation all assume the directory gives one answer, so a split shows up far away, as a message rejected by half the room or an owner who is the owner only on some machines.

With a strict two-thirds threshold, the conflict is ruled out by arithmetic rather than by a tuned timeout or a lucky test. Any two decisions about the same question share at least one validator who behaved correctly, and that validator will not sign both. For a room member, this means that when your software shows a room directory decision with a valid certificate, no second valid certificate for the same height and round says something else, as long as the assumptions listed below hold.

## Why two quorums overlap

Every validator in a room directory has a voting weight, a whole number. A decision is accepted when the validators who signed it hold more than two thirds of the total weight. Call any such group a quorum.

Take two quorums, L and R, drawn from the same roster. Adding their weights counts every member of both groups, and counts the members they share twice. So:

```
weight(L) + weight(R) ≤ total + weight(L and R)
```

Each quorum holds more than two thirds of the total, so the left side is more than four thirds of the total. That leaves the shared part with more than one third of the total weight. If faulty validators together hold at most one third, they cannot fill the shared part alone, so at least one validator in both quorums is honest.

Here is the threshold as a TypeScript illustration; Valhalla's own certificate code is Rust:

```ts
// "More than two thirds" in whole numbers, with no rounding surprises.
function minimumQuorum(totalWeight: bigint): bigint {
  return (2n * totalWeight) / 3n + 1n;
}

minimumQuorum(3n);  // 3n: every unit of weight must sign
minimumQuorum(64n); // 43n: 42 of 64 equal validators is not enough
```

The proof includes a theorem that "three times the signed weight is greater than twice the total" is the same test as "signed weight is at least this minimum", so the two ways of writing the rule cannot drift apart.

## What the Lean proof adds

The argument above is one a person could get wrong. Weights might not add the way it assumes, a signer might be counted twice, or an unknown signer might add weight the roster never granted. Valhalla states the rule in [Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/), a language whose checker verifies each step of a proof, and proves it for any finite roster with any weights. Simplified, the central theorem says:

```lean
theorem strict_quorums_have_honest_signer
    (roster left right : List Validator)
    -- no duplicates, and every signer is on the roster
    (left_quorum  : 3 * weight left  > 2 * weight roster)
    (right_quorum : 3 * weight right > 2 * weight roster)
    (fault_bound  : 3 * faultyWeight roster ≤ weight roster) :
    ∃ v ∈ roster, v ∈ left ∧ v ∈ right ∧ ¬ faulty v ∧ 0 < power v
```

The conclusion names a validator with positive weight who is honest and signed both. That named validator matters, because a statement that the overlap has positive weight would not be enough for the next theorem. The next theorem uses it: if two certificates were signed in the same signing context (for precommits, the same height and round) and honest validators sign only one value there, the two certificates carry the same value.

The proof also handles bookkeeping that the pencil argument skips. One theorem shows that a list of distinct signers, all on a roster with no duplicate entries, carries the weight the roster assigns them, whatever order they appear in. That is the step where a duplicated or unknown signer would otherwise add weight.

## Each assumption, and what breaks without it

The same file holds small checked examples showing that every assumption is needed:

- **More than two thirds, not at least two thirds.** Take three validators of weight one. One quorum is the first and second, the other is the first and third. Each holds two thirds, the faulty weight is one third, and the only shared validator is the faulty one.
- **Faulty weight at most one third.** Give the first validator weight two and make it faulty, with two honest validators of weight one. Both two-member quorums pass the strict threshold, and again the only overlap is faulty.
- **Honest validators sign one value per signing context.** With a single validator that will sign anything, two certificates for different values both pass. This is an assumption about the consensus engine's behavior; the proof uses it and does not prove it.
- **The same signing context.** Certificates from two different signing contexts can carry different values without any contradiction, so the proof says nothing across rounds.

## Check the implementation against the definition

The proof is about a definition written in Lean, not about the Rust that runs in a Valhalla node. Two things connect them.

Lean generates small rosters and signer sets with expected accept-or-reject decisions. The Rust certificate readers must match those decisions using real signatures. The cases include duplicate signers, unknown signers, exactly two-thirds weight, and totals near the arithmetic limit.

This tests the correspondence at the chosen inputs. It is particularly useful at boundaries where a mathematical integer and a machine integer can behave differently. Changing the certificate code still requires reviewing whether the proved definition describes the new behavior.

The comparison has already reproduced one real mismatch. Reading the certificate code for the trial raised the suspicion, and the comparison reproduced it with real signatures: the consensus engine accepted a certificate at the largest possible round number, while both of Valhalla's own certificate readers rejected it as a reserved value. The engine's verifier now rejects that value before it is recorded.

For why a room of a few peers needs agreement rules at all, see [Consensus for a group chat](https://hraness.com/reference/peer-to-peer-systems/room-scale-consensus).

## Keep the signing context fixed

The theorem assumes authenticated signatures, faulty weight of at most one third, and honest validators that never sign two values in the same signing context. It does not prove the cryptography, agreement across rounds, safe changes to the validator set, the consensus engine as a whole, or that the Rust code computes what the Lean definition does; the link to Rust is the finite set of generated cases above. The room directory validators sit behind the `experimental-rooms-node` build feature, and ordinary message delivery in public rooms does not wait on this consensus.
