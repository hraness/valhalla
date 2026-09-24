import Std

namespace Valhalla.Quorum

/- Maintained mathematical trial, not a refinement proof of production Rust.
The identity-list bridge added in this trial establishes how distinct signer
lists correspond to the weighted membership model below. -/
structure Voter where
  power : Nat
  left : Bool
  right : Bool
  faulty : Bool

def powerWhere (pred : Voter → Bool) : List Voter → Nat
  | [] => 0
  | v :: vs => (if pred v then v.power else 0) + powerWhere pred vs

def totalPower := powerWhere (fun _ => true)
def leftPower := powerWhere (fun v => v.left)
def rightPower := powerWhere (fun v => v.right)
def overlapPower := powerWhere (fun v => v.left && v.right)
def faultyPower := powerWhere (fun v => v.faulty)
def honestOverlapPower := powerWhere (fun v => v.left && v.right && !v.faulty)

theorem overlap_bound (vs : List Voter) :
    leftPower vs + rightPower vs ≤ totalPower vs + overlapPower vs := by
  induction vs with
  | nil => simp [leftPower, rightPower, totalPower, overlapPower, powerWhere]
  | cons v vs ih =>
    cases v with
    | mk p l r f =>
      cases l <;> cases r <;>
        simp_all [leftPower, rightPower, totalPower, overlapPower, powerWhere] <;>
        omega

theorem faulty_overlap_bound (vs : List Voter) :
    overlapPower vs ≤ faultyPower vs + honestOverlapPower vs := by
  induction vs with
  | nil => simp [overlapPower, faultyPower, honestOverlapPower, powerWhere]
  | cons v vs ih =>
    cases v with
    | mk p l r f =>
      cases l <;> cases r <;> cases f <;>
        simp_all [overlapPower, faultyPower, honestOverlapPower, powerWhere] <;>
        omega

theorem strict_quorums_have_honest_overlap (vs : List Voter)
    (left_quorum : 3 * leftPower vs > 2 * totalPower vs)
    (right_quorum : 3 * rightPower vs > 2 * totalPower vs)
    (fault_bound : 3 * faultyPower vs ≤ totalPower vs) :
    0 < honestOverlapPower vs := by
  have h₁ := overlap_bound vs
  have h₂ := faulty_overlap_bound vs
  omega

theorem threshold_exact (signed total : Nat) :
    3 * signed > 2 * total ↔ signed ≥ 2 * total / 3 + 1 := by
  omega

theorem multiplication_safe (signed total : Nat)
    (valid_total : total ≤ (2 ^ 64 - 1) / 3)
    (known_distinct_signers : signed ≤ total) :
    3 * signed ≤ 2 ^ 64 - 1 ∧ 2 * total ≤ 2 ^ 64 - 1 := by
  omega

-- Tight witnesses show why the two principal hypotheses must stay strict.
def weakQuorumWitness : List Voter :=
  [⟨1, true, true, true⟩, ⟨1, true, false, false⟩, ⟨1, false, true, false⟩]

theorem nonstrict_threshold_admits_no_honest_overlap :
    3 * leftPower weakQuorumWitness ≥ 2 * totalPower weakQuorumWitness ∧
    3 * rightPower weakQuorumWitness ≥ 2 * totalPower weakQuorumWitness ∧
    3 * faultyPower weakQuorumWitness ≤ totalPower weakQuorumWitness ∧
    honestOverlapPower weakQuorumWitness = 0 := by
  decide

def excessiveFaultWitness : List Voter :=
  [⟨2, true, true, true⟩, ⟨1, true, false, false⟩, ⟨1, false, true, false⟩]

theorem excess_faults_admit_no_honest_overlap :
    3 * leftPower excessiveFaultWitness > 2 * totalPower excessiveFaultWitness ∧
    3 * rightPower excessiveFaultWitness > 2 * totalPower excessiveFaultWitness ∧
    honestOverlapPower excessiveFaultWitness = 0 := by
  decide


/- Identity-level extension. All results quantify over arbitrary finite lists
and natural-number powers; the mathematics imposes no roster-size or integer
cap. The admission/fixture layer below supplies production-facing bounds. -/
namespace Identity

def weight {α : Type} (power : α → Nat) (xs : List α) : Nat :=
  (xs.map power).sum

def selected {α : Type} (power : α → Nat) (pred : α → Bool) (xs : List α) : Nat :=
  weight power (xs.filter pred)

theorem filtered_weight_le {α : Type} (power : α → Nat) (pred : α → Bool) (xs : List α) :
    selected power pred xs ≤ weight power xs := by
  induction xs with
  | nil => simp [selected, weight]
  | cons x xs ih =>
    cases hp : pred x <;> simp_all [selected, weight] <;> omega

/-- A duplicate-free signer list drawn from a duplicate-free roster has exactly
its membership-selected roster weight. Neither list order nor unit weights are
assumed. Both lists use one identity-to-power assignment. -/
theorem distinct_known_signer_weight {α : Type} [DecidableEq α]
    (power : α → Nat) (roster signers : List α)
    (roster_unique : roster.Nodup) (signers_unique : signers.Nodup)
    (known : ∀ x ∈ signers, x ∈ roster) :
    weight power signers = selected power (fun x => decide (x ∈ signers)) roster := by
  have hp : signers.Perm (roster.filter (fun x => decide (x ∈ signers))) := by
    apply (List.perm_ext_iff_of_nodup signers_unique (roster_unique.filter _)).mpr
    intro x
    simp only [List.mem_filter, decide_eq_true_eq]
    exact ⟨fun h => ⟨known x h, h⟩, fun h => h.2⟩
  exact (hp.map power).sum_nat

theorem known_distinct_signers_bounded {α : Type} [DecidableEq α]
    (power : α → Nat) (roster signers : List α)
    (roster_unique : roster.Nodup) (signers_unique : signers.Nodup)
    (known : ∀ x ∈ signers, x ∈ roster) :
    weight power signers ≤ weight power roster := by
  rw [distinct_known_signer_weight power roster signers roster_unique signers_unique known]
  exact filtered_weight_le _ _ _

theorem overlap_bound {α : Type} (power : α → Nat) (left right : α → Bool)
    (roster : List α) :
    selected power left roster + selected power right roster ≤
      weight power roster + selected power (fun x => left x && right x) roster := by
  induction roster with
  | nil => simp [selected, weight]
  | cons x xs ih =>
    cases hl : left x <;> cases hr : right x <;>
      simp_all [selected, weight] <;> omega

theorem faulty_overlap_bound {α : Type} (power : α → Nat)
    (left right faulty : α → Bool) (roster : List α) :
    selected power (fun x => left x && right x) roster ≤
      selected power faulty roster +
      selected power (fun x => left x && right x && !faulty x) roster := by
  induction roster with
  | nil => simp [selected, weight]
  | cons x xs ih =>
    cases hl : left x <;> cases hr : right x <;> cases hf : faulty x <;>
      simp_all [selected, weight] <;> omega

theorem selected_positive_witness {α : Type} (power : α → Nat)
    (pred : α → Bool) (roster : List α)
    (positive : 0 < selected power pred roster) :
    ∃ x ∈ roster, pred x = true ∧ 0 < power x := by
  induction roster with
  | nil => simp [selected, weight] at positive
  | cons x xs ih =>
    cases hp : pred x with
    | false =>
      have tail : 0 < selected power pred xs := by
        simpa [selected, weight, hp] using positive
      obtain ⟨y, hy, hp, hw⟩ := ih tail
      exact ⟨y, List.mem_cons_of_mem x hy, hp, hw⟩
    | true =>
      by_cases hw : 0 < power x
      · exact ⟨x, List.mem_cons_self, hp, hw⟩
      · have zero : power x = 0 := by omega
        have tail : 0 < selected power pred xs := by
          simpa [selected, weight, hp, zero] using positive
        obtain ⟨y, hy, hp, hw⟩ := ih tail
        exact ⟨y, List.mem_cons_of_mem x hy, hp, hw⟩

/-- The positive honest overlap contains a concrete known signer of positive
power. This is stronger than an anonymous scalar intersection lower bound. -/
theorem strict_quorums_have_honest_signer {α : Type} [DecidableEq α]
    (power : α → Nat) (faulty : α → Bool) (roster left right : List α)
    (roster_unique : roster.Nodup) (left_unique : left.Nodup) (right_unique : right.Nodup)
    (left_known : ∀ x ∈ left, x ∈ roster) (right_known : ∀ x ∈ right, x ∈ roster)
    (left_quorum : 3 * weight power left > 2 * weight power roster)
    (right_quorum : 3 * weight power right > 2 * weight power roster)
    (fault_bound : 3 * selected power faulty roster ≤ weight power roster) :
    ∃ x ∈ roster, x ∈ left ∧ x ∈ right ∧ faulty x = false ∧ 0 < power x := by
  let lp : α → Bool := fun x => decide (x ∈ left)
  let rp : α → Bool := fun x => decide (x ∈ right)
  have hl := distinct_known_signer_weight power roster left roster_unique left_unique left_known
  have hr := distinct_known_signer_weight power roster right roster_unique right_unique right_known
  have bound₁ := overlap_bound power lp rp roster
  have bound₂ := faulty_overlap_bound power lp rp faulty roster
  have positive : 0 < selected power (fun x => lp x && rp x && !faulty x) roster := by
    change weight power left = selected power lp roster at hl
    change weight power right = selected power rp roster at hr
    omega
  obtain ⟨x, hx, hp, hw⟩ := selected_positive_witness power _ roster positive
  have parts : (x ∈ left ∧ x ∈ right) ∧ faulty x = false := by
    simpa [lp, rp, Bool.and_eq_true] using hp
  exact ⟨x, hx, parts.1.1, parts.1.2, parts.2, hw⟩

structure Certificate (Id Context Value : Type) where
  context : Context
  value : Value
  signers : List Id

/-- Abstract certificate admission. `signed` denotes authenticated signatures;
this proposition assumes that relation and does not implement cryptography. -/
def Admitted {Id Context Value : Type} (power : Id → Nat) (roster : List Id)
    (signed : Id → Context → Value → Prop) (cert : Certificate Id Context Value) : Prop :=
  cert.signers.Nodup ∧
  (∀ x ∈ cert.signers, x ∈ roster) ∧
  (∀ x ∈ cert.signers, signed x cert.context cert.value) ∧
  3 * weight power cert.signers > 2 * weight power roster

/-- A fixed roster and identical signing context are essential. For production
precommits the context is the admitted height/round with vote type fixed to
Precommit. The honest-one-value premise remains an obligation of the consensus
engine and retained anti-equivocation state; this theorem does not prove it.
No conclusion about certificates in different rounds or rosters follows. -/
theorem same_context_certificate_value_unique {Id Context Value : Type} [DecidableEq Id]
    (power : Id → Nat) (faulty : Id → Bool) (roster : List Id)
    (signed : Id → Context → Value → Prop)
    (left right : Certificate Id Context Value)
    (roster_unique : roster.Nodup)
    (left_admitted : Admitted power roster signed left)
    (right_admitted : Admitted power roster signed right)
    (same_context : left.context = right.context)
    (fault_bound : 3 * selected power faulty roster ≤ weight power roster)
    (honest_one_value : ∀ x ∈ roster, faulty x = false →
      ∀ ctx v₁ v₂, signed x ctx v₁ → signed x ctx v₂ → v₁ = v₂) :
    left.value = right.value := by
  obtain ⟨ld, lk, la, lq⟩ := left_admitted
  obtain ⟨rd, rk, ra, rq⟩ := right_admitted
  obtain ⟨x, hx, hl, hr, hf, _⟩ := strict_quorums_have_honest_signer power faulty roster
    left.signers right.signers roster_unique ld rd lk rk lq rq fault_bound
  exact honest_one_value x hx hf left.context left.value right.value
    (la x hl) (same_context ▸ ra x hr)

-- Checked witnesses distinguish the two new assumptions. All weights are one.
def singletonPower (_ : Nat) : Nat := 1
def noFaults (_ : Nat) : Bool := false

def firstCert : Certificate Nat Nat Nat := ⟨0, 0, [0]⟩
def conflictingCert : Certificate Nat Nat Nat := ⟨0, 1, [0]⟩
def otherContextCert : Certificate Nat Nat Nat := ⟨1, 1, [0]⟩

theorem dropping_non_equivocation_allows_conflict :
    Admitted singletonPower [0] (fun _ _ _ => True) firstCert ∧
    Admitted singletonPower [0] (fun _ _ _ => True) conflictingCert ∧
    3 * selected singletonPower noFaults [0] ≤ weight singletonPower [0] ∧
    firstCert.context = conflictingCert.context ∧
    firstCert.value ≠ conflictingCert.value := by
  simp [Admitted, firstCert, conflictingCert, singletonPower, noFaults, selected, weight]

def contextValueSigned (_ : Nat) (ctx value : Nat) : Prop := ctx = value

theorem dropping_same_context_allows_distinct_values :
    Admitted singletonPower [0] contextValueSigned firstCert ∧
    Admitted singletonPower [0] contextValueSigned otherContextCert ∧
    3 * selected singletonPower noFaults [0] ≤ weight singletonPower [0] ∧
    firstCert.context ≠ otherContextCert.context ∧
    firstCert.value ≠ otherContextCert.value ∧
    (∀ x ∈ [0], noFaults x = false → ∀ ctx v₁ v₂,
      contextValueSigned x ctx v₁ → contextValueSigned x ctx v₂ → v₁ = v₂) := by
  refine ⟨?_, ?_, by decide, by decide, by decide, ?_⟩
  · simp [Admitted, firstCert, singletonPower, contextValueSigned, weight]
  · simp [Admitted, otherContextCert, singletonPower, contextValueSigned, weight]
  · intro x hx hf ctx v₁ v₂ h₁ h₂
    exact h₁.symm.trans h₂


end Identity

-- The generated corpus is finite differential-test data. Its acceptance oracle
-- covers roster/signer structure and arithmetic only. The Rust consumer creates
-- authentic signatures in an admitted context before comparing both verifiers.
-- These predicates do not execute Rust or establish cryptographic soundness.
def maxTotal : Nat := (2 ^ 64 - 1) / 3

def indexedPower (powers : List Nat) (identity : Nat) : Nat :=
  (powers[identity]?).getD 0

theorem indexed_roster_roundtrip (powers : List Nat) :
    (List.range powers.length).map (indexedPower powers) = powers := by
  induction powers with
  | nil => rfl
  | cons p ps ih =>
    change (List.range ps.length).map (fun i => (ps[i]?).getD 0) = ps at ih
    simpa [indexedPower, List.range_succ_eq_map, List.map_map, Function.comp_def] using
      congrArg (List.cons p) ih


def indexedSignedPower (powers signers : List Nat) : Nat :=
  (signers.map (indexedPower powers)).sum

def fixtureAdmissible (powers signers : List Nat) : Prop :=
  powers ≠ [] ∧ powers.length ≤ 64 ∧ (∀ p ∈ powers, 0 < p) ∧
  powers.sum ≤ maxTotal ∧ signers ≠ [] ∧ signers.length ≤ 64 ∧
  signers.Nodup ∧ (∀ i ∈ signers, i < powers.length) ∧
  3 * indexedSignedPower powers signers > 2 * powers.sum

instance (powers signers : List Nat) : Decidable (fixtureAdmissible powers signers) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _ ∧ _ ∧ _ ∧ _ ∧ _))

def fixtureAccept (powers signers : List Nat) : Bool :=
  decide (fixtureAdmissible powers signers)

theorem fixture_accept_exact (powers signers : List Nat) :
    fixtureAccept powers signers = true ↔ fixtureAdmissible powers signers := by
  simp [fixtureAccept]

theorem fixture_signer_weight_bounded (powers signers : List Nat)
    (accepted : fixtureAccept powers signers = true) :
    indexedSignedPower powers signers ≤ powers.sum := by
  obtain ⟨_, _, _, _, _, _, unique, known, _⟩ :=
    (fixture_accept_exact powers signers).mp accepted
  have bound := Identity.known_distinct_signers_bounded (indexedPower powers)
    (List.range powers.length) signers List.nodup_range unique
    (fun i hi => List.mem_range.mpr (known i hi))
  simpa [Identity.weight, indexedSignedPower, indexed_roster_roundtrip] using bound

/-- The indexed corpus oracle supplies the generic theorem's structural and
weight hypotheses. Authentication is an explicit additional premise. -/
theorem fixture_admits_identity_certificate {Context Value : Type}
    (powers signers : List Nat) (signed : Nat → Context → Value → Prop)
    (context : Context) (value : Value)
    (accepted : fixtureAccept powers signers = true)
    (authenticated : ∀ i ∈ signers, signed i context value) :
    Identity.Admitted (indexedPower powers) (List.range powers.length) signed
      ⟨context, value, signers⟩ := by
  obtain ⟨_, _, _, _, _, _, unique, known, quorum⟩ :=
    (fixture_accept_exact powers signers).mp accepted
  refine ⟨unique, fun i hi => List.mem_range.mpr (known i hi), authenticated, ?_⟩
  simpa [Identity.weight, indexedSignedPower, indexed_roster_roundtrip] using quorum

def minimumQuorum (powers : List Nat) : Nat := 2 * powers.sum / 3 + 1

structure CorpusCase where
  id : String
  powers : List Nat
  signers : List Nat

-- Every positive weight vector of lengths 1..4 with entries in {1, 2}.
def powerVectors : Nat → List (List Nat)
  | 0 => [[]]
  | n + 1 => (powerVectors n).flatMap (fun tail => [1 :: tail, 2 :: tail])

def smallRosters : List (List Nat) :=
  (List.range 4).flatMap (fun n => powerVectors (n + 1))

-- Every identity subset, including empty, in the original identity order.
def signerSubsets : List Nat → List (List Nat)
  | [] => [[]]
  | x :: xs => let tail := signerSubsets xs; tail ++ tail.map (x :: ·)

def smallCases : List CorpusCase :=
  smallRosters.zipIdx.flatMap (fun (powers, rosterIndex) =>
    (signerSubsets (List.range powers.length)).zipIdx.map (fun (signers, subsetIndex) =>
      ⟨"small-" ++ toString rosterIndex ++ "-" ++ toString subsetIndex, powers, signers⟩))

def nearCapPowers : List Nat :=
  let q := 2 * maxTotal / 3 + 1
  [q - 1, 1, 1, maxTotal - q - 1]

def boundaryCases : List CorpusCase :=
  [⟨"duplicate-signer", [1, 2, 1], [0, 1, 1]⟩,
   ⟨"unknown-signer", [1, 2], [0, 1, 2]⟩,
   ⟨"exact-two-thirds", [1, 1, 1], [0, 1]⟩,
   ⟨"above-two-thirds", [1, 1, 1], [0, 1, 2]⟩,
   ⟨"near-cap-below-threshold", nearCapPowers, [0]⟩,
   ⟨"near-cap-at-threshold", nearCapPowers, [0, 1]⟩,
   ⟨"near-cap-above-threshold", nearCapPowers, [0, 1, 2]⟩,
   ⟨"single-at-cap", [maxTotal], [0]⟩,
   ⟨"64-roster-below-threshold", List.replicate 64 1, List.range 42⟩,
   ⟨"64-roster-at-threshold", List.replicate 64 1, List.range 43⟩,
   ⟨"64-roster-all-signers", List.replicate 64 1, List.range 64⟩,
   ⟨"65-signatures-exceeds-bound", List.replicate 64 1, List.range 64 ++ [0]⟩,
   ⟨"near-cap-exact-two-thirds", [2 * (maxTotal - 2) / 3, (maxTotal - 2) / 3], [0]⟩]

def corpusCases : List CorpusCase :=
  [⟨"weighted-steel-thread", [1, 2], [0, 1]⟩] ++ smallCases ++ boundaryCases

set_option maxRecDepth 4096 in
theorem small_corpus_sizes_checked :
    smallRosters.length = 30 ∧ smallCases.length = 340 ∧ corpusCases.length = 354 := by
  decide

-- This is kernel evaluation of explicit expected outcomes, not native_decide.
-- The generated JSON is still finite differential-test data, not a Rust proof.
theorem boundary_fixture_results_checked :
    boundaryCases.map (fun row => fixtureAccept row.powers row.signers) =
      [false, false, false, true, false, true, true, true, false, true, true, false, false] := by
  decide

theorem weighted_steel_thread_checked :
    fixtureAccept [1, 2] [0, 1] = true ∧ minimumQuorum [1, 2] = 3 := by
  decide

private def renderNats (xs : List Nat) : String :=
  "[" ++ String.intercalate "," (xs.map toString) ++ "]"

private def renderCase (row : CorpusCase) : String :=
  "{\"id\":\"" ++ row.id ++ "\",\"powers\":" ++ renderNats row.powers ++
  ",\"signers\":" ++ renderNats row.signers ++ ",\"accept\":" ++
  toString (fixtureAccept row.powers row.signers) ++ ",\"quorum_power\":" ++
  toString (minimumQuorum row.powers) ++ "}"

def corpusJson : String :=
  "{\"version\":1,\"cases\":[\n" ++
  String.intercalate ",\n" (corpusCases.map renderCase) ++ "]}\n"

end Valhalla.Quorum

def main (args : List String) : IO UInt32 := do
  match args with
  | ["--emit-corpus", path] =>
    IO.FS.writeFile path Valhalla.Quorum.corpusJson
    return 0
  | [] => return 0
  | _ =>
    IO.eprintln "usage: lean --run Quorum.lean --emit-corpus OUTPUT.json"
    return 2
