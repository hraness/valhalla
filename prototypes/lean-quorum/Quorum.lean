import Std

/- Disposable fit spike, not a theorem about production Rust or consensus.
Each list entry denotes one distinct validator; the production validator-set
and certificate checks must establish that interpretation independently. -/
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

#print axioms strict_quorums_have_honest_overlap
#print axioms threshold_exact
#print axioms multiplication_safe
#print axioms nonstrict_threshold_admits_no_honest_overlap
#print axioms excess_faults_admit_no_honest_overlap
