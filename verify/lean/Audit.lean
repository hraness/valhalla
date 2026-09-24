import Lean

/- Admission code, not an additional mathematical axiom. The Python runner
compiles this file and the proof from copied source into an empty directory.
The generated final command supplies the independently maintained inventory. -/
open Lean Elab Command

namespace Valhalla.LeanAdmission

def auditModule (moduleName claimNamespace : Name) (required : Array Name) : CommandElabM Unit := do
  let env ← getEnv
  let some moduleIndex := env.getModuleIdx? moduleName |
    throwError "LEAN_AUDIT_MISSING_MODULE {moduleName}"
  for name in required do
    let some constant := env.find? name |
      throwError "LEAN_AUDIT_MISSING_THEOREM {name}"
    unless constant.isTheorem do
      throwError "LEAN_AUDIT_NOT_A_THEOREM {name}"
    unless env.getModuleIdxFor? name == some moduleIndex do
      throwError "LEAN_AUDIT_WRONG_MODULE {name}"
  let declarations := env.constants.toList.filter fun (name, _) =>
    env.getModuleIdxFor? name == some moduleIndex
  -- Source declaration ranges identify authored theorems, including nested
  -- namespaces, without confusing generated equation lemmas with public claims.
  let mut observed := []
  for (name, constant) in declarations do
    if constant.isTheorem && (← findDeclarationRangesCore? name).isSome then
      observed := name :: observed
  unless observed.length == required.size && observed.all required.contains do
    throwError "LEAN_AUDIT_THEOREM_INVENTORY"
  let allowed := #[`propext, `Classical.choice, `Quot.sound]
  -- Audit every declaration, including unused helpers and compiler-generated
  -- equation/proof declarations, rather than only the advertised conclusions.
  for (name, _) in declarations do
    for axiomName in ← collectAxioms name do
      unless allowed.contains axiomName do
        throwError "LEAN_AUDIT_FORBIDDEN_AXIOM {axiomName}"
  let results ← required.mapM fun name => do
    let axioms ← collectAxioms name
    return Json.mkObj [("name", toJson name.toString),
      ("axioms", toJson (axioms.map Name.toString))]
  let result := Json.mkObj [("module", toJson moduleName.toString),
    ("namespace", toJson claimNamespace.toString),
    ("declarations_audited", toJson declarations.length),
    ("theorems", Json.arr results)]
  logInfo m!"LEAN_AUDIT_OK {result.compress}"

end Valhalla.LeanAdmission
