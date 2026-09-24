#!/usr/bin/env python3
"""Admit the maintained Lean trial using a checksum-pinned local release archive.

No downloads, global installation, Lake or mathlib are performed. A fresh
temporary toolchain executes copied proof inputs; receipts contain evidence,
not the multi-gigabyte toolchain. The Rust correspondence remains finite tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time

from run_tlc import (
    EvidenceError, checked_path, read_json, require_keys, sha256, write_json,
)

ROOT = Path(__file__).resolve().parent.parent
LEAN_DIR = "verify/lean"
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
NAME = r"[A-Za-z_][A-Za-z_0-9]*"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def load_inputs(repo):
    claims = read_json(checked_path(repo, f"{LEAN_DIR}/claims.json").read_bytes())
    require_keys(claims, {"schema_version", "module", "namespace", "theorems", "correspondence_sources"})
    if type(claims["schema_version"]) is not int or claims["schema_version"] != 1 or claims["module"] != "Quorum" or claims["namespace"] != "Valhalla.Quorum":
        raise EvidenceError("unsupported Lean claims inventory")
    names = claims["theorems"]
    if (not isinstance(names, list) or not names or
            any(not isinstance(n, str) or not re.fullmatch(NAME + r"(?:\." + NAME + r")*", n) for n in names) or
            len(set(names)) != len(names)):
        raise EvidenceError("invalid or duplicate theorem inventory")
    sources = claims["correspondence_sources"]
    if (not isinstance(sources, list) or not sources or
            any(not isinstance(p, str) for p in sources) or len(set(sources)) != len(sources)):
        raise EvidenceError("invalid correspondence sources")
    paths = {"verify/run_lean.py", "verify/run_tlc.py", "verify/test_run_lean.py",
             f"{LEAN_DIR}/Quorum.lean", f"{LEAN_DIR}/Audit.lean", f"{LEAN_DIR}/corpus.json",
             f"{LEAN_DIR}/claims.json", f"{LEAN_DIR}/tools.json", f"{LEAN_DIR}/lean-toolchain", *sources}
    observed = {p.relative_to(repo).as_posix() for p in (repo / LEAN_DIR).rglob("*.lean")}
    if observed != {f"{LEAN_DIR}/Quorum.lean", f"{LEAN_DIR}/Audit.lean"}:
        raise EvidenceError("unlisted or missing maintained Lean source")
    snapshot = {p: checked_path(repo, p).read_bytes() for p in sorted(paths)}
    if read_json(snapshot[f"{LEAN_DIR}/claims.json"]) != claims:
        raise EvidenceError("claims changed during inventory read")
    tools = read_json(snapshot[f"{LEAN_DIR}/tools.json"])
    require_keys(tools, {"schema_version", "version", "commit", "provenance", "platforms"})
    if (type(tools["schema_version"]) is not int or tools["schema_version"] != 1 or
            not isinstance(tools["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tools["version"])):
        raise EvidenceError("unsupported Lean tool manifest")
    if not isinstance(tools["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", tools["commit"]):
        raise EvidenceError("invalid Lean commit pin")
    if not isinstance(tools["platforms"], dict) or not isinstance(tools["provenance"], str):
        raise EvidenceError("invalid Lean release provenance/platforms")
    if snapshot[f"{LEAN_DIR}/lean-toolchain"].decode().strip() != f"leanprover/lean4:v{tools['version']}":
        raise EvidenceError("lean-toolchain does not match tool manifest")
    # Reject malformed fixtures before invoking their producer. Byte-for-byte
    # regeneration below is the authoritative fixture/source correspondence.
    corpus = read_json(snapshot[f"{LEAN_DIR}/corpus.json"])
    if (not isinstance(corpus, dict) or type(corpus.get("version")) is not int or corpus.get("version") != 1
            or not isinstance(corpus.get("cases"), list) or not corpus["cases"]):
        raise EvidenceError("invalid or empty Lean corpus")
    return claims, tools, snapshot


def check_snapshot(root, snapshot):
    changed = [p for p, data in snapshot.items() if checked_path(root, p).read_bytes() != data]
    if changed:
        raise EvidenceError(f"Lean inputs changed during execution: {changed}")


def select_archive(tools, archive, system=None, machine=None):
    key = f"{(system or platform.system()).lower()}-{(machine or platform.machine()).lower()}"
    pin = tools["platforms"].get(key)
    if pin is None:
        raise EvidenceError(f"unsupported pinned Lean platform: {key}")
    require_keys(pin, {"archive", "directory", "url", "bytes", "sha256"})
    if (not isinstance(pin["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]) or
            type(pin["bytes"]) is not int or pin["bytes"] <= 0 or
            not isinstance(pin["directory"], str) or
            not re.fullmatch(r"lean-[0-9.]+-[A-Za-z0-9_]+", pin["directory"])):
        raise EvidenceError("invalid Lean archive pin")
    if archive.stat().st_size != pin["bytes"] or digest(archive) != pin["sha256"]:
        raise EvidenceError("Lean archive size/digest does not match official release pin")
    return key, pin


def diagnostics(output):
    messages = []
    for line in output.splitlines():
        try:
            message = read_json(line)
        except ValueError as error:
            raise EvidenceError("Lean emitted non-JSON diagnostics") from error
        if (not isinstance(message, dict) or message.get("severity") not in {"information", "warning", "error"}
                or not isinstance(message.get("data"), str)):
            raise EvidenceError("Lean emitted malformed diagnostics")
        messages.append(message)
    return messages


def require_success(code, output):
    messages = diagnostics(output)
    if code != 0 or any(m["severity"] != "information" for m in messages):
        raise EvidenceError("Lean did not finish successfully without warnings/errors")
    return messages


def audit_result(code, output, module, namespace, names):
    messages = require_success(code, output)
    if len(messages) != 1 or not messages[0]["data"].startswith("LEAN_AUDIT_OK "):
        raise EvidenceError("missing or duplicated Lean audit result")
    result = read_json(messages[0]["data"][len("LEAN_AUDIT_OK "):])
    require_keys(result, {"module", "namespace", "declarations_audited", "theorems"})
    if (result["module"] != module or result["namespace"] != namespace or
            type(result["declarations_audited"]) is not int or result["declarations_audited"] < len(names)
            or not isinstance(result["theorems"], list)):
        raise EvidenceError("Lean audit scope/count does not match inventory")
    observed = []
    for theorem in result["theorems"]:
        require_keys(theorem, {"name", "axioms"})
        axioms = theorem["axioms"]
        if (not isinstance(axioms, list) or any(not isinstance(a, str) for a in axioms)
                or len(axioms) != len(set(axioms)) or set(axioms) - ALLOWED_AXIOMS):
            raise EvidenceError("Lean audit contains forbidden or malformed axioms")
        observed.append(theorem["name"])
    if observed != [f"{namespace}.{name}" for name in names]:
        raise EvidenceError("Lean audit theorem inventory does not match")
    return result


def require_rejection(code, output, reason):
    messages = diagnostics(output)
    errors = [m["data"] for m in messages if m["severity"] == "error"]
    if (code != 1 or len(errors) != 1 or any(m["severity"] == "warning" for m in messages)
            or re.fullmatch(reason, errors[0]) is None):
        raise EvidenceError("negative control did not fail for its intended reason")


def require_version(code, reported, tools):
    if (code or re.fullmatch(r"Lean \(version " + re.escape(tools["version"]) +
            r", [^\n]+, commit " + tools["commit"] + r", Release\)\n?", reported) is None):
        raise EvidenceError("Lean executable version/commit does not match pin")


def require_corpus(generated, expected):
    if generated != expected:
        raise EvidenceError("Lean-generated corpus differs from committed fixture")


def command(command, cwd, env, timeout, log):
    started = time.monotonic()
    result = {"command": [str(x) for x in command], "timeout_seconds": timeout}
    try:
        # tar launches a decompressor. Own the whole subprocess group so a
        # timeout cannot leave its child holding the output pipe or scratch tree.
        with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                              errors="replace", start_new_session=True) as process:
            try:
                output, _ = process.communicate(timeout=timeout)
                result["exit_code"] = process.returncode
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                output, _ = process.communicate(timeout=5)
                result.update(exit_code=None, error="timeout")
    except OSError as error:
        output = str(error) + "\n"
        result.update(exit_code=None, error=str(error))
    log.write_text(output)
    result.update(elapsed_seconds=round(time.monotonic() - started, 6), log=log.name,
                  log_sha256=digest(log))
    return result, output


def audit_driver(module, namespace, names):
    targets = ", ".join(f"`{namespace}.{name}" for name in names)
    return (f"import Audit\nimport {module}\n"
            f"run_cmd Valhalla.LeanAdmission.auditModule `{module} `{namespace} #[{targets}]\n")


# Actual Lean failures are exercised on every run. Mathematical counterexample
# witnesses live in Quorum.lean; these controls test proof admission itself.
CONTROLS = {
    "sorry": ("set_option warningAsError false\ntheorem witness : True := by sorry\n",
              r"LEAN_AUDIT_FORBIDDEN_AXIOM sorryAx"),
    "custom-axiom": ("axiom poison : True\ntheorem witness : True := poison\n",
                     r"LEAN_AUDIT_FORBIDDEN_AXIOM Valhalla\.LeanControl\.poison"),
    "native-evaluation": ("theorem witness : 2 + 2 = 4 := by native_decide\n",
                          r"LEAN_AUDIT_FORBIDDEN_AXIOM Valhalla\.LeanControl\.witness\._native\.native_decide\.ax_[0-9_]+"),
    "missing-theorem": ("def placeholder : Nat := 0\n",
                        r"LEAN_AUDIT_MISSING_THEOREM Valhalla\.LeanControl\.witness"),
    "not-a-theorem": ("set_option linter.defProp false\ndef witness : True := True.intro\n",
                      r"LEAN_AUDIT_NOT_A_THEOREM Valhalla\.LeanControl\.witness"),
    "extra-theorem": ("theorem witness : True := True.intro\ntheorem extra : True := True.intro\n",
                      r"LEAN_AUDIT_THEOREM_INVENTORY"),
    "extra-nested-theorem": ("theorem witness : True := True.intro\nnamespace Nested\ntheorem extra : True := True.intro\nend Nested\n",
                             r"LEAN_AUDIT_THEOREM_INVENTORY"),
    "false-proof": ("theorem witness : (3 : Nat) > 3 := by decide\n",
                    r"Tactic `decide` proved that the proposition\n  3 > 3\nis false"),
}


def run_checks(repo, archive, out, timeout=120):
    if not 0 < timeout <= 600:
        raise EvidenceError("Lean timeout must be between 1 and 600 seconds")
    out.mkdir(parents=True, exist_ok=False)
    out = out.resolve()
    receipt = {"schema_version": 1, "complete": False, "verdict": "running",
               "scope": "kernel-checked mathematical trial and finite corpus, not Rust refinement",
               "steps": [], "negative_controls": []}
    receipt_path = out / "receipt.json"
    write_json(receipt_path, receipt)
    try:
        claims, tools, snapshot = load_inputs(repo)
        receipt["inputs_sha256"] = {p: sha256(data) for p, data in snapshot.items()}
        for path, data in snapshot.items():
            target = out / "inputs" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        archive = archive.resolve(strict=True)
        key, pin = select_archive(tools, archive)
        receipt["tool"] = {"platform": key, "version": tools["version"], "commit": tools["commit"], **pin}
        env = {k: v for k, v in os.environ.items() if not k.startswith(("LEAN_", "ELAN_"))}
        build = out / "inputs" / LEAN_DIR
        env["LEAN_PATH"] = str(build)

        def invoke(label, args, cwd=build, execution_env=env):
            entry, output = command(args, cwd, execution_env, timeout, out / f"{label}.log")
            entry["id"] = label
            receipt["steps"].append(entry)
            write_json(receipt_path, receipt)
            if entry["exit_code"] is None:
                raise EvidenceError(f"{label}: {entry['error']}")
            return entry["exit_code"], output

        # The verified official archive is the only executable distribution.
        # Its temporary extraction is deliberately excluded from the artifact.
        with tempfile.TemporaryDirectory(prefix="valhalla-lean-toolchain-") as scratch:
            code, output = invoke("extract", ["tar", "--zstd", "-xf", str(archive), "-C", scratch])
            if code:
                raise EvidenceError("pinned Lean archive extraction failed")
            lean = Path(scratch) / pin["directory"] / "bin" / "lean"
            receipt["tool"]["binary_sha256"] = digest(lean)
            code, version = invoke("version", [str(lean), "--version"])
            require_version(code, version, tools)
            receipt["tool"]["reported_version"] = version.strip()
            base = [str(lean), "--json", "-DwarningAsError=true", "-j", "1", "-M", "2048", "-t", "0"]
            for module in ("Audit", "Quorum"):
                code, output = invoke(f"compile-{module}", [*base, "-o", str(build / f"{module}.olean"),
                                                          str(build / f"{module}.lean")])
                require_success(code, output)
            driver = build / "Check.lean"
            driver.write_text(audit_driver(claims["module"], claims["namespace"], claims["theorems"]))
            receipt["audit_driver_sha256"] = digest(driver)
            code, output = invoke("audit", [*base, str(driver)])
            receipt["audit"] = audit_result(code, output, claims["module"], claims["namespace"], claims["theorems"])
            generated = out / "generated-corpus.json"
            code, output = invoke("corpus", [*base, "--run", str(build / "Quorum.lean"), "--emit-corpus", str(generated)])
            require_success(code, output)
            require_corpus(generated.read_bytes(), snapshot[f"{LEAN_DIR}/corpus.json"])
            receipt["corpus_sha256"] = digest(generated)
            for name, (body, reason) in CONTROLS.items():
                folder = out / "controls" / name
                folder.mkdir(parents=True)
                source = folder / "Negative.lean"
                source.write_text("import Std\nnamespace Valhalla.LeanControl\n" + body + "end Valhalla.LeanControl\n")
                check = folder / "Check.lean"
                check.write_text(audit_driver("Negative", "Valhalla.LeanControl", ["witness"]))
                control_env = {**env, "LEAN_PATH": os.pathsep.join((str(folder), str(build)))}
                code, output = invoke(f"{name}-compile", [*base, "-o", str(folder / "Negative.olean"), str(source)],
                                      folder, control_env)
                if name == "false-proof":
                    require_rejection(code, output, reason)
                else:
                    if name == "sorry":
                        messages = diagnostics(output)
                        if code or len(messages) != 1 or messages[0].get("kind") != "hasSorry" or messages[0]["severity"] != "warning":
                            raise EvidenceError("sorry control did not construct its intended incomplete proof")
                    else:
                        require_success(code, output)
                    code, output = invoke(f"{name}-audit", [*base, str(check)], folder, control_env)
                    require_rejection(code, output, reason)
                receipt["negative_controls"].append({"id": name, "verdict": "pass", "reason": reason,
                    "source_sha256": digest(source), "audit_driver_sha256": digest(check)})
                write_json(receipt_path, receipt)
            if digest(lean) != receipt["tool"]["binary_sha256"]:
                raise EvidenceError("Lean binary changed during execution")
        check_snapshot(out / "inputs", snapshot)
        check_snapshot(repo, snapshot)
        _, _, after = load_inputs(repo)
        if after != snapshot or digest(archive) != pin["sha256"]:
            raise EvidenceError("Lean inputs/tool archive changed during execution")
        receipt["inputs_after_sha256"] = {p: sha256(data) for p, data in after.items()}
        receipt.update(complete=True, verdict="pass")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt.update(complete=False, verdict="fail", error=str(error))
    write_json(receipt_path, receipt)
    print(json.dumps({"verdict": receipt["verdict"], "complete": receipt["complete"],
                      "theorems": len(receipt.get("audit", {}).get("theorems", [])),
                      "negative_controls": len(receipt["negative_controls"]),
                      "receipt": str(receipt_path), "error": receipt.get("error")}))
    return 0 if receipt["complete"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        return run_checks(ROOT, args.archive, args.out, args.timeout)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
