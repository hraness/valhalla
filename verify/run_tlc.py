#!/usr/bin/env python3
"""Run the complete, pinned finite-model inventory and retain attributable evidence.

Historical counterexamples are documentation, never inputs to a current verdict.
The runner copies the checked model/config bytes into the new evidence directory
and rejects source changes during a run. It never downloads or repairs tools.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
MANIFEST = "verify/cases.json"
IDENTIFIER = r"[A-Za-z_][A-Za-z_0-9]*"
SECTIONS = set("SPECIFICATION INIT NEXT CONSTANT CONSTANTS INVARIANT INVARIANTS "
               "PROPERTY PROPERTIES CONSTRAINT CONSTRAINTS ACTION_CONSTRAINT "
               "ACTION_CONSTRAINTS VIEW SYMMETRY ALIAS POSTCONDITION CHECK_DEADLOCK".split())


class EvidenceError(ValueError):
    """The selected input or result cannot support the requested claim."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha256(path.read_bytes())


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(data):
    return json.loads(data, object_pairs_hook=json_object)


def checked_path(repo, name):
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise EvidenceError(f"invalid repository path: {name!r}")
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or ".." in relative.parts:
        raise EvidenceError(f"path must be canonical and repository-relative: {name}")
    path = repo
    for part in relative.parts:
        path /= part
        if path.is_symlink():
            raise EvidenceError(f"symlink input is not allowed: {name}")
    if not stat.S_ISREG(path.stat().st_mode):
        raise EvidenceError(f"input is not a regular file: {name}")
    return path


def tokens(text):
    """Small config lexer: comments and quoted strings cannot invent declarations."""
    result, index = [], 0
    while index < len(text):
        if text[index].isspace():
            index += 1
        elif text.startswith("\\*", index):
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline + 1
        elif text.startswith("(*", index):
            depth, index = 1, index + 2
            while depth and index < len(text):
                if text.startswith("(*", index):
                    depth, index = depth + 1, index + 2
                elif text.startswith("*)", index):
                    depth, index = depth - 1, index + 2
                else:
                    index += 1
            if depth:
                raise EvidenceError("unterminated config comment")
        else:
            match = re.match(r'"(?:\\.|[^"\\])*"|' + IDENTIFIER + r'|\S', text[index:])
            if text[index] == '"' and (not match or match.group() == '"'):
                raise EvidenceError("unterminated quoted config value")
            result.append(match.group())
            index += len(match.group())
    return result


def config_declarations(text):
    words = tokens(text)
    declarations = {"invariants": [], "properties": []}
    for index, word in enumerate(words):
        if word not in {"INVARIANT", "INVARIANTS", "PROPERTY", "PROPERTIES"}:
            continue
        names = []
        for name in words[index + 1:]:
            if name in SECTIONS:
                break
            if not re.fullmatch(IDENTIFIER, name):
                raise EvidenceError(f"unsupported {word} declaration: {name}")
            names.append(name)
        if not names:
            raise EvidenceError(f"empty {word} declaration")
        declarations["invariants" if word.startswith("INVARIANT") else "properties"].extend(names)
    for kind, names in declarations.items():
        if len(names) != len(set(names)):
            raise EvidenceError(f"duplicate {kind} declaration")
    return declarations


def model_variables(text):
    words = tokens(text)
    starts = [i for i, word in enumerate(words) if word in {"VARIABLE", "VARIABLES"}]
    variables = []
    for index in starts:
        index += 1
        while index < len(words) and re.fullmatch(IDENTIFIER, words[index]):
            variables.append(words[index])
            index += 1
            if index >= len(words) or words[index] != ",":
                break
            index += 1
    if not variables or len(variables) != len(set(variables)):
        raise EvidenceError("model needs distinct explicitly declared state variables")
    return set(variables)


def inventory(repo):
    found = set()
    for path in (repo / "verify").rglob("*"):
        if path.is_symlink():
            raise EvidenceError(f"symlink in model inventory: {path.relative_to(repo)}")
        if path.suffix in {".tla", ".cfg"}:
            name = path.relative_to(repo).as_posix()
            checked_path(repo, name)
            found.add(name)
    return found


def require_keys(value, required, optional=()):
    if (not isinstance(value, dict) or not set(required) <= value.keys()
            or set(value) - set(required) - set(optional)):
        raise EvidenceError(f"unexpected or missing fields; expected {sorted(required)}, optional {sorted(optional)}")


def nonempty_strings(value, label):
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x.strip() for x in value):
        raise EvidenceError(f"{label} must be a nonempty list of strings")


def load_inventory(repo):
    parsed_inputs = {MANIFEST: checked_path(repo, MANIFEST).read_bytes()}
    manifest = read_json(parsed_inputs[MANIFEST])
    require_keys(manifest, {"schema_version", "suites"})
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise EvidenceError("unsupported case manifest schema_version")
    if not isinstance(manifest["suites"], list) or not manifest["suites"]:
        raise EvidenceError("manifest must contain suites")
    paths = {MANIFEST, "verify/run_tlc.py", "verify/tools.json"}
    models, configs, suite_ids, cases = set(), set(), set(), []
    for suite in manifest["suites"]:
        require_keys(suite, {"id", "module", "claim", "status", "bounds", "assumptions", "sources", "cases"})
        name = suite["id"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or name in suite_ids:
            raise EvidenceError("invalid or duplicate suite id")
        suite_ids.add(name)
        for field in ("claim", "bounds"):
            if not isinstance(suite[field], str) or not suite[field].strip():
                raise EvidenceError(f"empty {field}: {name}")
        if not isinstance(suite["status"], str) or suite["status"] not in {"implementation-correspondence", "design-only"}:
            raise EvidenceError(f"unsupported correspondence status: {name}")
        nonempty_strings(suite["assumptions"], "assumptions")
        module = suite["module"]
        model = checked_path(repo, module)
        if model.suffix != ".tla" or model.parent != repo / "verify" / name or module in models:
            raise EvidenceError(f"module must be unique and inside its suite: {module}")
        models.add(module)
        parsed_inputs[module] = model.read_bytes()
        variables = model_variables(parsed_inputs[module].decode())
        if not isinstance(suite["sources"], list) or not suite["sources"]:
            raise EvidenceError(f"missing correspondence sources: {name}")
        source_paths, source_roles = set(), set()
        for source in suite["sources"]:
            require_keys(source, {"path", "symbols", "role"})
            checked_path(repo, source["path"])
            nonempty_strings(source["symbols"], "source symbols")
            if (not isinstance(source["role"], str) or source["role"] not in {"production", "regression", "contract"}
                    or (source["path"], source["role"]) in source_roles):
                raise EvidenceError(f"invalid or duplicate correspondence source: {name}")
            source_paths.add(source["path"])
            source_roles.add((source["path"], source["role"]))
        paths.update(source_paths)
        if not isinstance(suite["cases"], list) or not suite["cases"]:
            raise EvidenceError(f"missing cases: {name}")
        case_ids = set()
        for case in suite["cases"]:
            require_keys(case, {"id", "config", "expected"}, {"historical_trace"})
            case_id = case["id"]
            if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", case_id) or case_id in case_ids:
                raise EvidenceError(f"invalid or duplicate case id: {name}")
            case_ids.add(case_id)
            config = case["config"]
            config_path = checked_path(repo, config)
            if config_path != model.parent / (case_id + ".cfg") or config in configs:
                raise EvidenceError(f"config must be unique and match its case id: {config}")
            configs.add(config)
            parsed_inputs[config] = config_path.read_bytes()
            declarations = config_declarations(parsed_inputs[config].decode())
            expected = case["expected"]
            require_keys(expected, {"kind"}, {"property"})
            kind = expected["kind"]
            if not isinstance(kind, str):
                raise EvidenceError("expected result kind must be a string")
            if kind == "success":
                if set(expected) != {"kind"}:
                    raise EvidenceError("successful case must not name an expected violation")
            elif kind in {"invariant", "temporal"}:
                prop = expected.get("property")
                if not isinstance(prop, str) or not re.fullmatch(IDENTIFIER, prop):
                    raise EvidenceError("expected violation must name a property")
                if kind == "invariant" and prop not in declarations["invariants"]:
                    raise EvidenceError(f"expected invariant is not declared: {prop}")
                # TLC 1.7.4 names invariant failures but prints no temporal
                # property name. A singleton PROPERTY gives unambiguous attribution.
                if kind == "temporal" and declarations["properties"] != [prop]:
                    raise EvidenceError("temporal mutant must declare exactly its one expected PROPERTY")
            else:
                raise EvidenceError(f"unsupported expected result kind: {kind}")
            if "historical_trace" in case:
                historical = case["historical_trace"]
                if checked_path(repo, historical).parent != model.parent / "counterexamples":
                    raise EvidenceError("historical trace must stay inside its suite counterexamples")
                # Hash this documentation, but never reuse it to supply a
                # missing current-run counterexample.
                paths.add(historical)
            cases.append({"suite": name, **case, "module": module,
                          "variables": variables, "declarations": declarations})
    declared = models | configs
    found = inventory(repo)
    if found != declared:
        raise EvidenceError(f"model inventory mismatch: unlisted={sorted(found - declared)}, missing={sorted(declared - found)}")
    paths.update(declared)
    snapshot = {path: checked_path(repo, path).read_bytes() for path in sorted(paths)}
    if any(snapshot[path] != data for path, data in parsed_inputs.items()):
        raise EvidenceError("verification inputs changed while inventory was read")
    return manifest, cases, snapshot


def parse_trace(output, variables):
    """Validate TLC state framing, preserving values as opaque original text."""
    boundary = re.compile(r"(?m)^(?:State (\d+):[ \t]*(.*)|Back to state (\d+)(?::.*)?|[\d,]+ states generated.*|Finished checking temporal properties .*|Finished in .*)$")
    for line in output.splitlines():
        if line.startswith(("State ", "Back to state")) and not boundary.fullmatch(line):
            raise EvidenceError("malformed counterexample state header")
    markers = list(boundary.finditer(output))
    states, loop, expected_number, stage = [], None, 1, "trace"
    for index, marker in enumerate(markers):
        number, label, back = marker.groups()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(output)
        body = output[marker.end():end].strip()
        if (number or back) and stage != "trace":
            raise EvidenceError("counterexample continues after checker statistics")
        if back:
            if loop is not None or not states or not 1 <= int(back) <= len(states) or body:
                raise EvidenceError("invalid counterexample back-edge")
            loop = {"kind": "back-edge", "state": int(back)}
        elif number:
            if loop is not None or int(number) != expected_number:
                raise EvidenceError("counterexample states must be consecutive from State 1")
            expected_number += 1
            if label == "Stuttering":
                if not states or body:
                    raise EvidenceError("invalid stuttering terminal")
                loop = {"kind": "stuttering", "state": len(states)}
                continue
            if not states and label != "<Initial predicate>":
                raise EvidenceError("counterexample does not start at its initial predicate")
            if not label.startswith("<") or not label.endswith(">"):
                raise EvidenceError("missing counterexample action label")
            prefix = r"/\\\s+" if len(variables) > 1 else ""
            assignments = list(re.finditer(r"(?m)^" + prefix + "(" + IDENTIFIER + r")\s*=", body))
            names = [m.group(1) for m in assignments]
            if set(names) != variables or len(names) != len(set(names)):
                raise EvidenceError("counterexample state variables are missing or duplicated")
            if body[:assignments[0].start()].strip():
                raise EvidenceError("unexpected text before state variables")
            for at, assignment in enumerate(assignments):
                end_value = assignments[at + 1].start() if at + 1 < len(assignments) else len(body)
                if not body[assignment.end():end_value].strip():
                    raise EvidenceError("counterexample state has an empty variable value")
            action_match = re.fullmatch(r"<(" + IDENTIFIER + r")(?:\s+.*)?>", label)
            if not action_match:
                raise EvidenceError("malformed counterexample action label")
            action = "Init" if not states else action_match.group(1)
            states.append({"state": int(number), "action": action,
                           "tlc_text": label + "\n" + body})
        else:
            if not states:
                raise EvidenceError("checker statistics/completion precede its counterexample")
            if marker.group().startswith("Finished checking temporal properties "):
                if stage != "trace" or loop is None:
                    raise EvidenceError("temporal completion must follow its complete loop witness")
                stage = "temporal-complete"
            elif marker.group().startswith("Finished in "):
                if stage != "statistics":
                    raise EvidenceError("checker completion must follow exactly one statistics record")
                stage = "finished"
            else:
                if stage not in {"trace", "temporal-complete"}:
                    raise EvidenceError("checker statistics are duplicated or follow completion")
                stage = "statistics"
    if not states:
        raise EvidenceError("counterexample has no states")
    if stage != "finished":
        raise EvidenceError("counterexample has no ordered checker completion")
    return {"states": states, "loop": loop}


def assess_result(code, output, case):
    stats = re.findall(r"(?m)^([\d,]+) states generated, ([\d,]+) distinct states found", output)
    if not stats or not re.search(r"(?m)^Finished in .+", output):
        raise EvidenceError("checker has no complete statistics/finish record")
    generated, distinct = (int(n.replace(",", "")) for n in stats[-1])
    if not 0 < distinct <= generated:
        raise EvidenceError("checker explored no reachable states or reported invalid counts")
    expected = case["expected"]
    errors = re.findall(r"(?m)^Error: (.*)$", output)
    trace = None
    if expected["kind"] == "success":
        if code != 0 or "Model checking completed. No error has been found." not in output or errors:
            raise EvidenceError("positive case did not complete successfully")
    else:
        if expected["kind"] == "invariant":
            wanted = [f"Invariant {expected['property']} is violated.", "The behavior up to this point is:"]
            wanted_code = 12
        else:
            wanted = ["Temporal properties were violated.", "The following behavior constitutes a counter-example:"]
            wanted_code = 13
        if code != wanted_code or errors != wanted:
            raise EvidenceError("checker did not report exactly the expected kind/property failure")
        # Earlier liveness passes may emit progress/completion messages. Only
        # the suffix introduced as this failure's counterexample is its trace.
        introduction = re.search(r"(?m)^Error: " + re.escape(wanted[1]) + r"$", output)
        trace = parse_trace(output[introduction.end():], case["variables"])
        if (trace["loop"] is not None) != (expected["kind"] == "temporal"):
            raise EvidenceError("counterexample terminal does not match safety/temporal expectation")
    return {"generated": generated, "distinct": distinct}, trace


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def check_copied_inputs(root, expected_hashes):
    """Bind every file TLC may consume to the retained input snapshot."""
    observed = {path: digest(checked_path(root, path)) for path in expected_hashes}
    changed = [path for path, expected in expected_hashes.items() if observed[path] != expected]
    if changed:
        raise EvidenceError(f"copied verification inputs changed: {changed}")
    return observed


def run_checks(repo, java, jar, out, timeout):
    if timeout <= 0:
        raise EvidenceError("timeout must be positive")
    manifest, cases, snapshot = load_inventory(repo)
    tools = read_json(snapshot["verify/tools.json"])
    jar = jar.resolve(strict=True)
    if digest(jar) != tools["tlc"]["sha256"]:
        raise EvidenceError("TLC jar digest does not match verify/tools.json")
    out.mkdir(parents=True, exist_ok=False)
    out = out.resolve()
    receipt = {"schema_version": 1, "complete": False, "verdict": "running",
               "scope": "finite model, not implementation proof", "tool": tools["tlc"],
               "inputs_sha256": {path: sha256(data) for path, data in snapshot.items()},
               "manifest": manifest, "expected_cases": len(cases), "cases": []}
    receipt_path = out / "receipt.json"
    write_json(receipt_path, receipt)
    try:
        runtime = subprocess.run([java, "-version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, timeout=15, check=True)
        receipt["java"] = runtime.stdout.strip()
        for path, data in snapshot.items():
            if Path(path).suffix in {".tla", ".cfg"}:
                copied = out / "inputs" / path
                copied.parent.mkdir(parents=True, exist_ok=True)
                copied.write_bytes(data)
        copied_hashes = {path: sha256(data) for path, data in snapshot.items()
                         if Path(path).suffix in {".tla", ".cfg"}}
        receipt["copied_inputs_sha256"] = copied_hashes
        for case in cases:
            check_copied_inputs(out / "inputs", copied_hashes)
            folder = out / case["suite"] / case["id"]
            folder.mkdir(parents=True)
            model, config = (out / "inputs" / case[key] for key in ("module", "config"))
            cmd = [java, "-Xmx512m", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC",
                   "-workers", "1", "-seed", "1", "-fp", "0", "-config", str(config),
                   "-metadir", str(folder / "states"), str(model)]
            entry = {"suite": case["suite"], "case": case["id"], "expected": case["expected"],
                     "declarations": case["declarations"], "command": cmd,
                     "model_sha256": sha256(snapshot[case["module"]]),
                     "config_sha256": sha256(snapshot[case["config"]])}
            started = time.monotonic()
            try:
                result = subprocess.run(cmd, cwd=model.parent, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, timeout=timeout)
                output = result.stdout
                entry["exit_code"] = result.returncode
                stats, trace = assess_result(result.returncode, output, case)
                entry.update(verdict="pass", states=stats)
                if trace is not None:
                    write_json(folder / "trace.json", {"schema_version": 1,
                        "scope": "current finite-model counterexample, not an implementation execution",
                        "model_sha256": entry["model_sha256"], "config_sha256": entry["config_sha256"],
                        "tlc_sha256": tools["tlc"]["sha256"], "expected": case["expected"], **trace})
            except subprocess.TimeoutExpired as error:
                output = error.stdout or ""
                if isinstance(output, bytes):
                    output = output.decode(errors="replace")
                output = "INCONCLUSIVE: timeout\n" + output
                entry.update(verdict="inconclusive", exit_code=None, error="timeout")
            except EvidenceError as error:
                entry.update(verdict="fail", error=str(error))
            except OSError as error:
                output = str(error) + "\n"
                entry.update(verdict="fail", exit_code=None, error=str(error))
            entry["elapsed_seconds"] = round(time.monotonic() - started, 6)
            (folder / "tlc.log").write_text(output)
            entry["log_sha256"] = digest(folder / "tlc.log")
            receipt["cases"].append(entry)
            write_json(receipt_path, receipt)
            print(json.dumps(entry), flush=True)
        # Reread the complete inventory and each attested source after all runs.
        # Copied model/config bytes pin what TLC consumed even during a bad edit.
        receipt["copied_inputs_after_sha256"] = check_copied_inputs(out / "inputs", copied_hashes)
        _, _, after = load_inventory(repo)
        receipt["inputs_after_sha256"] = {path: sha256(data) for path, data in after.items()}
        if receipt["inputs_sha256"] != receipt["inputs_after_sha256"] or digest(jar) != tools["tlc"]["sha256"]:
            raise EvidenceError("verification inputs changed during execution")
        receipt["complete"] = (len(receipt["cases"]) == len(cases)
                               and all(c["verdict"] == "pass" for c in receipt["cases"]))
        receipt["verdict"] = "pass" if receipt["complete"] else "fail"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt.update(verdict="fail", complete=False, error=str(error))
    write_json(receipt_path, receipt)
    return 0 if receipt["complete"] and receipt["verdict"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", required=True, type=Path)
    parser.add_argument("--java", default="java")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        return run_checks(ROOT.parent, args.java, args.jar, args.out, args.timeout)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
