#!/usr/bin/env python3
"""Check pinned finite models and require the known-bad mutations to fail.

The runner never downloads tools or silently treats an interrupted run as a pass.
Full outputs and counterexamples remain in the requested new evidence directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def accepted_result(code, output, expected, has_trace):
    if expected is None:
        return code == 0 and "Model checking completed. No error has been found." in output
    # TLC 1.7.4 reports a completed invariant counterexample with exit 12.
    # A signal or another failure after printing a partial trace is not evidence
    # that the checker completed its expected negative run.
    return (code == 12 and f"Invariant {expected} is violated." in output and has_trace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", required=True, type=Path)
    parser.add_argument("--java", default="java")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    tools = json.loads((ROOT / "tools.json").read_text())
    jar = args.jar.resolve()
    if digest(jar) != tools["tlc"]["sha256"]:
        parser.error("TLC jar digest does not match verify/tools.json")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    args.out.mkdir(parents=True, exist_ok=False)
    runtime = subprocess.run([args.java, "-version"], capture_output=True,
                             text=True, timeout=15, check=True)
    cases = [
        ("private-delivery", "PrivateDelivery", "normal", None),
        ("private-delivery", "PrivateDelivery", "capacity", None),
        ("private-delivery", "PrivateDelivery", "mutant-skip", "NoLostWork"),
        ("private-delivery", "PrivateDelivery", "mutant-crash", "NoLostWork"),
        ("private-delivery", "PrivateDelivery", "mutant-duplicate", "ExactlyOnce"),
        ("private-rotation", "PrivateRotation", "normal", None),
        ("private-rotation", "PrivateRotation", "mutant-orphan", "NoOrphans"),
        ("private-rotation", "PrivateRotation", "mutant-budget", "PreservedSpend"),
        ("private-rotation", "PrivateRotation", "mutant-receipt", "BoundReceipts"),
        ("private-publication", "PrivatePublication", "normal", None),
        ("private-publication", "PrivatePublication", "mutant-early", "ConfirmedOutput"),
        ("private-publication", "PrivatePublication", "mutant-retarget", "DraftBinding"),
        ("private-publication", "PrivatePublication", "mutant-revoked", "AuthorizedOutput"),
        ("private-egress", "PrivateEgress", "normal", None),
        ("private-egress", "PrivateEgress", "mutant-tail", "OldBeforeControl"),
    ]
    receipt = {"tool": tools["tlc"], "java": runtime.stderr.strip(),
               "scope": "finite model, not implementation proof", "cases": []}
    for suite, module, name, expected in cases:
        model = ROOT / suite / (module + ".tla")
        folder = args.out / suite / name
        folder.mkdir(parents=True)
        config = model.parent / (name + ".cfg")
        cmd = [args.java, "-Xmx512m", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC",
               "-workers", "1", "-seed", "1", "-fp", "0",
               "-config", str(config), "-metadir", str(folder / "states"), str(model)]
        try:
            result = subprocess.run(cmd, cwd=model.parent, capture_output=True,
                                    text=True, timeout=args.timeout)
            output = result.stdout + result.stderr
            # Stable TLC 1.7.4 predates -dumpTrace. Preserve its original state
            # blocks in a JSON container without pretending to parse TLA values.
            trace = re.findall(r"(?ms)^State (\d+): (.*?)(?=^State \d+:|^\d+ states generated|\Z)", output)
            if trace:
                (folder / "trace.json").write_text(json.dumps(
                    [{"state": int(number), "tlc_text": body.strip()}
                     for number, body in trace], indent=2) + "\n")
            passed = accepted_result(result.returncode, output, expected,
                                     (folder / "trace.json").exists())
            verdict = "pass" if passed else "fail"
            code = result.returncode
        except subprocess.TimeoutExpired as error:
            output = "INCONCLUSIVE: timeout\n"
            for part in (error.stdout, error.stderr):
                output += part.decode(errors="replace") if isinstance(part, bytes) else (part or "")
            verdict, code = "inconclusive", None
        (folder / "tlc.log").write_text(output)
        stats = re.findall(r"([\d,]+) states generated, ([\d,]+) distinct states found", output)
        entry = {"suite": suite, "case": name, "verdict": verdict, "exit_code": code,
                 "expected_violation": expected, "model_sha256": digest(model),
                 "config_sha256": digest(config), "states": stats[-1] if stats else None}
        receipt["cases"].append(entry)
        (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(entry), flush=True)
    return 0 if all(case["verdict"] == "pass" for case in receipt["cases"]) else 1


if __name__ == "__main__":
    sys.exit(main())
