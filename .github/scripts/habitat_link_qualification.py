#!/usr/bin/env python3
"""Run real ALGAL Habitat Link fixtures through Iroh on independent runners.

Reuse the mailbox controller's finite child supervision, credential isolation,
artifact selection, provenance checks, and cleanup verification.
"""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys

import iroh_qualification as controller

_original_context = controller.context
_original_child_env = controller.child_env
_original_validate_client = controller.validate_client
_original_setup = controller.setup
_probe = None


def algal_source():
    path = Path(os.environ["ALGAL_SOURCE"]).resolve(strict=True)
    expected = os.environ["ALGAL_REF"]
    controller.require(re.fullmatch(r"[a-f0-9]{40}", expected), "ALGAL_REF must be an exact commit")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
    controller.require(actual == expected, "ALGAL checkout differs from selected commit")
    controller.require((path / "scripts/habitat-link-iroh-qualification.ts").is_file(), "missing ALGAL fixture")
    return path


def context():
    source = algal_source()
    return dict(_original_context(), algal_sha=os.environ["ALGAL_REF"],
                algal_lock_sha256=controller.digest(source / "bun.lock"),
                bun_version=subprocess.check_output(["bun", "--version"], text=True).strip())


def package(messages, out):
    candidates = []
    for line in messages.read_text().splitlines():
        value = json.loads(line)
        if (value.get("reason") == "compiler-artifact" and value.get("executable")
                and value.get("target", {}).get("name") == "habitat-link-probe"
                and value["target"].get("kind") == ["example"]):
            candidates.append(Path(value["executable"]))
    controller.require(len(candidates) == 1, "expected one Habitat Link probe executable")
    out.mkdir(mode=0o700)
    shutil.copyfile(candidates[0], out / "fixture")
    (out / "fixture").chmod(0o700)
    controller.write_json(out / "build.json", dict(context(), schema=controller.SCHEMA,
        binary_sha256=controller.digest(out / "fixture"), lock_sha256=controller.digest(Path("Cargo.lock")),
        nonce=secrets.token_hex(32), toolchain="1.98.1", features="habitat-link",
        target="x86_64-unknown-linux-gnu"))


def setup(bundle, work, role):
    manifest, config = _original_setup(bundle, work, role)
    for key in ("secret", "token", "namespace"):
        config.pop(key, None)
    controller.write_json(work / "config.json", config)
    return manifest, config


def fixture_command(bundle, work):
    global _probe
    _probe = str((bundle / "fixture").resolve())
    bun = shutil.which("bun")
    controller.require(bun is not None, "Bun is required")
    # Probe and config paths are explicit arguments, never an ambient account token.
    return [bun, str(algal_source() / "scripts/habitat-link-iroh-qualification.ts")]


def child_env(config):
    controller.require(_probe is not None, "fixture command must select the probe")
    value = _original_child_env(config)
    value["ALGAL_IROH_PROBE"] = _probe
    return value


def validate_client(value, expected):
    _original_validate_client(value, expected)
    controller.require(all(value.get(key) == expected.get(key) for key in
                           ("algal_sha", "algal_lock_sha256", "bun_version")), "foreign ALGAL receipt")


def configure():
    controller.SCHEMA = "valhalla.habitat-link-independent-runners.v1"
    controller.CLIENT_CASES = ("caller_woke", "remote_result", "grant_refused", "exact_duplicate",
                               "forced_relay_paths_observed")
    controller.HOST_CASES = ("stopped_on_request", "service_joined", "remote_process_completed")
    controller.CONTROLLER = Path(__file__).resolve()
    controller.setup = setup
    controller.context = context
    controller.package = package
    controller.fixture_command = fixture_command
    controller.child_env = child_env
    controller.validate_client = validate_client

if __name__ == "__main__":
    try:
        configure()
        sys.exit(controller.main())
    except Exception as failure:
        print(f"Habitat Link qualification controller failed: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
