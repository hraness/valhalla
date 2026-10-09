#!/usr/bin/env python3
"""Fail-closed aggregation of this attempt's headless qualification artifacts.

The workflow downloads seven *exactly named* artifacts from its own run. This
verifier checks their files, commitments, successful journeys and cleanup. MCP
emits source/binary but not lock/run/attempt: its exact artifact selection and
successful job bind those latter values; do not invent fields in its receipt.
This is advisory headless evidence, not browser, per-byte direct-path or NAT
qualification. It does not independently authenticate a compromised runner.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import headless_linux_managed_qualification as linux
import headless_managed_qualification as managed
import headless_mcp_qualification as mcp
import headless_private_qualification as private
import headless_qualification as public

MAX_JSON = 65536
MAX_BINARY = 256 * 1024 * 1024
MAX_AGE = 2 * 60 * 60  # Longer than the bounded build and role jobs; no timeless replay.
SKEW = 5 * 60
SCRIPTS = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hex_string(value, length):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{" + str(length) + r"}", value) is not None


def digest(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum,
                "missing, unsafe or oversized artifact file")
        hashed = hashlib.sha256()
        with os.fdopen(os.dup(descriptor), "rb") as source:
            while chunk := source.read(65536):
                hashed.update(chunk)
                require(source.tell() <= maximum, "artifact file grew beyond bound")
        require(os.fstat(descriptor).st_size == info.st_size, "artifact file changed while reading")
        return hashed.hexdigest()
    finally:
        os.close(descriptor)


def document(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_JSON,
                "missing, unsafe or oversized receipt")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read(MAX_JSON + 1)
        require(len(raw) == info.st_size and os.fstat(descriptor).st_size == info.st_size,
                "receipt changed or exceeded bound")
    finally:
        os.close(descriptor)

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON field")
            value[key] = item
        return value

    def reject_constant(_value):
        raise ValueError("non-finite JSON value")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    require(type(value) is dict, "receipt is not a JSON object")
    return value


def artifact(root, directory, files):
    path = root / directory
    require(stat.S_ISDIR(path.lstat().st_mode) and not path.is_symlink(),
            "missing or unsafe artifact directory")
    require({part.name for part in path.iterdir()} == set(files), "artifact file set differs")
    return {name: path / name for name in files}


def selected(value, expected, fields):
    for field in fields:
        require(type(value.get(field)) is type(expected[field]) and value[field] == expected[field],
                "receipt selection differs: " + field)


def current(value, now):
    started, finished = value.get("started_unix"), value.get("finished_unix")
    require(type(started) is int and type(finished) is int
            and now - MAX_AGE <= started <= finished <= now + SKEW,
            "receipt is stale, unfinished or from the future")


def success(value, schema, expected, now, *, full=True):
    require(value.get("schema") == schema and value.get("passed") is True
            and value.get("cleanup_confirmed") is True, "journey or cleanup failed")
    selected(value, expected, ("source_sha", "binary_sha256"))
    if full:
        selected(value, expected, ("run_id", "run_attempt", "lock_sha256", "nonce"))
    current(value, now)


def claims(value, expected):
    # A receipt for one journey cannot add its own unverified qualification.
    # MCP and managed-service receipts emit no qualification fields at all.
    require(not ({name for name in value if name.endswith("_qualified")} - set(expected)),
            "unrecognized qualification claim")
    for name, claim in expected.items():
        require(type(value.get(name)) is type(claim) and value[name] == claim,
                "unsupported qualification claim: " + name)


def public_role(value, role, expected, now):
    success(value, public.SCHEMA, expected, now)
    require(value.get("role") == role and value.get("placement") ==
            "separate GitHub-hosted Ubuntu job VMs; NAT diversity unmeasured"
            and value.get("relay_configured") is True, "wrong public placement or configuration")
    require(type(value.get("fixture_exit_code")) is int and value["fixture_exit_code"] == 0
            and value.get("fixture_forced_cleanup") is False, "public process did not join cleanly")
    require(hex_string(value.get("machine"), 64), "invalid public runner identity")
    public.validate_cases(value.get("cases"), public.HOST_CASES if role == "host" else public.CLIENT_CASES, role)
    observations = public.validate_transport(value.get("transport_observations"), role, "relay_only")
    claims(value, public.path_claims("relay_only", observations))
    return value


def private_role(value, role, expected, now):
    success(value, private.SCHEMA, expected, now)
    require(value.get("role") == role and value.get("source_attested") is True
            and value.get("placement") == "separate GitHub-hosted Ubuntu VMs; NAT diversity unmeasured",
            "wrong private placement or source selection")
    require(type(value.get("fixture_exit_code")) is int and value["fixture_exit_code"] == 0
            and value.get("fixture_forced_cleanup") is False, "private process did not join cleanly")
    require(hex_string(value.get("machine"), 64), "invalid private runner identity")
    private.validate_result({"cases": value.get("cases"), "remote_machine": value.get("remote_machine")}, role)
    observations = private.validate_transport(value.get("transport_observations"), role,
                                              {"relay": private.RELAY})
    claims(value, private.claims({"relay": private.RELAY, "mode": "runners"}, True, observations))
    return value


def paired(host, client):
    require(host["machine"] != client["machine"]
            and host.get("selected_client_machine") == client["machine"]
            and host.get("client_verified") is True, "host did not verify this separate client")


def verify(root, source_sha, run_id, run_attempt, lockfile, *, now=None):
    require(hex_string(source_sha, 40) and type(run_id) is str and type(run_attempt) is str
            and all(re.fullmatch(r"[1-9][0-9]*", value) for value in (run_id, run_attempt)),
            "invalid workflow context")
    now = int(time.time()) if now is None else now
    require(type(now) is int and now > 0, "invalid clock")
    require(stat.S_ISDIR(root.lstat().st_mode) and not root.is_symlink(), "unsafe artifact root")
    require({part.name for part in root.iterdir()} ==
            {"binary", "public-host", "public-client", "private-host", "private-client", "linux-managed", "mcp"},
            "missing or unexpected role artifact")
    binary = artifact(root, "binary", ("build.json", "fixture"))
    manifest = document(binary["build.json"])
    require(manifest.get("schema") == public.SCHEMA and manifest.get("source_sha") == source_sha
            and manifest.get("run_id") == run_id and manifest.get("run_attempt") == run_attempt
            and hex_string(manifest.get("nonce"), 64)
            and manifest.get("features") == "headless" and manifest.get("toolchain") == "1.98.1"
            and manifest.get("target") == "x86_64-unknown-linux-gnu"
            and manifest.get("build_profile") == "release", "foreign or malformed build manifest")
    profile = manifest.get("cargo_profile")
    require(type(profile) is dict and profile.get("opt_level") == "3"
            and profile.get("test") is False and profile.get("debug_assertions") is False,
            "build is not the release candidate")
    require(hex_string(manifest.get("binary_sha256"), 64)
            and hex_string(manifest.get("lock_sha256"), 64)
            and digest(binary["fixture"], MAX_BINARY) == manifest["binary_sha256"]
            and digest(lockfile, 2 * 1024 * 1024) == manifest["lock_sha256"],
            "binary or source lock differs from build")
    expected = {key: manifest[key] for key in
                ("source_sha", "run_id", "run_attempt", "nonce", "binary_sha256", "lock_sha256")}
    host = public_role(document(artifact(root, "public-host", ("host-receipt.json",))["host-receipt.json"]),
                       "host", expected, now)
    client = public_role(document(artifact(root, "public-client", ("client-receipt.json",))["client-receipt.json"]),
                         "client", expected, now)
    paired(host, client)
    require(host.get("client_machine") == client["machine"]
            and client["cases"]["host_machine"] == host["machine"], "public participants selected another runner")
    host = private_role(document(artifact(root, "private-host", ("host-receipt.json",))["host-receipt.json"]),
                        "host", expected, now)
    client = private_role(document(artifact(root, "private-client", ("client-receipt.json",))["client-receipt.json"]),
                          "client", expected, now)
    paired(host, client)
    require(host["remote_machine"] == client["machine"] and client["remote_machine"] == host["machine"],
            "private participants selected another runner")
    managed_files = artifact(root, "linux-managed", ("receipt.json", "cleanup-receipt.json"))
    service = document(managed_files["receipt.json"])
    cleanup = document(managed_files["cleanup-receipt.json"])
    success(service, linux.SCHEMA, expected, now)
    claims(service, {})
    require(service.get("build_profile") == "release" and service.get("platform") == "Linux systemd user"
            and service.get("scope") == "one fresh synthetic home; loopback only"
            and service.get("cleanup_fallback_used") is False,
            "managed service has unsupported scope or required fallback")
    cases = service.get("cases")
    require(type(cases) is dict and set(cases) == set(managed.CASES) |
            {"initial_process_verified", "resumed_process_verified", "enable_link_removed"}
            and all(case is True for case in cases.values()), "managed journey is incomplete")
    for field, path in (("runner_sha256", SCRIPTS / "headless_linux_managed_qualification.py"),
                        ("common_runner_sha256", SCRIPTS / "headless_managed_qualification.py")):
        require(service.get(field) == digest(path, 1024 * 1024), "managed runner bytes differ")
    require(cleanup.get("schema") == linux.SCHEMA and cleanup.get("cleanup_confirmed") is True
            and cleanup.get("cleanup_fallback_used") is False and cleanup.get("no_install_attempted") is not True,
            "managed always-cleanup failed")
    selected(cleanup, expected, ("source_sha", "run_id", "run_attempt"))
    process = document(artifact(root, "mcp", ("receipt.json",))["receipt.json"])
    # The MCP runner does not emit lock_sha256, run_id or run_attempt. Its
    # successful job and exact run/attempt artifact name are the run binding.
    success(process, mcp.SCHEMA, expected, now, full=False)
    claims(process, {})
    require(process.get("platform") == "linux" and process.get("scope") ==
            "one fresh public room; actual foreground daemon and MCP pipes; no network peer"
            and process.get("cleanup_fallback_used") is False
            and process.get("runner_sha256") == digest(SCRIPTS / "headless_mcp_qualification.py", 1024 * 1024),
            "MCP process has unsupported scope or cleanup")
    cases = process.get("cases")
    require(type(cases) is dict and set(cases) == set(mcp.CASES)
            and all(case is True for case in cases.values()), "MCP journey is incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--lockfile", type=Path, required=True)
    args = parser.parse_args()
    verify(args.artifacts, args.source_sha, args.run_id, args.run_attempt, args.lockfile)
    print("Exact headless receipts, candidate and cleanup verified; browser, direct path and NAT remain unqualified.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as failure:
        print(f"headless result rejected: {type(failure).__name__}", file=sys.stderr)
        sys.exit(1)
