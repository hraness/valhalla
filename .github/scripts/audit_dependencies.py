"""Audit every maintained Rust graph while retaining raw lockfile findings.

Cargo tree supplies the feature-enabled graph across all targets. Metadata is
cross-checked, but can overapproximate weak optional dependencies on this Cargo.
See Cargo's metadata and tree command docs; both raw outputs are retained.
No advisory IDs are ignored, including findings in inactive lockfile packages.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys


MANIFESTS = (
    "Cargo.toml",
    "desktop/Cargo.toml",
    "vendor/libp2p-dns/Cargo.toml",
)
ARCHIVE = Path("prototypes/browser-records/interop/native-admission-reference")


def discover_manifests(root):
    """Cover every retained prototype lock, including new/nested prototypes."""
    manifests = set(MANIFESTS)
    for directory, children, files in os.walk(root / "prototypes"):
        children[:] = sorted(set(children) - {"target", "node_modules", ".git", ".cache", "dist"})
        relative = Path(directory).relative_to(root)
        if relative == ARCHIVE:
            children[:] = []
            continue
        if "Cargo.lock" in files:
            if "Cargo.toml" not in files:
                raise ValueError(f"retained lockfile has no adjacent manifest: {relative}")
            manifests.add(str(relative / "Cargo.toml"))
    for manifest in manifests:
        path = root / manifest
        if not path.is_file() or not path.with_name("Cargo.lock").is_file():
            raise ValueError(f"maintained manifest/lockfile is missing: {manifest}")
    return tuple(sorted(manifests))


def resolved_packages(metadata):
    if metadata.get("version") != 1:
        raise ValueError("unsupported Cargo metadata schema")
    packages = metadata["packages"]
    by_id = {package["id"]: (package["name"], package["version"]) for package in packages}
    if len(by_id) != len(packages):
        raise ValueError("duplicate Cargo package IDs")
    nodes = metadata["resolve"]["nodes"]
    ids = {node["id"] for node in nodes}
    if not ids or len(ids) != len(nodes) or not ids <= by_id.keys():
        raise ValueError("invalid Cargo resolve node/package mapping")
    if not metadata["workspace_members"] or not set(metadata["workspace_members"]) <= ids:
        raise ValueError("workspace members missing from Cargo resolve graph")
    for node in nodes:
        if not set(node["dependencies"]) <= ids:
            raise ValueError("Cargo dependency edge points outside resolved graph")
    return {by_id[identifier] for identifier in ids}


def active_packages(metadata, tree):
    resolved = resolved_packages(metadata)
    active = set()
    for line in tree.splitlines():
        if line in ("", "[build-dependencies]", "[dev-dependencies]"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_-]+) v([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?)(.*)", line)
        if not match:
            raise ValueError(f"unrecognized cargo tree package line: {line}")
        name, version, suffix = match.groups()
        if suffix.endswith(" (*)"):
            suffix = suffix[:-4]
        if suffix.startswith(" (proc-macro)"):
            suffix = suffix.removeprefix(" (proc-macro)")
        # Cargo appends an absolute path or git URL for non-registry sources.
        # Unknown annotations fail closed instead of silently dropping a package.
        if suffix and not re.fullmatch(r" \((?:/[^\r\n]+|[A-Za-z]:[\\/][^\r\n]+|https?://[^\r\n]+)\)", suffix):
            raise ValueError(f"unrecognized cargo tree source suffix: {suffix}")
        active.add((name, version))
    by_id = {package["id"]: (package["name"], package["version"]) for package in metadata["packages"]}
    roots = {by_id[identifier] for identifier in metadata["workspace_members"]}
    if not active or not active <= resolved or not roots <= active:
        raise ValueError("cargo tree disagrees with metadata packages or omits workspace roots")
    return active


def validate_report(report, returncode):
    if returncode not in (0, 1):
        raise ValueError(f"cargo-audit failed with exit code {returncode}")
    settings = report["settings"]
    if (settings["ignore"] or settings["target_arch"] or settings["target_os"]
            or settings["severity"] is not None
            or not {"unmaintained", "unsound", "notice"} <= set(settings["informational_warnings"])):
        raise ValueError("audit configuration suppresses advisories or target platforms")
    findings = report["vulnerabilities"]["list"]
    if (not isinstance(findings, list)
            or report["vulnerabilities"]["count"] != len(findings)
            or report["vulnerabilities"]["found"] is not bool(findings)
            or returncode != int(bool(findings))):
        raise ValueError("inconsistent cargo-audit result")
    if not isinstance(report["warnings"], dict) or not report["database"]["advisory-count"]:
        raise ValueError("missing warnings or advisory database evidence")
    for finding in findings:
        for field in (finding["package"]["name"], finding["package"]["version"],
                      finding["advisory"]["id"], finding["advisory"]["title"]):
            if not isinstance(field, str) or not field:
                raise ValueError("malformed advisory identity")
    return findings


def classify(report, returncode, active):
    findings = validate_report(report, returncode)
    return [(finding, (finding["package"]["name"], finding["package"]["version"]) in active)
            for finding in findings]


def verify_archive(root):
    archive = root / ARCHIVE
    checksum_lines = (archive / "SHA256SUMS").read_text().splitlines()
    if not checksum_lines:
        raise ValueError("empty archival integrity manifest")
    checked = set()
    for line in checksum_lines:
        expected, relative = line.split(maxsplit=1)
        relative = relative.removeprefix("*")
        path = archive / relative
        if not path.resolve().is_relative_to(archive.resolve()) or path.is_symlink():
            raise ValueError("archival checksum path escapes the preserved reference")
        with path.open("rb") as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
        if actual != expected:
            raise ValueError(f"archival reference changed: {relative}")
        checked.add(relative.removeprefix("./"))
    if "Cargo.lock" not in checked:
        raise ValueError("archival lockfile is not protected by its integrity manifest")


def run(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def audit(root, output, audit_bin="cargo-audit", database=None, no_fetch=False):
    output.mkdir(parents=True, exist_ok=True)
    blocked = False
    command = [audit_bin, "audit", "--json"]
    if database:
        command += ["--db", database]
    if no_fetch:
        command += ["--no-fetch"]
    manifests = discover_manifests(root)
    for index, manifest in enumerate((*manifests, str(ARCHIVE / "Cargo.toml"))):
        archived = index == len(manifests)
        label = manifest.replace("/", "__")
        active = set()
        if archived:
            verify_archive(root)
        # Refresh once, then audit every lock against the same database snapshot.
        reuse_database = [] if no_fetch or index == 0 else ["--no-fetch"]
        result = run(command + reuse_database + ["--file", str(Path(manifest).with_name("Cargo.lock"))], root)
        (output / f"{label}.audit.json").write_text(result.stdout)
        (output / f"{label}.audit.stderr").write_text(result.stderr)
        report = json.loads(result.stdout)
        findings = validate_report(report, result.returncode)
        # A clean complete lock needs no activation filter. Resolve only when
        # deciding whether a reported vulnerability is actually enabled.
        if findings and not archived:
            metadata = run(["cargo", "metadata", "--manifest-path", manifest, "--all-features",
                            "--locked", "--format-version", "1"], root)
            (output / f"{label}.metadata.json").write_text(metadata.stdout)
            (output / f"{label}.metadata.stderr").write_text(metadata.stderr)
            if metadata.returncode:
                raise ValueError(f"Cargo metadata failed for {manifest}; see retained stderr")
            tree = run(["cargo", "tree", "--manifest-path", manifest, "--workspace",
                        "--all-features", "--target", "all", "--locked", "--color", "never",
                        "--edges", "normal,build,dev", "--prefix", "none", "--format", "{p}"], root)
            (output / f"{label}.tree.txt").write_text(tree.stdout)
            (output / f"{label}.tree.stderr").write_text(tree.stderr)
            if tree.returncode:
                raise ValueError(f"Cargo tree failed for {manifest}; see retained stderr")
            active = active_packages(json.loads(metadata.stdout), tree.stdout)
        scope = "preserved nonactivated archive" if archived else "all features, all target platforms" if findings else "complete lockfile; no vulnerability findings"
        print(f"{manifest}: {scope}")
        for finding, activated in classify(report, result.returncode, active):
            package = finding["package"]
            advisory = finding["advisory"]
            status = "ACTIVE VULNERABILITY" if activated else "ARCHIVED VULNERABILITY" if archived else "INACTIVE LOCKFILE VULNERABILITY"
            print(f"  {status}: {advisory['id']} {package['name']} {package['version']}: {advisory['title']}")
            blocked |= activated
        for kind, warnings in report["warnings"].items():
            for warning in warnings:
                # Every warning is visible here; full details remain in the raw report.
                package = warning["package"]
                advisory = warning.get("advisory") or {}
                detail = advisory.get("title", warning.get("reason", "see raw report"))
                print(f"  WARNING ({kind}): {package['name']} {package['version']} "
                      f"{advisory.get('id', '')}: {detail}")
        print(f"  Raw report: {output / (label + '.audit.json')}")
    if blocked:
        raise ValueError("active dependency vulnerabilities must be remediated before delivery")
    print("No active vulnerability findings; inactive/archive findings and warnings remain recorded above.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--audit-bin", default="cargo-audit")
    parser.add_argument("--database")
    parser.add_argument("--no-fetch", action="store_true")
    args = parser.parse_args()
    try:
        audit(Path(__file__).resolve().parents[2], args.output_dir.resolve(),
              args.audit_bin, args.database, args.no_fetch)
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        sys.exit(f"Dependency audit blocked: {error}")
