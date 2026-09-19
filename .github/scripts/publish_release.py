"""Publish one complete, verified draft after the exact release commit passes gates."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


CODEQL_CHECKS = {
    "Analyze (actions)",
    "Analyze (python)",
    "Analyze (javascript-typescript)",
    "Analyze (rust)",
}


def run_gh(*args):
    return subprocess.run(
        ["gh", *args], check=True, capture_output=True, text=True
    ).stdout


def asset_names(tag):
    if not re.fullmatch(r"v[0-9][A-Za-z0-9.+-]*", tag):
        raise ValueError("release tag must be a version beginning with v and a digit")
    archives = [
        f"valhalla-{tag}-aarch64-apple-darwin.tar.gz",
        f"valhalla-{tag}-x86_64-unknown-linux-gnu.tar.gz",
        f"valhalla-menubar-{tag}-aarch64-apple-darwin.tar.gz",
    ]
    return sorted(archives + [name + ".sha256" for name in archives])


def file_hash(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validate_assets(directory, tag):
    expected = asset_names(tag)
    if sorted(path.name for path in directory.iterdir()) != expected:
        raise ValueError("release requires exactly all three archives and checksum sidecars")
    hashes = {}
    for name in expected:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"release asset is not a nonempty regular file: {name}")
        hashes[name] = file_hash(path)
    for name in expected:
        if name.endswith(".sha256"):
            archive = name.removesuffix(".sha256")
            fields = (directory / name).read_text().split()
            if fields != [hashes[archive], archive]:
                raise ValueError(f"invalid release checksum: {name}")
    return hashes


def require_release_gates(gh, repo, tag, sha):
    def api(path):
        return json.loads(gh("api", f"repos/{repo}/{path}"))

    if api("git/ref/heads/main")["object"]["sha"] != sha:
        raise ValueError("release SHA must be the current main commit")
    ref = api(f"git/ref/tags/{tag}")["object"]
    # Peel annotated tags without permitting a cyclic or unbounded chain.
    for _ in range(8):
        if ref["type"] != "tag":
            break
        ref = api(f"git/tags/{ref['sha']}")["object"]
    if ref["type"] != "commit" or ref["sha"] != sha:
        raise ValueError("release tag no longer names the validated commit")

    pages = json.loads(gh(
        "api", f"repos/{repo}/commits/{sha}/check-runs?filter=latest&per_page=100",
        "--paginate", "--slurp",
    ))
    latest = {}
    for page in pages:
        for check in page["check_runs"]:
            name = check["name"]
            if name in CODEQL_CHECKS and check.get("app", {}).get("slug") == "github-actions":
                if name not in latest or check["id"] > latest[name]["id"]:
                    latest[name] = check
    for name in sorted(CODEQL_CHECKS):
        check = latest.get(name, {})
        if (check.get("head_sha") != sha or check.get("status") != "completed"
                or check.get("conclusion") != "success"):
            raise ValueError(f"exact release SHA requires a successful latest CodeQL {name}")


def publish(directory, tag, sha, repo, gh=run_gh):
    expected = validate_assets(directory, tag)
    require_release_gates(gh, repo, tag, sha)
    pages = json.loads(gh("api", f"repos/{repo}/releases?per_page=100", "--paginate", "--slurp"))
    release = next((item for page in pages for item in page if item["tag_name"] == tag), None)
    if release is None:
        gh("release", "create", tag, "--repo", repo, "--draft", "--verify-tag", "--generate-notes")
    if release is None or release["draft"]:
        gh("release", "upload", tag, "--repo", repo,
           *(str(directory / name) for name in expected), "--clobber")

    # Verify downloaded bytes before a draft becomes public. A retry of an
    # already published release is read-only and succeeds only for identical assets.
    with tempfile.TemporaryDirectory(prefix="valhalla-release-") as temporary:
        gh("release", "download", tag, "--repo", repo, "--dir", temporary)
        if validate_assets(Path(temporary), tag) != expected:
            raise ValueError("uploaded release bytes differ from the validated artifacts")
    if release is None or release["draft"]:
        require_release_gates(gh, repo, tag, sha)
        gh("release", "edit", tag, "--repo", repo, "--draft=false")
    print(f"Verified complete release {tag}: {len(expected)} assets at {sha}")


if __name__ == "__main__":
    try:
        publish(Path(sys.argv[1]), os.environ["GITHUB_REF_NAME"],
                os.environ["GITHUB_SHA"], os.environ["GH_REPO"])
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        # Do not dump subprocess environments or credentials into workflow logs.
        sys.exit(f"Release blocked: {error}")
