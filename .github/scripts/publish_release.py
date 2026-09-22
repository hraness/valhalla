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
    "Analyze (actions)": "github-actions",
    "Analyze (python)": "github-actions",
    "Analyze (javascript-typescript)": "github-actions",
    "Analyze (rust)": "github-actions",
    # When GitHub emits its PR verdict, a workflow cannot impersonate it.
    "CodeQL": "github-advanced-security",
}
CODEQL_CATEGORIES = {f"/language:{language}" for language in
                     ("actions", "python", "javascript-typescript", "rust")}
CODEQL_ANALYSIS_KEY = "dynamic/github-code-scanning/codeql:analyze"


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
        f"valhalla-browser-{tag}.tar.gz",
    ]
    return sorted(archives + [name + ".sha256" for name in archives])


def file_hash(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validate_assets(directory, tag):
    expected = asset_names(tag)
    if sorted(path.name for path in directory.iterdir()) != expected:
        raise ValueError("release requires exactly all four archives and checksum sidecars")
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
            if (name in CODEQL_CHECKS
                    and check.get("app", {}).get("slug") == CODEQL_CHECKS[name]):
                if name not in latest or check["id"] > latest[name]["id"]:
                    latest[name] = check
    for name in sorted(CODEQL_CHECKS):
        # GitHub's managed CodeQL emits the separate verdict on PR heads,
        # but this repository's default-branch analysis has no such check.
        # Never infer a clean release from analysis-job success: the exact
        # main analysis + open-alert inventory below are always required.
        if name == "CodeQL" and name not in latest:
            if any(check.get("name") == "CodeQL" for page in pages for check in page["check_runs"]):
                raise ValueError("foreign CodeQL verdict cannot establish release security")
            continue
        check = latest.get(name, {})
        if (check.get("head_sha") != sha or check.get("status") != "completed"
                or check.get("conclusion") != "success"):
            raise ValueError(f"exact release SHA requires a successful latest CodeQL {name}")
    require_clean_main_analysis(gh, repo, sha)


def require_clean_main_analysis(gh, repo, sha):
    # These are the actual managed analysis categories on refs/heads/main.
    # GitHub returns newest-created first. IDs identify analyses but are not the
    # documented ordering contract. A bounded missing-category result refuses.
    analyses = json.loads(gh("api", f"repos/{repo}/code-scanning/analyses"
                            "?ref=refs%2Fheads%2Fmain&tool_name=CodeQL&per_page=100"
                            "&sort=created&direction=desc"))
    latest = {}
    for analysis in analyses:
        category = analysis.get("category")
        if (category in CODEQL_CATEGORIES
                and analysis.get("tool", {}).get("name") == "CodeQL"
                and analysis.get("ref") == "refs/heads/main"):
            latest.setdefault(category, analysis)
    for category in sorted(CODEQL_CATEGORIES):
        analysis = latest.get(category, {})
        if (analysis.get("commit_sha") != sha or analysis.get("error") != ""
                or analysis.get("analysis_key") != CODEQL_ANALYSIS_KEY):
            raise ValueError(f"exact release SHA requires a clean main analysis for {category}")
    pages = json.loads(gh("api", f"repos/{repo}/code-scanning/alerts"
                         "?ref=refs%2Fheads%2Fmain&tool_name=CodeQL&state=open&per_page=100",
                         "--paginate", "--slurp"))
    # Every open CodeQL alert blocks release, including preexisting findings.
    # Only actual fixes or separately authorized, individually reviewed GitHub
    # dispositions clear this gate. No severity/path/fixture exemptions here.
    if (not isinstance(pages, list) or not pages
            or any(not isinstance(page, list) or page for page in pages)):
        raise ValueError("release requires no open CodeQL alerts on the analyzed main branch")


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
