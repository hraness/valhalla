"""Render and check a Valhalla GitHub Release page.

The page follows the Hraness release standard (RELEASES.md in hraness/.github):
title "Valhalla <tag>", then the version's CHANGELOG.md section (summary and
`## Changes`), generated `## Install` and `## Verify`, and the release identity
record as a trailing HTML comment that forms the final bytes of the body.

Run directly to render the page for an already published tag, for example
when correcting a page by hand:

    python3 .github/scripts/release_notes.py v0.2.3 --repo hraness/valhalla \
        --commit <sha> --assets <dir-with-release-assets> > notes.md
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


PRODUCT = "Valhalla"
IDENTITY_PREFIX = "<!-- valhalla-release "
IDENTITY_SUFFIX = " -->"
CHANGELOG = Path(__file__).resolve().parents[2] / "CHANGELOG.md"
TARGET_LABELS = {
    "aarch64-apple-darwin": "Apple Silicon macOS",
    "x86_64-unknown-linux-gnu": "x86-64 Linux (glibc)",
    "x86_64-unknown-linux-musl": "x86-64 Linux (static musl)",
    "aarch64-unknown-linux-musl": "ARM64 Linux (static musl)",
}
_HEADING = re.compile(r"^## (?P<title>.*?)\s*$")
_VERSION_HEADING = re.compile(
    r"^v?(?P<version>[0-9][A-Za-z0-9.+-]*)(?: - (?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2}))?$")


def title(tag):
    return f"{PRODUCT} {tag}"


def changelog_section(text, tag):
    """Return (summary, bullets) for the tag's CHANGELOG section or raise."""
    version = tag.removeprefix("v")
    lines = text.replace("\r\n", "\n").split("\n")
    start = None
    for index, line in enumerate(lines):
        match = _HEADING.match(line)
        if not match:
            continue
        heading = match.group("title")
        words = re.split(r"[\s\-]+", heading)
        if words and words[0].removeprefix("v") == version and "unreleased" in heading.lower():
            raise ValueError(f"CHANGELOG.md section for {tag} still says Unreleased")
        found = _VERSION_HEADING.match(heading)
        if found and found.group("version") == version:
            if start is not None:
                raise ValueError(f"CHANGELOG.md has more than one section for {tag}")
            start = index + 1
    if start is None:
        raise ValueError(f"CHANGELOG.md has no section for {tag}")
    end = next((index for index in range(start, len(lines))
                if lines[index].startswith("## ") or lines[index].startswith("# ")),
               len(lines))
    body = "\n".join(lines[start:end]).strip()
    if not body:
        raise ValueError(f"CHANGELOG.md section for {tag} is empty")
    if "unreleased" in body.lower():
        raise ValueError(f"CHANGELOG.md section for {tag} still says Unreleased")
    body_lines = body.split("\n")
    first_bullet = next((index for index, line in enumerate(body_lines)
                         if line.startswith("- ")), None)
    if first_bullet is None:
        raise ValueError(f"CHANGELOG.md section for {tag} has no change bullets")
    summary = "\n".join(body_lines[:first_bullet]).strip()
    bullets = "\n".join(body_lines[first_bullet:]).strip()
    if not summary:
        raise ValueError(f"CHANGELOG.md section for {tag} has no summary paragraph")
    for line in bullets.split("\n"):
        if line and not (line.startswith("- ") or line.startswith("  ")):
            raise ValueError(f"CHANGELOG.md section for {tag} has text after its change bullets")
    return summary, bullets


def _archive_label(name, tag):
    if name == f"valhalla-browser-{tag}.tar.gz":
        return "Browser bundle"
    menubar = f"valhalla-menubar-{tag}-"
    if name.startswith(menubar):
        target = name.removeprefix(menubar).removesuffix(".tar.gz")
        return f"Menu-bar companion, {TARGET_LABELS.get(target, target)}"
    target = name.removeprefix(f"valhalla-{tag}-").removesuffix(".tar.gz")
    return f"`vhalla` CLI, {TARGET_LABELS.get(target, target)}"


def identity_record(repo, tag, commit, assets):
    return {"assets": dict(sorted(assets.items())), "commit": commit,
            "repository": repo, "tag": tag}


def identity_comment(repo, tag, commit, assets):
    record = identity_record(repo, tag, commit, assets)
    return IDENTITY_PREFIX + json.dumps(record, sort_keys=True, separators=(",", ":")) + IDENTITY_SUFFIX


def render_notes(changelog_text, repo, tag, commit, assets):
    """Return the visible notes (everything above the identity record)."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release commit must be a full 40-character SHA")
    summary, bullets = changelog_section(changelog_text, tag)
    archives = sorted(name for name in assets if name.endswith(".tar.gz"))
    cli = f"valhalla-{tag}-aarch64-apple-darwin.tar.gz"
    if cli not in archives or any(name + ".sha256" not in assets for name in archives):
        raise ValueError("release assets must include the Apple Silicon CLI and every checksum sidecar")
    download = f"https://github.com/{repo}/releases/download/{tag}"
    blob = f"https://github.com/{repo}/blob/{tag}"
    lines = [
        summary,
        "",
        "## Changes",
        "",
        bullets,
        "",
        "## Install",
        "",
        "Download, check and unpack the `vhalla` CLI for Apple Silicon macOS:",
        "",
        "```console",
        f"curl -fsSLO {download}/{cli}",
        f"curl -fsSLO {download}/{cli}.sha256",
        f"shasum -a 256 -c {cli}.sha256",
        f"tar -xzf {cli}",
        f"./valhalla-{tag}-aarch64-apple-darwin/vhalla --help",
        "```",
        "",
        "The other archives in this release download and check the same way:",
        "",
    ]
    lines += [f"- {_archive_label(name, tag)}: `{name}`" for name in archives if name != cli]
    lines += [
        "",
        "## Verify",
        "",
        "Each archive has a checksum file attached to this release, named after the archive "
        "with `.sha256` added. The SHA-256 digests are:",
        "",
        "```text",
        *(f"{assets[name]}  {name}" for name in archives),
        "```",
        "",
        f"Built from commit `{commit}`. "
        f"[How releases are built and checked]({blob}/crates/vhalla-cli/README.md#releases).",
        "",
    ]
    return "\n".join(lines)


def render_body(changelog_text, repo, tag, commit, assets):
    return (render_notes(changelog_text, repo, tag, commit, assets)
            + "\n" + identity_comment(repo, tag, commit, assets))


def parse_identity(body):
    """Return (notes, record) from a release body or raise ValueError."""
    if not body.endswith(IDENTITY_SUFFIX.strip()):
        raise ValueError("release body must end with its identity record")
    start = body.rfind(IDENTITY_PREFIX)
    if start < 0:
        raise ValueError("release body has no identity record")
    payload = body[start + len(IDENTITY_PREFIX):-len(IDENTITY_SUFFIX)]
    try:
        record = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError("release identity record is not valid JSON") from error
    if (not isinstance(record, dict)
            or set(record) != {"assets", "commit", "repository", "tag"}
            or not isinstance(record["assets"], dict)):
        raise ValueError("release identity record is malformed")
    notes = body[:start]
    if not notes.endswith("\n"):
        raise ValueError("release identity record must start on its own line")
    return notes[:-1], record


def verify_body(body, changelog_text, repo, tag, commit, assets):
    """Raise unless body is exactly the rendered page for this release."""
    notes, record = parse_identity(body)
    if record != identity_record(repo, tag, commit, assets):
        raise ValueError("release identity record does not match the validated release")
    if notes != render_notes(changelog_text, repo, tag, commit, assets):
        raise ValueError("release notes differ from the rendered CHANGELOG section")


def _asset_hashes(directory):
    hashes = {}
    for path in sorted(Path(directory).iterdir()):
        if path.is_file() and path.name.endswith((".tar.gz", ".tar.gz.sha256")):
            with path.open("rb") as source:
                hashes[path.name] = hashlib.file_digest(source, "sha256").hexdigest()
    return hashes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("tag")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets", required=True, help="directory holding the release assets")
    parser.add_argument("--changelog", default=str(CHANGELOG))
    parser.add_argument("--title", action="store_true", help="print the release title instead")
    args = parser.parse_args(argv)
    if args.title:
        print(title(args.tag))
        return
    text = Path(args.changelog).read_text(encoding="utf-8")
    sys.stdout.write(render_body(text, args.repo, args.tag, args.commit,
                                 _asset_hashes(args.assets)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        sys.exit(f"Release notes blocked: {error}")
