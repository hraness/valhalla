"""Select the expensive Rust verification groups a change can affect.

The Rust workflow runs four groups only when their inputs change:

- ``prototypes``: one matrix entry per ``prototypes/*/Cargo.toml``;
- ``kani``: the bounded ``vhalla-native`` spent-nonce proofs;
- ``browser``: the four browser qualification jobs;
- ``formal``: TLC, Lean and Verus through ``verification.yml``.

A group's inputs are its Cargo packages, every local path dependency reachable
from them, and every repository file their Rust sources name with a relative
``../`` path. Formal inputs are ``verify/`` plus each correspondence source
named by ``verify/cases.json`` and ``verify/lean/claims.json``.

The selector fails closed. Every group runs in full when:

- the event is not a pull request or a push to main (nightly, dispatch and the
  release call always run everything);
- the change list is missing, incomplete or empty;
- a changed path touches CI, this selector, the Cargo workspace or lockfile,
  vendored crates, shared vectors or the toolchain;
- a changed path is not mapped to a known package or known non-Rust area;
- anything in the computation raises.

Retired prototypes under ``prototypes/retired/`` are manual-only; see
``prototypes/retired/README.md``.
"""
from __future__ import annotations

import argparse
import json
import posixpath
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Any change here can alter every group, so everything runs.
GLOBAL_FULL = re.compile(
    r"^(?:"
    r"\.github/workflows/.+"
    r"|\.github/scripts/(?:test_)?verify_scope\.py"
    r"|Cargo\.toml|Cargo\.lock"
    r"|rust-toolchain(?:\.toml)?|\.cargo/.+|clippy\.toml|\.clippy\.toml|rustfmt\.toml|\.rustfmt\.toml"
    r"|vendor/.+|vectors/.+"
    r")$"
)

# Known areas that no selected group reads. The unscoped jobs (quality, site,
# workspace tests, auxiliary, Windows, macOS, security, main policy) still
# cover them. A file here that a scoped crate reads (such as the seed recipe's
# start.sh, which vhalla-cli's tests run) is matched through that crate's closure
# first; `docs/` and `verify/` can still select `formal`.
NON_AFFECTING = re.compile(
    r"^(?:"
    r"(?:site|docs|kb|verify|deploy)/.+"
    r"|bun\.lock|package\.json|vercel\.json|\.vercelignore|LICENSE|railway\.toml|[^/]+\.md"
    r"|\.github/(?!workflows/).+"
    r"|prototypes/README\.md|prototypes/retired/.+"
    r")$"
)

PROTOTYPE_ROOT = "prototypes"
KANI_ROOTS = ("crates/vhalla-native",)
BROWSER_PACKAGES = (
    "browser",
    "crates/vhalla-browser-storage",
    "crates/vhalla-browser-vault",
    "crates/vhalla-public-peer",
    "crates/vhalla-cli",
    "prototypes/private-rooms-mls",
)
BROWSER_EXTRA = (
    "prototypes/browser-archive-recovery",
    ".github/scripts/verify_browser_artifact.py",
    ".github/scripts/pinned_chromium.sh",
    "site/tools/browser-contract.mjs",
    "package.json",
    "bun.lock",
)
FORMAL_MANIFESTS = ("verify/cases.json", "verify/lean/claims.json")

RELATIVE_LITERAL = re.compile(r'"[^"\n]*?((?:\.\./)+[A-Za-z0-9_.\-/]+)"')
DEPENDENCY_TABLE = re.compile(r"^(?:dev-|build-)?dependencies$")


class ScopeError(Exception):
    """The selector cannot prove a narrower scope."""


@dataclass
class Selection:
    full: bool
    prototypes: list[str]
    kani: bool
    browser: bool
    formal: bool
    reasons: list[str] = field(default_factory=list)

    def outputs(self) -> dict[str, str]:
        return {
            "scope": "full" if self.full else "scoped",
            "prototypes": json.dumps(self.prototypes, separators=(",", ":")),
            "kani": str(self.kani).lower(),
            "browser": str(self.browser).lower(),
            "formal": str(self.formal).lower(),
        }


def prototype_manifests(repo: Path) -> list[str]:
    """Top-level prototype crates, the same set the old `find -maxdepth 2` listed."""
    return sorted(p.relative_to(repo).as_posix() for p in (repo / PROTOTYPE_ROOT).glob("*/Cargo.toml"))


def full(repo: Path, reason: str) -> Selection:
    return Selection(True, prototype_manifests(repo), True, True, True, [reason])


def normalize(path: str) -> str | None:
    """Repository-relative POSIX path, or None when it leaves the repository."""
    joined = posixpath.normpath(path)
    if joined in (".", "") or joined.startswith("../") or joined == ".." or joined.startswith("/"):
        return None
    return joined


def within(path: str, node: str) -> bool:
    return path == node or path.startswith(node + "/")


class Graph:
    """Local Cargo path-dependency closure plus relative file references."""

    def __init__(self, repo: Path):
        self.repo = repo
        self._root = self._load(repo / "Cargo.toml")
        self._workspace_deps = self._root.get("workspace", {}).get("dependencies", {})
        self._closures: dict[str, frozenset[str]] = {}

    @staticmethod
    def _load(path: Path) -> dict:
        try:
            return tomllib.loads(path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise ScopeError(f"cannot read {path}: {error}") from error

    def _dependency_specs(self, manifest: dict):
        tables = [manifest]
        tables.extend(t for t in manifest.get("target", {}).values() if isinstance(t, dict))
        for table in tables:
            for key, deps in table.items():
                if DEPENDENCY_TABLE.match(key) and isinstance(deps, dict):
                    yield from deps.items()
        for patches in manifest.get("patch", {}).values():
            if isinstance(patches, dict):
                yield from patches.items()

    def local_dependencies(self, package: str) -> set[str]:
        manifest_path = self.repo / package / "Cargo.toml"
        if not manifest_path.is_file():
            raise ScopeError(f"package without manifest: {package}")
        manifest = self._load(manifest_path)
        found = set()
        for name, spec in self._dependency_specs(manifest):
            if not isinstance(spec, dict):
                continue
            base = package
            if spec.get("workspace") is True:
                spec = self._workspace_deps.get(name, {})
                base = ""
            path = spec.get("path") if isinstance(spec, dict) else None
            if isinstance(path, str):
                resolved = normalize(posixpath.join(base, path))
                if resolved is None:
                    raise ScopeError(f"{package} depends outside the repository: {path}")
                found.add(resolved)
        return found

    def referenced_files(self, package: str) -> set[str]:
        """Relative `../` paths in the package's Rust sources.

        A literal resolves both against its file (include_str!, #[path]) and
        against the package root (CARGO_MANIFEST_DIR joins). Ancestors of the
        referencing file (such as "../..") are not specific inputs and are
        ignored; everything else is kept, so an over-match only runs more.
        """
        found = set()
        root = self.repo / package
        for source in root.rglob("*.rs"):
            relative = source.relative_to(self.repo)
            if "target" in relative.parts:
                continue
            try:
                text = source.read_text(errors="replace")
            except OSError as error:
                raise ScopeError(f"cannot read {relative}: {error}") from error
            directory = relative.parent.as_posix()
            for literal in RELATIVE_LITERAL.findall(text):
                for base in (directory, package):
                    resolved = normalize(posixpath.join(base, literal))
                    if resolved is None or within(relative.as_posix(), resolved):
                        continue
                    if not within(resolved, package):
                        found.add(resolved)
        return found

    def closure(self, roots) -> frozenset[str]:
        key = "\0".join(sorted(roots))
        if key in self._closures:
            return self._closures[key]
        seen: set[str] = set()
        stack = list(roots)
        while stack:
            package = stack.pop()
            if package in seen:
                continue
            seen.add(package)
            stack.extend(self.local_dependencies(package) - seen)
        nodes = set(seen)
        for package in seen:
            nodes |= self.referenced_files(package)
        self._closures[key] = frozenset(nodes)
        return self._closures[key]


def formal_inputs(repo: Path) -> set[str]:
    inputs = {"verify"}
    for name in FORMAL_MANIFESTS:
        try:
            data = json.loads((repo / name).read_text())
        except (OSError, ValueError) as error:
            raise ScopeError(f"cannot read {name}: {error}") from error
        if name.endswith("cases.json"):
            sources = [s["path"] for suite in data["suites"] for s in suite["sources"]]
        else:
            sources = list(data["correspondence_sources"])
        for source in sources:
            resolved = normalize(source) if isinstance(source, str) else None
            if resolved is None:
                raise ScopeError(f"invalid correspondence source in {name}: {source!r}")
            inputs.add(resolved)
    return inputs


def known_package(repo: Path, path: str) -> bool:
    """A path inside crates/<name>/ or prototypes/<name>/ that exists as a directory."""
    parts = path.split("/")
    return len(parts) >= 3 and parts[0] in ("crates", PROTOTYPE_ROOT) and (repo / parts[0] / parts[1]).is_dir()


def select_changes(repo: Path, changed: list[str] | None) -> Selection:
    if changed is None:
        return full(repo, "change list unavailable or incomplete")
    paths = sorted({p.strip() for p in changed if p.strip()})
    if not paths:
        return full(repo, "empty change list")
    for path in paths:
        if normalize(path) != path:
            return full(repo, f"unexpected path form: {path!r}")
        if GLOBAL_FULL.match(path):
            return full(repo, f"global input changed: {path}")

    graph = Graph(repo)
    manifests = prototype_manifests(repo)
    prototype_closures = {m: graph.closure([posixpath.dirname(m)]) for m in manifests}
    kani_nodes = graph.closure(KANI_ROOTS)
    browser_nodes = graph.closure(BROWSER_PACKAGES) | set(BROWSER_EXTRA)
    formal_nodes = formal_inputs(repo)

    def hit(path: str, nodes) -> bool:
        return any(within(path, node) for node in nodes)

    selected: set[str] = set()
    kani = browser = formal = False
    reasons = []
    for path in paths:
        mapped = False
        for manifest, nodes in prototype_closures.items():
            if hit(path, nodes):
                selected.add(manifest)
                mapped = True
        if hit(path, kani_nodes):
            kani = mapped = True
        if hit(path, browser_nodes):
            browser = mapped = True
        if hit(path, formal_nodes):
            formal = mapped = True
        if mapped or NON_AFFECTING.match(path):
            continue
        if path == "browser" or path.startswith("browser/"):
            continue  # browser/ is always in the browser closure; defensive only
        if known_package(repo, path):
            # A workspace crate or non-Cargo prototype outside every scoped
            # closure: only the unscoped jobs read it.
            continue
        return full(repo, f"unmapped path: {path}")
    reasons.append(f"{len(paths)} changed paths")
    return Selection(False, sorted(selected), kani, browser, formal, reasons)


def select(repo: Path, event: str, ref: str, changed: list[str] | None, rust: bool = True) -> Selection:
    if event == "pull_request" or (event == "push" and ref == "refs/heads/main"):
        try:
            selection = select_changes(repo, changed)
        except Exception as error:  # noqa: BLE001 - any failure runs everything
            selection = full(repo, f"selector error: {error}")
    else:
        selection = full(repo, f"{event} on {ref} always runs everything")
    if not rust:
        # The workflow's own non-Rust filter skipped every Rust job; formal
        # stays independently selected (docs can be correspondence sources).
        selection.prototypes, selection.kani, selection.browser = [], False, False
    return selection


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--changed-files", help="newline-separated changed paths; omit when unknown")
    parser.add_argument("--rust", choices=("true", "false"), default="true")
    parser.add_argument("--output", help="append key=value lines here (GITHUB_OUTPUT)")
    parser.add_argument("--repo", default=str(REPO))
    args = parser.parse_args(argv)
    repo = Path(args.repo)
    changed = None
    if args.changed_files:
        try:
            changed = Path(args.changed_files).read_text().splitlines()
        except OSError:
            changed = None
    selection = select(repo, args.event, args.ref, changed, args.rust == "true")
    outputs = selection.outputs()
    for reason in selection.reasons:
        print(f"reason: {reason}")
    if not args.output:
        for key, value in outputs.items():
            print(f"{key}={value}")
    else:
        with open(args.output, "a", encoding="utf-8") as stream:
            for key, value in outputs.items():
                stream.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
