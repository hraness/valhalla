#!/usr/bin/env python3
"""Download only immutable producer outputs from this release run and source."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
import zipfile


REPOSITORY = "hraness/valhalla"
MAX_BYTES = 128 * 1024 * 1024
RELEASE_TARGETS = {
    "LINUX_GNU": "x86_64-unknown-linux-gnu",
    "LINUX_MUSL": "x86_64-unknown-linux-musl",
    "LINUX_ARM64": "aarch64-unknown-linux-musl",
    "WINDOWS": "x86_64-pc-windows-msvc",
    "MACOS": "aarch64-apple-darwin",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None


def context():
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "unexpected repository")
    require(re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")), "invalid source SHA")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(positive(os.environ.get(name)), "invalid workflow run identity")


def admit(metadata, producer, artifact_id, digest):
    context()
    require(positive(artifact_id) and re.fullmatch(r"[0-9a-f]{64}", digest),
            "missing exact producer outputs")
    require(isinstance(metadata, dict), "invalid artifact metadata")
    require(type(metadata.get("id")) is int and str(metadata["id"]) == artifact_id
            and metadata.get("digest") == "sha256:" + digest, "artifact ID or digest mismatch")
    name = metadata.get("name", "")
    match = re.fullmatch(re.escape(producer) + r"-([1-9][0-9]{0,19})", name) if isinstance(name, str) else None
    # Failed-job reruns retain successful producer outputs. Select those exact
    # bytes, never a latest-name lookup or the consumer's current attempt.
    require(match is not None and int(match[1]) <= int(os.environ["GITHUB_RUN_ATTEMPT"]),
            "artifact producer name or attempt mismatch")
    run = metadata.get("workflow_run")
    require(isinstance(run, dict) and type(run.get("id")) is int
            and str(run["id"]) == os.environ["GITHUB_RUN_ID"]
            and run.get("head_sha") == os.environ["GITHUB_SHA"], "artifact run/source mismatch")
    require(metadata.get("expired") is False and type(metadata.get("size_in_bytes")) is int
            and 0 < metadata["size_in_bytes"] <= MAX_BYTES, "artifact expired or oversized")


def api_bytes(endpoint, maximum):
    # Consumers run on Ubuntu/macOS. Bound the child's temporary-file writes,
    # not just the bytes loaded after gh exits, and keep API errors out of logs.
    def limit_file_bytes():
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}/{endpoint}"],
                                stdout=output, stderr=subprocess.DEVNULL, timeout=180, check=False,
                                preexec_fn=limit_file_bytes)
        require(result.returncode == 0 and 0 < output.tell() <= maximum,
                "artifact API failed or exceeded its byte limit")
        output.seek(0)
        return output.read(maximum + 1)


def fetch(producer, prefix=""):
    context()
    key = prefix + "_" if prefix else ""
    artifact_id = os.environ.get(key + "ARTIFACT_ID", "")
    digest = os.environ.get(key + "ARTIFACT_DIGEST", "")
    require(positive(artifact_id) and re.fullmatch(r"[0-9a-f]{64}", digest),
            "missing exact producer outputs")
    metadata = json.loads(api_bytes(f"actions/artifacts/{artifact_id}", 65536))
    admit(metadata, producer, artifact_id, digest)
    data = api_bytes(f"actions/artifacts/{artifact_id}/zip", MAX_BYTES)
    require(len(data) == metadata["size_in_bytes"] and hashlib.sha256(data).hexdigest() == digest,
            "artifact ZIP digest or size mismatch")
    return data


def unpack(data, destination, names=None):
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        entries = source.infolist()
        inventory = {entry.filename for entry in entries}
        require(0 < len(entries) <= 65 and len(inventory) == len(entries)
                and (names is None or inventory == names), "artifact ZIP inventory mismatch")
        total = 0
        for entry in entries:
            # All release archives and the qualified browser bundle are flat.
            require(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,255}", entry.filename)
                    and ".." not in entry.filename and not entry.is_dir()
                    and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
                    and not entry.flag_bits & 1 and 0 < entry.file_size <= MAX_BYTES,
                    "unsafe artifact ZIP entry")
            total += entry.file_size
            require(total <= MAX_BYTES, "artifact ZIP expanded byte limit")
        if not destination.exists():
            destination.mkdir(mode=0o700)
        require(stat.S_ISDIR(destination.lstat().st_mode), "artifact destination is not a real directory")
        require(not any((destination / name).exists() or (destination / name).is_symlink()
                        for name in inventory), "artifact destination already contains a member")
        for entry in entries:
            with source.open(entry) as stream:
                contents = stream.read(entry.file_size + 1)
            require(len(contents) == entry.file_size, "artifact ZIP member size mismatch")
            with (destination / entry.filename).open("xb") as output:
                output.write(contents)


def fetch_release(destination):
    tag = os.environ.get("GITHUB_REF_NAME", "")
    require(len(tag) <= 256 and re.fullmatch(r"v[0-9][A-Za-z0-9.+-]*", tag), "invalid release tag")
    require(os.environ.get("GITHUB_REF") == "refs/tags/" + tag, "release must use the exact version tag")
    for key, target in RELEASE_TARGETS.items():
        extension = ".zip" if key == "WINDOWS" else ".tar.gz"
        name = f"valhalla-{tag}-{target}{extension}"
        unpack(fetch("release-cli-" + target, key), destination, {name, name + ".sha256"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    archive = commands.add_parser("fetch-zip")
    archive.add_argument("producer", choices=("vhalla-unsigned", "release-cli-aarch64-apple-darwin"))
    archive.add_argument("destination", type=Path)
    for command in ("fetch-browser", "fetch-release"):
        commands.add_parser(command).add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "fetch-zip":
        data = fetch(args.producer)
        with args.destination.open("xb") as output:
            output.write(data)
    elif args.command == "fetch-browser":
        unpack(fetch("vhalla-browser"), args.destination)
    else:
        fetch_release(args.destination)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        raise SystemExit(f"Artifact download refused: {error}") from None
