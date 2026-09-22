#!/usr/bin/env python3
"""Verify the exact flat production browser artifact qualified by a receipt."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat


MAX_FILES = 64
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}")


def read_regular(path, maximum):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
        raise ValueError("browser evidence must be a bounded nonempty regular file")
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) != metadata.st_size:
        raise ValueError("browser evidence changed while being read")
    return raw


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate browser evidence field")
        value[key] = item
    return value


def document(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def verify(directory, *, receipt=None, manifest_sha256=None):
    if (receipt is None) == (manifest_sha256 is None):
        raise ValueError("select exactly one qualified receipt or manifest commitment")
    if not stat.S_ISDIR(directory.lstat().st_mode):
        raise ValueError("browser artifact must be a real directory")
    raw = read_regular(directory / "artifact.json", 65536)
    digest = hashlib.sha256(raw).hexdigest()
    if receipt is not None:
        evidence = document(read_regular(receipt, 1024 * 1024))
        if not isinstance(evidence, dict) or evidence.get("passed") is not True:
            raise ValueError("browser delivery qualification must have passed")
        manifest_sha256 = evidence.get("artifactManifestSha256")
    if (not isinstance(manifest_sha256, str)
            or SHA256.fullmatch(manifest_sha256) is None
            or digest != manifest_sha256):
        raise ValueError("browser artifact differs from the qualified manifest")
    manifest = document(raw)
    if (not isinstance(manifest, dict)
            or set(manifest) != {"format", "purpose", "assets"}
            or type(manifest["format"]) is not int or manifest["format"] != 1
            or manifest["purpose"] != "production"):
        raise ValueError("browser release requires the production manifest format")
    assets = manifest["assets"]
    if not isinstance(assets, dict) or not 1 <= len(assets) <= MAX_FILES or "index.html" not in assets:
        raise ValueError("browser manifest allowlist exceeds its bound or has no entry point")
    if {path.name for path in directory.iterdir()} != set(assets) | {"artifact.json"}:
        raise ValueError("browser artifact has missing or unqualified extra paths")
    total = 0
    for name, entry in assets.items():
        if (NAME.fullmatch(name) is None or ".." in name or name == "artifact.json"
                or not isinstance(entry, dict) or set(entry) != {"bytes", "sha256"}
                or type(entry["bytes"]) is not int
                or not 0 < entry["bytes"] <= MAX_FILE_BYTES
                or not isinstance(entry["sha256"], str)
                or SHA256.fullmatch(entry["sha256"]) is None):
            raise ValueError("browser manifest path or commitment is malformed")
        total += entry["bytes"]
        if total > MAX_TOTAL_BYTES:
            raise ValueError("browser artifact aggregate byte limit exceeded")
        contents = read_regular(directory / name, entry["bytes"])
        if (len(contents) != entry["bytes"]
                or hashlib.sha256(contents).hexdigest() != entry["sha256"]):
            raise ValueError("browser asset differs from its qualified commitment")
    return digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--receipt", type=Path)
    source.add_argument("--manifest-sha256")
    args = parser.parse_args()
    print(verify(args.directory, receipt=args.receipt, manifest_sha256=args.manifest_sha256))
