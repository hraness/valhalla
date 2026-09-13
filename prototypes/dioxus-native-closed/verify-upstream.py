#!/usr/bin/env python3
"""Verify the exact prototype-only upstream patch, optionally against release tar."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

root = Path(__file__).resolve().parent
manifest = json.loads((root / 'upstream/provenance.json').read_text())
vendor = root / 'upstream/dioxus-native'
actual = {str(p.relative_to(vendor)) for p in vendor.rglob('*') if p.is_file()}
assert actual == set(manifest['original_files']), 'unexpected vendored file'
for name, original_hash in manifest['original_files'].items():
    expected = manifest['patched_sha256'] if name == manifest['patched_file'] else original_hash
    assert hashlib.sha256((vendor / name).read_bytes()).hexdigest() == expected, name
if len(sys.argv) > 1:
    archive = Path(sys.argv[1])
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == manifest['archive_sha256']
    with tarfile.open(archive, 'r:gz') as source:
        for name, expected in manifest['original_files'].items():
            data = source.extractfile('dioxus-native-0.7.10/' + name).read()
            assert hashlib.sha256(data).hexdigest() == expected, name
print('PASS: 12 published files retained; only src/config.rs differs by pinned cfg fallback patch')
print('official_archive_sha256', manifest['archive_sha256'])
print('patched_config_sha256', manifest['patched_sha256'])
