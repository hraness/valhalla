#!/usr/bin/env python3
"""Verify the retained CLI helper against separately obtained official tag files."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
source = Path(sys.argv[1])
manifest = json.loads((root / 'upstream/dx-feature-source.json').read_text())
for name, info in manifest.items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == info['sha256'], name
text = (source / 'build-renderer.rs').read_text()
start = text.index('    pub fn feature_for_platform_and_renderer(')
bracket = text.index('{', start)
end, depth = bracket + 1, 1
while depth:
    depth += (text[end] == '{') - (text[end] == '}')
    end += 1
helper = (root / 'upstream/dx-feature-helper.rs').read_text()
assert text[start:end] in helper
request = (source / 'build-request.rs').read_text()
assert 'Self::feature_for_platform_and_renderer(main_package, &triple, renderer)' in request
assert 'cargo_args.push("--no-default-features".to_string());' in request
print('PASS: exact dx0.7.10 helper source and Cargo feature-injection path; no CLI modification')
