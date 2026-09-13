#!/usr/bin/env python3
"""Inspect the actual Cargo fingerprint dependencies chosen for one dx binary.
The build owner supplies the exact fresh binary fingerprint and resulting artifact.
This is local build evidence, not authentication against a compromised build host.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_JSON = 256 * 1024
MAX_CANDIDATES = 4096
MAX_DEPS = 256
MAX_VARIANTS = 128
OWN_LIBRARY = 'vhalla_dioxus_native_closed_spike'
CRITICAL = {
    OWN_LIBRARY, 'dioxus_native', 'dioxus_native_dom', 'blitz_shell',
    'blitz_dom', 'blitz_traits', 'dioxus', 'vhalla_dioxus_ui_spike', 'winit',
}
ROOT_REQUIRED = CRITICAL - {'dioxus_native_dom'}
EXPECTED = {
    OWN_LIBRARY: {'native', 'renderer'},
    'dioxus_native': {'blitz-paint', 'svg', 'system-fonts'},
    'blitz_shell': set(),
    'blitz_traits': set(),
    'blitz_dom': {'accessibility', 'accesskit', 'svg', 'system_fonts'},
    'dioxus_native_dom': {'accessibility', 'default', 'svg', 'system-fonts'},
    'vhalla_dioxus_ui_spike': set(),
}
DIOXUS_DENIED = {'native', 'desktop', 'web', 'launch', 'devtools', 'fullstack', 'server', 'liveview'}


def read_json(path):
    assert path.stat().st_size <= MAX_JSON, 'fingerprint size'
    value = json.loads(path.read_text())
    assert isinstance(value, dict), 'unsupported Cargo fingerprint object'
    # Validate every dependency, including noncritical edges that are not traversed.
    features(value)
    dependencies(value)
    return value


def features(data):
    value = data['features']
    if isinstance(value, str):
        value = json.loads(value)
    assert isinstance(value, list) and len(value) <= 256, 'unsupported feature list'
    assert all(isinstance(item, str) and 0 < len(item) <= 128 for item in value), 'unsupported feature name'
    assert len(set(value)) == len(value), 'duplicate feature name'
    return set(value)


def dependencies(data):
    value = data['deps']
    assert isinstance(value, list) and len(value) <= MAX_DEPS, 'unsupported dependency list'
    names = set()
    for entry in value:
        assert isinstance(entry, list) and len(entry) == 4, 'unsupported dependency tuple'
        assert all(type(entry[index]) is int and 0 <= entry[index] < 2**64 for index in (0, 3)), 'unsupported dependency hash'
        assert isinstance(entry[1], str) and re.fullmatch(r'[A-Za-z0-9_]{1,128}', entry[1]), 'unsupported dependency name'
        assert type(entry[2]) is bool, 'unsupported dependency kind'
        assert entry[1] not in names, 'duplicate dependency name'
        names.add(entry[1])
    return value


def selected(base, parent, name):
    deps = [entry for entry in dependencies(parent) if entry[1] == name]
    assert len(deps) == 1, f'expected one direct compiled {name} dependency'
    expected_hash = deps[0][3]
    candidates = []
    for index, stamp in enumerate(base.glob('*/lib-' + name)):
        assert index < MAX_CANDIDATES, 'fingerprint scan bound'
        assert stamp.stat().st_size == 16, 'unsupported Cargo fingerprint encoding'
        encoded = stamp.read_text()
        assert re.fullmatch(r'[0-9a-fA-F]{16}', encoded), 'unsupported Cargo fingerprint encoding'
        if int.from_bytes(bytes.fromhex(encoded), 'little') == expected_hash:
            path = stamp.with_name(stamp.name + '.json')
            candidates.append((path, read_json(path)))
    assert candidates, f'missing compiled fingerprint for {name}'
    signatures = {json.dumps(data, sort_keys=True) for _, data in candidates}
    assert len(signatures) == 1, f'ambiguous compiled fingerprint for {name}'
    return candidates[0]


def audit(root_path):
    assert root_path.name == 'bin-vhalla-native-closed.json', 'wrong binary fingerprint'
    base = root_path.parent.parent
    assert base.name == '.fingerprint', 'expected exact Cargo fingerprint directory'
    root = read_json(root_path)
    assert ROOT_REQUIRED <= {entry[1] for entry in dependencies(root)}, 'missing direct root dependency'
    rows = {'vhalla_native_closed': (root_path, root)}
    pending = [root]
    seen = set()
    while pending:
        parent = pending.pop()
        for _, name, _, reference in dependencies(parent):
            if name not in CRITICAL or (name, reference) in seen:
                continue
            assert len(seen) < MAX_VARIANTS, 'critical variant bound'
            seen.add((name, reference))
            path, data = selected(base, parent, name)
            actual = features(data)
            if name in EXPECTED:
                assert actual == EXPECTED[name], f'compiled {name} features widened: {sorted(actual)}'
            if name == 'dioxus':
                assert not actual & DIOXUS_DENIED, f'compiled dioxus features widened: {sorted(actual)}'
            if name == 'dioxus_native':
                assert 'dioxus_native_dom' in {entry[1] for entry in dependencies(data)}, 'missing native DOM dependency'
            rows[f'{name}@{reference:016x}'] = (path, data)
            pending.append(data)
    assert CRITICAL <= {name for name, _ in seen}, 'missing critical compiled dependency'
    assert features(root) == {'native', 'renderer'}, 'dx did not select the closed local native alias'
    return rows


def digest(path):
    assert path.is_file() and path.stat().st_size <= 1024**3, 'artifact size bound'
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


if __name__ == '__main__':
    rows = audit(Path(sys.argv[1]))
    artifact = Path(sys.argv[2])
    for name, (path, data) in rows.items():
        print(name, ','.join(sorted(features(data))) or '(no features)', 'fingerprint_sha256=' + digest(path))
    print('PASS: every selected critical fingerprint edge links closed launcher/native/shell/DOM/UI feature variants')
    print('artifact', artifact.name, 'bytes', artifact.stat().st_size, 'sha256', digest(artifact))
