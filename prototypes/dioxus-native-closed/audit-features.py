#!/usr/bin/env python3
"""Check the selected cargo metadata graph; no building or network access."""
from collections import defaultdict
import copy
import hashlib
import json
from pathlib import Path
import sys

EXPECTED = {'dioxus-native': '0.7.10', 'dioxus-native-dom': '0.7.10', 'blitz-dom': '0.2.4', 'blitz-shell': '0.2.3', 'blitz-traits': '0.2.0', 'winit': '0.30.13'}

def audit(metadata):
    packages = {p['id']: p for p in metadata['packages']}
    groups = defaultdict(list)
    for n in metadata['resolve']['nodes']:
        p = packages[n['id']]
        groups[p['name']].append((p, set(n['features'])))
    def one(name):
        assert len(groups[name]) == 1, f'expected one {name}, found {len(groups[name])}'
        return groups[name][0]
    for name, version in EXPECTED.items():
        assert one(name)[0]['version'] == version, name
    assert one('dioxus-native')[1] == {'blitz-paint', 'svg', 'system-fonts'}
    assert not one('blitz-shell')[1]
    assert not one('blitz-traits')[1]
    assert not one('vhalla-dioxus-ui-spike')[1]
    assert not one('dioxus')[1] & {'native', 'desktop', 'web', 'launch', 'devtools', 'fullstack', 'server', 'liveview'}
    # Native-dom enables these defaults; they do not enable the platform bridge.
    assert one('dioxus-native-dom')[1] == {'accessibility', 'default', 'svg', 'system-fonts'}
    assert one('blitz-dom')[1] == {'accessibility', 'accesskit', 'svg', 'system_fonts'}
    for forbidden in ['wry', 'tao', 'blitz-net', 'blitz-html', 'arboard', 'rfd', 'accesskit_winit', 'accesskit_unix', 'glib']:
        assert not groups[forbidden], forbidden
    for p, _ in groups['quick-xml']:
        assert p['version'] == '0.41.0', 'unexpected quick-xml version: ' + p['version']
    return groups

def must_fail(metadata):
    try:
        audit(metadata)
    except AssertionError:
        return
    raise AssertionError('mutated feature graph was accepted')

def regression_checks(metadata):
    # A bad duplicate must not be hidden by the final by-name entry in either order.
    for reverse in [False, True]:
        changed = copy.deepcopy(metadata)
        for version in ['0.30.0', '0.41.0']:
            identifier = 'adversarial-test-quick-xml-' + version
            changed['packages'].append({'id': identifier, 'name': 'quick-xml', 'version': version})
            changed['resolve']['nodes'].append({'id': identifier, 'features': []})
        if reverse:
            changed['resolve']['nodes'].reverse()
        must_fail(changed)
    changed = copy.deepcopy(metadata)
    package = next(p for p in changed['packages'] if p['name'] == 'dioxus')
    next(n for n in changed['resolve']['nodes'] if n['id'] == package['id'])['features'].append('devtools')
    must_fail(changed)
    changed = copy.deepcopy(metadata)
    package = next(p for p in changed['packages'] if p['name'] == 'dioxus-native')
    changed['packages'].append(dict(package, id='duplicate-native'))
    node = next(n for n in changed['resolve']['nodes'] if n['id'] == package['id'])
    changed['resolve']['nodes'].append(dict(node, id='duplicate-native'))
    must_fail(changed)

raw = Path(sys.argv[1]).read_bytes()
metadata = json.loads(raw)
groups = audit(metadata)
regression_checks(metadata)
print('PASS: closed renderer features plus hidden-version/devtools/duplicate regressions')
print('selected_nodes', len(metadata['resolve']['nodes']), '(metadata graph includes dev dependencies)')
for name in [*EXPECTED, 'dioxus', 'vhalla-dioxus-ui-spike', 'dioxus-asset-resolver', 'webbrowser', 'quick-xml']:
    for package, features in groups[name]:
        print(name, package['version'], ','.join(sorted(features)) or '(no features)')
print('metadata_sha256', hashlib.sha256(raw).hexdigest())
