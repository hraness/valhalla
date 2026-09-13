#!/usr/bin/env python3
"""Compare audited tag bytes with separately resolved crates.io source."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
hashes = json.loads((Path(__file__).parent / 'upstream/source-hashes.json').read_text())
files = [(name, 'dioxus-desktop-0.7.10/src/' + name) for name in ['webview.rs', 'config.rs', 'protocol.rs', 'app.rs', 'launch.rs']]
files += [('asset-native.rs', 'dioxus-asset-resolver-0.7.10/src/native.rs'), ('manganis-macro.rs', 'manganis-macro-0.7.10/src/lib.rs')]
for name, source in files:
    assert hashlib.sha256((root / source).read_bytes()).hexdigest() == hashes[name], source
wry = (root / 'wry-0.53.5/src/lib.rs').read_text()
assert 'if self.attrs.custom_protocols.contains_key(&name)' in wry
assert 'crate::Error::DuplicateCustomProtocol(name)' in wry
print('PASS: 7 published crate files equal audited tag; Wry 0.53.5 duplicate-protocol rejection present')
