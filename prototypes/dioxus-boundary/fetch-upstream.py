#!/usr/bin/env python3
"""Fetch only pinned official source into an explicit disposable directory."""
import hashlib
import json
from pathlib import Path
import sys
from urllib.request import urlopen

FILES = {
    'webview.rs': 'packages/desktop/src/webview.rs',
    'config.rs': 'packages/desktop/src/config.rs',
    'protocol.rs': 'packages/desktop/src/protocol.rs',
    'app.rs': 'packages/desktop/src/app.rs',
    'launch.rs': 'packages/desktop/src/launch.rs',
    'asset-native.rs': 'packages/asset-resolver/src/native.rs',
    'desktop-Cargo.toml': 'packages/desktop/Cargo.toml',
    'root-Cargo.toml': 'Cargo.toml',
    'native-Cargo.toml': 'packages/native/Cargo.toml',
    'native-link-handler.rs': 'packages/native/src/link_handler.rs',
    'native-assets.rs': 'packages/native/src/assets.rs',
    'cli-bundle.rs': 'packages/cli/src/cli/bundle.rs',
    'manganis-macro.rs': 'packages/manganis/manganis-macro/src/lib.rs',
}

def main():
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    hashes = json.loads((Path(__file__).parent / 'upstream/source-hashes.json').read_text())
    assert set(hashes) == set(FILES)
    for name, source in FILES.items():
        path = target / name
        if path.exists():
            raw = path.read_bytes()
        else:
            with urlopen('https://raw.githubusercontent.com/DioxusLabs/dioxus/v0.7.10/' + source, timeout=30) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
        assert len(raw) <= 2 * 1024 * 1024
        assert hashlib.sha256(raw).hexdigest() == hashes[name], name
        if not path.exists():
            with path.open('xb') as output:
                output.write(raw)
    print('PASS: 13 exact official source files; no framework modification')

if __name__ == '__main__':
    main()
