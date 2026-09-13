#!/usr/bin/env python3
"""Extract the audited routines from separately downloaded official tagged source.
No framework is patched. The real browser-open effect is replaced with a counter.
"""
from pathlib import Path
import hashlib,json,sys
root=Path(__file__).resolve().parent
source=Path(sys.argv[1])
files=['webview.rs','config.rs','protocol.rs','app.rs','asset-native.rs','launch.rs','desktop-Cargo.toml','root-Cargo.toml','native-Cargo.toml','native-link-handler.rs','native-assets.rs','cli-bundle.rs','manganis-macro.rs']
manifest=json.loads((root/'upstream/source-hashes.json').read_text())
for name in files:
 raw=(source/name).read_bytes()
 assert hashlib.sha256(raw).hexdigest()==manifest[name],f'source changed: {name}'
web=(source/'webview.rs').read_text();asset=(source/'asset-native.rs').read_text();protocol=(source/'protocol.rs').read_text();config=(source/'config.rs').read_text();launch=(source/'launch.rs').read_text();app=(source/'app.rs').read_text()
start=web.index('.with_navigation_handler(move |var| {')+len('.with_navigation_handler(move |var| {')
end=web.index('\n            })',start)
nav=web[start:end]
assert nav.index('webbrowser::open')<nav.index('navigation_handler.as_ref()')
assert '.with_asynchronous_custom_protocol(String::from("dioxus"), request_handler)' in web
assert protocol.index('if trimmed_uri == "__file_dialog"')<protocol.index('asset_handlers.has_handler')<protocol.index('dioxus_asset_resolver::native::serve_asset')
assert 'let body = payload.into_body();' in web and 'serde_json::from_str(&body)' in web
assert 'Box<dyn Fn(&str) -> bool' in config
assert launch.index('f(&window_event, event_loop)')<launch.index('match window_event')
assert 'webbrowser::open(href)' in app
start=asset.index('fn resolve_asset_path_from_filesystem(')
brace=asset.index('{',start);depth=1;end=brace+1
while depth:
 if asset[end]=='{':depth+=1
 elif asset[end]=='}':depth-=1
 end+=1
resolver=asset[start:end]
content='''// Extracted verbatim from DioxusLabs/dioxus v0.7.10; MIT OR Apache-2.0.
// Only webbrowser::open is replaced by the safe recording stub. The asset
// root getter is a test-owned dependency; no user path is read by the tests.
use std::{path::PathBuf,sync::atomic::AtomicBool};
type NavigationHandler=Box<dyn Fn(&str)->bool>;
fn original_navigation(var:String,page_loaded:&AtomicBool,navigation_handler:Option<NavigationHandler>)->bool {'''+nav.replace('webbrowser::open(&var)','record_external(&var)')+'\n}\n'+resolver+'\n'
(root/'upstream/extracted.rs').write_text(content)
print('PASS: exact source hashes, reachable protocol/IPC paths and navigation ordering; extracted two routines')
