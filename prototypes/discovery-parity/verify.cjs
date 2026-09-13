// Qualification harness only; product modules remain Rust.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const [modulePath, nativePath, wasmOutput] = process.argv.slice(2);
if (!modulePath || !nativePath || !wasmOutput) throw new Error('usage: verify.cjs GLUE NATIVE_BYTES WASM_BYTES');
const moduleFixture = require(path.resolve(modulePath));
const wasm = Buffer.from(moduleFixture.fixture_bytes());
const native = fs.readFileSync(nativePath);
if (!native.equals(wasm)) throw new Error(`native/WASM mismatch: native=${native.length}, wasm=${wasm.length}`);
fs.writeFileSync(wasmOutput, wasm, {flag:'wx'});
console.log(JSON.stringify({native_wasm:'equal',bytes:wasm.length,sha256:crypto.createHash('sha256').update(wasm).digest('hex')}));
