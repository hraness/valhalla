// Runs the wasm-bindgen glue under Node, writes the wasm rendering, and
// compares it with the native rendering and the committed expectations.
const fs = require("node:fs");
const [glue, nativePath, wasmPath] = process.argv.slice(2);
const mod = require(glue);
const wasm = mod.run_corpus();
fs.writeFileSync(wasmPath, wasm);
const native = fs.readFileSync(nativePath, "utf8");
const expected = mod.expected_corpus();
if (wasm !== native) {
  console.error("wasm and native renderings differ");
  process.exit(1);
}
if (wasm !== expected) {
  console.error("wasm rendering differs from the committed vectors");
  process.exit(1);
}
const files = (wasm.match(/^file: /gm) || []).length;
console.log(`wasm32 and native replays agree with the committed vectors on ${files} files`);
