// Runs the wasm-bindgen glue under Node, writes the wasm rendering, and
// compares it with the native rendering and the committed expectations.
const fs = require("node:fs");
const [glue, nativePath, wasmPath] = process.argv.slice(2);
const mod = require(glue);
const t0 = process.hrtime.bigint();
const wasm = mod.run_corpus();
const ms = Number(process.hrtime.bigint() - t0) / 1e6;
fs.writeFileSync(wasmPath, wasm);
const native = fs.readFileSync(nativePath, "utf8");
const expected = mod.expected_corpus();
if (wasm.includes("error: ")) {
  console.error(wasm);
  process.exit(1);
}
if (wasm !== native) {
  console.error("wasm and native session replays differ");
  process.exit(1);
}
if (wasm !== expected) {
  console.error("wasm replay differs from the committed session vectors");
  process.exit(1);
}
const vectors = (wasm.match(/^vector: /gm) || []).length;
const seals = (wasm.match(/^seal\[\d+\]\.checkpoint_hash: /gm) || []).length;
console.log(
  `wasm32 and native session replays agree with the committed vectors on ${vectors} vectors and ${seals} checkpoints; whole corpus in ${ms.toFixed(1)} ms`,
);
