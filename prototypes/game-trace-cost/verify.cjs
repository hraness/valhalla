// Runs the wasm32 trace under Node, times it, and compares with native.
const fs = require("node:fs");
const [glue, nativePath, wasmPath] = process.argv.slice(2);
const mod = require(glue);
const t0 = process.hrtime.bigint();
const wasm = mod.run_corpus();
const ms = Number(process.hrtime.bigint() - t0) / 1e6;
fs.writeFileSync(wasmPath, wasm);
const native = fs.readFileSync(nativePath, "utf8");
if (wasm !== native) { console.error("wasm and native trace renderings differ"); process.exit(1); }
if (wasm.includes("error")) { console.error(wasm); process.exit(1); }
const files = (wasm.match(/^\S+\.txt: /gm) || []).length;
const heap = (process.memoryUsage().arrayBuffers / 1048576).toFixed(1);
console.log(`wasm32 trace heads equal native on ${files} vectors; whole corpus in ${ms.toFixed(1)} ms; wasm heap ${heap} MiB`);
