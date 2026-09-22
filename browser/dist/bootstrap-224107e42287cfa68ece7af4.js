
import init, * as bindings from '/vhalla-browser-ec7eb14c1d6f0ff0.js';
const wasm = await init({ module_or_path: '/vhalla-browser-ec7eb14c1d6f0ff0_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

