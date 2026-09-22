#!/usr/bin/env node
// Real Chromium/IndexedDB regression of the Rust example, isolated from all user profiles.
// Usage: node qualify_storage.mjs GENERATED_WASM_DIRECTORY CHROMIUM_EXECUTABLE
import {trackChild, cleanupOwned, runQualification} from './qualification_lifecycle.mjs';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';

const [directory, executable] = process.argv.slice(2);
if (!directory || !executable) throw new Error('requires generated WASM directory and Chromium executable');
const root = resolve(directory);
const profile = await mkdtemp(join(root, 'chromium-profile-'));
const runner = `import * as wasm from './indexeddb_qualification.js';
const init = wasm.default;
const qualify = wasm.qualify;
export const hasInterruption = typeof wasm.interruptible === 'function' && typeof wasm.verify_interrupted === 'function';
export async function run() {
try {
  await init();
  const original = IDBDatabase.prototype.transaction;
  const add = IDBObjectStore.prototype.add;
  const put = IDBObjectStore.prototype.put;
  let mode = 'require-strict', writes = 0, mutations = 0;
  const metrics = {strictWrites: 0, readonly: 0, faults: []};
  const foreign = {};
  IDBObjectStore.prototype.add = function(...args) { mutations++; return add.apply(this, args); };
  IDBObjectStore.prototype.put = function(...args) { mutations++; return put.apply(this, args); };
  IDBDatabase.prototype.transaction = function(names, access, options) {
    if (access !== 'readwrite') { metrics.readonly++; return original.call(this, names, access); }
    writes++;
    if (mode === 'deny-writes') throw new DOMException('synthetic write denial', 'QuotaExceededError');
    if (options?.durability !== 'strict') throw new Error('write omitted strict durability');
    metrics.strictWrites++;
    const tx = original.call(this, names, access, mode === 'ignored-options' ? undefined : options);
    if (mode === 'ignored-options') Object.defineProperty(tx, 'durability', {value: 'relaxed'});
    if (mode === 'throw-durability') Object.defineProperty(tx, 'durability', {get() { throw new Error('synthetic getter failure'); }});
    if (mode === 'abort-write') queueMicrotask(() => tx.abort());
    return tx;
  };
  const hook = (next, arg) => {
    if (next === 'assert-no-write') { if (writes) throw new Error('readonly unlock attempted write'); return; }
    if (next === 'assert-no-mutation') { if (mutations) throw new Error('durability refusal queued mutation'); return; }
    if (next === 'tick') return new Promise(resolve => setTimeout(resolve, 0));
    if (next === 'hold-create') {
      let held;
      foreign.held = new Promise(resolve => { held = resolve; });
      foreign.createDone = new Promise((resolve, reject) => {
        const request = indexedDB.open(arg, 1);
        request.onupgradeneeded = () => {
          const store = request.result.createObjectStore('images');
          const chain = () => {
            if (!foreign.hold) return;
            const probe = store.get(0);
            probe.onsuccess = () => { held(); chain(); };
            probe.onerror = () => { foreign.hold = false; };
          };
          chain();
        };
        request.onsuccess = () => {
          foreign.db = request.result;
          foreign.db.onversionchange = () => foreign.db.close();
          resolve();
        };
        request.onerror = () => reject(request.error);
      });
      foreign.hold = true;
      return foreign.held;
    }
    if (next === 'release-create') {
      foreign.hold = false;
      return foreign.createDone.then(() => new Promise(resolve => setTimeout(resolve, 0)));
    }
    if (next === 'bump-version') {
      return Promise.race([
        new Promise((resolve, reject) => {
          let blocked = false;
          const request = indexedDB.open(arg, 2);
          request.onblocked = () => { blocked = true; };
          request.onsuccess = () => { request.result.close(); resolve(blocked ? 'blocked+upgraded' : 'upgraded'); };
          request.onerror = () => reject(request.error);
        }).then(value => new Promise(resolve => setTimeout(() => resolve(value), 0))),
        new Promise(resolve => setTimeout(() => resolve('stuck'), 3000)),
      ]);
    }
    if (next === 'hold-and-delete') {
      return new Promise((resolve, reject) => {
        const open = indexedDB.open(arg, 1);
        open.onupgradeneeded = () => open.result.createObjectStore('images');
        open.onsuccess = () => {
          foreign.blocker = open.result;
          const del = indexedDB.deleteDatabase(arg);
          del.onblocked = () => resolve('delete-blocked');
          del.onsuccess = () => { foreign.deleted = true; };
          del.onerror = () => reject(del.error);
        };
        open.onerror = () => reject(open.error);
      });
    }
    if (next === 'release-blocker') {
      foreign.blocker.close();
      return new Promise(resolve => {
        const wait = () => foreign.deleted ? setTimeout(resolve, 0) : setTimeout(wait, 5);
        wait();
      }).then(() => new Promise(resolve => setTimeout(resolve, 0)));
    }
    if (next === 'finish') {
      IDBDatabase.prototype.transaction = original;
      IDBObjectStore.prototype.add = add;
      IDBObjectStore.prototype.put = put;
      return;
    }
    mode = next; writes = 0; mutations = 0; metrics.faults.push(next);
  };
  const namespace = crypto.getRandomValues(new Uint8Array(32));
  const message = await qualify(namespace, hook);
  return {passed: true, message, metrics, userAgent: navigator.userAgent, realm: typeof window === "undefined" ? "worker" : "window"};
} catch(error) { return {passed: false, error: String(error), stack: error?.stack}; }
}
export async function runInterruptible() {
  await init();
  const hex = new URLSearchParams(location.search).get('ns');
  const namespace = new Uint8Array(hex.match(/../g).map(pair => parseInt(pair, 16)));
  await wasm.interruptible(namespace, index => postMessage({committed: index}));
}
export async function verifyInterrupted(namespace, minimum) {
  return wasm.verify_interrupted(namespace, minimum);
}
`;
const worker = `import {run, runInterruptible} from './qualification.js';
if (typeof window !== 'undefined') throw Error('expected dedicated worker');
if (new URLSearchParams(location.search).has('interrupt')) { await runInterruptible(); } else { postMessage(await run()); }`;
const page = `<!doctype html><meta charset="utf-8"><title>Isolated storage regression</title>
<script>window.done = new Promise(resolve => { window.finish = resolve; });</script>
<script type="module">
import {run, verifyInterrupted, hasInterruption} from './qualification.js';
try {
  const main = await run();
  if (!main.passed || main.realm !== 'window') throw Error(JSON.stringify(main));
  const background = await new Promise((resolve, reject) => {
    const worker = new Worker('./worker.js', {type: 'module'});
    const timer = setTimeout(() => { worker.terminate(); reject(Error('worker deadline')); }, 20000);
    worker.onmessage = ({data}) => { clearTimeout(timer); worker.terminate(); resolve(data); };
    worker.onerror = () => { clearTimeout(timer); worker.terminate(); reject(Error('worker failed')); };
  });
  if (!background.passed || background.realm !== 'worker') throw Error(JSON.stringify(background));
  // Terminate a writer mid-flight, then verify only committed states survive.
  let interruption = 'fixture does not export interruption coverage';
  if (hasInterruption) {
    const interruptedNamespace = crypto.getRandomValues(new Uint8Array(32));
    const hex = [...interruptedNamespace].map(b => b.toString(16).padStart(2, '0')).join('');
    const writer = new Worker('./worker.js?interrupt&ns=' + hex, {type: 'module'});
    const observed = await new Promise((resolve, reject) => {
      let committed = -1;
      const timer = setTimeout(() => { writer.terminate(); reject(Error('interruption progress deadline')); }, 15000);
      writer.onmessage = ({data}) => {
        if (typeof data.committed === 'number') committed = data.committed;
        if (committed >= 3) { clearTimeout(timer); resolve(committed); }
      };
      writer.onerror = () => { clearTimeout(timer); writer.terminate(); reject(Error('interruptible writer failed')); };
    });
    writer.terminate();
    const verification = await verifyInterrupted(interruptedNamespace, observed);
    interruption = {observed, verification};
  }
  window.finish({passed: true, main, worker: background, interruption});
} catch(error) { window.finish({passed: false, error: String(error), stack: error?.stack}); }
</script>`;
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname === '/') { response.writeHead(200, {'content-type': 'text/html'}); response.end(page); return; }
    if (url.pathname === '/qualification.js' || url.pathname === '/worker.js') { response.writeHead(200, {'content-type': 'text/javascript'}); response.end(url.pathname === '/worker.js' ? worker : runner); return; }
    const target = resolve(root, '.' + decodeURIComponent(url.pathname));
    if (!target.startsWith(root + sep) || !/\.(js|wasm)$/.test(target)) { response.writeHead(404); response.end(); return; }
    const body = await readFile(target);
    response.writeHead(200, {'content-type': target.endsWith('.wasm') ? 'application/wasm' : 'text/javascript'});
    response.end(body);
  } catch { response.writeHead(404); response.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const chrome = trackChild(spawn(executable, [
  '--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--disable-background-networking', '--disable-component-update', '--disable-default-apps',
  '--disable-extensions', '--disable-sync', '--metrics-recording-only', '--no-proxy-server',
  '--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1',
  '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
  '--user-data-dir=' + profile, 'about:blank',
], {stdio: ['ignore', 'ignore', 'pipe']}));
let stderr = '', socket;
const pending = new Map();
let loadSession, resolveLoaded;
let sequence = 0;
const task = async () => {
  const websocket = await new Promise((resolve, reject) => {
    chrome.once('error', reject);
    chrome.once('exit', (code) => reject(new Error('Chromium exited before DevTools: ' + code)));
    chrome.stderr.on('data', chunk => {
      stderr += chunk.toString();
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) resolve(match[1]);
    });
  });
  socket = new WebSocket(websocket);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  socket.onmessage = ({data}) => {
    const value = JSON.parse(data);
    if (value.id) {
      const waiter = pending.get(value.id); pending.delete(value.id);
      if (value.error) waiter?.reject(new Error(JSON.stringify(value.error))); else waiter?.resolve(value.result);
    } else if (value.method === 'Page.loadEventFired' && value.sessionId === loadSession) {
      // This harness waits for one event in one selected session, not a
      // remotely selected method or a general event dispatch table.
      const done = resolveLoaded; resolveLoaded = undefined; done?.();
    }
  };
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence; pending.set(id, {resolve, reject});
    socket.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}));
  });
  const {targetId} = await call('Target.createTarget', {url: 'about:blank'});
  const {sessionId} = await call('Target.attachToTarget', {targetId, flatten: true});
  await call('Page.enable', {}, sessionId);
  loadSession = sessionId;
  const loaded = new Promise(resolve => { resolveLoaded = resolve; });
  await call('Page.navigate', {url: 'http://127.0.0.1:' + server.address().port + '/'}, sessionId);
  await loaded;
  const result = await call('Runtime.evaluate', {expression: 'window.done', awaitPromise: true, returnByValue: true}, sessionId);
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  const receipt = {...result.result.value, profile, generatedDirectory: root};
  if (!receipt.passed) throw new Error(JSON.stringify(receipt));
  return receipt;
};
await runQualification({
  work: task, timeoutMs: 45000,
  cleanup: async () => {
    try { await cleanupOwned({children:[chrome], server, socket, pending}); }
    finally { await writeFile(join(root, 'chromium.stderr.log'), stderr); }
  },
  publish: async receipt => {
    await writeFile(join(root, 'indexeddb-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
    console.log(JSON.stringify(receipt));
  },
});
