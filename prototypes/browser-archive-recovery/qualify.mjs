// Isolated prototype only: synthetic MLS accounts, real strict IndexedDB, no network delivery.
import {cleanupOwned, trackChild, runQualification} from '../../browser/tools/qualification_lifecycle.mjs';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir, mkdtemp, readFile, writeFile} from 'node:fs/promises';
import {join, resolve, sep} from 'node:path';

const [artifactArg, executable, outputArg] = process.argv.slice(2);
if (!artifactArg || !executable || !outputArg) throw Error('requires generated WASM directory, Chromium, new output directory');
const root = resolve(artifactArg), output = resolve(outputArg);
await mkdir(output, {recursive: false, mode: 0o700});
const profile = await mkdtemp(join(output, 'profile-'));
const assets = {};
for (const name of ['archive_recovery.js', 'archive_recovery_bg.wasm']) {
  const raw = await readFile(join(root, name));
  assets[name] = {bytes: raw.length, sha256: createHash('sha256').update(raw).digest('hex')};
}
const worker = `
import init, {setup, interrupt, verify} from './archive_recovery.js';
const ready = init();
const transaction = IDBDatabase.prototype.transaction;
const add = IDBObjectStore.prototype.add, put = IDBObjectStore.prototype.put, open = IDBFactory.prototype.open;
let mode = 'require-strict', mutations = 0, opens = 0;
const metrics = {strictWrites:0, deniedWrites:0, readonly:0, substitutionsBeforeMutation:false};
IDBFactory.prototype.open = function(...args) { opens++; return open.apply(this,args); };
IDBObjectStore.prototype.add = function(...args) { mutations++; return add.apply(this,args); };
IDBObjectStore.prototype.put = function(...args) { mutations++; return put.apply(this,args); };
IDBDatabase.prototype.transaction = function(names, access, options) {
  if(access !== 'readwrite') { metrics.readonly++; return transaction.call(this,names,access); }
  if(mode === 'deny-writes') { metrics.deniedWrites++; throw new DOMException('synthetic quota refusal','QuotaExceededError'); }
  if(options?.durability !== 'strict') throw Error('application write omitted strict durability');
  metrics.strictWrites++;
  return transaction.call(this,names,access,options);
};
const control = next => {
  if(next === 'assert-no-mutation') {
    if(mutations || opens) throw Error('substituted source reached destination access');
    metrics.substitutionsBeforeMutation=true; return;
  }
  mode=next; mutations=0; opens=0;
};
self.onmessage = async ({data}) => {
  try {
    await ready;
    if(data.mode === 'setup') postMessage({kind:'done',fixture:await setup(data.bytes),metrics});
    else if(data.mode === 'interrupt') await interrupt(data.bytes, committed=>postMessage({kind:'committed',committed,metrics}));
    else if(data.mode === 'verify') postMessage({kind:'done',message:await verify(data.bytes,control),metrics});
    else throw Error('unknown closed phase');
  } catch(error) { postMessage({kind:'error',error:String(error),stack:error?.stack}); }
};`;
const page = `<!doctype html><meta charset="utf-8"><title>Archive recovery isolation spike</title>
<script>
window.done=(async()=>{
  const job=(mode,bytes)=>new Promise((resolve,reject)=>{
    const worker=new Worker('/worker.js',{type:'module'});
    const timer=setTimeout(()=>{worker.terminate();reject(Error(mode+' deadline'));},45000);
    worker.onerror=()=>{clearTimeout(timer);worker.terminate();reject(Error(mode+' worker failure'));};
    worker.onmessage=({data})=>{
      clearTimeout(timer);worker.terminate();
      if(data.kind==='error')reject(Error(JSON.stringify(data)));
      else if(mode==='interrupt'&&data.kind!=='committed')reject(Error('missing durable teardown boundary'));
      else resolve(data);
    };
    worker.postMessage({mode,bytes});
  });
  try {
    const setup=await job('setup',crypto.getRandomValues(new Uint8Array(32)));
    if(!(setup.fixture instanceof Uint8Array)||setup.fixture.length>2*1024*1024)throw Error('fixture bound');
    const stopped=await job('interrupt',setup.fixture);
    const reopened=await job('verify',setup.fixture);
    if(reopened.metrics.deniedWrites!==1||!reopened.metrics.substitutionsBeforeMutation)throw Error('missing fault evidence');
    return {passed:true,fixtureBytes:setup.fixture.length,confirmedPageBeforeWorkerTermination:stopped.committed,message:reopened.message,metrics:{setup:setup.metrics,interrupted:stopped.metrics,reopened:reopened.metrics},userAgent:navigator.userAgent};
  }catch(error){return {passed:false,error:String(error),stack:error?.stack};}
})();
</script>`;
const server = createServer(async (request,response)=>{
  try {
    const path=new URL(request.url,'http://127.0.0.1').pathname;
    if(path==='/'){response.writeHead(200,{'content-type':'text/html'});response.end(page);return;}
    if(path==='/worker.js'){response.writeHead(200,{'content-type':'text/javascript'});response.end(worker);return;}
    const target=resolve(root,'.'+decodeURIComponent(path));
    if(!target.startsWith(root+sep)||!/^\/archive_recovery(?:_bg)?\.(?:js|wasm)$/.test(path)){response.writeHead(404);response.end();return;}
    const raw=await readFile(target);
    response.writeHead(200,{'content-type':path.endsWith('.wasm')?'application/wasm':'text/javascript'});response.end(raw);
  }catch{response.writeHead(404);response.end();}
});
let chrome, socket, stderr='', sequence=0, loadSession, loaded;
const pending=new Map();
async function task(signal) {
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  chrome=trackChild(spawn(executable,[
    '--headless','--disable-gpu','--no-first-run','--no-default-browser-check',
    '--disable-background-networking','--disable-component-update','--disable-default-apps',
    '--disable-extensions','--disable-sync','--metrics-recording-only','--no-proxy-server',
    '--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1',
    '--remote-debugging-address=127.0.0.1','--remote-debugging-port=0',
    '--user-data-dir='+profile,'about:blank',
  ],{stdio:['ignore','ignore','pipe']}));
  const address=await new Promise((resolve,reject)=>{
    chrome.once('error',reject);
    chrome.once('exit',code=>reject(Error('Chromium exited before DevTools: '+code)));
    chrome.stderr.on('data',chunk=>{stderr+=chunk.toString();const match=stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(match)resolve(match[1]);});
  });
  socket=new WebSocket(address);
  await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject;});
  socket.onmessage=({data})=>{
    const value=JSON.parse(data);
    if(value.id){const waiter=pending.get(value.id);pending.delete(value.id);if(value.error)waiter?.reject(Error(JSON.stringify(value.error)));else waiter?.resolve(value.result);}
    else if(value.method==='Page.loadEventFired'&&value.sessionId===loadSession){const ready=loaded;loaded=undefined;ready?.();}
  };
  const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{
    signal.throwIfAborted();const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
  const {targetId}=await call('Target.createTarget',{url:'about:blank'});
  const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  await call('Page.enable',{},sessionId);loadSession=sessionId;
  const ready=new Promise(resolve=>{loaded=resolve;});
  await call('Page.navigate',{url:'http://127.0.0.1:'+server.address().port+'/'},sessionId);await ready;
  const result=await call('Runtime.evaluate',{expression:'window.done',awaitPromise:true,returnByValue:true},sessionId);
  if(result.exceptionDetails)throw Error(JSON.stringify(result.exceptionDetails));
  if(!result.result.value?.passed)throw Error(JSON.stringify(result.result.value));
  return {...result.result.value,profile,assets,scope:'isolated prototype; synthetic accounts; legacy data preserved; no production routing or migration'};
}
await runQualification({
  work:task,timeoutMs:150000,
  cleanup:async()=>{try{await cleanupOwned({children:chrome?[chrome]:[],server,socket,pending});}finally{await writeFile(join(output,'chromium.stderr.log'),stderr);}},
  publish:async receipt=>{await writeFile(join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify(receipt));},
});
