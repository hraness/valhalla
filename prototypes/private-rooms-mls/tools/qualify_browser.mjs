// Execute only the isolated synthetic MLS qualification, in dedicated workers.
import {trackChild, cleanupOwned, runQualification} from '../../../browser/tools/qualification_lifecycle.mjs';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdir,mkdtemp,readdir} from 'node:fs/promises';
import {resolve,join,sep} from 'node:path';
import {createHash} from 'node:crypto';
const [rootArg,chromePath,outArg,moduleName='private_rooms_mls.js']=process.argv.slice(2);
if(!rootArg||!chromePath||!outArg||!/^[a-zA-Z0-9_]+\.js$/.test(moduleName))throw Error('requires generated directory, Chrome, new output and optional module name');
const root=resolve(rootArg),out=resolve(outArg);await mkdir(out,{recursive:false});
const profile=await mkdtemp(join(out,'profile-'));
const hashes={};for(const name of await readdir(root)){if(/\.(js|wasm)$/.test(name))hashes[name]=createHash('sha256').update(await readFile(join(root,name))).digest('hex');}
const csp="default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";
const page='<!doctype html><meta charset="utf-8"><title>Private MLS worker qualification</title><script type="module" src="/main.js"></script>';
const main=`globalThis.done=(async()=>{
  const run=denied=>new Promise((resolve,reject)=>{
    const worker=new Worker('/worker.js?deny='+Number(denied),{type:'module'});
    const timer=setTimeout(()=>{worker.terminate();reject(Error('MLS worker deadline'));},30000);
    worker.onmessage=({data})=>{clearTimeout(timer);worker.terminate();resolve(data);};
    worker.onerror=e=>{clearTimeout(timer);worker.terminate();reject(Error(e.message));};
  });
  const success=await run(false),denied=await run(true);
  return {passed:success.ok&&success.calls>0&&success.isWorker&&success.secure&&!success.sharedMemoryRequired&&!denied.ok&&denied.calls>0,success,denied};
})().catch(error=>({passed:false,error:String(error)}));`;
const worker=`let calls=0;const denied=new URL(location.href).searchParams.get('deny')==='1';
const original=crypto.getRandomValues.bind(crypto);
Object.defineProperty(crypto,'getRandomValues',{value:array=>{calls++;if(denied)throw new DOMException('synthetic entropy denial','NotAllowedError');return original(array);}});
try{
 const imported=await import('/${moduleName}');await imported.default();
 imported.qualify_browser();
 postMessage({ok:true,calls,isWorker:typeof window==='undefined'&&typeof document==='undefined',secure:isSecureContext,sharedMemoryRequired:crossOriginIsolated,userAgent:navigator.userAgent});
}catch(error){postMessage({ok:false,calls,error:String(error),isWorker:typeof window==='undefined',secure:isSecureContext});}`;
const server=createServer(async(req,res)=>{try{
 const path=decodeURIComponent(new URL(req.url,'http://127.0.0.1').pathname);
 res.setHeader('Content-Security-Policy',csp);res.setHeader('X-Content-Type-Options','nosniff');
 if(path==='/'){res.setHeader('Content-Type','text/html');res.end(page);return;}
 if(path==='/main.js'||path==='/worker.js'){res.setHeader('Content-Type','text/javascript');res.end(path==='/main.js'?main:worker);return;}
 const target=resolve(root,'.'+path);if(!target.startsWith(root+sep)||!/\.(js|wasm)$/.test(target))throw Error('unsupported');
 res.setHeader('Content-Type',target.endsWith('.wasm')?'application/wasm':'text/javascript');res.end(await readFile(target));
}catch{res.writeHead(404);res.end();}});
await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
const chrome=trackChild(spawn(chromePath,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-extensions','--disable-sync','--metrics-recording-only','--no-proxy-server','--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']}));
let log='',socket,seq=0;const pending=new Map(),events=new Map();
const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
async function work(){
 const ws=await new Promise((r,j)=>{chrome.once('error',j);chrome.once('exit',c=>j(Error('Chrome exit '+c)));chrome.stderr.on('data',c=>{log+=c;const m=log.match(/DevTools listening on (ws:\/\/\S+)/);if(m)r(m[1]);});});
 socket=new WebSocket(ws);await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
 socket.onmessage=({data})=>{const v=JSON.parse(data);if(v.id){const pendingCall=pending.get(v.id);pending.delete(v.id);if(pendingCall){if(v.error)pendingCall.reject(Error(JSON.stringify(v.error)));else pendingCall.resolve(v.result);}}else{const key=(v.sessionId||'')+':'+v.method;const eventCall=events.get(key);if(eventCall){events.delete(key);eventCall.resolve(v.params);}}};
 const {targetId}=await call('Target.createTarget',{url:'about:blank'}),{sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
 await call('Page.enable',{},sessionId);const loaded=new Promise(resolve=>events.set(sessionId+':Page.loadEventFired',{resolve}));
 await call('Page.navigate',{url:'http://127.0.0.1:'+server.address().port+'/'},sessionId);await loaded;
 const result=await call('Runtime.evaluate',{expression:'globalThis.done',awaitPromise:true,returnByValue:true},sessionId);
 if(result.exceptionDetails)throw Error(JSON.stringify(result.exceptionDetails));
 const receipt={...result.result.value,hashes,root,profile,csp};
 if(!receipt.passed)throw Error(JSON.stringify(receipt));
 return receipt;
}
await runQualification({
  work, timeoutMs: 90000,
  cleanup: async () => {
    try { await cleanupOwned({children:[chrome], server, socket, pending}); }
    finally { await writeFile(join(out,'chrome.log'),log); }
  },
  publish: async receipt => {
    await writeFile(join(out,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');
    console.log(JSON.stringify(receipt));
  },
});
