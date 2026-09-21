// Actual account UI + existing emitted worker, isolated synthetic profile only.
// Build BOTH local-qualification and private-rooms. Never a deployment artifact.
import {trackChild, childStopped, cleanupOwned, runQualification} from './qualification_lifecycle.mjs';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFile, writeFile, mkdir, mkdtemp, open} from 'node:fs/promises';
import {resolve, join, sep} from 'node:path';

const [artifactArg, chromeExecutable, outputArg] = process.argv.slice(2);
if (!artifactArg || !chromeExecutable || !outputArg) throw Error('requires artifact, Chromium, new output directory');
const artifact=resolve(artifactArg), output=resolve(outputArg);
await mkdir(output,{recursive:false});
const profile=await mkdtemp(join(output,'profile-'));
const manifestRaw=await readFile(join(artifact,'artifact.json'));
const manifest=JSON.parse(manifestRaw);
if(manifest.purpose!=='local-qualification')throw Error('qualification-only artifact required');
for(const [name,entry] of Object.entries(manifest.assets)){
  if(name.includes('/')||name.includes('..'))throw Error('nonlocal artifact');
  const raw=await readFile(join(artifact,name));
  if(raw.length!==entry.bytes||createHash('sha256').update(raw).digest('hex')!==entry.sha256)throw Error('artifact changed: '+name);
}
const modules=Object.keys(manifest.assets).filter(n=>/^vhalla-browser-[a-z0-9]+\.js$/.test(n));
if(modules.length!==1)throw Error('expected one main application module');
const headers=JSON.parse(await readFile(join(artifact,'vercel.json'),'utf8')).headers[0].headers;
const children=[],pending=new Map();let server,socket,chromeLog='',signal,sequence=0;
const deadline=Date.now()+300000;
const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{
  signal.throwIfAborted();const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
});
async function wait(f,label){for(;;){signal.throwIfAborted();if(await f())return;if(Date.now()>=deadline)throw Error('timeout: '+label);await new Promise(r=>setTimeout(r,30));}}

// Holds only real IDB open completion in one dedicated test worker. The actual
// compiled worker and kernel remain unchanged; termination closes its handles.
const busyLoader=`
const originalOpen=IDBFactory.prototype.open;
const success=Object.getOwnPropertyDescriptor(IDBRequest.prototype,'onsuccess');
if(!success?.set)throw Error('IDB success setter unavailable');
IDBFactory.prototype.open=function(...args){
  const request=originalOpen.apply(this,args);
  Object.defineProperty(request,'onsuccess',{configurable:true,set(callback){
    success.set.call(request,callback ? () => postMessage(['qa-open-held']) : null);
  }});
  return request;
};
importScripts('./vhalla-vault-worker.js');
wasm_bindgen('./vhalla-vault-worker_bg.wasm');
`;

// Install before the application creates its worker so the listener can withhold
// exactly one already committed Send reply, before the real UI broker observes it.
const instrumentation=`
window.qaControl={holdArtifact:false,held:null,late:null,target:null};
const NativeWorker=window.Worker;
window.Worker=class extends NativeWorker {
  constructor(...args){super(...args);this.addEventListener('message',event=>{
    const fields=event.data;
    if(window.qaControl.holdArtifact && Array.isArray(fields) && fields[0]==='private-reply' && fields[2] instanceof Uint8Array && fields[2][12]===105){
      window.qaControl.holdArtifact=false;window.qaControl.held=Array.from(fields[2]);window.qaControl.late=fields;window.qaControl.target=this;event.stopImmediatePropagation();
    }
  });}
};
`;

async function task(abortSignal){
  signal=abortSignal;
  signal.throwIfAborted();
  server=createServer(async(req,res)=>{
    try{
      for(const h of headers)res.setHeader(h.key,h.value);
      if(req.method!=='GET')throw Error('no network writes');
      const name=new URL(req.url,'http://127.0.0.1').pathname;
      if(name==='/__private_busy_loader.js'){res.setHeader('content-type','text/javascript');res.end(busyLoader);return;}
      const target=resolve(artifact,'.'+(name==='/'?'/index.html':name));
      if(!target.startsWith(artifact+sep)||!manifest.assets[target.slice(artifact.length+1)]){res.writeHead(404);res.end();return;}
      res.setHeader('content-type',target.endsWith('.wasm')?'application/wasm':target.endsWith('.js')?'text/javascript':target.endsWith('.css')?'text/css':'text/html');
      res.end(await readFile(target));
    }catch{res.writeHead(500);res.end('qualification request refused');}
  });
  await new Promise((r,j)=>{server.once('error',j);server.listen(8790,'127.0.0.1',r);});
  signal.throwIfAborted();
  const chrome=trackChild(spawn(chromeExecutable,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-extensions','--disable-sync','--metrics-recording-only','--no-proxy-server','--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1, EXCLUDE localhost','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']}));
  children.push(chrome);chrome.stderr.on('data',c=>chromeLog+=c);
  await wait(()=>/DevTools listening on (ws:\/\/[^\s]+)/.test(chromeLog)||childStopped(chrome),'Chrome');
  if(childStopped(chrome))throw Error('Chrome exited');
  socket=new WebSocket(chromeLog.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]);
  await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
  socket.onmessage=({data})=>{const v=JSON.parse(data);if(v.id){const w=pending.get(v.id);pending.delete(v.id);v.error?w?.reject(Error(JSON.stringify(v.error))):w?.resolve(v.result);}};
  const {targetId}=await call('Target.createTarget',{url:'about:blank'});
  const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  await call('Page.enable',{},sessionId);await call('Runtime.enable',{},sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:instrumentation},sessionId);
  const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
  const helpers=`
    window.qid=id=>document.getElementById(id);
    window.qassert=(v,m)=>{if(!v)throw Error(m)};
    window.qwait=async(f,m)=>{const end=Date.now()+45000;while(!f()){if(Date.now()>end)throw Error(m+' '+qid('status')?.textContent);await new Promise(r=>setTimeout(r,20));}};
    window.qpassword='SYNTHETIC-private-worker-qualification-only-20260920';
    window.qunlock=async()=>{await qwait(()=>!qid('unlock').disabled,'unlock ready');qid('password').value=qpassword;qid('unlock').click();await qwait(()=>qid('identity-state').textContent==='Unlocked','unlocked');};
    window.qphase=async(name,locator='')=>JSON.parse(await qm.qualify_private_session(name,locator));
    window.qhex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
    window.qbytes=h=>Uint8Array.from(h.match(/../g)||[],v=>parseInt(v,16));
    window.qm=await import('/${modules[0]}');
    qassert(typeof qm.qualify_private_session==='function' && typeof qm.qualify_private_cancel==='function','qualification feature exports missing');
  `;
  await call('Page.navigate',{url:'http://127.0.0.1:8790'},sessionId);
  await wait(()=>evaluate("!!document.getElementById('create')&&!document.getElementById('create').disabled"),'app ready');
  await evaluate(`(async()=>{${helpers}
    qid('password').value=qpassword;qid('create').click();await qwait(()=>qid('identity-state').textContent==='Unlocked','created');
    window.qaSnapshot=await qphase('transport-snapshot');
    qid('lock').click();await qwait(()=>!qid('unlock').disabled,'initial custody dropped');return true;
  })()`);
  const mode=await evaluate(`(async()=>{
    const modes=[];
    async function check(mode){
      const worker=new Worker(mode==='busy'?'./__private_busy_loader.js':'./vhalla-vault-worker_loader.js');
      const queue=[],waiters=[];let failure;
      worker.onmessage=({data})=>{const w=waiters.shift();w?w.resolve(data):queue.push(data);};
      worker.onerror=()=>{failure=Error('raw qualification worker error');for(const w of waiters.splice(0))w.reject(failure);};
      const take=()=>new Promise((resolve,reject)=>{if(failure){reject(failure);return;}if(queue.length){resolve(queue.shift());return;}const timer=setTimeout(()=>reject(Error('worker reply deadline')),30000);waiters.push({resolve:v=>{clearTimeout(timer);resolve(v)},reject:e=>{clearTimeout(timer);reject(e)}});});
      try{
        qassert((await take())[0]==='ready','raw ready');
        if(mode!=='dead'){
          worker.postMessage(['unlock',qpassword,qbytes(qaSnapshot.vault)]);
          qassert((await take())[0]==='unlocked','raw existing account unlock');
          worker.postMessage(['private',new Uint8Array(16),qbytes(qaSnapshot.entry)]);
          qassert((await take())[0]===(mode==='busy'?'qa-open-held':'private-reply'),'actual private mode entry');
        }else{
          worker.postMessage(['private',new Uint8Array(16),new Uint8Array(0)]);
          qassert((await take())[0]==='private-error','malformed entry latches dead');
        }
        for(const message of [['sign-activity',new Uint8Array(16),new Uint8Array(0)],['encrypt-author-page',new Uint8Array(16),new Uint8Array(0)],['create',qpassword]]){
          worker.postMessage(message);qassert((await take())[0]==='private-error','public handler reachable after private '+mode);
        }
        modes.push(mode);
      }finally{worker.terminate();for(const w of waiters.splice(0))w.reject(Error('raw worker terminated'));}
    }
    await check('ready');await check('busy');await check('dead');
    delete window.qaSnapshot;await qunlock();return modes;
  })()`);
  const prepared=await evaluate("qphase('prepare')");
  if(typeof prepared.locator!=='string')throw Error('missing prepared locator');
  // Atomic exclusive new file, retained BEFORE the two-step broker acknowledgement.
  const locatorFile=await open(join(output,'prepared-locator.json'),'wx',0o600);
  try{await locatorFile.writeFile(JSON.stringify(prepared,null,2)+'\n');await locatorFile.sync();}finally{await locatorFile.close();}
  const directory=await open(output,'r');try{await directory.sync();}finally{await directory.close();}
  const locator=prepared.locator;
  const commit=await evaluate(`qphase('commit',${JSON.stringify(locator)})`);
  await evaluate(`window.qaControl.holdArtifact=true;window.qaSend=qphase('send-for-cancel',${JSON.stringify(locator)});true`);
  await wait(()=>evaluate('qaControl.held!==null'),'committed private reply');
  const committedReply=await evaluate('qhex(qaControl.held)');
  await evaluate('qm.qualify_private_cancel();true');
  const cancellation=await evaluate('qaSend');
  await evaluate("qaControl.target.dispatchEvent(new MessageEvent('message',{data:qaControl.late}));qassert(qid('identity-state').textContent==='Reload required','late old reply restored authority');qaControl.target=null;qaControl.late=null;true");
  const reload=async()=>{
    await call('Page.reload',{},sessionId);
    await wait(()=>evaluate("!!document.getElementById('unlock')&&!document.getElementById('unlock').disabled"),'reload unlock');
    await evaluate(`(async()=>{${helpers}await qunlock();return true;})()`);
  };
  await reload();
  const reopened=await evaluate(`qphase('reopen',${JSON.stringify(locator)})`);
  if(reopened.retained_reply!==committedReply)throw Error('uncertain send did not retain exact ciphertext/operation');
  const stale=await evaluate(`qphase('stale-consent',${JSON.stringify(locator)})`);
  await reload();
  const renewal=await evaluate(`qphase('verify-renewal',${JSON.stringify(locator)})`);
  const replacement=await evaluate(`qphase('replace-vault',${JSON.stringify(locator)})`);
  await reload();
  const wrong=await evaluate(`qphase('wrong-account',${JSON.stringify(locator)})`);
  const left=await evaluate("qphase('leave')");
  await evaluate('qunlock()');
  const missing=await evaluate(`qphase('missing-state',${JSON.stringify(locator)})`);
  return {passed:true,mode,commit,cancellation,exactCommittedReplyRetained:true,stale,renewal,replacement,wrong,left,missing,artifact,artifactManifestSha256:createHash('sha256').update(manifestRaw).digest('hex'),profile,locatorFile:join(output,'prepared-locator.json'),scope:'synthetic existing-worker private custody; no relay or live account'};
}

await runQualification({work:task,timeoutMs:300000,
  cleanup:async()=>{try{await cleanupOwned({children,server,socket,pending});}finally{await writeFile(join(output,'chrome.log'),chromeLog);}},
  publish:async receipt=>{await writeFile(join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify(receipt));},
});
