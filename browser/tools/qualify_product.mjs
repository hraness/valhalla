// Actual app DOM regression, synthetic fixture and isolated Chrome profile only.
import {qualifyRecovery} from './qualify_recovery.mjs';
import {trackChild, childStopped, cleanupOwned, runQualification} from './qualification_lifecycle.mjs';
import {createServer, request as httpRequest} from 'node:http';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, writeFile, mkdir} from 'node:fs/promises';
import {resolve, join, sep} from 'node:path';
const [artifactArg, fixtureExecutable, chromeExecutable, outputArg, recoveryFlag] = process.argv.slice(2);
if(recoveryFlag && recoveryFlag!=='--recovery')throw Error('unsupported qualification flag');
const artifact=resolve(artifactArg), output=resolve(outputArg);
await mkdir(output, {recursive:false});
const profile=await mkdtemp(join(output,'profile-')), fixture=join(output,'fixture');
const manifest=JSON.parse(await readFile(join(artifact,'artifact.json'),'utf8'));
if(manifest.purpose!=='local-qualification') throw Error('local qualification artifact required');
for(const [name,entry] of Object.entries(manifest.assets)){if(name.includes('/')||name.includes('..'))throw Error('nonlocal asset');const raw=await readFile(join(artifact,name));if(raw.length!==entry.bytes||createHash('sha256').update(raw).digest('hex')!==entry.sha256)throw Error('changed artifact '+name);}
const children=[], logs={}; let server, socket, signal, activityPosts=0;
function start(label,cmd,args){
  signal.throwIfAborted();
  const p=trackChild(spawn(cmd,args,{stdio:['ignore','pipe','pipe']}));children.push(p);logs[label]='';
  for(const io of [p.stdout,p.stderr]) io.on('data',c=>logs[label]+=c);
  p.on('error',e=>logs[label]+=String(e));return p;
}
const pending=new Map();let sequence=0;
const deadline=Date.now()+300000;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(f,label){for(;;){signal.throwIfAborted();if(await f()){signal.throwIfAborted();return;}if(Date.now()>deadline)throw Error('timeout: '+label);await pause(50);}}
const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
async function task(abortSignal){
  signal=abortSignal;
  const peers=start('peers',fixtureExecutable,[fixture,'--public-posting']);
  await wait(()=>logs.peers.includes('fixture-status discovery-ready-both-read-peers') || logs.peers.includes('fixture-status discovery-ready-both-publishing-peers') || childStopped(peers),'fixture readiness');
  if(childStopped(peers))throw Error('fixture exited: '+logs.peers);
  const bootstrap=(await readFile(join(fixture,'bootstrap.vhbootstrap'))).toString('base64');
  const pin=(await readFile(join(fixture,'bootstrap.pin'),'utf8')).trim();
  const ads=await Promise.all(['peer-a.vhad','peer-b.vhad','peer-c.vhad'].map(async p=>(await readFile(join(fixture,p))).toString('base64')));
  const provider=JSON.parse(await readFile(join(artifact,'vercel.json'),'utf8')).headers[0].headers;
  signal.throwIfAborted();
  server=createServer(async(req,res)=>{
    try {
      signal.throwIfAborted();
      for(const h of provider) res.setHeader(h.key,h.value);
      const match=req.url.match(/^\/__qualification\/(peer-[abc])\/(vhalla\/v1(?:\?|\/).*)$/);
      if(match){
        if(req.method==='POST'&&match[2].startsWith('vhalla/v1/activity'))activityPosts++;
        const key=match[1], upstream=httpRequest({hostname:'127.0.0.1',port:{ 'peer-a':9781,'peer-b':9782,'peer-c':9783 }[key],path:'/'+match[2],method:req.method,headers:{host:key+'.vhalla.dev',origin:'http://127.0.0.1:8789','content-type':'application/octet-stream',...(req.headers['content-length']?{'content-length':req.headers['content-length']}:{})}},r=>{res.writeHead(r.statusCode,{'content-type':r.headers['content-type']||'application/octet-stream',...(r.headers['x-vhalla-proof']?{'x-vhalla-proof':r.headers['x-vhalla-proof']}:{})});r.pipe(res);});
        upstream.on('error',()=>{res.writeHead(502);res.end();});upstream.setTimeout(15000,()=>upstream.destroy());req.pipe(upstream);return;
      }
      const name=new URL(req.url,'http://127.0.0.1').pathname;
      const target=resolve(artifact,'.'+(name==='/'?'/index.html':name));
      if(!target.startsWith(artifact+sep)||!manifest.assets[target.slice(artifact.length+1)]){res.writeHead(404);res.end();return;}
      const body=await readFile(target);res.setHeader('content-type',target.endsWith('.wasm')?'application/wasm':target.endsWith('.js')?'text/javascript':target.endsWith('.css')?'text/css':'text/html');res.end(body);
    }catch{res.writeHead(500,{'content-type':'text/plain'});res.end('qualification request failed');}
  });
  signal.throwIfAborted();
  await new Promise((r,j)=>{server.once('error',j);server.listen(8790,'127.0.0.1',r);});
  signal.throwIfAborted();
  const chrome=start('chrome',chromeExecutable,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-extensions','--disable-sync','--metrics-recording-only','--no-proxy-server','--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1, EXCLUDE localhost','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank']);
  await wait(()=>/DevTools listening on (ws:\/\/[^\s]+)/.test(logs.chrome)||childStopped(chrome),'Chrome');
  if(childStopped(chrome))throw Error('Chrome exited');
  socket=new WebSocket(logs.chrome.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]);
  await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
  socket.onmessage=({data})=>{const v=JSON.parse(data);if(v.id){const w=pending.get(v.id);pending.delete(v.id);v.error?w?.reject(Error(JSON.stringify(v.error))):w?.resolve(v.result);}};
  const {targetId}=await call('Target.createTarget',{url:'about:blank'});
  const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  await call('Page.enable',{},sessionId);
  await call('Runtime.enable',{},sessionId);
  await call('Page.navigate',{url:'http://127.0.0.1:8790'},sessionId);
  const evaluate=async(expression)=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);if(r.exceptionDetails){const shot=await call('Page.captureScreenshot',{format:'png'},sessionId);await writeFile(join(output,'failure.png'),Buffer.from(shot.data,'base64'));throw Error(JSON.stringify(r.exceptionDetails));}return r.result.value;};
  await wait(()=>evaluate("!!document.getElementById('create') && !document.getElementById('create').disabled"),'app initialized');
  const setup=`window.qa={bootstrap:${JSON.stringify(bootstrap)},pin:${JSON.stringify(pin)},ads:${JSON.stringify(ads)},password:'Valhalla-synthetic-DOM-only-20260920',facts:[]};`;
  await evaluate(setup+`
    window.qid=id=>document.getElementById(id);
    window.qassert=(v,m)=>{if(!v)throw Error(m)};
    window.qwait=async(f,m)=>{const t=Date.now()+45000;while(!f()){if(Date.now()>t)throw Error(m+' status='+qid('status').textContent+' network='+qid('network-status').textContent+' activity='+qid('activity-status').textContent);await new Promise(r=>setTimeout(r,20));}};
    window.qset=(id,v,event='input')=>{qid(id).value=v;qid(id).dispatchEvent(new Event(event,{bubbles:true}));};
    window.qclick=async id=>{await qwait(()=>!qid(id).disabled,id+' enabled');qid(id).click();};
    window.qfile=(id,b64,name)=>{const bytes=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));const dt=new DataTransfer();dt.items.add(new File([bytes],name));qid(id).files=dt.files;qid(id).dispatchEvent(new Event('change',{bubbles:true}));};
    window.qidle=()=>qwait(()=>!qid('show-outbox').disabled,'network idle');
    window.qinstrument=()=>{window.qwrites=[];for(const name of ['add','put','delete']){const original=IDBObjectStore.prototype[name];IDBObjectStore.prototype[name]=function(...args){qwrites.push({name,key:String(name==='delete'?args[0]:args[1])});return original.apply(this,args);};}};
    (async()=>{
      qset('password',qa.password);await qclick('create');await qwait(()=>qid('identity-state').textContent==='Unlocked','identity creation');
      qa.author=qid('public-key').textContent;
      qfile('network-file',qa.bootstrap,'synthetic.vhbootstrap');qset('network-pin',qa.pin);await qclick('join-network');
      await qwait(()=>!qid('add-peer').disabled,'network selected');
      qfile('peer-file',qa.ads[0],'synthetic-a.vhad');await qclick('add-peer');await qwait(()=>!qid('sync-network').disabled,'peer selected');
      await qclick('sync-network');await qwait(()=>qid('activity-room').options.length===2 && !qid('activity-room').disabled,'two certified rooms');
      qa.rooms=Array.from(qid('activity-room').options,o=>({id:o.value,name:o.textContent}));
      qset('activity-room',qa.rooms[0].id,'change');qset('activity-text','SYNTHETIC_A_DRAFT');
      qset('activity-room',qa.rooms[1].id,'change');qinstrument();
      await qclick('queue-activity');await qidle();
      qassert(qid('activity-status').textContent.includes('not bound'),'cross-room refusal');qassert(qwrites.length===0,'cross-room attempted storage mutation');qassert(qid('activity-text').value==='SYNTHETIC_A_DRAFT','cross-room lost draft');
      qa.facts.push('A-to-B queue refused before all storage mutations; original text retained');
      await qclick('use-composer-here');await qclick('queue-activity');await qidle();qassert(qid('activity-status').textContent.includes('Post 1 saved'),'explicit move not saved');
      qset('activity-text','SYNTHETIC_RESERVED_BEFORE_CRASH');
      const add=IDBObjectStore.prototype.add;window.qfault=false;
      IDBObjectStore.prototype.add=function(value,key){if(!qfault && String(key).includes('/outbox/')){qfault=true;throw new DOMException('synthetic finalization quota','QuotaExceededError');}return add.apply(this,arguments);};
      await qclick('queue-activity');await qwait(()=>qfault && qid('activity-status').textContent.includes('Reload'),'post-reservation failure');
      qa.facts.push('Finalization fault left exact reserved draft for reload');
      return {author:qa.author,rooms:qa.rooms,facts:qa.facts};
    })()`);
  const saved=await evaluate('({author:qa.author,rooms:qa.rooms,facts:qa.facts,password:qa.password})');
  await call('Page.reload',{},sessionId);
  await wait(()=>evaluate("!!document.getElementById('unlock') && !document.getElementById('unlock').disabled"),'reload unlock');
  // Helpers are reinstalled on the fresh page; no persisted test-only globals.
  const helper=await readFile(new URL('./qualify_product_continue.txt',import.meta.url),'utf8');
  const result=await evaluate(`window.qa=${JSON.stringify({...saved,ads})};`+helper);
  await evaluate("document.querySelector('.puzzles').open=true;document.querySelector('.puzzles').scrollIntoView();");
  const shot=await call('Page.captureScreenshot',{format:'png'},sessionId);await writeFile(join(output,'puzzle-preview.png'),Buffer.from(shot.data,'base64'));
  const recovery = recoveryFlag ? await qualifyRecovery({call,targetId,sessionId,bootstrap,pin,ads,password:saved.password,author:saved.author,rooms:saved.rooms,postCount:()=>activityPosts}) : undefined;
  return {passed:true,...result,...(recovery?{recovery}:{}),artifact,artifactManifestSha256:createHash("sha256").update(await readFile(join(artifact,"artifact.json"))).digest("hex"),profile,fixture};
}
await runQualification({
  work: task, timeoutMs: 300000,
  cleanup: async () => {
    try { await cleanupOwned({children, server, socket, pending}); }
    finally { for(const [k,v] of Object.entries(logs)) await writeFile(join(output,k+'.log'),v); }
  },
  publish: async receipt => {
    await writeFile(join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');
    console.log(JSON.stringify(receipt));
  },
});
