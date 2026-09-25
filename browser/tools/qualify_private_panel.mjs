// Actual private DOM, two isolated synthetic account contexts, file exchange only.
// No account seeds, production signer calls, external routes or fixture KDF changes.
import {trackChild, childStopped, cleanupOwned, runQualification} from './qualification_lifecycle.mjs';
import {qualifyArchives} from './qualify_private_archives.mjs';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFile, writeFile, mkdir, mkdtemp, chmod, open} from 'node:fs/promises';
import {resolve, join, sep} from 'node:path';

const [artifactArg, chromeExecutable, outputArg, mode] = process.argv.slice(2);
if (mode !== undefined && mode !== '--production') throw Error('unknown qualification mode');
const production = mode === '--production';
if (!artifactArg || !chromeExecutable || !outputArg) throw Error('requires qualification artifact, Chromium, new output directory');
const artifact = resolve(artifactArg), output = resolve(outputArg);
await mkdir(output, {recursive:false, mode:0o700});
const profile = await mkdtemp(join(output,'profile-'));
const manifestRaw = await readFile(join(artifact,'artifact.json'));
const manifest = JSON.parse(manifestRaw);
if (manifest.purpose !== (production ? 'production' : 'local-qualification')) throw Error('artifact purpose differs from selected mode');
for (const [name, item] of Object.entries(manifest.assets)) {
  if (name.includes('/') || name.includes('..')) throw Error('nonlocal manifest asset');
  const bytes = await readFile(join(artifact,name));
  if (bytes.length !== item.bytes || createHash('sha256').update(bytes).digest('hex') !== item.sha256) throw Error('artifact changed: '+name);
}
const headers = JSON.parse(await readFile(join(artifact,'vercel.json'),'utf8')).headers[0].headers;
const modules=Object.keys(manifest.assets).filter(n=>/^vhalla-browser-[a-z0-9]+\.js$/.test(n));
if(modules.length!==1)throw Error('expected one main application module');
const children=[], pending=new Map(), downloads=new Map(), pages=[];
let server, serverOrigin, socket, signal, sequence=0, chromeLog='', unexpectedNetwork=false, networkWrites=0;
const facts=[], screenshots=[], files=[];
const deadline=Date.now()+300000;
const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{
  signal.throwIfAborted();
  const id=++sequence;
  // A CDP reply can be dropped silently (renderer teardown, a crashed service
  // restarting). Bound every call so a drop fails fast and names the method
  // instead of stalling until the outer qualification deadline.
  const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP call dropped: '+method));},120000);
  const done=f=>v=>{clearTimeout(timer);f(v);};
  pending.set(id,{resolve:done(resolve),reject:done(reject)});
  socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
});
async function wait(probe,label) {
  for (;;) {
    signal.throwIfAborted();
    if (await probe()) { signal.throwIfAborted(); return; }
    if (Date.now() >= deadline) throw Error('qualification timeout: '+label);
    await new Promise(r=>setTimeout(r,30));
  }
}
const instrumentation=`
window.qaURLs=new Set(); window.qaInjected=false;
Object.defineProperty(window, "showSaveFilePicker", {configurable:true,writable:true,value:undefined});
window.qaKeyboardClicks={'private-enter':0,'private-locator-retained':0};
document.addEventListener('click',event=>{
  const id=event.target?.id;
  if(event.isTrusted&&event.detail===0&&Object.hasOwn(qaKeyboardClicks,id))qaKeyboardClicks[id]++;
},true);
const make=URL.createObjectURL.bind(URL), revoke=URL.revokeObjectURL.bind(URL);
URL.createObjectURL=function(blob){const url=make(blob);qaURLs.add(url);return url;};
URL.revokeObjectURL=function(url){qaURLs.delete(url);return revoke(url);};
`;
const helpers=`
window.qid=id=>document.getElementById(id);
window.qassert=(value,message)=>{if(!value)throw Error(message)};
window.qwait=async(test,label)=>{const end=Date.now()+45000;while(!test()){if(Date.now()>end)throw Error(label+'; identity='+qid('status')?.textContent+'; private='+qid('private-status')?.textContent);await new Promise(r=>setTimeout(r,20));}};
window.qset=(id,value,event='input')=>{qid(id).value=value;qid(id).dispatchEvent(new Event(event,{bubbles:true}));};
window.qshow=id=>{for(let e=qid(id);e;e=e.parentElement)if(e.tagName==='DETAILS')e.open=true;qid(id).scrollIntoView({block:'center'});};
window.qclick=async id=>{await qwait(()=>!qid(id).disabled,id+' enabled');qshow(id);qid(id).click();};
window.qidle=async()=>{await qwait(()=>!qid('private-refresh').disabled,'private room idle');qassert(qid('private-status').dataset.error!=='true','private action refused: '+qid('private-status').textContent);};
window.qpassword='SYNTHETIC-private-panel-qualification-only-20260920';
window.qseparate=()=>{qassert(qid('activity-heading').closest('.activity').hidden,'public activity is visible');for(const id of ['activity-text','puzzle-artifact','puzzle-part'])qassert(qid(id).value==='','public composition survived private entry');qassert(qid('backup').disabled && qid('restore').disabled && qid('create').disabled,'public identity command remained enabled');};
`;
async function evaluate(page, expression) {
  const result=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},page.sessionId);
  if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function invoke(page, functionDeclaration, args = []) {
  const global = await call('Runtime.evaluate', {expression: 'window', returnByValue: false}, page.sessionId);
  const result = await call('Runtime.callFunctionOn', {
    objectId: global.result.objectId,
    functionDeclaration,
    arguments: args.map(value => ({value})),
    awaitPromise: true,
    returnByValue: true,
  }, page.sessionId);
  if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function setFile(page,id,path) {
  await invoke(page,`function(id){qshow(id);return true;}`,[id]);
  const {root}=await call('DOM.getDocument',{},page.sessionId);
  const {nodeId}=await call('DOM.querySelector',{nodeId:root.nodeId,selector:'#'+id},page.sessionId);
  if (!nodeId) throw Error('missing file input '+id);
  await call('DOM.setFileInputFiles',{nodeId,files:[path]},page.sessionId);
}
async function keypress(page,id,key,code,virtualKey) {
  // Select the actual context before focusing: the other account was created
  // last and can still be foreground. Do not substitute a synthetic click.
  await call('Page.bringToFront',{},page.sessionId);
  const before=await invoke(page,`async function(id){await qwait(()=>!qid(id).disabled,id+' keyboard enabled');qshow(id);qid(id).focus();qassert(document.hasFocus()&&document.activeElement===qid(id),'keyboard target lacks focus: '+id);return qaKeyboardClicks[id];}`,[id]);
  const args={key,code,windowsVirtualKeyCode:virtualKey,nativeVirtualKeyCode:virtualKey};
  // Chromium's keyDown needs the character payload to produce native Enter
  // button activation. Match ordinary automation for Enter and printable Space.
  const text=key==='Enter'?'\r':key;
  await call('Input.dispatchKeyEvent',{type:'keyDown',...args,text,unmodifiedText:text},page.sessionId);
  await call('Input.dispatchKeyEvent',{type:'keyUp',...args},page.sessionId);
  await invoke(page,`async function(id,expected,label){await qwait(()=>qaKeyboardClicks[id]===expected,label);return true;}`,[id,before+1,id+' trusted keyboard activation']);
}
async function download(page,button,extension) {
  const previous=new Set(downloads.keys());
  await invoke(page,`function(button){return qclick(button);}`,[button]);
  let item;
  await wait(()=>{
    item=[...downloads.values()].find(d=>!previous.has(d.guid)&&d.filename?.endsWith('.'+extension));
    if (item?.state==='canceled') throw Error('download canceled');
    return item?.state==='completed';
  },button+' real download');
  const path=join(page.downloads,item.guid);
  const raw=await readFile(path);
  if (!raw.length || raw.length>(extension==='vharchive'?16*1024*1024:266280)) throw Error('download byte bound');
  await chmod(path,0o600);
  // Confirm the actual downloaded locator/output before any retention acknowledgement.
  const file=await open(path,'r+');try{await file.sync();}finally{await file.close();}
  const directory=await open(page.downloads,'r');try{await directory.sync();}finally{await directory.close();}
  files.push({account:page.name,kind:extension,bytes:raw.length,sha256:createHash('sha256').update(raw).digest('hex'),file:path});
  return {path,raw};
}
async function context(name) {
  const directory=join(output,name+'-downloads');await mkdir(directory,{mode:0o700});
  const {browserContextId}=await call('Target.createBrowserContext');
  await call('Browser.setDownloadBehavior',{behavior:'allowAndName',browserContextId,downloadPath:directory,eventsEnabled:true});
  const {targetId}=await call('Target.createTarget',{url:'about:blank',browserContextId});
  const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  const page={name,downloads:directory,browserContextId,targetId,sessionId};pages.push(page);
  for(const method of ['Page.enable','Runtime.enable','DOM.enable','Network.enable'])await call(method,{},sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:instrumentation},sessionId);
  await call('Page.navigate',{url:serverOrigin},sessionId);
  await wait(()=>evaluate(page,"!!document.getElementById('private-panel') && !!document.getElementById('create') && !document.getElementById('create').disabled"),'private app '+name);
  return page;
}
async function account(name) {
  const page=await context(name);
  page.publicKey=await evaluate(page,`(async()=>{${helpers}
    qset('password',qpassword);await qclick('create');await qwait(()=>qid('identity-state').textContent==='Unlocked','normal account creation');
    qassert(/^[0-9a-f]{64}$/.test(qid('public-key').textContent),'complete account key');return qid('public-key').textContent;
  })()`);
  return page;
}
async function restored(name,backupPath) {
  const page=await context(name);
  await evaluate(page,`(async()=>{${helpers} qset('password',qpassword);return true;})()`);
  await setFile(page,'restore-file',backupPath);
  page.publicKey=await evaluate(page,`(async()=>{await qclick('restore');await qwait(()=>qid('identity-state').textContent==='Unlocked','restored backup unlock');
    qassert(qid('identity-help').textContent.startsWith('Imported identity'),'restored identity not marked imported');
    qassert(/^[0-9a-f]{64}$/.test(qid('public-key').textContent),'complete restored account key');return qid('public-key').textContent;
  })()`);
  return page;
}
async function enter(page,keyboard=false) {
  await evaluate(page,`qset('activity-text','SYNTHETIC_PUBLIC_DRAFT');qset('puzzle-artifact','SYNTHETIC_PUBLIC_ARTIFACT');qset('puzzle-part','SYNTHETIC_PUBLIC_PART');true`);
  if(keyboard)await keypress(page,'private-enter','Enter','Enter',13);else await evaluate(page,"qclick('private-enter')");
  await evaluate(page,"(async()=>{await qwait(()=>qid('identity-state').textContent==='Private custody'&&!qid('private-create').disabled,'private entry');qseparate();return true;})()");
}
async function retainCreation(page) {
  await evaluate(page,"(async()=>{await qwait(()=>!qid('private-download-locator').disabled,'prepared locator');qassert(!qid('private-locator-retained').checked && qid('private-commit').disabled,'retention defaults');qid('private-commit').disabled=false;qid('private-commit').click();await qwait(()=>!qid('private-download-locator').disabled,'refused early commit');qassert(qid('private-room').hidden && qid('private-status').dataset.error==='true','creation bypassed retention');return true;})()");
  const locator=await download(page,'private-download-locator','vhroom');
  if(locator.raw.length!==136 || locator.raw.subarray(0,8).toString()!=='VHPLOC1\0')throw Error('canonical full locator download');
  await evaluate(page,"qassert(!qid('private-locator-retained').checked && qid('private-commit').disabled,'download silently acknowledged retention');true");
  await keypress(page,'private-locator-retained',' ','Space',32);
  await evaluate(page,"(async()=>{qassert(qid('private-locator-retained').checked,'keyboard retention acknowledgement');await qclick('private-commit');await qidle();qassert(!qid('private-room').hidden,'committed room absent');qseparate();return true;})()");
  page.locator=locator.path;
  return locator;
}
async function receive(page,message) {
  await setFile(page,'private-message-file',message.path);
  await evaluate(page,"(async()=>{await qclick('private-receive');await qidle();return true;})()");
}
async function send(page,body) {
  await invoke(page,`async function(body){qset('private-message',body);await qclick('private-prepare-message');await qwait(()=>!qid('private-save-message').disabled,'exact consent');qassert(qid('private-consent').textContent.includes(body),'exact body preview');await qclick('private-save-message');await qidle();qassert(qid('private-message').value==='','saved draft not cleared');return true;}`,[body]);
  return download(page,'private-download-output','vhmsg');
}
async function leave(page) {
  await evaluate(page,"(async()=>{await qclick('private-leave');await qwait(()=>qid('identity-state').textContent==='Locked'&&!qid('unlock').disabled,'new locked worker');qassert(qid('private-workspace').hidden,'private workspace survives lock');qassert(qid('private-message').value==='','private message survived lock');for(const field of document.querySelectorAll('#private-panel input'))qassert(field.type==='checkbox'?!field.checked:field.value==='','private input survived lock: '+field.id);for(const id of ['private-consent','private-admission-consent','private-inbox-content','private-membership-details','private-secret-label'])qassert(qid(id).textContent==='','private view survived lock: '+id);qassert(qaURLs.size===0,'download URL survived lock');qassert(!qid('activity-heading').closest('.activity').hidden,'public activity remains hidden');for(const id of ['activity-text','puzzle-artifact','puzzle-part'])qassert(qid(id).value==='','private text carried into public composer');return true;})()");
}
async function reopen(page) {
  await evaluate(page,"(async()=>{qset('password',qpassword);await qclick('unlock');await qwait(()=>qid('identity-state').textContent==='Unlocked','explicit unlock');await qclick('private-enter');await qwait(()=>!qid('private-open').disabled,'new private entry');return true;})()");
  await setFile(page,'private-locator-file',page.locator);
  await evaluate(page,"(async()=>{await qclick('private-open');await qidle();return true;})()");
}
async function reload(page) {
  // A real document teardown: a fresh target in the same browser context gets
  // a new renderer and new worker, while this context's durable IndexedDB
  // custody must survive intact. Page.reload is not used: a CDP call bound to
  // the dying execution context can be dropped silently and stall forever.
  await call('Target.closeTarget',{targetId:page.targetId});
  const {targetId}=await call('Target.createTarget',{url:'about:blank',browserContextId:page.browserContextId});
  const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  page.targetId=targetId;page.sessionId=sessionId;
  for(const method of ['Page.enable','Runtime.enable','DOM.enable','Network.enable'])await call(method,{},sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:instrumentation},sessionId);
  await call('Page.navigate',{url:serverOrigin},sessionId);
  // A Runtime.evaluate bound to a context dying mid-navigation is dropped
  // without any response; bound each probe so a dropped call retries. On an
  // existing account the app boots to Locked with `create` disabled — `unlock`
  // enabled is the correct readiness signal.
  const timed=async()=>{try{return await Promise.race([evaluate(page,"!!document.getElementById('unlock')&&!document.getElementById('unlock').disabled"),new Promise(r=>setTimeout(()=>r(false),1500))]);}catch{return false;}};
  await wait(timed,'private app reload '+page.name);
  await evaluate(page,`(async()=>{${helpers} qset('password',qpassword);await qclick('unlock');await qwait(()=>qid('identity-state').textContent==='Unlocked','reload unlock');await qclick('private-enter');await qwait(()=>!qid('private-open').disabled,'private re-entry');return true;})()`);
  await setFile(page,'private-locator-file',page.locator);
  await evaluate(page,"(async()=>{await qclick('private-open');await qidle();return true;})()");
}
async function restartArchive(page) {
  await call('Page.navigate',{url:serverOrigin},page.sessionId);
  await wait(async()=>{try{return await evaluate(page,"!!document.getElementById('unlock')&&!document.getElementById('unlock').disabled");}catch{return false;}},'archive client reload');
  await evaluate(page,`(async()=>{${helpers} qset('password',qpassword);await qclick('unlock');await qwait(()=>qid('identity-state').textContent==='Unlocked','archive reload unlock');await qclick('private-enter');await qwait(()=>!qid('private-import-archive').disabled,'archive reload entry');return true;})()`);
}
async function screenshot(page,width,focus='private-room-title',label='private-panel') {
  // An occluded background target may never produce a compositor frame, which
  // leaves captureScreenshot unanswered; foreground the target first, and if a
  // capture is still dropped retry once on a fresh overlay. A detached session
  // surfaces through the Runtime.evaluate probe instead of hanging silently.
  await call('Page.bringToFront',{},page.sessionId);
  await call('Emulation.setDeviceMetricsOverride',{width,height:950,deviceScaleFactor:1,mobile:false},page.sessionId);
  const bounds=await invoke(page,`function(focus){qshow(focus);const panel=qid('private-panel');qassert(document.documentElement.scrollWidth<=innerWidth+1,'horizontal document overflow');for(const e of panel.querySelectorAll('button,input,textarea,select,pre')){if(!e.getClientRects().length)continue;const r=e.getBoundingClientRect();qassert(r.left>=-1&&r.right<=innerWidth+1,'private control overflow: '+e.id);}return {width:innerWidth,scrollWidth:document.documentElement.scrollWidth};}`,[focus]);
  let data;
  try{({data}=await Promise.race([call('Page.captureScreenshot',{format:'png'},page.sessionId),new Promise((_,j)=>setTimeout(()=>j(Error('capture stall')),15000))]));}
  catch(e){if(e.message!=='capture stall')throw e;
    await call('Emulation.clearDeviceMetricsOverride',{},page.sessionId).catch(()=>{});
    await call('Emulation.setDeviceMetricsOverride',{width,height:950,deviceScaleFactor:1,mobile:false},page.sessionId);
    await evaluate(page,'1');
    ({data}=await call('Page.captureScreenshot',{format:'png'},page.sessionId));}
  const path=join(output,label+'-'+width+'.png');await writeFile(path,Buffer.from(data,'base64'));screenshots.push({...bounds,file:path});
}
async function task(abortSignal) {
  signal=abortSignal;
  signal.throwIfAborted();
  server=createServer(async(req,res)=>{
    try{
      signal.throwIfAborted();
      for(const h of headers)res.setHeader(h.key,h.value);
      if(req.method!=='GET'){networkWrites++;throw Error('file-only qualification refuses network writes');}
      const pathname=new URL(req.url,'http://127.0.0.1').pathname;
      const target=resolve(artifact,'.'+(pathname==='/'?'/index.html':pathname));
      if(!target.startsWith(artifact+sep)||!manifest.assets[target.slice(artifact.length+1)]){res.writeHead(404);res.end();return;}
      res.setHeader('content-type',target.endsWith('.wasm')?'application/wasm':target.endsWith('.js')?'text/javascript':target.endsWith('.css')?'text/css':'text/html');
      res.end(await readFile(target));
    }catch{res.writeHead(500);res.end('qualification request refused');}
  });
  // Bind an ephemeral loopback port: a fixed port collides with a host service
  // and makes the qualification un-runnable beside a maintained gateway. The
  // local-qualification build instead pins an exact origin allowlist
  // (browser/src/qualification.rs); prefer the dedicated 8789 qualification
  // port and fall back to 8790 only when it is free.
  if(production){
    await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
  }else{
    let port=0;
    for(const candidate of [8789,8790]){
      const taken=await new Promise(r=>{const probe=createServer();probe.once('error',()=>r(true));probe.listen(candidate,'127.0.0.1',()=>probe.close(()=>r(false)));});
      if(!taken){port=candidate;break;}
    }
    if(!port)throw Error('no allowed loopback qualification port free');
    await new Promise((r,j)=>{server.once('error',j);server.listen(port,'127.0.0.1',r);});
  }
  serverOrigin='http://127.0.0.1:'+server.address().port;
  signal.throwIfAborted();
  // Backgrounding throttles keep an occluded non-foreground target from
  // producing compositor frames on demand, which leaves Page.captureScreenshot
  // unanswered. These flags disable only scheduling throttles, never a
  // behavior under test.
  // Chrome writes to a private log file rather than inheriting this driver's
  // pipe: its crash handler leaves the browser's process tree by design and
  // can outlive it, and an inherited pipe would withhold the closure evidence
  // cleanup requires. A child with no pipes closes as soon as it exits.
  const chromeLogPath=join(output,'chrome.log');
  const chromeLogFile=await open(chromeLogPath,'wx',0o600);
  let chrome;
  try{chrome=trackChild(spawn(chromeExecutable,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-default-apps','--disable-extensions','--disable-sync','--metrics-recording-only','--no-proxy-server','--disable-backgrounding-occluded-windows','--disable-renderer-backgrounding','--disable-background-timer-throttling','--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1, EXCLUDE localhost','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:['ignore',chromeLogFile.fd,chromeLogFile.fd]}));}
  finally{await chromeLogFile.close();}
  children.push(chrome);
  await wait(async()=>{chromeLog=(await readFile(chromeLogPath,'utf8').catch(()=>'')).slice(-131072);return /DevTools listening on (ws:\/\/[^\s]+)/.test(chromeLog)||childStopped(chrome);},'Chrome');
  if(childStopped(chrome))throw Error('Chrome exited');
  socket=new WebSocket(chromeLog.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]);
  await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
  socket.onmessage=({data})=>{
    const message=JSON.parse(data);
    if(message.id){const p=pending.get(message.id);pending.delete(message.id);message.error?p?.reject(Error(JSON.stringify(message.error))):p?.resolve(message.result);return;}
    if(message.method==='Browser.downloadWillBegin'){
      if(downloads.size>=64){unexpectedNetwork=true;return;}
      const p=message.params;downloads.set(p.guid,{guid:p.guid,filename:p.suggestedFilename,state:'begun'});
    }else if(message.method==='Browser.downloadProgress'){
      const p=message.params,item=downloads.get(p.guid);if(item)item.state=p.state;
    }else if(message.method==='Network.requestWillBeSent'){
      const url=message.params.request.url;
      if(!url.startsWith(serverOrigin+'/')&&!url.startsWith('blob:'+serverOrigin+'/')&&url!=='about:blank')unexpectedNetwork=true;
    }
  };
  const owner=await account('owner'), member=await account('member');
  if(owner.publicKey===member.publicKey)throw Error('accounts were not independent');
  // Keep the encrypted identity backup for the same-account fresh device below.
  // It must be downloaded while this context is unlocked and outside private custody.
  const ownerBackup=await download(owner,'backup','vhkey');
  // The identity backup URL expires on its own 10s deadline; wait for the
  // watchdog revocation so later lock assertions see no surviving URL.
  await wait(()=>evaluate(owner,'qaURLs.size===0'),'owner backup URL expiry');
  await enter(owner,true);
  await evaluate(owner,"qclick('private-create')");await retainCreation(owner);
  facts.push('keyboard entry, fresh owner, real locator download and explicit retention gate');
  await invoke(owner,`async function(recipient){qset('private-recipient',recipient);await qclick('private-offer');await qidle();return true;}`,[member.publicKey]);
  const offer=await download(owner,'private-download-secret','vhoffer');
  if(offer.raw.length!==714)throw Error('exact signed confidential offer length');
  await enter(member);
  await setFile(member,'private-offer-file',offer.path);
  await invoke(member,`async function(wrongOwner,ownerKey){qset('private-owner',wrongOwner);await qclick('private-review-offer');await qwait(()=>!qid('private-review-offer').disabled,'wrong owner pin refusal');qassert(qid('private-prepared').hidden&&qid('private-status').dataset.error==='true','wrong owner pin prepared a device');qset('private-owner',ownerKey);await qclick('private-review-offer');return true;}`,[member.publicKey,owner.publicKey]);
  await retainCreation(member);
  await evaluate(member,"(async()=>{await qclick('private-request');await qidle();return true;})()");
  const request=await download(member,'private-download-output','vhrequest');
  await setFile(owner,'private-request-file',request.path);
  await invoke(owner,`async function(recipient){qset('private-recipient',recipient);await qclick('private-accept');await qwait(()=>!qid('private-refresh').disabled,'changed recipient refusal');qassert(qid('private-status').dataset.error==='true'&&qid('identity-state').textContent==='Private custody','changed recipient reached owner publication');return true;}`,[owner.publicKey]);
  // Test actual restart custody and original-file expiry recovery, not only a
  // convenient in-memory offer. The request remains unconsumed after refusal.
  await leave(owner);await reopen(owner);
  await setFile(owner,'private-resume-offer-file',offer.path);
  await setFile(owner,'private-request-file',request.path);
  await invoke(owner,`async function(recipient){qset('private-recipient',recipient);await qclick('private-accept');await qidle();return true;}`,[member.publicKey]);
  const response=await download(owner,'private-download-output','vhjoin');
  await setFile(member,'private-join-file',response.path);
  await evaluate(member,"(async()=>{await qclick('private-join');await qidle();qassert(qid('private-membership-summary').textContent.includes('2 admitted devices'),'two-device roster absent');return true;})()");
  facts.push('two independent accounts joined through actual confidential offer and encrypted request/response files');
  const inert='<img src="https://not-a-route.invalid/panel" onerror="window.qaInjected=true"><script>window.qaInjected=true</script>\nSYNTHETIC_PRIVATE_TEXT';
  const message=await send(member,inert);await receive(owner,message);
  await invoke(owner,`function(body){qassert(qid('private-inbox-content').textContent.includes(body),'received bytes changed');qassert(!qaInjected && !qid('private-inbox-content').querySelector('img,script'),'private text became executable markup');return true;}`,[inert]);
  await evaluate(member,"(async()=>{await qclick('private-outbox');await qidle();const select=qid('private-outbox-select');const index=Array.from(select.options).findIndex(o=>o.textContent.includes('Encrypted message'));qassert(index>=0,'saved ciphertext missing');select.selectedIndex=index;return true;})()");
  const repeated=await download(member,'private-download-outbox','vhmsg');
  if(!message.raw.equals(repeated.raw))throw Error('ordinary retry changed ciphertext');
  const reply=await send(owner,'SYNTHETIC_PRIVATE_REPLY');await receive(member,reply);
  facts.push('bidirectional messages, inert imported markup and exact retained ciphertext retry');
  const draft='SYNTHETIC_DRAFT_BEFORE_OWNER_RENEWAL';
  await invoke(member,`async function(body){qset('private-message',body);await qclick('private-prepare-message');await qwait(()=>!qid('private-save-message').disabled,'prepared old-epoch consent');return true;}`,[draft]);
  await evaluate(owner,"(async()=>{await qclick('private-offer');await qidle();qassert(!qid('private-secret-output').hidden,'renewal fixture has no live offer');qassert(qid('private-resume-offer-file').value==='','new offer inherited a stale selected file');await qclick('private-renew');await qidle();qassert(qid('private-secret-output').hidden&&qid('private-download-secret').disabled&&qid('private-secret-label').textContent==='','renewal retained stale confidential offer');return true;})()");
  const renewal=await download(owner,'private-download-output','vhcontrol');
  await setFile(member,'private-control-file',renewal.path);
  await invoke(member,`async function(body){await qclick('private-apply-control');await qidle();qassert(qid('private-consent').textContent===''&&qid('private-save-message').disabled,'old-roster consent survived');qassert(qid('private-message').value===body,'unrelated draft was silently discarded');qid('private-save-message').disabled=false;qid('private-save-message').click();await qwait(()=>!qid('private-refresh').disabled,'stale consent refused');qassert(qid('private-status').dataset.error==='true','stale consent was queued');return true;}`,[draft]);
  await evaluate(member,"(async()=>{qset('private-message','SYNTHETIC_REVIEWED_TEXT');await qclick('private-prepare-message');await qwait(()=>!qid('private-save-message').disabled,'new consent');qid('private-message').value='SYNTHETIC_UNANNOUNCED_EDIT';qid('private-save-message').click();await qwait(()=>!qid('private-refresh').disabled,'unannounced edit refusal');qassert(qid('private-status').dataset.error==='true','changed text queued');return true;})()");
  await evaluate(owner,"(async()=>{await qclick('private-controls');await qidle();qassert(qid('private-control-select').options.length===2,'bounded control history');await qclick('private-outbox');await qidle();qassert(Array.from(qid('private-outbox-select').options).some(o=>o.textContent.includes('Metadata / non-exportable bootstrap')),'secret issuance metadata missing');return true;})()");
  const beforeSecretExport=downloads.size;
  await evaluate(owner,"(async()=>{const select=qid('private-outbox-select');select.selectedIndex=Array.from(select.options).findIndex(o=>o.textContent.includes('Metadata / non-exportable bootstrap'));await qclick('private-download-outbox');await qwait(()=>!qid('private-refresh').disabled,'secret metadata export refusal');qassert(qid('private-status').dataset.error==='true','secret outbox became ciphertext export');return true;})()");
  if(downloads.size!==beforeSecretExport)throw Error('secret metadata caused a download');
  facts.push('ordered renewal control invalidates exact consent; unsignaled text edit and ordinary secret export refused before queue');
  // Same-account fresh device: the owner backup restores into a third context,
  // and the owner admits it through the ordinary confidential offer flow under
  // a new device enrollment. The new device starts at the join checkpoint.
  await invoke(owner,`async function(self){qset('private-recipient',self);await qclick('private-offer');await qidle();return true;}`,[owner.publicKey]);
  const selfOffer=await download(owner,'private-download-secret','vhoffer');
  const fresh=await restored('fresh',ownerBackup.path);
  if(fresh.publicKey!==owner.publicKey)throw Error('restored backup produced a different account');
  await enter(fresh);
  await setFile(fresh,'private-offer-file',selfOffer.path);
  await invoke(fresh,`async function(ownerKey){qset('private-owner',ownerKey);await qclick('private-review-offer');await qwait(()=>!qid('private-prepared').hidden,'self-offer review');return true;}`,[owner.publicKey]);
  await retainCreation(fresh);
  await evaluate(fresh,"(async()=>{await qclick('private-request');await qidle();return true;})()");
  const selfRequest=await download(fresh,'private-download-output','vhrequest');
  await setFile(owner,'private-request-file',selfRequest.path);
  await invoke(owner,`async function(self){qset('private-recipient',self);await qclick('private-accept');await qidle();return true;}`,[owner.publicKey]);
  const selfJoin=await download(owner,'private-download-output','vhjoin');
  await setFile(fresh,'private-join-file',selfJoin.path);
  await evaluate(fresh,"(async()=>{await qclick('private-join');await qidle();qassert(qid('private-membership-summary').textContent.includes('3 admitted devices'),'same-account device roster absent');await qclick('private-inbox');await qidle();qassert(qid('private-inbox-content').textContent==='','fresh device received pre-join history');return true;})()");
  const freshText=await send(fresh,'SYNTHETIC_FRESH_DEVICE_TEXT');await receive(owner,freshText);
  await invoke(owner,`function(body){qassert(qid('private-inbox-content').textContent.includes(body),'fresh device text not received');return true;}`,['SYNTHETIC_FRESH_DEVICE_TEXT']);
  const ownerText=await send(owner,'SYNTHETIC_OWNER_TO_FRESH');await receive(fresh,ownerText);
  // The fresh device joined at the second control floor; the member-addition
  // proof predates its retained base and must not observe as applicable.
  await invoke(owner,"async function(){await qclick('private-proofs');await qidle();const select=qid('private-proof-select');const i=Array.from(select.options).findIndex(o=>o.textContent==='Signed control 1');qassert(i>=0,'first signed proof missing');select.selectedIndex=i;return true;}");
  await wait(()=>evaluate(owner,'qaURLs.size<8'),'owner download slot');
  const baseProof=await download(owner,'private-download-proof','vhproof');
  await setFile(fresh,'private-proof-file',baseProof.path);
  await evaluate(fresh,"(async()=>{await qclick('private-observe');await qidle();qassert(qid('private-status').textContent.includes('below this device'),'pre-join proof not reported below retained base');return true;})()");
  await leave(fresh);
  facts.push('same-account fresh device restored from encrypted backup, admitted by self-targeted offer, no pre-join history, bidirectional exchange');
  // Owner removal: exclude the member device and rekey. The member must first
  // apply the skipped fresh-device addition — controls chain strictly in order.
  const memberFloor=await evaluate(member,`(async()=>{await qclick('private-refresh');await qidle();const m=qid('private-membership-details').textContent.match(/Control floor ([0-9]+)/);qassert(m,'member control floor absent');return m[1];})()`);
  await invoke(owner,`async function(next){await qclick('private-controls');await qidle();const select=qid('private-control-select');const i=Array.from(select.options).findIndex(o=>o.textContent==='Encrypted control '+next);qassert(i>=0,'next control missing: '+next);select.selectedIndex=i;return true;}`,[String(Number(memberFloor)+1)]);
  // The panel caps live temporary download URLs; each expires on a 30s
  // watchdog. Wait for a free slot rather than racing the bound.
  await wait(()=>evaluate(owner,'qaURLs.size<8'),'owner download slot');
  const addition=await download(owner,'private-download-control','vhcontrol');
  await setFile(member,'private-control-file',addition.path);
  await evaluate(member,"(async()=>{await qclick('private-apply-control');await qidle();return true;})()");
  const memberDevice=await invoke(owner,`async function(account){await qclick('private-refresh');await qidle();const match=qid('private-membership-details').textContent.match(new RegExp('Account '+account+'\\\\nDevice ([0-9a-f]{64})'));qassert(match,'member device absent from owner roster');return match[1];}`,[member.publicKey]);
  await invoke(owner,`async function(account,device){qset('private-remove-device',device);qassert(qid('private-remove').disabled,'removal usable without review');await qclick('private-remove-review');await qidle();const review=qid('private-owner-consent').textContent;qassert(review.includes(account)&&review.includes(device)&&review.includes('Review removal and rekey')&&review.includes('Epoch ')&&review.includes('Roster ')&&review.includes('Control floor ')&&review.includes('expires at'),'removal review omitted exact target or current membership');return true;}`,[member.publicKey,memberDevice]);
  for(const width of [1280,390])await screenshot(owner,width,'private-owner-consent','private-removal-review');
  await call('Emulation.clearDeviceMetricsOverride',{},owner.sessionId);
  await evaluate(owner,"(async()=>{await qclick('private-remove');await qidle();qassert(qid('private-membership-summary').textContent.includes('2 admitted devices'),'owner roster did not shrink');qassert(qid('private-remove').disabled,'removal review remained reusable');return true;})()");
  await wait(()=>evaluate(owner,'qaURLs.size<8'),'owner download slot');
  const removal=await download(owner,'private-download-output','vhcontrol');
  // Signed-control inspection: the owner exports the removal's plaintext
  // proof; the member observes it as unknown history before applying the
  // encrypted envelope and as retained history after.
  const removalSeq=String(Number(memberFloor)+2);
  await invoke(owner,`async function(seq){await qclick('private-proofs');await qidle();const select=qid('private-proof-select');const i=Array.from(select.options).findIndex(o=>o.textContent==='Signed control '+seq);qassert(i>=0,'removal proof missing: '+seq);select.selectedIndex=i;return true;}`,[removalSeq]);
  await wait(()=>evaluate(owner,'qaURLs.size<8'),'owner download slot');
  const proof=await download(owner,'private-download-proof','vhproof');
  await setFile(member,'private-proof-file',proof.path);
  await evaluate(member,"(async()=>{await qclick('private-observe');await qidle();qassert(qid('private-status').textContent.includes('has not retained'),'unapplied proof not reported unknown');return true;})()");
  await setFile(member,'private-control-file',removal.path);
  await evaluate(member,"(async()=>{await qclick('private-apply-control');await qidle();qassert(qid('private-membership-summary').textContent.includes('2 admitted devices'),'removed member roster stale');qassert(qid('private-prepare-message').disabled,'removed member can still prepare');qassert(!qid('private-outbox').disabled&&!qid('private-inbox').disabled,'removed member lost retained history reads');await qclick('private-observe');await qidle();qassert(qid('private-status').textContent.includes('already retained history'),'applied proof not reported retained');await qclick('private-fork-evidence');await qidle();qassert(qid('private-status').textContent.includes('No locally retained fork proof'),'clean member reported a fork proof');qassert(qid('private-evidence').textContent==='','phantom fork detail rendered');return true;})()");
  facts.push('owner removal control excludes a device and rekeys; removed member retains read-only state but cannot send; signed proofs observe as unknown then retained with no fabricated fork evidence');
  // Fabricate the equivocation durable quarantine exists for: the owner device
  // re-signs divergent claims at the retained removal floor with its own
  // custody. Evidence material only — the owner's retained state is unchanged.
  let forkProof;
  if(!production){
    const divergent=await invoke(owner,`async function(seq,path){const m=await import(path);const r=JSON.parse(await m.qualify_private_session('divergent-proof',seq));return r.control;}`,[removalSeq,'/'+modules[0]]);
    const forkRaw=Buffer.from(divergent,'hex');
    forkProof=join(output,'divergent.vhproof');await writeFile(forkProof,forkRaw,{mode:0o600});
    files.push({account:owner.name,kind:'vhproof',bytes:forkRaw.length,sha256:createHash('sha256').update(forkRaw).digest('hex'),file:forkProof});
  }
  for(const width of [1280,768,390])await screenshot(member,width);
  // The removal-control download seconds ago still holds a live temporary URL;
  // the lock hook must revoke it. No extra download: the panel caps live URLs.
  await evaluate(owner,"qassert(qaURLs.size>0,'temporary download URL not observed');qset('private-message','PRIVATE_TEXT_MUST_NOT_CROSS_MODES');qset('private-succeed-device','PRIVATE_SUCCESSOR_MUST_NOT_SURVIVE_LOCK');true");
  await leave(owner);await leave(member);
  await reopen(member);
  await evaluate(member,"(async()=>{await qclick('private-outbox');await qidle();const select=qid('private-outbox-select');select.selectedIndex=Array.from(select.options).findIndex(o=>o.textContent.includes('Encrypted message'));qassert(select.selectedIndex>=0,'reopened ciphertext missing');return true;})()");
  const reopened=await download(member,'private-download-outbox','vhmsg');
  if(!message.raw.equals(reopened.raw))throw Error('exact locator reopen changed retained ciphertext');
  await leave(member);
  facts.push('lock clears plaintext/files/views/URLs, requires new unlock, exact locator reopen retains ciphertext');
  if(!production){
    // A divergent control validly signed by the owner device at the retained
    // removal floor is exactly the equivocation durable quarantine exists for.
    // The member kernel writes its fault before the worker reports failure.
    await reopen(member);
    await setFile(member,'private-proof-file',forkProof);
    await evaluate(member,"(async()=>{await qwait(()=>!qid('private-observe').disabled,'observe control enabled');qshow('private-observe');qid('private-observe').click();await qwait(()=>qid('identity-state').textContent==='Reload required','a proven conflict did not end the worker');return true;})()");
    await reload(member);
    await evaluate(member,`(async()=>{
      qassert(qid('private-membership-summary').textContent.includes('Quarantined'),'quarantine not surfaced after reload');
      qassert(qid('private-prepare-message').disabled,'quarantined device can still prepare');
      qassert(qid('private-apply-control').disabled,'quarantined device can still apply controls');
      await qclick('private-fork-evidence');await qidle();
      const evidence=qid('private-evidence').textContent;
      qassert(evidence.includes('Retained fork proof'),'retained fork proof missing');
      qassert(evidence.includes('Accepted floor ${removalSeq}'),'fork proof names the wrong floor');
      qassert(evidence.includes('durably quarantined'),'quarantine consequence text missing');
      qassert(qid('private-status').textContent.includes('conflicting owner signature'),'fork status message missing');
      await qclick('private-outbox');await qidle();
      qassert(qid('private-outbox-select').options.length>0,'quarantine lost retained outbox');
      await qclick('private-inbox');await qidle();
      return true;
    })()`);
    await leave(member);
    facts.push('a divergent owner-signed control at a retained floor durably quarantines the member: the worker ends terminally, reopen shows quarantine plus the retained fork proof, sends stay refused, and retained history stays readable');
  }
  // Expired-envelope edge: the fresh device's own retained next-floor control
  // (the member removal it never applied) under a caller clock past its
  // enrollment validity hits the kernel's ordinary time refusal — the worker
  // ends, nothing is published or quarantined, and the identical envelope
  // applies under the real clock after a document teardown.
  await reopen(fresh);
  if(!production){
    const expiredEnvelope=(await readFile(removal.path)).toString('hex');
    await invoke(fresh,`async function(hex,path){const m=await import(path);const r=JSON.parse(await m.qualify_private_session('expire-apply',hex));qassert(r.expired_refusal===true,'expired apply not refused');await qwait(()=>qid('identity-state').textContent==='Reload required','expired apply did not end the worker');return true;}`,[expiredEnvelope,'/'+modules[0]]);
    await reload(fresh);
  }
  await setFile(fresh,'private-control-file',removal.path);
  await evaluate(fresh,"(async()=>{await qclick('private-apply-control');await qidle();qassert(qid('private-membership-summary').textContent.includes('2 admitted devices'),'fresh roster did not shrink');qassert(!qid('private-prepare-message').disabled,'expired refusal removed the member');await qclick('private-fork-evidence');await qidle();qassert(qid('private-status').textContent.includes('No locally retained fork proof'),'expired refusal fabricated fork evidence');return true;})()");
  await leave(fresh);
  if(!production)facts.push('a control applied under a caller clock past enrollment validity is refused without mutation or quarantine: the worker ends, reopen shows no fork evidence, and the identical envelope applies under the real clock');
  else facts.push('production member applies the ordered removal envelope under the real clock before owner succession');
  // Account-authorized owner-device succession: the owner's account signs a
  // grant for its already-enrolled fresh device, carried by the predecessor's
  // next control. The predecessor stays an ordinary member; only the promoted
  // successor issues controls after the handoff floor.
  await reopen(owner);await reopen(fresh);
  const freshDevice=await evaluate(fresh,`(async()=>{await qclick('private-refresh');await qidle();const m=qid('private-membership-details').textContent.match(/Device ([0-9a-f]{64})/);qassert(m,'fresh device key absent');return m[1];})()`);
  await invoke(owner,`async function(account,device){qset('private-succeed-device',device);qassert(qid('private-succeed').disabled,'handoff usable without review');await qclick('private-succeed-review');await qidle();const review=qid('private-owner-consent').textContent;qassert(review.includes(account)&&review.includes(device)&&review.includes('Review ownership handoff')&&review.includes('Epoch ')&&review.includes('Roster ')&&review.includes('Control floor ')&&review.includes('expires at'),'handoff review omitted exact target or current membership');return true;}`,[fresh.publicKey,freshDevice]);
  for(const width of [1280,390])await screenshot(owner,width,'private-owner-consent','private-handoff-review');
  await call('Emulation.clearDeviceMetricsOverride',{},owner.sessionId);
  await evaluate(owner,"(async()=>{await qclick('private-succeed');qassert(qid('private-succeed-device').disabled,'successor input is editable during mutation');await qidle();qassert(qid('private-secret-output').hidden&&qid('private-download-secret').disabled,'succession retained a stale offer');qassert(qid('private-remove-review').disabled&&qid('private-remove').disabled&&qid('private-renew').disabled&&qid('private-succeed-review').disabled&&qid('private-succeed').disabled&&qid('private-offer').disabled,'predecessor kept owner actions');qassert(!qid('private-prepare-message').disabled,'predecessor lost ordinary membership');return true;})()");
  const handoff=await download(owner,'private-download-output','vhcontrol');
  await setFile(fresh,'private-control-file',handoff.path);
  await evaluate(fresh,"(async()=>{await qclick('private-apply-control');await qidle();qassert(qid('private-membership-summary').textContent.includes('2 admitted devices'),'succession churned the roster');qassert(!qid('private-remove-review').disabled&&!qid('private-renew').disabled&&!qid('private-succeed-review').disabled&&!qid('private-offer').disabled,'successor lacks owner review actions');qassert(qid('private-remove').disabled&&qid('private-succeed').disabled,'successor inherited a predecessor consent');return true;})()");
  // The promoted successor issues the next owner control; the demoted
  // predecessor applies it in floor order like any member.
  await evaluate(fresh,"(async()=>{await qclick('private-renew');await qidle();return true;})()");
  const successorRenewal=await download(fresh,'private-download-output','vhcontrol');
  await setFile(owner,'private-control-file',successorRenewal.path);
  await evaluate(owner,"(async()=>{await qclick('private-apply-control');await qidle();qassert(qid('private-remove').disabled,'demoted owner regained owner actions');return true;})()");
  await qualifyArchives({owner,fresh,output,evaluate,invoke,setFile,download,send,leave,reopen,restartArchive,facts});
  await leave(owner);await leave(fresh);
  facts.push('account-authorized succession hands ownership to the enrolled same-account device through one distributed owner control: the predecessor keeps ordinary membership, and the promoted successor issues controls the predecessor applies in order');
  if(unexpectedNetwork||networkWrites)throw Error('unexpected route, network write or unbounded download event');
  return {passed:true,artifact,purpose:manifest.purpose,artifactManifestSha256:createHash('sha256').update(manifestRaw).digest('hex'),serverOrigin,facts,screenshots,files,networkWrites,contexts:3,profile,scope:'synthetic private DOM file exchange; no external relay, public posting or production data'};
}

await runQualification({work:task,timeoutMs:300000,
  cleanup:async()=>cleanupOwned({children,server,socket,pending}),
  publish:async receipt=>{await writeFile(join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify(receipt));},
});
