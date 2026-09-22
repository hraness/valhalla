// Production private DOM through the actual loopback HTTP gateway and TLS relay.
// No account seeds, production signer calls, external routes or fixture KDF changes.
import {trackChild, childStopped, cleanupOwned, runQualification, closeTargetChecked} from './qualification_lifecycle.mjs';
import {stopChild} from './qualification_lifecycle.mjs';
import {spawn} from 'node:child_process';
import {createServer as createTcpServer} from 'node:net';
import {createHash} from 'node:crypto';
import {readFile, writeFile, mkdir, mkdtemp, chmod, open} from 'node:fs/promises';
import {resolve, join} from 'node:path';

const [artifactArg, chromeExecutable, outputArg, cliArg, opensslArg] = process.argv.slice(2);
if (!artifactArg || !chromeExecutable || !outputArg || !cliArg || !opensslArg) throw Error('requires production private artifact, Chromium, new output directory, vhalla CLI, OpenSSL');
const artifact = resolve(artifactArg), output = resolve(outputArg);
await mkdir(output, {recursive:false, mode:0o700});
const profile = await mkdtemp(join(output,'profile-'));
const manifestRaw = await readFile(join(artifact,'artifact.json'));
const manifest = JSON.parse(manifestRaw);
if (manifest.purpose !== 'production') throw Error('production artifact required');
for (const [name, item] of Object.entries(manifest.assets)) {
  if (name.includes('/') || name.includes('..')) throw Error('nonlocal manifest asset');
  const bytes = await readFile(join(artifact,name));
  if (bytes.length !== item.bytes || createHash('sha256').update(bytes).digest('hex') !== item.sha256) throw Error('artifact changed: '+name);
}
const modules=Object.keys(manifest.assets).filter(n=>/^vhalla-browser-[a-z0-9]+\.js$/.test(n));
if(modules.length!==1)throw Error('expected one main application module');
const children=[], pending=new Map(), downloads=new Map(), pages=[];
let socket, signal, sequence=0, chromeLog='', unexpectedNetwork=false;
const facts=[], files=[];
const deadline=Date.now()+360000;
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
// Harness-only IPC observation of the synthetic worker. Capture only a bounded
// disclosure preview, never credentials or identity commands. A valid Send
// control below proves that the stale-preview probe uses the actual wire ABI.
window.qaDraft=null;window.qaProbe='';window.qaProbeActive=false;
const NativeWorker=window.Worker;
window.Worker=new Proxy(NativeWorker,{construct(Type,args,NewType){
  const worker=Reflect.construct(Type,args,NewType);window.qaWorker=worker;
  worker.addEventListener('message',({data})=>{
    if(!Array.isArray(data))return;
    if(data[0]==='private-reply'&&data[2] instanceof Uint8Array){
      const raw=data[2];
      if(raw.length>13&&raw.length<270336&&raw[12]===104)window.qaDraft=raw.slice();
      if(qaProbeActive&&raw[12]===105){qaProbe='accepted';qaProbeActive=false;}
    }else if(qaProbeActive&&data[0]==='private-error'){qaProbe='refused';qaProbeActive=false;}
  });return worker;
}});
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
  await evaluate(page,`qshow(${JSON.stringify(id)});true`);
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
  await evaluate(page,`qclick(${JSON.stringify(button)})`);
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
  await call('Page.navigate',{url:'http://127.0.0.1:8790'},sessionId);
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
async function send(page,body) {
  await invoke(page,`async function(body){qset('private-message',body);await qclick('private-prepare-message');await qwait(()=>!qid('private-save-message').disabled,'exact consent');qassert(qid('private-consent').textContent.includes(body),'exact body preview');await qclick('private-save-message');await qidle();qassert(qid('private-message').value==='','saved draft not cleared');return true;}`,[body]);
  return download(page,'private-download-output','vhmsg');
}
async function leave(page) {
  await evaluate(page,"(async()=>{await qclick('private-leave');await qwait(()=>qid('identity-state').textContent==='Locked'&&!qid('unlock').disabled,'new locked worker');qassert(qid('private-workspace').hidden,'private workspace survives lock');qassert(qid('private-message').value==='','private message survived lock');for(const field of document.querySelectorAll('#private-panel input'))qassert(field.type==='checkbox'?!field.checked:field.value==='','private input survived lock: '+field.id);for(const id of ['private-consent','private-inbox-content','private-membership-details','private-secret-label'])qassert(qid(id).textContent==='','private view survived lock: '+id);qassert(qaURLs.size===0,'download URL survived lock');qassert(!qid('activity-heading').closest('.activity').hidden,'public activity remains hidden');for(const id of ['activity-text','puzzle-artifact','puzzle-part'])qassert(qid(id).value==='','private text carried into public composer');return true;})()");
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
  await closeTargetChecked(call,page.targetId);
  const {targetId}=await call('Target.createTarget',{url:'about:blank',browserContextId:page.browserContextId});
  const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  page.targetId=targetId;page.sessionId=sessionId;
  for(const method of ['Page.enable','Runtime.enable','DOM.enable','Network.enable'])await call(method,{},sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:instrumentation},sessionId);
  await call('Page.navigate',{url:'http://127.0.0.1:8790'},sessionId);
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
const cli=resolve(cliArg), openssl=resolve(opensslArg);
const namespace='31'.repeat(32), relayToken='42'.repeat(32), browserCapability='53'.repeat(32);
const tlsAddress='127.0.0.1:19473';
let relay, gateway, blackhole, fixtureSerial=0;
const blackholeSockets=new Set();
const serviceLogs=[];
async function privateFile(name,content) {const path=join(output,name);await writeFile(path,content,{mode:0o600,flag:'wx'});return path;}
async function command(executable,args) {
  signal.throwIfAborted();const process=trackChild(spawn(executable,args,{stdio:['ignore','pipe','pipe']}));children.push(process);
  let stdout='',stderr='';process.stdout.on('data',v=>stdout=(stdout+v).slice(-1048576));process.stderr.on('data',v=>stderr=(stderr+v).slice(-1048576));
  let timer;try {await Promise.race([new Promise((r,j)=>{process.once('error',j);process.once('exit',code=>code===0?r():j(Error('fixture command refused: '+stderr)));}),new Promise((_,j)=>{timer=setTimeout(()=>j(Error('fixture command deadline')),20000);})]);}finally{clearTimeout(timer);if(!childStopped(process))await stopChild(process);}
  return {stdout,stderr};
}
async function child(args,ready) {
  signal.throwIfAborted();const process=trackChild(spawn(cli,args,{stdio:['ignore','pipe','pipe']}));children.push(process);
  const record={args:args.map(a=>a.startsWith(output)?a.slice(output.length):a),stdout:'',stderr:''};serviceLogs.push(record);
  process.stdout.on('data',v=>record.stdout=(record.stdout+v).slice(-65536));process.stderr.on('data',v=>record.stderr=(record.stderr+v).slice(-65536));
  await wait(()=>{if(childStopped(process))throw Error('fixture service exited: '+record.stderr);return record.stdout.includes(ready);},ready);return process;
}
async function relayStart() {relay=await child(['private','relay-tls-serve',join(output,'mailbox'),'--namespace',namespace,'--config',join(output,'tls.json'),'--cert',join(output,'server.der'),'--key',join(output,'server-key.der'),'--listen',tlsAddress],'relay-tls-serve');}
async function fixture() {
  const caKey=join(output,'ca-key.pem'),caPem=join(output,'ca.pem'),serverKey=join(output,'server-key.pem'),csr=join(output,'server.csr'),serverPem=join(output,'server.pem');
  await command(openssl,['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',caKey,'-out',caPem,'-days','2','-subj','/CN=Synthetic Valhalla qualification CA','-addext','basicConstraints=critical,CA:TRUE']);
  await command(openssl,['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',serverKey,'-out',csr,'-subj','/CN=relay.test']);
  const extension=await privateFile('server.ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:relay.test\n');
  await command(openssl,['x509','-req','-in',csr,'-CA',caPem,'-CAkey',caKey,'-CAcreateserial','-out',serverPem,'-days','2','-extfile',extension]);
  await command(openssl,['x509','-in',caPem,'-outform','DER','-out',join(output,'ca.der')]);
  await command(openssl,['x509','-in',serverPem,'-outform','DER','-out',join(output,'server.der')]);
  await command(openssl,['pkcs8','-topk8','-nocrypt','-in',serverKey,'-outform','DER','-out',join(output,'server-key.der')]);
  for(const name of ['ca-key.pem','ca.pem','server-key.pem','server.csr','server.pem','ca.der','server.der','server-key.der'])await chmod(join(output,name),0o600);
  await privateFile('relay-token',relayToken);await privateFile('browser-token',browserCapability);
  await command(cli,['private','relay-mailbox',join(output,'mailbox'),'--namespace',namespace,'--max-items','4096','--max-bytes',String(128*1024*1024)]);
  await command(cli,['private','relay-tls-init',join(output,'mailbox'),'--namespace',namespace]);
  await privateFile('tls.json',JSON.stringify({max_connections:16,request_timeout_ms:10000,window_ms:1000,requests_per_window:128,bytes_per_window:64*1024*1024,credentials:[{id:'64'.repeat(16),namespace,token_files:[join(output,'relay-token')],put:true,page:true,max_items:2048,max_bytes:64*1024*1024,max_inflight:8,requests_per_window:64,bytes_per_window:32*1024*1024}]}));
  await privateFile('gateway.json',JSON.stringify({format:1,listen:'127.0.0.1:8790',namespace,browser_token_file:join(output,'browser-token'),upstream:{addr:tlsAddress,tls_name:'relay.test',tls_ca_file:join(output,'ca.der'),token_file:join(output,'relay-token')},assets_dir:artifact,initial_cursor:'0'}));
  await relayStart();gateway=await child(['private-gateway','serve',join(output,'gateway.json')],'private-gateway');
}
async function profileFile(initial,overrides={}) {return privateFile('profile-'+(++fixtureSerial)+'.json',JSON.stringify({format:1,origin:'http://127.0.0.1:8790',namespace,capability:browserCapability,initial_cursor:String(initial),...overrides}));}
async function connect(page,path,create=false) {
  await setFile(page,'private-delivery-profile',path);
  await evaluate(page,`(async()=>{await qclick('${create?'private-delivery-create':'private-delivery-open'}');await qidle();qassert(qid('private-delivery-profile').value==='','profile capability selection survived');qassert(!qid('private-delivery-sync').disabled,'delivery not ready');return true;})()`);
}
async function sync(page) {return evaluate(page,"(async()=>{await qclick('private-delivery-sync');await qidle();return qid('private-delivery-status').textContent;})()");}
async function sendRetainedPreview(page) {
  return evaluate(page,`(async()=>{
    qassert(qaDraft instanceof Uint8Array,'captured actual disclosure preview');
    const expected=new TextEncoder().encode('VHBRPRIVATE'+String.fromCharCode(4));
    qassert(expected.length===12&&expected.every((v,i)=>qaDraft[i]===v)&&qaDraft[12]===104,'actual private wire version');
    const frame=new Uint8Array(qaDraft.length+16);frame.set(expected);frame[12]=8;
    frame.set(crypto.getRandomValues(new Uint8Array(16)),13);frame.set(qaDraft.subarray(13),29);
    qaProbe='';qaProbeActive=true;qaWorker.postMessage(['private',new Uint8Array(16).fill(254),frame]);
    await qwait(()=>qaProbe!=='','worker verdict for actual retained preview');return qaProbe;
  })()`);
}
async function head() {
  const n=++fixtureSerial,path=join(output,'scan-'+n+'.json');
  await command(cli,['private','relay-scan',join(output,'scan-'+n),'--namespace',namespace,'--addr',tlsAddress,'--token',join(output,'relay-token'),'--tls-ca',join(output,'ca.der'),'--tls-name','relay.test','--limit','64','--out',path]);
  return JSON.parse(await readFile(path,'utf8')).head;
}
async function snapshot(page, expected=1) {
  return evaluate(page,`(async()=>{const names=await indexedDB.databases();let found=[];for(const info of names){const db=await new Promise((r,j)=>{const q=indexedDB.open(info.name);q.onsuccess=()=>r(q.result);q.onerror=()=>j(Error('read database'));});try{if(!db.objectStoreNames.contains('images'))continue;const rows=await new Promise((r,j)=>{const tx=db.transaction('images','readonly'),s=tx.objectStore('images'),q=s.openCursor(),rows=[];q.onsuccess=()=>{const c=q.result;if(c){if(String(c.key).endsWith('delivery-v1'))rows.push([...c.value]);c.continue();}else r(rows);};q.onerror=()=>j(Error('read delivery'));});found.push(...rows);}finally{db.close();}}qassert(found.length===${expected},'expected delivery image count');return found[0]??[];})()`);
}
async function task(abortSignal) {
  signal=abortSignal;await fixture();
  const chrome=trackChild(spawn(chromeExecutable,['--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-renderer-backgrounding','--disable-background-timer-throttling','--disable-backgrounding-occluded-windows','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']}));children.push(chrome);chrome.stderr.on('data',c=>chromeLog=(chromeLog+c).slice(-131072));
  await wait(()=>/DevTools listening on (ws:\/\/[^\s]+)/.test(chromeLog)||childStopped(chrome),'Chrome');
  if(childStopped(chrome))throw Error('Chrome exited');
  socket=new WebSocket(chromeLog.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]);await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
  socket.onmessage=({data})=>{const m=JSON.parse(data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p?.reject(Error(JSON.stringify(m.error))):p?.resolve(m.result);return;}if(m.method==='Browser.downloadWillBegin'){const p=m.params;downloads.set(p.guid,{guid:p.guid,filename:p.suggestedFilename,state:'begun'});}else if(m.method==='Browser.downloadProgress'){const p=m.params,item=downloads.get(p.guid);if(item)item.state=p.state;}else if(m.method==='Network.requestWillBeSent'){const url=m.params.request.url;if(!url.startsWith('http://127.0.0.1:8790/')&&!url.startsWith('blob:http://127.0.0.1:8790/')&&url!=='about:blank')unexpectedNetwork=true;}};
  const owner=await account('owner'),member=await account('member');
  await enter(owner,true);await evaluate(owner,"qclick('private-create')");await retainCreation(owner);
  await send(owner,'SYNTHETIC_PREJOIN_HISTORY');
  await snapshot(owner,0);const oversized=await profileFile(4097);await setFile(owner,'private-delivery-profile',oversized);
  await evaluate(owner,"(async()=>{await qclick('private-delivery-create');await qwait(()=>qid('identity-state').textContent==='Reload required','oversized initial cursor refusal');return true;})()");
  await snapshot(owner,0);await reload(owner);
  facts.push('oversized initial cursor refuses before creating a durable delivery profile');
  owner.deliveryProfile=await profileFile(0);await connect(owner,owner.deliveryProfile,true);await sync(owner);
  if(await head()!==1)throw Error('prejoin ciphertext not retained exactly once');
  await invoke(owner,`async function(recipient){qset('private-recipient',recipient);await qclick('private-offer');await qidle();return true;}`,[member.publicKey]);
  const offer=await download(owner,'private-download-secret','vhoffer');await enter(member);await setFile(member,'private-offer-file',offer.path);
  await invoke(member,`async function(owner){qset('private-owner',owner);await qclick('private-review-offer');return true;}`,[owner.publicKey]);await retainCreation(member);
  await evaluate(member,"(async()=>{await qclick('private-request');await qidle();return true;})()");const request=await download(member,'private-download-output','vhrequest');
  await setFile(owner,'private-request-file',request.path);await evaluate(owner,"(async()=>{await qclick('private-accept');await qidle();return true;})()");const response=await download(owner,'private-download-output','vhjoin');
  await setFile(member,'private-join-file',response.path);await evaluate(member,"(async()=>{await qclick('private-join');await qidle();return true;})()");
  await sync(owner);await sync(owner);const checkpoint=await head();if(checkpoint<2)throw Error('join output was not retained before trusted checkpoint');
  member.deliveryProfile=await profileFile(checkpoint);await connect(member,member.deliveryProfile,true);await sync(member);
  facts.push('new member starts at explicit trusted admission checkpoint, excluding undecryptable prejoin history; browser profiles bind that immutable cursor');
  await send(owner,'SYNTHETIC_GATEWAY_TLS_MESSAGE');await sync(owner);await sync(member);
  await evaluate(member,"(async()=>{await qclick('private-inbox');await qidle();qassert(qid('private-inbox-content').textContent.includes('SYNTHETIC_GATEWAY_TLS_MESSAGE'),'network message absent');qassert(!qid('private-inbox-content').textContent.includes('SYNTHETIC_PREJOIN_HISTORY'),'prejoin history leaked');return true;})()");
  await sync(member);await sync(owner);facts.push('production browser worker sends exact ciphertext through HTTP gateway and authenticated TLS relay, receiver commits locally and queues signed acceptance without receipt loops');
  // Positive ABI control: the actual worker accepts the current preview.
  // After a successful same-roster Sync, replaying its next still-valid preview
  // must fail inside worker custody even if a caller bypasses panel controls.
  await evaluate(owner,"(async()=>{qset('private-message','SYNTHETIC_VALID_IPC_PREVIEW');await qclick('private-prepare-message');await qwait(()=>!qid('private-save-message').disabled,'valid IPC preview');return true;})()");
  if(await sendRetainedPreview(owner)!=='accepted')throw Error('positive Send IPC control refused');
  await evaluate(owner,"(async()=>{qset('private-message','SYNTHETIC_STALE_AFTER_SYNC');await qclick('private-prepare-message');await qwait(()=>!qid('private-save-message').disabled,'stale IPC preview');return true;})()");
  await sync(owner);
  if(await sendRetainedPreview(owner)!=='refused')throw Error('worker reused a disclosure preview after Sync');
  await reload(owner);await connect(owner,owner.deliveryProfile);
  facts.push('a real valid Send IPC control succeeds, but an otherwise valid retained consent fails inside worker custody after same-roster Sync; no panel-only guard is relied on');
  const beforeOutage=await head();await send(owner,'SYNTHETIC_OUTAGE_RETRY');await stopChild(relay);const report=await sync(owner);if(!report.includes('Pending: true'))throw Error('outage did not preserve pending output');
  const before=Buffer.from(await snapshot(owner));if(before.includes(Buffer.from(browserCapability)))throw Error('gateway capability persisted');
  await reload(owner);await connect(owner,owner.deliveryProfile);const reopened=Buffer.from(await snapshot(owner));
  // Owner token changes on reopen; all reserved counters and ciphertext remain.
  if(!before.subarray(56).equals(reopened.subarray(56)))throw Error('reload changed pending progress/budget');
  await relayStart();await new Promise(r=>setTimeout(r,2200));await sync(owner);const afterOutage=await head();if(afterOutage!==beforeOutage+1)throw Error('outage retry duplicated or lost committed ciphertext');
  await sync(member);facts.push('relay outage, real document teardown, same-profile reopen and exact retry preserve ciphertext and counters and retain the output once');
  // Profile rebind refuses before any network mutation and leaves durable bytes.
  await reload(owner);const unchanged=Buffer.from(await snapshot(owner));const wrong=await profileFile(1);await setFile(owner,'private-delivery-profile',wrong);
  await evaluate(owner,"(async()=>{await qclick('private-delivery-open');await qwait(()=>qid('identity-state').textContent==='Reload required','changed cursor refusal');return true;})()");
  if(!unchanged.equals(Buffer.from(await snapshot(owner))))throw Error('wrong profile changed progress');await reload(owner);await connect(owner,owner.deliveryProfile);
  facts.push('changed profile initial cursor refuses without replacing retained state; capability is absent from durable delivery bytes');
  // A second same-origin tab claims a fresh CAS owner; the old worker refuses.
  const {targetId}=await call('Target.createTarget',{url:'about:blank',browserContextId:owner.browserContextId});const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});const twin={...owner,targetId,sessionId};
  for(const method of ['Page.enable','Runtime.enable','DOM.enable','Network.enable'])await call(method,{},sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:instrumentation},sessionId);await call('Page.navigate',{url:'http://127.0.0.1:8790'},sessionId);
  await wait(()=>evaluate(twin,"!!document.getElementById('unlock')&&!document.getElementById('unlock').disabled"),'second tab load');await evaluate(twin,helpers);await reopen(twin);await connect(twin,owner.deliveryProfile);
  await evaluate(owner,"(async()=>{await qclick('private-delivery-sync');await qwait(()=>qid('identity-state').textContent==='Reload required','old worker fence');return true;})()");await sync(twin);facts.push('second-tab CAS ownership invalidates the prior worker before another sync; the new worker retains exact existing counters');
  // Terminate the worker while the actual native gateway waits on a TLS
  // handshake. No delayed completion may repopulate its private UI or budgets.
  await send(twin,'SYNTHETIC_LOCKED_IN_FLIGHT');await stopChild(relay);
  blackhole=createTcpServer(socket=>{blackholeSockets.add(socket);socket.once('close',()=>blackholeSockets.delete(socket));});
  await new Promise((r,j)=>{blackhole.once('error',j);blackhole.listen(19473,'127.0.0.1',r);});
  await evaluate(twin,"qclick('private-delivery-sync')");await wait(()=>blackholeSockets.size>0,'gateway pending actual TLS handshake');
  await leave(twin);const canceled=Buffer.from(await snapshot(twin));
  for(const socket of blackholeSockets)socket.destroy();await new Promise(r=>blackhole.close(r));blackhole=undefined;
  await relayStart();await new Promise(r=>setTimeout(r,2200));
  await evaluate(twin,"qassert(qid('private-delivery-status').textContent==='','late response repopulated locked private UI');true");
  if(!canceled.equals(Buffer.from(await snapshot(twin))))throw Error('late canceled response changed durable progress');
  await reopen(twin);await connect(twin,owner.deliveryProfile);await sync(twin);
  facts.push('lock during a real gateway TLS handshake terminates worker Fetch; delayed failure cannot restore UI or alter charged progress, and explicit reopen resumes exact queued ciphertext');
  await leave(twin);await leave(member);
  if(unexpectedNetwork)throw Error('unexpected non-loopback page route');
  return {passed:true,artifact,artifactManifestSha256:createHash('sha256').update(manifestRaw).digest('hex'),facts,files,profile,scope:'production browser private custody → maintained local HTTP gateway → real TLS relay; synthetic same-machine identities; no independent-machine or Tailcat path claim'};
}
await runQualification({work:task,timeoutMs:360000,cleanup:async()=>{try{for(const socket of blackholeSockets)socket.destroy();if(blackhole){await new Promise(r=>blackhole.close(r));blackhole=undefined;}await cleanupOwned({children,socket,pending});}finally{await writeFile(join(output,'chrome.log'),chromeLog);await writeFile(join(output,'services.json'),JSON.stringify(serviceLogs,null,2));}},publish:async receipt=>{await writeFile(join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify(receipt));}});
