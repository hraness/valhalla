// Production private DOM through the loopback HTTP or explicit synthetic HTTPS gateway and TLS relay.
// No account seeds, production signer calls, external routes or fixture KDF changes.
import {spawnOwned, childStopped, cleanupOwned, runQualification, closeTargetChecked} from './qualification_lifecycle.mjs';
import {stopChild, stopServer} from './qualification_lifecycle.mjs';
import {createServer} from 'node:http';
import {createServer as createHttpsServer} from 'node:https';
import {chromeHttpsArguments, probeHttps} from './qualification_https.mjs';
import {createConnection, createServer as createTcpServer} from 'node:net';
import {createHash} from 'node:crypto';
import {readFile, writeFile, mkdir, mkdtemp, chmod, open} from 'node:fs/promises';
import {resolve, join} from 'node:path';

const [artifactArg, chromeExecutable, outputArg, cliArg, opensslArg, ...flags] = process.argv.slice(2);
if (!artifactArg || !chromeExecutable || !outputArg || !cliArg || !opensslArg) throw Error('requires production private artifact, Chromium, new output directory, vhalla CLI, OpenSSL [--gateway-port N] [--tls-port M] [--parent-stdin] [--https]');
process.umask(0o077);
const options={};
for(let i=0;i<flags.length;i++){
  const flag=flags[i];
  if(Object.hasOwn(options,flag))throw Error('duplicate flag: '+flag);
  if(flag==='--parent-stdin'||flag==='--https'){options[flag]=true;continue;}
  if(flag!=='--gateway-port'&&flag!=='--tls-port')throw Error('unknown flag: '+flag);
  const value=flags[++i];
  if(!/^[0-9]+$/.test(value??''))throw Error(flag+' requires a decimal loopback port');
  options[flag]=Number(value);
}
const httpsMode=options['--https']===true;
const httpsChecks=httpsMode?{profileFormat:2,contexts:[]}:undefined;
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
let socket, signal, sequence=0, chromeLog='', unexpectedNetwork=false, fatalNetwork='';
const facts=[], files=[], screenshots=[];
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
    if(fatalNetwork)throw Error(fatalNetwork);
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
window.qaDraft=null;window.qaAdmission=null;window.qaContactArtifact=null;window.qaProbe='';window.qaProbeActive=false;
const NativeWorker=window.Worker;
window.Worker=new Proxy(NativeWorker,{construct(Type,args,NewType){
  const worker=Reflect.construct(Type,args,NewType);window.qaWorker=worker;
  worker.addEventListener('message',({data})=>{
    if(!Array.isArray(data))return;
    if(data[0]==='private-reply'&&data[2] instanceof Uint8Array){
      const raw=data[2];
      if(raw.length>13&&raw.length<270336&&raw[12]===104)window.qaDraft=raw.slice();
      if(raw.length>13&&raw.length<270336&&raw[12]===122)window.qaAdmission=raw.slice();
      if(raw.length>171&&raw.length<270336&&raw[12]===105&&raw[165]===2)window.qaContactArtifact=raw.slice();
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
  await call('Page.navigate',{url:gatewayOrigin},sessionId);
  await wait(()=>evaluate(page,"!!document.getElementById('private-panel') && !!document.getElementById('create') && !document.getElementById('create').disabled"),'private app '+name);
  const origin=await evaluate(page,"location.origin");
  if(origin!==gatewayOrigin)throw Error('private app origin '+origin+' != configured '+gatewayOrigin);
  if(httpsMode){const secureContext=await evaluate(page,'isSecureContext');if(!secureContext)throw Error('HTTPS page is not a secure context');httpsChecks.contexts.push({account:name,origin,secureContext});}
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
  await evaluate(page,"(async()=>{await qclick('private-leave');await qwait(()=>qid('identity-state').textContent==='Locked'&&!qid('unlock').disabled,'new locked worker');qassert(qid('private-workspace').hidden,'private workspace survives lock');qassert(qid('private-message').value==='','private message survived lock');for(const field of document.querySelectorAll('#private-panel input'))qassert(field.type==='checkbox'?!field.checked:field.value==='','private input survived lock: '+field.id);for(const id of ['private-consent','private-admission-consent','private-inbox-content','private-outbox-acceptances','private-membership-details','private-secret-label'])qassert(qid(id).textContent==='','private view survived lock: '+id);qassert(qaURLs.size===0,'download URL survived lock');qassert(!qid('activity-heading').closest('.activity').hidden,'public activity remains hidden');for(const id of ['activity-text','puzzle-artifact','puzzle-part'])qassert(qid(id).value==='','private text carried into public composer');return true;})()");
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
  await call('Page.navigate',{url:gatewayOrigin},sessionId);
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
async function probeRefused(port) {
  await new Promise((resolve,reject)=>{
    const socket=createConnection({host:'127.0.0.1',port});
    socket.once('connect',()=>{socket.destroy();reject(Error('loopback port '+port+' already accepts connections'));});
    socket.once('error',error=>error?.code==='ECONNREFUSED'?resolve():reject(error));
    socket.setTimeout(2000,()=>{socket.destroy();reject(Error('loopback port '+port+' probe timed out'));});
  });
}
async function ephemeralPort() {
  const probe=createTcpServer();
  await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(0,'127.0.0.1',resolve);});
  const {port}=probe.address();
  await new Promise(r=>probe.close(r));
  return port;
}
// One loopback address, one name, one chosen port: an occupied port always
// refuses and is never silently reused, whichever service owns the collision.
async function resolvePort(explicit,label) {
  const port=explicit===undefined?await ephemeralPort():explicit;
  if(!Number.isInteger(port)||port<1||port>65535)throw Error(label+' port out of range');
  await probeRefused(port);
  return port;
}
const gatewayPort=await resolvePort(options['--gateway-port'],'gateway');
const tlsPort=await resolvePort(options['--tls-port'],'relay TLS');
const gatewayOrigin=httpsMode?`https://rooms.example.test:${gatewayPort}`:`http://127.0.0.1:${gatewayPort}`;
const tlsAddress=`127.0.0.1:${tlsPort}`;
// Collision-refusal self-check: resolvePort must never accept an occupied port.
{
  const occupied=createTcpServer();
  await new Promise((resolve,reject)=>{occupied.once('error',reject);occupied.listen(0,'127.0.0.1',resolve);});
  let refused=false;
  try{await resolvePort(occupied.address().port,'collision self-check');}catch{refused=true;}
  await new Promise(r=>occupied.close(r));
  if(!refused)throw Error('occupied loopback port was accepted');
}
let relay, gateway, blackhole, hostile, gatewayTls, chromeHttps, fixtureSerial=0;
const blackholeSockets=new Set();
const serviceLogs=[];
async function privateFile(name,content) {signal.throwIfAborted();const path=join(output,name);await writeFile(path,content,{mode:0o600,flag:'wx'});return path;}
async function command(executable,args) {
  signal.throwIfAborted();const process=spawnOwned(executable,args,{role:'fixture-command',timeoutMs:20000});children.push(process);
  let stdout='',stderr='';process.stdout.on('data',v=>stdout=(stdout+v).slice(-1048576));process.stderr.on('data',v=>stderr=(stderr+v).slice(-1048576));
  let timer;try {await Promise.race([new Promise((r,j)=>{process.once('error',j);process.once('exit',code=>code===0?r():j(Error('fixture command refused: '+stderr)));}),new Promise((_,j)=>{timer=setTimeout(()=>j(Error('fixture command deadline')),20000);})]);}finally{clearTimeout(timer);if(!childStopped(process))await stopChild(process);}
  return {stdout,stderr};
}
async function child(args,ready) {
  signal.throwIfAborted();const process=spawnOwned(cli,args,{role:args[0]});children.push(process);
  const record={args:args.map(a=>a.startsWith(output)?a.slice(output.length):a),stdout:'',stderr:''};serviceLogs.push(record);
  process.stdout.on('data',v=>record.stdout=(record.stdout+v).slice(-65536));process.stderr.on('data',v=>record.stderr=(record.stderr+v).slice(-65536));
  await wait(()=>{if(childStopped(process))throw Error('fixture service exited: '+record.stderr);return record.stdout.includes(ready);},ready);return process;
}
async function gatewayStart() {gateway=await child(['private-gateway','serve',join(output,'gateway.json')],'private-gateway '+gatewayOrigin);}
async function relayStart() {relay=await child(['private','relay-tls-serve',join(output,'mailbox'),'--namespace',namespace,'--config',join(output,'tls.json'),'--cert',join(output,'server.der'),'--key',join(output,'server-key.der'),'--listen',tlsAddress],'relay-tls-serve '+tlsAddress);}
async function fixture() {
  const caKey=join(output,'ca-key.pem'),caPem=join(output,'ca.pem'),serverKey=join(output,'server-key.pem'),csr=join(output,'server.csr'),serverPem=join(output,'server.pem');
  // Generate named-curve P-256 keys: an explicit-parameter EC encoding is
  // refused by the rustls server/client credential checks.
  await command(openssl,['ecparam','-name','prime256v1','-genkey','-noout','-out',caKey]);
  await command(openssl,['req','-x509','-new','-key',caKey,'-out',caPem,'-days','2','-subj','/CN=Synthetic Valhalla qualification CA','-addext','basicConstraints=critical,CA:TRUE']);
  await command(openssl,['ecparam','-name','prime256v1','-genkey','-noout','-out',serverKey]);
  await command(openssl,['req','-new','-key',serverKey,'-out',csr,'-subj','/CN=relay.test']);
  const extension=await privateFile('server.ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:relay.test\n');
  // LibreSSL's x509 -req defaults to ecdsa-with-SHA1, which webpki refuses.
  // -sha256 is accepted by both LibreSSL and OpenSSL for the signing digest.
  await command(openssl,['x509','-req','-in',csr,'-CA',caPem,'-CAkey',caKey,'-CAcreateserial','-out',serverPem,'-days','2','-sha256','-extfile',extension]);
  await command(openssl,['x509','-in',caPem,'-outform','DER','-out',join(output,'ca.der')]);
  await command(openssl,['x509','-in',serverPem,'-outform','DER','-out',join(output,'server.der')]);
  await command(openssl,['pkcs8','-topk8','-nocrypt','-in',serverKey,'-outform','DER','-out',join(output,'server-key.der')]);
  for(const name of ['ca-key.pem','ca.pem','server-key.pem','server.csr','server.pem','ca.der','server.der','server-key.der'])await chmod(join(output,name),0o600);
  if(httpsMode){
    const key=join(output,'gateway-key.pem'),csr=join(output,'gateway.csr'),cert=join(output,'gateway.pem');
    await command(openssl,['ecparam','-name','prime256v1','-genkey','-noout','-out',key]);
    await command(openssl,['req','-new','-key',key,'-out',csr,'-subj','/CN=rooms.example.test']);
    const ext=await privateFile('gateway.ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:rooms.example.test\n');
    await command(openssl,['x509','-req','-in',csr,'-CA',caPem,'-CAkey',caKey,'-CAcreateserial','-out',cert,'-days','2','-sha256','-extfile',ext]);
    await command(openssl,['x509','-in',cert,'-outform','DER','-out',join(output,'gateway.der')]);
    await command(openssl,['pkcs8','-topk8','-nocrypt','-in',key,'-outform','DER','-out',join(output,'gateway-key.der')]);
    for(const name of ['gateway-key.pem','gateway.csr','gateway.pem','gateway.der','gateway-key.der'])await chmod(join(output,name),0o600);
    gatewayTls={key:await readFile(key),cert:await readFile(cert),minVersion:'TLSv1.3',ALPNProtocols:['http/1.1']};
    chromeHttps=chromeHttpsArguments(gatewayTls.cert);
    httpsChecks.certificateSpkiSha256Base64=chromeHttps.spki;
    httpsChecks.trust='synthetic leaf SPKI exception in a fresh isolated Chrome profile; no system trust modification or public CA claim';
  }
  await privateFile('relay-token',relayToken);await privateFile('gateway-upstream-token',relayToken);await privateFile('browser-token',browserCapability);
  await command(cli,['private','relay-mailbox',join(output,'mailbox'),'--namespace',namespace,'--max-items','4096','--max-bytes',String(128*1024*1024)]);
  await command(cli,['private','relay-tls-init',join(output,'mailbox'),'--namespace',namespace]);
  await privateFile('tls.json',JSON.stringify({max_connections:16,request_timeout_ms:10000,window_ms:1000,requests_per_window:128,bytes_per_window:64*1024*1024,credentials:[{id:'64'.repeat(16),namespace,token_files:[join(output,'relay-token')],put:true,page:true,max_items:2048,max_bytes:64*1024*1024,max_inflight:8,requests_per_window:64,bytes_per_window:32*1024*1024}]}));
  const front=httpsMode?{format:2,origin:gatewayOrigin,
    tls:{certificate_chain_files:[join(output,'gateway.der')],private_key_file:join(output,'gateway-key.der')},
    clients:[{id:'75'.repeat(16),token_file:join(output,'browser-token'),expires_unix_secs:Math.floor(Date.now()/1000)+3600,revoked:false,max_inflight:8,requests_per_window:128,bytes_per_window:32*1024*1024}]
  }:{format:1,browser_token_file:join(output,'browser-token')};
  await privateFile('gateway.json',JSON.stringify({...front,listen:'127.0.0.1:'+gatewayPort,namespace,upstream:{addr:tlsAddress,tls_name:'relay.test',tls_ca_file:join(output,'ca.der'),token_file:join(output,'gateway-upstream-token')},assets_dir:artifact,initial_cursor:'0'}));
  await relayStart();await gatewayStart();
}
async function profileFile(initial,overrides={}) {return privateFile('profile-'+(++fixtureSerial)+'.json',JSON.stringify({format:httpsMode?2:1,origin:gatewayOrigin,namespace,capability:browserCapability,initial_cursor:String(initial),...overrides}));}
function fixtureHttpServer(handler) {
  return httpsMode?createHttpsServer(gatewayTls,handler):createServer(handler);
}
async function httpsGatewayProbes() {
  const body=Buffer.alloc(15);body.writeUInt32BE(11);body[4]=2;body.writeUInt16BE(1,13);
  const headers={origin:gatewayOrigin,authorization:'Bearer '+browserCapability,'content-type':'application/octet-stream','x-vhalla-namespace':namespace};
  const ca=await readFile(join(output,'ca.pem'));
  const before=await head(),statuses={};
  for(const [label,override,expected] of [
    ['correct',{},200],['wrongOrigin',{origin:'https://other.example.test:'+gatewayPort},403],
    ['wrongCapability',{authorization:'Bearer '+'54'.repeat(32)},403],
    ['wrongNamespace',{'x-vhalla-namespace':'32'.repeat(32)},403],
    ['forwardedOrigin',{'x-forwarded-host':'other.example.test'},403],
  ]){
    const result=await probeHttps({origin:gatewayOrigin,ca,body,headers:{...headers,...override},signal});
    if(result.status!==expected)throw Error('HTTPS gateway '+label+' status');
    if(label==='correct'&&(result.body.length<5||result.body[4]!==0||result.body.readUInt32BE(0)!==result.body.length-4))throw Error('HTTPS gateway positive control was not a canonical relay success');
    for(const forbidden of [namespace,browserCapability,relayToken])if(result.body.includes(Buffer.from(forbidden)))throw Error('HTTPS gateway refusal disclosed credentials or namespace');
    statuses[label]=result.status;
    httpsChecks.probeTlsProtocol=result.protocol;
    httpsChecks.probeAlpn=result.alpn;
  }
  if(await head()!==before)throw Error('HTTPS admission probes mutated mailbox');
  httpsChecks.admission={statuses,mailboxUnchanged:true,noCredentialOrNamespaceInErrors:true};
}
async function httpsRedirectProbe(page) {
  // Same-origin target deliberately stays inside CSP's connect-src 'self'.
  // Thus it is Fetch's redirect:error boundary that must prevent forwarding
  // the capability and namespace, rather than an unrelated cross-origin block.
  const beforeHead=await head(),message=await send(page,'SYNTHETIC_HTTPS_REDIRECT_RETRY');
  const before=Buffer.from(await snapshot(page));await stopChild(gateway);
  let redirects=0,targetRequests=0,badRequest=false;
  signal.throwIfAborted();hostile=fixtureHttpServer((request,response)=>{
    if(request.url==='/credential-redirect-target'){targetRequests++;request.resume();response.writeHead(403);response.end();return;}
    if(request.method!=='POST'||request.url!=='/private-relay/v1'||request.headers.origin!==gatewayOrigin||request.headers.authorization!=='Bearer '+browserCapability||request.headers['x-vhalla-namespace']!==namespace){badRequest=true;request.resume();response.writeHead(403);response.end();return;}
    const chunks=[];let bytes=0;
    request.on('data',chunk=>{bytes+=chunk.length;if(bytes>300000){badRequest=true;request.destroy();return;}chunks.push(chunk);});
    request.on('end',()=>{
      const frame=Buffer.concat(chunks);
      if(frame[4]!==1||!frame.includes(message.raw)){badRequest=true;response.writeHead(400);response.end();return;}
      redirects++;response.writeHead(307,{location:gatewayOrigin+'/credential-redirect-target','content-length':0,'cache-control':'no-store'});response.end();
    });
  });
  await new Promise((r,j)=>{hostile.once('error',j);hostile.listen(gatewayPort,'127.0.0.1',r);});
  const report=await sync(page),retained=Buffer.from(await snapshot(page));
  if(redirects!==1||targetRequests!==0||badRequest||!report.includes('Pending: true'))throw Error('HTTPS worker did not refuse the credential redirect with pending work retained');
  chargedPending(before,retained,message.raw);
  await stopServer(hostile);hostile=undefined;await gatewayStart();
  if(await head()!==beforeHead)throw Error('redirect challenge retained an item');
  await backoffWait(retained);await sync(page);
  if(await head()!==beforeHead+1)throw Error('redirect recovery lost or duplicated ciphertext');
  httpsChecks.redirect={status:307,redirectResponses:redirects,targetRequests,capabilityAndNamespaceForwarded:false,chargedPendingPreserved:true,exactRetryRetainedOnce:true};
}
async function connect(page,path,create=false) {
  await setFile(page,'private-delivery-profile',path);
  await evaluate(page,`(async()=>{await qclick('${create?'private-delivery-create':'private-delivery-open'}');await qidle();qassert(qid('private-delivery-profile').value==='','profile capability selection survived');qassert(!qid('private-delivery-sync').disabled,'delivery not ready');return true;})()`);
}
async function sync(page) {return evaluate(page,"(async()=>{await qclick('private-delivery-sync');await qidle();return qid('private-delivery-status').textContent;})()");}
function refusals(report) {const match=report.match(/Refused and skipped records: ([0-9]+)/);if(!match)throw Error('missing delivery refusal count');return Number(match[1]);}
async function sendRetainedPreview(page) {
  return evaluate(page,`(async()=>{
    qassert(qaDraft instanceof Uint8Array,'captured actual disclosure preview');
    const expected=new TextEncoder().encode('VHBRPRIVATE'+String.fromCharCode(7));
    qassert(expected.length===12&&expected.every((v,i)=>qaDraft[i]===v)&&qaDraft[12]===104,'actual private wire version');
    const frame=new Uint8Array(qaDraft.length+16);frame.set(expected);frame[12]=8;
    frame.set(crypto.getRandomValues(new Uint8Array(16)),13);frame.set(qaDraft.subarray(13),29);
    qaProbe='';qaProbeActive=true;qaWorker.postMessage(['private',new Uint8Array(16).fill(254),frame]);
    await qwait(()=>qaProbe!=='','worker verdict for actual retained preview');return qaProbe;
  })()`);
}
// AwaitingWelcome has no browser delivery authority. This synthetic adapter
// transports the already committed encrypted request with its exact public
// outbox metadata; it neither opens a signer nor enables prejoin browser sync.
async function submitRequest(page,downloaded) {
  const raw=Buffer.from(await evaluate(page,"Array.from(qaContactArtifact??[])"));
  const magic=Buffer.from('VHBRPRIVATE\x07');
  if(!raw.subarray(0,12).equals(magic)||raw[12]!==105||raw[165]!==2||raw[166]!==1)throw Error('actual contact request ABI');
  const length=raw.readUInt32BE(167),payload=raw.subarray(171,171+length);
  if(length===0||length>266240||raw.length!==172+length||raw.at(-1)!==0||!payload.equals(downloaded.raw))throw Error('retained request differs from actual worker artifact');
  const sequence=raw.subarray(141,149),operation=raw.subarray(149,165),kind=Buffer.from([1]);
  if(sequence.readBigUInt64BE()===0n)throw Error('zero request sequence');
  const ns=Buffer.from(namespace,'hex'),size=Buffer.alloc(4);size.writeUInt32BE(length);
  const digest=createHash('sha256').update('vhalla/private/relay-item/v1').update(ns).update(sequence).update(operation).update(kind).update(payload).digest();
  const item=Buffer.concat([Buffer.from('VHPRELAY\x01'),ns,sequence,operation,kind,size,payload,digest]);
  const n=++fixtureSerial,path=await privateFile('request-'+n+'.relay',item),receipt=join(output,'request-'+n+'.json');
  await command(cli,['private','relay-submit',path,'--namespace',namespace,'--addr',tlsAddress,'--token',join(output,'relay-token'),'--tls-ca',join(output,'ca.der'),'--tls-name','relay.test','--out',receipt]);
  const retained=JSON.parse(await readFile(receipt,'utf8'));
  if(!Number.isSafeInteger(retained.position)||retained.position<1)throw Error('request retention position');
  return {position:retained.position,digest:digest.toString('hex'),context:raw.subarray(13,141)};
}
async function reviewRequest(owner,member,offer,request) {
  const ownerLocator=await readFile(owner.locator);
  if(ownerLocator.length!==136||ownerLocator.subarray(0,8).toString()!=='VHPLOC1\0')throw Error('owner locator scope');
  const expectedScope=[owner.publicKey,...[8,40,72,104].map(offset=>ownerLocator.subarray(offset,offset+32).toString('hex')),request.context.subarray(96,128).toString('hex')];
  await setFile(owner,'private-resume-offer-file',offer.path);
  await invoke(owner,`async function(recipient,position,digest,context){
    qset('private-recipient',recipient);const select=qid('private-admission-select');
    const option=Array.from(select.options).find(o=>o.textContent.startsWith('mailbox '+position+' ·'));
    qassert(option,'exact relay-retained request listed');qset('private-admission-select',option.value,'change');
    qassert(qid('private-request-file').value==='','request was imported manually');
    await qclick('private-admission-review');await qidle();
    const text=qid('private-admission-consent').textContent;
    qassert(context.every(key=>text.includes(key))&&text.includes(recipient)&&text.includes(digest),'review omits full scope, recipient/device or commitment');
    qassert(text.includes('expires at')&&!qid('private-admission-confirm').disabled,'review lacks expiry or usable confirmation');
    return true;
  }`,[member.publicKey,request.position,request.digest,expectedScope]);
  await evaluate(owner,"qshow('private-admission-consent');true");
  const screenshot=await call('Page.captureScreenshot',{format:'png'},owner.sessionId);
  const name='admission-review-'+request.position+'-'+(++fixtureSerial)+'.png';
  await privateFile(name,Buffer.from(screenshot.data,'base64'));screenshots.push(name);
}
async function staleAdmissionProbe(page) {
  return evaluate(page,`(async()=>{
    const consent=qaAdmission,magic=new TextEncoder().encode('VHBRPRIVATE'+String.fromCharCode(7));
    qassert(consent instanceof Uint8Array&&consent[12]===122&&magic.every((v,i)=>consent[i]===v),'captured actual admission review');
    const frame=new Uint8Array(consent.length+16);frame.set(magic);frame[12]=42;
    frame.set(crypto.getRandomValues(new Uint8Array(16)),13);frame.set(consent.subarray(13),29);
    qaProbe='';qaProbeActive=true;qaWorker.postMessage(['private',new Uint8Array(16).fill(253),frame]);
    await qwait(()=>qaProbe!=='','stale admission worker verdict');return qaProbe;
  })()`);
}
async function head() {
  const n=++fixtureSerial,path=join(output,'scan-'+n+'.json');
  await command(cli,['private','relay-scan',join(output,'scan-'+n),'--namespace',namespace,'--addr',tlsAddress,'--token',join(output,'relay-token'),'--tls-ca',join(output,'ca.der'),'--tls-name','relay.test','--limit','64','--out',path]);
  return JSON.parse(await readFile(path,'utf8')).head;
}
// Read the charged retry deadline from the durable image itself rather than
// assuming the current backoff constant.
async function backoffWait(image) {
  const retry=Number(image.readBigUInt64BE(104));
  if(!retry)throw Error('charged attempt left no backoff deadline');
  const delay=retry*1000-Date.now()+250;
  if(delay>0)await new Promise(r=>setTimeout(r,Math.min(delay,15000)));
}
// An explicit reopen rotates only the owner token (40..56) and refreshes the
// durable monotone wall counter (96..104); every other reserved counter and
// all retained ciphertext must be byte-identical, and the wall never regresses.
function sameRetained(before,after,label) {
  const a=Buffer.from(before),b=Buffer.from(after);
  if(a.length!==b.length||!a.subarray(56,96).equals(b.subarray(56,96))||!a.subarray(104).equals(b.subarray(104))||b.readBigUInt64BE(96)<a.readBigUInt64BE(96))throw Error(label);
}
function chargedPending(before,after,committed,stopCode=0) {
  // Versioned delivery image v3: 8-byte magic, 32-byte binding, 16-byte owner,
  // thirteen u64 counters, stop/detail/blocked bytes, a refused-record ring,
  // retained-admission and deferred indices, optional full control watermark,
  // then canonical pending, staged and pending-control ciphertext.
  // These assertions inspect the exact persisted effect independently of the
  // UI report (the worker is dead).
  if(after.subarray(0,8).toString()!=='VHBRDEL'+String.fromCharCode(3))throw Error('delivery image is not the v3 format');
  if(after[160]!==stopCode||after.readBigUInt64BE(80)!==before.readBigUInt64BE(80)+1n||after.readBigUInt64BE(88)<=before.readBigUInt64BE(88)||after.readBigUInt64BE(112)!==before.readBigUInt64BE(112)+1n||after.readBigUInt64BE(104)<=after.readBigUInt64BE(96))throw Error('credential refusal reset or stopped finite progress');
  let at=164+after[163]*41;at+=1+after[at]*45;
  at+=1+after[at]*46;
  const hasControlFloor=after[at++];if(hasControlFloor>1)throw Error('noncanonical control watermark');if(hasControlFloor)at+=40;
  const length=after.readUInt32BE(at),item=after.subarray(at+4,at+4+length);
  if(length<102||item.subarray(0,9).toString()!=='VHPRELAY'+String.fromCharCode(1)||!item.subarray(70,70+item.readUInt32BE(66)).equals(committed))throw Error('credential refusal lost exact committed ciphertext');
}
async function snapshot(page, expected=1) {
  return evaluate(page,`(async()=>{const names=await indexedDB.databases();let found=[];for(const info of names){const db=await new Promise((r,j)=>{const q=indexedDB.open(info.name);q.onsuccess=()=>r(q.result);q.onerror=()=>j(Error('read database'));});try{if(!db.objectStoreNames.contains('images'))continue;const rows=await new Promise((r,j)=>{const tx=db.transaction('images','readonly'),s=tx.objectStore('images'),q=s.openCursor(),rows=[];q.onsuccess=()=>{const c=q.result;if(c){if(String(c.key).endsWith('delivery-v1'))rows.push([...c.value]);c.continue();}else r(rows);};q.onerror=()=>j(Error('read delivery'));});found.push(...rows);}finally{db.close();}}qassert(found.length===${expected},'expected delivery image count');return found[0]??[];})()`);
}
async function task(abortSignal) {
  signal=abortSignal;
  signal.addEventListener('abort',()=>{for(const waiter of pending.values())waiter.reject(signal.reason);pending.clear();},{once:true});
  await fixture();signal.throwIfAborted();
  if(httpsMode)await httpsGatewayProbes();
  // Crashpad deliberately leaves the browser's process tree. Disable that
  // unrelated reporting service for this isolated synthetic test so the owned
  // guardian can confirm the whole browser group has gone before publishing.
  const chrome=spawnOwned(chromeExecutable,['--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-crashpad-for-testing','--disable-renderer-backgrounding','--disable-background-timer-throttling','--disable-backgrounding-occluded-windows','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,...(chromeHttps?.args??[]),'about:blank'],{role:'chrome'});children.push(chrome);chrome.stdout.resume();chrome.stderr.on('data',c=>chromeLog=(chromeLog+c).slice(-131072));
  await wait(()=>/DevTools listening on (ws:\/\/[^\s]+)/.test(chromeLog)||childStopped(chrome),'Chrome');
  if(childStopped(chrome))throw Error('Chrome exited');
  signal.throwIfAborted();socket=new WebSocket(chromeLog.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]);await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
  socket.onmessage=({data})=>{const m=JSON.parse(data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p?.reject(Error(JSON.stringify(m.error))):p?.resolve(m.result);return;}if(m.method==='Browser.downloadWillBegin'){const p=m.params;downloads.set(p.guid,{guid:p.guid,filename:p.suggestedFilename,state:'begun'});}else if(m.method==='Browser.downloadProgress'){const p=m.params,item=downloads.get(p.guid);if(item)item.state=p.state;}else if(m.method==='Network.requestWillBeSent'){const url=m.params.request.url;if(!url.startsWith(gatewayOrigin+'/')&&!url.startsWith('blob:'+gatewayOrigin+'/')&&url!=='about:blank')unexpectedNetwork=true;}else if(m.method==='Network.loadingFailed'&&m.params.errorText==='net::ERR_CONTENT_LENGTH_MISMATCH'){fatalNetwork='gateway response truncated: '+m.params.errorText;}};
  if(httpsMode)httpsChecks.browser=await call('Browser.getVersion');
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
  const retainedRequest=await submitRequest(member,request);await sync(owner);
  await reviewRequest(owner,member,offer,retainedRequest);
  await evaluate(owner,"(async()=>{await qclick('private-admission-confirm');await qidle();qassert(qid('private-admission-confirm').disabled,'consent remained usable');return true;})()");const response=await download(owner,'private-download-output','vhjoin');
  facts.push('owner reviews exact full room/account/device/expiry and relay-retained request commitment, then explicitly confirms without downloading/reimporting the request; recipient still joins through the existing file flow');
  await setFile(member,'private-join-file',response.path);await evaluate(member,"(async()=>{await qclick('private-join');await qidle();return true;})()");
  await sync(owner);await sync(owner);const checkpoint=await head();if(checkpoint<2)throw Error('join output was not retained before trusted checkpoint');
  member.deliveryProfile=await profileFile(checkpoint);await connect(member,member.deliveryProfile,true);await sync(member);
  facts.push('new member starts at explicit trusted admission checkpoint, excluding undecryptable prejoin history; browser profiles bind that immutable cursor');
  await send(owner,'SYNTHETIC_GATEWAY_TLS_MESSAGE');await sync(owner);await sync(member);
  await evaluate(member,"(async()=>{await qclick('private-inbox');await qidle();qassert(qid('private-inbox-content').textContent.includes('SYNTHETIC_GATEWAY_TLS_MESSAGE'),'network message absent');qassert(!qid('private-inbox-content').textContent.includes('SYNTHETIC_PREJOIN_HISTORY'),'prejoin history leaked');return true;})()");
  await sync(member);await sync(owner);
  await evaluate(owner,"(async()=>{await qclick('private-outbox');await qidle();qassert(/verified device [0-9a-f]{64} claims acceptance at its inbox position [1-9]/.test(qid('private-outbox-acceptances').textContent),'verified device acceptance absent from outbox UI');return true;})()");
  facts.push('production browser worker sends exact ciphertext through '+(httpsMode?'HTTPS':'HTTP')+' gateway and authenticated TLS relay; receiver commits and queues signed acceptance without receipt loops; sender UI exposes the verified device claim without a human-read assertion');
  if(httpsMode)httpsChecks.productionWorkerV2Exchange=true;
  // Admit C while existing member B is offline. The owner must automatically
  // relay the separate encrypted membership control, not only C's invitation.
  // Keep an older committed owner message queued across that membership change
  // after the request-fetch and stale-consent Sync probes below have completed.
  const third=await account('third');
  await invoke(owner,`async function(recipient){qset('private-recipient',recipient);await qclick('private-offer');await qidle();return true;}`,[third.publicKey]);
  const thirdOffer=await download(owner,'private-download-secret','vhoffer');await enter(third);await setFile(third,'private-offer-file',thirdOffer.path);
  await invoke(third,`async function(owner){qset('private-owner',owner);await qclick('private-review-offer');return true;}`,[owner.publicKey]);await retainCreation(third);
  await evaluate(third,"(async()=>{await qclick('private-request');await qidle();return true;})()");const thirdRequest=await download(third,'private-download-output','vhrequest');
  const retainedThird=await submitRequest(third,thirdRequest);await sync(owner);
  await reviewRequest(owner,third,thirdOffer,retainedThird);await sync(owner);
  await evaluate(owner,"qassert(qid('private-admission-confirm').disabled,'Sync left admission confirmation enabled');true");
  if(await staleAdmissionProbe(owner)!=='refused')throw Error('worker reused admission consent after Sync');
  await reload(owner);await connect(owner,owner.deliveryProfile);
  await send(owner,'SYNTHETIC_BEFORE_THIRD_MEMBER');
  await reviewRequest(owner,third,thirdOffer,retainedThird);
  await evaluate(owner,"(async()=>{await qclick('private-admission-confirm');await qidle();return true;})()");const thirdResponse=await download(owner,'private-download-output','vhjoin');
  facts.push('same-roster Sync invalidates actual retained admission consent inside worker custody; explicit reopen and fresh review permit the exact pending device admission');
  await setFile(third,'private-join-file',thirdResponse.path);await evaluate(third,"(async()=>{await qclick('private-join');await qidle();return true;})()");
  await sync(owner);await sync(owner);
  await send(owner,'SYNTHETIC_AFTER_THIRD_MEMBER');await sync(owner);
  await sync(member);
  if(!/Review the current roster/.test(await evaluate(member,"qid('private-status').textContent")))throw Error('existing member did not receive the third-member admission control');
  await sync(member);await sync(member);
  await evaluate(member,"(async()=>{await qclick('private-inbox');await qidle();qassert(qid('private-inbox-content').textContent.includes('SYNTHETIC_BEFORE_THIRD_MEMBER'),'membership control overtook the older committed owner message');qassert(qid('private-inbox-content').textContent.includes('SYNTHETIC_AFTER_THIRD_MEMBER'),'existing member missed new-epoch content after third-member admission');return true;})()");
  const beforeRenewRefused=refusals(await sync(owner));
  facts.push('third device joins confidentially while the existing member is offline; the maintained delivery path preserves the older committed owner message before its encrypted admission control, then accepts new-epoch content without a manual control file');
  // An owner renewal publishes a membership control that advances the epoch.
  // A member ciphertext committed before applying that control is stale: it is
  // durably refused per record, skipped at the mailbox cursor, and delivery
  // continues for the epoch-fresh record behind it.
  await send(member,'SYNTHETIC_PRE_RENEW_STALE');
  await evaluate(owner,"(async()=>{await qclick('private-renew');await qidle();return true;})()");
  // The member's first sync after renewal applies the owner control and stops
  // at the review boundary before publishing its already-staged stale output;
  // the second sync publishes it. This mirrors the model's review assertion.
  await sync(owner);await sync(member);
  if(!/Review the current roster/.test(await evaluate(member,"qid('private-status').textContent")))throw Error('member sync after owner renewal did not stop at the review boundary');
  await sync(member);
  const refusedReport=await sync(owner);
  if(refusals(refusedReport)<=beforeRenewRefused)throw Error('stale member record added no durable refusal: '+refusedReport);
  await send(member,'SYNTHETIC_POST_RENEW');await sync(member);await sync(owner);
  await evaluate(owner,"(async()=>{await qclick('private-inbox');await qidle();qassert(qid('private-inbox-content').textContent.includes('SYNTHETIC_POST_RENEW'),'post-renewal message absent');return true;})()");
  await sync(owner);await sync(member);
  facts.push('owner renewal publishes a control before member sync; the stale-epoch member record is durably refused and skipped at the cursor while the epoch-fresh message behind it still delivers');
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
  sameRetained(before,reopened,'reload changed pending progress/budget');
  await relayStart();await backoffWait(before);await sync(owner);const afterOutage=await head();if(afterOutage!==beforeOutage+1)throw Error('outage retry duplicated or lost committed ciphertext');
  await sync(member);facts.push('relay outage, real document teardown, same-profile reopen and exact retry preserve ciphertext and counters and retain the output once');
  if(httpsMode){httpsChecks.retainedV2Reopen=true;await httpsRedirectProbe(owner);}
  // Authentication refusal ends custody, but a newly supplied host capability
  // may resume the exact charged job. Neither unlock nor corrected authority
  // resets the retained attempt or backoff, and wrong credentials never retain.
  const beforeCapabilityHead=await head();const capabilityMessage=await send(owner,'SYNTHETIC_CAPABILITY_RETRY');
  await reload(owner);const wrongCapability=await profileFile(0,{capability:'54'.repeat(32)});await connect(owner,wrongCapability);
  const beforeDenied=Buffer.from(await snapshot(owner));
  await evaluate(owner,"(async()=>{await qclick('private-delivery-sync');await qwait(()=>qid('identity-state').textContent==='Reload required','wrong capability ends worker');return true;})()");
  const denied=Buffer.from(await snapshot(owner));
  chargedPending(beforeDenied,denied,capabilityMessage.raw);
  if(await head()!==beforeCapabilityHead)throw Error('wrong capability retained an item');
  await reload(owner);await connect(owner,owner.deliveryProfile);
  sameRetained(denied,Buffer.from(await snapshot(owner)),'corrected capability renewed retained budgets or pending work');
  await backoffWait(denied);await sync(owner);
  if(await head()!==beforeCapabilityHead+1)throw Error('corrected capability did not resume exact item once');
  await sync(member);
  facts.push('wrong gateway capability locks the worker without discarding exact pending ciphertext or charged attempts/backoff; explicit reopen with corrected authority resumes once and does not renew lifetime budgets');
  // The same recovery boundary applies when the gateway's selected upstream
  // relay token becomes invalid: its HTTP200 contains canonical STATUS_DENIED.
  const beforeUpstreamHead=await head();const upstreamMessage=await send(owner,'SYNTHETIC_UPSTREAM_AUTH_RETRY');
  await stopChild(gateway);await writeFile(join(output,'gateway-upstream-token'),'55'.repeat(32));await gatewayStart();
  const beforeUpstream=Buffer.from(await snapshot(owner));
  await evaluate(owner,"(async()=>{await qclick('private-delivery-sync');await qwait(()=>qid('identity-state').textContent==='Reload required','upstream denied ends worker');return true;})()");
  const upstreamDenied=Buffer.from(await snapshot(owner));chargedPending(beforeUpstream,upstreamDenied,upstreamMessage.raw);
  if(await head()!==beforeUpstreamHead)throw Error('invalid upstream token retained an item');
  await stopChild(gateway);await writeFile(join(output,'gateway-upstream-token'),relayToken);await gatewayStart();
  await reload(owner);await connect(owner,owner.deliveryProfile);
  sameRetained(upstreamDenied,Buffer.from(await snapshot(owner)),'upstream repair renewed retained budgets or pending work');
  await backoffWait(upstreamDenied);await sync(owner);
  if(await head()!==beforeUpstreamHead+1)throw Error('upstream repair did not resume exact item once');
  await sync(member);
  facts.push('canonical upstream authorization denial locks custody with exact charged progress retained; operator repairs host token and explicit browser reopen resumes once without resetting credits');
  // Profile rebind refuses before any network mutation and leaves durable bytes.
  await reload(owner);const unchanged=Buffer.from(await snapshot(owner));const wrong=await profileFile(1);await setFile(owner,'private-delivery-profile',wrong);
  await evaluate(owner,"(async()=>{await qclick('private-delivery-open');await qwait(()=>qid('identity-state').textContent==='Reload required','changed cursor refusal');return true;})()");
  if(!unchanged.equals(Buffer.from(await snapshot(owner))))throw Error('wrong profile changed progress');await reload(owner);await connect(owner,owner.deliveryProfile);
  facts.push('changed profile initial cursor refuses without replacing retained state; capability is absent from durable delivery bytes');
  // A second same-origin tab claims a fresh CAS owner; the old worker refuses.
  const {targetId}=await call('Target.createTarget',{url:'about:blank',browserContextId:owner.browserContextId});const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});const twin={...owner,targetId,sessionId};
  for(const method of ['Page.enable','Runtime.enable','DOM.enable','Network.enable'])await call(method,{},sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:instrumentation},sessionId);await call('Page.navigate',{url:gatewayOrigin},sessionId);
  await wait(()=>evaluate(twin,"!!document.getElementById('unlock')&&!document.getElementById('unlock').disabled"),'second tab load');await evaluate(twin,helpers);await reopen(twin);await connect(twin,owner.deliveryProfile);
  await evaluate(owner,"(async()=>{await qclick('private-delivery-sync');await qwait(()=>qid('identity-state').textContent==='Reload required','old worker fence');return true;})()");await sync(twin);facts.push('second-tab CAS ownership invalidates the prior worker before another sync; the new worker retains exact existing counters');
  // Terminate the worker while the actual native gateway waits on a TLS
  // handshake. No delayed completion may repopulate its private UI or budgets.
  await send(twin,'SYNTHETIC_LOCKED_IN_FLIGHT');await stopChild(relay);
  signal.throwIfAborted();blackhole=createTcpServer(socket=>{blackholeSockets.add(socket);socket.once('close',()=>blackholeSockets.delete(socket));});
  await new Promise((r,j)=>{blackhole.once('error',j);blackhole.listen(tlsPort,'127.0.0.1',r);});
  await evaluate(twin,"qclick('private-delivery-sync')");await wait(()=>blackholeSockets.size>0,'gateway pending actual TLS handshake');
  await leave(twin);const canceled=Buffer.from(await snapshot(twin));
  for(const socket of blackholeSockets)socket.destroy();await new Promise(r=>blackhole.close(r));blackhole=undefined;
  await relayStart();await backoffWait(canceled);
  await evaluate(twin,"qassert(qid('private-delivery-status').textContent==='','late response repopulated locked private UI');true");
  if(!canceled.equals(Buffer.from(await snapshot(twin))))throw Error('late canceled response changed durable progress');
  await reopen(twin);await connect(twin,owner.deliveryProfile);await sync(twin);
  facts.push('lock during a real gateway TLS handshake terminates worker Fetch; delayed failure cannot restore UI or alter charged progress, and explicit reopen resumes exact queued ciphertext');
  // A hostile HTTP200 receipt with the wrong commitment is not a transient
  // outage or an authorization renewal. Persist the stop before ending custody.
  const hostileHead=await head();const hostileMessage=await send(twin,'SYNTHETIC_CORRUPT_RECEIPT');
  const beforeHostile=Buffer.from(await snapshot(twin));await stopChild(gateway);
  signal.throwIfAborted();hostile=fixtureHttpServer((request,response)=>{
    if(request.method!=='POST'||request.url!=='/private-relay/v1'||request.headers.origin!==gatewayOrigin||request.headers.authorization!=='Bearer '+browserCapability){response.writeHead(403);response.end();return;}
    const chunks=[];let size=0;request.on('data',chunk=>{size+=chunk.length;if(size>300000){request.destroy();return;}chunks.push(chunk);});
    request.on('end',()=>{const body=Buffer.concat(chunks);if(body.length<40||body[4]!==1){response.writeHead(400);response.end();return;}const receipt=Buffer.alloc(46);receipt.writeUInt32BE(42,0);receipt.writeBigUInt64BE(1n,5);body.subarray(-32).copy(receipt,13);receipt[13]^=1;response.writeHead(200,{'content-type':'application/octet-stream','content-length':receipt.length,'cache-control':'no-store'});response.end(receipt);});
  });await new Promise((r,j)=>{hostile.once('error',j);hostile.listen(gatewayPort,'127.0.0.1',r);});
  await evaluate(twin,"(async()=>{await qclick('private-delivery-sync');await qwait(()=>qid('identity-state').textContent==='Reload required','corrupt receipt ends worker');return true;})()");
  const halted=Buffer.from(await snapshot(twin));chargedPending(beforeHostile,halted,hostileMessage.raw,2);
  await stopServer(hostile);hostile=undefined;await gatewayStart();
  await reload(twin);await setFile(twin,'private-delivery-profile',owner.deliveryProfile);
  // Reopening the durably stopped delivery reports stop in the status banner;
  // the generic idle assertion cannot be used here because that refusal is the
  // expected outcome being verified.
  await evaluate(twin,"(async()=>{await qclick('private-delivery-open');await qwait(()=>!qid('private-refresh').disabled,'stopped reopen idle');qassert(qid('private-delivery-sync').disabled&&qid('private-delivery-status').textContent.includes('stopped: true'),'durable refusal lost on reopen');qid('private-delivery-sync').disabled=false;qid('private-delivery-sync').click();await qwait(()=>!qid('private-refresh').disabled,'forced stopped sync finished');return true;})()");
  sameRetained(halted,Buffer.from(await snapshot(twin)),'reopen or forced Sync reset durable hostile-response stop');
  if(await head()!==hostileHead)throw Error('reopen or forced Sync reset durable hostile-response stop');
  facts.push('a well-framed HTTP200 receipt with a corrupt commitment durably stops before worker termination; exact pending bytes and charged credits survive, and reopen or forced Sync cannot resume network work');
  await leave(twin);await leave(member);
  if(unexpectedNetwork)throw Error('unexpected page route outside selected gateway origin');
  const digest=v=>createHash('sha256').update(v).digest('hex');
  return {passed:true,artifact,artifactManifestSha256:digest(manifestRaw),gatewayOrigin,tlsAddress,namespaceSha256:digest(namespace),relayTokenSha256:digest(relayToken),browserCapabilitySha256:digest(browserCapability),facts,files,screenshots,profile,...(httpsMode?{https: httpsChecks}:{}),scope:'production browser private custody → maintained '+(httpsMode?'direct HTTPS gateway at synthetic DNS origin':'local HTTP gateway')+' → real TLS relay; synthetic same-machine identities; no public certificate, hosted deployment, independent-machine or Tailcat path claim'};
}
await runQualification({
  work:task, timeoutMs:360000,
  parentInput:options['--parent-stdin']?process.stdin:undefined,
  cleanup:async()=>{
    let receipt;
    try{
      for(const socket of blackholeSockets)socket.destroy();
      receipt=await cleanupOwned({children,servers:[blackhole,hostile],socket,pending});
      return receipt;
    }catch(error){receipt=error.cleanupReceipt;throw error;}
    finally{
      await writeFile(join(output,'cleanup.json'),JSON.stringify(receipt??{passed:false,error:'cleanup evidence unavailable'},null,2)+'\n');
      await writeFile(join(output,'chrome.log'),chromeLog);
      await writeFile(join(output,'services.json'),JSON.stringify(serviceLogs,null,2));
      await writeFile(join(output,'network-failure.txt'),fatalNetwork);
    }
  },
  onFailure:async({error,cleanup})=>{
    await writeFile(join(output,'receipt.json'),JSON.stringify({passed:false,failure:error.message,cleanup,...(httpsMode?{gatewayOrigin,https:httpsChecks}:{})},null,2)+'\n');
  },
  publish:async(receipt,cleanup)=>{
    receipt.cleanup=cleanup;
    await writeFile(join(output,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');
    console.log(JSON.stringify(receipt));
  },
});
