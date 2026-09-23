// Static-site responsive/CSP/navigation smoke, isolated browser only.
import {trackChild, cleanupOwned, runQualification} from '../../browser/tools/qualification_lifecycle.mjs';
import {qualifyAppearance} from './qualify_appearance.mjs';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdir,mkdtemp,readdir} from 'node:fs/promises';
import {resolve,join,sep} from 'node:path';
const [rootArg,chromePath,outArg,headersArg,mode]=process.argv.slice(2), root=resolve(rootArg),out=resolve(outArg);
if(mode!==undefined&&mode!=='--appearance-only')throw Error('unknown qualification mode');
await mkdir(out,{recursive:false});const profile=await mkdtemp(join(out,'profile-'));
const headers=JSON.parse(await readFile(headersArg,'utf8')).headers[0].headers;
const server=createServer(async(req,res)=>{try{let path=decodeURIComponent(new URL(req.url,'http://127.0.0.1').pathname);if(path.endsWith('/'))path+='index.html';const f=resolve(root,'.'+path);if(!f.startsWith(root+sep))throw Error('nonlocal');for(const h of headers)res.setHeader(h.key,h.value);res.setHeader('Content-Type',f.endsWith('.html')?'text/html':f.endsWith('.css')?'text/css':f.endsWith('.js')?'text/javascript':f.endsWith('.png')?'image/png':f.endsWith('.svg')?'image/svg+xml':f.endsWith('.woff2')?'font/woff2':'application/octet-stream');res.end(await readFile(f));}catch{res.writeHead(404);res.end();}});
await new Promise((r,j)=>{server.once('error',j);server.listen(0,'127.0.0.1',r);});
let log='',socket,seq=0;const pending=new Map();
const chrome=trackChild(spawn(chromePath,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-extensions','--disable-sync','--metrics-recording-only','--no-proxy-server','--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']}));
const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
async function work(){
 const ws=await new Promise((r,j)=>{chrome.once('error',j);chrome.once('exit',c=>j(Error('Chrome exit '+c)));chrome.stderr.on('data',c=>{log+=c;const m=log.match(/DevTools listening on (ws:\/\/\S+)/);if(m)r(m[1]);});});
 socket=new WebSocket(ws);await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j;});
 const errors=[];
 socket.onmessage=({data})=>{const v=JSON.parse(data);if(v.id){const p=pending.get(v.id);pending.delete(v.id);v.error?p?.reject(Error(JSON.stringify(v.error))):p?.resolve(v.result);}else if(v.method==='Runtime.exceptionThrown'||v.method==='Log.entryAdded'&&v.params.entry.level==='error'){errors.push(v.params);}};
 const {targetId}=await call('Target.createTarget',{url:'about:blank'}),{sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
 await call('Page.enable',{},sessionId);await call('Runtime.enable',{},sessionId);await call('Log.enable',{},sessionId);
 await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-color-scheme',value:'light'}]},sessionId);
 const evaluate=async expression=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
 const base='http://127.0.0.1:'+server.address().port;
 async function navigate(path,width,height){await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600},sessionId);await call('Page.navigate',{url:base+path},sessionId);let ready=false;for(let i=0;i<200;i++){if(await evaluate("location.pathname==="+JSON.stringify(path)+" && document.readyState==='complete' && !!document.querySelector('main')")){ready=true;break;}await new Promise(r=>setTimeout(r,25));}if(!ready)throw Error('navigation did not finish '+path);await evaluate('document.fonts.ready.then(()=>true)');}
 async function shot(name){const {data}=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:false},sessionId);await writeFile(join(out,name+'.png'),Buffer.from(data,'base64'));}
 const appearance=await qualifyAppearance({call,evaluate,navigate,sessionId});
 if(mode==='--appearance-only'){
  if(errors.length)throw Error('browser console/CSP failures '+JSON.stringify(errors));
  return {passed:true,appearance,consoleErrors:errors,root,profile};
 }
 const results=[];
 const paths=['/'];
 const walk=async dir=>{for(const e of await readdir(join(root,dir),{withFileTypes:true})){
  if(!e.isDirectory()||e.name==='design')continue;
  const sub=dir?dir+'/'+e.name:e.name;
  try{await readFile(join(root,sub,'index.html'));paths.push('/'+sub+'/');}catch{}
  await walk(sub);}};
 await walk('');
 for(const path of paths){
  await navigate(path,1365,950);
  const state=await evaluate(`({path:location.pathname,title:document.title,canonical:document.querySelector('link[rel=canonical]')?.href,main:document.querySelectorAll('main').length,h1:document.querySelectorAll('h1').length,width:innerWidth,scroll:document.documentElement.scrollWidth,images:Array.from(document.images).every(i=>i.complete&&i.naturalWidth>0),missingAnchors:Array.from(document.querySelectorAll('a[href^="#"]')).map(a=>a.getAttribute('href').slice(1)).filter(id=>id&&!document.getElementById(id)),links:Array.from(document.querySelectorAll('a[href^="/"]')).map(a=>a.getAttribute('href'))})`);
  if(state.main!==1||state.h1!==1||state.scroll>state.width||!state.images||state.missingAnchors.length)throw Error(JSON.stringify(state));
  for(const link of state.links){const url=new URL(link,base);const response=await fetch(url);if(response.status!==200)throw Error('broken internal link '+link);}
  results.push(state);
  if(path==='/'||path==='/docs/status/'||path==='/docs/security/'||path==='/docs/private-rooms/')await shot(path==='/'?'home-desktop':path.split('/')[2]+'-desktop');
  if(path==='/'){const {cssContentSize}=await call('Page.getLayoutMetrics',{},sessionId);const {data}=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true,clip:{x:0,y:0,width:cssContentSize.width,height:cssContentSize.height,scale:1}},sessionId);await writeFile(join(out,'home-full.png'),Buffer.from(data,'base64'));}
 }
 for(const width of [390,320,768,1024]){
  for(const path of ['/','/docs/status/','/docs/public-rooms/','/docs/private-rooms/','/compare/moltbook/','/writing/agent-swarms/','/use-cases/']){
   await navigate(path,width,844);
   const state=await evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth})');if(state.scroll>state.width)throw Error('mobile overflow '+path+' '+JSON.stringify(state));
   if(path!=='/'){
    const menu=await evaluate(`(()=>{const d=document.querySelector('.mobile-doc-nav');d.open=true;const ok=d.querySelectorAll('a').length>=4;d.open=false;return ok;})()`);if(!menu)throw Error('missing mobile documentation navigation '+path);
   }
   if(width===390)await shot(path==='/'?'home-mobile':path.split('/').filter(Boolean).pop()+'-mobile');
  }
 }
 await navigate('/',1365,950);
 await call('Page.bringToFront',{},sessionId);await call('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9},sessionId);await call('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9},sessionId);
 const keyboard=await evaluate("document.activeElement.classList.contains('skip-link')");if(!keyboard)throw Error('keyboard skip link not first focus');
 const light=await evaluate(`(()=>{const trigger=document.querySelector('[data-hraness-appearance-menu] button');trigger.click();const choice=document.querySelector('[data-theme-value="light"]');choice.click();return {checked:choice.getAttribute('aria-checked'),color:getComputedStyle(document.documentElement).color};})()`);if(light.checked!=='true')throw Error('light appearance failed');
 const dark=await evaluate(`(()=>{const trigger=document.querySelector('[data-hraness-appearance-menu] button');trigger.click();const choice=document.querySelector('[data-theme-value="dark"]');choice.click();return {ready:document.querySelector('[data-hraness-appearance-menu]').dataset.ready,checked:choice.getAttribute('aria-checked'),background:getComputedStyle(document.body).backgroundColor};})()`);
 if(dark.ready!=='true'||dark.checked!=='true')throw Error('appearance control failed '+JSON.stringify(dark));await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');await shot('home-dark');
 await call('Emulation.setScriptExecutionDisabled',{value:true},sessionId);await navigate('/docs/public-rooms/',390,844);const noScript=await evaluate("document.querySelector('main').textContent.includes('peer-add') && document.querySelectorAll('.mobile-doc-nav a').length >= 9");if(!noScript)throw Error('docs missing without JavaScript');
 if(errors.length)throw Error('browser console/CSP failures '+JSON.stringify(errors));
 return {passed:true,pages:results,viewports:[1365,1024,768,390,320],light,dark,noScript,keyboard,appearance,consoleErrors:errors,root,profile};
}
await runQualification({
  work, timeoutMs: 150000,
  cleanup: async () => {
    try { await cleanupOwned({children:[chrome], server, socket, pending}); }
    finally { await writeFile(join(out,'chrome.log'),log); }
  },
  publish: async receipt => {
    await writeFile(join(out,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');
    console.log(JSON.stringify(receipt));
  },
});
