// Complete synthetic author recovery across two loopback origins. No user files.
// Downloads stay as encrypted bytes in the test driver's memory; never logged.
import {closeTargetChecked} from './qualification_lifecycle.mjs';
const helpers = `
window.qid=id=>document.getElementById(id);
window.qassert=(v,m)=>{if(!v)throw Error(m)};
window.qwait=async(f,m)=>{const t=Date.now()+45000;while(!f()){if(Date.now()>t)throw Error(m+' status='+qid('status').textContent+' activity='+qid('activity-status').textContent+' recovery='+qid('author-state-status').textContent);await new Promise(r=>setTimeout(r,20));}};
window.qset=(id,v,event='input')=>{qid(id).value=v;qid(id).dispatchEvent(new Event(event,{bubbles:true}));};
window.qclick=async id=>{await qwait(()=>!qid(id).disabled,id+' enabled');qid(id).click();};
window.qfile=(id,b64,name)=>{const dt=new DataTransfer();dt.items.add(new File([Uint8Array.from(atob(b64),c=>c.charCodeAt(0))],name));qid(id).files=dt.files;qid(id).dispatchEvent(new Event('change',{bubbles:true}));};
window.qidle=()=>qwait(()=>!qid('show-outbox').disabled,'network idle');
window.qinstrument=()=>{window.qwrites=[];for(const name of ['add','put','delete']){const original=IDBObjectStore.prototype[name];IDBObjectStore.prototype[name]=function(...args){qwrites.push({name,key:String(name==='delete'?args[0]:args[1])});return original.apply(this,args);};}};
`;

export async function qualifyRecovery({call, targetId, sessionId, bootstrap, pin, ads, password, author, rooms, postCount}) {
  const evaluateIn = async (session, expression) => {
    const result = await call('Runtime.evaluate', {expression, awaitPromise:true, returnByValue:true}, session);
    if(result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  let active = sessionId;
  const evaluate = expression => evaluateIn(active, expression);
  const ready = async () => {
    for(let i=0;i<600;i++) {
      if(await evaluate("!globalThis.__recoveryNavigation && !!document.getElementById('restore') && !document.getElementById('restore').disabled")) return;
      await new Promise(resolve=>setTimeout(resolve,50));
    }
    throw Error('recovery page did not initialize');
  };
  await evaluate(helpers + `(async()=>{
    qset('activity-text','SYNTHETIC_BACKUP_PENDING_FOUR');
    const add=IDBObjectStore.prototype.add;let fired=false;
    IDBObjectStore.prototype.add=function(value,key){if(!fired&&String(key).includes('/outbox/')){fired=true;throw new DOMException('synthetic backup pending draft','QuotaExceededError');}return add.apply(this,arguments);};
    await qclick('queue-activity');await qwait(()=>fired&&qid('activity-status').textContent.includes('Reload'),'reserve fourth post');
  })()`);
  await evaluate('globalThis.__recoveryNavigation=true');
  await call('Page.reload',{},active);await ready();
  await evaluate(helpers + `window.qa=${JSON.stringify({password,rooms})};(async()=>{
    qset('password',qa.password);await qclick('unlock');await qwait(()=>qid('identity-state').textContent==='Unlocked','source unlock');
    await qwait(()=>qid('activity-room').options.length===2&&!qid('activity-room').disabled,'source room');qset('activity-room',qa.rooms[1].id,'change');
    window.qdownloads=[];const click=HTMLAnchorElement.prototype.click;
    const blobs=new Map(),create=URL.createObjectURL.bind(URL);
    URL.createObjectURL=blob=>{const url=create(blob);blobs.set(url,blob);return url;};
    HTMLAnchorElement.prototype.click=function(){
      if(this.download&&this.href.startsWith('blob:')){
        const name=this.download;
        qdownloads.push(blobs.get(this.href).arrayBuffer().then(raw=>{
          const bytes=new Uint8Array(raw);let binary='';for(let i=0;i<bytes.length;i+=4096)binary+=String.fromCharCode(...bytes.subarray(i,i+4096));
          return {name,base64:btoa(binary),bytes:bytes.length};
        }));return;
      }return click.apply(this,arguments);
    };
    await qclick('backup');
    for(let i=0;i<16;i++){
      await qclick('export-author-state');await qidle();
      const status=qid('author-state-status').textContent;
      qassert(/(?:Final )?Part|Final part/.test(status),'author export failed');
      if(status.startsWith('Final part'))return;
      if(qdownloads.length%7===0)await new Promise(r=>setTimeout(r,11000));
    }throw Error('bounded author export did not finish');
  })()`);
  const downloads = await evaluate('Promise.all(qdownloads)');
  const key = downloads.find(file=>file.name.endsWith('.vhkey'));
  const parts = downloads.filter(file=>file.name.endsWith('.vhauthor')).sort((a,b)=>a.name.localeCompare(b.name));
  if(!key || parts.length<2 || downloads.length!==parts.length+1)throw Error('complete synthetic encrypted exports missing');
  await evaluate("(async()=>{await qclick('lock');await qwait(()=>qid('identity-state').textContent==='Locked','source lock and replacement-worker readiness');})()");
  await closeTargetChecked(call,targetId); // Stop the former writer before any recovered signing.

  const next = await call('Target.createTarget',{url:'about:blank'});
  active = (await call('Target.attachToTarget',{targetId:next.targetId,flatten:true})).sessionId;
  await call('Page.enable',{},active);await call('Runtime.enable',{},active);
  await call('Page.navigate',{url:'http://localhost:8790'},active);await ready();
  await evaluate(helpers + `window.qa=${JSON.stringify({password,author,rooms,bootstrap,pin,ads,key,parts})};(async()=>{
    qassert(location.origin==='http://localhost:8790','wrong recovery origin');
    qset('password',qa.password);qfile('restore-file',qa.key.base64,qa.key.name);await qclick('restore');
    await qwait(()=>qid('identity-state').textContent==='Unlocked','restored key');qassert(qid('public-key').textContent===qa.author,'restored wrong author');
    qfile('network-file',qa.bootstrap,'synthetic.vhbootstrap');qset('network-pin',qa.pin);await qclick('join-network');await qwait(()=>!qid('add-peer').disabled,'restored network');
    qfile('peer-file',qa.ads[0],'synthetic-a.vhad');await qclick('add-peer');await qwait(()=>!qid('sync-network').disabled,'restored peer');await qclick('sync-network');
    await qwait(()=>qid('activity-room').options.length===2&&!qid('activity-room').disabled,'restored directory');
    qset('activity-room',qa.rooms[1].id,'change');qset('activity-text','KEY_ONLY_MUST_NOT_SIGN');qinstrument();
    await qclick('queue-activity');await qidle();qassert(qwrites.length===0,'key-only import reset author state');qassert(/restored identity|creation proof|read-only|recover/.test(qid('activity-status').textContent),'key-only authoring not refused');
    qset('activity-room',qa.rooms[0].id,'change');qfile('import-author-file',qa.parts[0].base64,qa.parts[0].name);await qclick('import-author-state');await qidle();
    qassert(qwrites.length===0,'wrong-room backup wrote state');qassert(/does not match|different|not match/.test(qid('author-state-status').textContent),'wrong-room backup not refused');
    qset('activity-room',qa.rooms[1].id,'change');const final=qa.parts.at(-1);qfile('import-author-file',final.base64,final.name);await qclick('import-author-state');await qidle();
    qassert(qwrites.length===0,'final-first backup wrote state');
    qfile('import-author-file',qa.parts[0].base64,qa.parts[0].name);await qclick('import-author-state');await qidle();
    qassert(qid('author-state-status').textContent.includes('Part retained safely'),'first part not retained');
    qwrites.length=0;qset('activity-text','PARTIAL_MUST_NOT_SIGN');await qclick('queue-activity');await qidle();qassert(qwrites.length===0,'partial restore authorized signing');
  })()`);
  // A new page/worker must recover staged import and continue the exact backup.
  await evaluate('globalThis.__recoveryNavigation=true');
  await call('Page.reload',{},active);await ready();
  await evaluate(helpers + `window.qa=${JSON.stringify({password,author,rooms,ads,parts})};(async()=>{
    qset('password',qa.password);await qclick('unlock');await qwait(()=>qid('identity-state').textContent==='Unlocked','restore reload unlock');
    await qwait(()=>qid('activity-room').options.length===2&&!qid('activity-room').disabled,'restore reload directory');qset('activity-room',qa.rooms[1].id,'change');
    for(let i=1;i<qa.parts.length;i++){const part=qa.parts[i];qfile('import-author-file',part.base64,part.name);await qclick('import-author-state');await qidle();}
    for(let i=0;i<16&&!qid('author-state-status').textContent.includes('Author state restored');i++){const final=qa.parts.at(-1);qfile('import-author-file',final.base64,final.name);await qclick('import-author-state');await qidle();}
    qassert(qid('author-state-status').textContent.includes('Author state restored through local sequence 3'),'restore did not activate exact sequence');
    await qclick('show-outbox');await qidle();qassert(qid('activity-list').children.length===3,'restored outbox missing records');
    qfile('peer-file',qa.ads[1],'synthetic-b.vhad');await qclick('add-peer');await qidle();
    await qclick('send-activity');await qidle();qassert((qid('activity-status').textContent.match(/already acknowledged through post 3/g)||[]).length===2,'restored peer receipts missing');
  })()`);
  const before = postCount();
  if(before!==6)throw Error('restored receipts unexpectedly retransmitted history: '+before);
  await evaluate(`(async()=>{
    qset('activity-text','UNRELATED_RESTORED_COMPOSER');await qclick('resume-activity');await qidle();
    qassert(qid('activity-status').textContent.includes('Post 4 saved'),'restored pending draft not resumed');qassert(qid('activity-text').value==='UNRELATED_RESTORED_COMPOSER','restore resume lost unrelated text');
    await qclick('send-activity');await qidle();qassert((qid('activity-status').textContent.match(/acknowledged through post 4/g)||[]).length===2,'recovered post not delivered');
    await qclick('read-activity');await qidle();qassert(qid('activity-list').children.length===4,'recovered peer history incomplete');qassert(qid('activity-list').textContent.includes('SYNTHETIC_BACKUP_PENDING_FOUR'),'restored pending bytes changed');
  })()`);
  if(postCount()!==8)throw Error('recovered send was not exactly one new post per peer');
  await evaluate('globalThis.__recoveryNavigation=true');
  await call('Page.reload',{},active);await ready();
  await evaluate(helpers+`window.qa=${JSON.stringify({password,rooms})};(async()=>{
    qset('password',qa.password);await qclick('unlock');await qwait(()=>qid('identity-state').textContent==='Unlocked','final reopen');
    await qwait(()=>qid('activity-room').options.length===2&&!qid('activity-room').disabled,'final directory');qset('activity-room',qa.rooms[1].id,'change');
    await qclick('show-outbox');await qidle();qassert(qid('activity-list').children.length===4,'fourth post lost after reopen');
    await qclick('send-activity');await qidle();qassert((qid('activity-status').textContent.match(/already acknowledged through post 4/g)||[]).length===2,'fourth receipts lost after reopen');
  })()`);
  if(postCount()!==8)throw Error('final reopen retransmitted confirmed posts');
  await closeTargetChecked(call,next.targetId);
  return {passed:true,sourceOrigin:'http://127.0.0.1:8790',recoveryOrigin:'http://localhost:8790',encryptedParts:parts.length,
    finalSequence:4,activityPosts:postCount(),keyOnlyRefused:true,wrongRoomRefused:true,finalFirstRefused:true,
    partialRestoreReadOnly:true,stagedRestart:true,pendingExactRetry:true,peerReceiptsPreserved:true,formerWriterClosed:true};
}
