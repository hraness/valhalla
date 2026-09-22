// Production DOM/worker recovery paths over synthetic accounts and real IndexedDB.
// The streaming picker is injected with a real OPFS FileSystemFileHandle; this
// qualifies the writable-stream path, not the operating system's picker UI.
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';

export async function qualifyArchives({owner,fresh,output,evaluate,invoke,setFile,download,send,leave,reopen,restartArchive,facts}) {
  const database = raw => 'vhalla-browser-storage-v1-'+createHash('sha256')
    .update('vhalla/browser-private-archive-destination/v1\0').update(raw.subarray(8,168)).digest('hex');
  const legacy = 'vhalla-browser-storage-v1-'+Buffer.from('vhalla-browser-local-archive-v01').toString('hex');
  const catalog = 'vhalla-browser-storage-v1-'+createHash('sha256').update('vhalla/browser-private-archive-catalog/v1\0').digest('hex');
  const enter = async()=>{
    if(await evaluate(fresh,"qid('unlock').disabled")){await restartArchive(fresh);return;}
    await evaluate(fresh,"(async()=>{qset('password',qpassword);await qclick('unlock');await qwait(()=>qid('identity-state').textContent==='Unlocked','archive unlock');await qclick('private-enter');await qwait(()=>!qid('private-import-archive').disabled,'archive selection');return true;})()");
  };
  const close = async()=>evaluate(fresh,"(async()=>{await qclick('private-archive-close');await qwait(()=>!qid('private-import-archive').disabled,'archive closed');return true;})()");
  const importFile = async archive=>{
    await setFile(fresh,'private-archive-file',archive.path);
    await evaluate(fresh,"(async()=>{await qclick('private-import-archive');await qwait(()=>!qid('private-archive').hidden&&!qid('private-archive-close').disabled,'archive completed');qassert(qid('private-status').dataset.error!=='true','archive import refused');return true;})()");
  };
  const inspect = async(archive,useLegacy=false)=>{
    await setFile(fresh,'private-archive-file',archive.path);
    await invoke(fresh,`async function(legacy){qid('private-archive-legacy').checked=legacy;await qclick('private-open-archive');await qwait(()=>!qid('private-archive').hidden&&!qid('private-archive-close').disabled,'exact archive opened');qassert(qid('private-status').dataset.error!=='true','archive open refused');await qclick('private-archive-outbox');await qwait(()=>!qid('private-archive-close').disabled,'archive records');return true;}`,[useLegacy]);
    const count=await evaluate(fresh,"(()=>{qassert(qid('private-archive-outbox-select').options.length>0,'archive records absent');return Number(qid('private-archive-summary').textContent.match(/Source revision (\\d+)/)[1]);})()");
    await close();await evaluate(fresh,"qid('private-archive-legacy').checked=false;true");return count;
  };
  const snapshot=async()=>invoke(fresh,`async function(names){
    const existing=new Set((await indexedDB.databases()).map(d=>d.name));const out={};
    for(const name of names){if(!existing.has(name)){out[name]=null;continue;}
      out[name]=await new Promise((resolve,reject)=>{const request=indexedDB.open(name);request.onerror=()=>reject(Error('snapshot open'));request.onsuccess=()=>{const db=request.result,tx=db.transaction('images','readonly'),store=tx.objectStore('images'),keys=store.getAllKeys(),values=store.getAll();tx.oncomplete=async()=>{db.close();const raw=JSON.stringify(keys.result.map((key,i)=>[key,Array.from(values.result[i])]));resolve(Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw)))));};tx.onabort=()=>{db.close();reject(Error('snapshot read'));};};});
    }return JSON.stringify(out);
  }`,[await evaluate(fresh,"(async()=> (await indexedDB.databases()).map(d=>d.name).filter(name=>name!=='vhalla-browser-storage-v1-'+Array.from(new TextEncoder().encode('vhalla-browser-local-profile-v01'),x=>x.toString(16).padStart(2,'0')).join('')).sort())()")]);
  const rejectFile=async(path)=>{
    await setFile(fresh,'private-archive-file',path);
    await evaluate(fresh,"(async()=>{await qclick('private-import-archive');await qwait(()=>qid('private-workspace').hidden&&qid('identity-state').textContent!=='Private custody','archive refusal closes worker');qassert(qid('private-archive-file').value==='','refused file survived lock');return true;})()");
  };
  const rejectOpen=async(archive,useLegacy=false)=>{
    await setFile(fresh,'private-archive-file',archive.path);
    await invoke(fresh,`async function(legacy){qid('private-archive-legacy').checked=legacy;await qclick('private-open-archive');await qwait(()=>qid('private-workspace').hidden&&qid('identity-state').textContent!=='Private custody','missing archive refusal closes worker');qassert(qid('private-archive-file').value==='','refused file survived lock');return true;}`,[useLegacy]);
  };

  const a=await download(owner,'private-export-archive','vharchive');
  await send(owner,'SYNTHETIC_NEWER_ARCHIVE_REVISION');
  const b=await download(owner,'private-export-archive','vharchive');
  await leave(fresh);await enter();
  // Valid seals authorize reading only retained custody. Neither the new route
  // nor explicit legacy selection may leave an empty database when absent.
  for(const useLegacy of [false,true]){
    const before=await snapshot();await rejectOpen(a,useLegacy);
    if(await snapshot()!==before)throw Error('read-only open created missing archive storage');
    await enter();
  }
  // A substituted context/ID must not reach either the catalog or destination.
  for(const offset of [8,136]){
    const before=await snapshot();
    const changed=Buffer.from(a.raw);changed[offset]^=1;
    const path=join(output,'archive-substitution-'+offset+'.vharchive');await writeFile(path,changed,{mode:0o600});
    await rejectFile(path);
    if(await snapshot()!==before)throw Error('substituted source changed archive storage');
    await enter();
  }
  const malformed=join(output,'archive-with-trailing-byte.vharchive');
  await writeFile(malformed,Buffer.concat([a.raw,Buffer.from([1])]),{mode:0o600});
  await rejectFile(malformed);
  const aDb=database(a.raw),bDb=database(b.raw);
  const retained=await invoke(fresh,`async function(name){return await new Promise((resolve,reject)=>{const r=indexedDB.open(name);r.onerror=()=>reject(Error('retained import'));r.onsuccess=()=>{const db=r.result,tx=db.transaction('images','readonly'),count=tx.objectStore('images').count();tx.oncomplete=()=>{db.close();resolve(count.result)};};});}`,[aDb]);
  if(retained<=2)throw Error('no durable cursor before malformed-tail refusal');
  await enter();await importFile(a);await close();
  const aCount=await inspect(a);
  // Seed only the fresh synthetic context's legacy fixture from exact archived
  // ciphertext. This is harness setup; production has no copy/migration API.
  await invoke(fresh,`async function(source,destination){
    const values=await new Promise((resolve,reject)=>{const r=indexedDB.open(source);r.onerror=()=>reject(Error('fixture source'));r.onsuccess=()=>{const db=r.result,tx=db.transaction('images','readonly'),keys=tx.objectStore('images').getAllKeys(),values=tx.objectStore('images').getAll();tx.oncomplete=()=>{db.close();resolve(keys.result.map((key,i)=>[key,values.result[i]]))};};});
    await new Promise((resolve,reject)=>{const r=indexedDB.open(destination,1);r.onupgradeneeded=()=>r.result.createObjectStore('images');r.onerror=()=>reject(Error('legacy fixture open'));r.onsuccess=()=>{const db=r.result,tx=db.transaction('images','readwrite',{durability:'strict'}),store=tx.objectStore('images');for(const [key,value]of values)store.add(value,key);tx.oncomplete=()=>{db.close();resolve()};tx.onabort=()=>{db.close();reject(Error('legacy fixture conflict'))};};});return true;
  }`,[aDb,legacy]);
  if(await inspect(a,true)!==aCount)throw Error('legacy snapshot changed');
  await importFile(b);await close();
  const bCount=await inspect(b);
  if(bCount<=aCount || await inspect(a)!==aCount || await inspect(a,true)!==aCount)throw Error('snapshots did not coexist');
  facts.push('Production archive routes authenticate full source before catalog/destination access; malformed context/ID create no database; interrupted A resumes; newer B coexists and explicit legacy A stays readable');

  // Fill the remaining two global reservations, then refuse a fifth before its
  // destination database exists. All previous ciphertext is byte-identical.
  for(let index=0;index<3;index++){
    const next=await download(owner,'private-export-archive','vharchive');
    if(index<2){await importFile(next);await close();}
    else {
      const before=await snapshot();await rejectFile(next.path);
      if(await snapshot()!==before)throw Error('catalog quota changed prior archive bytes');
      const exists=await invoke(fresh,`async function(name){return (await indexedDB.databases()).some(db=>db.name===name)}`,[database(next.raw)]);
      if(exists)throw Error('quota refusal created a destination');
      await enter();
      const beforeOpen=await snapshot();await rejectOpen(next);
      if(await snapshot()!==beforeOpen)throw Error('read-only open bypassed archive reservation quota');
      await enter();
    }
  }
  if(await inspect(a)!==aCount || await inspect(b)!==bCount || await inspect(a,true)!==aCount)throw Error('quota broke retained snapshots');
  facts.push('Four durable origin-wide reservations enforce a global cap before destination creation; quota refusal and read-only opens of missing new/legacy snapshots preserve the database set, exact prior snapshots and legacy data');

  // Real FileSystemWritableFileStream via an OPFS handle. The app only sees the
  // ordinary picker result, and writes bounded pages without a Blob download.
  await evaluate(owner,`(async()=>{window.qaFile=await(await navigator.storage.getDirectory()).getFileHandle('synthetic-archive',{create:true});window.qaWrites=[];window.qaAborts=0;window.qaCloses=0;window.showSaveFilePicker=async()=>({createWritable:async()=>{const stream=await qaFile.createWritable();return {write:async part=>{qaWrites.push(part.byteLength);await stream.write(part);},close:async()=>{await stream.close();qaCloses++;},abort:async()=>{qaAborts++;await stream.abort();}}}});return true;})()`);
  const streamed=await evaluate(owner,"(async()=>{await qclick('private-export-archive');await qidle();qassert(qaCloses===1&&qaAborts===0,'stream did not close exactly');const raw=new Uint8Array(await(await qaFile.getFile()).arrayBuffer());qassert(new TextDecoder().decode(raw.slice(0,8))==='VHARCHF1','stream header');qassert(raw.slice(-4).every(x=>x===0),'stream terminator');qassert(qaWrites.length>4&&Math.max(...qaWrites)<=270336,'stream buffering exceeded one bounded page');return {bytes:raw.length,chunks:qaWrites.length};})()");
  // Picker cancellation starts no worker export: another export can still run.
  await evaluate(owner,"(async()=>{window.showSaveFilePicker=()=>Promise.reject(new DOMException('synthetic cancel','AbortError'));await qclick('private-export-archive');await qwait(()=>!qid('private-refresh').disabled,'picker cancellation');qassert(qid('identity-state').textContent==='Private custody','picker cancellation changed custody');qassert(qid('private-status').textContent.includes('no export started'),'picker cancellation guidance');return true;})()");
  // Abort after one successful real write, then confirm close never publishes
  // over the previously complete file. A failed write also closes worker custody.
  await evaluate(owner,`window.showSaveFilePicker=async()=>({createWritable:async()=>{const stream=await qaFile.createWritable();let n=0;return {write:async part=>{if(n++===1)throw new DOMException('synthetic quota','QuotaExceededError');await stream.write(part);},close:async()=>{qaCloses++;await stream.close();},abort:async()=>{qaAborts++;await stream.abort();}}}});true`);
  const previous=await evaluate(owner,"(async()=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await(await qaFile.getFile()).arrayBuffer()))))()");
  await evaluate(owner,"(async()=>{await qclick('private-export-archive');await qwait(()=>qid('identity-state').textContent==='Locked'&&!qid('unlock').disabled,'failed streaming export locks');await qwait(()=>qaAborts===1,'temporary stream aborted');qassert(qaCloses===1,'failed stream closed');return true;})()");
  const after=await evaluate(owner,"(async()=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await(await qaFile.getFile()).arrayBuffer()))))()");
  if(JSON.stringify(previous)!==JSON.stringify(after))throw Error('aborted stream changed complete file');
  await reopen(owner);
  await evaluate(owner,`window.qaHolding=false;window.showSaveFilePicker=async()=>({createWritable:async()=>{const stream=await qaFile.createWritable();let n=0;return {write:async part=>{if(n++===1){qaHolding=true;await new Promise(resolve=>window.qaRelease=resolve);}await stream.write(part);},close:async()=>{qaCloses++;await stream.close();},abort:async()=>{qaAborts++;await stream.abort();window.qaRelease?.();}}}});true`);
  await evaluate(owner,"(async()=>{await qclick('private-export-archive');await qwait(()=>qaHolding,'stream is held between pages');await qclick('private-leave');await qwait(()=>qid('identity-state').textContent==='Locked'&&!qid('unlock').disabled,'user cancellation closes custody');await qwait(()=>qaAborts===2,'user cancellation aborts temporary file');qassert(qaCloses===1,'canceled stream closed');return true;})()");
  const canceled=await evaluate(owner,"(async()=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await(await qaFile.getFile()).arrayBuffer()))))()");
  if(JSON.stringify(previous)!==JSON.stringify(canceled))throw Error('user cancellation replaced prior complete file');
  await reopen(owner);
  // A real writer can arrive after custody closes while createWritable awaits.
  // The stale generation must abort that late handle before starting an export.
  await evaluate(owner,`window.qaOpening=false;window.showSaveFilePicker=async()=>({createWritable:async()=>{const stream=await qaFile.createWritable();qaOpening=true;await new Promise(resolve=>window.qaOpened=resolve);return {write:async part=>{qaWrites.push(part.byteLength);await stream.write(part);},close:async()=>{qaCloses++;await stream.close();},abort:async()=>{qaAborts++;await stream.abort();}}}});true`);
  await evaluate(owner,"(async()=>{const writes=qaWrites.length;await qclick('private-export-archive');await qwait(()=>qaOpening,'real writable opened before delayed handle reply');await qclick('private-leave');await qwait(()=>qid('identity-state').textContent==='Locked'&&!qid('unlock').disabled,'lock while createWritable awaits');qaOpened();await qwait(()=>qaAborts===3,'late writable handle aborted');qassert(qaWrites.length===writes&&qaCloses===1,'stale handle wrote or closed');return true;})()");
  const stale=await evaluate(owner,"(async()=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await(await qaFile.getFile()).arrayBuffer()))))()");
  if(JSON.stringify(previous)!==JSON.stringify(stale))throw Error('late handle replaced prior complete file');
  await reopen(owner);
  await evaluate(owner,"window.showSaveFilePicker=undefined;true");
  facts.push(`Production streaming export wrote ${streamed.bytes} bytes in ${streamed.chunks} bounded chunks through a real browser writable file; canceled picker starts no export; injected write quota, explicit lock and a late createWritable handle abort without replacing prior file; Blob fallback exercised separately`);
}
