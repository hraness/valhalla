// One fresh local browser/native generation transition through production UI,
// controller CLI and host maintenance. Read-only SQL observes the real stores;
// no fixture edits a queue, kernel image, receipt or selector.
import {readFile, writeFile, mkdir, readdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash, randomBytes} from 'node:crypto';

const require = (ok, message) => { if (!ok) throw Error(message); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const hash = (domain, ...parts) => {
  const h=createHash('sha256').update(domain); for(const p of parts)h.update(p);return h.digest('hex');
};
const bytes = hex => {require(/^[0-9a-f]{64}$/.test(hex),'noncanonical commitment');return Buffer.from(hex,'hex');};
const u64 = n => {const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(n));return b;};
const CONTEXT=['room','anchor','account','device'];
const ACCOUNTING=['attempts','wire_bytes','retained','received','refused_total','byte_ceiling','attempt_ceiling'];
const LEDGER=['outgoing','applied','retained_jobs','canonical_bytes','charged_attempts','outages','resumes'];
const sleep = ms => new Promise(resolve=>setTimeout(resolve,ms));
const active = new WeakMap();

class Reader {
  constructor(raw){this.raw=Buffer.from(raw);this.at=0;}
  take(n){require(Number.isSafeInteger(n)&&n>=0&&this.at+n<=this.raw.length,'truncated generation observation');const b=this.raw.subarray(this.at,this.at+n);this.at+=n;return b;}
  number(){const n=this.take(8).readBigUInt64BE();require(n<=BigInt(Number.MAX_SAFE_INTEGER),'observation number exceeds exact range');return Number(n);}
  byte(){return this.take(1)[0];}
  flag(){const n=this.byte();require(n<=1,'noncanonical discriminator');return n===1;}
  hex(){return this.take(32).toString('hex');}
  blob(){return this.take(this.take(4).readUInt32BE());}
  end(){require(this.at===this.raw.length,'trailing generation observation');}
}

// These observers assert the wire shape independently. Production native and
// browser decoders still authenticate and authorize every maintenance action.
export function decodePauseReceipt(raw) {
  const r=new Reader(raw),v={};require(r.take(9).equals(Buffer.from('VHCDRAIN\x01')),'pause magic');
  for(const k of [...CONTEXT,'controller_id','original_profile_binding','transition'])v[k]=r.hex();
  v.generation=r.number();for(const k of ['namespace','endpoint','profile_binding'])v[k]=r.hex();
  v.terminal_head=r.number();v.items_commitment=r.hex();v.outbox_head=r.number();v.control_head=r.number();v.image_commitment=r.hex();
  v.mode=r.byte();require(v.generation<16&&v.terminal_head<=4096,'pause generation/head bound');
  if(v.mode===0){
    require(raw.length===650,'native pause width');
    for(const name of ['normal','controls']){v[name]=Object.fromEntries(LEDGER.map(k=>[k,r.number()]));v[name].commitment=r.hex();}
    v.normal_ceiling=r.number();v.control_ceiling=r.number();
    require(v.normal.outgoing===v.outbox_head&&v.normal.applied===v.terminal_head&&v.controls.outgoing===v.control_head&&v.controls.applied===0,'native pause heads');
    for(const [name,ceiling] of [['normal','normal_ceiling'],['controls','control_ceiling']])require(v[ceiling]>0&&v[ceiling]<=1073741824&&v[name].canonical_bytes<=v[ceiling],'native lifetime ceiling');
  }else{
    require(v.mode===1&&raw.length===546,'browser pause mode/width');
    v.accounting=Object.fromEntries(ACCOUNTING.map(k=>[k,r.number()]));const commitment=r.hex();
    require(commitment===hash('vhalla/private/controller-browser-accounting/v1\0',...ACCOUNTING.map(k=>u64(v.accounting[k]))),'browser accounting commitment');
    require(v.accounting.byte_ceiling===1073741824&&v.accounting.wire_bytes<=v.accounting.byte_ceiling&&v.accounting.attempt_ceiling<=65536&&v.accounting.attempts<=v.accounting.attempt_ceiling,'browser lifetime ceiling');
  }
  v.prior=r.hex();r.end();
  require((v.generation===0)===(v.prior==='00'.repeat(32)),'pause lineage');
  require(v.controller_id===hash('vhalla/private/controller-id/v1\0',...CONTEXT.map(k=>bytes(v[k])),bytes(v.original_profile_binding)),'controller identity');
  v.receipt_commitment=hash('vhalla/private/controller-pause-receipt/v1\0',Buffer.from(raw));return v;
}

export function deliveryObservation(raw) {
  const r=new Reader(raw),v={};require(r.take(8).equals(Buffer.from('VHBRDEL\x05')),'current browser delivery format required');
  v.binding=r.hex();r.take(16);
  for(const k of ['initial','sent','cursor','attempts','wire_bytes','wall','retry_at','failures','retained','received','staged_after','applied','refused_total'])v[k]=r.number();
  v.stop=r.byte();v.detail=r.byte();v.blocked=r.byte();
  const refused=r.byte();require(refused<=64,'refusal bound');r.take(refused*41);
  v.admissions=r.byte();require(v.admissions<=8,'admission bound');r.take(v.admissions*45);
  v.deferred=r.byte();require(v.deferred<=8,'deferred bound');r.take(v.deferred*46);
  v.controls=null;if(r.flag()){v.controls=r.number();r.take(32);}
  v.pending=r.blob().length;v.staged=r.blob().length;v.pending_controls=r.blob().length;
  v.discovery_complete=true;
  if(r.flag()){r.take(24);r.flag();v.discovery_complete=r.flag();if(r.flag())r.take(45);r.blob();}
  v.generation=r.number();v.original=r.hex();v.prior=r.hex();v.byte_ceiling=r.number();v.attempt_ceiling=r.number();
  v.audit=null;if(r.flag()){const transition=r.hex(),head=r.number(),count=r.number();require(count<=head&&head<=4096,'audit bound');r.take(count*32);v.audit={transition,head,count};}
  v.pause=r.flag()?decodePauseReceipt(r.take(546)):null;
  v.intent=null;if(r.flag())v.intent={namespace:r.hex(),binding:r.hex(),fence:r.hex(),byte_ceiling:r.number(),attempt_ceiling:r.number()};
  r.end();
  v.drained=!v.pending&&!v.staged&&!v.pending_controls&&!v.admissions&&!v.deferred&&!v.blocked&&!v.applied&&!v.stop&&!v.failures&&!v.retry_at&&v.staged_after===v.cursor&&v.discovery_complete;
  return v;
}

async function sql(h,path,query){const result=await h.command('/usr/bin/sqlite3',['-readonly','-json','-cmd','.timeout 1000',path,query]);return JSON.parse(result.stdout||'[]');}
async function queue(h,state,stream){const path=join(state,stream,'delivery.db');const [v]=await sql(h,path,'SELECT outgoing,applied,(SELECT count(*) FROM jobs WHERE state!=2 OR uncertain!=0) AS pending FROM driver WHERE id=1');require(v,'queue checkpoint absent');return v;}
async function inventory(path){const rows=[];for(const entry of await readdir(path,{withFileTypes:true})){require(!entry.isSymbolicLink(),'fixture custody symlink');const p=join(path,entry.name);if(entry.isDirectory())for(const [name,digest] of await inventory(p))rows.push([entry.name+'/'+name,digest]);else{require(entry.isFile(),'unexpected custody object');rows.push([entry.name,sha(await readFile(p))]);}}return rows.sort(([a],[b])=>a.localeCompare(b));}
function preserves(old,next){const values=new Map(next);require(old.every(([name,digest])=>values.get(name)===digest),'prior encrypted custody changed or disappeared');}
async function browserCustody(h,owner,context){
  const prefix='private-rooms/v1/'+CONTEXT.map(k=>context[k]).join('')+'/';
  return h.invoke(owner,`async function(prefix){
    const all=[];for(const info of await indexedDB.databases()){
      const db=await new Promise((r,j)=>{const q=indexedDB.open(info.name);q.onsuccess=()=>r(q.result);q.onerror=()=>j(Error('open private observation'));});
      try{if(!db.objectStoreNames.contains('images'))continue;
        const rows=await new Promise((r,j)=>{const tx=db.transaction('images','readonly'),q=tx.objectStore('images').openCursor(),out=[];
          q.onsuccess=()=>{const c=q.result;if(!c){r(out);return;}const key=String(c.key);if(key===prefix+'state'||key.startsWith(prefix+'record/')||key.startsWith(prefix+'published/'))out.push([key,new Uint8Array(c.value)]);c.continue();};q.onerror=()=>j(Error('read private observation'));});
        for(const [key,raw] of rows){const digest=await crypto.subtle.digest('SHA-256',raw);all.push([key,Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('')]);}
      }finally{db.close();}}
    qassert(all.some(([key])=>key===prefix+'state'),'private kernel state absent');return all.sort(([a],[b])=>a.localeCompare(b));
  }`,[prefix]);
}
async function mailbox(h,name){
  const path=join(h.hostHome,name,'relay.db');
  const items=await sql(h,path,'SELECT position,lower(hex(digest)) AS digest FROM items ORDER BY position');
  const [{format}]=await sql(h,path,'SELECT format FROM tls_meta WHERE id=1');require(format===1||format===2,'TLS spend format');
  const budgets=await sql(h,path,`SELECT lower(hex(k.id)) AS id,k.max_items,k.max_bytes,count(c.digest) AS spent_items,coalesce(sum(c.bytes),0) AS spent_bytes FROM tls_keys k LEFT JOIN tls_charges c ON k.id=c.key_id GROUP BY k.id ORDER BY k.id`);
  for(const v of budgets){if(format===2){const [prior]=await sql(h,path,"SELECT prior_items,prior_bytes,authorized_items,authorized_bytes FROM tls_budget WHERE lower(hex(key_id))='"+v.id+"'");v.spent_items+=prior.prior_items;v.spent_bytes+=prior.prior_bytes;v.authorized_items=prior.authorized_items;v.authorized_bytes=prior.authorized_bytes;}else{v.authorized_items=v.max_items;v.authorized_bytes=v.max_bytes;}}
  return {items,budgets};
}

export async function drainMixedGeneration(h,{owner,roles}) {
  require(h.generationPilot&&roles.length===2&&!active.has(owner),'unexpected generation fixture');
  const deadline=Date.now()+120000;
  for(;;){
    h.signal.throwIfAborted();require(Date.now()<deadline,'mixed controllers failed to drain in 120 seconds');
    await h.sync(owner);const head=Number(await h.head());require(Number.isSafeInteger(head)&&head>0&&head<=4096,'drain head bound');
    let complete=true;const heads=[];
    for(const role of roles){const status=await role.agent.call('private_status'),profile=JSON.parse(await readFile(role.delivery,'utf8'));
      const jobs=await queue(h,profile.state,'jobs'),controls=await queue(h,profile.state,'controls');
      heads.push(String(status.outbox_head));
      complete&&=jobs.pending===0&&controls.pending===0&&jobs.outgoing===Number(status.outbox_head)&&jobs.applied===head;
    }
    const observed=deliveryObservation(await h.snapshot(owner));complete&&=observed.drained&&observed.cursor===head;
    if(complete)for(let i=0;i<roles.length;i++)complete&&=String((await roles[i].agent.call('private_status')).outbox_head)===heads[i];
    if(complete&&Number(await h.head())===head){active.set(owner,{head,transition:randomBytes(32).toString('hex'),namespace:h.namespace,tlsAddress:h.tlsAddress});return;}
    await sleep(500);
  }
}

export async function transitionMixedGeneration(h,{owner,roles,human,privateCommand}) {
  const stage=active.get(owner);require(stage&&roles.every(role=>!role.agent),'native agents must be closed after the common drain');
  require(Number(await h.head())===stage.head,'head changed after drain; preserve paused evidence');
  const beforeBrowser=await browserCustody(h,owner,human),oldBrowserProfile=JSON.parse(await readFile(owner.deliveryProfile,'utf8'));
  const receipts=[],native=[];const receiptDirectory=join(h.output,'generation-controller-receipts');await mkdir(receiptDirectory,{mode:0o700});
  const retainReceipt=async(raw,context,credentialId)=>{
    const value=decodePauseReceipt(raw);for(const k of CONTEXT)require(value[k]===context[k],'controller pause context');
    require(value.generation===0&&value.namespace===stage.namespace&&value.transition===stage.transition&&value.terminal_head===stage.head,'controller pause transition');
    require(!receipts.some(v=>v.controller_id===value.controller_id),'duplicate physical controller');
    value.credential_id=credentialId;receipts.push(value);await writeFile(join(receiptDirectory,value.controller_id+'.receipt'),raw,{flag:'wx',mode:0o600});return value;
  };
  const hostRaw=await readFile(join(h.hostHome,'config.json')),hostConfig=JSON.parse(hostRaw);
  require(hostConfig.credential_ids.length===3&&new Set(hostConfig.credential_ids).size===3,'fresh fixture inventory must be exactly three credentials');
  for(const role of roles){
    const profile=JSON.parse(await readFile(role.delivery,'utf8')),before=await inventory(join(role.home,'room'));
    require(profile.version===2&&profile.initial_cursor===0&&profile.addr===stage.tlsAddress,'native initial binding');
    const bootstrap=[];for(const name of await readdir(join(profile.state,'applied'))){require(!name.endsWith('.pending'),'unresolved native applied marker');if(name.endsWith('.json')){const marker=JSON.parse(await readFile(join(profile.state,'applied',name),'utf8'));if(marker.state==='dedicated-bootstrap-command-required')bootstrap.push(marker.digest);}}
    require(bootstrap.every(v=>/^[0-9a-f]{64}$/.test(v))&&new Set(bootstrap).size===bootstrap.length,'bootstrap review must name exact distinct retained digests');
    const review=await h.privateFile('generation-'+role.name+'-bootstrap.json',JSON.stringify(bootstrap.sort()));
    const path=join(role.home,'generation.pause.receipt');await privateCommand(role,'delivery-pause',{config:role.delivery,transition:stage.transition,head:stage.head,out:path,'reviewed-bootstrap':review});
    const raw=await readFile(path),receipt=await retainReceipt(raw,role.context,role.credentialId);require(receipt.mode===0,'native receipt accounting mode');
    preserves(before,await inventory(join(role.home,'room')));native.push({role,profile,before,path,raw,receipt});
  }
  await h.invoke(owner,`function(transition,head){qset('private-generation-transition',transition);qset('private-generation-head',head);}`,[stage.transition,String(stage.head)]);
  const drainDeadline=Date.now()+120000;
  for(let page=0;;page++){
    h.signal.throwIfAborted();require(page<=1024&&Date.now()<drainDeadline,'browser full drain deadline');
    const paused=await h.evaluate(owner,"(async()=>{await qclick('private-generation-drain');await qidle();qassert(qid('identity-state').textContent!=='Reload required','browser generation drain refused');return !qid('private-generation-receipt').disabled;})()");
    if(paused)break;await sleep(50);
  }
  const browserDownload=await h.download(owner,'private-generation-receipt','vhpause');
  const browserRaw=await readFile(browserDownload.path),browserReceipt=await retainReceipt(browserRaw,human,hostConfig.credential_ids[0]);
  require(browserReceipt.mode===1&&receipts.every(v=>v.items_commitment===browserReceipt.items_commitment),'controllers drained different items');
  require(new Set(receipts.map(v=>v.credential_id)).size===3&&hostConfig.credential_ids.every(id=>receipts.some(v=>v.credential_id===id)),'controller inventory omits an enrolled credential');
  const browserPaused=deliveryObservation(await h.snapshot(owner));require(browserPaused.pause?.receipt_commitment===browserReceipt.receipt_commitment,'browser pause not durable');
  require(JSON.stringify(beforeBrowser)===JSON.stringify(await browserCustody(h,owner,human)),'browser pause changed encrypted room state');
  await h.stopHost();
  const beforeHost=await mailbox(h,hostConfig.mailbox),successor=randomBytes(32).toString('hex'),tlsAddress='127.0.0.1:'+await h.choosePort();
  require(tlsAddress!==stage.tlsAddress,'successor listener collision');
  const controllers=receipts.map(v=>Object.fromEntries(['credential_id',...CONTEXT,'controller_id','original_profile_binding','profile_binding','endpoint','receipt_commitment'].map(k=>[k,v[k]])));
  const plan={version:1,complete_controller_inventory:true,config_sha256:sha(hostRaw),transition:stage.transition,generation:0,predecessor:stage.namespace,successor,successor_address:tlsAddress,expected_head:stage.head,items_commitment:browserReceipt.items_commitment,controllers,allowances:[]};
  const planPath=await h.privateFile('generation-plan.json',JSON.stringify(plan));
  for(const action of ['generation-check','generation-prepare'])await h.command(h.cli,['private-host',action,h.hostHome,'--plan',planPath,'--receipts',receiptDirectory]);
  for(const action of ['generation-fence','generation-fence','generation-cutover','generation-recover'])await h.command(h.cli,['private-host',action,h.hostHome]);
  const fencePath=join(h.hostHome,'generation-1.fence.json'),fenceRaw=await readFile(fencePath),fence=JSON.parse(fenceRaw);
  require(fence.version===1&&fence.transition===stage.transition&&fence.predecessor===stage.namespace&&fence.successor===successor&&fence.head===String(stage.head)&&fence.items_commitment===browserReceipt.items_commitment,'host fence binding');
  require(fence.predecessor_address===stage.tlsAddress&&fence.successor_address===tlsAddress&&fence.tls_name==='relay.test'&&fence.ca_sha256===sha(await readFile(join(h.output,'ca.der'))),'host fence pinned route');
  require(fence.fence_commitment===hash('vhalla/private/relay-generation-fence/v1\0',bytes(stage.transition),bytes(stage.namespace),bytes(successor),u64(stage.head),bytes(browserReceipt.items_commitment)),'host fence commitment');
  require(JSON.stringify(fence.receipt_commitments)===JSON.stringify(receipts.map(v=>v.receipt_commitment).sort()),'host fence omitted controller receipts');
  require(JSON.stringify(await mailbox(h,hostConfig.mailbox))===JSON.stringify(beforeHost),'predecessor mailbox/spend changed');
  const selectedHost=JSON.parse(await readFile(join(h.hostHome,'config.json'),'utf8')),successorHost=await mailbox(h,selectedHost.mailbox);
  require(!successorHost.items.length&&JSON.stringify(successorHost.budgets)===JSON.stringify(beforeHost.budgets),'successor reset host spend or copied items');
  for(const v of native){
    const state=join(v.role.home,'delivery-state-generation-1'),profilePath=await h.privateFile('generation-'+v.role.name+'-successor.json',JSON.stringify({...v.profile,namespace:successor,addr:tlsAddress,state}));
    const flags={config:v.role.delivery,successor:profilePath,receipt:v.path,fence:fencePath};
    await privateCommand(v.role,'delivery-transition',flags);await privateCommand(v.role,'delivery-transition',flags);
    const chosen=JSON.parse(await readFile(v.role.delivery,'utf8'));require(chosen.version===3&&chosen.namespace===successor&&chosen.lineage.generation===1&&chosen.initial_cursor===0,'native selector');
    for(const [stream,ledger,offset] of [['jobs','normal',426],['controls','controls',514]]){
      const [row]=await sql(h,join(state,stream,'delivery.db'),'SELECT generation,lower(hex(prior)) AS prior,lower(hex(receipt)) AS receipt,(SELECT count(*) FROM jobs) AS jobs,(SELECT outgoing FROM driver WHERE id=1) AS outgoing,(SELECT applied FROM driver WHERE id=1) AS applied FROM lineage WHERE id=1');
      require(row.generation===1&&row.prior===v.raw.subarray(offset,offset+88).toString('hex')&&row.receipt===v.receipt.receipt_commitment&&row.jobs===0&&row.outgoing===v.receipt[ledger].outgoing&&row.applied===0,'native inherited ledger or cursor changed');
    }
    preserves(v.before,await inventory(join(v.role.home,'room')));require((await readFile(join(v.profile.state,'generation.pause'))).equals(v.raw),'native predecessor receipt changed');
  }
  const capability=randomBytes(32).toString('hex'),browserProfile=await h.privateFile('generation-browser-successor.json',JSON.stringify({format:1,origin:oldBrowserProfile.origin,namespace:successor,capability,initial_cursor:'0'}));
  const attempts=browserReceipt.accounting.attempt_ceiling; // No extra authority needed by this finite fixture.
  await h.setFile(owner,'private-generation-profile',browserProfile);await h.setFile(owner,'private-generation-fence',fencePath);
  await h.invoke(owner,`async function(attempts,namespace,fence,receipt){qset('private-generation-attempts',String(attempts));await qclick('private-generation-review');await qidle();const text=qid('private-generation-consent').textContent;qassert(text.includes(namespace)&&text.includes(fence)&&text.includes(receipt),'review omitted selected namespace/fence/receipt');qassert(!qid('private-generation-confirm').disabled,'generation review refused');}`,[attempts,successor,fence.fence_commitment,browserReceipt.receipt_commitment]);
  await h.captureReview(owner,'private-generation-consent','generation-review');
  await h.evaluate(owner,"(async()=>{await qclick('private-generation-confirm');await qidle();qassert(!qid('private-delivery-sync').disabled,'successor did not reopen live delivery');})()");
  const browserNext=deliveryObservation(await h.snapshot(owner,1,1));
  require(browserNext.generation===1&&browserNext.prior===browserReceipt.receipt_commitment&&!browserNext.pause&&!browserNext.intent&&browserNext.cursor===0&&browserNext.initial===0&&browserNext.sent===browserReceipt.outbox_head&&browserNext.controls===browserReceipt.control_head,'browser successor baseline');
  for(const k of ACCOUNTING)require(browserNext[k]===browserReceipt.accounting[k],'browser cumulative accounting changed: '+k);
  require(JSON.stringify(beforeBrowser)===JSON.stringify(await browserCustody(h,owner,human)),'browser successor changed encrypted room state');
  const priorBrowser=deliveryObservation(await h.snapshot(owner));require(priorBrowser.pause?.receipt_commitment===browserReceipt.receipt_commitment&&priorBrowser.intent?.namespace===successor,'browser predecessor evidence not retained');
  owner.deliveryProfile=browserProfile;
  await h.startHost();await h.activateGeneration({namespace:successor,tlsAddress,capability});
  active.delete(owner);
  const summary={scenario:'actual-browser-and-two-native-controllers',controllers:3,generation:1,terminalHead:stage.head,receiptCommitments:receipts.map(v=>v.receipt_commitment).sort(),fenceSha256:sha(fenceRaw),
    encryptedRoomStatePreserved:true,incomingStartsAtZero:true,cumulativeClientSpendPreserved:true,cumulativeHostSpendPreserved:true,additionalAllowance:0,
    predecessorNamespaceSha256:sha(stage.namespace),successorNamespaceSha256:sha(successor),independentDevice:'DEFERRED'};
  await h.privateFile('generation-observation.json',JSON.stringify(summary,null,2));return {namespace:successor,tlsAddress,summary};
}
