// Synthetic integration of a human browser and two deterministic native MCP
// agents. This proves the public entry points cooperate; it invokes no model.
import {spawn} from 'node:child_process';
import {readFile, writeFile, mkdir, readdir, access} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {trackChild, childStopped} from './qualification_lifecycle.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const require = (value, message) => { if (!value) throw Error(message); };
const TOOLS = ['private_inbox', 'private_outbox_status', 'private_prepare', 'private_queue', 'private_status'];
const POLICY = {version:1, mode:'read-write', follow_inbox:true, lifetime:900,
  max_preparations:8, max_messages:4, max_body_bytes:8192,
  max_read_records:2048, max_read_bytes:8388608, max_launches:4,
  disclosure:{host:'synthetic mixed private-room pilot', provider:'none', model:'deterministic fixture',
    processing_policy:'local synthetic content only', allow_cooperating_host:true}};

export function validateClaim(claim, grant, raw) {
  require(claim.format === 'vhalla-agent-launch-claim-v1', 'unexpected launch claim format');
  for (const field of ['grant_id', 'expires_at', 'epoch', 'roster'])
    require(String(claim[field]) === String(grant[field]), 'claim binding differs: '+field);
  for (const field of ['room', 'anchor', 'account', 'device'])
    require(claim.context?.[field] === grant.context?.[field], 'claim context differs: '+field);
  require(claim.grant_sha256 === digest(raw), 'claim grant bytes differ');
}
export function computedResult(request) {
  require(request.task === 'mixed-statistics-1' && request.stage === 'request' &&
    JSON.stringify(request.values) === '[11,7,19,3]', 'unexpected authenticated task');
  return {count:request.values.length, sum:request.values.reduce((a,b)=>a+b,0),
    min:Math.min(...request.values), max:Math.max(...request.values)};
}
export function checkAcceptance(record, sent, recipient, inboxSequence) {
  require(String(record.sequence) === String(sent.sequence) && record.operation === sent.operation &&
    record.kind === 'application', 'outbox evidence belongs to another operation');
  const relay = record.relay ?? {};
  require(!['uncertain','stopped'].includes(relay.state), 'outbox requires reconciliation');
  const claims = record.member_acceptances ?? [];
  require(claims.length <= 2 && new Set(claims.map(c=>c.recipient)).size === claims.length,
    'duplicate or unexpected member acceptances');
  const claim = claims.find(c=>c.recipient === recipient);
  if (claim) require(String(claim.received_sequence) === String(inboxSequence), 'acceptance inbox sequence differs');
  return relay.state === 'retained' && relay.uncertain === false && BigInt(relay.position) > 0n && !!claim;
}

// Read only the actual bounded production Inbox reply. Receipt framing is
// filtered for the application-set audit, never treated as verified acceptance.
export function decodeBrowserInbox(raw) {
  require(raw.length>=151&&raw.subarray(0,12).equals(Buffer.from('VHBRPRIVATE\x08'))&&raw[12]===110,'unexpected browser inbox frame');
  let at=141;
  const number=()=>{require(at+8<=raw.length,'truncated inbox number');const n=raw.readBigUInt64BE(at);at+=8;require(n<=BigInt(Number.MAX_SAFE_INTEGER),'inbox number bound');return Number(n);};
  const head=number(),flag=raw[at++];require(flag===0||flag===1,'inbox next discriminator');const next=flag?number():null;
  const count=raw[at++];require(count<=16,'inbox count bound');const records=[];
  for(let i=0;i<count;i++){const sequence=number();require(sequence>0&&sequence<=head&&at+36<=raw.length,'inbox sequence/body bound');
    const sender=raw.subarray(at,at+32).toString('hex');at+=32;const size=raw.readUInt32BE(at);at+=4;
    require(size<=4096&&at+size<=raw.length,'inbox body bound');const body=raw.subarray(at,at+size);at+=size;records.push({sequence,sender,body});}
  require(at===raw.length,'trailing inbox bytes');return {head,next,records};
}

class Agent {
  constructor(child, signal) {
    this.child=child; this.signal=signal; this.next=0; this.pending=new Map(); this.buffer=''; this.stderr='';
    child.stderr.on('data', data=>{this.stderr=(this.stderr+data).slice(-65536);});
    child.stdout.on('data', data=>{
      this.buffer+=data;
      if(Buffer.byteLength(this.buffer)>1048576){this.fail(Error('MCP line exceeds bound'));return;}
      for(;;){const end=this.buffer.indexOf('\n');if(end<0)break;const line=this.buffer.slice(0,end);this.buffer=this.buffer.slice(end+1);
        try {const response=JSON.parse(line);if(response.id===undefined)throw Error('unexpected MCP notification');
          const waiter=this.pending.get(response.id);if(!waiter)throw Error('unexpected MCP response identity');
          this.pending.delete(response.id);clearTimeout(waiter.timer);
          if(response.error || !response.result)waiter.reject(Error('MCP request refused'));else waiter.resolve(response.result);
        }catch(error){this.fail(error);}
      }
    });
    child.on('error', error=>this.fail(error));
    child.on('exit', ()=>this.fail(Error('MCP child exited')));
  }
  fail(error){this.failure ??= error;for(const waiter of this.pending.values()){clearTimeout(waiter.timer);waiter.reject(error);}this.pending.clear();}
  ask(method,params){
    this.signal.throwIfAborted();if(this.failure)return Promise.reject(this.failure);
    const id=++this.next;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending.delete(id);reject(Error('MCP deadline: '+method));},10000);
      this.pending.set(id,{resolve,reject,timer});
      this.child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n',error=>{if(error)this.fail(error);});
    });
  }
  async call(name, args={}) {
    const result=await this.ask('tools/call',{name,arguments:{...args,session:this.grant.grant_id}});
    require(!result.isError && result.structuredContent && typeof result.structuredContent==='object', name+' refused');
    return result.structuredContent;
  }
  async close() {
    this.child.stdin.end();
    if(!childStopped(this.child))await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.child.off('exit',done);reject(Error('MCP did not close after EOF'));},10000);
      const done=()=>{clearTimeout(timer);resolve();};this.child.once('exit',done);
      if(childStopped(this.child)){this.child.off('exit',done);done();}
    });
    require(this.child.exitCode===0 && this.child.signalCode===null,'MCP required a forced exit');
  }
}

export async function runMixedPilot(h) {
  const {account,enter,evaluate,invoke,setFile,download,retainCreation,connect,profileFile,sync,head,
    command,privateFile,send,reload,leave,wait,cli,output,children,signal}=h;
  let {namespace,tlsAddress}=h;
  let generationSummary;
  const facts=[], launches=[], work=[], grants=new Set(), retainedFiles=[];
  const roles=[];
  const owner=await account('mixed-owner');await enter(owner);await evaluate(owner,"qclick('private-create')");await retainCreation(owner);
  const privateCommand=async(role,action,flags={},includeRoom=true)=>{
    const args=['private',action,join(role.home,'identity')];if(includeRoom)args.push(join(role.home,'room'));
    for(const [name,value] of Object.entries(flags))args.push('--'+name,String(value));
    const result=await command(cli,args);require(result.stdout.trim()==='private operation completed; consult the retained result for delivery status','private command completion changed: '+action);
  };
  const ownerContext=async()=>invoke(owner,`function(){const raw=qaMembership;qassert(raw instanceof Uint8Array&&raw[12]===103&&raw.length>141,'membership wire evidence absent');const hex=v=>Array.from(v,b=>b.toString(16).padStart(2,'0')).join('');return {room:hex(raw.slice(13,45)),anchor:hex(raw.slice(45,77)),account:hex(raw.slice(77,109)),device:hex(raw.slice(109,141))};}`);
  const human=await ownerContext();require(human.account===owner.publicKey,'browser account/context mismatch');
  for(const name of ['analyst','reviewer']) {
    const role={name,home:join(output,'mixed-'+name),generation:0,cursor:0,received:new Map()};roles.push(role);await mkdir(role.home,{mode:0o700});
    const identity=await command(cli,['identity','init',join(role.home,'identity')]);
    const match=identity.stdout.trim().match(/^application-key ([0-9a-f]{64})$/);require(match,'native identity output changed');role.account=match[1];
    await invoke(owner,`async function(recipient){qset('private-recipient',recipient);await qclick('private-offer');await qidle();}`,[role.account]);
    const offer=await download(owner,'private-download-secret','vhoffer');
    const reviewPath=join(role.home,'offer-review.json');await privateCommand(role,'offer-inspect',{offer:offer.path,owner:owner.publicKey,out:reviewPath},false);
    const review=JSON.parse(await readFile(reviewPath,'utf8'));require(review.kind==='confidential-offer-metadata'&&review.room===human.room&&review.anchor===human.anchor,'offer scope mismatch');
    const now=Math.floor(Date.now()/1000);
    await privateCommand(role,'import',{offer:offer.path,owner:owner.publicKey,room:review.room,anchor:review.anchor,'not-before':now-30,expires:now+7200});
    const request=join(role.home,'request.cipher');await privateCommand(role,'request',{offer:offer.path,operation:(roles.length+10).toString(16).padStart(32,'0'),out:request});
    await setFile(owner,'private-request-file',request);await evaluate(owner,"(async()=>{await qclick('private-accept');await qidle();})()");
    const response=await download(owner,'private-download-output','vhjoin');await privateCommand(role,'join',{response:response.path});
    const inspect=join(role.home,'inspect.json');await privateCommand(role,'inspect',{out:inspect});
    const status=JSON.parse(await readFile(inspect,'utf8')).status;
    role.context=Object.fromEntries(['room','anchor','account','device'].map(k=>[k,status[k]]));
    require(role.context.account===role.account&&role.context.room===human.room&&role.context.anchor===human.anchor,'native joined scope mismatch');
  }
  async function latestControl() {
    await evaluate(owner,"(async()=>{await qclick('private-controls');await qidle();})()");
    await invoke(owner,`function(){const s=qid('private-control-select');qassert(s.options.length>0,'encrypted control missing');qset('private-control-select',s.options.length-1,'change');}`);
    return download(owner,'private-download-control','vhcontrol');
  }
  // The first native recipient was offline for the second admission. Catch it
  // up through the existing authenticated encrypted-control import path.
  const admitted=await latestControl();await privateCommand(roles[0],'apply',{control:admitted.path});
  owner.deliveryProfile=await profileFile(0);await connect(owner,owner.deliveryProfile,true);
  for(let i=0;i<6;i++)await sync(owner);
  const checkpoint=await head();require(checkpoint>0,'browser controls never reached relay');
  for(const role of roles) {
    const transport=h.nativeCredential?await h.nativeCredential(role):{token:join(output,'relay-token')};role.credentialId=transport.id;
    const delivery={version:1,context:role.context,namespace,addr:tlsAddress,tls_name:'relay.test',
      ca:join(output,'ca.der'),token:transport.token,state:join(role.home,'delivery-state'),
      max_jobs:128,max_bytes:67108864,max_attempts:20,initial_backoff_secs:1,max_backoff_secs:30,
      emit_acceptance:true,initial_cursor:h.generationPilot?0:checkpoint};
    role.delivery=await privateFile('mixed-'+role.name+'-delivery.json',JSON.stringify(delivery));
    role.policy=await privateFile('mixed-'+role.name+'-policy.json',JSON.stringify(POLICY));
    await privateCommand(role,'delivery-init',{config:role.delivery});
  }
  async function launch(role) {
    signal.throwIfAborted();const child=trackChild(spawn(cli,['private','agent-launch',join(role.home,'identity'),join(role.home,'room'),
      '--policy',role.policy,'--session-dir',join(role.home,'sessions'),'--delivery',role.delivery],
      {stdio:['pipe','pipe','pipe'],env:{...process.env,HRANESS_SUPPORT:'off',XDG_STATE_HOME:join(output,'xdg-state')}}));children.push(child);
    const agent=new Agent(child,signal);role.agent=agent;role.generation++;
    const initialized=await agent.ask('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'valhalla-mixed-pilot',version:'1'}});
    require(initialized.protocolVersion==='2025-11-25','MCP protocol changed');
    const prefix=join(role.home,'sessions',String(role.generation).padStart(4,'0'));
    const raw=await readFile(prefix+'-grant.json');agent.grant=JSON.parse(raw);
    require(!grants.has(agent.grant.grant_id),'grant identifier reused');grants.add(agent.grant.grant_id);
    child.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
    const listed=(await agent.ask('tools/list',{})).tools;
    require(JSON.stringify(listed.map(t=>t.name).sort())===JSON.stringify(TOOLS),'MCP tool set differs');
    require(listed.every(t=>t.inputSchema.properties.session.const===agent.grant.grant_id),'tool grant mismatch');
    if(role.priorGrant){const stale=await agent.ask('tools/call',{name:'private_status',arguments:{session:role.priorGrant}});require(stale.isError===true,'stale grant accepted');}
    const status=await agent.call('private_status');require(status.status==='live','MCP session not live');
    for(const key of ['room','anchor','account','device'])require(status.context[key]===role.context[key],'MCP context mismatch');
    const claimRaw=await readFile(prefix+'-claim.json');validateClaim(JSON.parse(claimRaw),agent.grant,raw);
    retainedFiles.push({path:prefix+'-grant.json',sha256:digest(raw)},{path:prefix+'-claim.json',sha256:digest(claimRaw)});
    role.priorGrant=agent.grant.grant_id;
    const entry={role:role.name,generation:role.generation,grantSha256:digest(raw),claimSha256:digest(claimRaw),
      epoch:String(status.epoch),initialRemaining:status.remaining,staleSessionRefused:role.generation>1};
    launches.push(entry);role.launch=entry;
  }
  async function close(role) {
    const status=await role.agent.call('private_status');
    for(const key of ['preparations','messages','body_bytes','read_records','read_bytes'])
      require(BigInt(status.remaining[key])<=BigInt(role.launch.initialRemaining[key]),'grant allowance increased');
    role.launch.finalRemaining=status.remaining;await role.agent.close();delete role.agent;
  }
  for(const role of roles)await launch(role);
  async function nativeReceives(role,body,sender) {
    await wait(async()=>{
      const result=await role.agent.call('private_inbox',{after:String(role.cursor),limit:16});
      for(const record of result.records){const sequence=Number(record.sequence);require(Number.isSafeInteger(sequence)&&sequence>role.cursor,'inbox sequence regressed');
        const text=Buffer.from(record.body_hex,'hex').toString('utf8');require(!role.received.has(text),'duplicate authenticated body');
        role.received.set(text,{sequence,sender:record.sender});role.cursor=sequence;}
      const next=Number(result.next??result.head);require(Number.isSafeInteger(next)&&next>=role.cursor,'inbox page cursor regressed');role.cursor=next;
      return role.received.has(body);
    },role.name+' accepts synthetic work');
    const record=role.received.get(body);require(record.sender===sender,'wrong authenticated sender');return record.sequence;
  }
  async function browserReceives(body,sender) {
    let text='';await wait(async()=>{await sync(owner);text=await evaluate(owner,"(async()=>{await qclick('private-inbox');await qidle();return qid('private-inbox-content').textContent;})()");return text.includes(body);},'human browser accepts synthetic work');
    const lines=text.trim().split('\n');let found=[];
    for(let i=0;i<lines.length;i++)if(lines[i]===body){const m=lines[i-1]?.match(/^Message ([1-9][0-9]*) · device ([0-9a-f]{64})$/);require(m&&m[2]===sender,'browser sender/position mismatch');found.push(Number(m[1]));}
    require(found.length===1,'browser body absent or duplicated');return found[0];
  }
  async function queue(role,body,number) {
    const prepared=await role.agent.call('private_prepare',{body});require(prepared.status==='prepared_exact_content','prepare did not disclose exact content');
    const operation=number.toString(16).padStart(32,'0');const queued=await role.agent.call('private_queue',{draft:prepared.draft,operation});
    require(queued.status==='durable_local_only'&&queued.kind==='application'&&!queued.relay,'queue overclaims delivery');
    const sent={sequence:String(queued.sequence),operation,bodySha256:digest(body)};
    Object.defineProperty(sent,'relaySelection',{value:{namespace,tlsAddress}});return sent;
  }
  async function accepted(role,sent,recipient,inboxSequence) {
    await wait(async()=>{const report=await role.agent.call('private_outbox_status',{after:(BigInt(sent.sequence)-1n).toString(),limit:1});
      require(report.records.length===1,'outbox operation missing');const ready=checkAcceptance(report.records[0],sent,recipient,inboxSequence);
      if(ready)sent.relayPosition=String(report.records[0].relay.position);return ready;
    },'exact authenticated acceptance for '+role.name);
  }
  const request=JSON.stringify({version:1,task:'mixed-statistics-1',stage:'request',values:[11,7,19,3],requested:['count','sum','min','max']});
  await send(owner,request);await sync(owner);
  const requestAt=await nativeReceives(roles[0],request,human.device);
  await nativeReceives(roles[1],request,human.device);
  const result=JSON.stringify({version:1,task:'mixed-statistics-1',stage:'result',previous_sha256:digest(request),result:computedResult(JSON.parse(request))});
  const resultSent=await queue(roles[0],result,2);const resultAt=await nativeReceives(roles[1],result,roles[0].context.device);
  await accepted(roles[0],resultSent,roles[1].context.device,resultAt);
  const humanResultAt=await browserReceives(result,roles[0].context.device);await sync(owner);await accepted(roles[0],resultSent,human.device,humanResultAt);
  require(JSON.stringify(JSON.parse(result).result)===JSON.stringify({count:4,sum:40,min:3,max:19}),'reviewer rejected statistics');
  const reviewed=JSON.stringify({version:1,task:'mixed-statistics-1',stage:'verified',previous_sha256:digest(result),accepted:true});
  const reviewSent=await queue(roles[1],reviewed,3);const reviewAt=await browserReceives(reviewed,roles[1].context.device);await sync(owner);await accepted(roles[1],reviewSent,human.device,reviewAt);
  const humanReview=JSON.stringify({version:1,task:'mixed-statistics-1',stage:'human-review',previous_sha256:digest(reviewed),accepted:true});
  await send(owner,humanReview);await sync(owner);await nativeReceives(roles[0],humanReview,human.device);
  await nativeReceives(roles[1],humanReview,human.device);
  work.push({stage:'request',bodySha256:digest(request),analystInbox:requestAt},{stage:'result',...resultSent,reviewerInbox:resultAt,humanInbox:humanResultAt},
    {stage:'verified',...reviewSent,humanInbox:reviewAt},{stage:'human-review',bodySha256:digest(humanReview)});
  if(h.drainGeneration)await h.drainGeneration(h,{owner,roles,privateCommand});
  for(const role of roles)await close(role);
  const original=join(roles[0].home,'original-result.cipher');await privateCommand(roles[0],'export',{sequence:resultSent.sequence,out:original});
  const originalSha=digest(await readFile(original));
  if(h.transitionGeneration){const transitioned=await h.transitionGeneration(h,{owner,roles,human,privateCommand});namespace=transitioned.namespace;tlsAddress=transitioned.tlsAddress;generationSummary=transitioned.summary;}
  await h.removeMember(owner,roles[1].context.account,roles[1].context.device);
  const removal=await latestControl();for(const role of roles)await privateCommand(role,'apply',{control:removal.path});
  await reload(owner);await connect(owner,owner.deliveryProfile);for(let i=0;i<4;i++)await sync(owner);
  await launch(roles[0]);require(launches.at(-1).epoch!==launches[0].epoch,'membership change failed to replace grant scope');
  const completion=JSON.stringify({version:1,task:'mixed-statistics-1',stage:'completion',previous_sha256:digest(humanReview),completed_after_restart:true});
  const completionSent=await queue(roles[0],completion,4);const completionAt=await browserReceives(completion,roles[0].context.device);await sync(owner);
  await accepted(roles[0],completionSent,human.device,completionAt);await close(roles[0]);
  const after=join(roles[0].home,'reopened-result.cipher');await privateCommand(roles[0],'export',{sequence:resultSent.sequence,out:after});
  require(digest(await readFile(after))===originalSha,'restart changed retained original ciphertext');
  for(const retained of retainedFiles)require(digest(await readFile(retained.path))===retained.sha256,'restart changed retained grant/claim');
  const removedInspect=join(roles[1].home,'removed-inspect.json');await privateCommand(roles[1],'inspect',{out:removedInspect});
  const removedStatus=JSON.parse(await readFile(removedInspect,'utf8')).status;require(removedStatus.phase==='Removed','removed native member remained active');
  // Read the complete bounded inboxes after every live writer is stopped.
  const expectedByRole=[new Map([[request,human.device],[reviewed,roles[1].context.device],[humanReview,human.device]]),
    new Map([[request,human.device],[result,roles[0].context.device],[humanReview,human.device]])];
  for(const [index,role] of roles.entries()) {
    const path=join(role.home,'final-inbox.json');await privateCommand(role,'inbox',{after:0,limit:16,out:path});
    const page=JSON.parse(await readFile(path,'utf8')), seen=new Set();
    require(page.next===null&&page.records.filter(record=>!Buffer.from(record.body_hex,'hex').subarray(0,8).equals(Buffer.from('VHACK\0\0\x01'))).length===expectedByRole[index].size,'final inbox count/page differs');
    for(const record of page.records){const bytes=Buffer.from(record.body_hex,'hex');if(bytes.subarray(0,8).equals(Buffer.from('VHACK\0\0\x01')))continue;const body=bytes.toString('utf8');
      require(expectedByRole[index].get(body)===record.sender&&!seen.has(body),'unexpected/duplicate final inbox content');seen.add(body);
      const observed=role.received.get(body);require(observed&&String(observed.sequence)===String(record.sequence),'restart changed inbox position');}
    require(Number(page.head)===page.records.length,'final inbox head differs');
  }
  await evaluate(owner,"(async()=>{await qclick('private-inbox');await qidle();})()");
  const browserPage=decodeBrowserInbox(Buffer.from(await evaluate(owner,'Array.from(qaInbox??[])')));
  const browserExpected=new Map([[result,roles[0].context.device],[reviewed,roles[1].context.device],[completion,roles[0].context.device]]);
  const browserBodies=new Set();require(browserPage.next===null,'final browser inbox exceeds one bounded page');
  for(const record of browserPage.records){if(record.body.subarray(0,8).equals(Buffer.from('VHACK\0\0\x01')))continue;
    const body=record.body.toString('utf8');require(browserExpected.get(body)===record.sender&&!browserBodies.has(body),'final browser inbox sender/content differs');browserBodies.add(body);}
  require(browserBodies.size===browserExpected.size,'final browser work exchange incomplete');
  async function inventory(directory) {
    const result={};for(const entry of (await readdir(directory,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){
      const path=join(directory,entry.name);if(entry.isDirectory()){const nested=await inventory(path);for(const [key,value] of Object.entries(nested))result[entry.name+'/'+key]=value;}
      else {require(entry.isFile(),'unexpected custody entry');result[entry.name]=digest(await readFile(path));}}
    return result;
  }
  const removedRoom=join(roles[1].home,'room'),beforeDenied=await inventory(removedRoom);
  const deniedText=await privateFile('mixed-removed-send.txt','synthetic denied send'),deniedOut=join(output,'mixed-removed-send.cipher');
  const denied=await command(cli,['private','send',join(roles[1].home,'identity'),removedRoom,'--text',deniedText,
    '--operation','99'.padStart(32,'0'),'--epoch',String(removedStatus.epoch),'--roster',removedStatus.roster,'--out',deniedOut],1);
  require(!denied.stdout&&denied.stderr.includes('local private membership is not currently authorized'),'wrong reason for removed sender refusal');
  let published=false;try{await access(deniedOut);published=true;}catch(error){require(error.code==='ENOENT','cannot inspect denied output');}
  require(!published&&JSON.stringify(await inventory(removedRoom))===JSON.stringify(beforeDenied),'removed send changed custody or published output');
  // Independently join reported relay positions to a full authenticated TLS
  // scan and exported original ciphertext, including the post-reopen send.
  const relayByNamespace=new Map();
  for(const selection of [resultSent.relaySelection,reviewSent.relaySelection,completionSent.relaySelection]) {
    if(relayByNamespace.has(selection.namespace))continue;
    const {namespace,tlsAddress}=selection,ordinal=relayByNamespace.size;
    const scan=join(output,'mixed-final-scan-'+ordinal),report=join(output,'mixed-final-scan-'+ordinal+'.json');
  await command(cli,['private','relay-scan',scan,'--namespace',namespace,'--addr',tlsAddress,'--token',join(output,'relay-token'),
    '--tls-ca',join(output,'ca.der'),'--tls-name','relay.test','--limit','64','--out',report]);
  const scanReport=JSON.parse(await readFile(report,'utf8'));require(scanReport.cursor===scanReport.head&&scanReport.head<=64,'final relay audit exceeds one page');
  const relayItems=[];
  for(let position=1;position<=scanReport.head;position++){
    const raw=await readFile(join(scan,'items',position.toString(16).padStart(16,'0')+'.vhrelay'));
    require(raw.length>=102&&raw.subarray(0,9).equals(Buffer.from('VHPRELAY\x01'))&&raw.subarray(9,41).toString('hex')===namespace,'final relay item framing/scope');
    const length=raw.readUInt32BE(66);require(raw.length===102+length,'final relay item length');
    const payload=raw.subarray(70,70+length);
    const commitment=createHash('sha256').update('vhalla/private/relay-item/v1').update(raw.subarray(9,66)).update(payload).digest();
    require(commitment.equals(raw.subarray(-32)),'final relay item digest');
    relayItems.push({position,sequence:raw.readBigUInt64BE(41).toString(),operation:raw.subarray(49,65).toString('hex'),kind:raw[65],payload,commitment:commitment.toString('hex')});
  }
    relayByNamespace.set(namespace,relayItems);
  }
  for(const [role,sent,label] of [[roles[0],resultSent,'result'],[roles[1],reviewSent,'verified'],[roles[0],completionSent,'completion']]){
    const path=join(role.home,'audited-'+label+'.cipher');await privateCommand(role,'export',{sequence:sent.sequence,out:path});const ciphertext=await readFile(path);
    const rows=relayByNamespace.get(sent.relaySelection.namespace).filter(row=>row.operation===sent.operation);
    require(rows.length===1&&String(rows[0].position)===sent.relayPosition&&rows[0].sequence===sent.sequence&&rows[0].kind===5&&rows[0].payload.equals(ciphertext),
      'reported relay receipt does not match exactly one retained operation/ciphertext');
    sent.relayDigest=rows[0].commitment;const stage=work.find(stage=>stage.operation===sent.operation);if(stage)stage.relayDigest=sent.relayDigest;
  }
  work.push({stage:'completion',...completionSent,humanInbox:completionAt});
  facts.push('one browser owner and two native agent-launch MCP sessions join the same private room through confidential offers and exact encrypted admission files');
  facts.push('browser requests statistics; analyst computes 4/40/3/19; independent fixture role verifies; browser reviews exact authenticated output; device acceptances match sender operations and recipient inbox positions');
  facts.push('native processes close cleanly; owner removes reviewer; offline controllers apply authenticated control; browser reloads; fresh scoped grant refuses old session and delivers completion while preserving original ciphertext, grants and claims');
  await leave(owner);
  await writeFile(join(output,'mixed-launches.json'),JSON.stringify(launches,null,2)+'\n',{mode:0o600,flag:'wx'});
  return {facts,mixedPilot:{generation:generationSummary,scenario:'browser-human-two-deterministic-native-mcp-agents',realModel:'NOT_RUN',externalDevice:'DEFERRED',
    stages:work,launches,originalCiphertextSha256:originalSha,finalInboxAudit:true,removedSendRefused:true,exactRelayAudit:true,scope:'fresh synthetic same-machine custody; explicit file admission and offline control catch-up; no model or independent-device claim'}};
}
