import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {validateClaim, computedResult, checkAcceptance, decodeBrowserInbox} from './private_mixed_pilot.mjs';

test('mixed pilot joins a launch claim to exact grant bytes and complete private scope',()=>{
  const grant={grant_id:'ab'.repeat(16),expires_at:123456,epoch:'2',roster:'cd'.repeat(32),
    context:{room:'11'.repeat(32),anchor:'22'.repeat(32),account:'33'.repeat(32),device:'44'.repeat(32)}};
  const raw=Buffer.from(JSON.stringify(grant));
  const claim={...structuredClone(grant),format:'vhalla-agent-launch-claim-v1',
    grant_sha256:createHash('sha256').update(raw).digest('hex')};
  validateClaim(claim,grant,raw);
  for(const field of ['grant_id','expires_at','epoch','roster','grant_sha256']){
    const wrong=structuredClone(claim);wrong[field]='different';assert.throws(()=>validateClaim(wrong,grant,raw));
  }
  for(const field of ['room','anchor','account','device']){
    const wrong=structuredClone(claim);wrong.context[field]='ff'.repeat(32);assert.throws(()=>validateClaim(wrong,grant,raw));
  }
  assert.throws(()=>validateClaim(claim,grant,Buffer.concat([raw,Buffer.from('\n')])));
});

test('mixed pilot computes the requested statistics from the exact synthetic input',()=>{
  const request={task:'mixed-statistics-1',stage:'request',values:[11,7,19,3]};
  assert.deepEqual(computedResult(request),{count:4,sum:40,min:3,max:19});
  assert.throws(()=>computedResult({...request,values:[11,7,19,4]}));
  assert.throws(()=>computedResult({...request,task:'different'}));
});

test('acceptance evidence must join operation, recipient, inbox and actual relay retention',()=>{
  const sent={sequence:'9',operation:'55'.repeat(16)};
  const record={...sent,kind:'application',relay:{state:'retained',uncertain:false,position:'17'},
    member_acceptances:[{recipient:'66'.repeat(32),received_sequence:'4'},{recipient:'77'.repeat(32),received_sequence:'8'}]};
  assert.equal(checkAcceptance(record,sent,'77'.repeat(32),8),true);
  assert.equal(checkAcceptance(record,sent,'88'.repeat(32),8),false);
  assert.throws(()=>checkAcceptance(record,sent,'77'.repeat(32),7));
  assert.throws(()=>checkAcceptance({...record,operation:'99'.repeat(16)},sent,'77'.repeat(32),8));
  assert.throws(()=>checkAcceptance({...record,member_acceptances:[record.member_acceptances[0],record.member_acceptances[0]]},sent,'66'.repeat(32),4));
  assert.throws(()=>checkAcceptance({...record,relay:{state:'uncertain'}},sent,'77'.repeat(32),8));
  assert.equal(checkAcceptance({...record,relay:{state:'retained',uncertain:true,position:'17'}},sent,'77'.repeat(32),8),false);
});


test('browser inbox audit decodes bounded actual frames and refuses malformed evidence',()=>{
  const n=value=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(value));return b;};
  const body=Buffer.from('{"result":40}'),size=Buffer.alloc(4);size.writeUInt32BE(body.length);
  const raw=Buffer.concat([Buffer.from('VHBRPRIVATE\x08'),Buffer.from([110]),Buffer.alloc(128,1),n(4),Buffer.from([0,1]),n(4),Buffer.alloc(32,2),size,body]);
  const page=decodeBrowserInbox(raw);assert.equal(page.head,4);assert.equal(page.next,null);assert.equal(page.records[0].sender,'02'.repeat(32));assert.deepEqual(page.records[0].body,body);
  assert.throws(()=>decodeBrowserInbox(raw.subarray(0,-1)));
  assert.throws(()=>decodeBrowserInbox(Buffer.concat([raw,Buffer.from([0])])));
  const wrong=Buffer.from(raw);wrong[149]=2;assert.throws(()=>decodeBrowserInbox(wrong));
});
