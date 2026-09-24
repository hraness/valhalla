import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decodePauseReceipt} from './private_generation_pilot.mjs';

const vector=JSON.parse(await readFile(new URL('../../vectors/private-controller-pause-v1.json',import.meta.url),'utf8'));
const raw=Buffer.from(vector.encoded_hex,'hex');

test('mixed generation observer decodes the shared production controller receipt vector',()=>{
  const decoded=decodePauseReceipt(raw);
  assert.equal(decoded.receipt_commitment,vector.commitment);
  for(const field of ['room','anchor','account','device'])assert.equal(decoded[field],vector.fields.context[field]);
  for(const field of ['controller_id','original_profile_binding','profile_binding','transition','namespace','endpoint','items_commitment','image_commitment'])
    assert.equal(decoded[field],vector.fields[field]);
  assert.equal(decoded.mode,1);
  assert.equal(decoded.terminal_head,Number(vector.fields.terminal_head));
  assert.equal(decoded.accounting.byte_ceiling,1073741824);
  assert.equal(decoded.accounting.attempts,9);
  assert.equal(decoded.accounting.wire_bytes,1024);
  assert.equal(decoded.accounting.attempt_ceiling,4096);
});

test('mixed generation observer refuses truncation, mode confusion and unauthenticated accounting',()=>{
  for(let end=0;end<raw.length;end++)assert.throws(()=>decodePauseReceipt(raw.subarray(0,end)),`truncation ${end}`);
  assert.throws(()=>decodePauseReceipt(Buffer.concat([raw,Buffer.from([0])])),/trailing|width/);
  for(const offset of [0,73,137,425,426,482]){
    const changed=Buffer.from(raw);changed[offset]^=1;
    assert.throws(()=>decodePauseReceipt(changed),`changed field at ${offset}`);
  }
  const lineage=Buffer.from(raw);lineage.writeBigUInt64BE(1n,233);
  assert.throws(()=>decodePauseReceipt(lineage),/lineage/);
});
