import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnOwned, stopChild, childStopped, childCleanupReceipt} from './qualification_lifecycle.mjs';

async function ready(process, marker = 'ready') {
  let output = '', errors = '';
  await new Promise((resolve,reject) => {
    const timer = setTimeout(() => finish(Error('test child readiness deadline')),5000);
    const finish = error => {
      clearTimeout(timer); process.stdout.off('data',data); process.off('exit',exit);
      error ? reject(error) : resolve();
    };
    const data = bytes => { output += bytes; if (output.includes(marker)) finish(); };
    const exit = () => finish(Error('test child exited before ready: '+errors));
    process.stdout.on('data',data); process.once('exit',exit);
    process.stderr.on('data', bytes => { errors = (errors + bytes).slice(-4096); });
  });
}

async function exited(process) {
  if (childStopped(process)) return;
  await new Promise((resolve,reject) => {
    const timer = setTimeout(() => { process.off('exit',done); reject(Error('test guardian exit deadline')); },7000);
    const done = () => { clearTimeout(timer); resolve(); };
    process.once('exit',done);
  });
}

async function retainCleanup(process) {
  await stopChild(process).catch(() => {});
  // Synthetic PIDs, verdicts and bounded observation counts only. Preserve
  // failure evidence too, so an independent reader can recheck exact groups.
  console.log('GUARDIAN_CLEANUP '+JSON.stringify(childCleanupReceipt(process)));
}

// These bounded process-custody tests belong under the host scheduler when one
// is installed. They use synthetic Node children, never a browser or user PID.
test('guardian stops a live leader and its grandchild and proves group absence', {timeout:15000}, async () => {
  const script = `const {spawn}=require('node:child_process');
    const child=spawn(process.execPath,['-e',"setInterval(()=>{},1000);console.log('grandchild-ready')"],{stdio:['ignore','pipe','inherit']});
    child.stdout.once('data',()=>console.log('ready'));setInterval(()=>{},1000);`;
  const process = spawnOwned(globalThis.process.execPath,['-e',script],{role:'custody-test',timeoutMs:10000});
  try {
    await ready(process); const receipt = await stopChild(process);
    assert.equal(receipt.status,'stopped'); assert.equal(receipt.groupAbsent,true);
    assert.equal(receipt.guardian.forced,false); assert.ok(receipt.guardian.observedMembers.length >= 2);
  } finally { await retainCleanup(process); }
});

test('guardian force-kills a TERM-resistant group but the result remains a failure', {timeout:15000}, async () => {
  const process = spawnOwned(globalThis.process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000);console.log('ready')"],
    {role:'resistant-test',timeoutMs:10000,graceMs:50});
  try {
    await ready(process); await assert.rejects(stopChild(process),/forced termination/);
    const receipt = childCleanupReceipt(process);
    assert.equal(receipt.groupAbsent,true); assert.equal(receipt.guardian.forced,true); assert.equal(receipt.status,'failed');
  } finally { await retainCleanup(process); }
});

test('guardian failed spawn, independent deadline and lost IPC cannot produce success', {timeout:30000}, async () => {
  for (const mode of ['spawn','deadline','disconnect']) {
    const process = spawnOwned(mode === 'spawn'?'/nonexistent-valhalla-qualification-command':globalThis.process.execPath,
      mode === 'spawn'?[]:['-e',"setInterval(()=>{},1000);console.log('ready')"],
      {role:'failure-test',timeoutMs:mode === 'deadline'?500:10000});
    try {
      if (mode === 'disconnect') { await ready(process); process.disconnect(); }
      await exited(process);
      await assert.rejects(stopChild(process), mode === 'spawn'?/ENOENT/:mode === 'deadline'?/deadline/:/evidence is missing/);
      assert.equal(childCleanupReceipt(process).groupAbsent,true);
    } finally { await retainCleanup(process); }
  }
});
