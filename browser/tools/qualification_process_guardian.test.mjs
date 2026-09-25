import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnOwned, stopChild, childStopped, childCleanupReceipt} from './qualification_lifecycle.mjs';
import {mkdtemp, readFile, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

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

async function fileIncludes(path, marker) {
  const until = Date.now() + 5000;
  for (;;) {
    const text = await readFile(path,'utf8').catch(() => '');
    if (text.includes(marker)) return text;
    if (Date.now() >= until) throw Error('test output file readiness deadline');
    await new Promise(resolve => setTimeout(resolve,50));
  }
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
    assert.equal(receipt.status,'stopped'); assert.equal(receipt.groupAbsent,true); assert.equal(receipt.closeObserved,true);
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
    assert.equal(receipt.closeObserved,true);
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
      assert.equal(childCleanupReceipt(process).closeObserved,true);
    } finally { await retainCleanup(process); }
  }
});

test('only the exit status declared at spawn is a normal self-exit', {timeout:20000}, async () => {
  for (const expectedExit of [3, 0]) {
    const process = spawnOwned(globalThis.process.execPath,['-e',"console.log('ready');process.exit(3)"],
      {role:'exit-status-test',timeoutMs:10000,expectedExit});
    try {
      await exited(process);
      if (expectedExit === 3) {
        const receipt = await stopChild(process);
        assert.equal(receipt.status,'stopped'); assert.equal(receipt.groupAbsent,true); assert.equal(receipt.closeObserved,true);
        assert.equal(receipt.guardian.expectedExit,3); assert.deepEqual(receipt.guardian.leaderExit,{code:3,signal:null});
      } else {
        await assert.rejects(stopChild(process),/exited unsuccessfully/);
        const receipt = childCleanupReceipt(process);
        assert.equal(receipt.status,'failed'); assert.equal(receipt.groupAbsent,true);
        assert.deepEqual(receipt.guardian.leaderExit,{code:3,signal:null});
      }
    } finally { await retainCleanup(process); }
  }
});

test('a private output file keeps an escaped descendant off the parent pipes; inherited pipes fail closed', {timeout:30000}, async () => {
  // Mirrors a browser whose crash handler leaves the group by design and
  // outlives it while holding the leader's stdout/stderr.
  const script = `const {spawn}=require('node:child_process');
    const escaped=spawn(process.execPath,['-e',"setTimeout(()=>{},4000)"],{detached:true,stdio:['ignore','inherit','inherit']});
    escaped.unref();console.log('ready');setInterval(()=>{},1000);`;
  const directory = await mkdtemp(join(tmpdir(),'valhalla-guardian-output-'));
  try {
    const outputPath = join(directory,'leader.log');
    const owned = spawnOwned(globalThis.process.execPath,['-e',script],{role:'escaped-output-test',timeoutMs:10000,outputPath});
    try {
      await fileIncludes(outputPath,'ready');
      const receipt = await stopChild(owned);
      assert.equal(receipt.status,'stopped'); assert.equal(receipt.groupAbsent,true); assert.equal(receipt.closeObserved,true);
      assert.equal(receipt.guardian.output,outputPath); assert.equal(receipt.guardian.forced,false);
      assert.equal((await stat(outputPath)).mode & 0o777,0o600);
    } finally { await retainCleanup(owned); }
    const piped = spawnOwned(globalThis.process.execPath,['-e',script],{role:'escaped-pipe-test',timeoutMs:10000});
    try {
      await ready(piped);
      await assert.rejects(stopChild(piped),/stdio closure/);
      const receipt = childCleanupReceipt(piped);
      assert.equal(receipt.status,'failed'); assert.equal(receipt.groupAbsent,true); assert.equal(receipt.closeObserved,false);
      assert.deepEqual(receipt.parentStreamsDisposed,[1,2]);
    } finally { await retainCleanup(piped); }
    // An output path that already exists is refused, never truncated or appended.
    const taken = spawnOwned(globalThis.process.execPath,['-e',"console.log('ready');setInterval(()=>{},1000)"],
      {role:'taken-output-test',timeoutMs:10000,outputPath});
    try {
      await exited(taken);
      await assert.rejects(stopChild(taken),/output file was not created: EEXIST/);
      assert.equal(childCleanupReceipt(taken).groupAbsent,true);
      assert.equal(await readFile(outputPath,'utf8'),'ready\n');
    } finally { await retainCleanup(taken); }
  } finally { await rm(directory,{recursive:true,force:true}); }
});

test('owned command options are validated before any process exists', () => {
  const executable = globalThis.process.execPath;
  for (const options of [{expectedExit:-1},{expectedExit:256},{expectedExit:1.5},{outputPath:'relative/leader.log'},{outputPath:''},{outputPath:42}]) {
    assert.throws(() => spawnOwned(executable,['-e','0'],{role:'validation-test',timeoutMs:1000,...options}),/invalid owned command/);
  }
});
