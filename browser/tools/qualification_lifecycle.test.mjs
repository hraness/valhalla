import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {trackChild, childStopped, stopChild, stopServer, cleanupOwned, runQualification, closeTargetChecked,
  childCleanupReceipt, groupAbsent, observeGroupAbsence} from './qualification_lifecycle.mjs';

function child(onKill = () => {}) {
  const process = new EventEmitter();
  Object.assign(process, {exitCode: null, signalCode: null, pid: 42, signals: []});
  process.kill = signal => { process.signals.push(signal); onKill(process, signal); return true; };
  return trackChild(process);
}
const terminated = (process, signal) => { process.signalCode = signal; process.emit('exit', null, signal); process.emit('close', null, signal); };

test('an already signal-exited child never waits on a past exit event or signals a reused PID', async () => {
  const process = child(); terminated(process, 'SIGKILL');
  assert.equal(process.exitCode, null); assert.equal(childStopped(process), true);
  await stopChild(process, 5, 5); assert.deepEqual(process.signals, []);
});

test('already normal-exited and failed-spawn children are settled', async () => {
  const normal = child(); normal.exitCode = 0; normal.emit('close', 0, null);
  const failed = child(); failed.pid = undefined; failed.emit('error', Error('ENOENT')); failed.emit('close', -2, null);
  await Promise.all([stopChild(normal, 5, 5), stopChild(failed, 5, 5)]);
  assert.deepEqual(normal.signals, []); assert.deepEqual(failed.signals, []);
});

test('exit alone cannot complete cleanup before the separate stdio close event', async () => {
  const process = child(process => { process.exitCode = 0; process.emit('exit', 0, null); });
  let settled = false;
  const stopping = stopChild(process, 100, 100).then(value => { settled = true; return value; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(childStopped(process), true); assert.equal(settled, false);
  assert.equal(childCleanupReceipt(process).status, 'stopping');
  process.emit('close', 0, null);
  const receipt = await stopping;
  assert.equal(receipt.closeObserved, true); assert.equal(receipt.status, 'stopped');
  assert.equal(receipt.parentStreamsDisposed, undefined);
});

test('already exited but never closed child fails within a bound and disposes only parent streams', async () => {
  const process = child(); process.exitCode = 0;
  process.stdout = new PassThrough(); process.stderr = new PassThrough();
  const started = performance.now();
  await assert.rejects(stopChild(process, 5, 5), /stdio closure/);
  assert.ok(performance.now() - started < 250);
  const receipt = childCleanupReceipt(process);
  assert.equal(receipt.status, 'failed'); assert.equal(receipt.closeObserved, false);
  assert.deepEqual(receipt.parentStreamsDisposed, [1, 2]);
  assert.equal(process.stdout.destroyed, true); assert.equal(process.stderr.destroyed, true);
  assert.deepEqual(process.signals, []);
  process.emit('close', 0, null);
  await assert.rejects(stopChild(process, 5, 5), /stdio closure/);
  assert.equal(receipt.closeObserved, false); assert.equal(receipt.status, 'failed');
});

function pipedChild(onKill = () => {}) {
  const process = new EventEmitter();
  Object.assign(process, {exitCode: null, signalCode: null, pid: 42, signals: [], stdout: new PassThrough(), stderr: new PassThrough()});
  process.kill = signal => { process.signals.push(signal); onKill(process, signal); return true; };
  return trackChild(process);
}

test('exit plus every tracked output pipe closing is closure evidence when Node never emits close', async () => {
  // A parent-side IPC disconnect leaves Node's aggregate `close` unemitted forever.
  for (const order of ['exit-first', 'pipes-first']) {
    const process = pipedChild(process => {
      if (order === 'pipes-first') { process.stdout.destroy(); process.stderr.destroy(); }
      setImmediate(() => {
        process.exitCode = 0; process.emit('exit', 0, null);
        if (order === 'exit-first') setImmediate(() => { process.stdout.destroy(); process.stderr.destroy(); });
      });
    });
    const receipt = await stopChild(process, 100, 100);
    assert.equal(receipt.closeObserved, true); assert.equal(receipt.status, 'stopped');
    assert.equal(receipt.parentStreamsDisposed, undefined);
  }
});

test('one still-open output pipe withholds closure evidence and a parent-side disposal never supplies it', async () => {
  const process = pipedChild(process => { process.exitCode = 0; process.emit('exit', 0, null); process.stdout.destroy(); });
  const started = performance.now();
  await assert.rejects(stopChild(process, 5, 5), /stdio closure/);
  assert.ok(performance.now() - started < 250);
  const receipt = childCleanupReceipt(process);
  assert.equal(receipt.status, 'failed'); assert.equal(receipt.closeObserved, false);
  assert.deepEqual(receipt.parentStreamsDisposed, [2]);
  assert.equal(process.stderr.destroyed, true);
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(stopChild(process, 5, 5), /stdio closure/);
  assert.equal(childCleanupReceipt(process).closeObserved, false);
});

test('an unclosed child prevents a successful qualification receipt', async () => {
  const process = child(); process.exitCode = 0; let published = false, failed = false;
  await assert.rejects(runQualification({work:async()=>({passed:true}),timeoutMs:100,
    cleanup:async()=>stopChild(process,5,5), publish:async()=>{published=true;},
    onFailure:async()=>{failed=true;}}), /stdio closure/);
  assert.equal(published,false); assert.equal(failed,true);
});

test('TERM completion succeeds but KILL escalation settles as failure and retains evidence', async () => {
  const normal = child(terminated);
  const resistant = child((process, signal) => { if (signal === 'SIGKILL') terminated(process, signal); });
  await stopChild(normal, 5, 5);
  await assert.rejects(stopChild(resistant, 5, 5), /forced termination/);
  assert.deepEqual(normal.signals, ['SIGTERM']); assert.deepEqual(resistant.signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(resistant.listenerCount('exit'), 0);
  assert.equal(childCleanupReceipt(resistant).forced, true);
  await assert.rejects(stopChild(resistant, 5, 5), /forced termination/);
});

test('concurrent cleanup calls await the same stop and never treat stopping as stopped', async () => {
  const process = child(); let completed = 0;
  const first = stopChild(process,100,100).then(receipt => { completed++; return receipt; });
  const second = stopChild(process,100,100).then(receipt => { completed++; return receipt; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(completed,0); assert.deepEqual(process.signals,['SIGTERM']);
  terminated(process,'SIGTERM');
  const receipts = await Promise.all([first,second]);
  assert.equal(completed,2); assert.equal(receipts[0],receipts[1]);
  assert.equal(receipts[0].status,'stopped');
});

test('failed kill is not mistaken for failed spawn; cleanup has a hard rejection bound', async () => {
  const process = child(process => { process.emit('error', Error('EPERM')); });
  await assert.rejects(stopChild(process, 5, 5), /did not exit/);
  assert.deepEqual(process.signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(childStopped(process), false); assert.equal(process.listenerCount('exit'), 0);
});

test('local server closure handles absence, already closed and an unresponsive close callback', async () => {
  await stopServer(undefined);
  await stopServer({close: done => done(Object.assign(Error('closed'), {code:'ERR_SERVER_NOT_RUNNING'})), closeAllConnections() {}}, 5);
  await assert.rejects(stopServer({close() {}, closeAllConnections() {}}, 5), /did not close/);
});

test('one cleanup failure still stops other owned resources and rejects pending CDP calls', async () => {
  const process = child(terminated); let rejected = 0, serverClosed = false;
  const pending = new Map([[1, {reject() { rejected++; }}]]);
  await assert.rejects(cleanupOwned({children:[process], pending,
    socket:{close() { throw Error('socket failure'); }},
    server:{close(done) { serverClosed = true; done(); }, closeAllConnections() {}},
  }), /cleanup failed/);
  assert.equal(rejected, 1); assert.equal(pending.size, 0); assert.equal(serverClosed, true);
  assert.equal(childStopped(process), true);
});

test('a successful receipt is published strictly after cleanup', async () => {
  const order = [];
  await runQualification({work:async()=>{order.push('work');return {passed:true};},timeoutMs:50,
    cleanup:async()=>{order.push('cleanup');},publish:async result=>{assert.equal(result.passed,true);order.push('receipt');}});
  assert.deepEqual(order,['work','cleanup','receipt']);
});

test('cleanup failure or assertion failure never publishes a success receipt', async () => {
  let published = 0, cleaned = 0;
  const publish = async()=>{published++;};
  await assert.rejects(runQualification({work:async()=>({passed:true}),timeoutMs:50,cleanup:async()=>{cleaned++;throw Error('cleanup failed');},publish}),/cleanup failed/);
  await assert.rejects(runQualification({work:async()=>{throw Error('assertion');},timeoutMs:50,cleanup:async()=>{cleaned++;},publish}),/assertion/);
  assert.equal(published,0);assert.equal(cleaned,2);
});

test('a task completing after the deadline cannot publish a late PASS', async () => {
  let complete, published = 0, cleaned = 0;
  await assert.rejects(runQualification({work:()=>new Promise(resolve=>{complete=resolve;}),timeoutMs:5,
    cleanup:async()=>{cleaned++;},publish:async()=>{published++;}}),/deadline/);
  complete({passed:true});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(cleaned,1);assert.equal(published,0);
});

test('former-writer closure requires success and observed absence before continuation', async () => {
  for (const reply of [undefined, {success:false}]) {
    const methods=[];
    await assert.rejects(closeTargetChecked(async method=>{methods.push(method);return reply;},'old'),/refused/);
    assert.deepEqual(methods,['Target.closeTarget']);
  }
  await assert.rejects(closeTargetChecked(async method=>method==='Target.closeTarget'?{success:true}:{targetInfos:[{targetId:'old'}]},'old',{timeoutMs:5,pollMs:1}),/remains/);
  await assert.rejects(closeTargetChecked(async method=>method==='Target.closeTarget'?{success:true}:{},'old'),/invalid target inventory/);
  const calls=[];
  await closeTargetChecked(async(method,params)=>{calls.push([method,params]);return method==='Target.closeTarget'?{success:true}:{targetInfos:[{targetId:'other'}]};},'old');
  assert.deepEqual(calls,[['Target.closeTarget',{targetId:'old'}],['Target.getTargets',undefined]]);
});

test('deadline aborts delayed setup before cleanup; resumed setup cannot start owned resources', async () => {
  let resume, lateWork, signal, childStarts = 0, serverStarts = 0;
  const delayed = new Promise(resolve => { resume = resolve; });
  await assert.rejects(runQualification({
    work: current => {
      signal = current;
      lateWork = (async () => {
        await delayed;
        // The product launcher uses this guard after file/listen awaits and in start().
        current.throwIfAborted();
        childStarts++; serverStarts++;
      })();
      return lateWork;
    },
    timeoutMs: 5,
    cleanup: async () => { assert.equal(signal.aborted, true); },
    publish: async () => { assert.fail('late publication'); },
  }), /deadline/);
  resume();
  await assert.rejects(lateWork, /closing/);
  assert.equal(childStarts, 0); assert.equal(serverStarts, 0);
});

test('asynchronous target teardown is observed before the restored writer can proceed', async () => {
  let inventories = 0, closed = 0;
  await closeTargetChecked(async method => {
    if (method === 'Target.closeTarget') { closed++; return {success:true}; }
    return {targetInfos: ++inventories < 3 ? [{targetId:'old'}] : []};
  }, 'old', {timeoutMs:100,pollMs:1});
  assert.equal(closed,1); assert.equal(inventories,3);
});

test('a hung close or inventory request cannot continue after the closure deadline', async () => {
  for (const hungMethod of ['Target.closeTarget','Target.getTargets']) {
    let resume; const methods=[];
    await assert.rejects(closeTargetChecked(async method => {
      methods.push(method);
      if (method === hungMethod) return new Promise(resolve => { resume = resolve; });
      return {success:true};
    },'old',{timeoutMs:5,pollMs:1}),/closure.*deadline/);
    const count=methods.length;
    resume(hungMethod === 'Target.closeTarget' ? {success:true} : {targetInfos:[]});
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(methods.length,count);
  }
});

test('interrupts abort active work, persist failure after cleanup, and remove signal listeners', async () => {
  for (const name of ['SIGTERM','SIGHUP','SIGINT']) {
    const events = new EventEmitter(), order = [];
    await assert.rejects(runQualification({
      signals:events, timeoutMs:100,
      work:async signal => {
        signal.addEventListener('abort', () => order.push('abort'));
        events.emit(name); await new Promise(() => {});
      },
      cleanup:async () => { order.push('cleanup'); return {passed:true}; },
      publish:async () => assert.fail('interrupted run published'),
      onFailure:async ({error,cleanup}) => {
        assert.match(error.message, new RegExp(name)); assert.equal(cleanup.passed,true); order.push('failure');
      },
    }), /interrupted/);
    assert.deepEqual(order,['abort','cleanup','failure']);
    assert.equal(events.listenerCount(name),0);
  }
});

test('explicit parent monitoring fails on EOF, prior EOF, error and heartbeat expiry', async () => {
  for (const mode of ['end','prior-end','error','idle']) {
    const input = new PassThrough(); let started = false, cleaned = false;
    if (mode === 'prior-end') input.destroy();
    await assert.rejects(runQualification({
      parentInput:input, parentIdleMs:10, signals:new EventEmitter(), timeoutMs:100,
      work:async signal => {
        started = true;
        if (mode === 'end') input.end();
        if (mode === 'error') input.emit('error', Error('synthetic input error'));
        await new Promise(() => {});
        signal.throwIfAborted();
      },
      cleanup:async () => { cleaned = true; }, publish:async () => assert.fail('parent ended'),
    }), /parent input/);
    assert.equal(cleaned,true);
    assert.equal(started,mode !== 'prior-end');
    for (const event of ['end','close','error','data']) assert.equal(input.listenerCount(event),0);
  }
});

test('parent heartbeats extend only the idle deadline and cannot extend the qualification deadline', async () => {
  const input = new PassThrough(); let heartbeat;
  try {
    await assert.rejects(runQualification({parentInput:input,parentIdleMs:20,timeoutMs:55,signals:new EventEmitter(),
      work:async () => { heartbeat = setInterval(() => input.write('\n'),5); await new Promise(() => {}); },
      cleanup:async () => {}, publish:async () => assert.fail('deadline published'),
    }), /qualification deadline/);
  } finally { clearInterval(heartbeat); }
});

test('an interrupt during cleanup or publication replaces success with retained failure', async () => {
  for (const at of ['cleanup','publish']) {
    const events = new EventEmitter(); let failure = false, published = false;
    await assert.rejects(runQualification({signals:events,timeoutMs:100,work:async () => ({passed:true}),
      cleanup:async () => { if (at === 'cleanup') events.emit('SIGHUP'); return {passed:true}; },
      publish:async () => { published = true; if (at === 'publish') events.emit('SIGHUP'); },
      onFailure:async () => { failure = true; },
    }), /interrupted/);
    assert.equal(failure,true); assert.equal(published,at === 'publish');
  }
});

test('group absence requires ESRCH; permission refusal is not proof and only signal zero is used', () => {
  const calls = [];
  assert.equal(groupAbsent(42,(pid,signal) => { calls.push([pid,signal]); }),false);
  assert.equal(groupAbsent(42,() => { throw Object.assign(Error('gone'),{code:'ESRCH'}); }),true);
  assert.throws(() => groupAbsent(42,() => { throw Object.assign(Error('denied'),{code:'EPERM'}); }),/denied/);
  assert.deepEqual(calls,[[-42,0]]);
});

test('transient group observation denial may be retried but only ESRCH establishes absence', async () => {
  let calls = 0;
  const result = await observeGroupAbsence(42,{timeoutMs:100,pollMs:1,probe:(pid,signal) => {
    assert.equal(pid,-42); assert.equal(signal,0);
    throw Object.assign(Error('synthetic observation'),{code:++calls < 3?'EPERM':'ESRCH'});
  }});
  assert.deepEqual(result,{absent:true,checks:3,permissionDenials:2});
});

test('persistent group observation denial remains a failed absence proof at deadline', async () => {
  const result = await observeGroupAbsence(42,{timeoutMs:5,pollMs:1,probe:() => {
    throw Object.assign(Error('denied'),{code:'EPERM'});
  }});
  assert.equal(result.absent,false); assert.ok(result.permissionDenials > 0);
  assert.equal(result.permissionDenials,result.checks);
  await assert.rejects(observeGroupAbsence(42,{probe:() => { throw Error('unexpected failure'); }}),/unexpected failure/);
});
