import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {trackChild, childStopped, stopChild, stopServer, cleanupOwned, runQualification, closeTargetChecked} from './qualification_lifecycle.mjs';

function child(onKill = () => {}) {
  const process = new EventEmitter();
  Object.assign(process, {exitCode: null, signalCode: null, pid: 42, signals: []});
  process.kill = signal => { process.signals.push(signal); onKill(process, signal); return true; };
  return trackChild(process);
}
const terminated = (process, signal) => { process.signalCode = signal; process.emit('exit', null, signal); };

test('an already signal-exited child never waits on a past exit event or signals a reused PID', async () => {
  const process = child(); terminated(process, 'SIGKILL');
  assert.equal(process.exitCode, null); assert.equal(childStopped(process), true);
  await stopChild(process, 5, 5); assert.deepEqual(process.signals, []);
});

test('already normal-exited and failed-spawn children are settled', async () => {
  const normal = child(); normal.exitCode = 0;
  const failed = child(); failed.pid = undefined; failed.emit('error', Error('ENOENT'));
  await Promise.all([stopChild(normal, 5, 5), stopChild(failed, 5, 5)]);
  assert.deepEqual(normal.signals, []); assert.deepEqual(failed.signals, []);
});

test('successful TERM completion and KILL escalation both settle and remove temporary listeners', async () => {
  const normal = child(terminated);
  const resistant = child((process, signal) => { if (signal === 'SIGKILL') terminated(process, signal); });
  await Promise.all([stopChild(normal, 5, 5), stopChild(resistant, 5, 5)]);
  assert.deepEqual(normal.signals, ['SIGTERM']); assert.deepEqual(resistant.signals, ['SIGTERM', 'SIGKILL']);
  assert.equal(resistant.listenerCount('exit'), 0);
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
