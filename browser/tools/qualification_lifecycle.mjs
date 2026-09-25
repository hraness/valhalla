// Custody helpers for isolated local qualification harnesses, never user processes.
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const childStates = new WeakMap();

// Install immediately after spawn so a failed spawn is handled even before cleanup.
export function trackChild(child) {
  if (!childStates.has(child)) {
    const state = {spawnError: null, cleanup:null, closeObserved:false, closeWaiters:[],
      outputsOpen:new Set(), outputsDisposed:false};
    child.on('error', error => { state.spawnError = error; });
    const closed = () => {
      if (state.closeObserved) return;
      state.closeObserved = true;
      for (const waiter of state.closeWaiters.splice(0)) waiter();
    };
    // Node's exit event does not prove that every inherited stdio pipe closed.
    // Observe close from spawn time, including a child which exits before stop.
    child.once('close', closed);
    // Node withholds `close` for good once this parent disconnects the IPC
    // channel itself, even after the child exited and every inherited pipe
    // closed. The inherited pipes are this parent's readable stdio streams, so
    // a recorded exit plus each tracked stream's own closure is equivalent
    // evidence. A stream this parent destroys during failed cleanup never
    // counts, and a child tracked without stdio streams still needs `close`.
    const outputs = (child.stdio ?? [child.stdin, child.stdout, child.stderr]).slice(1)
      .filter(stream => stream && typeof stream.once === 'function');
    state.settle = () => {
      if (childStopped(child) && outputs.length && !state.outputsOpen.size && !state.outputsDisposed) closed();
    };
    for (const stream of outputs) {
      if (stream.closed) continue;
      state.outputsOpen.add(stream);
      stream.once('close', () => { state.outputsOpen.delete(stream); state.settle(); });
    }
    childStates.set(child, state);
  }
  return child;
}

export function childStopped(child) {
  return child.exitCode !== null || child.signalCode !== null ||
    (child.pid === undefined && childStates.get(child)?.spawnError != null);
}

// All commands stay subordinate to a finite IPC guardian. `detached` creates
// its dedicated POSIX group; it is deliberately never unref'd or abandoned.
// `expectedExit` is the only exit status the guardian treats as a normal
// self-exit. `outputPath` sends the command's stdout/stderr to a fresh private
// file instead of this parent's pipes, for commands whose descendants leave
// the group by design and could otherwise hold those pipes open.
export function spawnOwned(executable, args, {role, timeoutMs = 380000, graceMs = 2000, expectedExit = 0, outputPath} = {}) {
  if (!['darwin','linux'].includes(process.platform)) throw Error('owned process groups require macOS or Linux');
  if (typeof executable !== 'string' || !executable.startsWith('/') ||
      !Array.isArray(args) || args.some(arg => typeof arg !== 'string') ||
      typeof role !== 'string' || !/^[a-z0-9-]{1,64}$/.test(role) ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 420000 ||
      !Number.isInteger(graceMs) || graceMs < 1 || graceMs > 10000 ||
      !Number.isInteger(expectedExit) || expectedExit < 0 || expectedExit > 255 ||
      (outputPath !== undefined && (typeof outputPath !== 'string' || !outputPath.startsWith('/') || outputPath.length > 4096))) {
    throw Error('invalid owned command');
  }
  const child = trackChild(spawn(process.execPath,
    [fileURLToPath(new URL('./qualification_process_guardian.mjs', import.meta.url))],
    {detached:true, stdio:['ignore','pipe','pipe','ipc']}));
  const state = childStates.get(child);
  Object.assign(state, {group:child.pid, role, guardian:true, graceMs, expectedExit, outputPath:outputPath ?? null, guardianReceipt:null});
  child.on('message', message => {
    if (message?.type === 'cleanup' && message.receipt?.group === child.pid && message.receipt.role === role) {
      state.guardianReceipt = message.receipt;
    }
  });
  child.send({type:'launch', executable, args, role, timeoutMs, graceMs, expectedExit, outputPath:outputPath ?? null}, error => {
    if (error) state.spawnError = error;
  });
  return child;
}

export function childCleanupReceipt(child) {
  const state = childStates.get(child);
  return state?.cleanup ?? {role:state?.role ?? 'direct-child', pid:child.pid ?? null,
    group:state?.group ?? null, status:'not-confirmed'};
}

// Signal 0 observes existence only; never send a terminating signal through a
// group ID retained after its leader exits. ESRCH is the sole absence evidence.
export function groupAbsent(group, probe = process.kill) {
  if (!Number.isSafeInteger(group) || group <= 1) throw Error('invalid owned process group');
  try { probe(-group, 0); return false; }
  catch (error) { if (error.code === 'ESRCH') return true; throw error; }
}

export async function observeGroupAbsence(group, {timeoutMs = 2000, pollMs = 20, probe = process.kill} = {}) {
  const until = performance.now() + timeoutMs;
  let checks = 0, permissionDenials = 0;
  do {
    checks++;
    try {
      if (groupAbsent(group, probe)) return {absent:true, checks, permissionDenials};
    } catch (error) {
      // macOS can temporarily refuse signal 0 while a killed group is being
      // reaped. A refusal proves nothing; retry only the read-only observation
      // and require an eventual ESRCH within the original cleanup bound.
      if (error.code !== 'EPERM') throw error;
      permissionDenials++;
    }
    if (performance.now() >= until) break;
    await new Promise(resolve => setTimeout(resolve, Math.min(pollMs, Math.max(1, until - performance.now()))));
  } while (performance.now() < until);
  return {absent:false, checks, permissionDenials};
}

async function stopOwned(child, state, killMs) {
  let failure;
  if (!childStopped(child)) {
    await new Promise(resolve => {
      const finished = () => { clearTimeout(timer); child.off('exit', finished); child.off('error', failed); resolve(); };
      const failed = () => { if (childStopped(child)) finished(); };
      // The guardian has its own deadline and disconnect handling. A missing
      // reply fails closed; disconnect requests its independent cleanup path.
      const timer = setTimeout(() => {
        failure = Error('owned guardian did not exit before cleanup deadline');
        if (child.connected) child.disconnect();
        finished();
      }, state.graceMs + killMs + 3000);
      child.once('exit', finished); child.on('error', failed);
      if (childStopped(child)) { finished(); return; }
      if (child.connected) child.send({type:'stop'}, error => { if (error) state.spawnError = error; });
    });
  }
  // The guardian flushes its cleanup receipt before exiting, but this parent
  // can observe the exit before that last message is read. Wait, bounded, for
  // the receipt or the channel's closure before judging the evidence.
  if (!state.guardianReceipt && child.connected) {
    await new Promise(resolve => {
      const done = () => { clearTimeout(timer); child.off('disconnect', done); child.off('message', arrived); resolve(); };
      const arrived = () => { if (state.guardianReceipt) done(); };
      const timer = setTimeout(done, killMs);
      child.on('message', arrived); child.once('disconnect', done);
      if (state.guardianReceipt || !child.connected) done();
    });
  }
  let absent = state.group === undefined && childStopped(child);
  let observation;
  try {
    if (!absent) {
      observation = await observeGroupAbsence(state.group, {timeoutMs:killMs});
      absent = observation.absent;
    }
  } catch (error) { failure ??= error; }
  const receipt = state.guardianReceipt;
  state.cleanup = {role:state.role, pid:child.pid ?? null, group:state.group ?? null,
    status:'failed', groupAbsent:absent, leaderStopped:childStopped(child),
    exitCode:child.exitCode, signal:child.signalCode, observation, guardian:receipt};
  if (!absent) failure ??= Error('owned process group absence was not confirmed');
  if (!receipt) failure ??= Error('owned guardian cleanup evidence is missing');
  if (receipt?.forced) failure ??= Error('owned process group required forced termination');
  if (receipt?.failure) failure ??= Error(receipt.failure);
  if (child.exitCode !== 0) failure ??= Error('owned guardian exited unsuccessfully');
  if (failure) { state.cleanup.failure = failure.message; throw failure; }
  state.cleanup.status = 'stopping';
  return state.cleanup;
}

export async function stopChild(child, graceMs = 2000, killMs = 2000) {
  trackChild(child);
  const state = childStates.get(child);
  state.stopping ??= finishChildStop(child, state, graceMs, killMs);
  return state.stopping;
}

async function observeChildClose(state, timeoutMs) {
  state.settle();
  if (state.closeObserved) return true;
  return new Promise(resolve => {
    const waiter = () => { clearTimeout(timer); resolve(true); };
    const timer = setTimeout(() => {
      const index = state.closeWaiters.indexOf(waiter);
      if (index >= 0) state.closeWaiters.splice(index, 1);
      resolve(false);
    }, timeoutMs);
    state.closeWaiters.push(waiter);
  });
}

async function finishChildStop(child, state, graceMs, killMs) {
  let failure;
  try {
    await (state.guardian ? stopOwned(child, state, killMs) : stopDirect(child, state, graceMs, killMs));
  } catch (error) { failure = error; }
  // The closure wait is finite and recorded in the receipt.
  const closeDeadlineMs = killMs;
  const closeStarted = performance.now();
  const closed = await observeChildClose(state, closeDeadlineMs);
  const receipt = state.cleanup ??= {role:state.role ?? 'direct-child', pid:child.pid ?? null,
    group:state.group ?? null, status:'failed', exitCode:child.exitCode, signal:child.signalCode};
  receipt.closeObserved = closed;
  receipt.closeDeadlineMs = closeDeadlineMs;
  receipt.closeWaitMs = Math.round(performance.now() - closeStarted);
  if (!closed) {
    failure ??= Error('owned child stdio closure was not observed before cleanup deadline');
    // Dispose only this parent's FDs after latching failed evidence. An escaped
    // pipe holder is not thereby proved dead, and a later close cannot turn
    // this cached failure into success. Never signal a saved descendant PID.
    receipt.parentStreamsDisposed = [];
    state.outputsDisposed = true;
    const streams = child.stdio ?? [child.stdin, child.stdout, child.stderr];
    for (const [index, stream] of streams.entries()) {
      if (!stream || typeof stream.destroy !== 'function' || stream.destroyed) continue;
      try { stream.destroy(); receipt.parentStreamsDisposed.push(index); }
      catch { receipt.parentStreamDisposalFailed = true; }
    }
    if (child.connected) {
      try { child.disconnect(); receipt.parentIpcDisconnected = true; }
      catch { receipt.parentIpcDisconnectFailed = true; }
    }
  }
  if (failure) {
    receipt.status = 'failed'; receipt.failure = failure.message;
    throw failure;
  }
  receipt.status = 'stopped';
  return receipt;
}

async function stopDirect(child, state, graceMs, killMs) {
  if (state.cleanup) {
    if (state.cleanup.failure) throw Error(state.cleanup.failure);
    return state.cleanup;
  }
  state.cleanup = {role:'direct-child', pid:child.pid ?? null, group:null, status:'stopping', forced:false};
  const settle = () => {
    state.cleanup.exitCode = child.exitCode; state.cleanup.signal = child.signalCode;
    state.cleanup.status = state.cleanup.failure ? 'failed' : 'stopping';
  };
  if (childStopped(child)) { settle(); return state.cleanup; }
  try { await new Promise((resolve, reject) => {
    let grace, deadline, finished = false, forced = false;
    const finish = error => {
      if (finished) return;
      finished = true;
      clearTimeout(grace); clearTimeout(deadline);
      child.off('exit', exited); child.off('error', failed);
      if (forced) error ??= Error('owned child required forced termination');
      error ? reject(error) : resolve();
    };
    const exited = () => finish();
    const failed = error => {
      if (childStopped(child)) finish();
      // A kill error does not prove that a previously spawned child has exited.
      else if (child.pid === undefined) finish(error);
    };
    const signal = name => {
      try { child.kill(name); } catch (error) { failed(error); }
    };
    child.once('exit', exited); child.on('error', failed);
    // Recheck after registering listeners, including an already signaled exit.
    if (childStopped(child)) { finish(); return; }
    grace = setTimeout(() => {
      if (childStopped(child)) { finish(); return; }
      forced = true; state.cleanup.forced = true;
      signal('SIGKILL');
    }, graceMs);
    deadline = setTimeout(() => {
      if (childStopped(child)) finish();
      else finish(Error('owned child did not exit after SIGTERM/SIGKILL'));
    }, graceMs + killMs);
    signal('SIGTERM');
  }); } catch (error) { state.cleanup.failure = error.message; throw error; }
  finally { settle(); }
  return state.cleanup;
}

export async function stopServer(server, timeoutMs = 2000) {
  if (!server) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('local qualification server did not close')), timeoutMs);
    const done = error => {
      clearTimeout(timer);
      if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error);
      else resolve();
    };
    try {
      server.close(done);
      server.closeAllConnections?.();
    } catch (error) { done(error); }
  });
}

export async function cleanupOwned({children, server, servers = [], socket, pending}) {
  const failures = [];
  try { socket?.close(); } catch (error) { failures.push(error); }
  for (const waiter of pending.values()) {
    try { waiter.reject(Error('qualification closing')); } catch (error) { failures.push(error); }
  }
  pending.clear();
  // A failure to stop one resource must not skip the other owned resources.
  const results = await Promise.allSettled([...children.map(child => stopChild(child)), ...[server, ...servers].map(value => stopServer(value))]);
  for (const result of results) if (result.status === 'rejected') failures.push(result.reason);
  const receipt = {passed:failures.length === 0, children:children.map(childCleanupReceipt),
    failures:failures.map(error => error.message)};
  if (failures.length) {
    const error = new AggregateError(failures, 'qualification cleanup failed');
    error.cleanupReceipt = receipt; throw error;
  }
  return receipt;
}

// No successful receipt can be published by a late task after a deadline, or
// before owned-process/server cleanup has succeeded. Work must check the supplied
// signal immediately before creating resources after any asynchronous setup.
export async function runQualification({work, timeoutMs, cleanup, publish, onFailure,
  parentInput, parentIdleMs = 45000, signals = process}) {
  if (parentInput && (!Number.isInteger(parentIdleMs) || parentIdleMs < 1 || parentIdleMs > 60000)) {
    throw Error('invalid parent input idle deadline');
  }
  const controller = new AbortController();
  let timer, idleTimer, result, failure, failed = false, cleanupReceipt, interruptReject;
  const interrupt = reason => {
    const error = Error(reason);
    if (!failed) { failed = true; failure = error; }
    controller.abort(error); interruptReject?.(error);
  };
  const handlers = new Map(['SIGTERM','SIGHUP','SIGINT'].map(name => [name, () => interrupt('qualification interrupted: '+name)]));
  for (const [name, handler] of handlers) signals.on(name, handler);
  const ended = () => interrupt('qualification parent input ended');
  const inputError = () => interrupt('qualification parent input failed');
  const heartbeat = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => interrupt('qualification parent input idle deadline'), parentIdleMs);
  };
  parentInput?.once('end', ended); parentInput?.once('close', ended); parentInput?.once('error', inputError);
  parentInput?.on('data', heartbeat);
  if (parentInput) heartbeat();
  if (parentInput?.readableEnded || parentInput?.destroyed) ended();
  parentInput?.resume();
  try {
    result = await Promise.race([
      Promise.resolve().then(() => { controller.signal.throwIfAborted(); return work(controller.signal); }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error('qualification deadline')), timeoutMs); }),
      new Promise((_, reject) => { interruptReject = reject; }),
    ]);
  } catch (error) { failed = true; failure = error; }
  finally {
    clearTimeout(timer);
    // Latch closure before cleanup snapshots the resources created so far.
    controller.abort(Error('qualification closing'));
  }
  try {
    try { cleanupReceipt = await cleanup(); }
    catch (error) { cleanupReceipt = error.cleanupReceipt; failure = failed ? new AggregateError([failure, error], 'qualification and cleanup failed') : error; failed = true; }
    if (!failed) {
      try { await publish(result, cleanupReceipt); }
      catch (error) { failure = error; failed = true; }
    }
    if (failed) { await onFailure?.({error:failure, cleanup:cleanupReceipt}); throw failure; }
  } finally {
    for (const [name, handler] of handlers) signals.off(name, handler);
    parentInput?.off('end', ended); parentInput?.off('close', ended); parentInput?.off('error', inputError);
    parentInput?.off('data', heartbeat); clearTimeout(idleTimer);
    parentInput?.pause();
  }
}

export async function closeTargetChecked(call, targetId, {timeoutMs = 2000, pollMs = 20} = {}) {
  let timer, stopped = false;
  const observe = async () => {
    const closed = await call('Target.closeTarget', {targetId});
    if (stopped) return;
    if (closed?.success !== true) throw Error('browser refused to close the selected target');
    // CDP acknowledges the close request before asynchronous target teardown
    // necessarily disappears from getTargets. Require observed absence, with
    // a deadline, before the restored writer is allowed to proceed.
    while (!stopped) {
      const targets = await call('Target.getTargets');
      if (stopped) return;
      if (!Array.isArray(targets?.targetInfos)) throw Error('browser returned invalid target inventory');
      if (!targets.targetInfos.some(target => target.targetId === targetId)) return;
      await new Promise(resolve => setTimeout(resolve, pollMs));
    }
  };
  try {
    await Promise.race([
      observe(),
      new Promise((_, reject) => { timer = setTimeout(() => {
        stopped = true;
        reject(Error('selected browser target remains or its closure was not confirmed before deadline'));
      }, timeoutMs); }),
    ]);
  } finally { stopped = true; clearTimeout(timer); }
}
