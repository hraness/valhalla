// Custody helpers for isolated local qualification harnesses, never user processes.
const childStates = new WeakMap();

// Install immediately after spawn so a failed spawn is handled even before cleanup.
export function trackChild(child) {
  if (!childStates.has(child)) {
    const state = {spawnError: null};
    child.on('error', error => { state.spawnError = error; });
    childStates.set(child, state);
  }
  return child;
}

export function childStopped(child) {
  return child.exitCode !== null || child.signalCode !== null ||
    (child.pid === undefined && childStates.get(child)?.spawnError != null);
}

export async function stopChild(child, graceMs = 2000, killMs = 2000) {
  trackChild(child);
  if (childStopped(child)) return;
  await new Promise((resolve, reject) => {
    let grace, deadline, finished = false;
    const finish = error => {
      if (finished) return;
      finished = true;
      clearTimeout(grace); clearTimeout(deadline);
      child.off('exit', exited); child.off('error', failed);
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
      signal('SIGKILL');
    }, graceMs);
    deadline = setTimeout(() => {
      if (childStopped(child)) finish();
      else finish(Error('owned child did not exit after SIGTERM/SIGKILL'));
    }, graceMs + killMs);
    signal('SIGTERM');
  });
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
      server.closeAllConnections();
    } catch (error) { done(error); }
  });
}

export async function cleanupOwned({children, server, socket, pending}) {
  const failures = [];
  try { socket?.close(); } catch (error) { failures.push(error); }
  for (const waiter of pending.values()) waiter.reject(Error('qualification closing'));
  pending.clear();
  // A failure to stop one resource must not skip the other owned resources.
  const results = await Promise.allSettled([...children.map(child => stopChild(child)), stopServer(server)]);
  for (const result of results) if (result.status === 'rejected') failures.push(result.reason);
  if (failures.length) throw new AggregateError(failures, 'qualification cleanup failed');
}

// No successful receipt can be published by a late task after a deadline, or
// before owned-process/server cleanup has succeeded. Work must check the supplied
// signal immediately before creating resources after any asynchronous setup.
export async function runQualification({work, timeoutMs, cleanup, publish}) {
  const controller = new AbortController();
  let timer, result, failure, failed = false;
  try {
    result = await Promise.race([
      Promise.resolve().then(() => work(controller.signal)),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error('qualification deadline')), timeoutMs); }),
    ]);
  } catch (error) { failed = true; failure = error; }
  finally {
    clearTimeout(timer);
    // Latch closure before cleanup snapshots the resources created so far.
    controller.abort(Error('qualification closing'));
  }
  try { await cleanup(); }
  catch (error) { failure = failed ? new AggregateError([failure, error], 'qualification and cleanup failed') : error; failed = true; }
  if (failed) throw failure;
  await publish(result);
}

export async function closeTargetChecked(call, targetId) {
  const closed = await call('Target.closeTarget', {targetId});
  if (closed?.success !== true) throw Error('browser refused to close the selected target');
  const targets = await call('Target.getTargets');
  if (!Array.isArray(targets?.targetInfos) || targets.targetInfos.some(target => target.targetId === targetId)) {
    throw Error('selected browser target remains after close');
  }
}
