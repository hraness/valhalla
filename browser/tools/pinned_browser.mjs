import {rm} from 'node:fs/promises';
import {cleanupOwned} from './qualification_lifecycle.mjs';
import {assertBrowserArgs, assertBrowserVersion} from '../../site/tools/browser-contract.mjs';

export {resolvePinnedBrowser, requiredBrowserArgs} from '../../site/tools/browser-contract.mjs';

export async function verifyPinnedBrowser(call, browser, profile) {
  const version = await call('Browser.getVersion');
  const browserVersion = assertBrowserVersion(version.product, browser.expectedVersion);
  const args = (await call('Browser.getBrowserCommandLine')).arguments;
  assertBrowserArgs(args, profile);
  const identity = {...browser, browserVersion, args};
  console.log(JSON.stringify({browser: identity}));
  return identity;
}

// Cleanup runs after runQualification latches its abort signal. Use a separate
// CDP id so that a driver's aborted command queue cannot suppress Browser.close.
export async function closePinnedBrowser(socket, child, timeoutMs = 5000) {
  if (!socket || socket.readyState !== 1) throw Error('Owned browser has no open connection for graceful closure.');
  if (!child || child.exitCode !== null || child.signalCode !== null) throw Error('Owned browser exited before graceful closure.');
  await new Promise((resolve, reject) => {
    let timer;
    const finish = error => {
      clearTimeout(timer);
      child.off('exit', exited);
      socket.removeEventListener('message', message);
      error ? reject(error) : resolve();
    };
    const exited = (code, signal) => finish(code === 0 && signal == null
      ? undefined : Error('Owned browser did not exit normally after Browser.close.'));
    const message = event => {
      let response;
      try { response = JSON.parse(event.data); } catch { return; }
      if (response.id === -2147483648 && response.error) finish(Error('Owned browser rejected Browser.close.'));
    };
    child.once('exit', exited);
    socket.addEventListener('message', message);
    timer = setTimeout(() => finish(Error('Owned browser did not finish graceful closure.')), timeoutMs);
    try { socket.send(JSON.stringify({id: -2147483648, method: 'Browser.close'})); }
    catch (error) { finish(error); }
  });
}

export async function cleanupPinnedBrowser({browserChild, profile, ...options}) {
  const failures = [];
  let graceful = false, cleanup;
  if (browserChild) {
    try { await closePinnedBrowser(options.socket, browserChild); graceful = true; }
    catch (error) { failures.push(error); }
  }
  // A failed close never skips the existing process, pipe and server custody
  // checks. Preserve their receipt, and do not remove a live browser's profile.
  try { cleanup = await cleanupOwned(options); }
  catch (error) { cleanup = error.cleanupReceipt; failures.push(error); }
  let profileRemoved = false;
  if (cleanup?.passed && profile) {
    try { await rm(profile, {recursive: true, force: true}); profileRemoved = true; }
    catch (error) { failures.push(error); }
  }
  const receipt = {...cleanup, passed: cleanup?.passed === true && failures.length === 0, browserClosedGracefully: graceful, profileRemoved};
  if (failures.length) {
    const error = new AggregateError(failures, 'Pinned browser cleanup failed');
    error.cleanupReceipt = receipt;
    throw error;
  }
  return receipt;
}
