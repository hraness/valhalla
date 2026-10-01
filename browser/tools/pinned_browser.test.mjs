import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import test from 'node:test';
import {cleanupPinnedBrowser, closePinnedBrowser, verifyPinnedBrowser} from './pinned_browser.mjs';

function fixture(onSend) {
  const child = Object.assign(new EventEmitter(), {exitCode: null, signalCode: null});
  const socket = Object.assign(new EventTarget(), {readyState: 1, send: value => onSend(JSON.parse(value), child, socket)});
  return {child, socket};
}

test('graceful closure waits for normal process exit, independent of the driver command queue', async () => {
  const {child, socket} = fixture((command, process) => {
    assert.equal(command.method, 'Browser.close');
    assert.ok(command.id < 0);
    setImmediate(() => { process.exitCode = 0; process.emit('exit', 0, null); });
  });
  await closePinnedBrowser(socket, child);
  assert.equal(child.listenerCount('exit'), 0);
});

test('a protocol rejection, abnormal exit and missing close each fail closure', async () => {
  const rejected = fixture((command, _, socket) => setImmediate(() => socket.dispatchEvent(new MessageEvent('message', {data: JSON.stringify({id: command.id, error: {message: 'refused'}})}))));
  await assert.rejects(closePinnedBrowser(rejected.socket, rejected.child), /rejected Browser.close/);
  const abnormal = fixture((_, child) => setImmediate(() => { child.signalCode = 'SIGTERM'; child.emit('exit', null, 'SIGTERM'); }));
  await assert.rejects(closePinnedBrowser(abnormal.socket, abnormal.child), /did not exit normally/);
  const hanging = fixture(() => {});
  await assert.rejects(closePinnedBrowser(hanging.socket, hanging.child, 10), /did not finish graceful closure/);
  for (const item of [rejected, abnormal, hanging]) assert.equal(item.child.listenerCount('exit'), 0);
});

test('a disconnected or previously exited browser cannot claim graceful closure', async () => {
  const {child, socket} = fixture(() => assert.fail('must not send'));
  socket.readyState = 3;
  await assert.rejects(closePinnedBrowser(socket, child), /no open connection/);
  socket.readyState = 1;
  child.exitCode = 0;
  await assert.rejects(closePinnedBrowser(socket, child), /exited before graceful closure/);
});

test('runtime verification checks both the physical version and owned launch arguments', async () => {
  const browser = {executablePath: '/owned/chromium-1243/chrome', expectedVersion: '153.0.8010.12'};
  const args = ['--mute-audio', '--disable-features=PaintHolding,MacAppCodeSignClone', '--user-data-dir=/owned/profile'];
  const call = async method => method === 'Browser.getVersion' ? {product: 'Chrome/153.0.8010.12'} : {arguments: args};
  const identity = await verifyPinnedBrowser(call, browser, '/owned/profile');
  assert.equal(identity.browserVersion, browser.expectedVersion);
  await assert.rejects(verifyPinnedBrowser(call, {...browser, expectedVersion: '153.0.8010.13'}, '/owned/profile'), /running browser must match/);
  await assert.rejects(verifyPinnedBrowser(call, browser, '/another/profile'), /owned temporary profile/);
});

test('a failed graceful close cannot publish successful cleanup even when custody succeeds', async () => {
  await assert.rejects(cleanupPinnedBrowser({
    browserChild: {exitCode: 0, signalCode: null},
    children: [], pending: new Map(),
  }), error => {
    assert.equal(error.cleanupReceipt.passed, false);
    assert.equal(error.cleanupReceipt.browserClosedGracefully, false);
    assert.deepEqual(error.cleanupReceipt.children, []);
    return true;
  });
});
