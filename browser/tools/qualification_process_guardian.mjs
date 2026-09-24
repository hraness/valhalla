// A finite subordinate supervisor for POSIX qualification processes. The parent
// retains its IPC channel and never unrefs this process. Only this live group
// leader signals the group it currently belongs to: no saved/reused PID is used
// for destructive signaling after a leader exits.
import {spawn, execFileSync} from 'node:child_process';
import {openSync, closeSync} from 'node:fs';

if (!process.send || !['darwin', 'linux'].includes(process.platform)) {
  throw Error('qualification process guardian requires POSIX IPC custody');
}
if (Number(execFileSync('/bin/ps', ['-p', String(process.pid), '-o', 'pgid='],
  {encoding:'utf8', timeout:1000, maxBuffer:1024}).trim()) !== process.pid) {
  throw Error('qualification guardian does not own its process group');
}

let child, deadline, stopping = false, started = false, leaderExit;
let graceMs = 2000, expectedExit = 0, role = 'unconfigured', outputPath = null, observed = new Set();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const send = message => new Promise(resolve => {
  if (!process.connected) { resolve(); return; }
  const timer = setTimeout(resolve, 1000);
  try { process.send(message, () => { clearTimeout(timer); resolve(); }); }
  catch { clearTimeout(timer); resolve(); }
});

// Read-only, bounded inventory. Only rows in our dedicated group are retained;
// no process found through this inventory is ever individually signaled.
async function members() {
  const probe = spawn('/bin/ps', ['-axo', 'pid=,pgid='], {stdio:['ignore', 'pipe', 'pipe']});
  let output = '', overflow = false;
  probe.stdout.on('data', bytes => {
    if (output.length + bytes.length > 4 * 1024 * 1024) { overflow = true; probe.kill(); }
    else output += bytes;
  });
  probe.stderr.resume();
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { probe.kill('SIGKILL'); reject(Error('process inventory deadline')); }, 1000);
    probe.once('error', error => { clearTimeout(timer); reject(error); });
    probe.once('close', code => { clearTimeout(timer); code === 0 && !overflow ? resolve() : reject(Error('process inventory refused')); });
  });
  const result = [];
  for (const row of output.trim().split('\n')) {
    const match = /^\s*([0-9]+)\s+([0-9]+)\s*$/.exec(row);
    if (!match) throw Error('invalid process inventory');
    const pid = Number(match[1]), group = Number(match[2]);
    if (group === process.pid && pid !== process.pid && pid !== probe.pid) {
      result.push(pid); observed.add(pid);
    }
  }
  return result;
}

async function finish(cause, failure) {
  if (stopping) return;
  stopping = true; clearTimeout(deadline);
  const receipt = {role, group:process.pid, leader:child?.pid ?? null, cause,
    graceMs, expectedExit, output:outputPath, forced:false, remaining:[], observedMembers:[], leaderExit:null};
  try {
    receipt.remaining = await members();
    // Include all descendants that still share our group, even after their
    // direct parent exited. Our own TERM handler deliberately keeps us alive.
    process.kill(0, 'SIGTERM');
    const until = performance.now() + graceMs;
    do {
      receipt.remaining = await members();
      if (!receipt.remaining.length && (!child || leaderExit)) break;
      await sleep(20);
    } while (performance.now() < until);
    receipt.leaderExit = leaderExit ?? null;
    receipt.observedMembers = [...observed].sort((a,b) => a-b);
    if (failure) receipt.failure = failure;
    if (receipt.remaining.length || (child && !leaderExit)) {
      receipt.forced = true;
      receipt.failure ??= 'owned group did not stop within grace period';
      await send({type:'cleanup', receipt});
      // This is our current group, anchored by this executing process. Record
      // intent before KILL; the parent independently checks group absence.
      process.kill(0, 'SIGKILL');
      return;
    }
    // Only the exit status declared at launch is a normal self-exit; a stop
    // requested by the parent may also end in a clean SIGTERM.
    const normal = leaderExit?.code === expectedExit || (cause !== 'leader-exit' && leaderExit?.signal === 'SIGTERM');
    if (child && !normal) receipt.failure ??= 'owned command exited unsuccessfully';
    await send({type:'cleanup', receipt});
    process.exit(receipt.failure ? 1 : 0);
  } catch (error) {
    receipt.forced = true;
    receipt.failure = error.message;
    receipt.leaderExit = leaderExit ?? null;
    receipt.observedMembers = [...observed].sort((a,b) => a-b);
    await send({type:'cleanup', receipt});
    process.kill(0, 'SIGKILL');
  }
}

for (const name of ['SIGTERM','SIGINT','SIGHUP']) process.on(name, () => { void finish(name); });
process.on('disconnect', () => { void finish('parent-disconnect'); });
// A parent which never sends the launch message cannot leave an idle guardian.
deadline = setTimeout(() => { void finish('configuration-deadline', 'configuration deadline'); }, 5000);
process.on('message', message => {
  if (message?.type === 'stop') { void finish('parent-stop'); return; }
  if (message?.type !== 'launch' || started || stopping) return;
  started = true;
  const {executable, args, timeoutMs} = message;
  role = message.role;
  graceMs = message.graceMs;
  expectedExit = message.expectedExit ?? 0;
  outputPath = message.outputPath ?? null;
  if (typeof executable !== 'string' || !executable.startsWith('/') ||
      !Array.isArray(args) || args.some(arg => typeof arg !== 'string') ||
      typeof role !== 'string' || !/^[a-z0-9-]{1,64}$/.test(role) ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 420000 ||
      !Number.isInteger(graceMs) || graceMs < 1 || graceMs > 10000 ||
      !Number.isInteger(expectedExit) || expectedExit < 0 || expectedExit > 255 ||
      (outputPath !== null && (typeof outputPath !== 'string' || !outputPath.startsWith('/') || outputPath.length > 4096))) {
    void finish('invalid-configuration', 'invalid guardian configuration'); return;
  }
  clearTimeout(deadline);
  deadline = setTimeout(() => { void finish('deadline', 'owned command deadline'); }, timeoutMs);
  // A command whose descendants leave the owned group by design (a browser's
  // crash handler or updater) and outlive it writes to a fresh private file
  // rather than inheriting the parent's pipes, so no escaped holder can
  // withhold the parent's closure evidence. The file is created here
  // exclusively, mode 0600; the guardian keeps no descriptor for it.
  let output = null;
  if (outputPath !== null) {
    try { output = openSync(outputPath, 'wx', 0o600); }
    catch (error) { void finish('output-error', 'owned command output file was not created: ' + (error.code ?? 'error')); return; }
  }
  try { child = spawn(executable, args, {stdio:['ignore', output ?? 1, output ?? 2], detached:false}); }
  finally { if (output !== null) closeSync(output); }
  child.once('error', error => { child = undefined; void finish('spawn-error', error.code ?? 'spawn failed'); });
  child.once('exit', (code, signal) => { leaderExit = {code, signal}; void finish('leader-exit'); });
  void send({type:'started', leader:child.pid, group:process.pid});
});
