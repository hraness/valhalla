// Independent SHA-256 encoder over the frozen direct-room signed wire fixtures.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const roomFile = fileURLToPath(new URL('../../../vectors/direct-room-v1.txt', import.meta.url));
const output = fileURLToPath(new URL('../tests/snapshot-v1.txt', import.meta.url));
const fields = Object.fromEntries(readFileSync(roomFile, 'utf8').split('\n')
  .filter((line) => line.includes('='))
  .map((line) => line.split('=')));
const raw = (name) => Buffer.from(fields[name], 'hex');
const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const u64 = (n) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(n)); return bytes; };
const source = raw('genesis_unsigned').subarray(5, 37);
const room = raw('genesis_id');
const epoch = Buffer.alloc(32, 8);
let digest = sha256(Buffer.from('vhalla/direct-sync/source/v1\0'), source, room, epoch);
const lines = ['# Valhalla direct-sync v1; independent SHA-256 over direct-room-v1.txt.',
  `source=${source.toString('hex')}`, `epoch=${epoch.toString('hex')}`, `seed=${digest.toString('hex')}`];
let count = 0;
let bytes = 0;
for (const [kind, name] of [[1, 'genesis_signed'], [3, 'event_signed'], [2, 'policy_signed']]) {
  const frame = raw(name);
  count += 1;
  bytes += frame.length;
  digest = sha256(Buffer.from('vhalla/direct-sync/frame/v1\0'), digest,
    u64(count), Buffer.from([kind]), u64(frame.length), sha256(frame));
  lines.push(`prefix_${count}=${digest.toString('hex')}`);
}
const checkpoint = sha256(Buffer.from('vhalla/direct-sync/checkpoint/v1\0'), source,
  room, epoch, u64(count), u64(bytes), digest);
lines.push(`checkpoint_id=${checkpoint.toString('hex')}`);
const expected = `${lines.join('\n')}\n`;
if (process.argv.slice(2).join(' ') === '--write') {
  writeFileSync(output, expected);
  process.stdout.write('Wrote direct-sync v1 vector.\n');
} else if (process.argv.length <= 2 || process.argv.slice(2).join(' ') === '--check') {
  if (readFileSync(output, 'utf8') !== expected) throw new Error('Direct-sync snapshot differs from independent SHA-256 encoding');
  process.stdout.write('Direct-sync v1 vector matches independent SHA-256 encoding.\n');
} else {
  throw new Error('Usage: vectors.mjs [--check|--write]');
}
