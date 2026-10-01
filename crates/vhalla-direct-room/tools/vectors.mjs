// Independent Node-compatible Ed25519/SHA-256 encoder for frozen protocol bytes.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const file = fileURLToPath(new URL('../../../vectors/direct-room-v1.txt', import.meta.url));
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const concat = (...parts) => Buffer.concat(parts);
const domain = (kind) => Buffer.from(`vhalla/direct-room/${kind}/v1\0`);
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const privateKey = (n) => createPrivateKey({
  key: concat(Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, n)),
  format: 'der', type: 'pkcs8',
});
const publicKey = (key) => createPublicKey(key).export({ type: 'spki', format: 'der' }).subarray(-32);
const owner = privateKey(1), author = privateKey(2);
const ownerKey = publicKey(owner), authorKey = publicKey(author);
const writers = [ownerKey, authorKey].sort(Buffer.compare);
function record(kind, unsigned, key) {
  const transcript = concat(domain(kind), unsigned);
  const signature = sign(null, transcript, key);
  return { unsigned, signature, signed: concat(unsigned, signature), id: hash(transcript) };
}
const genesis = record('genesis', concat(
  Buffer.from('VHDG\x01'), ownerKey, Buffer.alloc(32, 9), u16(2), ...writers,
), owner);
const initialPolicy = hash(concat(Buffer.from('vhalla/direct-room/policy-root/v1\0'), genesis.id));
const text = Buffer.from('hello from a direct room');
const event = record('event', concat(
  Buffer.from('VHDE\x01'), genesis.id, initialPolicy, authorKey,
  u64(1), Buffer.alloc(32), u64(1234), u32(text.length), text,
), author);
const policy = record('policy', concat(
  Buffer.from('VHDP\x01'), genesis.id, ownerKey, u64(1), initialPolicy,
  u16(1), ownerKey, u16(1), authorKey, u64(1), event.id,
), owner);
const lines = ['# Valhalla direct-room v1; fixture seeds are 32 bytes of 01 and 02.',
  `initial_policy=${initialPolicy.toString('hex')}`];
for (const [name, fields] of Object.entries({ genesis, event, policy })) {
  for (const [field, bytes] of Object.entries(fields)) lines.push(`${name}_${field}=${bytes.toString('hex')}`);
}
const expected = `${lines.join('\n')}\n`;
if (process.argv.slice(2).join(' ') === '--write') {
  writeFileSync(file, expected);
  process.stdout.write('Wrote direct-room v1 vectors.\n');
} else if (process.argv.length <= 2 || process.argv.slice(2).join(' ') === '--check') {
  if (readFileSync(file, 'utf8') !== expected) throw new Error('Direct-room bytes differ from the frozen independent vectors');
  process.stdout.write('Direct-room v1 vectors match independent Ed25519/SHA-256 encoding.\n');
} else {
  throw new Error('Usage: vectors.mjs [--check|--write]');
}
