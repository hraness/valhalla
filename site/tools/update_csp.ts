// Rewrites the script-src hashes in vercel.json from the rendered pages.
// Every page carries one JSON-LD block, and the CSP admits each block by its
// SHA-256, so any change to a page title, summary or home FAQ answer changes a
// hash. Run from the repository root: bun site/tools/update_csp.ts
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { docs } from '../pages.ts';
import { compare } from '../compare.ts';
import { writing } from '../writing.ts';
import { renderDoc, renderCompare, renderUseCases, renderWriting } from '../docs.ts';
import { renderHome } from '../home.ts';

const vercelPath = new URL('../../vercel.json', import.meta.url);
const index = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const pages = [renderHome(index), ...docs.map(page => renderDoc(page, index)), ...compare.map(page => renderCompare(page, index)), ...writing.map(page => renderWriting(page, index)), renderUseCases(index)];
const hashes = pages.map(html => {
  const blocks = [...html.matchAll(/<script type="application\/ld\+json">(.+?)<\/script>/g)];
  if (blocks.length !== 1) throw new Error(`Expected one JSON-LD block, found ${blocks.length}`);
  return `'sha256-${createHash('sha256').update(blocks[0][1], 'utf8').digest('base64')}'`;
});
const text = await readFile(vercelPath, 'utf8');
const updated = text.replace(/script-src 'self'(?: 'sha256-[A-Za-z0-9+/=]+')*;/, () => `script-src 'self' ${hashes.join(' ')};`);
if (updated === text) console.log('vercel.json CSP already matches the rendered pages.');
else {
  await writeFile(vercelPath, updated);
  console.log(`Wrote ${hashes.length} JSON-LD hashes to vercel.json.`);
}
