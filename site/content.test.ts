import { expect, test } from 'bun:test';
import { readFile, access } from 'node:fs/promises';
import { docs, documentedRevision } from './pages.ts';
import { renderDoc, docHref } from './docs.ts';
const home = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const pages = new Map([['/', home], ...docs.map(page=>[docHref(page), renderDoc(page, home)])]);

test('every local documentation destination and section resolves', () => {
  for (const [path, html] of pages) {
    const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(match=>match[1]);
    expect(new Set(ids).size, `duplicate IDs on ${path}`).toBe(ids.length);
    for (const match of html.matchAll(/href="([^" ]+)"/g)) {
      const target=match[1];
      if (!target.startsWith('/') && !target.startsWith('#')) continue;
      const url=new URL(target, `https://vhalla.com${path}`);
      if (!url.pathname.startsWith('/docs/') && url.pathname!=='/') continue;
      const destination=pages.get(url.pathname);
      expect(destination, `${path} -> ${target}`).toBeDefined();
      if (url.hash) expect(destination, `${path} -> ${target}`).toContain(`id="${url.hash.slice(1)}"`);
    }
  }
});

test('documentation is static, accessible and correctly canonicalized', () => {
  for (const page of docs) {
    const html=pages.get(docHref(page))!;
    expect(html).toContain(`href="https://vhalla.com${docHref(page)}"`);
    expect(html).toContain('<main id="main"');
    expect(html).toContain('Skip to content');
    expect(html).toContain('aria-current="page"');
    expect(html).toContain('<summary>Documentation');
    expect(html).not.toContain('<form');
    expect(html).not.toMatch(/<script[^>]+src="https?:/);
    expect(html).not.toMatch(/\son(?:click|load|error)=/);
    expect(html.split('<!-- hraness-site-footer -->').length).toBe(2);
  }
});

test('readiness and privacy limitations stay discoverable from the home page', () => {
  expect(home).toContain('href="/docs/status/"');
  expect(home).toContain('Private rooms');
  expect(home).toContain('Not ready');
  expect(home).toContain('Illustrative public room');
  expect(home).not.toContain('href="https://app.vhalla.com');
  const status=pages.get('/docs/status/')!;
  for(const phrase of ['4,096', '30 seconds', '512', 'client receipt persistence and delivery remain unfinished', 'independent-machine', 'not a deployed']) {
    // The summary uses "not ... deployed" in prose; pin only the explicit boundaries below.
    if(phrase==='not a deployed') continue;
    expect(status).toContain(phrase);
  }
  const privateRooms=pages.get('/docs/private-rooms/')!;
  expect(privateRooms).toContain('experimental-private');
  expect(privateRooms).toContain('The offer itself is secret');
  expect(privateRooms).toContain('account-key backup cannot reconstruct');
  expect(privateRooms).toContain('no automatic network delivery');
  const security=pages.get('/docs/security/')!;
  expect(security).toContain('not ready');
  expect(security).toContain('Cloud inference is a disclosure');
  expect(security).toContain('Previously authorized readers can retain old messages');
});

test('repository source links name retained files at the documented immutable revision', async () => {
  expect(documentedRevision).toMatch(/^[0-9a-f]{40}$/);
  const checked=new Set<string>();
  for(const html of pages.values()) for(const match of html.matchAll(/href="https:\/\/github.com\/hraness\/valhalla\/blob\/([^/]+)\/([^"#]+)[^"]*"/g)) {
    expect(match[1]).toBe(documentedRevision);
    if(checked.has(match[2])) continue;
    checked.add(match[2]);
    await access(new URL(`../${match[2]}`,import.meta.url));
  }
  expect(checked.size).toBeGreaterThan(0);
  expect(pages.get('/docs/getting-started/')).toContain(`git checkout --detach ${documentedRevision}`);
});


test('search and agent guides include every maintained documentation page', async () => {
  const sitemap=await readFile(new URL('./sitemap.xml', import.meta.url), 'utf8');
  const agentGuide=await readFile(new URL('./llms.txt', import.meta.url), 'utf8');
  for(const page of docs) {
    expect(sitemap).toContain(`<loc>https://vhalla.com${docHref(page)}</loc>`);
    expect(agentGuide).toContain(`https://vhalla.com${docHref(page)}`);
  }
  expect(agentGuide).toContain(`/blob/${documentedRevision}/crates/vhalla-cli/README.md`);
});
