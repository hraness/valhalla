import { expect, test } from 'bun:test';
import { readFile, access } from 'node:fs/promises';
import { docs, documentedRevision, latestRelease } from './pages.ts';
import { compare, useCases } from './compare.ts';
import { writing } from './writing.ts';
import { renderArticle, renderDoc, renderCompare, renderUseCases, renderWriting, docHref, compareHref, writingHref } from './docs.ts';
import { articles, articleHref, indexableArticles, isIndexable } from './articles.ts';
import { articleEvidenceRevision, launchEvidenceRevision, irohEvidenceRevision } from './article-admissions.ts';
import { renderLlms, renderSitemap } from './discovery.ts';
import { renderHome } from './home.ts';
import { daemonRelease, daemonUnixInstall, daemonWindowsInstall } from './platform-install.ts';
const home = renderHome(await readFile(new URL('./index.html', import.meta.url), 'utf8'));
const pages = new Map([['/', home], ...docs.map(page=>[docHref(page), renderDoc(page, home)]), ...compare.map(page=>[compareHref(page), renderCompare(page, home)]), ...writing.map(page=>[writingHref(page), renderWriting(page, home)]), ...articles.map(article=>[articleHref(article), renderArticle(article, home)]), ['/use-cases/', renderUseCases(home)]]);

test('every local page destination and section resolves', () => {
  for (const [path, html] of pages) {
    const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(match=>match[1]);
    expect(new Set(ids).size, `duplicate IDs on ${path}`).toBe(ids.length);
    for (const match of html.matchAll(/href="([^" ]+)"/g)) {
      const target=match[1];
      if (!target.startsWith('/') && !target.startsWith('#')) continue;
      const url=new URL(target, `https://vhalla.com${path}`);
      if (!pages.has(url.pathname)) continue;
      const destination=pages.get(url.pathname);
      expect(destination, `${path} -> ${target}`).toBeDefined();
      if (url.hash) expect(destination, `${path} -> ${target}`).toContain(`id="${url.hash.slice(1)}"`);
    }
  }
  for (const [path, html] of pages) {
    for (const match of html.matchAll(/href="(\/[^" ]+)"/g)) {
      const url=new URL(match[1], `https://vhalla.com${path}`);
      if (url.pathname==='/'||url.pathname.startsWith('/docs/')||url.pathname.startsWith('/compare/')||url.pathname.startsWith('/writing/')||url.pathname.startsWith('/use-cases/')) {
        expect(pages.has(url.pathname), `${path} -> ${match[1]} unresolved`).toBe(true);
      }
    }
  }
});

const quarantinedPaths = new Set(articles.filter(article => !isIndexable(article)).map(articleHref));
test('documentation and marketing pages are static, accessible and correctly canonicalized', () => {
  for (const [path, html] of pages) {
    if (path==='/') continue;
    expect(html, path).toContain(`href="https://vhalla.com${path}"`);
    expect(html).toContain('<main id="main"');
    expect(html).toContain('Skip to content');
    // Quarantined articles stay out of every navigation list, so they have no current nav item.
    if (!quarantinedPaths.has(path)) expect(html, path).toContain('aria-current="page"');
    expect(html).toMatch(/<summary>(Documentation|Compare|Writing|Explore)/);
    expect(html).not.toContain('<form');
    expect(html).not.toMatch(/<script[^>]+src="https?:/);
    expect(html).not.toMatch(/\son(?:click|load|error)=/);
    expect(html.split('<!-- hraness-site-footer -->').length).toBe(2);
  }
});

test('readiness and privacy limitations stay discoverable from the home page', () => {
  expect(home).toContain('href="/docs/status/"');
  expect(home).toContain('Private rooms');
  expect(home).toContain('headless daemon');
  expect(home).toContain(`VHALLA_VERSION=${daemonRelease}`);
  expect(home).not.toContain('href="https://app.vhalla.com');
  const status=pages.get('/docs/status/')!;
  for(const phrase of ['CLI/JSON', 'MCP', 'separate runners', 'pending', 'AT Protocol']) {
    expect(status).toContain(phrase);
  }
  const daemon=pages.get('/docs/headless-daemon/')!;
  for (const operation of ['agent.status', 'agent.messages', 'agent.send', 'agent.outbox_status', 'public.sync_status', 'private.delivery_status']) expect(daemon).toContain(`<code>${operation}</code>`);
  expect(daemon).toContain('read-only history');
  expect(daemon).toContain('cloud model');
  expect(daemon).toContain('64-room limit');
  expect(daemon).toContain('eight selected sources');
});

test('earlier guides stay available with historical context outside primary navigation', () => {
  for (const page of docs.filter(page => page.historical)) {
    const html = pages.get(docHref(page))!;
    expect(html, page.slug).toContain('data-historical-documentation');
    expect(html, page.slug).toContain('href="/docs/headless-daemon/"');
  }
  expect(docs.find(page => page.slug === 'public-rooms')?.historical).toBe(true);
  expect(docs.find(page => page.slug === 'private-rooms')?.historical).toBe(true);
  expect(pages.get('/docs/historical-getting-started/')).toContain(`git checkout --detach ${documentedRevision}`);
  expect(pages.get('/docs/historical-agent-setup/')).toContain('bootstrap-check');
  expect(pages.get('/docs/historical-status/')).toContain('Incremental finalization');
  const overview = docs.find(page => page.slug === '')!.content;
  expect(overview).toContain('/docs/headless-daemon/');
  expect(overview).not.toContain('/docs/public-rooms/');
  expect(overview).not.toContain('/docs/clankdar/');
});

test('comparisons state custody and status', () => {
  const moltbook=pages.get('/compare/moltbook/')!;
  expect(moltbook).toContain('hosted');
  expect(moltbook).toContain('in development');
  expect(moltbook).toMatch(/no hosted (?:Valhalla )?network/);
  for (const page of compare) {
    const html=pages.get(compareHref(page))!;
    expect(html, compareHref(page)).toContain('development');
  }
});

test('comparisons and use cases retain source-check dates in metadata', () => {
  for (const [path, page] of [...compare.map(item => [compareHref(item), item] as const), ['/use-cases/', useCases] as const]) {
    expect(page.checkedOn, path).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(Number.isNaN(Date.parse(`${page.checkedOn}T00:00:00Z`)), path).toBe(false);
    expect(page.sources?.length ?? 0, path).toBeGreaterThan(0);
    for (const source of page.sources ?? []) expect(source.url, path).toStartWith('https://');
    const html = pages.get(path)!;
    expect(html, path).not.toContain(`Checked on ${page.checkedOn}`);
    expect(html, path).toContain('<h2 id="sources">Sources</h2>');
    for (const source of page.sources ?? []) expect(html, path).toContain(`href="${source.url}"`);
    const graph = JSON.parse(html.match(/<script type="application\/ld\+json">(.+?)<\/script>/)![1]);
    expect(graph['@graph'][0].dateModified, path).toBe(page.checkedOn);
  }
});

test('historical source links keep immutable revisions and current guides name existing source files', async () => {
  expect(documentedRevision).toMatch(/^[0-9a-f]{40}$/);
  const checked=new Set<string>();
  for(const html of pages.values()) for(const match of html.matchAll(/href="https:\/\/github.com\/hraness\/valhalla\/blob\/([^/]+)\/([^"#]+)[^"]*"/g)) {
    if (match[1] === 'main') {
      expect(['docs/headless-daemon.md', 'docs/headless-api.md', 'docs/iroh-private-rooms.md', 'docs/release-readiness.md', 'crates/vhalla-direct-room/README.md']).toContain(match[2]);
    } else {
      expect([documentedRevision, articleEvidenceRevision, launchEvidenceRevision, irohEvidenceRevision]).toContain(match[1]);
    }
    if(checked.has(match[2])) continue;
    checked.add(match[2]);
    await access(new URL(`../${match[2]}`,import.meta.url));
  }
  expect(checked.size).toBeGreaterThan(0);
  expect(pages.get('/docs/getting-started/')).toContain('cargo +1.98.1 build --locked -p vhalla-cli --bin vhalla');
});


test('search and agent guides include every maintained page', async () => {
  const sitemap=renderSitemap(await readFile(new URL('./sitemap.xml', import.meta.url), 'utf8'));
  const agentGuide=renderLlms(await readFile(new URL('./llms.txt', import.meta.url), 'utf8'));
  for(const page of docs) {
    expect(sitemap).toContain(`<loc>https://vhalla.com${docHref(page)}</loc>`);
    expect(agentGuide).toContain(`https://vhalla.com${docHref(page)}`);
  }
  for(const page of compare) {
    expect(sitemap).toContain(`<loc>https://vhalla.com${compareHref(page)}</loc>`);
    expect(agentGuide).toContain(`https://vhalla.com${compareHref(page)}`);
  }
  for(const page of writing) {
    expect(sitemap).toContain(`<loc>https://vhalla.com${writingHref(page)}</loc>`);
    expect(agentGuide).toContain(`https://vhalla.com${writingHref(page)}`);
  }
  for(const article of indexableArticles) {
    expect(sitemap).toContain(`<loc>https://vhalla.com${articleHref(article)}</loc><lastmod>${article.updated ?? article.published}</lastmod>`);
    expect(agentGuide).toContain(`https://vhalla.com${articleHref(article)}`);
  }
  expect(sitemap).toContain('<loc>https://vhalla.com/use-cases/</loc>');
  expect(agentGuide).toContain('https://vhalla.com/use-cases/');
  expect(agentGuide).toContain(`/blob/${documentedRevision}/crates/vhalla-cli/README.md`);
});

test('the home page and Homebrew instructions name the current release and formula', () => {
  // One release is typed in pages.ts; the home page may name no other version.
  expect(new Set(home.match(/\bv\d+\.\d+\.\d+\b/g))).toEqual(new Set([latestRelease, daemonRelease]));
  // Homebrew 7 refuses formulae from untrusted taps unless the install names the formula in full.
  const getStarted=pages.get('/docs/getting-started/')!;
  expect(getStarted).toContain('brew install hraness/tap/vhalla');
  expect(home).toContain(`VHALLA_VERSION=${daemonRelease}`);
  for (const [path, html] of pages) expect(html, path).not.toMatch(/brew install vhalla\b/);
});

test('released daemon selection stays distinct from unchanged installer defaults', async () => {
  expect(daemonRelease).toBe('v0.3.1');
  expect(latestRelease).toBe('v0.2.13');
  const guide = renderLlms(await readFile(new URL('./llms.txt', import.meta.url), 'utf8'));
  for (const html of [home, ...docs.filter(page => !page.historical).map(page => page.content), guide]) {
    expect(html).toContain(daemonRelease);
    expect(html).toContain(latestRelease);
    expect(html).not.toContain('requires a source build');
    expect(html).not.toContain('it does not include this daemon');
    expect(html).not.toContain('{{DAEMON_RELEASE}}');
  }
  const started = pages.get('/docs/getting-started/')!;
  expect(started).toContain(daemonUnixInstall);
  expect(started).toContain(daemonWindowsInstall);
  for (const text of [started, guide]) {
    expect(text).toContain('Apple silicon');
    expect(text).toContain('ARM64');
    expect(text).toContain('private-room member commands');
    expect(text).toContain('not the daemon');
    expect(text).toContain('gh auth login');
  }
  const unix = await readFile(new URL('./install.sh', import.meta.url), 'utf8');
  const windows = await readFile(new URL('./install.ps1', import.meta.url), 'utf8');
  expect(unix).toContain(`VERSION="${latestRelease}"`);
  expect(unix).toContain('VERSION="${VHALLA_VERSION:-$VERSION}"');
  expect(unix).toContain('--pinned');
  expect(windows).toContain(`$Version = '${latestRelease}'`);
  expect(windows).toContain('$Version = $env:VHALLA_VERSION');
  expect(await readFile(new URL('../README.md', import.meta.url), 'utf8')).toContain(daemonUnixInstall);
});

test('install.sh --with-menubar matches the release it serves', async () => {
  // The installer downloads latestRelease, not this revision. Releases before
  // v0.2.9 ship the menu bar and have no top-level `vhalla status`, so the flag
  // keeps installing it until latestRelease moves past the retirement.
  const installer=await readFile(new URL('./install.sh', import.meta.url), 'utf8');
  const [major, minor, patch]=latestRelease.slice(1).split('.').map(Number);
  const retired=major>0 || minor>2 || (minor===2 && patch>=9);
  if (retired) {
    expect(installer).not.toContain('valhalla-menubar-');
    expect(installer).toContain('vhalla status');
  } else {
    expect(installer).toContain('valhalla-menubar-$VERSION-aarch64-apple-darwin.tar.gz');
    expect(installer).not.toContain('vhalla status');
  }
});

test('install.sh serves the documented release and is wired into the build', async () => {
  const installer=await readFile(new URL('./install.sh', import.meta.url), 'utf8');
  const build=await readFile(new URL('./build.ts', import.meta.url), 'utf8');
  expect(installer).toContain(`VERSION="${latestRelease}"`);
  expect(installer).toContain('sha256');
  expect(build).toContain('"install.sh"');
});

test('install.ps1 serves the documented release and is wired into the build', async () => {
  const installer=await readFile(new URL('./install.ps1', import.meta.url), 'utf8');
  const build=await readFile(new URL('./build.ts', import.meta.url), 'utf8');
  expect(installer).toContain(`$Version = '${latestRelease}'`);
  expect(installer).toContain('Get-FileHash');
  expect(installer).toContain('x86_64-pc-windows-msvc.zip');
  expect(build).toContain('"install.ps1"');
});
