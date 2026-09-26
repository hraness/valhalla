import { describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { renderSitemap } from './discovery.ts';
import { knownRoutes, notFoundContent, renderNotFound } from './not-found.ts';

const template = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const sitemap = renderSitemap(await readFile(new URL('./sitemap.xml', import.meta.url), 'utf8'));
const page = renderNotFound(template);

describe('404 page', () => {
  test('offers the home page hero action', () => {
    const hero = template.match(/<a class="button-link" href="([^"]+)">([^<]+?) </);
    expect(hero).not.toBeNull();
    expect(notFoundContent.primaryAction).toEqual({ href: hero![1]!, label: hero![2]! });
    expect(page).toContain(`data-emphasis="primary" data-foil="" href="${hero![1]}">${hero![2]}</a>`);
  });

  test('suggests only pages the sitemap lists', () => {
    const listed = new Set([...sitemap.matchAll(/<loc>https:\/\/vhalla\.com([^<]*)<\/loc>/g)].map(match => match[1]));
    const routes = knownRoutes();
    expect(new Set(routes.map(route => route.href)).size).toBe(routes.length);
    for (const route of routes) expect(listed.has(route.href)).toBe(true);
    for (const link of notFoundContent.next) expect(listed.has(link.href)).toBe(true);
    expect(page).toContain('data-hraness-status-routes=');
  });

  test('keeps the masthead, footers and the restrictive CSP', () => {
    expect(page.match(/<main id="main">/g)).toHaveLength(1);
    expect(page.match(/class="hraness-status-page"/g)).toHaveLength(1);
    expect(page).toContain('<header class="masthead');
    expect(page).toContain('<div class="project-footer">');
    expect(page.split('<!-- hraness-site-footer -->')).toHaveLength(2);
    expect(page).toContain('<meta name="robots" content="noindex">');
    expect(page).not.toContain('rel="canonical"');
    expect(page).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
    expect(page).not.toMatch(/\sstyle="/);
    expect(page).toContain('<script src="/status-page.js" defer></script>');
    expect(page).toContain('<link rel="stylesheet" href="/design/status-page.css">');
  });
});
