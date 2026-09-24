import { expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { ARTICLE_REASSESS_WINDOW, articleDaysBetween, articleProvenanceFromAdmission, articleProvenanceSentence, assertArticleAdmissions } from '@hraness/design-kit';
import { portfolioProducts } from '@hraness/design-kit/portfolio';
import { articleAdmissions } from './article-admissions.ts';
import { articleHref, articles, type Article } from './articles.ts';
import { renderArticle, renderWriting } from './docs.ts';
import { renderAtomFeed, renderLlms, renderSitemap } from './discovery.ts';
import { writing } from './writing.ts';

const template = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const staticSitemap = await readFile(new URL('./sitemap.xml', import.meta.url), 'utf8');
const staticGuide = await readFile(new URL('./llms.txt', import.meta.url), 'utf8');

test('the admission registry is valid and covers exactly the published articles', () => {
  assertArticleAdmissions(articleAdmissions);
  expect(articleAdmissions.map(record => record.href).sort()).toEqual(articles.map(articleHref).sort());
  for (const record of articleAdmissions) {
    // Reviews are disclosed AI reviews; nothing claims a person reviewed these posts.
    expect(record.review?.reviewerType, record.href).toBe('ai');
    expect(record.humanReview, record.href).toBeNull();
    const days = articleDaysBetween(record.review!.reviewedOn, record.reassessOn);
    expect(days).toBeGreaterThanOrEqual(ARTICLE_REASSESS_WINDOW.minimumDays);
    expect(days).toBeLessThanOrEqual(ARTICLE_REASSESS_WINDOW.maximumDays);
  }
});

test('every article shows the Hraness byline, the provenance note and dated sources', () => {
  for (const article of articles) {
    const html = renderArticle(article, template);
    const sentence = articleProvenanceSentence(articleProvenanceFromAdmission(article.admission));
    expect(sentence).toBe('Drafted with AI from the source code and reviewed by Claude Opus 5.5 (claude-opus-5-5) editorial review.');
    expect(html, article.slug).toContain(sentence);
    expect(html, article.slug).not.toMatch(/human/i);
    expect(html, article.slug).toContain('By <a href="https://hraness.com" rel="author">Hraness</a>');
    expect(html, article.slug).toContain('<section aria-labelledby="article-sources" class="plain-publication__sources">');
    expect(html, article.slug).toContain('<meta property="og:type" content="article">');
    expect(html, article.slug).toContain(`<link rel="canonical" href="https://vhalla.com${articleHref(article)}">`);
    expect(html, article.slug).not.toContain('—');
    const graph = JSON.parse(html.match(/<script type="application\/ld\+json">(.+?)<\/script>/)![1]!);
    const posting = graph['@graph'][0];
    expect(posting['@type']).toBe('BlogPosting');
    expect(posting.author).toEqual([{ '@type': 'Organization', name: 'Hraness' }]);
    expect(posting.datePublished).toBe(`${article.published}T00:00:00.000Z`);
    expect(posting.isPartOf['@id']).toBe('https://vhalla.com/writing/#blog');
  }
});

// Links to other Hraness sites go only to reviewed pages that are live or to a
// product home page. The hraness.com correctness reference posts are held
// back until they return 200; add each one here when it is linked.
const reviewedRoutes = new Set([
  'https://hraness.com/reference/peer-to-peer-systems/room-scale-consensus',
]);
const productHosts = new Set([...Object.values(portfolioProducts).map(product => new URL(product.canonicalUrl).host), 'hraness.com']);

test('article links to other Hraness sites use absolute URLs to reviewed posts or product home pages', () => {
  for (const article of articles) {
    const hrefs = [...article.bodyHtml.matchAll(/href="([^"]+)"/g)].map(match => match[1]!).concat(article.links.map(link => link.href));
    for (const href of hrefs) {
      if (href.startsWith('/') || href.startsWith('#')) continue;
      const url = new URL(href);
      expect(url.protocol, href).toBe('https:');
      if (!productHosts.has(url.host) || url.host === 'vhalla.com') continue;
      const home = url.pathname === '/' || url.pathname === '';
      expect(home || reviewedRoutes.has(`${url.origin}${url.pathname}`), `${article.slug} -> ${href}`).toBe(true);
    }
  }
});

test('indexable articles enter the index, sitemap, Atom feed and llms.txt', () => {
  const hub = renderWriting(writing[0]!, template);
  const sitemap = renderSitemap(staticSitemap);
  const feed = renderAtomFeed();
  const guide = renderLlms(staticGuide);
  for (const article of articles.filter(item => item.admission.lifecycle === 'indexable')) {
    const url = `https://vhalla.com${articleHref(article)}`;
    expect(renderArticle(article, template)).not.toContain('name="robots"');
    expect(hub).toContain(`href="${articleHref(article)}"`);
    expect(sitemap).toContain(`<loc>${url}</loc><lastmod>${article.published}</lastmod>`);
    expect(feed).toContain(`<id>${url}</id>`);
    expect(guide).toContain(url);
  }
  expect(feed).toStartWith('<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"');
  expect(hub).toContain('"@type":"Blog"');
});

test('a quarantined article is readable but noindex and absent from every discovery list', () => {
  const quarantined: Article = { ...articles[0]!, slug: 'quarantine-fixture', navLabel: 'Quarantine fixture', admission: { ...articles[0]!.admission, href: '/writing/quarantine-fixture/', lifecycle: 'quarantined' } };
  const list = [...articles, quarantined];
  const page = renderArticle(quarantined, template);
  expect(page).toContain('<meta name="robots" content="noindex, follow">');
  expect(page).toContain('Drafted with AI from the source code');
  const href = articleHref(quarantined);
  expect(renderWriting(writing[0]!, template, list)).not.toContain(href);
  expect(renderSitemap(staticSitemap, list)).not.toContain(href);
  expect(renderAtomFeed(list)).not.toContain(href);
  expect(renderLlms(staticGuide, list)).not.toContain(href);
});
