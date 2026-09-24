// Discovery files for the /writing/ articles. Only indexable articles enter
// the sitemap, the Atom feed and llms.txt; quarantined ones stay readable but
// out of all three. The build and the tests share these functions.
import { createAtomFeed, createBlogSitemapPaths, createFeedEntry } from '@hraness/web-discovery';
import { articleDiscovery, searchSite, writingBlog } from './docs.ts';
import { articleHref, articles, isIndexable, type Article } from './articles.ts';

const origin = 'https://vhalla.com';

/** Adds one `<url>` with `<lastmod>` per indexable article to the maintained sitemap. */
export function renderSitemap(staticSitemap: string, list: readonly Article[] = articles): string {
  const indexableArticles = list.filter(isIndexable);
  const entries = createBlogSitemapPaths({ path: writingBlog.path }, indexableArticles.map(articleDiscovery)).slice(1)
    .map(entry => `  <url><loc>${origin}${entry.path}</loc>${entry.lastModified ? `<lastmod>${String(entry.lastModified).slice(0, 10)}</lastmod>` : ''}</url>`);
  if (staticSitemap.split('</urlset>').length !== 2) throw new Error('Expected one </urlset> in sitemap.xml');
  return entries.length ? staticSitemap.replace('</urlset>', `${entries.join('\n')}\n</urlset>`) : staticSitemap;
}

/** Lists each indexable article in llms.txt, just before the use-cases line. */
export function renderLlms(staticGuide: string, list: readonly Article[] = articles): string {
  const indexableArticles = list.filter(isIndexable);
  const marker = '- Use cases: https://vhalla.com/use-cases/';
  if (staticGuide.split(marker).length !== 2) throw new Error('Expected one use-cases line in llms.txt');
  const lines = indexableArticles.map(article => `- ${article.title}: ${origin}${articleHref(article)}\n`).join('');
  return staticGuide.replace(marker, `${lines}${marker}`);
}

/** The Atom feed for indexable articles, newest first, with full bodies. */
export function renderAtomFeed(list: readonly Article[] = articles): string {
  const indexableArticles = list.filter(isIndexable);
  const entries = [...indexableArticles]
    .sort((a, b) => (b.updated ?? b.published).localeCompare(a.updated ?? a.published) || a.slug.localeCompare(b.slug))
    .map(article => createFeedEntry(articleDiscovery(article), { contentHtml: article.bodyHtml }));
  return createAtomFeed(searchSite, {
    title: 'vhalla writing',
    description: writingBlog.description,
    homePath: writingBlog.path,
    path: '/writing/feed.xml',
    authors: [writingBlog.publisher],
    ...(entries.length ? {} : { updated: '2026-09-24T00:00:00.000Z' }),
  }, entries);
}
