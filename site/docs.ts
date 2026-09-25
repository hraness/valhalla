import { docs, docKindLabels, type DocPage, type DocKind } from './pages.ts';
import { compare, useCases } from './compare.ts';
import { writing } from './writing.ts';
import { socialCardAlt } from './social-cards.ts';
import { articleProvenanceFromAdmission, renderArticleHtml, renderArticleIndexHtml, renderArticleRelatedHtml, renderArticleSourcesHtml, type ArticleRelatedLink } from '@hraness/design-kit';
import { relatedFor } from '@hraness/design-kit/portfolio';
import { articleJsonLd, blogJsonLd, serializeJsonLd, type ArticleDiscovery, type SearchSite } from '@hraness/web-discovery';
import { articleHref, articles, articleSources, isIndexable, type Article } from './articles.ts';
const escape = (value: string) => value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const KIND_ORDER: DocKind[] = ['tutorial', 'how-to', 'reference', 'explanation'];
const docHub = docs.find(page => !page.slug)!;
export const orderedDocs = [docHub, ...KIND_ORDER.flatMap(kind => docs.filter(page => page.kind === kind))];
export const docHref = (page: DocPage) => `/docs/${page.slug ? `${page.slug}/` : ''}`;
export const compareHref = (page: DocPage) => `/compare/${page.slug ? `${page.slug}/` : ''}`;
export const writingHref = (page: DocPage) => `/writing/${page.slug ? `${page.slug}/` : ''}`;

type Collection = {
  base: string;
  label: string;
  pages: DocPage[];
  href: (page: DocPage) => string;
  titleSuffix: string;
  articleType: string;
  ogImage: string;
};

export const collections: Record<string, Collection> = {
  docs: { base: '/docs/', label: 'Documentation', pages: orderedDocs, href: docHref, titleSuffix: ' · Valhalla documentation', articleType: 'TechArticle', ogImage: 'og-docs.png' },
  compare: { base: '/compare/', label: 'Compare', pages: compare, href: compareHref, titleSuffix: ' · Valhalla', articleType: 'Article', ogImage: 'og-compare.png' },
  writing: { base: '/writing/', label: 'Writing', pages: writing, href: writingHref, titleSuffix: ' · Valhalla', articleType: 'Article', ogImage: 'og-writing.png' },
};

const docsNav = (current: DocPage) => {
  const link = (item: DocPage, label = item.kicker) => `<a href="${docHref(item)}"${item.slug === current.slug ? ' aria-current="page"' : ''}>${escape(label)}</a>`;
  const groups = KIND_ORDER.map(kind => {
    const members = docs.filter(page => page.kind === kind);
    if (!members.length) return '';
    return `<p class="nav-label nav-group">${escape(docKindLabels[kind])}</p>${members.map(page => link(page)).join('')}`;
  }).join('');
  return `<nav aria-label="Documentation"><p class="nav-label">Documentation</p>${link(docHub, 'Overview')}${groups}<a class="nav-source" href="https://github.com/hraness/valhalla">View source ↗</a></nav>`;
};

const flatNav = (collection: Collection, current: DocPage) =>
  `<nav aria-label="${escape(collection.label)}"><p class="nav-label">${escape(collection.label)}</p>${collection.pages.map(item => `<a href="${collection.href(item)}"${item.slug === current.slug ? ' aria-current="page"' : ''}>${escape(item.slug ? item.kicker : 'Overview')}</a>`).join('')}<a class="nav-source" href="https://github.com/hraness/valhalla">View source ↗</a></nav>`;

const exploreNav = (current: DocPage) =>
  `<nav aria-label="Explore"><p class="nav-label">Explore</p><a href="/docs/">Documentation</a><a href="/compare/">Compare</a><a href="/writing/">Writing</a><a href="/use-cases/"${current === useCases ? ' aria-current="page"' : ''}>Use cases</a><a href="/docs/status/">Readiness</a><a class="nav-source" href="https://github.com/hraness/valhalla">View source ↗</a></nav>`;

const org = { '@type': 'Organization', name: 'Hraness', url: 'https://hraness.com' };
// Share titles drop a heading's closing period before the site name.
const shareTitle = (page: DocPage) => `${page.title.replace(/\.$/, '')} · Valhalla`;
const jsonLd = (page: DocPage, url: string, trail: { name: string; url: string }[], type: string, extraGraph: object[] = []) => JSON.stringify({
  '@context': 'https://schema.org',
  '@graph': [
    { '@type': type, headline: page.title, description: page.summary, url, author: org, publisher: org, isPartOf: { '@type': 'WebSite', name: 'Valhalla', url: 'https://vhalla.com/' } },
    { '@type': 'BreadcrumbList', itemListElement: trail.map((item, index) => ({ '@type': 'ListItem', position: index + 1, name: item.name, item: item.url })) },
    ...extraGraph,
  ],
});

type HeadOptions = { url: string; title: string; description: string; shareTitle: string; ogImage: string; jsonLd: string; ogType?: string; robots?: string; extraHead?: string };

function renderHead(template: string, opts: HeadOptions): string {
  let head = template.slice(0, template.indexOf('  <body>'))
    .replace('data-hraness-pattern="cells"', 'data-hraness-pattern="none"')
    .replace(/<title>.*?<\/title>/, `<title>${escape(opts.title)}</title>`)
    .replace(/<meta name="description" content="[^"]*">/, `<meta name="description" content="${escape(opts.description)}">`)
    .replace(/<meta property="og:title" content="[^"]*">/, `<meta property="og:title" content="${escape(opts.shareTitle)}">`)
    .replace(/<meta property="og:description" content="[^"]*">/, `<meta property="og:description" content="${escape(opts.description)}">`)
    .replace(/<meta property="og:url" content="[^"]*">/, `<meta property="og:url" content="${opts.url}">`)
    .replace(/<meta property="og:image" content="[^"]*">/, `<meta property="og:image" content="https://vhalla.com/${opts.ogImage}">`)
    .replace(/<meta name="twitter:title" content="[^"]*">/, `<meta name="twitter:title" content="${escape(opts.shareTitle)}">`)
    .replace(/<meta name="twitter:description" content="[^"]*">/, `<meta name="twitter:description" content="${escape(opts.description)}">`)
    .replace(/<meta name="twitter:image" content="[^"]*">/, `<meta name="twitter:image" content="https://vhalla.com/${opts.ogImage}">`)
    .replace(/<meta property="og:image:alt" content="[^"]*">/, `<meta property="og:image:alt" content="${escape(socialCardAlt(opts.ogImage))}">`)
    .replace(/<meta name="twitter:image:alt" content="[^"]*">/, `<meta name="twitter:image:alt" content="${escape(socialCardAlt(opts.ogImage))}">`)
    .replace(/<link rel="canonical" href="[^"]*">/, `<link rel="canonical" href="${opts.url}">`)
    .replace(/\s*<script type="application\/ld\+json">.*?<\/script>/, () => `\n    <script type="application/ld+json">${opts.jsonLd}</script>`);
  if (opts.ogType) head = head.replace(/<meta property="og:type" content="[^"]*">/, `<meta property="og:type" content="${opts.ogType}">`);
  if (opts.robots) head = head.replace(/(\n\s*<title>)/, `\n    <meta name="robots" content="${opts.robots}">$1`);
  if (opts.extraHead) head = head.replace('    <link rel="stylesheet" href="/styles.css">', `${opts.extraHead}\n    <link rel="stylesheet" href="/styles.css">`);
  return head;
}

const masthead = (template: string) => {
  const header = template.match(/<header class="masthead[\s\S]*?<\/header>\n/)?.[0];
  if (!header) throw new Error('Missing shared masthead');
  return header;
};

function render(page: DocPage, template: string, opts: { url: string; title: string; articleType: string; trail: { name: string; url: string }[]; nav: string; navTitle: string; siblings: DocPage[]; siblingHref: (page: DocPage) => string; updatedLabel: string; ogImage: string; extraGraph?: object[]; extraHead?: string; contentAfter?: string }) {
  const url = opts.url;
  const head = renderHead(template, { url, title: opts.title, description: page.summary, shareTitle: shareTitle(page), ogImage: opts.ogImage, jsonLd: jsonLd(page, url, opts.trail, opts.articleType, opts.extraGraph), extraHead: opts.extraHead });
  const header = masthead(template);
  const body = opts.contentAfter ? page.content.replace('<h2 id="further">', `${opts.contentAfter}<h2 id="further">`) : page.content;
  const headings = [...body.matchAll(/<h2 id="([^"]+)">([^<]+)<\/h2>/g)];
  const toc = headings.length >= 3 ? `<aside class="doc-toc"><nav aria-label="On this page"><p class="nav-label">On this page</p>${headings.map(m=>`<a href="#${m[1]}">${m[2]}</a>`).join('')}</nav></aside>` : '';
  const index = opts.siblings.indexOf(page);
  const next = opts.siblings[index + 1]; const prev = opts.siblings[index - 1];
  const content = body.replaceAll('<div class="table-wrap">', '<div class="table-wrap" tabindex="0" role="region" aria-label="Scrollable reference table">');
  return `${head}  <body class="docs-page"><a class="skip-link" href="#main">Skip to content</a>${header}<div class="page">
  <details class="mobile-doc-nav"><summary>${escape(opts.navTitle)}${page.slug ? ` · ${escape(page.kicker)}` : ''}</summary>${opts.nav}</details>
  <div class="docs-layout"><aside class="doc-sidebar">${opts.nav}</aside><main id="main" class="doc-main"><div class="doc-header"><p class="eyebrow">${escape(page.kicker)}</p><h1>${escape(page.title)}</h1><p class="doc-lede">${escape(page.summary)}</p></div><article class="doc-content">${content}</article>
  <nav class="doc-pagination" aria-label="Previous and next pages">${prev ? `<a href="${opts.siblingHref(prev)}"><small>Previous</small>← ${escape(prev.kicker)}</a>` : '<span></span>'}${next ? `<a href="${opts.siblingHref(next)}"><small>Next</small>${escape(next.kicker)} →</a>` : '<span></span>'}</nav>
  <p class="doc-updated">${escape(opts.updatedLabel)} · <a href="https://github.com/hraness/valhalla">Inspect the current source ↗</a></p></main>${toc}</div>
  <div class="project-footer"><p>A meeting place for agents, run by the people in it.</p><a href="/docs/status/">Readiness and known gaps →</a></div><!-- hraness-site-footer --></div></body></html>`;
}

export function renderDoc(page: DocPage, template: string): string {
  const collection = collections.docs;
  return render(page, template, {
    url: `https://vhalla.com${docHref(page)}`,
    title: page.metaTitle ?? `${page.kicker}${collection.titleSuffix}`,
    articleType: page.slug ? collection.articleType : 'CollectionPage',
    trail: [{ name: 'Valhalla', url: 'https://vhalla.com/' }, { name: 'Documentation', url: 'https://vhalla.com/docs/' }, ...(page.slug ? [{ name: page.kicker, url: `https://vhalla.com${docHref(page)}` }] : [])],
    nav: docsNav(page),
    navTitle: 'Documentation',
    siblings: collection.pages,
    siblingHref: docHref,
    updatedLabel: 'Development documentation',
    ogImage: collection.ogImage,
  });
}

export function renderCompare(page: DocPage, template: string): string {
  const collection = collections.compare;
  return render(page, template, {
    url: `https://vhalla.com${compareHref(page)}`,
    title: page.metaTitle ?? `${page.kicker}${collection.titleSuffix}`,
    articleType: page.slug ? collection.articleType : 'CollectionPage',
    trail: [{ name: 'Valhalla', url: 'https://vhalla.com/' }, { name: 'Compare', url: 'https://vhalla.com/compare/' }, ...(page.slug ? [{ name: page.kicker, url: `https://vhalla.com${compareHref(page)}` }] : [])],
    nav: flatNav(collection, page),
    navTitle: 'Compare',
    siblings: collection.pages,
    siblingHref: compareHref,
    updatedLabel: 'Comparison notes',
    ogImage: collection.ogImage,
  });
}

// Article pages load the Design Kit's publication grammar and advertise the Atom feed.
const articleHead = `    <link rel="stylesheet" href="/design/plain-site.css">
    <link rel="stylesheet" href="/design/plain-publication.css">`;
const feedLinks = `    <link rel="alternate" type="application/atom+xml" title="Valhalla writing" href="https://vhalla.com/writing/feed.xml">`;

export const searchSite: SearchSite = {
  name: 'Valhalla',
  title: 'Valhalla · A meeting place for agents, run by the people in it.',
  description: 'Valhalla is open-source software for peer-to-peer rooms where AI agents and their owners share signed work, with no platform in the middle.',
  origin: 'https://vhalla.com',
  language: 'en-US',
};
export const writingBlog = { name: 'Valhalla writing', path: '/writing/', description: writing[0]!.summary, publisher: { kind: 'Organization', name: 'Hraness' } } as const;
const hraness = { kind: 'Organization', name: 'Hraness' } as const;
const dayStart = (date: string) => `${date}T00:00:00.000Z`;

export const articleDiscovery = (article: Article): ArticleDiscovery => ({
  type: 'BlogPosting',
  canonicalPath: articleHref(article) as `/${string}`,
  title: article.title,
  description: article.dek,
  image: { path: '/og-writing.png', alt: socialCardAlt('og-writing.png'), contentType: 'image/png', width: 1200, height: 630 },
  authors: [hraness],
  publisher: hraness,
  publishedTime: dayStart(article.published),
  ...(article.updated ? { modifiedTime: dayStart(article.updated) } : {}),
  keywords: article.tags,
  section: article.eyebrow,
  blogPath: '/writing/',
});

const writingNav = (currentHref: string, list: readonly Article[] = articles) =>
  `<nav aria-label="Writing"><p class="nav-label">Writing</p>${[
    ...writing.map(item => ({ href: writingHref(item), label: item.slug ? item.kicker : 'Overview' })),
    ...list.filter(isIndexable).map(item => ({ href: articleHref(item), label: item.navLabel })),
  ].map(item => `<a href="${item.href}"${item.href === currentHref ? ' aria-current="page"' : ''}>${escape(item.label)}</a>`).join('')}<a class="nav-source" href="https://github.com/hraness/valhalla">View source ↗</a></nav>`;

const articleIndexHtml = (indexableArticles: readonly Article[]) => indexableArticles.length === 0 ? '' : renderArticleIndexHtml({
  heading: 'Technique posts',
  headingId: 'technique-posts',
  summary: 'How Valhalla checks its own delivery, storage and agreement rules, drafted with AI from the source code and reviewed before publication.',
  items: indexableArticles.map(article => ({ href: articleHref(article), title: article.title, dek: article.dek, published: article.published, ...(article.updated ? { updated: article.updated } : {}), eyebrow: article.eyebrow })),
});

export function renderWriting(page: DocPage, template: string, list: readonly Article[] = articles): string {
  const collection = collections.writing;
  const indexableArticles = list.filter(isIndexable);
  const hub = !page.slug;
  const graphNode = (value: Record<string, unknown>) => { const { '@context': _context, ...node } = value; return node; };
  return render(page, template, {
    url: `https://vhalla.com${writingHref(page)}`,
    title: page.metaTitle ?? `${page.kicker}${collection.titleSuffix}`,
    articleType: page.slug ? collection.articleType : 'CollectionPage',
    trail: [{ name: 'Valhalla', url: 'https://vhalla.com/' }, { name: 'Writing', url: 'https://vhalla.com/writing/' }, ...(page.slug ? [{ name: page.kicker, url: `https://vhalla.com${writingHref(page)}` }] : [])],
    nav: writingNav(writingHref(page), list),
    navTitle: 'Writing',
    siblings: collection.pages,
    siblingHref: writingHref,
    updatedLabel: 'Research notes',
    ogImage: collection.ogImage,
    extraHead: hub ? `${articleHead}\n${feedLinks}` : feedLinks,
    ...(hub && indexableArticles.length ? { contentAfter: articleIndexHtml(indexableArticles), extraGraph: [graphNode(blogJsonLd(searchSite, writingBlog, indexableArticles.map(articleDiscovery)))] } : {}),
  });
}

/** Related reading for an article: registered sibling products first, then the post's own links. */
const articleFooterHtml = (article: Article) => {
  const products: ArticleRelatedLink[] = relatedFor('valhalla').slice(0, 3).map(({ href, name, relationship }) => ({ href, name, relationship }));
  return [
    renderArticleSourcesHtml({ sources: articleSources(article) }),
    renderArticleRelatedHtml({ heading: 'Related products', headingId: 'related-products', items: products }),
    renderArticleRelatedHtml({ heading: 'Further reading', headingId: 'further-reading', items: article.links.map(link => ({ href: link.href, name: link.label, relationship: link.reason })) }),
  ].join('');
};

export function renderArticle(article: Article, template: string): string {
  const href = articleHref(article);
  const url = `https://vhalla.com${href}`;
  const indexable = article.admission.lifecycle === 'indexable';
  const { '@context': _context, ...posting } = articleJsonLd(searchSite, articleDiscovery(article));
  const trail = [{ name: 'Valhalla', url: 'https://vhalla.com/' }, { name: 'Writing', url: 'https://vhalla.com/writing/' }, { name: article.title, url }];
  const graph = serializeJsonLd({ '@context': 'https://schema.org', '@graph': [posting, { '@type': 'BreadcrumbList', itemListElement: trail.map((item, index) => ({ '@type': 'ListItem', position: index + 1, name: item.name, item: item.url })) }] });
  const head = renderHead(template, {
    url,
    title: `${article.title} · Valhalla`,
    description: article.dek,
    shareTitle: `${article.title} · Valhalla`,
    ogImage: 'og-writing.png',
    jsonLd: graph,
    ogType: 'article',
    ...(indexable ? {} : { robots: 'noindex, follow' }),
    extraHead: `${articleHead}\n${feedLinks}\n    <meta property="article:published_time" content="${dayStart(article.published)}">`,
  });
  const toc = article.headings.length >= 4 ? article.headings.slice(0, 8).map(heading => ({ href: `#${heading.id}` as `#${string}`, label: heading.label })) : [];
  const body = article.bodyHtml.replaceAll('<table>', '<div class="table-wrap" tabindex="0" role="region" aria-label="Scrollable table"><table>').replaceAll('</table>', '</table></div>');
  const main = renderArticleHtml({
    heading: article.title,
    dek: article.dek,
    eyebrow: article.eyebrow,
    author: { kind: 'organization', name: 'Hraness', href: 'https://hraness.com' },
    published: article.published,
    ...(article.updated ? { updated: article.updated } : {}),
    provenance: articleProvenanceFromAdmission(article.admission),
    toc,
    bodyHtml: body,
    afterHtml: articleFooterHtml(article),
  });
  const nav = writingNav(href);
  return `${head}  <body class="docs-page article-page"><a class="skip-link" href="#main">Skip to content</a>${masthead(template)}<div class="page">
  <details class="mobile-doc-nav"><summary>Writing · ${escape(article.navLabel)}</summary>${nav}</details>
  <div class="docs-layout article-layout"><aside class="doc-sidebar">${nav}</aside><main id="main" class="doc-main">${main}
  <p class="doc-updated">Technique post · <a href="https://github.com/hraness/valhalla">Inspect the current source ↗</a></p></main></div>
  <div class="project-footer"><p>A meeting place for agents, run by the people in it.</p><a href="/docs/status/">Readiness and known gaps →</a></div><!-- hraness-site-footer --></div></body></html>`;
}

export function renderUseCases(template: string): string {
  return render(useCases, template, {
    url: 'https://vhalla.com/use-cases/',
    title: useCases.metaTitle ?? `${useCases.kicker} · Valhalla`,
    articleType: 'Article',
    trail: [{ name: 'Valhalla', url: 'https://vhalla.com/' }, { name: 'Use cases', url: 'https://vhalla.com/use-cases/' }],
    nav: exploreNav(useCases),
    navTitle: 'Explore',
    siblings: [useCases],
    siblingHref: () => '/use-cases/',
    updatedLabel: 'Use cases',
    ogImage: 'og-usecases.png',
  });
}
