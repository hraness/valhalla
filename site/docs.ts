import { docs, docKindLabels, type DocPage, type DocKind } from './pages.ts';
import { compare, useCases } from './compare.ts';
import { writing } from './writing.ts';
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
  docs: { base: '/docs/', label: 'Documentation', pages: orderedDocs, href: docHref, titleSuffix: ' — vhalla documentation', articleType: 'TechArticle', ogImage: 'og-docs.png' },
  compare: { base: '/compare/', label: 'Compare', pages: compare, href: compareHref, titleSuffix: ' — vhalla', articleType: 'Article', ogImage: 'og-compare.png' },
  writing: { base: '/writing/', label: 'Writing', pages: writing, href: writingHref, titleSuffix: ' — vhalla', articleType: 'Article', ogImage: 'og-writing.png' },
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
const jsonLd = (page: DocPage, url: string, trail: { name: string; url: string }[], type: string) => JSON.stringify({
  '@context': 'https://schema.org',
  '@graph': [
    { '@type': type, headline: page.title, description: page.summary, url, author: org, publisher: org, isPartOf: { '@type': 'WebSite', name: 'vhalla (valhalla)', url: 'https://vhalla.com/' } },
    { '@type': 'BreadcrumbList', itemListElement: trail.map((item, index) => ({ '@type': 'ListItem', position: index + 1, name: item.name, item: item.url })) },
  ],
});

function render(page: DocPage, template: string, opts: { url: string; title: string; articleType: string; trail: { name: string; url: string }[]; nav: string; navTitle: string; siblings: DocPage[]; siblingHref: (page: DocPage) => string; updatedLabel: string; ogImage: string }) {
  const url = opts.url;
  const head = template.slice(0, template.indexOf('  <body>'))
    .replace('data-hraness-pattern="cells"', 'data-hraness-pattern="none"')
    .replace(/<title>.*?<\/title>/, `<title>${escape(opts.title)}</title>`)
    .replace(/<meta name="description" content="[^"]*">/, `<meta name="description" content="${escape(page.summary)}">`)
    .replace(/<meta property="og:title" content="[^"]*">/, `<meta property="og:title" content="${escape(page.title)} — vhalla">`)
    .replace(/<meta property="og:description" content="[^"]*">/, `<meta property="og:description" content="${escape(page.summary)}">`)
    .replace(/<meta property="og:url" content="[^"]*">/, `<meta property="og:url" content="${url}">`)
    .replace(/<meta property="og:image" content="[^"]*">/, `<meta property="og:image" content="https://vhalla.com/${opts.ogImage}">`)
    .replace(/<meta name="twitter:title" content="[^"]*">/, `<meta name="twitter:title" content="${escape(page.title)} — vhalla">`)
    .replace(/<meta name="twitter:description" content="[^"]*">/, `<meta name="twitter:description" content="${escape(page.summary)}">`)
    .replace(/<meta name="twitter:image" content="[^"]*">/, `<meta name="twitter:image" content="https://vhalla.com/${opts.ogImage}">`)
    .replace(/<link rel="canonical" href="[^"]*">/, `<link rel="canonical" href="${url}">`)
    .replace(/\s*<script type="application\/ld\+json">.*?<\/script>/, `\n    <script type="application/ld+json">${jsonLd(page, url, opts.trail, opts.articleType)}</script>`);
  const header = template.match(/<header class="masthead[\s\S]*?<\/header>\n/)?.[0];
  if (!header) throw new Error('Missing shared masthead');
  const headings = [...page.content.matchAll(/<h2 id="([^"]+)">([^<]+)<\/h2>/g)];
  const toc = headings.length >= 3 ? `<aside class="doc-toc"><nav aria-label="On this page"><p class="nav-label">On this page</p>${headings.map(m=>`<a href="#${m[1]}">${m[2]}</a>`).join('')}</nav></aside>` : '';
  const index = opts.siblings.indexOf(page);
  const next = opts.siblings[index + 1]; const prev = opts.siblings[index - 1];
  const content = page.content.replaceAll('<div class="table-wrap">', '<div class="table-wrap" tabindex="0" role="region" aria-label="Scrollable reference table">');
  return `${head}  <body class="docs-page"><a class="skip-link" href="#main">Skip to content</a>${header}<div class="page">
  <details class="mobile-doc-nav"><summary>${escape(opts.navTitle)}${page.slug ? ` · ${escape(page.kicker)}` : ''}</summary>${opts.nav}</details>
  <div class="docs-layout"><aside class="doc-sidebar">${opts.nav}</aside><main id="main" class="doc-main"><div class="doc-header"><p class="eyebrow">${escape(page.kicker)}</p><h1>${escape(page.title)}</h1><p class="doc-lede">${escape(page.summary)}</p></div><article class="doc-content">${content}</article>
  <nav class="doc-pagination" aria-label="Previous and next pages">${prev ? `<a href="${opts.siblingHref(prev)}"><small>Previous</small>← ${escape(prev.kicker)}</a>` : '<span></span>'}${next ? `<a href="${opts.siblingHref(next)}"><small>Next</small>${escape(next.kicker)} →</a>` : '<span></span>'}</nav>
  <p class="doc-updated">${escape(opts.updatedLabel)} · 21 September 2026 · <a href="https://github.com/hraness/valhalla">Inspect the current source ↗</a></p></main>${toc}</div>
  <div class="project-footer"><p>Rooms for agents. Room for people.</p><a href="/docs/status/">Readiness and known gaps →</a></div><!-- hraness-site-footer --></div></body></html>`;
}

export function renderDoc(page: DocPage, template: string): string {
  const collection = collections.docs;
  return render(page, template, {
    url: `https://vhalla.com${docHref(page)}`,
    title: page.metaTitle ?? `${page.kicker}${collection.titleSuffix}`,
    articleType: page.slug ? collection.articleType : 'CollectionPage',
    trail: [{ name: 'vhalla', url: 'https://vhalla.com/' }, { name: 'Documentation', url: 'https://vhalla.com/docs/' }, ...(page.slug ? [{ name: page.kicker, url: `https://vhalla.com${docHref(page)}` }] : [])],
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
    trail: [{ name: 'vhalla', url: 'https://vhalla.com/' }, { name: 'Compare', url: 'https://vhalla.com/compare/' }, ...(page.slug ? [{ name: page.kicker, url: `https://vhalla.com${compareHref(page)}` }] : [])],
    nav: flatNav(collection, page),
    navTitle: 'Compare',
    siblings: collection.pages,
    siblingHref: compareHref,
    updatedLabel: 'Comparison notes',
    ogImage: collection.ogImage,
  });
}

export function renderWriting(page: DocPage, template: string): string {
  const collection = collections.writing;
  return render(page, template, {
    url: `https://vhalla.com${writingHref(page)}`,
    title: page.metaTitle ?? `${page.kicker}${collection.titleSuffix}`,
    articleType: page.slug ? collection.articleType : 'CollectionPage',
    trail: [{ name: 'vhalla', url: 'https://vhalla.com/' }, { name: 'Writing', url: 'https://vhalla.com/writing/' }, ...(page.slug ? [{ name: page.kicker, url: `https://vhalla.com${writingHref(page)}` }] : [])],
    nav: flatNav(collection, page),
    navTitle: 'Writing',
    siblings: collection.pages,
    siblingHref: writingHref,
    updatedLabel: 'Research notes',
    ogImage: collection.ogImage,
  });
}

export function renderUseCases(template: string): string {
  return render(useCases, template, {
    url: 'https://vhalla.com/use-cases/',
    title: useCases.metaTitle ?? `${useCases.kicker} — vhalla`,
    articleType: 'Article',
    trail: [{ name: 'vhalla', url: 'https://vhalla.com/' }, { name: 'Use cases', url: 'https://vhalla.com/use-cases/' }],
    nav: exploreNav(useCases),
    navTitle: 'Explore',
    siblings: [useCases],
    siblingHref: () => '/use-cases/',
    updatedLabel: 'Working shapes',
    ogImage: 'og-usecases.png',
  });
}
