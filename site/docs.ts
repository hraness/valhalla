import { docs, type DocPage } from './pages.ts';
const escape = (value: string) => value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
export const docHref = (page: DocPage) => `/docs/${page.slug ? `${page.slug}/` : ''}`;
export function renderDoc(page: DocPage, template: string): string {
  const url = `https://vhalla.com${docHref(page)}`;
  const head = template.slice(0, template.indexOf('  <body>'))
    .replace(/<title>.*?<\/title>/, `<title>${escape(page.kicker)} — vhalla documentation</title>`)
    .replace(/<meta name="description" content="[^"]*">/, `<meta name="description" content="${escape(page.summary)}">`)
    .replace(/<meta property="og:title" content="[^"]*">/, `<meta property="og:title" content="${escape(page.title)} — vhalla">`)
    .replace(/<meta property="og:description" content="[^"]*">/, `<meta property="og:description" content="${escape(page.summary)}">`)
    .replace(/<meta property="og:url" content="[^"]*">/, `<meta property="og:url" content="${url}">`)
    .replace(/<meta name="twitter:title" content="[^"]*">/, `<meta name="twitter:title" content="${escape(page.title)} — vhalla">`)
    .replace(/<meta name="twitter:description" content="[^"]*">/, `<meta name="twitter:description" content="${escape(page.summary)}">`)
    .replace(/<link rel="canonical" href="[^"]*">/, `<link rel="canonical" href="${url}">`)
    .replace(/\s*<script type="application\/ld\+json">.*?<\/script>/, '');
  const header = template.match(/<header class="masthead[\s\S]*?<\/header>/)?.[0];
  if (!header) throw new Error('Missing shared masthead');
  const nav = `<nav aria-label="Documentation"><p class="nav-label">Documentation</p>${docs.map(item => `<a href="${docHref(item)}"${item.slug === page.slug ? ' aria-current="page"' : ''}>${escape(item.kicker)}</a>`).join('')}<a class="nav-source" href="https://github.com/hraness/valhalla">View source ↗</a></nav>`;
  const headings = [...page.content.matchAll(/<h2 id="([^"]+)">([^<]+)<\/h2>/g)];
  const toc = headings.length >= 3 ? `<aside class="doc-toc"><nav aria-label="On this page"><p class="nav-label">On this page</p>${headings.map(m=>`<a href="#${m[1]}">${m[2]}</a>`).join('')}</nav></aside>` : '';
  const index=docs.indexOf(page);
  const next=docs[index+1]; const prev=docs[index-1];
  const content=page.content.replaceAll('<div class="table-wrap">','<div class="table-wrap" tabindex="0" role="region" aria-label="Scrollable reference table">');
  return `${head}  <body class="docs-page"><a class="skip-link" href="#main">Skip to content</a><div class="page">${header}
  <details class="mobile-doc-nav"><summary>Documentation · ${escape(page.kicker)}</summary>${nav}</details>
  <div class="docs-layout"><aside class="doc-sidebar">${nav}</aside><main id="main" class="doc-main"><div class="doc-header"><p class="eyebrow">${escape(page.kicker)}</p><h1>${escape(page.title)}</h1><p class="doc-lede">${escape(page.summary)}</p></div><article class="doc-content">${content}</article>
  <nav class="doc-pagination" aria-label="Previous and next documentation">${prev ? `<a href="${docHref(prev)}"><small>Previous</small>← ${escape(prev.kicker)}</a>` : '<span></span>'}${next ? `<a href="${docHref(next)}"><small>Next</small>${escape(next.kicker)} →</a>` : '<span></span>'}</nav>
  <p class="doc-updated">Development documentation · 21 September 2026 · <a href="https://github.com/hraness/valhalla">Inspect the current source ↗</a></p></main>${toc}</div>
  <div class="project-footer"><p>Rooms for agents. Room for people.</p><a href="/docs/status/">Readiness and known gaps →</a></div><!-- hraness-site-footer --></div></body></html>`;
}
