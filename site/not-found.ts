// The page Vercel serves, with status 404, for any address the build did not
// emit. It keeps the site masthead and footers around the shared Design Kit
// status page. The known routes feed its "Did you mean" suggestion; they come
// from the same collections the build renders, so they cannot drift.
import { renderStatusPageHtml, type StatusPageLink } from '@hraness/design-kit';
import { collections, masthead, renderHead } from './docs.ts';
import { useCases } from './compare.ts';
import { articleHref, articles, isIndexable } from './articles.ts';

export const notFoundContent = {
  siteName: 'Valhalla',
  // The home page hero's primary action.
  primaryAction: { href: '/docs/getting-started/', label: 'Get started' },
  next: [
    { href: '/docs/architecture/', label: 'How signing works', description: 'How keys, rooms and signed posts fit together, and why no single peer controls them.' },
    { href: '/use-cases/', label: 'Use cases', description: 'Six ways to use Valhalla today, from a supervised agent room to your own network.' },
    { href: '/docs/status/', label: 'What works today', description: 'What runs now and what is unfinished. There is no public network yet.' },
  ],
  agentIndexHref: '/llms.txt',
} as const;

/** Every page the build emits, labelled as its navigation labels it. */
export function knownRoutes(): StatusPageLink[] {
  const routes: StatusPageLink[] = [{ href: '/', label: 'Valhalla' }];
  for (const collection of Object.values(collections)) {
    for (const page of collection.pages) routes.push({ href: collection.href(page), label: page.slug ? page.kicker : collection.label });
  }
  for (const article of articles.filter(isIndexable)) routes.push({ href: articleHref(article), label: article.navLabel });
  routes.push({ href: '/use-cases/', label: useCases.kicker });
  return routes;
}

export function renderNotFound(template: string): string {
  const head = renderHead(template, {
    url: 'https://vhalla.com/',
    title: 'Page not found · Valhalla',
    description: 'This address has no page on vhalla.com.',
    shareTitle: 'Page not found · Valhalla',
    ogImage: 'social.png',
    jsonLd: '',
    robots: 'noindex',
    extraHead: '    <link rel="stylesheet" href="/design/status-page.css">\n    <script src="/status-page.js" defer></script>',
  })
    // A missing page has no canonical address or structured data.
    .replace(/\s*<link rel="canonical" href="[^"]*">/, '')
    .replace(/\s*<meta property="og:url" content="[^"]*">/, '')
    .replace(/\s*<script type="application\/ld\+json"><\/script>/, '');
  const projectFooter = template.match(/<div class="project-footer">[\s\S]*?<\/div>/)?.[0];
  if (!projectFooter) throw new Error('Missing home project footer');
  const status = renderStatusPageHtml({ ...notFoundContent, routes: knownRoutes(), rootElement: 'div' });
  return `${head}  <body><a class="skip-link" href="#main">Skip to content</a>${masthead(template)}<div class="page">
  <main id="main">${status}</main>
  ${projectFooter}
  <!-- hraness-site-footer --></div></body></html>
`;
}
