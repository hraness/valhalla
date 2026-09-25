// Long-form articles in the /writing/ collection, drafted with AI from the
// source code and reviewed as recorded in article-admissions.ts. Bodies live
// in site/articles/<slug>.md and render through Bun's Markdown parser and the
// Design Kit's static article renderer.
import { readFileSync } from 'node:fs';
import type { ArticleAdmission, ArticleIsoDate, ArticleSourceItem } from '@hraness/design-kit';
import { articleAdmissions } from './article-admissions.ts';

export type ArticleLink = { label: string; href: string; reason: string };
export type Article = {
  slug: string;
  title: string;
  dek: string;
  eyebrow: string;
  /** Short label for the collection navigation. */
  navLabel: string;
  published: ArticleIsoDate;
  updated?: ArticleIsoDate;
  tags: string[];
  links: ArticleLink[];
  admission: ArticleAdmission;
  bodyHtml: string;
  /** Second-level headings in order, with their rendered ids and plain source text. */
  headings: { id: string; label: string }[];
};

const admissionFor = (slug: string): ArticleAdmission => {
  const admission = articleAdmissions.find(record => record.href === `/writing/${slug}/`);
  if (!admission) throw new Error(`Missing admission record for /writing/${slug}/`);
  return admission;
};

/** Renders a body and pairs each `## ` heading's source text with the id the renderer gave it. */
const markdown = (slug: string) => {
  const source = readFileSync(new URL(`./articles/${slug}.md`, import.meta.url), 'utf8');
  const bodyHtml = Bun.markdown.html(source, { headings: { ids: true } });
  const ids = [...bodyHtml.matchAll(/<h2 id="([^"]+)">/g)].map(match => match[1]!);
  const labels = [...source.replace(/^```[\s\S]*?^```/gm, '').matchAll(/^## (.+)$/gm)].map(match => match[1]!.trim());
  if (ids.length !== labels.length) throw new Error(`Heading mismatch in site/articles/${slug}.md`);
  return { bodyHtml, headings: ids.map((id, index) => ({ id, label: labels[index]! })) };
};

const article = (fields: Omit<Article, 'admission' | 'bodyHtml' | 'headings'>): Article => ({ ...fields, admission: admissionFor(fields.slug), ...markdown(fields.slug) });

// Further-reading links to hraness.com reference pages are added only once
// those pages return 200 (see each record's refreshTriggers).
export const articles: Article[] = [
  article({
    slug: 'delivery-specs-that-fail-on-purpose',
    title: 'Testing Valhalla\'s delivery rules with bugs that must fail',
    dek: 'Valhalla\'s model check fails unless each of its 51 planted delivery bugs breaks the rule it names.',
    eyebrow: 'Technique',
    navLabel: 'Planted delivery bugs',
    published: '2026-09-24',
    tags: ['vhalla', 'TLA+', 'model checking', 'message delivery', 'retries', 'offline'],
    links: [
      { label: 'Receipts, not logs', href: '/writing/receipts-not-logs/', reason: 'What the relay\'s signed confirmation is, and why the owner keeps it.' },
      { label: 'Readiness page', href: '/docs/status/', reason: 'What has and has not been tested today, for a reader deciding whether to rely on delivery.' },
    ],
  }),
  article({
    slug: 'ledger-recovery-under-random-crashes',
    title: 'How Valhalla uses random restarts to test its ledger',
    dek: 'After every step of a random event history, Valhalla\'s tests restore the ledger from its saved bytes and check that the copy is the same ledger.',
    eyebrow: 'Technique',
    navLabel: 'Ledger restarts',
    published: '2026-09-24',
    tags: ['crash recovery', 'stateful testing', 'Hegel', 'Verus', 'Kani', 'Rust', 'vhalla'],
    links: [
      { label: 'Receipts, not logs', href: '/writing/receipts-not-logs/', reason: 'What Valhalla keeps as evidence of what was sent.' },
    ],
  }),
  article({
    slug: 'weighted-quorum-proof',
    title: 'Why two Valhalla quorums always overlap',
    dek: 'A Lean proof shows that any two groups holding over two thirds of a room directory\'s voting weight share an honest validator when faulty validators hold at most a third.',
    eyebrow: 'Technique',
    navLabel: 'Quorum overlap proof',
    published: '2026-09-24',
    tags: ['vhalla', 'lean', 'formal-verification', 'quorum', 'consensus', 'proofs'],
    links: [
      { label: 'A room in sixty seconds', href: '/writing/a-room-in-sixty-seconds/', reason: 'What a peer and a room are, for readers who arrive here first.' },
      { label: 'Consensus for a group chat', href: 'https://hraness.com/reference/peer-to-peer-systems/room-scale-consensus', reason: 'Why a room of a few peers needs agreement rules at all; this post is the proof-specific follow-up.' },
      { label: 'Readiness page', href: '/docs/status/', reason: 'What has and has not been tested so far.' },
    ],
  }),
];

export const articleHref = (article: Article) => `/writing/${article.slug}/`;
export const isIndexable = (article: Article) => article.admission.lifecycle === 'indexable';
export const indexableArticles = articles.filter(isIndexable);

export const articleSources = (article: Article): ArticleSourceItem[] =>
  article.admission.sources.map(source => ({ title: source.title, href: source.url, checkedOn: source.checkedOn }));
