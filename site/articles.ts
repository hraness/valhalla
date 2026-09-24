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
};

const admissionFor = (slug: string): ArticleAdmission => {
  const admission = articleAdmissions.find(record => record.href === `/writing/${slug}/`);
  if (!admission) throw new Error(`Missing admission record for /writing/${slug}/`);
  return admission;
};

const markdown = (slug: string) => Bun.markdown.html(readFileSync(new URL(`./articles/${slug}.md`, import.meta.url), 'utf8'), { headings: { ids: true } });

const article = (fields: Omit<Article, 'admission' | 'bodyHtml'>): Article => ({ ...fields, admission: admissionFor(fields.slug), bodyHtml: markdown(fields.slug) });

export const articles: Article[] = [
  article({
    slug: 'delivery-specs-that-fail-on-purpose',
    title: 'Testing vhalla\'s delivery rules with bugs that must fail',
    dek: 'vhalla\'s model check fails unless each of its 51 planted delivery bugs breaks the rule it names.',
    eyebrow: 'Technique',
    navLabel: 'Planted delivery bugs',
    published: '2026-09-24',
    tags: ['vhalla', 'TLA+', 'model checking', 'message delivery', 'retries', 'offline'],
    links: [
      { label: 'Checking every interleaving with TLA+ and Quint', href: 'https://hraness.com/reference/correctness/tla-plus-interleavings', reason: 'The general lesson on model checking; this post is the vhalla version.' },
      { label: 'Planted bugs: who tests the tests', href: 'https://hraness.com/reference/correctness/planted-bugs', reason: 'Why a checker that must catch a deliberate mistake is worth more than one that reports no errors.' },
      { label: 'Receipts, not logs', href: '/writing/receipts-not-logs/', reason: 'What the relay\'s signed confirmation is, and why the owner keeps it.' },
      { label: 'Readiness page', href: '/docs/status/', reason: 'What has and has not been tested today, for a reader deciding whether to rely on delivery.' },
    ],
  }),
  article({
    slug: 'ledger-recovery-under-random-crashes',
    title: 'How vhalla uses random restarts to test its ledger',
    dek: 'After every step of a random event history, vhalla\'s tests restore the ledger from its saved bytes and check that the copy is the same ledger.',
    eyebrow: 'Technique',
    navLabel: 'Ledger restarts',
    published: '2026-09-24',
    tags: ['crash recovery', 'stateful testing', 'Hegel', 'Verus', 'Kani', 'Rust', 'vhalla'],
    links: [
      { label: 'Hegel: random operations against a model', href: 'https://hraness.com/reference/correctness/hegel-stateful-testing', reason: 'The technique behind the recovery test.' },
      { label: 'Kani: proofs over every value within chosen sizes', href: 'https://hraness.com/reference/correctness/kani-bounded-proofs', reason: 'The technique behind the spent-set checks.' },
      { label: 'Receipts, not logs', href: '/writing/receipts-not-logs/', reason: 'What vhalla keeps as evidence of what was sent.' },
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
      { label: 'Lean proofs cover the cases your tests skip', href: 'https://hraness.com/reference/correctness/lean-proofs', reason: 'The general technique post that uses this quorum proof as one of its examples.' },
      { label: 'A room in sixty seconds', href: '/writing/a-room-in-sixty-seconds/', reason: 'What a peer and a room are, for readers who arrive here first.' },
      { label: 'Readiness page', href: '/docs/status/', reason: 'What has and has not been tested so far.' },
    ],
  }),
];

export const articleHref = (article: Article) => `/writing/${article.slug}/`;
export const isIndexable = (article: Article) => article.admission.lifecycle === 'indexable';
export const indexableArticles = articles.filter(isIndexable);

export const articleSources = (article: Article): ArticleSourceItem[] =>
  article.admission.sources.map(source => ({ title: source.title, href: source.url, checkedOn: source.checkedOn }));
