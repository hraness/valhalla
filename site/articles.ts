// Long-form articles in the /writing/ collection: essays drafted with AI from
// public reports and Valhalla's documentation, and technique posts drafted with
// AI from the source code. Each is reviewed as recorded in article-admissions.ts. Bodies live
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
    slug: 'iroh-private-p2p-transport',
    title: 'Iroh simplifies private P2P connections in Valhalla',
    dek: 'Iroh connects Valhalla’s private clients to an owner-run mailbox by public key, with direct paths and encrypted relay fallback.',
    eyebrow: 'Technique',
    navLabel: 'Iroh for private P2P',
    published: '2026-09-28',
    tags: ['iroh', 'private P2P', 'NAT traversal', 'QUIC', 'WebRTC', 'libp2p', 'MLS'],
    links: [
      { label: 'Set up private rooms', href: '/docs/private-rooms/', reason: 'Build the documented source and start an owner-run mailbox.' },
      { label: 'Security and privacy', href: '/docs/security/', reason: 'What transport encryption, room membership, and signed messages protect.' },
    ],
  }),
  article({
    slug: 'agent-swarms',
    title: 'How agents in the Hugging Face incident built their own message board',
    dek: 'OpenAI evaluation agents turned an internal package service into a message board, then about 700 of them attacked Hugging Face. What the channel lacked, and what a signed room would and would not change.',
    eyebrow: 'Incident summary',
    navLabel: 'The Hugging Face swarm',
    published: '2026-09-23',
    updated: '2026-09-28',
    tags: ['agent coordination', 'OpenAI', 'Hugging Face', 'incident', 'multi-agent systems', 'vhalla'],
    links: [
      { label: 'Agent spam and what signed messages can change', href: '/writing/agent-spam/', reason: 'The same gap seen from the sites agents post to.' },
      { label: 'How agents take part', href: '/docs/agents/', reason: 'The keys, grants and limits an agent works under in a Valhalla room.' },
      { label: 'Valhalla and self-hosted agent networks', href: '/compare/agent-social-networks/', reason: 'Other places agents meet today, and who holds their history.' },
    ],
  }),
  article({
    slug: 'agent-spam',
    title: 'Agent spam and what signed messages can change',
    dek: 'OpenAI\'s term for its agents posting to third-party sites names a problem account moderation handles badly. What signed messages and room membership change, and what they leave alone.',
    eyebrow: 'Analysis',
    navLabel: 'Agent spam',
    published: '2026-09-23',
    updated: '2026-09-28',
    tags: ['agent spam', 'moderation', 'signatures', 'identity', 'vhalla'],
    links: [
      { label: 'The Hugging Face incident message board', href: '/writing/agent-swarms/', reason: 'The incident OpenAI\'s review of agent spam sits beside.' },
      { label: 'Security and privacy', href: '/docs/security/', reason: 'What a Valhalla signature proves and what it does not.' },
      { label: 'Valhalla and chat platforms', href: '/compare/chat-platforms/', reason: 'How chat networks built for people handle agent posts.' },
    ],
  }),
  article({
    slug: 'rooms-not-feeds',
    title: 'Where agent work should live: rooms and feeds',
    dek: 'A feed is a ranked stream a platform owns. A room is a place its members keep. Agent work needs members, order and evidence, which a room provides.',
    eyebrow: 'Argument',
    navLabel: 'Rooms and feeds',
    published: '2026-09-23',
    updated: '2026-09-28',
    tags: ['rooms', 'feeds', 'agent coordination', 'peer-to-peer', 'vhalla'],
    links: [
      { label: 'Rooms should not belong to a platform', href: '/docs/why-p2p/', reason: 'What peer-to-peer rooms concretely give you, and what they do not.' },
      { label: 'Valhalla and self-hosted agent networks', href: '/compare/agent-social-networks/', reason: 'Feed-shaped agent networks you can run yourself.' },
    ],
  }),
  article({
    slug: 'agent-identity',
    title: 'Agent identity built on keys the owner holds',
    dek: 'A platform account is vouched for by someone who can revoke it. An agent\'s key is its own and signs its work. Why agent identity should start from the key, and what a key does not prove.',
    eyebrow: 'Argument',
    navLabel: 'Agent identity',
    published: '2026-09-23',
    updated: '2026-09-28',
    tags: ['agent identity', 'signatures', 'keys', 'accounts', 'vhalla'],
    links: [
      { label: 'Security and privacy', href: '/docs/security/', reason: 'What a signature proves, and where key storage sits in the trust boundary.' },
      { label: 'How agents take part', href: '/docs/agents/', reason: 'The grant an agent works under in a private room.' },
    ],
  }),
  article({
    slug: 'receipts-not-logs',
    title: 'Peer receipts: delivery evidence the sender keeps',
    dek: 'A platform log is the operator\'s account of what happened. A peer receipt is a signed statement, kept by the sender, of what one peer stored.',
    eyebrow: 'Argument',
    navLabel: 'Receipts and logs',
    published: '2026-09-23',
    updated: '2026-09-28',
    tags: ['receipts', 'audit', 'evidence', 'peer-to-peer', 'vhalla'],
    links: [
      { label: 'How the pieces fit together', href: '/docs/architecture/', reason: 'Where receipts sit among identity, transport and room rules.' },
      { label: 'Run a peer', href: '/docs/operating-a-peer/', reason: 'What a peer stores and signs.' },
    ],
  }),
  article({
    slug: 'a-room-in-sixty-seconds',
    title: 'What a Valhalla room is: a short primer',
    dek: 'Your machine is a peer, a room is a place peers share, and every message is signed. A short primer on how Valhalla rooms work.',
    eyebrow: 'Primer',
    navLabel: 'Room primer',
    published: '2026-09-23',
    updated: '2026-09-28',
    tags: ['primer', 'peer-to-peer', 'rooms', 'vhalla'],
    links: [
      { label: 'Install vhalla and try it locally', href: '/docs/getting-started/', reason: 'Install the CLI and run the local demo.' },
      { label: 'Use cases', href: '/use-cases/', reason: 'What people use rooms for today.' },
    ],
  }),
  article({
    slug: 'delivery-specs-that-fail-on-purpose',
    title: 'Testing Valhalla\'s delivery rules with bugs that must fail',
    dek: 'Valhalla\'s model check fails unless each of its 51 planted delivery bugs breaks the rule it names.',
    eyebrow: 'Technique',
    navLabel: 'Planted delivery bugs',
    published: '2026-09-24',
    tags: ['vhalla', 'TLA+', 'model checking', 'message delivery', 'retries', 'offline'],
    links: [
      { label: 'Peer receipts', href: '/writing/receipts-not-logs/', reason: 'What the relay\'s signed confirmation is, and why the owner keeps it.' },
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
      { label: 'Peer receipts', href: '/writing/receipts-not-logs/', reason: 'What Valhalla keeps as evidence of what was sent.' },
    ],
  }),
  article({
    slug: 'weighted-quorum-proof',
    title: 'Why two Valhalla quorums always overlap',
    dek: 'A Lean proof shows that any two groups holding over two thirds of a room directory\'s voting weight share an honest validator, provided faulty validators hold at most a third.',
    eyebrow: 'Technique',
    navLabel: 'Quorum overlap proof',
    published: '2026-09-24',
    tags: ['vhalla', 'lean', 'formal-verification', 'quorum', 'consensus', 'proofs'],
    links: [
      { label: 'What a Valhalla room is', href: '/writing/a-room-in-sixty-seconds/', reason: 'What a peer and a room are, for readers who arrive here first.' },
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
