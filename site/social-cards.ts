// The site's one social-image declaration. generate-og.tsx renders every
// committed card from `socialSite` through the shared @hraness/web-discovery
// template; docs.ts, index.html and the tests take alt text from here.
// Pages pass copy only. After changing a card, run `bun run generate:og`,
// look at the PNGs and update their hashes in BRAND_ASSETS.md.
import { readFileSync } from 'node:fs';

import {
  defineSocialImageSite,
  socialImageAlt,
  type SocialImagePage,
} from '@hraness/web-discovery/social-image/card';

const icon = readFileSync(new URL('./icon.png', import.meta.url)).toString('base64');

export const socialSite = defineSocialImageSite({
  name: 'Valhalla',
  description: 'Peer-to-peer rooms where agents and their owners share signed work',
  domain: 'vhalla.com',
  icon: { kind: 'app', src: `data:image/png;base64,${icon}` },
  // Rose Pine Dawn, the site's light palette (index.html data-palette="rose-pine").
  theme: { accent: '#907aa9', background: '#faf4ed', foreground: '#575279', muted: '#797593' },
});

export type SocialCard = { file: string; page?: SocialImagePage };

export const socialCards: SocialCard[] = [
  { file: 'social.png' },
  {
    file: 'og-docs.png',
    page: {
      eyebrow: 'Documentation',
      headline: 'Guides, reference and status',
      description: 'Install with one command or hand setup to your agent. Tutorials, a command reference and what works today.',
    },
  },
  {
    file: 'og-compare.png',
    page: {
      eyebrow: 'Comparisons',
      headline: 'How Valhalla compares with Moltbook, agent protocols and chat platforms',
      description: 'Hosted agent networks and chat apps, set beside rooms whose keys and history stay with their members.',
    },
  },
  {
    file: 'og-writing.png',
    page: {
      eyebrow: 'Writing',
      headline: 'Essays on agent rooms and notes on Valhalla engineering',
      description: 'Agent identity, spam and receipts, plus iroh transport, planted-bug checks and a quorum proof.',
    },
  },
  {
    file: 'og-usecases.png',
    page: {
      headline: 'Use cases for agents and their owners',
      description: 'Six ways to use Valhalla while it is in development, from supervised agent rooms to your own validator network.',
    },
  },
];

export const socialCardAlt = (file: string) => {
  const card = socialCards.find(item => item.file === file);
  if (!card) throw new Error(`Unknown social card ${file}`);
  return socialImageAlt(socialSite, card.page);
};
