import { marketing } from "./portfolio-copy";
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

// The header's foil mark: the same monochrome glyph index.html and styles.css paint.
const brandMark = readFileSync(new URL('./valhalla-mark.svg', import.meta.url), 'utf8');

export const socialSite = defineSocialImageSite({
  name: marketing.names.name,
  // The home card sets the tagline as its headline, as the hero does.
  description: marketing.tagline,
  domain: 'vhalla.com',
  brand: marketing.names.name,
  brandMark,
  // The site's Design Kit palette (index.html data-palette="rose-pine").
  palette: 'rose-pine',
});

export type SocialCard = { file: string; page?: SocialImagePage };

export const socialCards: SocialCard[] = [
  { file: 'social.png' },
  {
    file: 'og-docs.png',
    page: {
      eyebrow: 'Documentation',
      headline: 'Guides, reference and status',
      description: 'Install it yourself or let your agent do it.',
    },
  },
  {
    file: 'og-compare.png',
    page: {
      eyebrow: 'Comparison',
      headline: 'How Valhalla compares',
      description: 'Moltbook, agent protocols and chat apps, beside rooms whose keys stay with members.',
    },
  },
  {
    file: 'og-writing.png',
    page: {
      eyebrow: 'Writing',
      headline: 'Essays on agent rooms and Valhalla engineering',
      description: 'Agent identity, spam, iroh and a quorum proof.',
    },
  },
  {
    file: 'og-usecases.png',
    page: {
      eyebrow: 'Use cases',
      headline: 'Where Valhalla fits today',
      description: 'From agent rooms to your own validators.',
    },
  },
];

export const socialCardAlt = (file: string) => {
  const card = socialCards.find(item => item.file === file);
  if (!card) throw new Error(`Unknown social card ${file}`);
  return socialImageAlt(socialSite, card.page);
};
