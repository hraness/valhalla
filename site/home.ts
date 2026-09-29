// Renders the home page. The FAQPage structured data is built from the visible
// FAQ at build time, so search engines and readers get the same questions and
// answers. Each JSON-LD answer is the text of the first paragraph of the
// visible answer; put "more" links in a later paragraph.
import { latestRelease } from './pages.ts';
import { vhallaBadges, vhallaInstall } from './platform-install.ts';
import { highlightCode } from '@hraness/design-kit/syntax-highlighting';
import { homeRoomHtml, homeTourHtml } from './launch/mockups.tsx';
import { launchStylesHead, launchStylesMarker } from './launch/styles.ts';

const slot = (template: string, marker: string, html: string) => {
  if (template.split(marker).length !== 2) throw new Error(`Home page needs exactly one ${marker}`);
  return template.replace(marker, () => html);
};

type FaqEntry = { question: string; answer: string };

const decode = (value: string) => value
  .replaceAll('&lt;', '<')
  .replaceAll('&gt;', '>')
  .replaceAll('&quot;', '"')
  .replaceAll('&#39;', "'")
  .replaceAll('&nbsp;', ' ')
  .replaceAll('&amp;', '&');
// Strip tags until the string stops changing, so a tag split by another tag
// cannot survive a single pass.
const stripTags = (html: string) => {
  let previous: string;
  do {
    previous = html;
    html = html.replace(/<[^>]*>/g, '');
  } while (html !== previous);
  return html;
};
const text = (html: string) => decode(stripTags(html)).replace(/\s+/g, ' ').trim();

export function homeFaq(template: string): FaqEntry[] {
  const pattern = /<details class="hraness-marketing-question"><summary class="hraness-marketing-question__summary">([\s\S]*?)<\/summary><div class="hraness-marketing-question__answer"><p>([\s\S]*?)<\/p>/g;
  return [...template.matchAll(pattern)].map(match => ({ question: text(match[1]), answer: text(match[2]) }));
}

export function renderHome(template: string): string {
  template = template.replaceAll('{{LATEST_RELEASE}}', latestRelease);
  template = slot(template, launchStylesMarker, launchStylesHead);
  template = slot(template, '<!-- vhalla-launch-tour -->', homeTourHtml());
  template = slot(template, '<!-- vhalla-launch-room -->', homeRoomHtml());
  template = template.replace('<!-- vhalla-platform-install -->', vhallaInstall('install-home'));
  template = template.replace('<!-- vhalla-platform-badges -->', vhallaBadges());
  template = template.replace(/<(code|span) data-home-code="shell">([\s\S]*?)<\/\1>/g, (_match, tag: string, source: string) => {
    const code = highlightCode(decode(source), 'shell', { styles: 'classes' });
    return `<${tag} class="${code.className}" data-language="${code.language}">${code.html}</${tag}>`;
  });
  const faq = homeFaq(template);
  const visible = template.match(/<details class="hraness-marketing-question">/g)?.length ?? 0;
  if (!faq.length || faq.length !== visible) throw new Error(`Home FAQ: parsed ${faq.length} of ${visible} visible questions`);
  const script = template.match(/<script type="application\/ld\+json">(.+?)<\/script>/);
  if (!script) throw new Error('Home page has no JSON-LD block');
  const graph = JSON.parse(script[1]);
  const node = graph['@graph']?.find((item: { '@type'?: string }) => item['@type'] === 'FAQPage');
  if (!node) throw new Error('Home JSON-LD has no FAQPage node');
  const software = graph['@graph']?.find((item: { '@type'?: string }) => item['@type'] === 'SoftwareApplication');
  if (!software) throw new Error('Home JSON-LD has no SoftwareApplication node');
  software.softwareVersion = latestRelease.replace(/^v/, '');
  node.mainEntity = faq.map(({ question, answer }) => ({ '@type': 'Question', name: question, acceptedAnswer: { '@type': 'Answer', text: answer } }));
  const json = JSON.stringify(graph).replaceAll('<', '\\u003c');
  return template.replace(script[0], () => `<script type="application/ld+json">${json}</script>`);
}
