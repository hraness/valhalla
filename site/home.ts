// Renders the home page. The FAQPage structured data is built from the visible
// FAQ at build time, so search engines and readers get the same questions and
// answers. Each JSON-LD answer is the text of the first paragraph of the
// visible answer; put "more" links in a later paragraph.
type FaqEntry = { question: string; answer: string };

const decode = (value: string) => value
  .replaceAll('&lt;', '<')
  .replaceAll('&gt;', '>')
  .replaceAll('&quot;', '"')
  .replaceAll('&#39;', "'")
  .replaceAll('&nbsp;', ' ')
  .replaceAll('&amp;', '&');
const text = (html: string) => decode(html.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();

export function homeFaq(template: string): FaqEntry[] {
  const pattern = /<details class="hraness-marketing-question"><summary class="hraness-marketing-question__summary">([\s\S]*?)<\/summary><div class="hraness-marketing-question__answer"><p>([\s\S]*?)<\/p>/g;
  return [...template.matchAll(pattern)].map(match => ({ question: text(match[1]), answer: text(match[2]) }));
}

export function renderHome(template: string): string {
  const faq = homeFaq(template);
  const visible = template.match(/<details class="hraness-marketing-question">/g)?.length ?? 0;
  if (!faq.length || faq.length !== visible) throw new Error(`Home FAQ: parsed ${faq.length} of ${visible} visible questions`);
  const script = template.match(/<script type="application\/ld\+json">(.+?)<\/script>/);
  if (!script) throw new Error('Home page has no JSON-LD block');
  const graph = JSON.parse(script[1]);
  const node = graph['@graph']?.find((item: { '@type'?: string }) => item['@type'] === 'FAQPage');
  if (!node) throw new Error('Home JSON-LD has no FAQPage node');
  node.mainEntity = faq.map(({ question, answer }) => ({ '@type': 'Question', name: question, acceptedAnswer: { '@type': 'Answer', text: answer } }));
  const json = JSON.stringify(graph).replaceAll('<', '\\u003c');
  return template.replace(script[0], () => `<script type="application/ld+json">${json}</script>`);
}
