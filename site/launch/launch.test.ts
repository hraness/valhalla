// Pins the launch post's facts and fixtures to the records they come from.
// It checks values, not prose: a changed tour step, release, grant expiry or
// status golden fails here before the post, the social kit or the film drifts.
import { expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { LAUNCH_LIMITS, blueskyPostLength, xPostLength } from '@hraness/design-kit/launch';
import { product } from '@hraness/design-kit/portfolio';
import { articleAdmissions } from '../article-admissions.ts';
import { articleHref, articles, isIndexable } from '../articles.ts';
import { renderArticle } from '../docs.ts';
import { renderHome } from '../home.ts';
import { latestRelease } from '../pages.ts';
import { LAUNCH_SLUG, launchBeats, socialKit } from './beats.ts';
import { notReady } from './cards.tsx';
import { LAUNCH_STATUS, launchFacts, valhallaMessaging } from './facts.ts';
import { launchFilm } from './film.ts';
import { statusGoldenPath, statusLines } from './mockups.tsx';
import { launchStylesheets } from './styles.ts';
import { tourSteps, tourText } from './tour.ts';

const read = (path: string) => readFile(new URL(`../../${path}`, import.meta.url), 'utf8');
const template = await readFile(new URL('../index.html', import.meta.url), 'utf8');
const demo = await read('crates/vhalla-cli/src/demo.rs');
const launch = articles.find(article => article.slug === LAUNCH_SLUG)!;

test('the tour fixture matches every step vhalla demo prints', () => {
  const steps = [...demo.matchAll(/step\(\s*(\d+),\s*"([^"]+)",\s*"((?:[^"\\]|\\.)*)",?\s*\)/g)]
    .map(match => ({ step: Number(match[1]), title: match[2]!, body: match[3]!.replaceAll('\\n', '\n').replaceAll("\\'", "'") }));
  expect(steps.length).toBe(Number(launchFacts.demoSteps.value));
  expect(tourSteps.map(({ step, title, body }) => ({ step, title, body }))).toEqual(steps);
  expect(demo).toContain(`── {number}/${launchFacts.demoSteps.value} · {title}`);
  for (const text of [tourText.agentPost, tourText.agentBio, tourText.bobReply]) expect(demo).toContain(`"${text}"`);
});

test('every launch fact matches the record it names', async () => {
  expect(launchFacts.release.value).toBe(latestRelease);
  // Source can prepare the next version before its archives are published.
  // The launch names the version both installers currently serve.
  expect(await read('site/install.sh')).toContain(`VERSION="${latestRelease}"`);
  expect(await read('site/install.ps1')).toContain(`$Version = '${latestRelease}'`);
  expect(await read('CHANGELOG.md')).toContain(`## ${latestRelease.slice(1)} - `);
  expect(demo).toContain('expiring in one\\nhour');
  expect(launchFacts.grantExpiry.value).toBe('one hour');
  expect(await read('docs/cli-agents.md')).toContain(`exposes exactly ${launchFacts.agentTools.value} tools`);
  expect(await read('README.md')).toContain(`**${LAUNCH_STATUS}.**`);
  expect(template).toContain(`· ${LAUNCH_STATUS}</p>`);
  expect(valhallaMessaging).toEqual(product('valhalla').messaging);
});

test('the status mockup is the vhalla status golden, line for line', async () => {
  const golden = (await readFile(statusGoldenPath, 'utf8')).trimEnd().split('\n');
  const [command, ...output] = statusLines();
  expect(command).toEqual({ kind: 'input', text: 'vhalla status' });
  expect(output.map(line => line.text)).toEqual(golden.slice(0, output.length));
  expect(output.length).toBeGreaterThan(4);
});

test('the limits card names the gaps the readiness page leads with', async () => {
  const pages = await readFile(new URL('../pages.ts', import.meta.url), 'utf8');
  expect(pages).toContain('there is no public network, and private rooms are not ready');
  expect(template).toContain('There is no public network or hosted service to join yet');
  expect(template).toContain('An agent keeps whatever access it already has on your machine; Valhalla does not sandbox it yet.');
  expect(notReady.map(item => item.title)).toEqual(['No public network yet', 'Private rooms are not ready for general use', 'No agent sandbox']);
});

test('beats and the social kit stay inside the launch limits', () => {
  expect(launchBeats.length).toBeGreaterThanOrEqual(7);
  expect(launchBeats.length).toBeLessThanOrEqual(10);
  for (const beat of launchBeats) {
    expect(beat.headline.length, beat.id).toBeLessThanOrEqual(LAUNCH_LIMITS.headline);
    expect(beat.alt.length, beat.id).toBeLessThanOrEqual(LAUNCH_LIMITS.alt);
    expect(beat.post, beat.id).not.toMatch(/\{\w+\}/);
  }
  for (const post of socialKit.x) expect(xPostLength(post)).toBeLessThanOrEqual(280);
  for (const post of socialKit.bluesky) expect(blueskyPostLength(post)).toBeLessThanOrEqual(300);
  expect(JSON.stringify(socialKit)).not.toMatch(/mastodon/i);
});

test('the launch post renders every beat with accessible descriptions and keeps its review state honest', () => {
  const html = renderArticle(launch, template);
  for (const beat of launchBeats) expect(html, beat.id).toContain(`id="beat-${beat.id}"`);
  expect(html).toContain(valhallaMessaging.meta);
  expect(html).toMatch(/aria-label="[^"]+"/u);
  expect(html).not.toContain(' style="');
  for (const href of launchStylesheets) expect(html).toContain(`href="${href}"`);
  const admission = articleAdmissions.find(record => record.href === articleHref(launch))!;
  expect(admission.readerJob).toBe('decide whether to try it');
  if (admission.review === null) {
    expect(isIndexable(launch)).toBe(false);
    expect(html).toContain('<meta name="robots" content="noindex, follow">');
  }
  // The film embeds only when its rendered files are in site/media.
  if (!launchFilm) expect(html).not.toContain('<video');
});

test('the home page shows the tour and room illustrations with no inline styles', () => {
  const html = renderHome(template);
  expect(html).toContain('home-tour');
  expect(html).toContain('Signed and received. Who else is in here?');
  expect(html).not.toContain('<!-- vhalla-launch');
  expect(html).not.toContain(' style="');
  for (const href of launchStylesheets) expect(html).toContain(`href="${href}"`);
});

test('social posts carry claims only: no limits beat and no untested-network line', () => {
  const limits = launchBeats.find(beat => beat.part === 'limits');
  expect(limits).toBeDefined();
  const all = [...socialKit.x, ...socialKit.bluesky, ...socialKit.threads, socialKit.linkedin, ...socialKit.showHnFacts].join('\n');
  expect(all).not.toContain(limits?.post ?? 'missing');
  expect(all).not.toMatch(/not ready|sandbox|tested across/i);
  expect(socialKit.x.length).toBe(launchBeats.length - 1);
});

test('kb/launch/social-kit.md matches the beats and facts; run `bun run launch:kit` after changing them', async () => {
  const { renderSocialKitMarkdown } = await import('./social-kit-markdown.ts');
  const text = await Bun.file(new URL('../../kb/launch/social-kit.md', import.meta.url)).text();
  expect(text).toBe(renderSocialKitMarkdown());
});

test('the site copy of the vhalla status golden matches the CLI golden', async () => {
  expect(await readFile(statusGoldenPath, 'utf8')).toBe(await read('crates/vhalla-cli/tests/fixtures/status/in-sync.w80.txt'));
});
