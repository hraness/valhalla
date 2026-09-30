import assert from 'node:assert/strict';
import {readFile, realpath} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {dirname, isAbsolute, join} from 'node:path';

const require = createRequire(import.meta.url);
const revisionPath = /[/\\]((?:chromium|chromium_headless_shell|chrome-headless-shell)-\d+)[/\\]/u;
const installedChrome = /[/\\]Google Chrome\.app[/\\]/iu;

// An override is an alias for the repository's provisioned browser, not a
// second selection mechanism. Resolve both paths before any process starts.
export async function pinnedBrowserExecutable(pinned, override = pinned) {
  assert.ok(typeof pinned === 'string' && isAbsolute(pinned), 'The pinned browser must name an absolute executable.');
  assert.ok(typeof override === 'string' && isAbsolute(override), 'Browser executable must be an absolute path.');
  const revision = pinned.match(revisionPath)?.[1];
  assert.ok(revision && !installedChrome.test(pinned), 'Use the versioned Chromium provisioned by this repository, never installed Chrome.');
  const executable = await realpath(pinned);
  assert.ok(!installedChrome.test(executable), 'Installed Chrome and aliases to it cannot be used for qualification.');
  assert.equal(executable.match(revisionPath)?.[1], revision, 'The provisioned browser must retain its pinned revision after realpath resolution.');
  assert.equal(await realpath(override), executable, 'Browser override must resolve to this repository\'s pinned Chromium.');
  return executable;
}

export async function resolvePinnedBrowser(override) {
  const manifest = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  const pin = manifest.devDependencies?.['playwright-core'];
  assert.match(pin ?? '', /^\d+\.\d+\.\d+$/u, 'The site needs an exact playwright-core development dependency.');
  let coreManifestPath;
  try { coreManifestPath = require.resolve('playwright-core/package.json'); }
  catch (cause) { throw new Error('Install the frozen site dependencies and provision their Chromium before qualification.', {cause}); }
  const core = JSON.parse(await readFile(coreManifestPath, 'utf8'));
  assert.equal(core.version, pin, 'Installed Playwright must match the repository pin.');
  const browsers = JSON.parse(await readFile(join(dirname(coreManifestPath), 'browsers.json'), 'utf8'));
  const expectedVersion = browsers.browsers.find(browser => browser.name === 'chromium')?.browserVersion;
  assert.match(expectedVersion ?? '', /^\d+\.\d+\.\d+\.\d+$/u, 'Pinned Chromium must declare its browser version.');
  const executablePath = await pinnedBrowserExecutable(require('playwright-core').chromium.executablePath(), override);
  return {executablePath, playwrightVersion: pin, expectedVersion};
}

// Preserve authored feature exclusions while supplying one effective switch.
export function requiredBrowserArgs(args) {
  const features = new Set();
  const retained = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--mute-audio' || arg.startsWith('--mute-audio=')) continue;
    let disabled;
    if (arg.startsWith('--disable-features=')) disabled = arg.slice('--disable-features='.length);
    else if (arg === '--disable-features') {
      disabled = args[++index];
      assert.ok(typeof disabled === 'string' && !disabled.startsWith('--'), '--disable-features needs a value.');
    } else {
      retained.push(arg);
      continue;
    }
    for (const feature of disabled.split(',').map(value => value.trim()).filter(Boolean)) features.add(feature);
  }
  features.add('PaintHolding');
  features.add('MacAppCodeSignClone');
  if (!retained.includes('--enable-automation')) retained.unshift('--enable-automation');
  return ['--mute-audio', '--disable-features=' + [...features].join(','), ...retained];
}

export function assertBrowserArgs(args, profile) {
  assert.ok(Array.isArray(args) && args.every(arg => typeof arg === 'string'), 'The browser must report its physical command line.');
  assert.equal(args.filter(arg => arg === '--mute-audio').length, 1, 'The browser must have one effective mute-audio switch.');
  const switches = args.filter(arg => arg.startsWith('--disable-features='));
  assert.equal(switches.length, 1, 'The browser must have one physical disable-features switch.');
  const features = new Set(switches[0].slice('--disable-features='.length).split(','));
  assert.ok(features.has('PaintHolding') && features.has('MacAppCodeSignClone'), 'The running browser must disable both required features.');
  assert.deepEqual(args.filter(arg => arg.startsWith('--user-data-dir=')), ['--user-data-dir=' + profile], 'The browser must use only its owned temporary profile.');
}

export function assertBrowserVersion(product, expectedVersion) {
  const version = /^(?:Headless)?Chrome\/(\d+\.\d+\.\d+\.\d+)$/u.exec(product ?? '')?.[1];
  assert.equal(version, expectedVersion, 'The running browser must match the Chromium version provisioned by pinned Playwright.');
  return version;
}
