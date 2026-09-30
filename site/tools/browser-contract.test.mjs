import {expect, test} from 'bun:test';
import {mkdir, mkdtemp, realpath, rm, symlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {assertBrowserArgs, assertBrowserVersion, pinnedBrowserExecutable, requiredBrowserArgs} from './browser-contract.mjs';

async function fixture(work) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'vhalla-browser-contract-')));
  const file = async path => {
    const target = join(root, path);
    await mkdir(join(target, '..'), {recursive: true});
    await writeFile(target, 'unlaunched browser fixture\n');
    return target;
  };
  try { await work({root, file}); }
  finally { await rm(root, {recursive: true}); }
}

test('the default and an alias resolve only to the provisioned browser', async () => fixture(async ({root, file}) => {
  const pinned = await file('chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
  const alias = join(root, 'browser-alias');
  await symlink(pinned, alias);
  expect(await pinnedBrowserExecutable(pinned)).toBe(pinned);
  expect(await pinnedBrowserExecutable(pinned, alias)).toBe(pinned);
  await expect(pinnedBrowserExecutable('relative/chromium-1234/chrome')).rejects.toThrow('absolute');
  await expect(pinnedBrowserExecutable(pinned, 'chrome')).rejects.toThrow('absolute');
}));

test('installed Chrome, a misleading cache symlink, and a different revision are rejected', async () => fixture(async ({root, file}) => {
  const system = await file('Applications/Google Chrome.app/Contents/MacOS/Google Chrome');
  const pinned = await file('chromium-1234/chrome');
  const other = await file('chromium-1235/chrome');
  const disguised = join(root, 'chromium-1234', 'disguised-chrome');
  await symlink(system, disguised);
  await expect(pinnedBrowserExecutable(system)).rejects.toThrow('never installed Chrome');
  await expect(pinnedBrowserExecutable(pinned, system)).rejects.toThrow('pinned Chromium');
  await expect(pinnedBrowserExecutable(disguised)).rejects.toThrow('Installed Chrome');
  await expect(pinnedBrowserExecutable(pinned, other)).rejects.toThrow('pinned Chromium');
  const drifted = join(root, 'chromium-1234', 'drifted-chrome');
  await symlink(other, drifted);
  await expect(pinnedBrowserExecutable(drifted)).rejects.toThrow('pinned revision');
}));

test('required flags merge all existing exclusions into one switch and retain authored args', () => {
  const input = ['--headless', '--disable-features=ExistingFeature,PaintHolding', '--mute-audio',
    '--disable-features', 'AnotherFeature,ExistingFeature', '--user-data-dir=/owned/profile', 'about:blank'];
  const args = requiredBrowserArgs(input);
  expect(args.filter(arg => arg === '--mute-audio')).toHaveLength(1);
  expect(args.filter(arg => arg.startsWith('--disable-features='))).toEqual([
    '--disable-features=ExistingFeature,PaintHolding,AnotherFeature,MacAppCodeSignClone',
  ]);
  expect(args.slice(2)).toEqual(['--enable-automation', '--headless', '--user-data-dir=/owned/profile', 'about:blank']);
  expect(input).toHaveLength(7);
  expect(() => requiredBrowserArgs(['--disable-features', '--headless'])).toThrow('needs a value');
});

test('physical browser command lines retain the required features and owned profile', () => {
  const args = requiredBrowserArgs(['--headless', '--user-data-dir=/owned/profile']);
  expect(() => assertBrowserArgs(args, '/owned/profile')).not.toThrow();
  expect(() => assertBrowserArgs([...args, '--disable-features=AnotherFeature'], '/owned/profile')).toThrow('one physical');
  expect(() => assertBrowserArgs(args.filter(arg => arg !== '--mute-audio'), '/owned/profile')).toThrow('mute-audio');
  expect(() => assertBrowserArgs(args.map(arg => arg.startsWith('--disable-features=') ? '--disable-features=PaintHolding' : arg), '/owned/profile')).toThrow('both required');
  expect(() => assertBrowserArgs(args, '/other/profile')).toThrow('owned temporary profile');
});

test('the actual CDP product must match the browser version recorded by the pin', () => {
  expect(assertBrowserVersion('Chrome/151.0.7886.0', '151.0.7886.0')).toBe('151.0.7886.0');
  expect(assertBrowserVersion('HeadlessChrome/151.0.7886.0', '151.0.7886.0')).toBe('151.0.7886.0');
  expect(() => assertBrowserVersion('Chrome/150.0.1.2', '151.0.7886.0')).toThrow('running browser');
  expect(() => assertBrowserVersion('Chromium/unversioned', '151.0.7886.0')).toThrow('running browser');
});
