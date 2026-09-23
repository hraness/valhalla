#!/usr/bin/env node
// Regenerate Formula/vhalla.rb for a release tag: fetches each archive's
// published .sha256 sidecar so the formula carries the same immutable sums
// the release page serves. Usage: node tools/brew-formula.mjs [vX.Y.Z]
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const tag = process.argv[2] ?? 'v0.2.1';
const version = tag.replace(/^v/, '');
const base = `https://github.com/hraness/valhalla/releases/download/${tag}`;
const assets = {
  'aarch64-apple-darwin': `valhalla-${tag}-aarch64-apple-darwin.tar.gz`,
  'x86_64-unknown-linux-gnu': `valhalla-${tag}-x86_64-unknown-linux-gnu.tar.gz`,
};

const sums = {};
for (const [target, name] of Object.entries(assets)) {
  const response = await fetch(`${base}/${name}.sha256`);
  if (!response.ok) throw new Error(`${name}.sha256: HTTP ${response.status}`);
  const text = await response.text();
  const [sum, file] = text.trim().split(/\s+/);
  if (file !== name) throw new Error(`${name}.sha256 names ${file}`);
  if (!/^[0-9a-f]{64}$/.test(sum)) throw new Error(`${name}: bad digest '${sum}'`);
  sums[target] = sum;
}

const formula = `# frozen_string_literal: true

# Binary distribution of the vhalla CLI from immutable GitHub release
# archives. Regenerate checksums/versions with: node tools/brew-formula.mjs
class Vhalla < Formula
  desc "Peer-to-peer rooms for AI agents and the people who own them"
  homepage "https://vhalla.com"
  version "${version}"
  license "MIT"

  on_macos do
    on_arm do
      url "${base}/${assets['aarch64-apple-darwin']}"
      sha256 "${sums['aarch64-apple-darwin']}"
    end
  end

  on_linux do
    on_intel do
      url "${base}/${assets['x86_64-unknown-linux-gnu']}"
      sha256 "${sums['x86_64-unknown-linux-gnu']}"
    end
  end

  def install
    binary = Dir.glob("**/vhalla").find { |path| File.file?(path) }
    odie "release archive did not contain a vhalla binary" if binary.nil?
    bin.install binary => "vhalla"
  end

  test do
    assert_match "vhalla identity", shell_output("#{bin}/vhalla --help")
  end
end
`;

const path = resolve(new URL('..', import.meta.url).pathname, 'Formula/vhalla.rb');
await writeFile(path, formula);
console.log(`wrote ${path} for ${tag}`);
