import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { agentSetupTargets } from "@hraness/design-kit";
import { renderAgentSetup, vhallaDaemonPrompt, vhallaInstallPrompt } from "./agent-setup.ts";
import { docs } from "./pages.ts";
import { renderDoc } from "./docs.ts";

const template = await readFile(new URL("./index.html", import.meta.url), "utf8");
const setup = renderDoc(docs.find(page => page.slug === "agent-setup")!, template);
const unescape = (value: string) => value.replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&quot;", '"').replaceAll("&#x27;", "'").replaceAll("&amp;", "&");

test("both setup sources use the shared composition with complete caller-authored text", () => {
  expect(setup.match(/data-hraness-agent-setup-prompt=""/gu)).toHaveLength(2);
  const sources = [...setup.matchAll(/<pre[^>]*class="[^"]*\bhraness-agent-setup__full\b[^"]*"[^>]*>([\s\S]*?)<\/pre>/gu)].map(match => unescape(match[1]!));
  expect(sources).toEqual([vhallaDaemonPrompt, vhallaInstallPrompt]);
  expect(vhallaInstallPrompt).toContain("stop if the checksum fails");
  expect(vhallaInstallPrompt).toContain("Do not pin any network or create identities");
  expect(vhallaDaemonPrompt).toContain("cargo +1.98.1 build --locked -p vhalla-cli --bin vhalla");
  expect(vhallaDaemonPrompt).toContain("./target/debug/vhalla daemon --help");
  expect(vhallaDaemonPrompt).toContain("do not substitute it for this source build");
});

test("provider destinations use each full source and never include placeholders for the install prompt", () => {
  for (const prompt of [vhallaDaemonPrompt, vhallaInstallPrompt]) {
    const html = renderAgentSetup("test-source", prompt, "Set up Valhalla");
    for (const target of agentSetupTargets(prompt)) {
      expect(html).toContain(`data-agent-target="${target.id}"`);
      expect(html).toContain(`data-agent-target-mode="${target.mode}"`);
      expect(unescape(html)).toContain(`href="${target.href}"`);
      if (target.mode === "prefill") expect(new URL(target.href).searchParams.get(target.id === "cursor" ? "text" : "prompt")).toBe(prompt);
    }
    expect(html).not.toContain("javascript:");
  }
});

test("server rendering has distinct accessible IDs, native full-source disclosures and inert copy buttons", () => {
  const ids = [...setup.matchAll(/\bid="([^"]+)"/gu)].map(match => match[1]);
  expect(new Set(ids).size).toBe(ids.length);
  expect(setup.match(/<details class="[^"]*hraness-agent-setup__details\b/gu)).toHaveLength(2);
  const buttons = [...setup.matchAll(/<button\b[^>]*class="[^"]*\bhraness-agent-setup__copy\b[^>]*>/gu)];
  expect(buttons).toHaveLength(2);
  for (const [button] of buttons) expect(button).toContain(" hidden>");
  expect(setup).toContain('<link rel="stylesheet" href="/design/stylex.css">');
  expect(setup).toContain('<script src="/platform-install-client.js" defer></script>');
  expect(setup).not.toMatch(/\son(?:click|load|error)=/u);
  expect(setup).not.toMatch(/\sstyle=/u);
});
