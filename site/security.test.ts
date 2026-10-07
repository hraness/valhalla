import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";

const vercel = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));
const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const catchAll = vercel.headers.find((rule: { source: string }) => rule.source === "/(.*)");
const header = (key: string): string | undefined => catchAll.headers.find((h: { key: string }) => h.key === key)?.value;

test("every response carries the baseline security headers", () => {
  expect(header("Strict-Transport-Security")).toMatch(/^max-age=\d{8,}; includeSubDomains$/u);
  expect(header("X-Frame-Options")).toBe("DENY");
  expect(header("X-Content-Type-Options")).toBe("nosniff");
  expect(header("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
  expect(header("Content-Security-Policy")).toContain("frame-ancestors 'none'");
  expect(header("Content-Security-Policy")).not.toContain("'unsafe-inline'");
  expect(header("Content-Security-Policy")).not.toContain("'unsafe-eval'");
});

test("publishes a current security.txt that the build copies", async () => {
  const text = await readFile(new URL("./.well-known/security.txt", import.meta.url), "utf8");
  expect(text).toContain("Contact: https://github.com/hraness/valhalla/security/advisories/new");
  const expires = /^Expires: (.+)$/mu.exec(text)?.[1];
  expect(Date.parse(expires ?? "")).toBeGreaterThan(Date.now());
  expect(await readFile(new URL("./build.ts", import.meta.url), "utf8")).toContain('".well-known", "security.txt"');
  expect(vercel.headers.some((rule: { source: string }) => rule.source === "/.well-known/security.txt")).toBe(true);
});

test("package metadata states the MIT license", async () => {
  expect(pkg.license).toBe("MIT");
  expect(await readFile(new URL("../LICENSE", import.meta.url), "utf8")).toStartWith("MIT License");
});

test("workflow actions are pinned to full commit SHAs", async () => {
  const { readdir } = await import("node:fs/promises");
  const dir = new URL("../.github/workflows/", import.meta.url);
  for (const name of (await readdir(dir)).filter(file => file.endsWith(".yml"))) {
    const source = await readFile(new URL(name, dir), "utf8");
    for (const [, ref] of source.matchAll(/^\s*-?\s*uses:\s*(\S+)/gmu)) {
      if (ref!.startsWith("./")) continue;
      expect(`${name}: ${ref}`).toMatch(/@[0-9a-f]{40}$/u);
    }
  }
});
