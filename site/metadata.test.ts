import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const index = await readFile(new URL("./index.html", import.meta.url), "utf8");
const vercel = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));

const csp = (): string => {
  const header = vercel.headers.flatMap((h: { headers: { key: string; value: string }[] }) => h.headers).find((h: { key: string }) => h.key === "Content-Security-Policy");
  if (!header) throw new Error("Missing Content-Security-Policy header");
  return header.value;
};

test("page metadata is complete and consistent", () => {
  expect(index).toContain('<link rel="canonical" href="https://vhalla.com/">');
  expect(index).toContain('<meta property="og:url" content="https://vhalla.com/">');
  expect(index).toContain('<meta property="og:site_name" content="vhalla (valhalla)">');
  expect(index).toContain('<meta property="og:image" content="https://vhalla.com/social.png">');
  expect(index).toContain('<meta property="og:image:width" content="1200">');
  expect(index).toContain('<meta property="og:image:height" content="630">');
  expect(index).toContain('<meta name="twitter:card" content="summary_large_image">');
  expect(index).toContain('<meta name="twitter:image" content="https://vhalla.com/social.png">');
  expect(index).toContain('<meta name="twitter:title"');
  expect(index).toContain('<meta name="twitter:description"');
});

test("structured data describes only what the page shows", () => {
  const match = index.match(/<script type="application\/ld\+json">(.+?)<\/script>/);
  if (!match) throw new Error("Missing JSON-LD block");
  const graph = JSON.parse(match[1]);
  const types = graph["@graph"].map((node: { "@type": string }) => node["@type"]);
  expect(types).toEqual(["Organization", "WebSite", "SoftwareApplication", "SoftwareSourceCode"]);
  const app = graph["@graph"][2];
  expect(app.description).toContain("in development");
  expect(app.applicationCategory).toBe("CommunicationApplication");
  expect(app.operatingSystem).toBeUndefined();
  expect(app.offers).toBeUndefined();
});

test("the CSP admits exactly the checked JSON-LD block", () => {
  const match = index.match(/<script type="application\/ld\+json">(.+?)<\/script>/);
  if (!match) throw new Error("Missing JSON-LD block");
  const digest = `sha256-${createHash("sha256").update(match[1], "utf8").digest("base64")}`;
  expect(csp()).toContain(`'${digest}'`);
  expect(csp()).not.toContain("unsafe-inline");
});

test("the social card is a committed 1200×630 PNG", async () => {
  const png = await readFile(new URL("./social.png", import.meta.url));
  expect(png.subarray(0, 8)).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  expect(png.readUInt32BE(16)).toBe(1200);
  expect(png.readUInt32BE(20)).toBe(630);
});
