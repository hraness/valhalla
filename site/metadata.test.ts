import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { docs } from "./pages.ts";
import { compare, useCases } from "./compare.ts";
import { writing } from "./writing.ts";
import { renderArticle, renderDoc, renderCompare, renderUseCases, renderWriting, docHref, compareHref, writingHref } from "./docs.ts";
import { articles, articleHref } from "./articles.ts";
import { homeFaq, renderHome } from "./home.ts";
import { socialCardAlt } from "./social-cards.ts";

const index = await readFile(new URL("./index.html", import.meta.url), "utf8");
const home = renderHome(index);
const vercel = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));
const brandAssets = await readFile(new URL("./BRAND_ASSETS.md", import.meta.url), "utf8");

const csp = (): string => {
  const header = vercel.headers.flatMap((h: { headers: { key: string; value: string }[] }) => h.headers).find((h: { key: string }) => h.key === "Content-Security-Policy");
  if (!header) throw new Error("Missing Content-Security-Policy header");
  return header.value;
};

const pages = new Map([["/", home], ...docs.map(page => [docHref(page), renderDoc(page, index)]), ...compare.map(page => [compareHref(page), renderCompare(page, index)]), ...writing.map(page => [writingHref(page), renderWriting(page, index)]), ...articles.map(article => [articleHref(article), renderArticle(article, index)]), ["/use-cases/", renderUseCases(index)]]);

test("page metadata is complete and consistent", () => {
  expect(index).toContain('<link rel="canonical" href="https://vhalla.com/">');
  expect(index).toContain('<meta property="og:url" content="https://vhalla.com/">');
  expect(index).toContain('<meta property="og:site_name" content="Valhalla">');
  expect(index).toContain('<meta property="og:image" content="https://vhalla.com/social.png">');
  expect(index).toContain('<meta property="og:image:width" content="1200">');
  expect(index).toContain('<meta property="og:image:height" content="630">');
  expect(index).toContain('<meta name="twitter:card" content="summary_large_image">');
  expect(index).toContain('<meta name="twitter:image" content="https://vhalla.com/social.png">');
  expect(index).toContain('<meta name="twitter:title"');
  expect(index).toContain('<meta name="twitter:description"');
});

test("structured data describes only what the page shows", () => {
  const match = home.match(/<script type="application\/ld\+json">(.+?)<\/script>/);
  if (!match) throw new Error("Missing JSON-LD block");
  const graph = JSON.parse(match[1]);
  const types = graph["@graph"].map((node: { "@type": string }) => node["@type"]);
  expect(types).toEqual(["Organization", "WebSite", "SoftwareApplication", "SoftwareSourceCode", "FAQPage"]);
  const app = graph["@graph"][2];
  expect(app.description).toContain("in development");
  expect(app.applicationCategory).toBe("CommunicationApplication");
  expect(app.operatingSystem).toBeUndefined();
  expect(app.offers).toBeUndefined();
  const faq = graph["@graph"][4];
  const questions = index.matchAll(/hraness-marketing-question__summary">([^<]+)</g);
  expect(faq.mainEntity.length).toBe([...questions].length);
  // The structured FAQ is built from the visible one, word for word.
  const structured = faq.mainEntity.map((entry: { name: string; acceptedAnswer: { text: string } }) => ({ question: entry.name, answer: entry.acceptedAnswer.text }));
  expect(structured).toEqual(homeFaq(index));
  for (const { question, answer } of structured) {
    expect(question.length, question).toBeGreaterThan(0);
    expect(answer.length, question).toBeGreaterThan(0);
  }
});

const metaContent = (html: string, attribute: string, name: string) => html.match(new RegExp(`<meta ${attribute}="${name}" content="([^"]*)">`))?.[1];

test("titles, descriptions and share text use no em dashes", () => {
  for (const [path, html] of pages) {
    const fields = [
      html.match(/<title>([^<]*)<\/title>/)?.[1],
      metaContent(html, "name", "description"),
      metaContent(html, "property", "og:title"),
      metaContent(html, "property", "og:description"),
      metaContent(html, "property", "og:image:alt"),
      metaContent(html, "name", "twitter:title"),
      metaContent(html, "name", "twitter:description"),
      metaContent(html, "name", "twitter:image:alt"),
    ];
    for (const field of fields) {
      expect(field, path).toBeDefined();
      expect(field, path).not.toContain("\u2014");
    }
  }
});

test("social image alt text describes the card each page uses", () => {
  for (const [path, html] of pages) {
    const image = metaContent(html, "property", "og:image")?.replace("https://vhalla.com/", "");
    if (!image) throw new Error(`Missing og:image on ${path}`);
    const alt = socialCardAlt(image).replaceAll("&", "&amp;").replaceAll('"', "&quot;");
    expect(socialCardAlt(image).length, path).toBeLessThanOrEqual(125);
    expect(metaContent(html, "property", "og:image:alt"), path).toBe(alt);
    expect(metaContent(html, "name", "twitter:image:alt"), path).toBe(alt);
  }
});

test("every page carries one JSON-LD block whose hash is admitted by the CSP", () => {
  for (const [path, html] of pages) {
    const blocks = [...html.matchAll(/<script type="application\/ld\+json">(.+?)<\/script>/g)];
    expect(blocks.length, path).toBe(1);
    const digest = `sha256-${createHash("sha256").update(blocks[0][1], "utf8").digest("base64")}`;
    expect(csp(), `${path} JSON-LD ${digest}`).toContain(`'${digest}'`);
    const parsed = JSON.parse(blocks[0][1]);
    expect(Array.isArray(parsed["@graph"]), path).toBe(true);
  }
  expect(csp()).not.toContain("unsafe-inline");
});

test("collection pages carry their own social card", () => {
  const expected: [string, string][] = [
    ["/docs/", "og-docs.png"],
    ["/docs/getting-started/", "og-docs.png"],
    ["/compare/", "og-compare.png"],
    ["/compare/moltbook/", "og-compare.png"],
    ["/writing/", "og-writing.png"],
    ["/writing/agent-swarms/", "og-writing.png"],
    ["/use-cases/", "og-usecases.png"],
  ];
  for (const [path, image] of expected) {
    const html = pages.get(path);
    if (!html) throw new Error(`Missing page ${path}`);
    expect(html, path).toContain(`<meta property="og:image" content="https://vhalla.com/${image}">`);
    expect(html, path).toContain(`<meta name="twitter:image" content="https://vhalla.com/${image}">`);
  }
});

test("every social card is a committed 1200×630 PNG", async () => {
  for (const name of ["social.png", "og-docs.png", "og-compare.png", "og-writing.png", "og-usecases.png"]) {
    const png = await readFile(new URL(`./${name}`, import.meta.url));
    expect(png.subarray(0, 8), name).toEqual(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
    expect(png.readUInt32BE(16), name).toBe(1200);
    expect(png.readUInt32BE(20), name).toBe(630);
    const digest = createHash("sha256").update(png).digest("hex");
    expect(brandAssets, `${name} hash in BRAND_ASSETS.md`).toContain(`\`${name}\` SHA-256: \`${digest}\``);
  }
});
