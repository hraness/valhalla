import { access, cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createHash } from "node:crypto";
import { supportFooter } from "./support-footer.ts";
import { docs } from "./pages.ts";
import { compare } from "./compare.ts";
import { renderDoc, renderCompare, renderUseCases } from "./docs.ts";
const root = import.meta.dir;
const output = resolve(root, "dist");
const kit = dirname(fileURLToPath(import.meta.resolve("@hraness/design-kit/paper-theme.css")));
await rm(output, { recursive: true, force: true });
await mkdir(resolve(output, "design"), { recursive: true });
for (const name of ["styles.css", "icon.png", "apple-icon.png", "social.png", "robots.txt", "sitemap.xml", "llms.txt", "valhalla-mark.svg"]) await cp(resolve(root, name), resolve(output, name));
const html = await readFile(resolve(root, "index.html"), "utf8");
const footerMarker = "<!-- hraness-site-footer -->";
if (html.split(footerMarker).length !== 2) throw new Error("Expected one shared footer slot.");
await writeFile(resolve(output, "index.html"), html.replace(footerMarker, supportFooter()));
for (const page of docs) {
  const target = resolve(output, "docs", page.slug);
  await mkdir(target, { recursive: true });
  const rendered = renderDoc(page, html);
  if (rendered.split(footerMarker).length !== 2) throw new Error(`Expected one footer slot: ${page.slug}`);
  await writeFile(resolve(target, "index.html"), rendered.replace(footerMarker, supportFooter()));
}
for (const page of compare) {
  const target = resolve(output, "compare", page.slug);
  await mkdir(target, { recursive: true });
  const rendered = renderCompare(page, html);
  if (rendered.split(footerMarker).length !== 2) throw new Error(`Expected one footer slot: compare/${page.slug}`);
  await writeFile(resolve(target, "index.html"), rendered.replace(footerMarker, supportFooter()));
}
await mkdir(resolve(output, "use-cases"), { recursive: true });
const useCasesHtml = renderUseCases(html);
if (useCasesHtml.split(footerMarker).length !== 2) throw new Error("Expected one footer slot: use-cases");
await writeFile(resolve(output, "use-cases", "index.html"), useCasesHtml.replace(footerMarker, supportFooter()));
await cp(fileURLToPath(import.meta.resolve("@hraness/site-footer/stylex.css")), resolve(output, "footer.css"));
const files = ["paper-theme.css", "product-marketing-preset.css", "product-marketing.css", "syntax-highlighting.css", "lantern-material.css", "appearance-menu.css", "fonts.css"];
for (const name of files) await cp(resolve(kit, name), resolve(output, "design", name));
// Keep the exact web fonts and license/provenance files, not native OTF copies
// or the embedded TypeScript font data used only by social-card generators.
for (const family of ["nebula-sans", "instrument-serif", "geist-mono"]) {
  await cp(resolve(kit, "fonts", family), resolve(output, "design/fonts", family), {
    recursive: true,
    filter: path => !/\.(?:otf|ttf|ts|js)$/i.test(path),
  });
}
// Every font declared by the unchanged shared stylesheet must be deployable.
const fontCSS = await readFile(resolve(output, "design/fonts.css"), "utf8");
for (const match of fontCSS.matchAll(/url\(["']?(\.\/fonts\/[^"')]+)["']?\)/g)) {
  await access(resolve(output, "design", match[1]));
}
await cp(resolve(kit, "marketing-assets"), resolve(output, "design/marketing-assets"), { recursive: true });
await cp(resolve(kit, "../LICENSE"), resolve(output, "design/LICENSE"));
const result = await Bun.build({ entrypoints: [resolve(root, "appearance.ts")], outdir: output, naming: "appearance.js", target: "browser", format: "iife", minify: true });
if (!result.success) throw new AggregateError(result.logs, "Appearance bundle failed");
const pkg = JSON.parse(await readFile(resolve(kit, "../package.json"), "utf8"));
await writeFile(resolve(output, "design/source.json"), JSON.stringify({ package: pkg.name, version: pkg.version, files: Object.fromEntries(await Promise.all(files.map(async name => [name, createHash("sha256").update(await readFile(resolve(output, "design", name))).digest("hex")]))) }, null, 2));
console.log(`Built Vhalla home, ${docs.length} documentation pages, ${compare.length} comparisons and use cases with ${pkg.name}@${pkg.version}.`);
