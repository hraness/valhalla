import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createSocialImageCard } from "@hraness/web-discovery/social-image/card";
import { Resvg } from "@resvg/resvg-js";
import satori from "satori";

import { socialCards } from "./social-cards.ts";

const siteDirectory = dirname(fileURLToPath(import.meta.url));

const mark = (
  <svg aria-label="vhalla" fill="none" height="42" role="img" viewBox="0 0 42 42" width="42">
    <path d="M4 19 21 6l17 13" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" />
    <path d="M10 23v11M21 23v11M32 23v11" stroke="currentColor" strokeLinecap="round" strokeWidth="3" />
    <path d="M6 38h30" stroke="currentColor" strokeLinecap="round" strokeWidth="3" />
  </svg>
);

const theme = {
  accent: "#9a402f",
  background: "#f3f1e9",
  foreground: "#272b25",
  muted: "#606258",
};

for (const variant of socialCards) {
  const card = createSocialImageCard({
    description: variant.description,
    domain: "vhalla.com",
    eyebrow: variant.eyebrow,
    mark,
    theme,
    title: variant.title,
  });
  const svg = await satori(card.element, {
    fonts: card.fonts.map((font) => ({
      data: font.data,
      name: font.name,
      style: font.style,
      weight: font.weight,
    })),
    height: card.height,
    width: card.width,
  });
  const png = new Resvg(svg).render().asPng();
  await writeFile(join(siteDirectory, variant.file), png);
  console.log(`Wrote ${png.byteLength} bytes to ${join(siteDirectory, variant.file)}`);
}
