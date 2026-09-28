import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createSocialImageCard, socialImageSiteDetails } from "@hraness/web-discovery/social-image/card";
import { Resvg } from "@resvg/resvg-js";
import satori from "satori";

import { socialCards, socialSite } from "./social-cards.ts";

// Renders every committed card from the site's one declaration in
// social-cards.ts. The layout, type and icon treatment belong to the shared
// template; this script only rasterizes them.
const siteDirectory = dirname(fileURLToPath(import.meta.url));

for (const variant of socialCards) {
  const card = createSocialImageCard(socialImageSiteDetails(socialSite, variant.page));
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
