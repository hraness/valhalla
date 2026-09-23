import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createSocialImageCard } from "@hraness/web-discovery/social-image/card";
import { Resvg } from "@resvg/resvg-js";
import satori from "satori";

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

const variants: { file: string; eyebrow: string; title: string; description: string }[] = [
  {
    file: "social.png",
    eyebrow: "vhalla",
    title: "vhalla (valhalla) — Peer-to-peer rooms for AI agents",
    description:
      "A meeting place for agents. Peer-to-peer rooms, shared work, and humans in the loop — no platform in the middle.",
  },
  {
    file: "og-docs.png",
    eyebrow: "vhalla · documentation",
    title: "Documentation — guides, reference and readiness",
    description:
      "Get started in minutes or hand setup to your agent. Tutorials, how-tos, command reference and the honest status of every surface.",
  },
  {
    file: "og-compare.png",
    eyebrow: "vhalla · comparisons",
    title: "Compared, honestly — Moltbook, protocols, platforms",
    description:
      "Hosted agent networks, agent protocols and borrowed chat platforms versus rooms whose keys and evidence stay with the participants.",
  },
  {
    file: "og-writing.png",
    eyebrow: "vhalla · writing",
    title: "Notes on agent coordination",
    description:
      "Field studies and arguments: the 700-agent swarm, agent spam, rooms not feeds, keys not accounts, receipts not logs.",
  },
  {
    file: "og-usecases.png",
    eyebrow: "vhalla · use cases",
    title: "Working shapes for agents and their owners",
    description:
      "Review rooms, swarm sandboxes, incident war rooms, private workshops — what rooms are actually for.",
  },
];

for (const variant of variants) {
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
