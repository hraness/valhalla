# Valhalla marketing and documentation site

A static home page, a documentation hub with fourteen pages, a comparison hub
with four comparisons, a writing hub with six notes, and a use-cases page for
vhalla.com. Documentation follows the Diátaxis split: tutorials, how-to guides,
reference and explanation. Keep every claim true to the current source and the
[promotion plan](../kb/plans/valhalla-promotion-gates.md); the copy rules are in
[`AGENTS.md`](AGENTS.md).

From the repository root, preview locally:

```console
bun install --frozen-lockfile --ignore-scripts
bun run build:site
python3 -m http.server 8764 --bind 127.0.0.1 --directory site/dist
```

Open http://127.0.0.1:8764. The site uses the pinned `@hraness/design-kit`
Rosé Pine palette, Lantern material, marketing texture, Nebula Sans and Instrument
Serif fonts. The shared appearance controller provides Light, Dark and System
from the final header control. Build output retains asset licenses and exact
stylesheet hashes in `design/source.json`. Deployment includes the referenced web
fonts and their licenses, excluding duplicate native-font files and generator-only
TypeScript font data. The build checks every shared font URL resolves. Product content and layout stay here. `pages.ts` owns the maintained static documentation with each page's Diátaxis kind, `compare.ts` owns the comparison and use-cases pages, `writing.ts` owns the notes, `articles.ts` owns the reviewed technique posts (Markdown bodies in `articles/`, review records in `article-admissions.ts`), `discovery.ts` adds indexable posts to the sitemap, `llms.txt` and the Atom feed, `docs.ts` renders the shared grouped navigation and per-page metadata, `home.ts` builds the home FAQ's structured data from the visible FAQ, and `build.ts` writes ordinary HTML paths under `/docs/`, `/compare/`, `/writing/` and `/use-cases/`. No framework, analytics, external scripts or runtime content fetching are added. Navigation and code examples remain usable without JavaScript.
The header title and transparent catalog mark use the shared metallic foil
recipe. The original SVG remains the fallback for unsupported masks and forced
colors; mask configuration stays in the external stylesheet under the same CSP.
The pinned shared footer renders an optional paid-support link for Valhalla,
without a newsletter form or client runtime. `bun run check:site` checks that
boundary, validates documentation links/security disclosures, and builds every page; `/llms.txt` points agents to the installed CLI's optional
support protocol. The CSP still allows no executable inline script;
it admits each page's checked JSON-LD block by exact SHA-256 hash.
`bun site/tools/update_csp.ts` rewrites those hashes in `vercel.json`, and
`site/metadata.test.ts` fails when they drift from the rendered pages. Social
previews use the committed cards hashed in `BRAND_ASSETS.md`.

`vercel.json` builds `site/dist/` as the static output and sets restrictive content
security headers. Deploy from the repository root to the Hraness `valhalla`
project after reviewing the changes and checking the page at desktop and mobile
sizes:

```console
vercel link --project valhalla --scope hraness
vercel deploy --prod --scope hraness
```

Keep `.vercel/` private and untracked. Verify that https://vhalla.com returns the
new page and that CSS, font, navigation, and HTTPS work after deployment. Use
Vercel's retained production deployments to roll back; never delete the domain
or recreate the project to repair a page.


## Documentation contract

- Home illustrations are explicitly illustrative, not screenshots or live state.
- Public activity is plaintext. Private MLS file exchange is an opt-in native/browser development
  capability. The actual browser worker/panel has targeted local Chromium evidence;
  native and browser `.vharchive` recovery is read-only. Browser archives,
  owner-authorized fresh-device rejoin, predecessor-authorized owner succession
  and local relay adapters have targeted local evidence. Safe dead-device
  recovery, live-device transfer, hardened public relay operation and enforced
  agent compartments remain explicit gaps. The native client has a bounded
  account-owned fixed-room adapter, but it is a cooperating-host boundary and
  does not claim OS or provider isolation. Ordinary public builds exclude
  optional MLS dependencies.
- Keep current CLI examples aligned with `public_activity`, `public_serve`,
  private archive and Clankdar command help. Native continuity has its own receipt
  session: temporary staging, terminal admission and the exact-source Evidence
  floor are different claims. Source status is distinct from deployment evidence.
- Readiness documents concrete history/capacity/continuity/replication limits and
  next qualification work. Update it when those boundaries actually change.
- Validate desktop/mobile, dark/light, keyboard navigation, overflow and direct
  documentation URLs before deployment. No hosted application link is invented.


The maintained browser smoke uses Node 24 with an explicitly selected Chromium:

```sh
node site/tools/qualify_browser.mjs ABS_SITE_DIST CHROMIUM_EXECUTABLE NEW_OUTPUT_DIR ABS_VERCEL_JSON
```

It serves the exact static build and deployment CSP on loopback in a fresh
profile, checks all documentation paths, desktop/mobile overflow, keyboard
navigation, appearance modes and reading with JavaScript disabled, then writes
screenshots and a receipt. CI retains those outputs without the browser profile.
The same gate checks first-visit System appearance, live OS preference changes,
saved Light/Dark choices and actual back/forward-cache restoration of the hero
controller. Append `--appearance-only` to run only those focused checks against
an already built site; this does not replace the complete deployment gate.
Reduced-motion and forced-color changes suppress interaction in the desktop
document; coarse-pointer suppression uses a separate native touch target.


Documentation source links and the setup command pin `documentedRevision` to a
retained full Git commit, rather than assuming unreleased commands exist on the
default branch. Publish that commit before the site. Advance the pin deliberately
when the documented implementation changes; the source-link regression requires
every source guide to use the same immutable revision.
