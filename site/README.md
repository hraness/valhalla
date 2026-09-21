# Valhalla marketing and documentation site

A static home page and ten documentation pages for vhalla.com. Keep claims aligned with the repository
README and [promotion status](../kb/plans/valhalla-promotion-gates.md).

From the repository root, preview locally:

```console
bun install --frozen-lockfile --ignore-scripts
bun run build:site
python3 -m http.server 8764 --bind 127.0.0.1 --directory site/dist
```

Open http://127.0.0.1:8764. The site uses the pinned `@hraness/design-kit`
Paper palette, Lantern material, marketing texture, Nebula Sans and Instrument
Serif fonts. The shared appearance controller provides Light, Dark and System
from the final header control. Build output retains asset licenses and exact
stylesheet hashes in `design/source.json`. Deployment includes the referenced web
fonts and their licenses, excluding duplicate native-font files and generator-only
TypeScript font data. The build checks every shared font URL resolves. Product content and layout stay here. `pages.ts` owns the maintained static documentation, `docs.ts` renders the shared navigation and per-page metadata, and `build.ts` writes ordinary HTML paths under `/docs/`. No framework, analytics, external scripts or runtime content fetching are added. Navigation and code examples remain usable without JavaScript.
The pinned shared footer renders an optional paid-support link for Valhalla,
without a newsletter form or client runtime. `bun run check:site` checks that
boundary, validates documentation links/security disclosures, and builds every page; `/llms.txt` documents the installed CLI's optional
support protocol for agents. The CSP still allows no executable inline script;
it admits the one checked JSON-LD block by exact SHA-256 hash, which
`site/metadata.test.ts` keeps in sync with `index.html`. Social previews use the
committed `social.png` card hashed in `BRAND_ASSETS.md`.

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
  native `.vharchive` recovery is read-only. Browser archives, fresh-device rejoin,
  owner-device succession, live-device transfer, relay transports and enforced agent
  compartments remain explicit gaps. The native client has a bounded
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


Documentation source links and the setup command pin `documentedRevision` to a
retained full Git commit, rather than assuming unreleased commands exist on the
default branch. Publish that commit before the site. Advance the pin deliberately
when the documented implementation changes; the source-link regression requires
every source guide to use the same immutable revision.
