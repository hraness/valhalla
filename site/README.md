# Valhalla marketing page

One static page for vhalla.com. Keep its claims aligned with the repository
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
stylesheet hashes in `design/source.json`. Product content and layout stay here.
The pinned shared footer renders an optional paid-support link for Valhalla,
without a newsletter form or client runtime. `bun run check:site` checks that
boundary and builds the page; `/llms.txt` documents the installed CLI's optional
support protocol for agents. The existing no-form CSP remains unchanged.

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
