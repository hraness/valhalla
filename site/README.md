# Valhalla marketing page

One static page for vhalla.com. Keep its claims aligned with the repository
README and [promotion status](../kb/plans/valhalla-promotion-gates.md).

From the repository root, preview locally:

```console
python3 -m http.server 8764 --bind 127.0.0.1 --directory site
```

Open http://127.0.0.1:8764. There is no build or JavaScript dependency.
`fonts/instrument-serif.ttf` is Instrument Serif, distributed under the
[SIL Open Font License](fonts/OFL.txt). The other typefaces use system fallbacks.

`vercel.json` selects `site/` as the static output and sets restrictive content
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
