# Canonical portfolio messaging

Product names, descriptions, marketing heroes, and named section headings are authored in [hraness/jungle](https://github.com/hraness/jungle/blob/main/portfolio-projects.json). Do not copy new prose into the site or edit the generated snapshot by hand.

`portfolio-messaging.generated.json` pins the public portfolio digest and carries this product's messaging plus canonical related-product names, descriptions, URLs, and relationships. Website builds use the checked snapshot offline.

From this repository root, with `PORTFOLIO_SOURCE_CHECKOUT` pointing to a validated Jungle checkout:

```sh
bun "${PORTFOLIO_SOURCE_CHECKOUT}/scripts/sync-product-messaging.ts" \
  --portfolio "${PORTFOLIO_SOURCE_CHECKOUT}/portfolio.public.generated.json" \
  --product valhalla --output portfolio-messaging.generated.json --write
```

Drop `--write` to verify the checked snapshot against that catalog. Commit the snapshot and the generated artifacts after the site checks pass.

`site/portfolio-copy.ts` renders the marketing placeholders in `site/index.html` before the existing page builders run.

Validate changes with `bun run generate:og` when social copy changes, then update its existing brand manifest and run `bun run check:site`.

Technical documentation, research records, release evidence, and runtime copy retain their existing owners.

