# Contents

- `index.html`, `styles.css`, `appearance.ts`, and `build.ts` own the static Valhalla website.
- `pages.ts` owns documentation pages with their Diátaxis kinds; `compare.ts` owns comparison and use-case pages; `writing.ts` owns notes and research articles; `docs.ts` renders every collection with grouped navigation, breadcrumbs and per-page JSON-LD.
- `tools/qualify_browser.mjs` walks every built `index.html` (not just `/docs/`) and checks overflow, navigation, CSP and console errors at desktop and phone widths.
- `valhalla-mark.svg` and `BRAND_ASSETS.md` record the checked header identity and unchanged browser/social assets.
- `metadata.test.ts`, `content.test.ts` and `support-footer.test.ts` verify discovery, per-page CSP hashes, link resolution and the shared support boundary.

# Guidelines

- Keep public claims aligned with the repository README and promotion status.
- Use the released Design Kit recipe for both header title and exact-alpha mark. Keep the original SVG fallback, existing home label, navigation, and final appearance control.
- Declare the mask URL in the external stylesheet. Preserve the restrictive CSP without adding inline-style or script exceptions.
- Copy every imported design stylesheet and its license; record their exact hashes in the built source receipt.
- Run `bun run check:site` and inspect the built header at phone and desktop sizes. Follow `README.md` for site deployment and production verification, and preserve required repository CI.
