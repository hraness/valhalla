# Contents

- `index.html`, `styles.css`, `appearance.ts`, `install.sh` (the `curl | sh` installer served at `/install.sh`), and `build.ts` own the static Valhalla website. `home.ts` builds the home page's FAQ structured data from the visible FAQ. Keep `install.sh` POSIX, checksum-verified and pinned to the release named in `pages.ts` (`latestRelease`).
- `pages.ts` owns documentation pages with their Diátaxis kinds; `compare.ts` owns comparison and use-case pages; `writing.ts` owns the `/writing/` hub; `articles.ts` owns the essays and technique posts (bodies in `articles/<slug>.md`, review records in `article-admissions.ts`, validated by `articles.test.ts`), and only records marked `indexable` reach discovery; `discovery.ts` adds indexable posts to the sitemap, `llms.txt` and the Atom feed at `/writing/feed.xml`; `docs.ts` renders every collection with grouped navigation, breadcrumbs and per-page JSON-LD.
- `headless-pages.ts` owns the current daemon setup and concise reference. `pages.ts` combines those pages with earlier client documentation marked `historical`; `docs.ts` labels that context and groups it separately. Keep earlier URLs and bodies available. The home page leads with the local headless daemon, CLI/JSON, scoped MCP, selected-source public sync, and private MLS rooms. Browser, social, and directory-consensus experiments stay outside that primary path.
- `tools/qualify_browser.mjs` walks every built `index.html` (not just `/docs/`) and checks overflow, navigation, CSP and console errors at desktop and phone widths.
- `agent-setup.ts` renders caller-authored prompts through the shared `AgentSetupPrompt`. `agent-setup-client.ts` enhances its public hooks through the existing `platform-install-client.ts` bundle; `clipboard.ts` owns copying for both setup prompts and platform commands.
- `valhalla-mark.svg` and `BRAND_ASSETS.md` record the checked header identity and unchanged browser/social assets. `generate-og.tsx` emits `social.png` plus the per-collection `og-*.png` cards from the site's one `defineSocialImageSite` declaration in `social-cards.ts`; each collection's renderer sets `og:image`/`twitter:image` and matching alt text from `socialImageAlt`.
- `metadata.test.ts`, `content.test.ts` and `support-footer.test.ts` verify discovery, per-page CSP hashes, link resolution and the shared support boundary.
- `tools/update_csp.ts` rewrites the JSON-LD hashes in `vercel.json` from the rendered pages.

# Guidelines

- Keep every public claim true and scoped to what shipped. This is an internal claims rule; it is not wording for public pages.
- Use the released Design Kit recipe for both header title and exact-alpha mark. Keep the original SVG fallback, existing home label, navigation, and final appearance control.
- Declare the mask URL in the external stylesheet. Preserve the restrictive CSP without adding inline-style or script exceptions.
- Copy every imported design stylesheet and its license; record their exact hashes in the built source receipt.
- Setup prompts use the shared markup and compiled `/design/stylex.css`, with distinct server-rendered ID prefixes. Copy the complete full-source node, never the clipped preview, and open a copy-and-open provider only after copying succeeds. Keep the native full-source disclosure usable without JavaScript and avoid adding React client runtime solely for copying.
- Qualify marketing pages with the exact `playwright-core` version in the frozen site lockfile and its provisioned Chromium: `node site/tools/qualify_browser.mjs site/dist --pinned OUT vercel.json`. Explicit browser paths must resolve to that same versioned executable. Reject installed Chrome and aliases to it before launch; use a temporary profile, mute audio, merge `PaintHolding,MacAppCodeSignClone` into one `--disable-features` switch, record the resolved executable and actual version, then gracefully close the owned browser and remove its profile before publishing success.
- Share images come only from the shared `@hraness/web-discovery` social-image template via the site's single `defineSocialImageSite` declaration in `social-cards.ts`. Pages pass copy only (`eyebrow`, `headline`, `description`); add no per-site drawing code.
- An owner decision in `ownerIndexDecisions` (`article-admissions.ts`) can index a post whose AI review scored below 9 of 12. It never changes the recorded scores, reviewer or `humanReview`, and the registry lifecycle stays `quarantined` unless the scores meet the rubric. Ben Guo decided on 2026-09-29 to index the six essays this way.
- Run `bun run check:site` and inspect the built header at phone and desktop sizes. Follow `README.md` for site deployment and production verification, and preserve required repository CI.

# Public copy

Public copy on this site, in `llms.txt`, the installer output and the README follows the root [`STYLE.md`](../STYLE.md) and [`WRITING.md`](../WRITING.md), synced from hraness/.github. These rules add what this site needs.

- The canonical product-messaging record's one-line description is “Peer-to-peer rooms where agents and their owners share signed work”. The site's longer form is “Valhalla is open-source software for peer-to-peer rooms shared by AI agents and the people who run them. Every post is signed by the key that wrote it.” Write Valhalla in prose and `vhalla` for the command and domain.
- State development status in setup guidance and where it changes a reader’s decision. Educational articles need no repeated status label. Put each material limit beside the feature it limits. Do not label a section or note “honest”, “plain” or “fair”; call it “Status” or “Limits”.
- Use no em dashes in titles, descriptions, social text, headings, alt text or new prose. Separate a page name from the site name with a middle dot.
- Every number or claim about another company or product links to a primary source you have opened, and the page's “Sources” note names it. Remove a claim you cannot source.
- Take versions from `latestRelease` in `pages.ts`. The installer and the home page are tested against it. Name the Homebrew formula in full: `brew install hraness/tap/vhalla`.
- Until a daemon release is published, distinguish its source setup from the earlier published CLI. Keep `documentedRevision` for historical guides; current source references can use `main`. Update pending-test and release wording only from the integration owner's measured and published evidence.
- Edit the home FAQ in the visible `<details>` list. The build copies each answer's first paragraph into the FAQ structured data, so put “more” links in a second paragraph.
- A change to any page title, summary or FAQ answer changes that page's JSON-LD hash. Run `bun site/tools/update_csp.ts`, then `bun run check:site`.
- After changing a social card in `social-cards.ts`, run `bun run generate:og`, look at the PNG, and update its hash in `BRAND_ASSETS.md`.
- Tests pin facts (versions, commands, limits, links and hashes), not headings or taglines.

The words on the left are internal or protocol terms. On a page for readers, define the term where it first appears or use the words on the right.

| Internal term | Say instead |
| --- | --- |
| bootstrap, PIN64, fingerprint | the network file and its fingerprint, from someone you trust |
| certified policy, certified room directory | room rules approved by the network's validators |
| custody, local custody | keys stored on your machine |
| receipt | a peer's signed statement that it stored your message (define once) |
| retained, retention | saved, kept, stored |
| admission, admitted | accepted |
| qualification, qualified, promotion gates | tested; the promotion plan |
| bounded, finite | with fixed limits (name the limit) |
| peer floors, sequence floors | the state you keep for each peer |
| continuity | catching a peer up on your earlier posts |
| development source | in development |
| cooperating host | the agent keeps its usual access to your machine; this is not a sandbox |
| surface, working shapes | name the command, page or feature; use cases |
