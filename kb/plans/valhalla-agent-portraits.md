---
type: plan
area: agent-identity
status: in-progress
tags: [design, rust, security, wasm]
---

# Agent portraits with family resemblance

## Outcome and reference

Give every Valhalla agent a deterministic, recognizable profile image. The user
supplied the Codex sidebar's small jewel-like abstract marks and requested much
more diversity, with a shared owner influencing the patterning of its agents.
This is agent identity presentation, separate from the crossed-swords product
favicon and the marketing site's shared design migration.

The prototype is [agent-portraits](../../prototypes/agent-portraits/README.md).
It is excluded from the maintained workspace. No live identity, affiliation,
permission, network message or installed client behavior changes.

## Decisions after the first code spike

| Fork | Current choice | Why / remaining evidence |
| --- | --- | --- |
| Generated imagery or procedural symbols | Pure Rust deterministic SVG | Portable, cheap, inspectable, no model/network/runtime dependency. A later bitmap adapter can rasterize the same geometry. |
| Owner selects one silhouette species | Owner selects construction, palette, material and recurring emblem; agent selects any topology | Avoids filling an owner's roster with near-identical flowers or checkerboards. |
| Hue alone identifies a family | Redundant cut, central mark and material cues | The compact renderer retains cut and mark when removing microtexture. Grayscale review is required. |
| Tiny portraits use scaled large artwork | Explicit compact output at 16/24px | Remove detail that becomes noise. Stronger simplification may be needed after real roster use. |
| Random generation per login | Domain-separated stable application/display inputs | Restarts and transport rotation must not redraw familiar agents. |
| A portrait proves affiliation | No authority in the renderer; affiliation admitted separately | Current sessions prove pinned peer keys, not ownership. Artwork is freely copyable. |
| Global public pictures in every context | Explicit scope in derivation | Useful presentation partition; it is not anonymity when public keys are reused. |
| Mutable style updates | Versioned derivation and golden vectors | Freeze a stable renderer before integrating identity-bearing UI; prototype v0 remains revisable. |

The current grammar has 16 arrangements: corolla, fan, pinwheel, bifold, knot,
crescent, cairn, coral, constellation, lattice, crown, comet, folded ribbon,
trifid, weave, and seed with satellites. Six piece cuts, six materials and eight
owner marks combine with independently derived agent dimensions. This is an
empirical diversity mechanism, not an injective mapping from keys to images.

## Security and resource boundary

Only three fixed 32-byte values enter the renderer: scope, owner hint and agent.
No user text, path, URL, uploaded SVG or style enters output. The library has no
I/O, entropy, filesystem, clock, unsafe Rust or ambient authority. SHA-256 uses
separate transcripts for family, individual and cache. Fixed integer geometry,
12-atom maximum and bounded output prevent arbitrary recursive or resource-heavy
scenes. Host consumers should render the resulting SVG as an image and supply
accessible identity labels separately.

Before a real UI uses family grouping, derive display inputs from the social
layer's admitted immutable `OwnerId` and owner-bound `AgentId`, plus explicit
scope. Raw application keys alone conflate distinct incarnations and key reuse.
The joint genesis proves historical affiliation; scoped grants and current
control separately determine live eligibility. Expiry, revocation or retirement
must show an inactive status while preserving verified historical affiliation.
Missing/invalid genesis evidence gets unverified presentation. Wrong-realm live
grants cannot authorize activity in this realm. The renderer constructs no
ownership capability, and resemblance never grants tool authority.

Copying a picture, copying an owner hint and grinding for a lookalike are easy.
Display full-key verification for consequential actions and keep verification
status outside the glyph. Do not describe the image as a security fingerprint,
proof of agency, Sybil defense or hardware identity. Family appearance reveals
relationships intentionally; use separately scoped identities for private groups.

## Verification and next admission work

The first native spike has property tests for arbitrary-key deterministic bounded
output and sibling inheritance; unit tests check domain/role/scope separation and
all geometry parameter combinations. Independent review caught a test that
rounded arbitrary rotations to 15-degree steps; it now uses actual-angle
host-only trigonometry and includes stroke clearance. SVG generation stays
integer-only. A separate Python stdlib XML verifier admits only the renderer's
fixed vocabulary, checks local references and budgets, rejects four injected
unsafe variants, and compares 12 golden outputs across themes/detail modes.

The fixed 64-owner × 16-agent sample has 1,024 distinct normalized SVGs after
removing hash-derived SVG IDs. It includes all 16 topologies; the largest sample
SVG is 4,709 bytes. Distinct source does not establish distinguishability at 16px.
The review gallery uses 8 owners × 8 agents, both themes, grayscale and four sizes.

Independent review found only **48 compact grayscale family categories**: six
cuts times eight emblems. The other owner palette/material cues disappear in
that mode. The 64-owner sample occupies 35 categories, with 45 same-category owner
pairs and up to five owners per category. Even the eight-owner gallery repeats a
category between Moss and Iris. These are family-cue collisions, not identical
agent pictures. The generator now records these counts in `sample.json`. Strong
owner recognition across large populations is an unresolved design requirement.

The fixed grammar currently emits at most seven atoms; the conservative cap is
12. Atom/output assertions now remain active in release builds, and release
property tests cover returned output. The 32 KiB check runs after string building,
so it is not an independent allocator budget. A maintained adapter should use a
fallible bounded writer before accepting any extensible grammar or user styling.

Next, in dependency order:

1. Completed local browser inspection at desktop and 390px mobile in
   dark/light/grayscale and 16/24/32/64px. Rows wrap without clipping. At 16px
   fine family cues are weak, so readable identity labels remain essential.
   Gather user matching feedback before promoting this v0 reference.
2. Measure nearest-neighbor silhouette similarity, family confusion and compact
   collisions across much larger populations. Human matching tasks must include
   siblings, strangers with similar colors, grayscale and adversarial lookalikes.
   Choose a measured admission threshold; do not invent a universal uniqueness claim.
3. Verify native/WASM byte parity using the same corpus and measure allocations,
   rendering time and artifact sizes on browser and constrained targets. WASM
   compilation alone is not runtime parity or embedded qualification.
4. Compare additional owner cutout motifs and topology families if the review
   shows confusion. Add recurring negative-space seams, rather than solving
   every collision with more color or fine detail.
5. Connect the implemented social affiliation boundary through a reviewed display
   adapter. Test invalid evidence before family assignment, plus retired/revoked
   agents retaining historical family identity. Add accessible labels and a
   separate trust indicator; confirm portraits cannot enter effect authority.
6. Promote only the renderer/descriptor API after stable-version and cache
   migration decisions. Keep transports, game state and profile presentation
   separately owned. No protocol payload needs to carry raw SVG.

## Recovery

The prototype adds no migration or live network state. Remove the optional preview
or select a prior renderer version to restore presentation. Never change keys,
trust records or permissions to repair a picture. Keep previous stable rendering
versions available when a future release changes the visual grammar.
