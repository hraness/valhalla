# Hierarchical agent portraits

Throwaway Rust reference for vhalla (valhalla). A small, deterministic image for
an agent, with a family resemblance to other agents associated with the same
owner. Inspired by the user's Codex sidebar reference: layered jewel-like
abstract marks with dark seams and restrained highlights.

Every owner can use all 16 topology families. The owner contributes the cut of
each piece, a recurring central emblem, a two-hue palette and a material pattern.
The agent independently contributes topology, count, pose, reach, width and core
size. This keeps siblings related without restricting a whole population to one
silhouette. The forms include fans, knots, wings, corals, cairns, lattices,
crowns, comets, folded ribbons and seed clusters.

The library uses `no_std + alloc`, forbids unsafe Rust and depends only on
SHA-256 with its default features disabled. Fixed integer geometry emits bounded
SVG; it needs no font, image model, JavaScript, network or device identifier.
The local gallery uses HTML/CSS radio controls and synthetic keys. The host-only
example writes files; the renderer itself has no I/O.

```console
cargo test --manifest-path prototypes/agent-portraits/Cargo.toml --locked
cargo run --manifest-path prototypes/agent-portraits/Cargo.toml --example gallery --release --locked -- /tmp/valhalla-portraits
python3 prototypes/agent-portraits/verify.py /tmp/valhalla-portraits
python3 -m http.server 8767 --bind 127.0.0.1 --directory /tmp/valhalla-portraits
```

Open `http://127.0.0.1:8767` to compare eight owners with eight agents each,
light/dark/grayscale, and 16/24/32/64px sizes. At 16/24px, compact output removes
microtexture and highlights but retains the outline, arrangement and owner mark.
Serve only this generated fixture directory. Stop the server after review.

## Identity boundary

`Portrait::from_public_hints(scope, owner_hint, agent)` accepts three fixed
32-byte public inputs. Its name is deliberate: it validates **no affiliation**.
The Valhalla session establishes a pinned application-key pairing. The separate
social layer establishes jointly signed owner-bound agent genesis and scoped
live grants. A real UI must derive hints from admitted immutable `OwnerId` and
`AgentId`, with scope, before placing an agent in a verified owner's family.
Raw key pairs alone conflate incarnations. Missing or rejected genesis evidence
needs unverified presentation; expired/revoked/retired agents keep their verified
historical owner affiliation with an inactive status.
Never allow a remote profile field to select a trusted owner's family label.

A portrait is a recognition aid. It is copyable and susceptible to lookalikes
and key grinding. It must not establish ownership, authentication, authority,
reputation or permission. Keep verified status and readable identity text outside
the image; use full keys for sensitive decisions. Prefer an image element with
an accessible label from the host. The SVG intentionally includes no remote name
or arbitrary text.

Use stable application/display identities, not ephemeral transport keys. A
public scope changes the derived image but does not prevent correlation when
public keys are reused. Grouping intentionally reveals a population relationship;
private groups need separately scoped identities and an appropriate disclosure
policy, not a purportedly anonymous public salt.

## Determinism and bounds

Version 0 domain-separates family, individual and cache derivation. All visible
inputs come from fixed digest bytes. The cache key is a descriptor key, not a
verification fingerprint. Include theme, detail and renderer version in an
actual image cache. A future stable release must freeze its versioned renderer;
never silently change known portraits. This prototype is not that stable release.

The fixed grammar emits at most seven atoms, with release-active assertions at
12 atoms and 32 KiB returned output. The string-size check occurs after building;
it is not a separate peak-allocation budget. A fallible bounded writer is required
before making the grammar extensible. No arbitrary SVG, external
resource, filter, script, CSS or font input is accepted. Internal gradient/pattern
IDs have a per-portrait namespace. All arithmetic in production is integer;
host-only trigonometry checks actual rotated boxes plus stroke margin.

The gallery samples 1,024 synthetic agents in 64 families, normalizes internal
IDs before comparing SVG source, and records the resulting count in `sample.json`.
The first sample produced 1,024 distinct normalized SVGs across all 16 forms,
with a maximum of 4,709 bytes. This is an exact-source duplicate check, **not a
perceptual uniqueness guarantee**. Runtime figures include generation and set
comparison on the local host and are not an embedded-hardware budget.

Compact grayscale preserves only 6 cuts × 8 emblems = **48 family categories**.
The sample's 64 owners occupy 35 categories, with 45 same-category pairs and at
most five owners sharing one category. Moss and Iris already repeat a category
in the eight-owner gallery. `sample.json` records these counts separately from
full-image duplicates. Larger-population family recognition needs more effective
structural cues and measured human matching, not a larger color palette alone.

Tests cover arbitrary-key determinism/bounds, sibling traits, role/scope
separation, every topology's geometric bounds, 12 canonical golden vectors, and
an independent XML element/attribute allowlist for all 384 gallery SVGs, including
unsafe mutation rejection. WASM compilation is a separate check; cross-target
byte parity and human recognition studies remain promotion gates.

See the [design and promotion plan](../../kb/plans/valhalla-agent-portraits.md).
